"""F360 Vault 0.4.0: Fusion project backup and export add-in."""

import adsk.core
import os
import json
import traceback
import shutil
import tempfile
from datetime import datetime, timezone


_COMMAND_ID = 'AndrewZAP1977_F360Vault_Open'
_PALETTE_ID = 'AndrewZAP1977_F360Vault_Palette'
_PANEL_ID = 'SolidScriptsAddinsPanel'
_handlers = []
_ui = None


def _show_palette():
    palette = _ui.palettes.itemById(_PALETTE_ID)
    if palette:
        palette.isVisible = True
        return

    palette = _ui.palettes.add2(
        _PALETTE_ID,
        'F360 Vault',
        'ui/palette.html',
        False,
        True,
        True,
        475,
        570,
    )
    if not palette:
        raise RuntimeError('Fusion did not create the F360 Vault palette.')

    on_html = PaletteIncomingHandler()
    palette.incomingFromHTML.add(on_html)
    _handlers.append(on_html)

    # A September 2026 Fusion feature: dock at the edge of the Fusion window,
    # resizing the canvas instead of overlapping it. Older Fusion falls back
    # to regular right-side docking.
    try:
        palette.isDockedInCanvas = False
    except AttributeError:
        pass
    palette.dockingState = adsk.core.PaletteDockingStates.PaletteDockStateRight
    palette.isVisible = True


def _read_active_hub_projects():
    """Read only project metadata from the currently active Fusion hub."""
    app = adsk.core.Application.get()
    if not app:
        raise RuntimeError('Fusion application is unavailable.')
    data = app.data
    if not data:
        raise RuntimeError('Fusion data API is unavailable.')
    collection = data.dataProjects
    if collection is None:
        raise RuntimeError('The active hub projects collection is unavailable.')
    projects = []
    for project in collection.asArray():
        if project:
            projects.append({
                'name': project.name or '(untitled)',
                'id': project.id or '',
            })
    projects.sort(key=lambda item: (item['name'].casefold(), item['id']))
    return {
        'ok': True,
        'scope': 'active_hub',
        'count': len(projects),
        'projects': projects,
    }


def _read_one_folder(request):
    """Read one folder in an active-hub project; never open documents."""
    if not isinstance(request, dict):
        raise ValueError('Invalid folder request.')
    project_id = request.get('project_id')
    folder_id = request.get('folder_id')
    if not isinstance(project_id, str) or not project_id or len(project_id) > 512:
        raise ValueError('Invalid project identifier.')
    if folder_id is not None and (
            not isinstance(folder_id, str) or not folder_id or len(folder_id) > 1024):
        raise ValueError('Invalid folder identifier.')

    app = adsk.core.Application.get()
    if not app or not app.data:
        raise RuntimeError('Fusion cloud data is unavailable.')
    data = app.data
    project = next((item for item in data.dataProjects.asArray()
                    if item and item.id == project_id), None)
    if not project:
        raise RuntimeError('Project not found in active hub.')
    folder = project.rootFolder if folder_id is None else data.findFolderById(folder_id)
    if not folder or not folder.parentProject or folder.parentProject.id != project_id:
        raise RuntimeError('Folder not found in selected project.')

    subfolders = [{'id': sub.id or '', 'name': sub.name or '(unnamed folder)'}
                  for sub in folder.dataFolders.asArray() if sub]
    files = [{'id': item.id or '', 'name': item.name or '(unnamed file)'}
             for item in folder.dataFiles.asArray() if item]
    subfolders.sort(key=lambda item: (item['name'].casefold(), item['id']))
    files.sort(key=lambda item: (item['name'].casefold(), item['id']))
    parent = folder.parentFolder
    return {
        'ok': True,
        'project_id': project.id,
        'project_name': project.name,
        'folder_id': folder.id,
        'folder_name': folder.name,
        'parent_id': parent.id if parent else None,
        'is_root': bool(folder.isRoot),
        'folders': subfolders,
        'files': files,
    }


_SETTINGS_FORMATS = ('native', 'step', 'stl', '3mf')


def _settings_file():
    """Keep all persistent F360 Vault state beside the installed add-in."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'data', 'settings.json')


def _validate_settings(value):
    if not isinstance(value, dict):
        raise ValueError('Settings must be a JSON object.')
    if value.get('schema_version', 1) != 1:
        raise ValueError('Unsupported settings schema version.')
    folder = value.get('output_folder', '')
    if not isinstance(folder, str) or len(folder) > 4096 or '\x00' in folder:
        raise ValueError('Invalid destination path in settings.')
    formats = value.get('formats', ['native'])
    if not isinstance(formats, list) or not formats or len(formats) > len(_SETTINGS_FORMATS) + 1:
        raise ValueError('Invalid export format selection.')
    if any(not isinstance(item, str) or item not in _SETTINGS_FORMATS + ('iges',) for item in formats):
        raise ValueError('Unsupported export format.')
    if len(formats) != len(set(formats)):
        raise ValueError('Duplicate export format.')
    # Backward-compatible reading of Personal-license settings. Never erase the
    # original settings.json merely to migrate away from restricted IGES.
    formats = [item for item in formats if item != 'iges']
    if not formats:
        formats = ['native']
    mode = value.get('version_mode', 'latest')
    if mode not in ('latest', 'all'):
        raise ValueError('Invalid version selection.')
    return {
        'schema_version': 1,
        'output_folder': folder,
        'formats': [fmt for fmt in _SETTINGS_FORMATS if fmt in formats],
        'version_mode': mode,
    }


def _read_export_settings():
    path = _settings_file()
    if not os.path.isfile(path):
        return _validate_settings({})
    with open(path, 'r', encoding='utf-8') as handle:
        return _validate_settings(json.load(handle))


def _save_export_settings(candidate):
    # Refuse to overwrite an existing but invalid file. No silent data loss.
    _read_export_settings()
    settings = _validate_settings(candidate)
    dest = _settings_file()
    directory = os.path.dirname(dest)
    os.makedirs(directory, exist_ok=True)
    backup_dir = os.path.join(directory, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix='.settings-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
            json.dump(settings, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.isfile(dest):
            shutil.copy2(dest, os.path.join(backup_dir, 'settings.json.previous'))
        os.replace(temp_path, dest)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return settings


# Dry-run only: walk cloud metadata and save a preview; never open CAD documents.
_PREVIEW_MAX_FOLDERS = 10000
_PREVIEW_MAX_FILES = 50000


def _preview_folder_parts(folder, project_id):
    """Return real cloud path relative to project root, rejecting foreign folders."""
    parts = []
    visited = set()
    current = folder
    while current:
        identifier = current.id
        if not identifier or identifier in visited:
            raise RuntimeError('Invalid or circular cloud folder ancestry.')
        visited.add(identifier)
        owner = current.parentProject
        if not owner or owner.id != project_id:
            raise RuntimeError('Cloud folder belongs to another project.')
        if current.isRoot:
            return list(reversed(parts))
        parts.append(current.name or '(unnamed folder)')
        current = current.parentFolder
    raise RuntimeError('Cloud folder is not connected to a project root.')


def _preview_folder_ids(folder, project_id):
    identifiers = []
    seen = set()
    current = folder
    while current:
        cid = current.id
        if not cid or cid in seen or not current.parentProject or current.parentProject.id != project_id:
            raise RuntimeError('Invalid cloud folder identity or ancestry.')
        seen.add(cid)
        if current.isRoot:
            return list(reversed(identifiers))
        identifiers.append(cid)
        current = current.parentFolder
    raise RuntimeError('Cloud folder is detached from project root.')


def _preview_file_versions(data_file, history):
    """Get latest cloud revision explicitly, including history when selected."""
    newest = data_file.latestVersion
    if not newest:
        raise RuntimeError('Cloud file has no accessible latest version.')
    expected = data_file.latestVersionNumber
    actual = newest.versionNumber
    if not isinstance(expected, int) or expected < 1 or actual != expected:
        raise RuntimeError('Cloud latest-version metadata is inconsistent.')
    candidates = [newest]
    if history:
        older = data_file.versions
        if older is None:
            raise RuntimeError('Cloud version history is unavailable.')
        candidates.extend(item for item in older.asArray() if item)
    found = {}
    for version in candidates:
        number = version.versionNumber
        version_id = version.versionId
        if (not isinstance(number, int) or number < 1 or number > expected
                or not isinstance(version_id, str) or not version_id):
            raise RuntimeError('Cloud version information is incomplete.')
        if number in found and found[number] != version_id:
            raise RuntimeError('Conflicting cloud version identifiers.')
        found[number] = version_id
    if actual not in found:
        raise RuntimeError('Latest cloud version is missing from metadata.')
    if history and set(found) != set(range(1, expected + 1)):
        raise RuntimeError('Cloud version history is incomplete; preview aborted.')
    return [{'number': n, 'id': found[n]} for n in sorted(found)]


def _build_export_preview(request):
    """Build a fresh, deduplicated, read-only cloud inventory."""
    if not isinstance(request, dict):
        raise ValueError('Invalid preview request.')
    raw_roots = request.get('sources')
    if not isinstance(raw_roots, list) or not raw_roots or len(raw_roots) > 2000:
        raise ValueError('Choose at least one cloud project, folder, or design.')
    settings = _validate_settings(request.get('settings'))
    app = adsk.core.Application.get()
    if not app or not app.data:
        raise RuntimeError('Fusion cloud data is unavailable.')
    data = app.data
    projects = {p.id: p for p in data.dataProjects.asArray() if p and p.id}
    roots = []
    individual_files = []
    root_keys = set()
    for entry in raw_roots:
        if not isinstance(entry, dict):
            raise ValueError('Invalid source descriptor.')
        kind = entry.get('kind')
        if kind == 'file':
            if set(entry) != {'kind', 'project_id', 'folder_id', 'file_id'}:
                raise ValueError('Invalid individual-file descriptor.')
        elif set(entry) != {'kind', 'project_id', 'folder_id'}:
            raise ValueError('Invalid project/folder descriptor.')
        pid = entry['project_id']
        fid = entry['folder_id']
        if kind not in ('project', 'folder', 'file') or not isinstance(pid, str) or not pid or len(pid) > 512:
            raise ValueError('Invalid selected project.')
        if kind == 'project' and fid is not None:
            raise ValueError('Unexpected folder in project selection.')
        if kind == 'folder' and (not isinstance(fid, str) or not fid or len(fid) > 1024):
            raise ValueError('Invalid selected folder.')
        if kind == 'file' and fid is not None and (not isinstance(fid, str) or not fid or len(fid) > 1024):
            raise ValueError('Invalid selected file parent folder.')
        project = projects.get(pid)
        if not project:
            raise RuntimeError('A selected project is no longer available in the active hub.')
        if kind == 'file':
            file_id = entry['file_id']
            if not isinstance(file_id, str) or not file_id or len(file_id) > 1024:
                raise ValueError('Invalid selected file ID.')
            cloud_file = data.findFileById(file_id)
            if not cloud_file or cloud_file.id != file_id or not cloud_file.parentProject or cloud_file.parentProject.id != pid:
                raise RuntimeError('Selected file is missing or moved to another project.')
            parent = cloud_file.parentFolder
            if not parent or not parent.parentProject or parent.parentProject.id != pid:
                raise RuntimeError('Selected file has an invalid parent folder.')
            if (parent.isRoot and fid is not None) or (not parent.isRoot and parent.id != fid):
                raise RuntimeError('Selected file moved after choosing it. Refresh Sources.')
            individual_files.append((project, cloud_file, parent))
            continue
        folder = project.rootFolder if kind == 'project' else data.findFolderById(fid)
        if not folder:
            raise RuntimeError('A selected cloud folder is unavailable.')
        relative_parts = _preview_folder_parts(folder, pid)
        if kind == 'folder' and folder.isRoot:
            raise RuntimeError('Selected folder unexpectedly resolves to a project root.')
        key = (pid, folder.id)
        if key not in root_keys:
            root_keys.add(key)
            roots.append((project, folder, relative_parts, _preview_folder_ids(folder, pid)))
    folders_seen = set()
    files_seen = set()
    duplicates = 0
    inventory = []
    history = settings['version_mode'] == 'all'
    for project, folder, rel, rel_ids in roots:
        stack = [(folder, rel, rel_ids)]
        while stack:
            current, parts, path_ids = stack.pop()
            owner = current.parentProject
            if not owner or owner.id != project.id:
                raise RuntimeError('A cloud folder changed project during scanning.')
            folder_key = (project.id, current.id)
            if not current.id:
                raise RuntimeError('A cloud folder has no ID.')
            if folder_key in folders_seen:
                duplicates += 1
                continue
            folders_seen.add(folder_key)
            if len(folders_seen) > _PREVIEW_MAX_FOLDERS:
                raise RuntimeError('Preview safety limit: too many cloud folders.')
            children = [f for f in current.dataFolders.asArray() if f]
            children.sort(key=lambda f: ((f.name or '').casefold(), f.id or ''))
            for sub in reversed(children):
                if not sub.id:
                    raise RuntimeError('A child folder has no ID.')
                stack.append((sub, parts + [sub.name or '(unnamed folder)'], path_ids + [sub.id]))
            files = [f for f in current.dataFiles.asArray() if f]
            files.sort(key=lambda f: ((f.name or '').casefold(), f.id or ''))
            for item in files:
                if not item.id:
                    raise RuntimeError('A cloud file has no stable ID.')
                file_key = (project.id, item.id)
                if file_key in files_seen:
                    duplicates += 1
                    continue
                files_seen.add(file_key)
                if len(files_seen) > _PREVIEW_MAX_FILES:
                    raise RuntimeError('Preview safety limit: too many documents.')
                versions = _preview_file_versions(item, history)
                inventory.append({
                    'project_id': project.id,
                    'project': project.name or '(untitled project)',
                    'folder_path': parts,
                    'folder_ids': path_ids,
                    'file_id': item.id,
                    'name': item.name or '(unnamed file)',
                    'latest_version': versions[-1]['number'],
                    'versions': versions,
                })
    # Include separately selected cloud files, including designs in project root.
    # The same data-file ID may also be covered by a whole folder/project source.
    for project, item, parent in individual_files:
        owner = item.parentProject
        actual_parent = item.parentFolder
        if not owner or owner.id != project.id or not actual_parent or actual_parent.id != parent.id:
            raise RuntimeError('Selected file location changed during scan.')
        parts = _preview_folder_parts(actual_parent, project.id)
        path_ids = _preview_folder_ids(actual_parent, project.id)
        file_key = (project.id, item.id)
        if file_key in files_seen:
            duplicates += 1
            continue
        files_seen.add(file_key)
        if len(files_seen) > _PREVIEW_MAX_FILES:
            raise RuntimeError('Preview safety limit: too many documents.')
        versions = _preview_file_versions(item, history)
        inventory.append({
            'project_id': project.id,
            'project': project.name or '(untitled project)',
            'folder_path': parts,
            'folder_ids': path_ids,
            'file_id': item.id,
            'name': item.name or '(unnamed file)',
            'latest_version': versions[-1]['number'],
            'versions': versions,
        })
    inventory.sort(key=lambda row: (
        row['project'].casefold(), '/'.join(row['folder_path']).casefold(),
        row['name'].casefold(), row['file_id']))
    preview = {
        'schema_version': 1,
        'kind': 'read_only_export_preview',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'settings': settings,
        'sources': [{'kind': entry['kind'], 'project_id': entry['project_id'],
                     'folder_id': entry['folder_id'],
                     **({'file_id': entry['file_id']} if entry['kind'] == 'file' else {})}
                    for entry in raw_roots],
        'folders_scanned': len(folders_seen),
        'documents_count': len(inventory),
        'versions_count': sum(len(row['versions']) for row in inventory),
        'duplicates_skipped': duplicates,
        'documents': inventory,
    }
    directory = os.path.join(os.path.dirname(_settings_file()), 'state')
    os.makedirs(directory, exist_ok=True)
    destination = os.path.join(directory, 'last_preview.json')
    fd, temporary = tempfile.mkstemp(prefix='.preview-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(preview, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {
        'ok': True,
        'created_utc': preview['created_utc'],
        'folders_scanned': preview['folders_scanned'],
        'documents_count': preview['documents_count'],
        'versions_count': preview['versions_count'],
        'duplicates_skipped': preview['duplicates_skipped'],
        'preview_path': destination,
        'sample': [
            {'project': doc['project'], 'folder_path': doc['folder_path'],
             'name': doc['name'], 'latest_version': doc['latest_version'],
             'versions': len(doc['versions'])}
            for doc in inventory[:15]
        ],
    }


# Local path planning is a separate, read-only step after cloud preview.
# It must never create folders or files in the chosen backup destination.
def _build_local_path_plan(request):
    if not isinstance(request, dict):
        raise ValueError('Invalid local path plan request.')
    preview_path = os.path.join(os.path.dirname(_settings_file()),
                                'state', 'last_preview.json')
    with open(preview_path, 'r', encoding='utf-8') as stream:
        preview = json.load(stream)
    if preview.get('created_utc') != request.get('preview_created_utc'):
        raise RuntimeError('Cloud preview changed. Check the cloud list again.')
    if preview.get('sources') != request.get('sources'):
        raise RuntimeError('Selected sources changed. Check the cloud list again.')
    validated = _validate_settings(request.get('settings'))
    if validated != preview.get('settings') or validated != _read_export_settings():
        raise RuntimeError('Export settings changed. Check the cloud list again.')
    import importlib.util
    module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'path_layout.py')
    spec = importlib.util.spec_from_file_location('f360vault_local_layout', module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError('Path planning module is unavailable.')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = module.build_local_plan(preview, check_disk=True)
    directory = os.path.join(os.path.dirname(_settings_file()), 'state')
    os.makedirs(directory, exist_ok=True)
    destination = os.path.join(directory, 'last_path_plan.json')
    fd, temporary = tempfile.mkstemp(prefix='.path-plan-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(plan, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {
        'ok': True,
        'planned_items': plan['planned_items'],
        'occupied_items': plan['occupied_items'],
        'blocked_items': plan['blocked_items'],
        'native_pending_items': plan['native_pending_items'],
        'renaming_examples': plan['renaming_examples'][:5],
        'path_plan': 'F360Vault/data/state/last_path_plan.json',
    }


# A separate module owns the per-version queue, journal, and fail-safe document handling.
_VAULT_EVENT_ID = 'AndrewZAP1977_F360Vault_ExportTick_dev6'
_vault_engine = None


def _vault_load_file_module(name, filename):
    import importlib.util
    root = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(name, os.path.join(root, filename))
    if spec is None or spec.loader is None:
        raise RuntimeError('F360 Vault module is unavailable: ' + filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vault_get_engine():
    global _vault_engine
    if _vault_engine is None:
        _vault_engine = _vault_load_file_module('f360vault_export_engine_dev6', 'export_engine.py')
    return _vault_engine


def _vault_fire():
    app = adsk.core.Application.get()
    if not app:
        raise RuntimeError('Fusion is unavailable for export queue tick.')
    # Completion is confirmed by the registered Fusion event handler and
    # persistent job report. The return value can be non-canonical even when
    # the queued event is later processed successfully.
    app.fireCustomEvent(_VAULT_EVENT_ID)


def _vault_start(request):
    return _vault_get_engine().start(
        request, _build_export_preview, _read_export_settings,
        _settings_file(), lambda: _vault_load_file_module('f360vault_export_layout', 'path_layout.py'),
        _vault_fire)


def _vault_control(request):
    if not isinstance(request, dict):
        raise ValueError('Invalid export control request.')
    return _vault_get_engine().control(request.get('action'))


class PaletteIncomingHandler(adsk.core.HTMLEventHandler):
    def notify(self, args):
        try:
            palette = _ui.palettes.itemById(_PALETTE_ID)
            if not palette:
                return
            if args.action == 'ping':
                palette.sendInfoToHTML(
                    'pong',
                    json.dumps({
                        'ok': True,
                        'message': 'Fusion API connection confirmed.',
                        'version': '0.1.0',
                    }),
                )
            elif args.action == 'list_projects':
                try:
                    response = _read_active_hub_projects()
                except Exception:
                    response = {
                        'ok': False,
                        'error': traceback.format_exc(limit=3),
                        'projects': [],
                    }
                palette.sendInfoToHTML(
                    'projects_result',
                    json.dumps(response, ensure_ascii=False),
                )
            elif args.action == 'load_export_settings':
                try:
                    reply = {'ok': True, 'settings': _read_export_settings()}
                except Exception:
                    reply = {'ok': False, 'error': traceback.format_exc(limit=3)}
                palette.sendInfoToHTML(
                    'export_settings_result',
                    json.dumps(reply, ensure_ascii=False),
                )
            elif args.action == 'save_export_settings':
                try:
                    candidate = json.loads(args.data or '{}')
                    _save_export_settings(candidate)
                    reply = {'ok': True}
                except Exception:
                    reply = {'ok': False, 'error': traceback.format_exc(limit=3)}
                palette.sendInfoToHTML(
                    'export_settings_saved',
                    json.dumps(reply, ensure_ascii=False),
                )
            elif args.action == 'preview_export_plan':
                try:
                    request = json.loads(args.data or '{}')
                    reply = _build_export_preview(request)
                except Exception:
                    reply = {'ok': False, 'error': traceback.format_exc(limit=4)}
                palette.sendInfoToHTML(
                    'export_preview_result',
                    json.dumps(reply, ensure_ascii=False),
                )
            elif args.action == 'plan_local_paths':
                try:
                    request = json.loads(args.data or '{}')
                    reply = _build_local_path_plan(request)
                except Exception:
                    reply = {'ok': False, 'error': traceback.format_exc(limit=4)}
                palette.sendInfoToHTML(
                    'local_path_plan_result',
                    json.dumps(reply, ensure_ascii=False),
                )
            elif args.action == 'aps_connect':
                try:
                    reply = _vault_get_engine().aps_connect()
                except Exception:
                    reply = {'ok': False, 'state': 'ERROR', 'error': traceback.format_exc(limit=3)}
                palette.sendInfoToHTML('aps_connect_result', json.dumps(reply, ensure_ascii=False))
            elif args.action == 'aps_status':
                try:
                    reply = _vault_get_engine().aps_status()
                except Exception:
                    reply = {'ok': False, 'state': 'ERROR', 'error': traceback.format_exc(limit=3)}
                palette.sendInfoToHTML('aps_status_result', json.dumps(reply, ensure_ascii=False))
            elif args.action == 'vault_export_start':
                try:
                    reply = _vault_start(json.loads(args.data or '{}'))
                except Exception as exc:
                    if getattr(exc, 'error_code', None) == 'INTEGRITY_BLOCKED':
                        # An expected safety refusal is not a Python failure.
                        # Send structured data to the UI without a traceback.
                        problem = getattr(exc, 'problem', {})
                        reply = {'ok': False, 'code': 'INTEGRITY_BLOCKED',
                                 'message': 'Проверка резервной копии не пройдена. Экспорт не запускался.',
                                 'problem': problem if isinstance(problem, dict) else {}}
                    else:
                        reply = {'ok': False, 'code': 'EXPORT_START_ERROR',
                                 'message': 'Не удалось начать экспорт. Смотри подробности в журнале.',
                                 'error': traceback.format_exc(limit=7)}
                palette.sendInfoToHTML('vault_export_start_result', json.dumps(reply, ensure_ascii=False))
            elif args.action == 'vault_export_control':
                try:
                    reply = _vault_control(json.loads(args.data or '{}'))
                except Exception:
                    reply = {'ok': False, 'error': traceback.format_exc(limit=5)}
                palette.sendInfoToHTML('vault_export_progress', json.dumps(reply, ensure_ascii=False))
            elif args.action == 'open_report_folder':
                try:
                    query = json.loads(args.data or '{}')
                    status = _vault_get_engine().current_status()
                    job_id = status.get('job_id')
                    if (not isinstance(query, dict) or set(query) != {'job_id'}
                            or not isinstance(job_id, str)
                            or not job_id or query['job_id'] != job_id):
                        raise ValueError('Report job does not match the current export job.')
                    import re
                    if not re.fullmatch(r'[0-9A-Za-z.+_-]{1,120}', job_id):
                        raise ValueError('Invalid report job identifier.')
                    base = os.path.realpath(os.path.join(
                        os.path.dirname(os.path.abspath(__file__)), 'data', 'jobs'))
                    folder = os.path.realpath(os.path.join(base, job_id))
                    if (os.path.commonpath((base, folder)) != base or
                            not os.path.isfile(os.path.join(folder, 'report.json'))):
                        raise RuntimeError('Verified report directory unavailable.')
                    os.startfile(folder)
                    reply = {'ok': True}
                except Exception:
                    reply = {'ok': False, 'error': traceback.format_exc(limit=3)}
                palette.sendInfoToHTML('open_report_folder_result',
                                       json.dumps(reply, ensure_ascii=False))
            elif args.action == 'vault_export_status':
                try:
                    reply = _vault_get_engine().current_status()
                except Exception:
                    reply = {'ok': False, 'error': traceback.format_exc(limit=5)}
                palette.sendInfoToHTML('vault_export_progress', json.dumps(reply, ensure_ascii=False))
            elif args.action == 'get_ui_theme':
                theme = 'light'
                try:
                    app = adsk.core.Application.get()
                    active = app.preferences.generalPreferences.activeUserInterfaceTheme
                    dark = (
                        adsk.core.UserInterfaceThemes.DarkBlueUserInterfaceTheme,
                        adsk.core.UserInterfaceThemes.DarkGrayUserInterfaceTheme,
                    )
                    theme = 'dark' if active in dark else 'light'
                except Exception:
                    pass
                palette.sendInfoToHTML('ui_theme', json.dumps({'theme': theme}))
            elif args.action == 'choose_output_folder':
                try:
                    dialog = _ui.createFolderDialog()
                    if not dialog:
                        raise RuntimeError('Fusion did not create a local folder dialog.')
                    dialog.title = 'F360 Vault - choose backup folder'
                    outcome = dialog.showDialog()
                    if outcome == adsk.core.DialogResults.DialogOK:
                        chosen = os.path.normpath(dialog.folder or '')
                        if not chosen or not os.path.isdir(chosen):
                            raise RuntimeError('The selected local directory is not accessible.')
                        reply = {'ok': True, 'cancelled': False, 'path': chosen}
                    else:
                        reply = {'ok': True, 'cancelled': True}
                except Exception:
                    reply = {'ok': False, 'error': traceback.format_exc(limit=3)}
                palette.sendInfoToHTML(
                    'output_folder_result',
                    json.dumps(reply, ensure_ascii=False),
                )
            elif args.action == 'browse_folder':
                try:
                    request = json.loads(args.data or '{}')
                    response = _read_one_folder(request)
                except Exception:
                    response = {
                        'ok': False,
                        'error': traceback.format_exc(limit=3),
                    }
                palette.sendInfoToHTML(
                    'folder_result',
                    json.dumps(response, ensure_ascii=False),
                )
        except Exception:
            if _ui:
                _ui.messageBox('F360 Vault HTML event error:\n' + traceback.format_exc())


class OpenPaletteExecutedHandler(adsk.core.CommandEventHandler):
    def notify(self, args):
        try:
            _show_palette()
        except Exception:
            if _ui:
                _ui.messageBox('F360 Vault palette error:\n' + traceback.format_exc())


class OpenPaletteCreatedHandler(adsk.core.CommandCreatedEventHandler):
    def notify(self, args):
        on_execute = OpenPaletteExecutedHandler()
        args.command.execute.add(on_execute)
        _handlers.append(on_execute)


class VaultExportTickHandler(adsk.core.CustomEventHandler):
    def notify(self, args):
        try:
            reply = _vault_get_engine().tick(adsk.core.Application.get())
        except Exception:
            reply = {'ok': False, 'status': 'FAILED_SAFE',
                     'error': traceback.format_exc(limit=8)}
        try:
            palette = _ui.palettes.itemById(_PALETTE_ID) if _ui else None
            if palette:
                palette.sendInfoToHTML('vault_export_progress', json.dumps(reply, ensure_ascii=False))
        except Exception:
            if _ui:
                _ui.messageBox('F360 Vault export status error:\n' + traceback.format_exc(limit=5))


def run(context):
    global _ui
    try:
        app = adsk.core.Application.get()
        if not app:
            raise RuntimeError('Fusion application is not available.')
        _ui = app.userInterface
        panel = _ui.allToolbarPanels.itemById(_PANEL_ID)
        if not panel:
            raise RuntimeError('Fusion Design / ADD-INS panel was not found.')

        command_definition = _ui.commandDefinitions.itemById(_COMMAND_ID)
        if not command_definition:
            command_definition = _ui.commandDefinitions.addButtonDefinition(
                _COMMAND_ID,
                'F360 Vault',
                'Open F360 Vault backup and export tool',
                os.path.join(os.path.dirname(__file__), 'resources', 'open'),
            )
        created = OpenPaletteCreatedHandler()
        command_definition.commandCreated.add(created)
        _handlers.append(created)

        button = panel.controls.itemById(_COMMAND_ID)
        if not button:
            button = panel.controls.addCommand(command_definition)
        if not button:
            raise RuntimeError('Fusion did not create the toolbar button.')
        button.isPromotedByDefault = True
        button.isPromoted = True
        tick_event = app.registerCustomEvent(_VAULT_EVENT_ID)
        if tick_event is None:
            raise RuntimeError('Fusion did not register the export custom event.')
        on_tick = VaultExportTickHandler()
        tick_event.add(on_tick)
        _handlers.append(on_tick)
    except Exception:
        if _ui:
            _ui.messageBox('F360 Vault failed to start:\n' + traceback.format_exc())


def stop(context):
    global _ui
    try:
        if not _ui:
            return
        engine = _vault_engine
        if engine is not None:
            snapshot = engine.current_status()
            if snapshot.get('status') in ('RUNNING', 'PAUSED'):
                engine.control('stop')  # Stop between versions before unregistering event.
        app = adsk.core.Application.get()
        if app:
            app.unregisterCustomEvent(_VAULT_EVENT_ID)
        palette = _ui.palettes.itemById(_PALETTE_ID)
        if palette:
            palette.deleteMe()

        panel = _ui.allToolbarPanels.itemById(_PANEL_ID)
        if panel:
            button = panel.controls.itemById(_COMMAND_ID)
            if button:
                button.deleteMe()

        command_definition = _ui.commandDefinitions.itemById(_COMMAND_ID)
        if command_definition:
            command_definition.deleteMe()
    except Exception:
        if _ui:
            _ui.messageBox('F360 Vault failed to stop cleanly:\n' + traceback.format_exc())
    finally:
        _handlers.clear()
        _ui = None