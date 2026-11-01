"""F360 Vault v0.4.0-dev4: read-only planning of Windows output paths.

This module does NOT create directories or export/modify CAD files.
"""

import hashlib
import ntpath
import os
import re
import unicodedata

_EXTENSIONS = {'step': '.step', 'stl': '.stl', '3mf': '.3mf'}
_WINDOWS_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')
_RESERVED = {'CON', 'PRN', 'AUX', 'NUL'} | {
    '{}{}'.format(prefix, digit) for prefix in ('COM', 'LPT') for digit in range(10)
}
_RESERVED.update({'COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³'})
_MAX_ITEMS = 100000
_MAX_PATH = 240  # conservative: do not assume Windows long-path opt-in


def _digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:10]


def _name(value):
    if not isinstance(value, str) or not value:
        raise ValueError('Empty or invalid cloud name.')
    normalized = unicodedata.normalize('NFC', value)
    cleaned = _WINDOWS_BAD.sub('_', normalized).rstrip(' .')
    if not cleaned or cleaned in ('.', '..'):
        cleaned = '_unnamed_' + _digest(normalized)
    if cleaned.split('.')[0].upper() in _RESERVED:
        cleaned = '_' + cleaned
    if len(cleaned) > 110:
        cleaned = cleaned[:99].rstrip(' .') + '~' + _digest(normalized)
    return cleaned


def _key(path):
    return unicodedata.normalize('NFC', path).casefold()


def _require_preview(preview):
    if not isinstance(preview, dict) or preview.get('kind') != 'read_only_export_preview':
        raise ValueError('Unsupported cloud preview.')
    docs = preview.get('documents')
    settings = preview.get('settings')
    if not isinstance(docs, list) or not isinstance(settings, dict):
        raise ValueError('Incomplete cloud preview.')
    if len(docs) != preview.get('documents_count'):
        raise ValueError('Cloud preview document count mismatch.')
    fmts = settings.get('formats')
    if not isinstance(fmts, list) or not fmts or len(set(fmts)) != len(fmts):
        raise ValueError('Invalid format selection.')
    if any(fmt not in ('native', *tuple(_EXTENSIONS)) for fmt in fmts):
        raise ValueError('Unsupported format.')
    if settings.get('version_mode') not in ('latest', 'all'):
        raise ValueError('Unknown version mode.')
    return docs, settings, fmts


def build_local_plan(preview, check_disk=True):
    """Plan outputs and report conflicts. No writes to output folder.

    Native F3D/F3Z extensions are intentionally unresolved until document
    type is determined; both possible destinations are checked for occupancy.
    """
    documents, settings, formats = _require_preview(preview)
    root = settings.get('output_folder')
    if not isinstance(root, str) or not root or '\x00' in root:
        raise ValueError('Choose a valid output directory.')
    root = ntpath.normpath(root)
    drive, tail = ntpath.splitdrive(root)
    if not drive or not ntpath.isabs(root) or (tail and not tail.startswith('\\')):
        raise ValueError('Destination must be an absolute Windows path.')
    if root.startswith(('\\\\?\\', '\\\\.\\')):
        raise ValueError('Windows device paths are not supported.')
    if check_disk and not os.path.isdir(root):
        raise RuntimeError('Destination folder is not accessible: ' + root)
    if len(root) > _MAX_PATH - 40:
        raise ValueError('Destination path is too long for safe planning.')

    # Folder names alone cannot distinguish different cloud folder IDs.
    # Fail closed for normalized/case-insensitive name collisions.
    seen_folder_names = {}
    seen_files = set()
    entries = []
    folder_warnings = []
    for doc in documents:
        if not isinstance(doc, dict):
            raise ValueError('Invalid cloud document.')
        fid = doc.get('file_id')
        pid = doc.get('project_id')
        paths = doc.get('folder_path')
        versions = doc.get('versions')
        if not isinstance(fid, str) or not fid or not isinstance(pid, str) or not pid:
            raise ValueError('Cloud document ID missing.')
        if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths):
            raise ValueError('Invalid folder ancestry.')
        folder_ids = doc.get('folder_ids')
        if not isinstance(folder_ids, list) or len(folder_ids) != len(paths) or any(
                not isinstance(fid_part, str) or not fid_part for fid_part in folder_ids):
            raise ValueError('Cloud folder identity missing. Refresh preview before planning.')
        project = doc.get('project')
        fname = doc.get('name')
        sourceparts = [project] + paths
        folderparts = []
        for part_number, raw in enumerate(sourceparts):
            mapped = _name(raw)
            parent = _key(ntpath.join(*folderparts)) if folderparts else ''
            k = (parent, _key(mapped))
            identity = pid if part_number == 0 else folder_ids[part_number - 1]
            previous = seen_folder_names.get(k)
            if previous is not None and (previous[0] != raw or previous[1] != identity):
                raise ValueError('Two cloud folders map to the same Windows path: {} / {}'.format(previous[0], raw))
            seen_folder_names[k] = (raw, identity)
            if raw != mapped:
                folder_warnings.append('Renamed folder segment: {} -> {}'.format(raw, mapped))
            folderparts.append(mapped)
        folder = ntpath.join(root, *folderparts)
        if not isinstance(versions, list) or not versions:
            raise ValueError('No versions in cloud document.')
        if settings['version_mode'] == 'latest' and len(versions) != 1:
            raise ValueError('Latest-only preview contains multiple versions.')
        filekey = (pid, fid)
        if filekey in seen_files:
            raise ValueError('Duplicate cloud file in deduplicated preview.')
        seen_files.add(filekey)
        base = _name(fname)
        if base != fname:
            folder_warnings.append('Renamed document: {} -> {}'.format(fname, base))
        for version in versions:
            number = version.get('number') if isinstance(version, dict) else None
            version_id = version.get('id') if isinstance(version, dict) else None
            if not isinstance(number, int) or number < 1 or not isinstance(version_id, str) or not version_id:
                raise ValueError('Invalid cloud version metadata.')
            for fmt in formats:
                entries.append({
                    'project_id': pid, 'file_id': fid, 'version_id': version_id,
                    'version': number, 'format': fmt,
                    'folder': folder, 'stem': base + '__v{:04d}'.format(number),
                    'cloud_name': fname,
                })
                if len(entries) > _MAX_ITEMS:
                    raise ValueError('Path plan exceeds safety item limit.')
    if sum(len(d['versions']) for d in documents) != preview.get('versions_count'):
        raise ValueError('Cloud preview version count mismatch.')

    # Resolve filename collisions by a stable file-ID suffix for colliding
    # documents, with no risky attempt to merge distinct source files.
    groups = {}
    for entry in entries:
        if entry['format'] == 'native':
            ext = '.f3d'  # only for collision grouping; output remains unresolved
        else:
            ext = _EXTENSIONS[entry['format']]
        key = _key(ntpath.join(entry['folder'], entry['stem'] + ext))
        groups.setdefault(key, set()).add(entry['file_id'])
    collisions = {key for key, ids in groups.items() if len(ids) > 1}
    targets = set()
    outputs = []
    occupied = 0
    blocked = 0
    unresolved = 0
    for entry in entries:
        fmt = entry['format']
        ext = '.f3d' if fmt == 'native' else _EXTENSIONS[fmt]
        candidate_key = _key(ntpath.join(entry['folder'], entry['stem'] + ext))
        stem = entry['stem']
        if candidate_key in collisions:
            stem += '~' + _digest(entry['project_id'] + ':' + entry['file_id'])
        possible_exts = ('.f3d', '.f3z') if fmt == 'native' else (ext,)
        candidates = [ntpath.join(entry['folder'], stem + e) for e in possible_exts]
        for path in candidates:
            k = _key(path)
            if k in targets:
                raise ValueError('Non-unique output path after disambiguation.')
            targets.add(k)
        path_too_long = any(len(p) > _MAX_PATH for p in candidates)
        existing = [p for p in candidates if check_disk and os.path.lexists(p)]
        if path_too_long:
            status = 'blocked_long_path'; blocked += 1
        elif existing:
            status = 'occupied'; occupied += 1
        elif fmt == 'native':
            status = 'native_extension_pending'; unresolved += 1
        else:
            status = 'available'
        outputs.append({
            'file_id': entry['file_id'], 'version_id': entry['version_id'],
            'version': entry['version'], 'format': fmt,
            'status': status,
            'target': candidates[0] if fmt != 'native' else None,
            'native_candidates': candidates if fmt == 'native' else None,
            'occupied_paths': existing,
        })
    return {
        'schema_version': 1, 'kind': 'read_only_local_path_plan',
        'preview_created_utc': preview.get('created_utc'),
        'output_folder': root, 'documents_count': len(documents),
        'planned_items': len(outputs), 'occupied_items': occupied,
        'blocked_items': blocked, 'native_pending_items': unresolved,
        'renaming_examples': sorted(set(folder_warnings))[:15],
        'note': 'Dry-run only. Native F3D/F3Z extension unresolved. No export files written.',
        'outputs': outputs,
    }
