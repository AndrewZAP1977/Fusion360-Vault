"""F360 Vault dev7: conservative export queue with provenance-backed backup auditing.

This module is loaded by the native Fusion add-in, not a stand-alone script.
No cloud save, no destination overwrite, no automatic closing of user tabs.
"""
import os
import json
import hashlib
import tempfile
import traceback
import uuid
import zipfile
import struct
import re
from datetime import datetime, timezone
from collections import Counter

_ALLOWED = ('native', 'step', 'stl', '3mf')
_EXT = {'step': '.step', 'stl': '.stl', '3mf': '.3mf'}
_FIELDS = ('name', 'visible', 'modified', 'valid', 'data_file_id', 'version_id', 'version_number')
_job = None
_audit_module = None
_aps_module = None


def _aps():
    global _aps_module
    if _aps_module is None:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aps_f3z.py')
        spec = importlib.util.spec_from_file_location('f360vault_dev9_aps_f3z', path)
        if spec is None or spec.loader is None:
            raise RuntimeError('APS F3Z module is missing')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _aps_module = mod
    return _aps_module


def aps_connect():
    return _aps().connect()


def aps_status():
    return _aps().status()



class IntegrityBlockedError(RuntimeError):
    # Typed pre-export refusal: safe to show without a Python traceback.
    error_code = 'INTEGRITY_BLOCKED'

    def __init__(self, problem):
        self.problem = problem
        super().__init__('INTEGRITY_BLOCKED: existing local backup needs review; no exports started.')


def _audit():
    global _audit_module
    if _audit_module is None:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backup_audit.py')
        spec = importlib.util.spec_from_file_location('f360vault_dev7_backup_audit', path)
        if not spec or not spec.loader:
            raise RuntimeError('Backup audit module unavailable.')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _audit_module = module
    return _audit_module


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.vault-report-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for part in iter(lambda: f.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def _validate(path, fmt, has_geometry):
    size = os.path.getsize(path)
    if size < 128:
        raise RuntimeError('Export file is empty/too small.')
    result = {'bytes': size, 'sha256': _hash(path)}
    if fmt in ('f3d', 'f3z', '3mf'):
        with zipfile.ZipFile(path) as z:
            if z.testzip() is not None or not z.namelist():
                raise RuntimeError('Invalid ZIP/CRC in export.')
            result['archive_entries'] = len(z.namelist())
            if fmt == '3mf':
                parts = [s for s in z.namelist() if s.lower().endswith('.model')]
                if not parts:
                    raise RuntimeError('3MF missing 3D model XML.')
                data = b''.join(z.read(p) for p in parts)
                if b'<triangle' not in data or b'<vertex' not in data:
                    raise RuntimeError('3MF mesh geometry missing.')
    elif fmt == 'step':
        with open(path, 'rb') as f:
            data = f.read(min(size, 40 * 1024 * 1024))
        if b'ISO-10303-21' not in data or b'DATA;' not in data:
            raise RuntimeError('STEP header/data missing.')
        if has_geometry and b'ADVANCED_FACE' not in data and b'MANIFOLD_SOLID_BREP' not in data:
            raise RuntimeError('STEP has no expected BRep geometry.')
    elif fmt == 'stl':
        with open(path, 'rb') as f:
            head = f.read(84)
        if len(head) != 84:
            raise RuntimeError('STL header missing.')
        count = struct.unpack_from('<I', head, 80)[0]
        if count < 1 or size != 84 + 50 * count:
            raise RuntimeError('STL binary triangle structure invalid.')
        result['triangles'] = count
    return result


def _snapshot(doc):
    if doc is None:
        raise RuntimeError('Null Fusion document.')
    cloud = doc.dataFile
    snap = {'name': doc.name, 'visible': doc.isVisible, 'modified': doc.isModified,
            'valid': doc.isValid, 'data_file_id': cloud.id if cloud else None,
            'version_id': cloud.versionId if cloud else None,
            'version_number': cloud.versionNumber if cloud else None}
    if not isinstance(snap['name'], str) or not snap['name'] or any(type(snap[k]) is not bool for k in ('visible','modified','valid')):
        raise RuntimeError('Invalid Fusion document snapshot.')
    return snap


def _key(s):
    return tuple(s[k] for k in _FIELDS)


def _documents(app):
    collection = app.documents
    count = collection.count
    if not isinstance(count, int) or count < 1 or count > 60:
        raise RuntimeError('Unexpected number of open documents.')
    snapshots = [_snapshot(collection.item(i)) for i in range(count)]
    if collection.count != count or len({_key(s) for s in snapshots}) != count:
        raise RuntimeError('Documents changed or indistinguishable; unsafe.')
    active = _snapshot(app.activeDocument)
    if Counter(_key(s) for s in snapshots)[_key(active)] != 1 or not active['visible'] or not active['valid']:
        raise RuntimeError('Active user document ambiguous.')
    return snapshots, active


def _verify(app, before, active, owned=None, references=()):
    """Require exact baseline, owned top-level document, and attested references."""
    now, now_active = _documents(app)
    expect = Counter(_key(s) for s in before)
    if owned is not None:
        expect[_key(owned)] += 1
    for reference in references:
        expect[_key(reference)] += 1
    if Counter(_key(s) for s in now) != expect or _key(active) != _key(now_active):
        raise RuntimeError('Document composition or active tab changed: fail safe, do not close.')
    return True


def _attest_new_references(app, before, active, opened, owned):
    """Identify only documents newly loaded as verified references by Fusion.

    No child document is ever closed by F360 Vault. We accept a child only if
    it appeared with the owned assembly, is unmodified, has an exact cloud
    identity and version, and is named by opened.allDocumentReferences.
    """
    now, now_active = _documents(app)
    if _key(active) != _key(now_active):
        raise RuntimeError('Active user document changed while opening assembly.')
    base = Counter(_key(s) for s in before)
    current = Counter(_key(s) for s in now)
    if base - current:
        raise RuntimeError('A pre-existing user document was changed or closed.')
    new = current - base
    if new[_key(owned)] != 1:
        raise RuntimeError('Opened top-level document is not uniquely present.')
    new.subtract(Counter({_key(owned): 1}))
    new += Counter()  # Discard zero/negative counts.
    if not new:
        return ()
    try:
        refs = opened.allDocumentReferences
        if refs is None or not isinstance(refs.count, int) or refs.count < 1 or refs.count > 59:
            raise RuntimeError('Unavailable or invalid assembly reference collection.')
        candidates = Counter()
        for i in range(refs.count):
            ref = refs.item(i)
            if ref is None or not ref.isValid:
                raise RuntimeError('Assembly document reference is invalid.')
            cloud = ref.dataFile
            child = ref.referencedDocument
            if cloud is None or child is None:
                raise RuntimeError('Assembly document reference is unresolved.')
            snap = _snapshot(child)
            if (not snap['valid'] or snap['modified'] or not snap['data_file_id']
                    or not snap['version_id'] or snap['version_number'] is None
                    or cloud.id != snap['data_file_id']
                    or cloud.versionId != snap['version_id']):
                raise RuntimeError('Referenced document identity/version changed or was modified.')
            candidates[_key(snap)] += 1
        if new - candidates:
            raise RuntimeError('An unexpected document opened alongside the assembly.')
        # All extra documents must be separately identifiable; never guess ownership.
        if any(count != 1 for count in new.values()):
            raise RuntimeError('Duplicate newly loaded references are ambiguous.')
        extras = tuple(s for s in now if new[_key(s)])
        _verify(app, before, active, owned, extras)
        return extras
    except Exception as exc:
        raise RuntimeError('Cannot attest automatically opened assembly references: ' + str(exc)) from exc


def _resolve(app, item):
    cloud = app.data.findFileById(item['file_id'])
    if not cloud or cloud.id != item['file_id'] or cloud.name != item['name']:
        raise RuntimeError('Cloud identity/name changed.')
    if not cloud.isComplete:
        raise RuntimeError('Cloud file incomplete.')
    if (cloud.fileExtension or '').lower().lstrip('.') != 'f3d':
        return None, cloud
    if not isinstance(cloud.latestVersionNumber, int) or cloud.latestVersionNumber < item['version']:
        raise RuntimeError('Cloud version no longer exists.')
    if item['mode'] == 'latest' and cloud.latestVersionNumber != item['version']:
        raise RuntimeError('Cloud latest version changed after fresh scan.')
    history = cloud.versions
    if history is None:
        raise RuntimeError('Cloud version collection missing.')
    found = [v for v in history.asArray() if v and v.versionNumber == item['version']]
    if len(found) != 1:
        raise RuntimeError('Cloud version is missing or ambiguous.')
    version = found[0]
    if (version.id != item['file_id'] or version.versionId != item['version_id']
            or version.versionNumber != item['version'] or not version.isComplete
            or (version.fileExtension or '').lower().lstrip('.') != 'f3d'):
        raise RuntimeError('Cloud version ID/extension/completeness mismatch.')
    return version, cloud


def _new_parent(path, root):
    """Create only absent directory segments inside existing, canonical output root."""
    root_real = os.path.normcase(os.path.realpath(root))
    parent = os.path.dirname(path)
    if os.path.commonpath((root_real, os.path.normcase(os.path.realpath(parent)))) != root_real:
        raise RuntimeError('Output folder escapes destination root.')
    relative = os.path.relpath(parent, root)
    current = root
    for segment in ([] if relative == '.' else relative.split(os.sep)):
        current = os.path.join(current, segment)
        if os.path.lexists(current):
            if not os.path.isdir(current) or os.path.islink(current) or os.path.normcase(os.path.realpath(current)) != os.path.normcase(os.path.abspath(current)):
                raise RuntimeError('Output has a symlink/junction/reparse path.')
        else:
            os.mkdir(current)
    if os.path.commonpath((root_real, os.path.normcase(os.path.realpath(parent)))) != root_real:
        raise RuntimeError('Destination folder moved outside root.')


def _options(manager, design, fmt, tmp):
    if fmt in ('f3d', 'f3z'):
        return manager.createFusionArchiveExportOptions(tmp)
    if fmt == 'step':
        return manager.createSTEPExportOptions(tmp)
    if fmt == 'stl':
        opts = manager.createSTLExportOptions(design.rootComponent, tmp)
        if opts:
            opts.isBinaryFormat = True
            opts.isOneFilePerBody = False
            opts.sendToPrintUtility = False
        return opts
    if fmt == '3mf':
        opts = manager.createC3MFExportOptions(design.rootComponent, tmp)
        if opts:
            opts.sendToPrintUtility = False
        return opts
    raise RuntimeError('Unrecognized export format.')


def _write_manual_f3z_list(job):
    """Write a human-readable list only for genuine incomplete F3Z exports.

    This is supplemental job evidence, not a substitute for report.json or the
    persistent SHA-256 provenance. No files in the user backup destination are touched.
    """
    rows = []
    locations = job.get('document_locations', {})
    for record in job.get('records', []):
        unsupported = [f for f in record.get('files', [])
                       if f.get('status') in ('UNSUPPORTED_F3Z', 'APS_AUTH_REQUIRED', 'APS_FAILED', 'APS_PENDING_REMOTE')
                       or (f.get('status') == 'SKIPPED_UNOPENABLE' and f.get('format') == 'f3z')]
        if not unsupported:
            continue
        location = locations.get(record.get('file_id'), {})
        rows.append((location, record, unsupported))
    if not rows:
        return ''
    destination = os.path.join(os.path.dirname(job['report_path']),
                               'Manual_F3Z_Required.txt')
    output = ['F360 Vault - manual F3Z exports required',
              'Job: ' + job['id'],
              'The following linked assemblies are NOT fully backed up.',
              'Export each assembly manually as a complete F3Z from Fusion 360.',
              'Other CAD formats are not substitutes for an archive with links.',
              '', 'Assembly versions requiring action: ' + str(len(rows)), '']
    for number, (location, record, unsupported) in enumerate(rows, 1):
        cloudpath = ' / '.join([location.get('project', '(unknown project)')] +
                                list(location.get('folder_path') or []))
        output.extend([str(number) + '. ' + str(record.get('name', '(unnamed)')),
                       '   Cloud folder: ' + cloudpath,
                       '   Version: v' + str(record.get('version', '?')),
                       '   Cloud file ID: ' + str(record.get('file_id', '')),
                       '   Cloud version ID: ' + str(record.get('version_id', '')),
                       '   Status: ' + str(unsupported[0].get('status')), ''])
    data = ('\n'.join(output) + '\n').encode('utf-8')
    # Write only our own job-local file, atomically. Reuse identical bytes.
    if os.path.exists(destination):
        with open(destination, 'rb') as check:
            if check.read() == data:
                return destination
    directory = os.path.dirname(destination)
    fd, temporary = tempfile.mkstemp(prefix='.manual-f3z-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    return destination


def _event(job, message):
    job['last_message'] = message
    job['updated_utc'] = _utc()
    job['manual_f3z_list'] = _write_manual_f3z_list(job)
    _atomic_json(job['report_path'], {k: v for k, v in job.items() if k not in ('queue','fire','audit_proofs')})
    return {'ok': True, 'job_id': job['id'], 'status': job['status'],
            'completed': job['completed'], 'total': job['total'],
            'passed': job['passed'], 'failed': job['failed'],
            'skipped': job['skipped'], 'unverified': job.get('unverified', 0),
            'newer_versions_count': len(job.get('newer_cloud_versions', [])),
            'newer_versions_sample': job.get('newer_cloud_versions', [])[:8],
            'integrity_verified': job.get('integrity_at_start', {}).get('verified_existing', 0),
            'unfinished_prior_count': len(job.get('incomplete_prior_jobs', [])),
            'retained_temp_count': len(job.get('incomplete_temp_files', [])),
            'document_count': job.get('document_count', 0),
            'documents_completed': len({r.get('file_id') for r in job.get('records', [])
                                        if r.get('file_id')}),
            'up_next_name': (job['queue'][0]['name'] if job.get('queue') else ''),
            'up_next_version': (job['queue'][0]['version'] if job.get('queue') else 0),
            'verified_count': sum(f.get('status') == 'SKIPPED_EXISTS'
                                  for r in job.get('records', []) for f in r.get('files', [])),
            'unopenable_count': sum(r.get('status') == 'SKIPPED_UNOPENABLE' for r in job.get('records', [])),
            'no_geometry_count': sum(f.get('status') == 'NO_GEOMETRY'
                                     for r in job.get('records', []) for f in r.get('files', [])),
            'unsupported_f3z_count': sum(f.get('status') in ('UNSUPPORTED_F3Z', 'APS_AUTH_REQUIRED', 'APS_FAILED', 'APS_PENDING_REMOTE')
                                       for r in job.get('records', []) for f in r.get('files', [])),
            'message': message, 'report': job['report_path'],
            'manual_f3z_list': job.get('manual_f3z_list', '')}


def current_status():
    if _job is None:
        return {'ok': True, 'status': 'IDLE'}
    _finish_aps_if_ready(_job)
    return _event(_job, _job.get('last_message', ''))


def start(request, build_preview, read_settings, settings_path, load_layout, fire):
    global _job
    if _job and _job['status'] in ('RUNNING', 'PAUSED'):
        raise RuntimeError('An export job is already running.')
    if not isinstance(request, dict) or not isinstance(request.get('sources'), list):
        raise ValueError('Invalid export request.')
    settings = read_settings()
    if settings != request.get('settings'):
        raise RuntimeError('Saved settings differ from current UI; wait for settings save.')
    if any(f not in _ALLOWED for f in settings['formats']):
        raise RuntimeError('Unsupported format in settings.')
    root = settings['output_folder']
    if not root or not os.path.isdir(root) or os.path.islink(root):
        raise RuntimeError('Choose an existing output folder; export does not create the root.')
    # Protect previous preview: a fresh cloud scan regenerates last_preview.json.
    state_dir = os.path.join(os.path.dirname(settings_path), 'state')
    prior = os.path.join(state_dir, 'last_preview.json')
    if os.path.isfile(prior):
        backup_dir = os.path.join(os.path.dirname(settings_path), 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        import shutil
        shutil.copy2(prior, os.path.join(backup_dir, 'last_preview.before-export-' + uuid.uuid4().hex + '.json'))
    summary = build_preview({'sources': request['sources'], 'settings': settings})
    with open(prior, 'r', encoding='utf-8') as f:
        preview = json.load(f)
    layout = load_layout()
    plan = layout.build_local_plan(preview, check_disk=True)
    if plan['blocked_items']:
        raise RuntimeError('Output path planner reports too-long/unsafe paths; nothing exported.')
    # A read-only audit happens BEFORE any export file can be written.
    audit = _audit()
    history = audit.load_prior(settings_path, root)
    inspected = audit.audit_plan(plan['outputs'], root, history['proofs'])
    if inspected['corrupt'] or inspected['unsafe'] or inspected['native_conflicts']:
        problem = ((inspected['corrupt'] or inspected['unsafe'] or
                    [{'state': 'NATIVE_CONFLICT', 'path': pair}
                     for pair in inspected['native_conflicts']])[0])
        raise IntegrityBlockedError(problem)
    stale_temps = audit.find_temporary_outputs(plan['outputs'], root)
    new_versions = audit.newly_seen_versions(preview['documents'], history['previous_versions'])
    tasks = {}
    for doc in preview['documents']:
        for ver in doc['versions']:
            k = (doc['file_id'], ver['id'])
            tasks[k] = {'file_id': doc['file_id'], 'name': doc['name'],
                        'version': ver['number'], 'version_id': ver['id'],
                        'mode': settings['version_mode'], 'project_id': doc['project_id'], 'formats': []}
    if not tasks:
        raise RuntimeError('Fresh preview contains no exportable document versions.')
    for out in plan['outputs']:
        k = (out['file_id'], out['version_id'])
        if k not in tasks:
            raise RuntimeError('Path plan disagrees with cloud scan.')
        tasks[k]['formats'].append(out)
    if sum(len(t['formats']) for t in tasks.values()) != plan['planned_items']:
        raise RuntimeError('Path plan cardinality mismatch.')
    ident = _utc().replace(':','-') + '-' + uuid.uuid4().hex[:12]
    base = os.path.join(os.path.dirname(settings_path), 'jobs', ident)
    os.makedirs(base, exist_ok=False)
    _job = {'id': ident, 'kind': 'f360vault_integrated_export', 'status': 'RUNNING',
            'root': root, 'started_utc': _utc(), 'updated_utc': _utc(),
            'report_path': os.path.join(base, 'report.json'),
            'mode': settings['version_mode'], 'formats_selected': settings['formats'],
            'source_count': len(request['sources']), 'fresh_cloud_scan': summary,
            'document_count': len({task['file_id'] for task in tasks.values()}),
            'document_locations': {doc['file_id']: {'project': doc['project'],
                                  'folder_path': doc['folder_path']}
                                  for doc in preview['documents']},
            'total': len(tasks), 'completed': 0, 'passed': 0, 'failed': 0,
            'skipped': 0, 'unverified': 0, 'records': [],
            'integrity_at_start': {'verified_existing': inspected['verified'],
                                   'unverified_existing': inspected['unverified'],
                                   'prior_reports_scanned': history['reports_scanned'],
                                   'prior_pass_proofs': history['proof_records']},
            'incomplete_prior_jobs': history['unfinished_ids'],
            'incomplete_temp_files': stale_temps,
            'newer_cloud_versions': new_versions,
            'last_message': 'Fresh cloud scan and integrity audit complete.',
            'queue': list(tasks.values()), 'fire': fire,
            'audit_proofs': history['proofs']}
    _event(_job, 'Queue prepared: {} versions; {} planned files.'.format(len(tasks), plan['planned_items']))
    fire()
    return _event(_job,
        'Queue started: {} versions; {} prior files SHA-256 verified, {} unverified; '
        '{} unfinished previous jobs, {} retained temporary outputs, {} newer cloud versions.'.format(
            len(tasks), inspected['verified'], inspected['unverified'],
            len(history['unfinished_ids']), len(stale_temps), len(new_versions)))


def control(action):
    if _job is None or _job['status'] not in ('RUNNING', 'PAUSED'):
        raise RuntimeError('No active job.')
    if action == 'pause' and _job['status'] == 'RUNNING':
        _job['status'] = 'PAUSED'
    elif action == 'resume' and _job['status'] == 'PAUSED':
        _job['status'] = 'RUNNING'
        _job['fire']()
    elif action == 'stop':
        _job['status'] = 'STOPPED'
    else:
        raise RuntimeError('Invalid export control command.')
    return _event(_job, 'Export control: ' + action)


def _do_one(app, task, root, proofs):
    import adsk.fusion
    record = {'file_id': task['file_id'], 'version_id': task['version_id'],
              'version': task['version'], 'name': task['name'], 'files': [],
              'status': 'RUNNING'}
    before, active = _documents(app)
    if any(s['data_file_id'] == task['file_id'] or s['version_id'] == task['version_id'] for s in before):
        raise RuntimeError('Target file already open in user session; no ownership.')
    _verify(app, before, active)
    try:
        target, cloud = _resolve(app, task)
    except Exception:
        record['status'] = 'FAILED'
        record['error'] = traceback.format_exc(limit=6)
        return record
    if target is None:
        for f in task['formats']:
            record['files'].append({'format': f['format'], 'status': 'UNSUPPORTED_SOURCE'})
        record['status'] = 'UNSUPPORTED_SOURCE'
        return record
    owned = None
    opened = None
    related = ()
    error = None
    try:
        linked = bool(target.hasChildReferences)
        todo = []
        audit = _audit()
        for output in task['formats']:
            fmt = output['format']
            if output['status'] == 'blocked_long_path':
                record['files'].append({'format': fmt, 'status': 'BLOCKED_PATH'})
                continue
            candidates = audit.candidate_paths(output)
            # Never equate mere file existence with a validated backup.
            existing = [audit.inspect(p, root, proofs) for p in candidates]
            occupied = [entry for entry in existing if entry['state'] != 'ABSENT']
            if fmt == 'native' and len(occupied) > 1:
                raise RuntimeError('Both F3D and F3Z destinations exist: unsafe ambiguity.')
            if any(entry['state'] in ('CORRUPT', 'UNSAFE') for entry in existing):
                raise RuntimeError('Existing backup changed during export: ' + str(occupied)[:700])
            if fmt == 'native' and linked:
                # Only an APS download is a legitimate full F3Z for a linked assembly.
                # Never silently replace it with a Fusion local F3D.
                destination = candidates[1]
                if occupied:
                    found = occupied[0]
                    if found['path'] != destination:
                        raise RuntimeError('Linked assembly has unexpected native F3D; review required.')
                    record['files'].append({'format':'f3z',
                        'status':'SKIPPED_EXISTS' if found['state']=='VERIFIED' else 'SKIPPED_UNVERIFIED',
                        'path':destination, 'integrity':found['state']})
                elif len(destination) > 240:
                    record['files'].append({'format':'f3z', 'status':'BLOCKED_PATH', 'path':destination})
                elif _aps().status()['connected']:
                    record['files'].append({'format':'f3z', 'status':'APS_PENDING', 'path':destination})
                    record['aps_request'] = {'project_id':task['project_id'],
                          'version_id':task['version_id'], 'path':destination}
                else:
                    record['files'].append({'format':'f3z', 'status':'APS_AUTH_REQUIRED',
                        'path':destination,
                        'reason':'Connect Autodesk on the Sources tab, then rerun to back up this assembly.'})
                continue
            if occupied:
                entry = occupied[0]
                status = ('SKIPPED_EXISTS' if entry['state'] == 'VERIFIED'
                          else 'SKIPPED_UNVERIFIED')
                record['files'].append({'format': fmt, 'status': status,
                                        'path': entry['path'],
                                        'integrity': entry['state'],
                                        'proof_job': entry.get('proof_job')})
                continue
            extension = '.f3z' if linked else '.f3d'
            path = candidates[1 if extension == '.f3z' else 0] if fmt == 'native' else candidates[0]
            if len(path) > 240:
                record['files'].append({'format': fmt, 'status': 'BLOCKED_PATH', 'path': path})
                continue
            todo.append((fmt, path))
        if not todo:
            record['status'] = ('APS_PENDING' if any(f['status'] == 'APS_PENDING' for f in record['files'])
                                else 'PARTIAL_SUCCESS' if any(f['status'] in ('UNSUPPORTED_F3Z','APS_AUTH_REQUIRED')
                                                        for f in record['files'])
                                else 'SKIPPED_UNVERIFIED' if any(f['status'] == 'SKIPPED_UNVERIFIED'
                                                                  for f in record['files'])
                                else 'SKIPPED_EXISTS')
            return record
        _verify(app, before, active)
        try:
            opened = app.documents.open(target, False)
        except Exception as exc:
            # Skip unopenable items only when Fusion's active tab and complete
            # document collection exactly match the pre-open snapshot.
            # Any ambiguous/modified state must remain FAILED_SAFE.
            _verify(app, before, active)
            reason = 'Fusion declined to open document: ' + str(exc)[:240]
            for entry in record['files']:
                if entry['status'] == 'APS_PENDING':
                    entry.update(status='SKIPPED_UNOPENABLE', reason=reason)
            for fmt, path in todo:
                kind = ('f3z' if linked else 'f3d') if fmt == 'native' else fmt
                record['files'].append({'format':kind, 'status':'SKIPPED_UNOPENABLE',
                                        'path':path, 'reason':reason})
            record['status'] = 'SKIPPED_UNOPENABLE'
            record['error'] = reason
            return record
        if opened is None:
            raise RuntimeError('Fusion Documents.open returned null; ownership unknown.')
        owned = _snapshot(opened)
        if (owned['data_file_id'] != task['file_id'] or owned['version_id'] != task['version_id']
                or owned['version_number'] != task['version'] or owned['visible'] or owned['modified']
                or not owned['valid']):
            raise RuntimeError('Opened document does not match requested cloud version.')
        related = _attest_new_references(app, before, active, opened, owned)
        if related:
            record['opened_references'] = [dict(s) for s in related]
        _verify(app, before, active, owned, related)
        design = adsk.fusion.Design.cast(opened.products.itemByProductType('DesignProductType'))
        if not design or not design.exportManager:
            raise RuntimeError('Opened file is not exportable as a Fusion Design.')
        root_component = design.rootComponent
        bodies = root_component.bRepBodies.count
        for i in range(root_component.allOccurrences.count):
            bodies += root_component.allOccurrences.item(i).component.bRepBodies.count
        for fmt, path in todo:
            _verify(app, before, active, owned, related)
            if _snapshot(opened) != owned:
                raise RuntimeError('Owned document state changed before export.')
            destfmt = ('.f3z' if linked else '.f3d').lstrip('.') if fmt == 'native' else fmt
            if bodies < 1 and destfmt in ('step','stl','3mf'):
                record['files'].append({'format': destfmt, 'status': 'NO_GEOMETRY', 'path': path})
                continue
            tmp = None
            try:
                _new_parent(path, root)
                if os.path.lexists(path):
                    existing = audit.inspect(path, root, proofs)
                    if existing['state'] in ('CORRUPT', 'UNSAFE'):
                        raise RuntimeError('Backup destination was tampered with: ' + str(existing))
                    record['files'].append({'format': destfmt,
                        'status': 'SKIPPED_EXISTS' if existing['state'] == 'VERIFIED'
                                  else 'SKIPPED_UNVERIFIED',
                        'path': path, 'integrity': existing['state']})
                    continue
                tmp = os.path.join(os.path.dirname(path), '.__fv~' + uuid.uuid4().hex[:10] + os.path.splitext(path)[1])
                if os.path.lexists(tmp):
                    raise RuntimeError('Unexpected temporary export path occupied.')
                opts = _options(design.exportManager, design, destfmt, tmp)
                if opts is None:
                    raise RuntimeError('Fusion did not provide ExportOptions.')
                _verify(app, before, active, owned, related)
                if _snapshot(opened) != owned or os.path.lexists(path):
                    raise RuntimeError('Document or destination changed before execute.')
                if design.exportManager.execute(opts) is not True:
                    raise RuntimeError('Fusion export execute returned false.')
                proof = _validate(tmp, destfmt, bodies > 0)
                # Windows os.rename() refuses to replace an existing target; temp is on same volume.
                if os.path.lexists(path):
                    raise RuntimeError('Target appeared before publication; preserve temporary output.')
                os.rename(tmp, path)
                proofs[audit._canonical(path)] = {'sha256': proof['sha256'],
                                                    'bytes': proof['bytes'],
                                                    'job_id': 'CURRENT_JOB'}
                record['files'].append({'format': destfmt, 'status': 'PASS', 'path': path, 'validation': proof})
            except Exception:
                record['files'].append({'format': destfmt, 'status': 'FAILED', 'path': path,
                                        'error': traceback.format_exc(limit=5),
                                        'temporary_file': tmp if tmp and os.path.lexists(tmp) else None})
            _verify(app, before, active, owned, related)
            if _snapshot(opened) != owned:
                raise RuntimeError('Opened document changed during export.')
        record['status'] = ('APS_PENDING' if any(f['status']=='APS_PENDING' for f in record['files'])
                            else 'PASS' if all(f['status'] in ('PASS', 'SKIPPED_EXISTS', 'NO_GEOMETRY')
                                              for f in record['files']) else 'PARTIAL_SUCCESS')
    except Exception:
        error = traceback.format_exc(limit=8)
        record['error'] = error
        record['status'] = 'FAILED_SAFE'
    finally:
        if opened is not None:
            try:
                if owned is None:
                    raise RuntimeError('Unknown opened-document ownership: leaving open.')
                _verify(app, before, active, owned, related)
                if _snapshot(opened) != owned:
                    raise RuntimeError('Opened document changed: leave open.')
                record['close_started'] = True
                closed = opened.close(False)
                record['close_return_value'] = closed
                if closed is not True:
                    raise RuntimeError('Owned document close(False) returned false.')
                # Fusion must automatically release all references. If any child
                # remains, do not close it: report FAILED_SAFE for manual review.
                _verify(app, before, active)
                record['closed_safe'] = True
            except Exception:
                record['status'] = 'FAILED_SAFE'
                record['close_error'] = traceback.format_exc(limit=8)
                record['needs_manual_check'] = True
    return record


def _final_status(job):
    return ('COMPLETED_WITH_WARNINGS' if (job['unverified'] or any(r.get('status') == 'SKIPPED_UNOPENABLE' for r in job['records'])) and not job['failed']
            else 'COMPLETED' if not job['failed'] else 'PARTIAL_SUCCESS')


def _count_record(job, record):
    files = record.get('files', [])
    job['passed'] += sum(f['status'] == 'PASS' for f in files)
    job['skipped'] += sum(f['status'] in ('SKIPPED_EXISTS','SKIPPED_UNVERIFIED',
                         'UNSUPPORTED_SOURCE','SKIPPED_UNOPENABLE','NO_GEOMETRY') for f in files)
    job['unverified'] += sum(f['status'] == 'SKIPPED_UNVERIFIED' for f in files)
    job['failed'] += sum(f['status'] in ('FAILED','BLOCKED_PATH','UNSUPPORTED_F3Z',
                         'APS_AUTH_REQUIRED','APS_FAILED', 'APS_PENDING_REMOTE') for f in files)
    if record['status'] == 'FAILED':
        job['failed'] += 1
    if record['status'] == 'FAILED_SAFE' or record.get('needs_manual_check'):
        job['failed'] += 1
        job['status'] = 'FAILED_SAFE'
    job['completed'] += 1


def _finish_aps_if_ready(job):
    index = job.get('aps_pending_index')
    if index is None:
        return False
    state = _aps().transfer_status()
    if state['state'] in ('RUNNING','RESERVED','REQUESTING_JOB','JOB_CREATED','IDLE'):
        return False
    record = job['records'][index]
    candidates = [f for f in record['files'] if f['status'] == 'APS_PENDING']
    if len(candidates) != 1:
        job['status'] = 'FAILED_SAFE'
        return False
    file = candidates[0]
    if state['state'] == 'PASS':
        validation = state.get('validation')
        if not validation or not os.path.isfile(file['path']) or _hash(file['path']) != validation.get('sha256'):
            file.update(status='APS_FAILED', reason='Downloaded F3Z validation changed after APS worker.')
        else:
            file.update(status='PASS', validation=validation, aps_download_job_id=state.get('job_id'))
            proof = job['audit_proofs']
            proof[_audit()._canonical(file['path'])] = {'sha256':validation['sha256'],
                'bytes':validation['bytes'], 'job_id':'CURRENT_JOB'}
    elif state['state'] == 'JOB_PENDING':
        file.update(status='APS_PENDING_REMOTE', reason='APS job is still processing; use saved job ID to resume later.')
        file['aps_download_job_id'] = state.get('job_id')
    else:
        file.update(status='APS_FAILED', reason=state.get('error','APS download not completed')[:350])
        file['aps_download_job_id'] = state.get('job_id')
    record['status'] = ('PASS' if all(f['status'] in ('PASS','SKIPPED_EXISTS','NO_GEOMETRY')
                                  for f in record['files']) else 'PARTIAL_SUCCESS')
    job.pop('aps_pending_index', None)
    _count_record(job, record)
    if job['status'] == 'RUNNING':
        if job['queue']:
            job['fire']()
        else:
            job['status'] = _final_status(job)
    return True


def tick(app):
    global _job
    job = _job
    if not job:
        return current_status()
    _finish_aps_if_ready(job)
    if job['status'] != 'RUNNING':
        return current_status()
    if job.get('aps_pending_index') is not None:
        return _event(job, 'APS is building the full F3Z archive in the background.')
    if not job['queue']:
        job['status'] = _final_status(job)
        return _event(job, 'Export queue finished.')
    task = job['queue'].pop(0)
    try:
        record = _do_one(app, task, job['root'], job['audit_proofs'])
    except Exception:
        record = {'file_id':task['file_id'], 'version_id':task['version_id'],
                  'status':'FAILED_SAFE', 'error':traceback.format_exc(limit=8),
                  'needs_manual_check':True, 'files':[]}
    job['records'].append(record)
    if record['status'] == 'APS_PENDING':
        request = record.get('aps_request')
        try:
            if not request or not isinstance(request, dict):
                raise RuntimeError('APS request payload missing')
            _new_parent(request['path'], job['root'])
            _aps().begin(job['report_path'], job['root'], request)
            job['aps_pending_index'] = len(job['records'])-1
            return _event(job, 'APS is creating a full linked-assembly F3Z in the background.')
        except Exception as exc:
            for f in record['files']:
                if f['status']=='APS_PENDING':
                    f.update(status='APS_FAILED', reason=str(exc)[:350])
            record['status'] = 'PARTIAL_SUCCESS'
    _count_record(job, record)
    if job['status'] == 'FAILED_SAFE':
        return _event(job, 'Unsafe/unknown Fusion state. Stop and inspect report.')
    if job['queue']:
        job['fire']()
    else:
        job['status'] = _final_status(job)
    return _event(job, 'Export queue finished.' if not job['queue'] else
           '{}/{} versions; succeeded {}, failed {}, skipped {}.'.format(
               job['completed'],job['total'],job['passed'],job['failed'],job['skipped']))
