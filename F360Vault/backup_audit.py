"""F360 Vault dev7: read-only proof audit for prior local export jobs.

Prior PASS reports are a provenance ledger, not a cryptographically trusted signature.
Unknown outputs must never be overwritten or claimed verified.
No Fusion API, cloud mutations, deletion, or moving of user files.
"""
import hashlib
import json
import os
import re
import unicodedata

_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_TEMP = re.compile(r'^\.__fv~[0-9a-f]{10}\.(?:f3d|f3z|step|stl|3mf)$', re.I)
_FORMATS = {'f3d', 'f3z', 'step', 'stl', '3mf'}


def _canonical(value):
    if not isinstance(value, str) or not value or '\x00' in value:
        raise ValueError('Invalid output path.')
    return unicodedata.normalize('NFC', os.path.normcase(os.path.abspath(value))).casefold()


def _inside(path, root):
    try:
        a, b = _canonical(path), _canonical(root)
        return os.path.commonpath((a, b)) == b and a != b
    except (ValueError, OSError):
        return False


def _safe_path(path, root):
    if not _inside(path, root):
        return False
    root_abs = os.path.abspath(root)
    root_real = os.path.realpath(root_abs)
    if os.path.islink(root_abs) or os.path.normcase(root_abs) != os.path.normcase(root_real):
        return False
    parent = os.path.dirname(os.path.abspath(path))
    try:
        if os.path.commonpath((os.path.normcase(root_real), os.path.normcase(os.path.realpath(parent)))) != os.path.normcase(root_real):
            return False
        rel = os.path.relpath(parent, root_abs)
    except (ValueError, OSError):
        return False
    cur = root_abs
    for part in ([] if rel == '.' else rel.split(os.sep)):
        cur = os.path.join(cur, part)
        if os.path.islink(cur) or (os.path.lexists(cur) and os.path.normcase(os.path.realpath(cur)) != os.path.normcase(os.path.abspath(cur))):
            return False
    return not os.path.islink(path)


def _sha256(path):
    d = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            d.update(b)
    return d.hexdigest()


def load_prior(settings_path, root):
    """Reconstruct most recent PASS per output from previous job reports.

    Preserve original reports. Collect prior RUNNING/PAUSED for crash detection.
    """
    job_root = os.path.join(os.path.dirname(os.path.abspath(settings_path)), 'jobs')
    result = {'proofs': {}, 'previous_versions': {}, 'unfinished_ids': [],
              'reports_scanned': 0, 'proof_records': 0}
    if not os.path.isdir(job_root):
        return result
    folders = sorted(os.scandir(job_root), key=lambda e: e.name)
    if len(folders) > 2500:
        raise RuntimeError('Job history safety limit exceeded; manual audit required.')
    summaries = []
    for folder in folders:
        if not folder.is_dir(follow_symlinks=False):
            continue
        path = os.path.join(folder.path, 'report.json')
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        if os.path.getsize(path) > 24 * 1024 * 1024:
            raise RuntimeError('Job report exceeds safety size: ' + folder.name)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                report = json.load(f)
        except (ValueError, UnicodeError, OSError):
            # An unreadable report cannot authorize skipping a local file.
            continue
        if not isinstance(report, dict) or report.get('kind') != 'f360vault_integrated_export':
            continue
        if not isinstance(report.get('root'), str) or _canonical(report['root']) != _canonical(root):
            continue
        result['reports_scanned'] += 1
        summaries.append((str(report.get('updated_utc', '')), folder.name, report))
    for _, folder_id, report in sorted(summaries):
        status = report.get('status')
        if status in ('RUNNING', 'PAUSED') and report.get('completed', 0) < report.get('total', 0):
            result['unfinished_ids'].append(folder_id)
        for row in report.get('records', []):
            if not isinstance(row, dict):
                continue
            file_id, version = row.get('file_id'), row.get('version')
            if isinstance(file_id, str) and file_id and type(version) is int and version >= 1:
                result['previous_versions'][file_id] = max(result['previous_versions'].get(file_id, 0), version)
            for entry in row.get('files', []):
                if not isinstance(entry, dict) or entry.get('status') != 'PASS' or entry.get('format') not in _FORMATS:
                    continue
                path, proof = entry.get('path'), entry.get('validation')
                if not isinstance(path, str) or not _inside(path, root) or not isinstance(proof, dict):
                    continue
                digest, size = proof.get('sha256'), proof.get('bytes')
                if not isinstance(digest, str) or not _HEX64.fullmatch(digest) or type(size) is not int or size < 128:
                    continue
                result['proofs'][_canonical(path)] = {'sha256': digest, 'bytes': size, 'job_id': folder_id}
                result['proof_records'] += 1
    return result


def inspect(path, root, proofs):
    """Return ABSENT, VERIFIED, UNVERIFIED, CORRUPT, or UNSAFE."""
    if not _safe_path(path, root):
        return {'state': 'UNSAFE', 'path': path}
    if not os.path.lexists(path):
        return {'state': 'ABSENT', 'path': path}
    if not os.path.isfile(path):
        return {'state': 'UNSAFE', 'path': path}
    expected = proofs.get(_canonical(path))
    if not expected:
        return {'state': 'UNVERIFIED', 'path': path, 'reason': 'No previous PASS proof for this exact destination.'}
    actual_size = os.path.getsize(path)
    if actual_size != expected['bytes']:
        return {'state': 'CORRUPT', 'path': path, 'expected_sha256': expected['sha256'],
                'expected_bytes': expected['bytes'], 'actual_bytes': actual_size, 'proof_job': expected['job_id']}
    actual_digest = _sha256(path)
    if actual_digest != expected['sha256']:
        return {'state': 'CORRUPT', 'path': path, 'expected_sha256': expected['sha256'],
                'actual_sha256': actual_digest, 'proof_job': expected['job_id']}
    return {'state': 'VERIFIED', 'path': path, 'sha256': actual_digest, 'proof_job': expected['job_id']}


def candidate_paths(output):
    if not isinstance(output, dict):
        raise ValueError('Invalid planned export item.')
    paths = output.get('native_candidates') if output.get('format') == 'native' else [output.get('target')]
    if not isinstance(paths, list) or not paths or any(not isinstance(p, str) for p in paths):
        raise ValueError('Invalid candidate output paths.')
    return paths


def audit_plan(plan_outputs, root, proofs):
    stats = {'verified': 0, 'unverified': 0, 'absent': 0,
             'corrupt': [], 'unsafe': [], 'native_conflicts': [], 'unknown_paths': []}
    for output in plan_outputs:
        paths = candidate_paths(output)
        present = []
        for path in paths:
            r = inspect(path, root, proofs)
            if r['state'] != 'ABSENT':
                present.append(path)
            if r['state'] == 'VERIFIED':
                stats['verified'] += 1
            elif r['state'] == 'UNVERIFIED':
                stats['unverified'] += 1
                stats['unknown_paths'].append(path)
            elif r['state'] == 'ABSENT':
                stats['absent'] += 1
            elif r['state'] == 'CORRUPT':
                stats['corrupt'].append(r)
            elif r['state'] == 'UNSAFE':
                stats['unsafe'].append(r)
        if output.get('format') == 'native' and len(present) > 1:
            stats['native_conflicts'].append(paths)
    return stats


def find_temporary_outputs(plan_outputs, root):
    """Read-only recognition of interrupted ExportManager temporary files."""
    seen, found = set(), []
    for output in plan_outputs:
        for path in candidate_paths(output):
            parent = os.path.dirname(path)
            if parent in seen or not os.path.isdir(parent) or not _safe_path(path, root):
                continue
            seen.add(parent)
            for entry in os.scandir(parent):
                if _TEMP.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                    found.append(entry.path)
            if len(found) > 1000:
                raise RuntimeError('Excessive interrupted export temporary files; review manually.')
    return sorted(found)


def newly_seen_versions(documents, previous_versions):
    result = []
    for doc in documents:
        old = previous_versions.get(doc.get('file_id'))
        if old is None:
            continue
        newest = doc.get('latest_version')
        if type(newest) is int and newest > old:
            result.append({'file_id': doc['file_id'], 'name': doc.get('name'),
                           'previously_processed_max': old, 'current_cloud_latest': newest})
    return result
