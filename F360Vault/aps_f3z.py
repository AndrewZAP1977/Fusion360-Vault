"""F360 Vault APS F3Z bridge.

Runs Autodesk API I/O in background threads; never touches Fusion API in worker.
No client secret, no persistent tokens, no cloud CAD modifications. Jobs durable.
"""
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile

CLIENT_ID = 'LCMjDTRUAhj7ZSPZ819WuZqMMwPi4TDFV4E8f0TS42DpKvdc'  # public APS app identifier
CALLBACK = 'http://127.0.0.1:8765/oauth/callback/'
API = 'https://developer.api.autodesk.com'
SCOPES = 'data:read data:create'
MAX_WAIT = 240
_LOCK = threading.RLock()
_REFRESH_LOCK = threading.Lock()
_AUTH = {'state': 'DISCONNECTED', 'token': None, 'expires': 0,
         'refresh_token': None, 'error': ''}
_TRANSFER = {'state': 'IDLE', 'ledger': '', 'error': ''}


def _atomic(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    temporary = os.path.join(directory, '.aps-' + secrets.token_hex(12) + '.tmp')
    try:
        with open(temporary, 'x', encoding='utf-8', newline='\n') as out:
            json.dump(data, out, indent=2, ensure_ascii=False)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _status_safe():
    with _LOCK:
        return {'ok': True, 'state': _AUTH['state'],
                'connected': (_AUTH['state'] == 'CONNECTED' and
                               (_AUTH['expires'] > time.time() + 90 or bool(_AUTH['refresh_token']))),
                'error': _AUTH['error'][:250]}


def status():
    return _status_safe()


def _request(path, token, method='GET', payload=None, timeout=40):
    if not path.startswith('/') or path.startswith('//'):
        raise RuntimeError('Unsafe APS relative path')
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        headers['Content-Type'] = 'application/vnd.api+json'
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None
    with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as res:
        return json.loads(res.read(5_000_000).decode('utf-8'))


def _pkce_login():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b'=').decode('ascii')
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    state = secrets.token_urlsafe(24)
    received = {}

    class Callback(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                parts = urllib.parse.urlsplit(self.path)
                params = urllib.parse.parse_qs(parts.query)
                if parts.path != '/oauth/callback/' or params.get('state') != [state] or len(params.get('code', [])) != 1:
                    raise RuntimeError('Invalid callback path/state')
                received['code'] = params['code'][0]
                msg = 'Autodesk authorization received. Return to Fusion 360.'
            except Exception:
                received['error'] = 'OAuth callback rejected'
                msg = 'Autodesk authorization was rejected. Return to Fusion 360.'
            data = ('<!doctype html><meta charset="utf-8"><title>F360 Vault APS</title><p>' + msg + '</p>').encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 8765), Callback)
    server.timeout = 1
    try:
        params = {'response_type': 'code', 'client_id': CLIENT_ID, 'redirect_uri': CALLBACK,
                  'scope': SCOPES, 'state': state, 'code_challenge': challenge,
                  'code_challenge_method': 'S256'}
        url = API + '/authentication/v2/authorize?' + urllib.parse.urlencode(params)
        if not webbrowser.open(url):
            raise RuntimeError('Could not open Autodesk authorization browser.')
        until = time.monotonic() + 300
        while time.monotonic() < until and not received:
            server.handle_request()
        if 'code' not in received:
            raise RuntimeError(received.get('error', 'Autodesk authorization timed out.'))
    finally:
        server.server_close()
    fields = urllib.parse.urlencode({'grant_type': 'authorization_code', 'client_id': CLIENT_ID,
                                     'code': received['code'], 'code_verifier': verifier,
                                     'redirect_uri': CALLBACK}).encode('ascii')
    req = urllib.request.Request(API + '/authentication/v2/token', data=fields,
              headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
    with urllib.request.urlopen(req, timeout=40) as response:
        tokens = json.loads(response.read(200_000).decode('utf-8'))
    token = tokens.get('access_token')
    if not isinstance(token, str) or not token:
        raise RuntimeError('Autodesk did not return an access token.')
    refresh = tokens.get('refresh_token')
    if not isinstance(refresh, str) or not refresh:
        refresh = None
    return token, time.time() + min(int(tokens.get('expires_in', 3600)), 3600), refresh


def _refresh_grant(refresh):
    # Autodesk public-client PKCE refresh: no client secret and no disk writes.
    fields = urllib.parse.urlencode({'grant_type':'refresh_token',
                                     'client_id':CLIENT_ID, 'refresh_token':refresh}).encode('ascii')
    req = urllib.request.Request(API + '/authentication/v2/token', data=fields,
          headers={'Content-Type':'application/x-www-form-urlencoded',
                   'Accept':'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=40) as response:
        tokens = json.loads(response.read(200_000).decode('utf-8'))
    token, rotated = tokens.get('access_token'), tokens.get('refresh_token')
    if not isinstance(token, str) or not token or not isinstance(rotated, str) or not rotated:
        raise RuntimeError('Autodesk refresh reply lacks valid tokens.')
    expires_in = int(tokens.get('expires_in', 0))
    if expires_in < 120:
        raise RuntimeError('Autodesk refresh reply has an invalid expiry.')
    return token, time.time() + min(expires_in, 3600), rotated


def connect():
    with _LOCK:
        if _AUTH['state'] == 'CONNECTING':
            return _status_safe()
        if _AUTH['state'] == 'CONNECTED' and _AUTH['expires'] > time.time() + 90:
            return _status_safe()
        _AUTH.update(state='CONNECTING', token=None, expires=0, refresh_token=None, error='')

    def runner():
        try:
            token, expires, refresh = _pkce_login()
            with _LOCK:
                _AUTH.update(state='CONNECTED', token=token, expires=expires,
                             refresh_token=refresh, error='')
        except Exception as exc:
            with _LOCK:
                _AUTH.update(state='ERROR', token=None, expires=0, refresh_token=None,
                             error=str(exc)[:250])

    threading.Thread(target=runner, daemon=True, name='F360Vault-APS-OAuth').start()
    return _status_safe()


def _token():
    # Runs in the APS worker, not on Fusion's main event thread.
    # Serialize token rotation and renew shortly before the current token expires.
    with _LOCK:
        if _AUTH['state'] != 'CONNECTED':
            raise RuntimeError('APS authorization required; reconnect Autodesk.')
        if _AUTH['expires'] > time.time() + 180:
            return _AUTH['token']
    with _REFRESH_LOCK:
        with _LOCK:
            if _AUTH['state'] != 'CONNECTED':
                raise RuntimeError('APS authorization required; reconnect Autodesk.')
            if _AUTH['expires'] > time.time() + 180:
                return _AUTH['token']
            refresh = _AUTH['refresh_token']
            if not refresh:
                _AUTH.update(state='ERROR', token=None, expires=0,
                             error='APS authorization expired; reconnect Autodesk.')
                raise RuntimeError('APS authorization expired; reconnect Autodesk.')
        try:
            token, expires, rotated = _refresh_grant(refresh)
        except Exception as exc:
            with _LOCK:
                _AUTH.update(state='ERROR', token=None, expires=0, refresh_token=None,
                             error='APS token renewal failed; reconnect Autodesk.')
            raise RuntimeError('APS token renewal failed; reconnect Autodesk.') from exc
        with _LOCK:
            _AUTH.update(state='CONNECTED', token=token, expires=expires,
                         refresh_token=rotated, error='')
            return token


def _validate_cloud_target(project, version):
    if not isinstance(project, str) or not project.startswith('a.') or len(project) > 200:
        raise RuntimeError('Invalid APS project ID')
    if not isinstance(version, str) or not version.startswith('urn:adsk.wipprod:fs.file:') or '?version=' not in version or len(version) > 350:
        raise RuntimeError('Invalid cloud version ID')
    return urllib.parse.quote(project, safe=''), urllib.parse.quote(version, safe='')


def _single_api_object(value, label, optional=False):
    """Resolve an APS singleton JSON resource without guessing between multiple items."""
    if value is None or (optional and value == []):
        if optional:
            return {}
        raise RuntimeError(label + ' missing')
    if isinstance(value, list):
        if len(value) != 1:
            raise RuntimeError(label + ' contains {} resources; manual review required'.format(len(value)))
        value = value[0]
    if not isinstance(value, dict):
        raise RuntimeError(label + ' must be a JSON object')
    return value


def _aps_link(value, label):
    """Extract only a direct href/string, refusing ambiguous list-valued links."""
    if isinstance(value, list):
        if len(value) != 1:
            raise RuntimeError(label + ' contains {} links; manual review required'.format(len(value)))
        value = value[0]
    if isinstance(value, dict):
        value = value.get('href')
    return value if isinstance(value, str) and value.strip() else None


class APSJobFailedError(RuntimeError):
    """Only a confirmed terminal server-side job failure."""


def _job_state(project_enc, job_id, token):
    job_enc = urllib.parse.quote(job_id, safe='')
    path = '/data/v1/projects/' + project_enc + '/jobs/' + job_enc
    req = urllib.request.Request(API + path, headers={'Authorization':'Bearer '+token, 'Accept':'application/json'})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=35) as response:
            data = json.loads(response.read(2_000_000).decode('utf-8'))
            resource = _single_api_object(data.get('data'), 'APS job data')
            attributes = _single_api_object(resource.get('attributes'), 'APS job attributes', optional=True)
            state = str(attributes.get('status', '')).lower()
            if state == 'failed':
                raise APSJobFailedError('APS reported unexpected job state: failed')
            if state not in ('pending', 'queued', 'running', 'processing'):
                raise RuntimeError('APS reported unexpected job state: ' + state)
            return state, ''
    except urllib.error.HTTPError as error:
        if error.code != 303:
            raise
        location = error.headers.get('Location', '')
        if not location:
            raise RuntimeError('APS job is ready but download location is missing.')
        return 'READY', location


def _download_metadata(location, token):
    uri = urllib.parse.urlsplit(urllib.parse.urljoin(API, location))
    if uri.scheme != 'https' or uri.hostname != 'developer.api.autodesk.com' or not uri.path.startswith('/data/v1/projects/'):
        raise RuntimeError('Unsafe APS metadata location')
    return _request(uri.path + ('?' + uri.query if uri.query else ''), token)


def _archive_url(details):
    # APS may encode a single download resource as an object or a one-item array.
    # Never select an arbitrary resource if more than one is returned.
    envelope = _single_api_object(details, 'APS downloads response')
    obj = _single_api_object(envelope.get('data'), 'APS downloads data')
    attributes = _single_api_object(obj.get('attributes'), 'APS download attributes', optional=True)
    links = _single_api_object(obj.get('links'), 'APS download links', optional=True)
    for value, name in ((attributes.get('url'), 'APS attributes.url'),
                        (attributes.get('downloadUrl'), 'APS attributes.downloadUrl'),
                        (attributes.get('link'), 'APS attributes.link'),
                        (links.get('content'), 'APS links.content'),
                        (links.get('download'), 'APS links.download')):
        found = _aps_link(value, name)
        if found:
            return found
    relationships = _single_api_object(obj.get('relationships'), 'APS relationships', optional=True)
    storage = _single_api_object(relationships.get('storage'), 'APS storage', optional=True)
    meta = _single_api_object(storage.get('meta'), 'APS storage.meta', optional=True)
    storage_links = _single_api_object(storage.get('links'), 'APS storage.links', optional=True)
    storage_data = _single_api_object(storage.get('data'), 'APS storage.data', optional=True)
    data_meta = _single_api_object(storage_data.get('meta'), 'APS storage.data.meta', optional=True)
    for value, name in ((meta.get('link'), 'APS storage.meta.link'),
                        (storage_links.get('related'), 'APS storage.links.related'),
                        (data_meta.get('link'), 'APS storage.data.meta.link')):
        found = _aps_link(value, name)
        if found:
            return found
    raise RuntimeError('APS downloads resource has no recognized archive URL')


def _trusted_download(url):
    u = urllib.parse.urlsplit(urllib.parse.urljoin(API, url))
    host = (u.hostname or '').lower()
    suffixes = ('autodesk.com', 'autodesk360.com', 'amazonaws.com', 'cloudfront.net')
    if u.scheme != 'https' or not (host == 'developer.api.autodesk.com' or any(host == s or host.endswith('.'+s) for s in suffixes)):
        raise RuntimeError('Untrusted archive host')
    return u.geturl(), host


def _check_archive(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if z.testzip() is not None:
            raise RuntimeError('F3Z CRC validation failed')
        if 'Manifest.json' not in names or 'DesignDescription.json' not in names:
            raise RuntimeError('Incomplete F3Z manifest')
        children = [n for n in names if n.lower().endswith('.f3d')]
        if len(children) < 2:
            raise RuntimeError('F3Z does not contain referenced F3D designs')
        text = z.read('DesignDescription.json')
        if b'XREF' not in text:
            raise RuntimeError('F3Z lacks an XREF relationship')
        for name in children:
            if z.getinfo(name).file_size > 300_000_000:
                raise RuntimeError('Unreasonably large nested F3D')
        return {'bytes': os.stat(path).st_size, 'sha256': _sha(path), 'archive_entries': len(names),
                'nested_f3d': len(children), 'xref': True}


def _sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for data in iter(lambda: f.read(1024*1024), b''):
            h.update(data)
    return h.hexdigest()


def _worker(ledger):
    path = ledger['ledger']
    try:
        _token()  # Check/renew in memory before processing this APS ledger.
        with open(path, encoding='utf-8') as f:
            info = json.load(f)
        project_enc, version_enc = _validate_cloud_target(info['project_id'], info['version_id'])
        prefix = '/data/v1/projects/' + project_enc
        fmt = _request(prefix + '/versions/' + version_enc + '/downloadFormats', _token())
        if fmt.get('data', {}).get('id') != info['version_id']:
            raise RuntimeError('APS format response did not match cloud version.')
        formats = [str(x.get('fileType','')).lower() for x in fmt.get('data', {}).get('attributes', {}).get('formats', [])]
        if 'f3z' not in formats:
            raise RuntimeError('APS does not advertise a full F3Z for this version.')
        if not info.get('job_id'):
            # Verify/renew credentials BEFORE writing REQUESTING_JOB. A failed
            # token renewal makes no server POST and must remain retryable.
            post_token = _token()
            # Write-before-request is mandatory: uncertain responses must never be retried automatically.
            info['state'] = 'REQUESTING_JOB'
            _atomic(path, info)
            payload = {'jsonapi':{'version':'1.0'}, 'data':{'type':'downloads',
                       'attributes': {'format': {'fileType':'f3z'}},
                       'relationships':{'source':{'data':{'type':'versions','id':info['version_id']}}}}}
            reply = _request(prefix + '/downloads', post_token, method='POST', payload=payload, timeout=60)
            resource = reply.get('data')
            if isinstance(resource, list):
                if len(resource) != 1: raise RuntimeError('Unexpected APS multiple jobs')
                resource = resource[0]
            if not isinstance(resource, dict) or resource.get('type') not in ('jobs', 'downloads') or not resource.get('id'):
                raise RuntimeError('APS job response lacks a unique job ID')
            info['job_id'] = resource['id']
            info['resource_type'] = resource['type']
            info['state'] = 'JOB_CREATED'
            _atomic(path, info)
        details_path = prefix + '/downloads/' + urllib.parse.quote(info['job_id'], safe='')
        if info['resource_type'] == 'jobs':
            until = time.monotonic() + MAX_WAIT
            while time.monotonic() < until:
                state, location = _job_state(project_enc, info['job_id'], _token())
                if state == 'READY':
                    details_path = location
                    break
                time.sleep(5)
            else:
                # Pending is resumable using the saved ID; do not launch another POST.
                info['state'] = 'JOB_PENDING'
                _atomic(path, info)
                return
        details = _download_metadata(details_path, _token())
        remote, host = _trusted_download(_archive_url(details))
        root = info['root']
        output = info['output']
        if os.path.commonpath((os.path.normcase(os.path.realpath(root)),
                               os.path.normcase(os.path.realpath(os.path.dirname(output))))) != os.path.normcase(os.path.realpath(root)):
            raise RuntimeError('F3Z output moved outside selected root')
        if os.path.lexists(output) or os.path.lexists(output+'.partial'):
            raise RuntimeError('F3Z destination or temporary output already exists')
        os.makedirs(os.path.dirname(output), exist_ok=True)
        temporary = output + '.partial'
        url = remote
        # Handle redirects explicitly so no bearer authorization can leak to another host.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        for _ in range(5):
            _, host = _trusted_download(url)
            headers = {'Authorization':'Bearer '+_token()} if host == 'developer.api.autodesk.com' else {}
            req = urllib.request.Request(url, headers=headers)
            try:
                response = opener.open(req, timeout=180)
                break
            except urllib.error.HTTPError as error:
                if error.code not in (301,302,303,307,308) or not error.headers.get('Location'):
                    raise
                url = urllib.parse.urljoin(url, error.headers['Location'])
        else:
            raise RuntimeError('Too many archive download redirects.')
        try:
            with open(temporary, 'xb') as f:
                total = 0
                while True:
                    part = response.read(1024*1024)
                    if not part: break
                    total += len(part)
                    if total > 2_000_000_000: raise RuntimeError('F3Z download exceeds size limit')
                    f.write(part)
                f.flush(); os.fsync(f.fileno())
        finally:
            response.close()
        validation = _check_archive(temporary)
        # A missing local F3Z may be re-downloaded from a previously successful
        # server job. Do not accept a different archive for that same proof.
        previous_sha = info.get('expected_prior_sha256')
        if previous_sha and validation['sha256'] != previous_sha:
            raise RuntimeError('Re-downloaded F3Z SHA-256 differs from prior successful archive; manual review required.')
        if os.path.lexists(output): raise RuntimeError('F3Z target appeared unexpectedly')
        os.rename(temporary, output)
        info.update(state='PASS', validation=validation)
        _atomic(path, info)
    except Exception as exc:
        try:
            with open(path, encoding='utf-8') as f:
                info = json.load(f)
            if (isinstance(exc, APSJobFailedError) and info.get('job_id')
                    and info.get('resource_type') == 'jobs'):
                info['state'] = 'SERVER_FAILED'
                info['server_job_status'] = 'failed'
            else:
                info['state'] = ('ERROR' if info.get('job_id') else
                                 'UNCERTAIN_JOB_CREATION' if info.get('state') == 'REQUESTING_JOB' else
                                 'ERROR_BEFORE_POST')
            if isinstance(exc, urllib.error.HTTPError):
                reason = 'APS HTTP status ' + str(exc.code)
            elif isinstance(exc, urllib.error.URLError):
                reason = 'APS network failure: ' + type(exc.reason).__name__
            else:
                reason = re.sub(r'https?://\S+', '[redacted URL]', str(exc))
            info['error'] = reason[:350]
            _atomic(path, info)
        except Exception:
            pass


def _ledger_location(report, request):
    # Distinct linked designs/versions in one Fusion export job require distinct
    # ledgers. Keep the identity stable so retries cannot POST a duplicate APS job.
    identity = '\n'.join((request['project_id'], request['version_id'],
                           os.path.normcase(os.path.abspath(request['path']))))
    digest = hashlib.sha256(identity.encode('utf-8')).hexdigest()
    return os.path.join(os.path.dirname(report), 'aps_transfer_' + digest + '.json')


def _previous_ledgers(report, current):
    # Include legacy single-ledger jobs plus per-design ledgers, including those
    # in the current job. Never follow arbitrary symlinked job directories/files.
    jobs = os.path.dirname(os.path.dirname(report))
    if not os.path.isdir(jobs):
        return
    for folder in os.listdir(jobs):
        directory = os.path.join(jobs, folder)
        if not os.path.isdir(directory) or os.path.islink(directory):
            continue
        for name in os.listdir(directory):
            if name == 'aps_transfer.json' or re.fullmatch(r'aps_transfer_[0-9a-f]{64}\.json', name):
                prior = os.path.join(directory, name)
                if prior != current and os.path.isfile(prior) and not os.path.islink(prior):
                    yield prior


def _confirmed_server_failure(item):
    """Recognize terminal APS failed, including exact legacy ERROR evidence."""
    if (item.get('resource_type') != 'jobs' or
            not isinstance(item.get('job_id'), str) or not item['job_id']):
        return False
    return ((item.get('state') == 'SERVER_FAILED' and
             item.get('server_job_status') == 'failed') or
            (item.get('state') == 'ERROR' and
             item.get('error') == 'APS reported unexpected job state: failed'))


def _recover_prior_transfer(report, ledger, initial):
    """Resume existing jobs or allow one new POST after confirmed APS failed.

    Do not alter historical ledgers; retain retry provenance in the new ledger.
    Pending/unknown/network outcomes are never grounds for creating a new job.
    """
    groups = {}
    retries = {}
    allowed = {'PASS', 'JOB_CREATED', 'JOB_PENDING', 'ERROR',
               'SERVER_FAILED', 'RESUMING_EXISTING_JOB'}
    uncertain = {'UNCERTAIN_JOB_CREATION', 'REQUESTING_JOB', 'RESERVED'}
    for prior in _previous_ledgers(report, ledger):
        try:
            with open(prior, encoding='utf-8') as src:
                earlier = json.load(src)
        except Exception:
            raise RuntimeError('Uninspectable previous APS transfer ledger; review required.')
        if not isinstance(earlier, dict):
            raise RuntimeError('Invalid previous APS transfer ledger; review required.')
        if (earlier.get('project_id') != initial['project_id'] or
                earlier.get('version_id') != initial['version_id'] or
                os.path.normcase(str(earlier.get('output'))) !=
                os.path.normcase(initial['output'])):
            continue
        state = earlier.get('state')
        if state == 'ERROR_BEFORE_POST' and not earlier.get('job_id'):
            continue
        job_id = earlier.get('job_id')
        if (state in uncertain or state not in allowed or
                not isinstance(job_id, str) or not job_id or
                earlier.get('resource_type') not in ('jobs', 'downloads')):
            raise RuntimeError('Indeterminate previous APS job; manual review required.')
        groups.setdefault(job_id, []).append(earlier)
        retry_of = earlier.get('retry_of_job_id')
        if retry_of is not None:
            if not isinstance(retry_of, str) or not retry_of or retry_of == job_id:
                raise RuntimeError('Invalid APS retry provenance; manual review required.')
            retries.setdefault(job_id, set()).add(retry_of)

    if not groups:
        return
    if retries:
        # A retry already submitted; resume it, but never create a third job.
        if len(retries) != 1:
            raise RuntimeError('Multiple APS retries; manual review required.')
        chosen_id, sources = next(iter(retries.items()))
        if len(sources) != 1 or len(groups) != 2 or next(iter(sources)) not in groups:
            raise RuntimeError('Conflicting APS retry history; manual review required.')
        first_id = next(iter(sources))
        if not any(_confirmed_server_failure(r) for r in groups[first_id]):
            raise RuntimeError('APS retry lacks confirmed original failure.')
        if any(_confirmed_server_failure(r) for r in groups[chosen_id]):
            raise RuntimeError('APS retry also failed; manual review required.')
    else:
        if len(groups) != 1:
            raise RuntimeError('Conflicting prior APS jobs; manual review required.')
        chosen_id = next(iter(groups))
        if any(_confirmed_server_failure(r) for r in groups[chosen_id]):
            if any(r.get('state') == 'PASS' for r in groups[chosen_id]):
                raise RuntimeError('Contradictory APS PASS and failure.')
            # Only a new, explicit export start can authorize this one retry.
            initial.update(retry_of_job_id=chosen_id,
                           state='RETRY_AFTER_CONFIRMED_SERVER_FAILURE')
            return

    records = groups[chosen_id]
    passes = [r for r in records if r.get('state') == 'PASS']
    if passes:
        hashes = set()
        for prior in passes:
            proof = prior.get('validation') or {}
            digest = proof.get('sha256')
            if (not isinstance(digest, str) or
                    re.fullmatch(r'[0-9a-f]{64}', digest) is None or
                    proof.get('xref') is not True or
                    type(proof.get('nested_f3d')) is not int or
                    proof['nested_f3d'] < 2):
                raise RuntimeError('Previous APS PASS lacks safe job/sha proof.')
            hashes.add(digest)
        if len(hashes) != 1:
            raise RuntimeError('Conflicting previous APS file hashes.')
        initial['expected_prior_sha256'] = next(iter(hashes))
    kinds = {row['resource_type'] for row in records}
    if len(kinds) != 1:
        raise RuntimeError('Conflicting previous APS job resource types.')
    initial.update(job_id=chosen_id, resource_type=next(iter(kinds)),
                   state='RESUMING_EXISTING_JOB')
    if retries:
        initial['retry_of_job_id'] = next(iter(retries[chosen_id]))


def begin(report, root, request):
    """Called by Fusion main thread; never waits for cloud HTTP calls."""
    with _LOCK:
        if _TRANSFER['state'] == 'RUNNING':
            raise RuntimeError('Another APS F3Z transfer is still running.')
    if not _status_safe()['connected']:
        raise RuntimeError('APS authorization is not connected.')
    _validate_cloud_target(request['project_id'], request['version_id'])
    output = request['path']
    if not output.lower().endswith('.f3z') or not os.path.isabs(output) or os.path.lexists(output):
        raise RuntimeError('Invalid/occupied F3Z destination.')
    if os.path.commonpath((os.path.normcase(os.path.realpath(root)),
                           os.path.normcase(os.path.realpath(os.path.dirname(output))))) != os.path.normcase(os.path.realpath(root)):
        raise RuntimeError('Unsafe F3Z output root.')
    ledger = _ledger_location(report, request)
    if os.path.lexists(ledger):
        raise RuntimeError('APS transfer ledger already exists: do not create a duplicate APS job.')
    initial = {'schema':1, 'state':'RESERVED', 'project_id':request['project_id'],
               'version_id':request['version_id'], 'output':output, 'root':root,
               'job_id':None, 'resource_type':None, 'error':''}
    # Preserve all old evidence, allowing one explicit retry of terminal APS failed.
    _recover_prior_transfer(report, ledger, initial)
    # Exclusive creation prevents accidentally using a previous transfer ID.
    with open(ledger, 'x', encoding='utf-8') as f:
        json.dump(initial, f, indent=2); f.flush(); os.fsync(f.fileno())
    with _LOCK:
        _TRANSFER.update(state='RUNNING', ledger=ledger, error='')
    def runner():
        try: _worker({'ledger':ledger})
        finally:
            with _LOCK: _TRANSFER['state'] = 'DONE'
    threading.Thread(target=runner, daemon=True, name='F360Vault-APS-F3Z').start()
    return {'state':'RUNNING'}


def transfer_status():
    with _LOCK:
        state = _TRANSFER['state']
        path = _TRANSFER['ledger']
    if not path:
        return {'state':'IDLE'}
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        safe = {'state':data['state'], 'validation':data.get('validation'),
                'error':data.get('error',''), 'job_id':data.get('job_id')}
        if state == 'RUNNING' and safe['state'] not in ('PASS', 'ERROR', 'SERVER_FAILED', 'UNCERTAIN_JOB_CREATION', 'JOB_PENDING'):
            safe['state'] = 'RUNNING'
        return safe
    except Exception as exc:
        return {'state':'ERROR', 'error':'Unable to read APS transfer ledger: '+str(exc)[:150]}
