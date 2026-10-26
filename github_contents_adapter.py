"""DN43 candidate, inert unless explicitly constructed with approved sender/receiver credentials.
The adapter makes repository-wide GitHub token risk explicit; path guards are code-only,
not GitHub permission boundaries. Never write plaintext, keys or archive bytes to Git.
"""
import base64
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from real_archive_contract import Denied, ISOLATED_REPO
from multipart_bridge import ALLOWED_FILES

BRANCH = 'main'
MAX_OBJECT = 160_000  # GitHub JSON with base64 content for <=32768-byte part
MAX_READ = 250_000
_SHA = re.compile(r'^[0-9a-f]{40}$')
_RUN = re.compile(r'^[0-9]{5,25}$')
_PART = re.compile(r'^part-[0-9]{3}\.txt$')

class GitHubContentsAdapter:
    """Bounded, per-run Github Contents API adapter with injected transport for offline tests.

    token deliberately provided only by an authorized process and not stored in receipts.
    transport(request, timeout) must return (status:int, body:bytes).
    GitHub's token cannot be limited to a file path; deny-by-default code is not IAM.
    """
    def __init__(self, run_id, attempt, token, *, transport=None, repo=ISOLATED_REPO):
        if repo != ISOLATED_REPO or not _RUN.fullmatch(str(run_id)) or str(attempt) != '1':
            raise Denied('identity_denied')
        if not isinstance(token,str) or not token or any(c in token for c in '\r\n'):
            raise Denied('credential_denied')
        self.root = f'transfer/{run_id}-1/'
        self._token = token
        self._transport = transport or self._http
        self.last_methods = []

    @staticmethod
    def _http(request, timeout):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read(MAX_READ+1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return 404, b'{}'
            raise Denied('github_http_denied') from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Denied('github_transport_denied') from None

    def _name(self, p):
        if not isinstance(p,str) or not p.startswith(self.root):
            raise Denied('path_denied')
        name=p[len(self.root):]
        if name not in ALLOWED_FILES or '/' in name or '\\' in name or '?' in name or '#' in name:
            raise Denied('path_denied')
        return name

    def _request(self,method,p,payload=None):
        self._name(p)
        if method not in ('GET','PUT','DELETE'):
            raise Denied('method_denied')
        url='https://api.github.com/repos/'+ISOLATED_REPO+'/contents/'+p
        if method=='GET':url+='?'+urllib.parse.urlencode({'ref':BRANCH})
        if payload is not None:
            body=json.dumps(payload,sort_keys=True,separators=(',',':')).encode('ascii')
            if len(body)>MAX_OBJECT:raise Denied('request_size_denied')
        else: body=None
        req=urllib.request.Request(url, data=body,method=method,headers={
            'Authorization':'Bearer '+self._token,
            'Accept':'application/vnd.github+json',
            'X-GitHub-Api-Version':'2022-11-28',
            'Content-Type':'application/json',
            'User-Agent':'peoplerun-o01-dn43',
            'Cache-Control':'no-cache'})
        self.last_methods.append(method)
        try:
            status,raw=self._transport(req,12)
        except Denied:raise
        except Exception:raise Denied('github_transport_denied') from None
        if len(raw)>MAX_READ:raise Denied('response_size_denied')
        if status==404 and method=='GET':return None
        if status not in ((200,) if method=='GET' else (200,201)):
            raise Denied('github_status_denied')
        try:
            response=json.loads(raw)
            if not isinstance(response,dict):raise ValueError
            return response
        except (ValueError,UnicodeDecodeError,TypeError):
            raise Denied('github_json_denied') from None

    @staticmethod
    def _encode(obj):
        if isinstance(obj,bytes):data=obj
        elif isinstance(obj,dict):data=json.dumps(obj,sort_keys=True,separators=(',',':')).encode('ascii')
        else:raise Denied('object_type_denied')
        if not 0<len(data)<=32768:raise Denied('object_size_denied')
        return data

    def _get_raw(self,p):
        d=self._request('GET',p)
        if d is None:return None
        try:
            raw=base64.b64decode(d['content'].replace('\n',''),validate=True)
            gitsha=d['sha']
            if not _SHA.fullmatch(gitsha) or not 0<len(raw)<=32768:raise ValueError
            # GitHub blob SHA verification prevents silent response-content mismatch.
            if hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\x00'+raw).hexdigest()!=gitsha:raise ValueError
            return raw,gitsha
        except (ValueError,TypeError,KeyError,AttributeError):
            raise Denied('github_content_denied') from None

    def get(self,p):
        name=self._name(p)
        row=self._get_raw(p)
        if row is None:return None
        data=row[0]
        if _PART.fullmatch(name):return data
        try:
            result=json.loads(data)
            if not isinstance(result,dict):raise ValueError
            return result
        except (ValueError,UnicodeDecodeError):
            raise Denied('github_content_denied') from None

    def put_new(self,p,value):
        self._name(p)
        if self._get_raw(p) is not None:raise Denied('collision_denied')
        data=self._encode(value)
        body={'branch':BRANCH,'message':'DN43 ephemeral encrypted transfer object',
              'content':base64.b64encode(data).decode('ascii')}
        self._request('PUT',p,body)
        row=self._get_raw(p)
        if row is None or row[0]!=data:raise Denied('write_readback_denied')

    def delete(self,p):
        self._name(p)
        row=self._get_raw(p)
        if row is None:return
        body={'branch':BRANCH,'message':'DN43 remove ephemeral transfer branch object','sha':row[1]}
        self._request('DELETE',p,body)
        if self._get_raw(p) is not None:raise Denied('cleanup_denied')
