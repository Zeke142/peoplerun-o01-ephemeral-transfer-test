#!/usr/bin/env python3
"""Isolated public-RSA transport acceptance: synthetic bytes only, no customer data."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = 'Zeke142/peoplerun-o01-ephemeral-transfer-test'
BRANCH = 'main'
TTL = 600
PATH_ROOT = 'transfer'
MAX_BODY = 8192
AUDIT_KEYS = ('repository', 'run_id', 'attempt', 'source_commit', 'session', 'created_epoch')

class Denied(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('ascii')

def identity(env):
    if env.get('GITHUB_REPOSITORY') != REPO or env.get('GITHUB_REF') != 'refs/heads/main':
        raise Denied('identity_denied')
    if env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or env.get('GITHUB_ACTOR') != 'Zeke142' or env.get('GITHUB_RUN_ATTEMPT') != '1':
        raise Denied('event_denied')
    run = env.get('GITHUB_RUN_ID', '')
    commit = env.get('GITHUB_SHA', '')
    if not re.fullmatch(r'[0-9]{5,25}', run) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise Denied('binding_denied')
    return {'repository': REPO, 'run_id': run, 'attempt': '1', 'source_commit': commit}

def transfer_path(meta):
    return f"{PATH_ROOT}/{meta['run_id']}-{meta['attempt']}"

def validate_identity(expected, actual, now, *, requires_key=False):
    if not isinstance(actual, dict) or any(actual.get(k) != expected.get(k) for k in ('repository','run_id','attempt','source_commit','session')):
        raise Denied('binding_denied')
    created = actual.get('created_epoch')
    if type(created) is not int or created > now + 5 or now >= created + TTL:
        raise Denied('expired_or_invalid')
    if requires_key:
        pem = actual.get('public_key_pem')
        if not isinstance(pem,str) or len(pem) > 1600 or not pem.startswith('-----BEGIN PUBLIC KEY-----\n') or not pem.endswith('-----END PUBLIC KEY-----\n'):
            raise Denied('public_key_denied')
        if actual.get('public_key_sha256') != sha(pem.encode()):
            raise Denied('public_key_denied')
    return True

class GitHubAPI:
    def __init__(self, token):
        if not token:
            raise Denied('no_ephemeral_token')
        self.token=token

    def req(self, method, path, obj=None):
        if not re.fullmatch(r'transfer/[0-9]{5,25}-1/(handshake|response)\.json', path):
            raise Denied('path_denied')
        url='https://api.github.com/repos/'+REPO+'/contents/'+path
        if method=='GET':
            url+='?'+urllib.parse.urlencode({'ref':BRANCH})
        if method not in ('GET','PUT','DELETE'):
            raise Denied('method_denied')
        data=None if obj is None else canonical(obj)
        request=urllib.request.Request(url, data=data, method=method, headers={
            'Authorization':'Bearer '+self.token,
            'Accept':'application/vnd.github+json',
            'X-GitHub-Api-Version':'2022-11-28',
            'Content-Type':'application/json',
            'User-Agent':'peoplerun-o01-isolated-acceptance',
            'Cache-Control':'no-cache'})
        try:
            with urllib.request.urlopen(request,timeout=12) as res:
                if res.status not in (200,201):
                    raise Denied('api_status_denied')
                body=res.read(MAX_BODY+1)
                if len(body)>MAX_BODY:raise Denied('api_size_denied')
                return json.loads(body)
        except urllib.error.HTTPError as e:
            if method=='GET' and e.code==404:
                return None
            raise Denied('api_request_denied') from None
        except (urllib.error.URLError,TimeoutError):
            raise Denied('api_request_denied') from None

    def get(self,path):
        res=self.req('GET',path)
        if res is None:return None
        try:
            body=base64.b64decode(res['content'],validate=False)
            if len(body)>MAX_BODY:raise ValueError
            return json.loads(body),res['sha']
        except (ValueError,KeyError,TypeError,json.JSONDecodeError):
            raise Denied('api_content_denied') from None

    def put(self,path,data):
        if self.get(path) is not None:raise Denied('collision_denied')
        obj={'branch':BRANCH,'message':'O01 isolated synthetic acceptance create',
             'content':base64.b64encode(canonical(data)).decode()}
        return self.req('PUT',path,obj)

    def delete(self,path):
        item=self.get(path)
        if item is None:return
        self.req('DELETE',path,{'branch':BRANCH,'sha':item[1],'message':'O01 isolated synthetic acceptance cleanup'})
        if self.get(path) is not None:raise Denied('cleanup_denied')

def crypto(*args,input=None):
    p=subprocess.run(['openssl',*args],input=input,capture_output=True,timeout=12)
    if p.returncode!=0:raise Denied('cryptography_denied')
    return p.stdout

def make_key(folder):
    private=folder/'private.pem'
    public=folder/'public.pem'
    subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',str(private)], stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=50,check=True)
    private.chmod(0o600)
    p=subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)],capture_output=True,timeout=15)
    if p.returncode:raise Denied('cryptography_denied')
    return private,public.read_text()

def encrypt(public,payload,folder):
    pub=folder/'pub.pem';pub.write_text(public)
    return crypto('pkeyutl','-encrypt','-pubin','-inkey',str(pub),'-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha256','-pkeyopt','rsa_mgf1_md:sha256',input=payload)

def decrypt(private,cipher):
    return crypto('pkeyutl','-decrypt','-inkey',str(private),'-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha256','-pkeyopt','rsa_mgf1_md:sha256',input=cipher)

def wait_for(api,path,until):
    while time.monotonic()<until:
        item=api.get(path)
        if item:return item[0]
        time.sleep(5)
    raise Denied('wait_expired')

def receiver(api,meta):
    base=transfer_path(meta)
    hp=base+'/handshake.json'; rp=base+'/response.json'
    if api.get(hp) or api.get(rp):raise Denied('collision_denied')
    with tempfile.TemporaryDirectory(prefix='o01-accept-') as folder:
        private,pub=make_key(Path(folder))
        session=secrets.token_hex(16)
        m={**meta,'session':session,'created_epoch':int(time.time())}
        handshake={**m,'schema':'o01.public-rsa-isolated.v1','public_key_pem':pub,'public_key_sha256':sha(pub.encode()),'ttl_seconds':TTL}
        api.put(hp,handshake)
        try:
            response=wait_for(api,rp,time.monotonic()+TTL)
            validate_identity(m,response,int(time.time()))
            if response.get('schema')!='o01.synthetic-response.v1':raise Denied('schema_denied')
            enc=response.get('ciphertext_base64')
            if not isinstance(enc,str) or len(enc)>600:raise Denied('ciphertext_denied')
            try:cipher=base64.b64decode(enc,validate=True)
            except ValueError:raise Denied('ciphertext_denied') from None
            if len(cipher)!=384:raise Denied('ciphertext_denied')
            plain=decrypt(private,cipher)
            expect=canonical({**m,'test':'synthetic-only-v1'})
            if plain!=expect:raise Denied('payload_binding_denied')
            print('O01_RSA_ACCEPTANCE_PASS synthetic_only=true',flush=True)
        finally:
            # Deletion removes files from branch HEAD, not from Git history.
            errors=[]
            for path in (rp,hp):
                try:api.delete(path)
                except Denied:errors.append('cleanup_denied')
            if errors:raise Denied('cleanup_denied')
    print('O01_CLEANUP_PASS working_tree_absent=true history_retained=true',flush=True)

def sender(api,meta):
    base=transfer_path(meta)
    handshake=wait_for(api,base+'/handshake.json',time.monotonic()+300)
    expected={**meta,'session':handshake.get('session')}
    validate_identity(expected,handshake,int(time.time()),requires_key=True)
    if handshake.get('schema')!='o01.public-rsa-isolated.v1' or handshake.get('ttl_seconds')!=TTL:
        raise Denied('schema_denied')
    with tempfile.TemporaryDirectory(prefix='o01-accept-') as p:
        payload=canonical({**{k:handshake[k] for k in AUDIT_KEYS},'test':'synthetic-only-v1'})
        ciphertext=encrypt(handshake['public_key_pem'],payload,Path(p))
    response={**{k:handshake[k] for k in AUDIT_KEYS},'schema':'o01.synthetic-response.v1',
              'ciphertext_base64':base64.b64encode(ciphertext).decode()}
    api.put(base+'/response.json',response)
    print('O01_RSA_SENDER_SENT synthetic_only=true',flush=True)

def main():
    try:
        meta=identity(os.environ)
        api=GitHubAPI(os.environ.get('GH_TOKEN'))
        if len(sys.argv)!=2 or sys.argv[1] not in ('sender','receiver'):raise Denied('mode_denied')
        {'sender':sender,'receiver':receiver}[sys.argv[1]](api,meta)
    except Denied as e:
        print('O01_RSA_DENIED category='+e.code,flush=True)
        sys.exit(1)
    except Exception:
        print('O01_RSA_DENIED category=unexpected_failure',flush=True)
        sys.exit(1)
if __name__=='__main__':main()
