"""DN42 SOURCE-ONLY reference bridge; no executable GitHub client or credentials.
Public test data metadata + ciphertext may be written by an independently admitted adapter;
never publish private key, AES key or plaintext. Tests use an in-memory adapter.
"""
import base64, hashlib, json, re, time, os
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from real_archive_contract import (Denied, ISOLATED_REPO, REAL_SHA, REAL_SIZE, TTL,
    PART_COUNT, PART_MAX, MAX_PARTS, binding, receive, digest, must, aad)

ALLOWED_FILES = frozenset(["handshake.json", "manifest.json"] + [f"part-{i:03}.txt" for i in range(PART_COUNT)])
TRANSFER_PREFIX = "transfer/"

@dataclass(frozen=True)
class Session:
    repo: str
    run_id: str
    attempt: str
    commit: str
    source_sha: str
    created_epoch: int
    key_sha: str
    def identity(self):
        return binding(self.repo, self.run_id, self.attempt, self.commit, self.source_sha)
    def root(self):
        return f"transfer/{self.run_id}-{self.attempt}/"

def path(session, name):
    session.identity()
    must(name in ALLOWED_FILES, 'path_denied')
    return session.root()+name

def require_fresh(session, now):
    must(type(now) is int and type(session.created_epoch) is int
         and session.created_epoch <= now + 5 and now < session.created_epoch + TTL,
         'expired_denied')

def handshake(session, public_pem):
    must(isinstance(public_pem, bytes) and len(public_pem) <= 1600,'key_denied')
    must(digest(public_pem)==session.key_sha,'key_denied')
    d = {**session.identity(), 'schema':'peoplerun.o01.real-handshake.v1',
         'created_epoch':session.created_epoch,'expires_in_seconds':TTL,
         'public_key_sha256':session.key_sha,'public_key_pem':public_pem.decode('ascii')}
    return d

def admit_handshake(doc, session, now):
    require_fresh(session,now)
    must(isinstance(doc,dict) and doc.get('schema')=='peoplerun.o01.real-handshake.v1','schema_denied')
    must(all(doc.get(k)==v for k,v in session.identity().items()),'binding_denied')
    must(doc.get('created_epoch')==session.created_epoch and doc.get('expires_in_seconds')==TTL,'ttl_denied')
    pem=doc.get('public_key_pem')
    must(isinstance(pem,str) and 0<len(pem.encode())<=1600 and digest(pem.encode())==session.key_sha and doc.get('public_key_sha256')==session.key_sha,'key_denied')
    from cryptography.hazmat.primitives.asymmetric import rsa
    try:
        key=serialization.load_pem_public_key(pem.encode())
        must(isinstance(key,rsa.RSAPublicKey) and key.key_size==3072,'key_denied')
    except (ValueError,TypeError):raise Denied('key_denied') from None
    return key

class MemoryAdapter:
    """No credentials, URLs or networking. Only scoped in-memory objects."""
    def __init__(self):self.objects={};self.events=[];self.fail_on=None
    def put_new(self,p,value):
        if p in self.objects:raise Denied('collision_denied')
        if self.fail_on==('put',p):raise Denied('adapter_denied')
        self.objects[p]=value
        self.events.append(('PUT',p))
    def get(self,p):
        if self.fail_on==('get',p):raise Denied('adapter_denied')
        self.events.append(('GET',p))
        return self.objects.get(p)
    def delete(self,p):
        if self.fail_on==('delete',p):raise Denied('cleanup_denied')
        self.objects.pop(p,None)
        self.events.append(('DELETE',p))

def publish_handshake(adapter,session,public_pem,now):
    require_fresh(session,now)
    obj=handshake(session,public_pem)
    adapter.put_new(path(session,'handshake.json'),obj)
    return {'code':'HANDSHAKE_READY','run_id':session.run_id,'synthetic_only':False}

def send_real_archive(adapter,session,archive,now):
    """The sender needs ONLY the public PEM from the verified handshake."""
    require_fresh(session,now)
    doc=adapter.get(path(session,'handshake.json'))
    public=admit_handshake(doc,session,now)
    must(type(archive) is bytes and len(archive)==REAL_SIZE and digest(archive)==REAL_SHA,'archive_pin_denied')
    b=session.identity()
    key=AESGCM.generate_key(bit_length=256)
    nonce=os.urandom(12)
    cipher=AESGCM(key).encrypt(nonce,archive,aad(b))
    wrapped=public.encrypt(key,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=aad(b)))
    encoded=base64.b64encode(cipher)
    parts=[encoded[i:i+PART_MAX] for i in range(0,len(encoded),PART_MAX)]
    must(len(parts)==PART_COUNT,'part_count_denied')
    manifest={**b,'public_key_sha256':session.key_sha,'created_epoch':session.created_epoch,
       'expires_in_seconds':TTL,'synthetic_only':False,
       'schema':'peoplerun.o01.encrypted-private-input.v1',
       'ciphertext_size':len(cipher),'ciphertext_sha256':digest(cipher),
       'nonce':base64.b64encode(nonce).decode(),
       'wrapped_key':base64.b64encode(wrapped).decode(),
       'parts':[{'name':f'part-{i:03}.txt','sha256':digest(p)} for i,p in enumerate(parts)]}
    for i,chunk in enumerate(parts):adapter.put_new(path(session,f'part-{i:03}.txt'),chunk)
    adapter.put_new(path(session,'manifest.json'),manifest) # manifest last
    return {'code':'MANIFEST_COMMITTED_LAST','parts':len(parts),'archive_sha256':REAL_SHA}

def receive_real_archive(adapter,session,private,now):
    require_fresh(session,now)
    manifest=adapter.get(path(session,'manifest.json'))
    must(manifest is not None,'manifest_missing')
    items=manifest.get('parts') if isinstance(manifest,dict) else None
    must(isinstance(items,list) and len(items)==PART_COUNT,'parts_denied')
    parts=[]
    for i in range(PART_COUNT):
        chunk=adapter.get(path(session,f'part-{i:03}.txt'))
        must(type(chunk) is bytes and 0<len(chunk)<=PART_MAX,'part_missing_or_oversize')
        parts.append(chunk)
    evidence=receive(manifest,parts,session.identity(),private,now)
    must(evidence['archive_sha256']==REAL_SHA and evidence['category']=='ARCHIVE_ACCEPTED_REAL_PIN','archive_pin_denied')
    return {'code':'REAL_ARCHIVE_VERIFIED','bytes':REAL_SIZE,'parts':PART_COUNT,'source_sha256':session.source_sha}

def cleanup(adapter,session):
    """Attempts every owned object; fail closed if any deletion/readback fails."""
    missing=[]
    for name in ['manifest.json']+[f'part-{i:03}.txt' for i in range(PART_COUNT)]+['handshake.json']:
        p=path(session,name)
        try:
            adapter.delete(p)
            if adapter.get(p) is not None:missing.append(name)
        except Exception:missing.append(name)
    must(not missing,'cleanup_denied')
    return {'code':'CLEANUP_PASS','working_tree_absent':True,'history_retained':True}

def offline_acceptance(adapter,session,archive,private,public_pem,now,*,fault=None):
    """Offline orchestrator. Ensures owned cleanup even after intermediate failure.
    In production use separate sender/receiver processes, NEVER share the private key.
    """
    outcome=None
    try:
        publish_handshake(adapter,session,public_pem,now)
        if fault=='after_handshake':raise Denied('injected_denial')
        send_real_archive(adapter,session,archive,now)
        if fault=='after_manifest':raise Denied('injected_denial')
        outcome=receive_real_archive(adapter,session,private,now)
    finally:
        cleanup(adapter,session)
    return outcome
