"""DN40 local-only contract. No GitHub/host networking, writes, or production archive."""
import base64, hashlib, json, re, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ORIGINAL_REPO='Zeke142/peoplerun-wp-adapter'
ISOLATED_REPO='Zeke142/peoplerun-o01-ephemeral-transfer-test'
REAL_SIZE=1047421
REAL_SHA='b266241398c3f22bbc58a5b8d28250fcf6d8894257cf697a50c0eecf0cca5871'
PART_MAX=32768
PART_COUNT=43
TTL=600
MAX_PARTS=64
class Denied(Exception): pass
def must(ok, code):
    if not ok: raise Denied(code)
def digest(b):return hashlib.sha256(b).hexdigest()
def binding(repo, run, attempt, commit, source_sha, archive_sha=REAL_SHA):
    must(repo == ISOLATED_REPO, 'repo_denied')
    must(re.fullmatch(r'[0-9]{5,25}',run) is not None and attempt=='1','run_denied')
    must(re.fullmatch(r'[0-9a-f]{40}',commit) is not None,'commit_denied')
    must(re.fullmatch(r'[0-9a-f]{64}',source_sha) is not None,'source_denied')
    must(re.fullmatch(r'[0-9a-f]{64}',archive_sha) is not None,'archive_denied')
    return {'repository':repo,'run_id':run,'attempt':attempt,'source_commit':commit,'source_sha256':source_sha,'archive_sha256':archive_sha}
def aad(b):
    return json.dumps(b,sort_keys=True,separators=(',',':')).encode()
def encrypt(archive, b, private, created_epoch, *, synthetic=False):
    must(len(archive)==REAL_SIZE,'length_denied')
    # The production contract cannot accept synthetic bytes as the real PIN.
    if not synthetic:must(digest(archive)==REAL_SHA,'archive_pin_denied')
    public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    m={**b,'public_key_sha256':digest(public),'created_epoch':created_epoch,'expires_in_seconds':TTL,'synthetic_only':bool(synthetic)}
    key=AESGCM.generate_key(bit_length=256);nonce=__import__('os').urandom(12)
    cipher=AESGCM(key).encrypt(nonce,archive,aad(b))
    wrapped=private.public_key().encrypt(key,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=aad(b)))
    encoded=base64.b64encode(cipher)
    parts=[encoded[i:i+PART_MAX] for i in range(0,len(encoded),PART_MAX)]
    must(len(parts)==PART_COUNT,'part_count_denied')
    manifest={**m,'schema':'peoplerun.o01.encrypted-private-input.v1','ciphertext_size':len(cipher),'ciphertext_sha256':digest(cipher),'nonce':base64.b64encode(nonce).decode(),'wrapped_key':base64.b64encode(wrapped).decode(),'parts':[{'name':f'part-{i:03}.txt','sha256':digest(part)} for i,part in enumerate(parts)]}
    return manifest,parts

def receive(manifest,parts,b,private,now,*,synthetic=False):
    must(isinstance(manifest,dict),'manifest_denied')
    must(all(manifest.get(k)==v for k,v in b.items()),'binding_denied')
    must(manifest.get('schema')=='peoplerun.o01.encrypted-private-input.v1','schema_denied')
    must(manifest.get('synthetic_only') is synthetic,'mode_denied')
    created=manifest.get('created_epoch')
    must(type(created) is int and created<=now+5 and now < created+TTL,'expired_denied')
    must(manifest.get('expires_in_seconds')==TTL,'ttl_denied')
    public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    must(manifest.get('public_key_sha256')==digest(public),'key_denied')
    items=manifest.get('parts')
    must(isinstance(items,list) and len(items)==PART_COUNT==len(parts) and len(items)<=MAX_PARTS,'parts_denied')
    chunks=[]
    for i,(entry,part) in enumerate(zip(items,parts)):
        must(type(entry) is dict and entry.get('name')==f'part-{i:03}.txt','part_order_denied')
        must(type(part) is bytes and 0<len(part)<=PART_MAX and entry.get('sha256')==digest(part),'part_integrity_denied')
        chunks.append(part)
    try: cipher=base64.b64decode(b''.join(chunks),validate=True)
    except Exception:raise Denied('encoding_denied') from None
    must(len(cipher)==REAL_SIZE+16==manifest.get('ciphertext_size') and digest(cipher)==manifest.get('ciphertext_sha256'),'cipher_denied')
    try:
        wrapped=base64.b64decode(manifest['wrapped_key'],validate=True)
        nonce=base64.b64decode(manifest['nonce'],validate=True)
        key=private.decrypt(wrapped,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=aad(b)))
        must(len(key)==32 and len(nonce)==12,'key_size_denied')
        clear=AESGCM(key).decrypt(nonce,cipher,aad(b))
    except Exception:raise Denied('decrypt_denied') from None
    must(len(clear)==REAL_SIZE,'plaintext_length_denied')
    if not synthetic:must(digest(clear)==REAL_SHA,'archive_pin_denied')
    return {'category':'ARCHIVE_ACCEPTED_SYNTHETIC' if synthetic else 'ARCHIVE_ACCEPTED_REAL_PIN','bytes':len(clear),'archive_sha256':digest(clear),'plaintext_not_persisted':True}
