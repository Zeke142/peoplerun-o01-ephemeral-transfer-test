"""DN43 separate-process choreography. Deliberately no CLI network entrypoint.
Runner/credential authorization must be independently granted before any live adapter use.
"""
import time
from real_archive_contract import Denied, REAL_SHA, REAL_SIZE, digest, must
from multipart_bridge import (path, publish_handshake, send_real_archive,
                              receive_real_archive, cleanup, require_fresh)

MAX_POLL_SECONDS=600

def wait_for(adapter,session,name,*,clock=time.monotonic,sleep=time.sleep,deadline_seconds=MAX_POLL_SECONDS):
    must(0<deadline_seconds<=MAX_POLL_SECONDS,'deadline_denied')
    dest=path(session,name)
    end=clock()+deadline_seconds
    while clock()<end:
        item=adapter.get(dest)
        if item is not None:return item
        sleep(min(5,max(0,end-clock())))
    raise Denied('wait_expired')

def sender_process(adapter,session,archive,*,epoch=time.time,clock=time.monotonic,sleep=time.sleep):
    """Needs public handshake and private archive, but NEVER receiver private RSA key."""
    try:
        doc=wait_for(adapter,session,'handshake.json',clock=clock,sleep=sleep,deadline_seconds=300)
        # Sender must validate live session binding before using real archive.
        must(doc.get('source_commit')==session.commit and doc.get('source_sha256')==session.source_sha,'binding_denied')
        must(doc.get('public_key_sha256')==session.key_sha,'key_denied')
        must(type(archive) is bytes and len(archive)==REAL_SIZE and digest(archive)==REAL_SHA,'archive_pin_denied')
        return send_real_archive(adapter,session,archive,int(epoch()))
    except Denied:raise
    except Exception:raise Denied('sender_denied') from None
    # Receiver owns cleanup; sender must not delete objects while being consumed.

def receiver_process(adapter,session,private,public_pem,*,epoch=time.time,clock=time.monotonic,sleep=time.sleep):
    """Only receiver owns RSA private key and best-effort, fail-closed cleanup."""
    outcome=None
    try:
        publish_handshake(adapter,session,public_pem,int(epoch()))
        wait_for(adapter,session,'manifest.json',clock=clock,sleep=sleep,
                 deadline_seconds=min(600,max(1,session.created_epoch+600-int(epoch()))))
        outcome=receive_real_archive(adapter,session,private,int(epoch()))
    finally:
        cleanup(adapter,session)
    return outcome
