from typing import Annotated, ReadableBuffer
import hashlib
import hmac
from fastapi import APIRouter, HTTPException, Request, Header, status
import logging
import json

BRANCH_NAME: str = 'esgvoc'
_LOGGER = logging.getLogger('update')
router = APIRouter()


def check_signature(raw_payload: ReadableBuffer | None,
                    secret: str, signature: str | None) -> None:
    if not signature:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='missing X-Hub-Signature-256 in the request header')
    elif not raw_payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='missing body')
    hash_object = hmac.new(secret.encode('utf-8'), msg=raw_payload, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Mismatch signature')


def check_files(files: list[str]) -> bool:
    result = False
    for file in files:
        pass  # TODO
    return result


def check_commit(commit: dict) -> bool:
    if check_files(commit['modified']):
        return True
    elif check_files(commit['added']):
        return True
    elif check_files(commit['removed']):
        return True
    else:
        return False


def check_conditions(payload: dict, event_type: str | None) -> bool:
    if event_type:
        if event_type != 'push':
            _LOGGER.info(f"ignored: event type is '{event_type}'")
            return False
    else:
        msg = 'error: missing event_type'
        _LOGGER.info(msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    if 'ref' in payload:
        if payload['ref'] != f'refs/heads/{BRANCH_NAME}':
            _LOGGER.info(f"ignored: ref is '{payload['ref']}'")
            return False
    else:
        msg = 'error: missing ref'
        _LOGGER.info(msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    if 'commits' in payload:
        has_interesting_files = False
        for commit in payload['commits']:
            if check_commit(commit):
                has_interesting_files = True
                break
        if not has_interesting_files:
            _LOGGER.info('ignored: no interesting file were modified, added or deleted')
            return False
    else:
        msg = 'error: missing commits'
        _LOGGER.info(msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='missing commits')
    return True


@router.post('/update')
async def update(request: Request,
                 x_hub_signature_256: Annotated[str | None, Header()] = None,
                 x_github_event: Annotated[str | None, Header()] = None):
    raw_payload = await request.body()
    check_signature(raw_payload=raw_payload, secret='monsecret', signature=x_hub_signature_256)
    payload = json.loads(raw_payload)
    if check_conditions(payload, x_github_event):
        pass
