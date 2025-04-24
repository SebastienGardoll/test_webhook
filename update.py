from typing import Annotated
import hashlib
import hmac
from fastapi import APIRouter, HTTPException, Request, Header, status
import logging
import json
from pathlib import PurePath, Path
from datetime import datetime


BRANCH_NAME: str = 'esgvoc'
FILE_OF_INTEREST_SUFFIX = '.json'
GH_WEB_HOOK_SECRET_FILE_NAME = 'gh_web_hook_secret'
GH_WEB_HOOK_SECRET_FILE_PATH = Path(f'/run/secrets/{GH_WEB_HOOK_SECRET_FILE_NAME}')
UPDATE_DIR_PATH = Path('update')
UPDATE_FILE_PATH = UPDATE_DIR_PATH.joinpath('mark')
_LOGGER = logging.getLogger(__name__)


router = APIRouter()

GH_WEB_HOOK_SECRET: str | None = None
if GH_WEB_HOOK_SECRET_FILE_PATH.exists():
    with open(GH_WEB_HOOK_SECRET_FILE_PATH, 'r') as file:
        GH_WEB_HOOK_SECRET = file.read()
else:
    _LOGGER.error('missing GitHub web hook secret (route update is disabled)')


def check_signature(raw_payload: bytes, signature: str, secret: str) -> bool:
    hash_object = hmac.new(secret.encode('utf-8'), msg=raw_payload, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    # Do not raise an exception: security best practices.
    return hmac.compare_digest(expected_signature, signature)


def check_files(files: list[str]) -> bool:
    result = False
    for file in files:
        try:
            file_path = PurePath(file)
            if FILE_OF_INTEREST_SUFFIX == file_path.suffix:
                return True
        except Exception:
            continue
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


def check_payload(raw_payload: bytes | None, event_type: str | None,
                  signature: str | None, secret: str) -> bool:
    if not signature:
        msg = 'missing X-Hub-Signature-256 in the request header'
        _LOGGER.info(msg)
        _LOGGER.info('return 403')
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)
    elif not raw_payload:
        msg = 'missing body'
        _LOGGER.info(msg)
        _LOGGER.info('return 400')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    """
    if not check_signature(raw_payload=raw_payload, signature=signature, secret=secret):
        # Do not raise an exception: security best practices.
        _LOGGER.info('mismatch signature')
        return False
    """
    if event_type:
        if event_type != 'push':
            _LOGGER.info(f"event type '{event_type}' not supported")
            return False
    else:
        msg = 'missing event_type'
        _LOGGER.info(msg)
        _LOGGER.info('return 400')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    payload = json.loads(raw_payload)
    if 'ref' in payload:
        if payload['ref'] != f'refs/heads/{BRANCH_NAME}':
            _LOGGER.info(f"ref '{payload['ref']}' not supported")
            return False
    else:
        msg = 'missing ref'
        _LOGGER.info(msg)
        _LOGGER.info('return 400')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    if 'commits' in payload:
        has_interesting_files = False
        for commit in payload['commits']:
            if check_commit(commit):
                has_interesting_files = True
                break
        if not has_interesting_files:
            _LOGGER.info('no interesting file')
            return False
    else:
        msg = 'missing commits'
        _LOGGER.info(msg)
        _LOGGER.info('return 400')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='missing commits')
    return True


@router.post('/update')
async def update(request: Request,
                 x_hub_signature_256: Annotated[str | None, Header()] = None,
                 x_github_event: Annotated[str | None, Header()] = None) -> None:
    if GH_WEB_HOOK_SECRET:
        raw_payload = await request.body()
        _LOGGER.info(f'web hook payload: {raw_payload}')
        if check_payload(raw_payload, x_github_event, x_hub_signature_256, GH_WEB_HOOK_SECRET):
            _LOGGER.info('checks passed')
            if UPDATE_FILE_PATH.exists():
                _LOGGER.info('update file already exists (skip)')
            else:
                file_content = [f'date: {datetime.now()}\n',
                                f'web hook payload:\n\n{json.loads(raw_payload)}']
                with open(UPDATE_FILE_PATH, 'w') as file:
                    file.writelines(file_content)
                _LOGGER.info('update file written')
        else:
            _LOGGER.info('ignore')
    else:
        _LOGGER.error('missing GitHub web hook secret (route disable)')
