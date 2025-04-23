from typing import Annotated
import hashlib
import hmac
from fastapi import APIRouter, HTTPException, Request, Header
import logging
import json

_LOGGER = logging.getLogger()
router = APIRouter()


def verify_signature(payload_body, secret_token, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Raise and return 403 if not authorized.

    Args:
        payload_body: original request body to verify (request.body())
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    if not signature_header:
        raise HTTPException(status_code=403, detail="x-hub-signature-256 header is missing!")
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        _LOGGER.warning('*** SIGNATURE DID NOT MATCH ***')
        #raise HTTPException(status_code=403, detail="Request signatures didn't match!")


@router.post('/update')
async def update(request: Request,
                 x_hub_signature_256: Annotated[str | None, Header()] = None,
                 x_github_event: Annotated[str | None, Header()] = None):
    raw_payload = await request.body()
    verify_signature(payload_body=raw_payload, secret_token='monsecret', signature_header=x_hub_signature_256)
    payload = json.loads(raw_payload)
    _LOGGER.warning(f'event type: {x_github_event}')
    _LOGGER.warning(f'ref: {payload.get("ref")}')
    _LOGGER.warning(f'repository: {payload.get("repository")}')
    _LOGGER.warning(f'commits: {payload.get("commits")}')
