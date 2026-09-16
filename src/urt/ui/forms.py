"""Minimal `application/x-www-form-urlencoded` parsing for the `/ui` forms.

Starlette's `request.form()` needs the optional `python-multipart` package; the
UI only ever posts plain URL-encoded forms, so the stdlib parser is enough and
anything else (JSON, multipart, text/plain) is refused with 415. Refusing other
media types also closes the classic form-enctype CSRF tricks.
"""

from __future__ import annotations

from urllib.parse import parse_qsl

from fastapi import HTTPException, Request

FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"
MAX_FORM_BYTES = 64 * 1024


async def read_form(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_FORM_BYTES:
        # Refuse before reading: the body is never buffered for an oversized post.
        raise HTTPException(status_code=413, detail="Form body too large")
    body = await request.body()
    if not content_type and not body:
        return {}
    if content_type != FORM_MEDIA_TYPE:
        raise HTTPException(status_code=415, detail=f"Form posts must be {FORM_MEDIA_TYPE}")
    if len(body) > MAX_FORM_BYTES:
        raise HTTPException(status_code=413, detail="Form body too large")
    fields: dict[str, str] = {}
    for key, value in parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True):
        fields.setdefault(key, value)
    return fields
