"""How a bundle file is handed to a browser, decided once for the API and `urt view`.

Text-like files are served inline with a fixed media type. Everything else —
HTML, binaries, unknown suffixes — is a download (`Content-Disposition:
attachment`) so attacker-influenced tool output never renders in the serving
origin. The one exception is the viewer we rendered ourselves (`report.html` at
the bundle root), which the caller must opt into explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .constants import (
    ARTIFACT_ATTACHMENT_MEDIA_TYPES,
    ARTIFACT_INLINE_MEDIA_TYPES,
    ARTIFACT_RESPONSE_HEADERS,
)

VIEWER_FILE = "report.html"


@dataclass(slots=True)
class ArtifactResponsePolicy:
    media_type: str
    inline: bool
    headers: dict[str, str]
    filename: str

    @property
    def content_disposition(self) -> str | None:
        if self.inline:
            return None
        safe_name = self.filename.replace('"', "").replace("\r", "").replace("\n", "")
        return f'attachment; filename="{safe_name}"'


def artifact_response_policy(relative_path: str) -> ArtifactResponsePolicy:
    """Policy for one bundle-relative path (never for the viewer itself; see `is_viewer_file`)."""
    name = PurePosixPath(relative_path).name
    suffix = PurePosixPath(name).suffix.lower()
    headers = dict(ARTIFACT_RESPONSE_HEADERS)
    if suffix in ARTIFACT_INLINE_MEDIA_TYPES:
        return ArtifactResponsePolicy(ARTIFACT_INLINE_MEDIA_TYPES[suffix], True, headers, name)
    media_type = ARTIFACT_ATTACHMENT_MEDIA_TYPES.get(suffix, "application/octet-stream")
    return ArtifactResponsePolicy(media_type, False, headers, name)


def is_viewer_file(relative_path: str) -> bool:
    """True only for the bundle-root `report.html` that Redplane rendered."""
    return relative_path == VIEWER_FILE
