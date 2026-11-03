#!/usr/bin/env python3
"""Build docs/index.html from docs/index.html.template.

Embeds the pinned Mincifry root certificate and its SHA256 fingerprint so the
page works offline and verifies the upstream certificate against the pinned
fingerprint even without network access to the repository files.
"""

import hashlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main() -> None:
    template = (REPO / "docs" / "index.html.template").read_text(encoding="utf-8")
    pem_text = (REPO / "pinned" / "mincifry-root.crt").read_text().strip()
    m = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem_text, re.DOTALL
    )
    if not m:
        sys.exit("no CERTIFICATE block in pinned/mincifry-root.crt")
    body = "\n".join(m.group(1).split())
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    der = hashlib.sha256(bytes(__import__("base64").b64decode(body))).hexdigest().upper()

    out = template.replace("@@UPSTREAM_PEM@@", lines).replace("@@UPSTREAM_SHA256@@", der)
    if "@@" in out:
        sys.exit("unresolved placeholders remain in template output")
    (REPO / "docs" / "index.html").write_text(out, encoding="utf-8")
    print(f"docs/index.html built (upstream sha256: {der})")


if __name__ == "__main__":
    main()
