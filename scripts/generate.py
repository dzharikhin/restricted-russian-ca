#!/usr/bin/env python3
"""Generate a personal restricted CA (own root + name-constrained proxy of the
Ministry of Digital Development (Mincifry) root CA).

The proxy carries the Mincifry root's subject and public key but is signed by
the personal root and carries critical nameConstraints limiting trust to the
domains listed in the domains file. The original Mincifry root is never
installed.

Requires only Python 3 stdlib and the openssl CLI (3.x).
"""

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT_SUBJECT_SLASH = "/CN=restricted-russian-ca Personal Root/O=restricted-russian-ca"
UNLIMITED_NOT_AFTER = "99991231235959Z"

IP4_EXCLUDE = "0.0.0.0/0.0.0.0"
IP6_EXCLUDE = "0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0"


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def run(cmd: list[str], stdin: bytes | None = None) -> bytes:
    proc = subprocess.run(cmd, input=stdin, capture_output=True)
    if proc.returncode != 0:
        die(f"command failed: {' '.join(cmd)}\n{proc.stderr.decode(errors='replace')}")
    return proc.stdout


def sha256_der(cert_path: Path) -> str:
    der = run(["openssl", "x509", "-in", str(cert_path), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest().upper()


def parse_domains(text: str) -> list[str]:
    domains: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("*."):
            line = line[2:]
            print(f"note: wildcard stripped (subdomains are covered automatically): *.{line}")
        line = line.rstrip(".").lower()
        if "/" in line or " " in line:
            die(f"invalid domain: {raw.strip()!r}")
        if not re.fullmatch(r"[a-z0-9\-]+(\.[a-z0-9\-]+)*", line):
            try:
                line = line.encode("idna").decode("ascii").lower()
            except UnicodeError:
                die(f"cannot convert domain to punycode: {raw.strip()!r}")
        if not re.fullmatch(r"[a-z0-9\-]+(\.[a-z0-9\-]+)*", line):
            die(f"invalid domain after normalization: {raw.strip()!r}")
        if line not in domains:
            domains.append(line)
    if not domains:
        die("domain list is empty")
    return domains


def domain_covered(domain: str, permitted: list[str]) -> bool:
    return any(domain == p or domain.endswith("." + p) for p in permitted)


def pem_blocks(path: Path) -> list[tuple[str, str]]:
    text = path.read_text()
    blocks = re.findall(
        r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", text, re.DOTALL
    )
    if not blocks:
        die(f"no PEM blocks found in {path}")
    return [(label, body.strip()) for label, body in blocks]


def pem_from_block(label: str, body: str) -> str:
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def read_upstream(cert_path: Path) -> dict:
    out = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-nameopt", "RFC2253"])
    m = re.search(r"subject=(.*)", out.decode())
    if not m:
        die("cannot read upstream subject")
    subject_rfc2253 = m.group(1).strip()

    verify = subprocess.run(
        ["openssl", "verify", "-CAfile", str(cert_path), str(cert_path)],
        capture_output=True,
    )
    if verify.returncode != 0:
        die("upstream certificate is not self-signed/valid — refusing to proceed")

    pubkey = run(["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"]).decode()
    ski = run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-ext", "subjectKeyIdentifier"]
    ).decode()
    m = re.search(r"([0-9A-F]{2}(?::[0-9A-F]{2})+)", ski)
    ski_hex = m.group(1) if m else ""

    return {
        "subject_rfc2253": subject_rfc2253,
        "subject_slash": rfc2253_to_slash(subject_rfc2253),
        "pubkey_pem": pubkey,
        "ski": ski_hex,
        "sha256": sha256_der(cert_path),
    }


def rfc2253_to_slash(dn: str) -> str:
    parts: list[str] = []
    buf = ""
    escaped = False
    for ch in dn:
        if escaped:
            buf += ch
            escaped = False
        elif ch == "\\":
            buf += ch
            escaped = True
        elif ch == ",":
            parts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    parts.reverse()
    for rdn in parts:
        if "/" in rdn:
            die(f"unsupported character in subject DN component: {rdn!r}")
    return "/" + "/".join(parts)


def nc_extfile_lines(domains: list[str]) -> list[str]:
    permitted = ",".join(f"permitted;DNS:{d}" for d in domains)
    return [
        "[ext]",
        f"nameConstraints=critical,{permitted},"
        f"excluded;IP:{IP4_EXCLUDE},excluded;IP:{IP6_EXCLUDE}",
    ]


def write_extfile(tmp: Path, lines: list[str]) -> Path:
    f = tmp / f"ext_{abs(hash(tuple(lines)))}.cnf"
    f.write_text("\n".join(lines) + "\n")
    return f


def validity_args(days: int | None) -> list[str]:
    if days:
        return ["-days", str(days)]
    return ["-not_after", UNLIMITED_NOT_AFTER]


def issue_root_cert(key_path: Path, domains: list[str], days: int | None, tmp: Path) -> bytes:
    ext = write_extfile(
        tmp,
        [
            "[ext]",
            "basicConstraints=critical,CA:true,pathlen:3",
            "keyUsage=critical,keyCertSign,cRLSign",
            "subjectKeyIdentifier=hash",
        ]
        + nc_extfile_lines(domains),
    )
    cmd = [
        "openssl", "req", "-x509", "-new",
        "-key", str(key_path),
        "-subj", ROOT_SUBJECT_SLASH,
        "-sha256",
        "-config", str(ext),
        "-extensions", "ext",
    ] + validity_args(days)
    return run(cmd)


def issue_proxy_cert(
    root_cert: Path,
    root_key: Path,
    upstream: dict,
    domains: list[str],
    days: int | None,
    tmp: Path,
) -> bytes:
    throwaway_key = tmp / "throwaway.key"
    run(
        ["openssl", "genpkey", "-algorithm", "EC",
         "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(throwaway_key)]
    )
    csr = tmp / "proxy.csr"
    run(
        ["openssl", "req", "-new", "-key", str(throwaway_key),
         "-subj", upstream["subject_slash"], "-out", str(csr)]
    )
    upstream_pub = tmp / "upstream.pub"
    upstream_pub.write_text(upstream["pubkey_pem"])
    ext = write_extfile(
        tmp,
        [
            "[ext]",
            "basicConstraints=critical,CA:true,pathlen:2",
            "keyUsage=critical,keyCertSign,cRLSign",
            "subjectKeyIdentifier=hash",
            "authorityKeyIdentifier=keyid",
        ]
        + nc_extfile_lines(domains),
    )
    cmd = [
        "openssl", "x509", "-req", "-in", str(csr),
        "-CA", str(root_cert), "-CAkey", str(root_key),
        "-force_pubkey", str(upstream_pub),
        "-extfile", str(ext), "-extensions", "ext",
        "-sha256",
    ] + validity_args(days)
    return run(cmd)


def new_root_key(tmp: Path) -> Path:
    key = tmp / "root.key"
    run(
        ["openssl", "genpkey", "-algorithm", "EC",
         "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)]
    )
    return key


def cert_pubkey_pem(cert_der_pem: bytes) -> str:
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(cert_der_pem)
        cert_file = Path(f.name)
    try:
        return run(["openssl", "x509", "-in", str(cert_file), "-pubkey", "-noout"]).decode()
    finally:
        cert_file.unlink(missing_ok=True)


def key_pubkey_pem(key_pem: bytes) -> str:
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(key_pem)
        key_file = Path(f.name)
    try:
        return run(["openssl", "pkey", "-in", str(key_file), "-pubout"]).decode()
    finally:
        key_file.unlink(missing_ok=True)


def load_existing_root(pem_path: Path) -> tuple[bytes, bytes]:
    key_block = None
    cert_block = None
    for label, body in pem_blocks(pem_path):
        if "PRIVATE KEY" in label:
            key_block = (label, body)
        elif label == "CERTIFICATE":
            cert_block = (label, body)
    if not key_block or not cert_block:
        die(f"{pem_path} must contain a private key and a certificate")
    key_pem = pem_from_block(*key_block).encode()
    cert_pem = pem_from_block(*cert_block).encode()
    if key_pubkey_pem(key_pem) != cert_pubkey_pem(cert_pem):
        die(f"{pem_path}: certificate does not match the private key")
    return key_pem, cert_pem


def cert_nc_state(cert_pem: bytes) -> tuple[list[str], bool, bool]:
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(cert_pem)
        cert_file = Path(f.name)
    try:
        text = run(
            ["openssl", "x509", "-in", str(cert_file), "-noout", "-text", "-ext", "nameConstraints"]
        ).decode()
    finally:
        cert_file.unlink(missing_ok=True)
    permitted: list[str] = []
    section = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Permitted:"):
            section = "permitted"
        elif line.startswith("Excluded:"):
            section = "excluded"
        elif section == "permitted" and line.startswith("DNS:"):
            permitted.append(line[4:])
    ip4 = IP4_EXCLUDE in text
    ip6 = IP6_EXCLUDE in text
    return permitted, ip4, ip6


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate personal restricted root + name-constrained proxy of the Mincifry root CA."
    )
    ap.add_argument("--domains", default="allowed-domains.txt", help="domains file (default: allowed-domains.txt)")
    ap.add_argument("--upstream", default="pinned/mincifry-root.crt", help="Mincifry root certificate (default: pinned/mincifry-root.crt)")
    ap.add_argument("--root-pem", help="existing root.pem (private key + certificate); a new root is generated if omitted")
    ap.add_argument("--days", type=int, help="validity in days for both certificates (default: unlimited, 9999-12-31)")
    ap.add_argument("--out", default="out", help="output directory (default: out)")
    args = ap.parse_args()

    domains_path = Path(args.domains)
    upstream_path = Path(args.upstream)
    if not domains_path.exists():
        die(f"domains file not found: {domains_path}")
    if not upstream_path.exists():
        die(f"upstream certificate not found: {upstream_path}")

    domains = parse_domains(domains_path.read_text())
    upstream = read_upstream(upstream_path)
    print(f"upstream: {upstream['subject_rfc2253']}")
    print(f"upstream sha256: {upstream['sha256']}")
    print(f"domains ({len(domains)}): {', '.join(domains)}")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="rrca-") as tmp_name:
        tmp = Path(tmp_name)
        root_cert_reissued = False

        if args.root_pem:
            root_pem_path = Path(args.root_pem)
            if not root_pem_path.exists():
                die(f"root.pem not found: {root_pem_path}")
            root_key_pem, root_cert_pem = load_existing_root(root_pem_path)
            permitted, ip4, ip6 = cert_nc_state(root_cert_pem)
            missing = [d for d in domains if not domain_covered(d, permitted)]
            if missing or not ip4 or not ip6:
                root_cert_reissued = True
                reason = []
                if missing:
                    reason.append(f"domains not covered by existing nameConstraints: {', '.join(missing)}")
                if not ip4 or not ip6:
                    reason.append("existing certificate lacks IP exclusions")
                print(f"re-issuing root certificate (same key): {'; '.join(reason)}")
                root_key = tmp / "root.key"
                root_key.write_bytes(root_key_pem)
                root_cert_pem = issue_root_cert(root_key, domains, args.days, tmp)
            else:
                print("existing root certificate covers all domains — reusing it")
        else:
            root_key = new_root_key(tmp)
            root_cert_pem = issue_root_cert(root_key, domains, args.days, tmp)
            root_key_pem = root_key.read_bytes()

        root_cert = tmp / "root.crt"
        root_cert.write_bytes(root_cert_pem)
        proxy_cert = issue_proxy_cert(root_cert, root_key, upstream, domains, args.days, tmp)

        root_pem = root_key_pem + b"\n" + root_cert_pem

        (out_dir / "root.pem").write_bytes(root_pem)
        (out_dir / "root.crt").write_bytes(root_cert_pem)
        (out_dir / "proxy.crt").write_bytes(proxy_cert)
        (out_dir / "domains.txt").write_text("\n".join(domains) + "\n")

    print()
    print(f"root sha256:  {sha256_der(out_dir / 'root.crt')}")
    print(f"proxy sha256: {sha256_der(out_dir / 'proxy.crt')}")
    if root_cert_reissued or not args.root_pem:
        print(f"\noutputs:\n  {out_dir / 'root.pem'}   (PRIVATE KEY + CERTIFICATE, keep it safe!)")
    else:
        print("\noutputs:")
    print(f"  {out_dir / 'root.crt'}")
    print(f"  {out_dir / 'proxy.crt'}")
    print(f"  {out_dir / 'domains.txt'}")


if __name__ == "__main__":
    main()
