#!/usr/bin/env python3
"""Cross-validation of the JS implementation (web/generate.mjs) with an
independent stack: Python stdlib + openssl CLI.

Generation happens once, in JS — the same code the browser page runs
(web/src/ca.js). This script never generates certificates itself (except
openssl-made throwaway leaves used to probe name constraint behavior) and
instead validates the CLI output with openssl's independent PKIX engine:

  1. test hierarchy (fake upstream in the shape of the real one): an allowed
     domain validates through root -> proxy -> subCA -> leaf, a blocked domain
     fails with a permitted-subtree violation, IP-SAN leaves are rejected;
  2. real world structure (needs network): the actual Mincifry root is
     downloaded from the sources listed in mincifry-certs/fingerprints.json
     (official gu-st.ru first), its SHA256 is checked against the pinned
     fingerprint, and the real sub-CA verifies against the generated
     personal root + proxy. Skipped with a warning when offline;
  3. optional live E2E (--e2e): real TLS handshakes are verified against the
     generated bundle.

Used by CI on every push (and weekly with --e2e). Requires Node.js 20+ with
`cd web && npm ci` (the CLI needs pkijs), Python 3 stdlib and the openssl CLI.
Network access is needed for the real-chain checks and --e2e (skipped when
offline).
"""

import argparse
import json
import subprocess
import sys
import hashlib
import json
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

JS_CLI = REPO / "web" / "generate.mjs"
FINGERPRINTS = REPO / "mincifry-certs" / "fingerprints.json"

FAKE_UPSTREAM_SUBJ = "/CN=Russian Trusted Root CA/O=The Ministry of Digital Development and Communications/C=RU"
FAKE_SUBCA_SUBJ = "/CN=Russian Trusted Sub CA/O=The Ministry of Digital Development and Communications/C=RU"

PASS = 0
FAIL = 0
SKIP = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
    if ok:
        PASS += 1
    else:
        FAIL += 1


def skip(name: str, detail: str = "") -> None:
    global SKIP
    SKIP += 1
    print(f"[SKIP] {name}" + (f" — {detail}" if detail else ""))


def run(cmd: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=stdin, capture_output=True)


def openssl(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return run(["openssl", *args], stdin=stdin)


def js_generate(domains_file: Path, upstream: Path, out: Path) -> subprocess.CompletedProcess:
    """Генерация через JS CLI (web/generate.mjs) — тот же код, что и на странице."""
    return run(["node", str(JS_CLI),
                "--domains", str(domains_file), "--upstream", str(upstream), "--out", str(out)])


def load_fingerprints() -> dict:
    return json.loads(FINGERPRINTS.read_text(encoding="utf-8"))


def fetch_cert(urls: list[str], out_path: Path) -> tuple[bool, str]:
    """Скачивает первый доступный источник; (ok, последний-URL-или-ошибка)."""
    last = ""
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "restricted-russian-ca-verify/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                out_path.write_bytes(resp.read())
            return True, url
        except Exception as exc:  # noqa: BLE001
            last = f"{url}: {exc}"
    return False, last


def cert_sha256(path: Path) -> str:
    """SHA256 сертификата (PEM или DER); "" — не разбирается."""
    r = openssl("x509", "-in", str(path), "-outform", "DER")
    if r.returncode != 0:
        r = openssl("x509", "-inform", "DER", "-in", str(path), "-outform", "DER")
    if r.returncode != 0:
        return ""
    return hashlib.sha256(r.stdout).hexdigest().upper()


def gen_key(path: Path) -> None:
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(path))


def make_ca(key: Path, cert: Path, subj: str, ext_lines: list[str] | None = None, tmp: Path | None = None) -> bool:
    cmd = [
        "req", "-x509", "-new", "-key", str(key),
        "-subj", subj, "-sha256",
    ]
    if ext_lines:
        ext = tmp / f"{cert.stem}.cnf"
        ext.write_text("[ext]\n" + "\n".join(ext_lines) + "\n")
        cmd += ["-config", str(ext), "-extensions", "ext"]
    p = openssl(*cmd)
    cert.write_bytes(p.stdout)
    return p.returncode == 0


def make_leaf(signer_cert: Path, signer_key: Path, subj: str, ext_lines: list[str], out: Path) -> bool:
    key = out.with_suffix(".key")
    csr = out.with_suffix(".csr")
    ext = out.with_suffix(".cnf")
    gen_key(key)
    ext.write_text("[ext]\n" + "\n".join(ext_lines) + "\n")
    r = openssl("req", "-new", "-key", str(key), "-subj", subj, "-out", str(csr))
    if r.returncode != 0:
        return False
    r = openssl(
        "x509", "-req", "-in", str(csr), "-CA", str(signer_cert), "-CAkey", str(signer_key),
        "-extfile", str(ext), "-extensions", "ext", "-sha256",
    )
    out.write_bytes(r.stdout)
    return r.returncode == 0


LEAF_BASE = [
    "basicConstraints=critical,CA:false",
    "keyUsage=critical,digitalSignature",
]


def test_hierarchy(tmp: Path) -> None:
    print("--- test hierarchy (fake upstream, real subject shape) ---")

    up_key, up_cert = tmp / "up.key", tmp / "up.crt"
    gen_key(up_key)
    check("fake upstream CA created", make_ca(up_key, up_cert, FAKE_UPSTREAM_SUBJ), "self-signed")

    sub_key, sub_cert = tmp / "sub.key", tmp / "sub.crt"
    gen_key(sub_key)
    ext = tmp / "sub.cnf"
    ext.write_text("[ext]\n" + "\n".join(
        LEAF_BASE[:0] + [
            "basicConstraints=critical,CA:true,pathlen:0",
            "keyUsage=critical,keyCertSign,cRLSign",
            "subjectKeyIdentifier=hash",
            "authorityKeyIdentifier=keyid",
        ]
    ) + "\n")
    r = openssl("req", "-new", "-key", str(sub_key), "-subj", FAKE_SUBCA_SUBJ, "-out", str(tmp / "sub.csr"))
    r2 = openssl(
        "x509", "-req", "-in", str(tmp / "sub.csr"), "-CA", str(up_cert), "-CAkey", str(up_key),
        "-extfile", str(ext), "-extensions", "ext", "-sha256",
    )
    sub_cert.write_bytes(r2.stdout)
    check("fake sub-CA created", r.returncode == 0 and r2.returncode == 0)

    domains_file = tmp / "domains.txt"
    domains_file.write_text("allowed.example\n")
    out = tmp / "out"
    r = js_generate(domains_file, up_cert, out)
    check("js CLI (web/generate.mjs) succeeded", r.returncode == 0, r.stderr.decode().strip()[:120] if r.returncode else "")
    if r.returncode != 0:
        return

    root, proxy = out / "root.crt", out / "proxy.crt"

    leaves = {
        "leaf_allowed": (["/CN=allowed.example"], "subjectAltName=DNS:allowed.example"),
        "leaf_blocked": (["/CN=blocked.example"], "subjectAltName=DNS:blocked.example"),
        "leaf_sub_allowed": (["/CN=sub.allowed.example"], "subjectAltName=DNS:sub.allowed.example"),
        "leaf_ipsan": (["/CN=1.2.3.4"], "subjectAltName=IP:1.2.3.4"),
        "leaf_nosan_allowed": (["/CN=allowed.example"], None),
        "leaf_nosan_blocked": (["/CN=blocked.example"], None),
    }
    for name, (subj, san) in leaves.items():
        lines = list(LEAF_BASE) + ([san] if san else [])
        ok = make_leaf(sub_cert, sub_key, subj[0], lines, tmp / f"{name}.crt")
        check(f"{name} created", ok)
        if not ok:
            return

    def verify(leaf: Path, ca: Path = root, untrusted: list[Path] | None = None) -> subprocess.CompletedProcess:
        cmd = ["verify", "-CAfile", str(ca)]
        for u in untrusted or []:
            cmd += ["-untrusted", str(u)]
        return openssl(*cmd, str(leaf))

    proxy_untrusted = [proxy, sub_cert]

    r = verify(tmp / "leaf_allowed.crt", untrusted=proxy_untrusted)
    check("allowed domain validates through proxy", r.returncode == 0, r.stdout.decode().strip())

    r = verify(tmp / "leaf_sub_allowed.crt", untrusted=proxy_untrusted)
    check("subdomain of allowed domain validates", r.returncode == 0)

    r = verify(tmp / "leaf_blocked.crt", untrusted=proxy_untrusted)
    err = (r.stdout + r.stderr).decode()
    check("blocked domain rejected", r.returncode != 0 and "permitted subtree" in err,
          "permitted subtree violation" if r.returncode != 0 else "VERIFIED UNEXPECTEDLY")

    r = verify(tmp / "leaf_ipsan.crt", untrusted=proxy_untrusted)
    err = (r.stdout + r.stderr).decode()
    check("IP-SAN leaf rejected (excluded subtrees)", r.returncode != 0 and "excluded subtree" in err,
          "excluded subtree violation" if r.returncode != 0 else "VERIFIED UNEXPECTEDLY")

    r = verify(tmp / "leaf_nosan_allowed.crt", untrusted=proxy_untrusted)
    check("no-SAN leaf with allowed CN validates (legacy CN)", r.returncode == 0)

    r = verify(tmp / "leaf_nosan_blocked.crt", untrusted=proxy_untrusted)
    err = (r.stdout + r.stderr).decode()
    check("no-SAN leaf with blocked CN rejected", r.returncode != 0, err.strip()[:80])

    print("--- real Mincifry chain (downloaded from fingerprints.json sources) ---")
    pins = load_fingerprints()
    root = tmp / "mincifry-root.crt"
    ok, info = fetch_cert(pins["mincifry_root"]["sources"], root)
    if not ok:
        skip("real Mincifry chain", f"sources unreachable: {info}")
        return
    check("root downloaded from sources", True, info)

    sha = cert_sha256(root)
    check("downloaded root matches pinned SHA256", sha == pins["mincifry_root"]["sha256"],
          sha or "unparseable")
    if sha != pins["mincifry_root"]["sha256"]:
        return

    sub = tmp / "mincifry-sub-ca.crt"
    ok, info = fetch_cert([pins["mincifry_sub_ca"]["source"]], sub)
    if not ok:
        skip("real Mincifry sub-CA download", info)
        return
    check("sub-CA downloaded from official source", True, info)

    real_domains = tmp / "real-domains.txt"
    real_domains.write_text("gosuslugi.ru\ncbr.ru\nvtb.ru\n")
    real_out = tmp / "real-out"
    r = js_generate(real_domains, root, real_out)
    check("js CLI succeeded on downloaded upstream", r.returncode == 0,
          r.stderr.decode().strip()[:120] if r.returncode else "")
    if r.returncode != 0:
        return

    r = openssl(
        "verify", "-CAfile", str(real_out / "root.crt"),
        "-untrusted", str(real_out / "proxy.crt"), str(sub)
    )
    check("real Mincifry sub-CA validates against personal root + proxy", r.returncode == 0,
          (r.stdout + r.stderr).decode().strip().splitlines()[-1] if r.returncode else "OK")


def test_e2e(tmp: Path) -> None:
    print("--- live E2E ---")
    import ssl
    import socket

    if not FINGERPRINTS.exists():
        check("e2e setup", False, "mincifry-certs/fingerprints.json missing")
        return
    pins = load_fingerprints()

    domains_file = tmp / "e2e-domains.txt"
    domains_file.write_text("cbr.ru\nvtb.ru\n")
    out = tmp / "e2e-out"
    root = tmp / "mincifry-root.crt"
    ok, info = fetch_cert(pins["mincifry_root"]["sources"], root)
    if not ok:
        skip("e2e generate", f"sources unreachable: {info}")
        return
    r = js_generate(domains_file, root, out)
    if r.returncode != 0:
        check("e2e generate", False, r.stderr.decode()[:120])
        return

    for host in ("cbr.ru", "vtb.ru"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    chain = tls.get_unverified_chain() or []
            der_chain = [c.public_bytes(ssl.DER) if hasattr(c, "public_bytes") else bytes(c) for c in chain]
            for i, der in enumerate(der_chain):
                pem = _der_to_pem(der)
                (tmp / f"{host}-{i}.pem").write_text(pem)
            check(f"{host}: handshake ok, {len(der_chain)} certs received", len(der_chain) >= 2)
        except Exception as exc:  # noqa: BLE001
            check(f"{host}: reachable", False, f"{type(exc).__name__}: {exc}")
            continue

        leaf = tmp / f"{host}-0.pem"
        inter = tmp / f"{host}-1.pem"
        if not inter.exists():
            check(f"{host}: intermediate present", False)
            continue
        r = openssl(
            "verify", "-CAfile", str(out / "root.crt"),
            "-untrusted", str(out / "proxy.crt"), "-untrusted", str(inter), str(leaf)
        )
        err = (r.stdout + r.stderr).decode()
        if r.returncode == 0:
            check(f"{host}: live chain validates through restricted bundle", True)
        else:
            msg = err.strip().splitlines()[-1] if err.strip() else ""
            if "name constraints" in msg.lower() or "subtree" in msg.lower():
                check(f"{host}: live chain rejected by constraints", False,
                      f"site is not in the allowed list or serves a non-Mincifry chain: {msg}")
            else:
                check(f"{host}: live chain validates", False, msg)


def _der_to_pem(der: bytes) -> str:
    import base64
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Cross-validation of web/generate.mjs with openssl (CI)")
    ap.add_argument("--e2e", action="store_true", help="also run live network tests (cbr.ru, vtb.ru)")
    args = ap.parse_args()

    if shutil_which("openssl") is None:
        print("ERROR: openssl CLI not found", file=sys.stderr)
        sys.exit(2)
    if shutil_which("node") is None:
        print("ERROR: node not found — JS CLI (web/generate.mjs) requires Node.js 20+", file=sys.stderr)
        sys.exit(2)
    if not JS_CLI.exists():
        print(f"ERROR: {JS_CLI} not found", file=sys.stderr)
        sys.exit(2)
    if not (REPO / "web" / "node_modules" / "pkijs").exists():
        print("ERROR: web/node_modules is empty — run `cd web && npm ci` first", file=sys.stderr)
        sys.exit(2)
    if not FINGERPRINTS.exists():
        print(f"ERROR: {FINGERPRINTS} not found", file=sys.stderr)
        sys.exit(2)

    with tempfile.TemporaryDirectory(prefix="rrca-verify-") as tmp_name:
        test_hierarchy(Path(tmp_name))
        if args.e2e:
            test_e2e(Path(tmp_name))

    print(f"\n{PASS} passed, {FAIL} failed, {SKIP} skipped")
    sys.exit(1 if FAIL else 0)


def shutil_which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


if __name__ == "__main__":
    main()
