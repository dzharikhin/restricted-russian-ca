#!/usr/bin/env python3
"""Self-tests for restricted-russian-ca.

Verifies the name-constrained proxy architecture:
  1. test hierarchy (fake upstream in the shape of the real one): an allowed
     domain validates through root -> proxy -> subCA -> leaf, a blocked domain
     fails with a permitted-subtree violation, IP-SAN leaves are rejected;
  2. real world structure: the pinned Mincifry sub-CA verifies against the
     personal root + proxy generated from the pinned Mincifry root;
  3. optional live E2E (--e2e): a real TLS handshake is verified against the
     generated bundle.

Requires Python 3 stdlib and openssl CLI. Network access is needed only for --e2e.
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import generate as gen  # noqa: E402

FAKE_UPSTREAM_SUBJ = "/CN=Russian Trusted Root CA/O=The Ministry of Digital Development and Communications/C=RU"
FAKE_SUBCA_SUBJ = "/CN=Russian Trusted Sub CA/O=The Ministry of Digital Development and Communications/C=RU"

PASS = 0
FAIL = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
    if ok:
        PASS += 1
    else:
        FAIL += 1


def run(cmd: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=stdin, capture_output=True)


def openssl(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return run(["openssl", *args], stdin=stdin)


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
    r = run(
        [sys.executable, str(REPO / "scripts" / "generate.py"),
         "--domains", str(domains_file), "--upstream", str(up_cert), "--out", str(out)]
    )
    check("generate.py succeeded", r.returncode == 0, r.stderr.decode().strip()[:120] if r.returncode else "")
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

    print("--- real Mincifry chain ---")
    pinned_root = REPO / "pinned" / "mincifry-root.crt"
    pinned_sub = REPO / "pinned" / "mincifry-sub-ca.crt"
    if not pinned_root.exists() or not pinned_sub.exists():
        check("pinned certificates present", False, "pinned/mincifry-*.crt missing")
        return

    real_domains = tmp / "real-domains.txt"
    real_domains.write_text("gosuslugi.ru\ncbr.ru\nvtb.ru\n")
    real_out = tmp / "real-out"
    r = run(
        [sys.executable, str(REPO / "scripts" / "generate.py"),
         "--domains", str(real_domains), "--upstream", str(pinned_root), "--out", str(real_out)]
    )
    check("generate.py succeeded on pinned upstream", r.returncode == 0,
          r.stderr.decode().strip()[:120] if r.returncode else "")
    if r.returncode != 0:
        return

    r = openssl(
        "verify", "-CAfile", str(real_out / "root.crt"),
        "-untrusted", str(real_out / "proxy.crt"), str(pinned_sub)
    )
    check("real Mincifry sub-CA validates against personal root + proxy", r.returncode == 0,
          (r.stdout + r.stderr).decode().strip().splitlines()[-1] if r.returncode else "OK")

    r = openssl("verify", "-CAfile", str(pinned_root), str(pinned_sub))
    check("pinned certificates are consistent (root signs sub-CA)", r.returncode == 0)


def test_e2e(tmp: Path) -> None:
    print("--- live E2E ---")
    import ssl
    import socket

    pinned_root = REPO / "pinned" / "mincifry-root.crt"
    if not pinned_root.exists():
        check("e2e setup", False, "no pinned root")
        return

    domains_file = tmp / "e2e-domains.txt"
    domains_file.write_text("cbr.ru\nvtb.ru\n")
    out = tmp / "e2e-out"
    r = run(
        [sys.executable, str(REPO / "scripts" / "generate.py"),
         "--domains", str(domains_file), "--upstream", str(pinned_root), "--out", str(out)]
    )
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
    ap = argparse.ArgumentParser(description="Self-tests for restricted-russian-ca")
    ap.add_argument("--e2e", action="store_true", help="also run live network tests (cbr.ru, vtb.ru)")
    args = ap.parse_args()

    if shutil_which("openssl") is None:
        print("ERROR: openssl CLI not found", file=sys.stderr)
        sys.exit(2)

    with tempfile.TemporaryDirectory(prefix="rrca-verify-") as tmp_name:
        test_hierarchy(Path(tmp_name))
        if args.e2e:
            test_e2e(Path(tmp_name))

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


def shutil_which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


if __name__ == "__main__":
    main()
