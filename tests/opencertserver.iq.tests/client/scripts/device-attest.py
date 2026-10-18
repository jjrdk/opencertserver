#!/usr/bin/env python3
"""Independent software AIK/TPM quote fixtures; no production libraries or hardware."""

import base64
import json
from pathlib import Path
import struct
import subprocess
import sys


def openssl(*args):
    return subprocess.run(
        ["openssl", *args], check=True, stdout=subprocess.PIPE, timeout=30
    ).stdout


def b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def tpm2b(value):
    return struct.pack(">H", len(value)) + value


def init(work):
    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
        "-subj", "/CN=IQ Disposable Manufacturer", "-keyout", str(work / "root.key"),
        "-out", str(work / "root.pem"),
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    openssl(
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-subj", "/CN=IQ Software AIK", "-keyout", str(work / "aik.key"),
        "-out", str(work / "aik.csr"),
    )
    (work / "aik.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
    )
    openssl(
        "x509", "-req", "-in", str(work / "aik.csr"),
        "-CA", str(work / "root.pem"), "-CAkey", str(work / "root.key"),
        "-set_serial", "2", "-days", "1", "-sha256",
        "-extfile", str(work / "aik.ext"), "-out", str(work / "aik.pem"),
    )
    openssl("verify", "-CAfile", str(work / "root.pem"), str(work / "aik.pem"))
    print((work / "root.pem").read_text(), end="")


def answer(work, challenge_path, mode):
    challenge = json.loads(Path(challenge_path).read_text())
    assert challenge["type"] == "device-attest-01"
    token = challenge["token"]
    nonce = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))

    # TPM2B_ATTEST: TPMS_ATTEST with a SHA-256 PCR selection and synthetic PCR digest.
    attest = (
        struct.pack(">IH", 0xFF544347, 0x8018)
        + tpm2b(b"")
        + tpm2b(nonce)
        + struct.pack(">QIIBQ", 0, 0, 0, 1, 0)
        + struct.pack(">IHB", 1, 0x000B, 3)
        + b"\xff\x00\x00"
        + tpm2b(bytes(32))
    )
    proof = tpm2b(attest)
    if mode == "empty":
        proof = b""
    elif mode == "malformed":
        proof = b"\x00\x01\x00"
    elif mode != "valid":
        raise ValueError(f"Unknown proof mode: {mode}")

    (work / "proof.bin").write_bytes(proof)
    openssl(
        "dgst", "-sha256", "-sign", str(work / "aik.key"),
        "-out", str(work / "proof.sig"), str(work / "proof.bin"),
    )
    # Verify the signature with OpenSSL independently before sending the fixture.
    (work / "aik.pub").write_bytes(
        openssl("x509", "-in", str(work / "aik.pem"), "-pubkey", "-noout")
    )
    openssl(
        "dgst", "-sha256", "-verify", str(work / "aik.pub"),
        "-signature", str(work / "proof.sig"), str(work / "proof.bin"),
    )
    certificate = openssl("x509", "-in", str(work / "aik.pem"), "-outform", "DER")
    (work / "answer.json").write_text(json.dumps({
        "nonce": token,
        "proof": b64url(proof),
        "signature": b64url((work / "proof.sig").read_bytes()),
        "aikCertificate": b64url(certificate),
    }))


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    directory.mkdir(parents=True, exist_ok=True)
    if sys.argv[2] == "init":
        init(directory)
    elif sys.argv[2] == "answer":
        answer(directory, sys.argv[3], sys.argv[4])
    else:
        raise ValueError(f"Unknown command: {sys.argv[2]}")
