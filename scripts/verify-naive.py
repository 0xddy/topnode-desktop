#!/usr/bin/env python3
"""Exercise a Naive test core over loopback without changing system trust."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
from threading import Thread
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


HOST = "127.0.0.1"
SERVER_NAME = "naive.test"


def certificate(name, issuer=None, *, ca=False, expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer_cert, issuer_key = issuer or (None, key)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def free_port(kind):
    with socket.socket(type=kind) as listener:
        listener.bind((HOST, 0))
        return listener.getsockname()[1]


@contextmanager
def core_process(binary, config, port):
    with tempfile.TemporaryFile() as diagnostics, subprocess.Popen(
        [binary, "run", "-c", "stdin"], stdin=subprocess.PIPE,
        stdout=diagnostics, stderr=diagnostics,
    ) as process:
        try:
            process.stdin.write(json.dumps(config).encode())
            process.stdin.close()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection((HOST, port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                diagnostics.seek(0)
                raise RuntimeError(f"Naive test core failed to start: {diagnostics.read().decode(errors='replace')}")
            yield
            if process.poll() is not None:
                raise RuntimeError("Naive test core exited during the request")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()


def request_through_proxy(binary, transport, server_cert, key, trust, name, password, origin):
    naive_port = free_port(socket.SOCK_DGRAM if transport == "quic" else socket.SOCK_STREAM)
    proxy_port = free_port(socket.SOCK_STREAM)
    while proxy_port == naive_port:
        proxy_port = free_port(socket.SOCK_STREAM)
    test_password = "loopback-only"
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "naive", "tag": "server", "listen": HOST, "listen_port": naive_port,
                "network": "udp" if transport == "quic" else "tcp",
                "users": [{"username": "probe", "password": test_password}],
                "tls": {
                    "enabled": True, "certificate": [pem(server_cert)],
                    "key": [key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    ).decode()],
                },
            },
            {"type": "mixed", "tag": "client", "listen": HOST, "listen_port": proxy_port},
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {
                "type": "naive", "tag": "tunnel", "server": HOST, "server_port": naive_port,
                "username": "probe", "password": password or test_password, "quic": transport == "quic",
                "tls": {"enabled": True, "server_name": name, **({"certificate": [pem(trust)]} if trust else {})},
            },
        ],
        "route": {"rules": [{"inbound": ["client"], "action": "route", "outbound": "tunnel"}], "final": "direct"},
    }
    with core_process(binary, config, proxy_port):
        connection = HTTPConnection(HOST, proxy_port, timeout=8)
        try:
            address = f"{HOST}:{origin.server_port}"
            connection.request("GET", f"http://{address}/", headers={"Host": address})
            with connection.getresponse() as response:
                return response.status == 200 and response.read() == origin.body
        except (OSError, HTTPException):
            return False
        finally:
            connection.close()


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.body
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    args = parser.parse_args()
    binary = args.core.resolve(strict=True)
    ca = certificate("Desktop Naive test CA", ca=True)
    leaf, leaf_key = certificate(SERVER_NAME, ca)
    self_signed, self_key = certificate(SERVER_NAME)
    expired, expired_key = certificate(SERVER_NAME, ca, expired=True)
    other_ca, _ = certificate("Wrong Naive test CA", ca=True)
    cases = (
        ("private-ca", leaf, leaf_key, ca[0], SERVER_NAME, None, True),
        ("self-signed", self_signed, self_key, self_signed, SERVER_NAME, None, True),
        ("system-rejects-private-ca", leaf, leaf_key, None, SERVER_NAME, None, False),
        ("wrong-ca", leaf, leaf_key, other_ca, SERVER_NAME, None, False),
        ("expired", expired, expired_key, ca[0], SERVER_NAME, None, False),
        ("wrong-name", leaf, leaf_key, ca[0], "wrong.naive.test", None, False),
        ("wrong-password", leaf, leaf_key, ca[0], SERVER_NAME, "incorrect", False),
    )
    failures = []
    with ThreadingHTTPServer((HOST, 0), Origin) as origin:
        origin.body = secrets.token_hex(16).encode()
        Thread(target=origin.serve_forever, daemon=True).start()
        try:
            for transport in ("https", "quic"):
                for case, cert, key, trust, name, password, expected in cases:
                    actual = request_through_proxy(binary, transport, cert, key, trust, name, password, origin)
                    label = f"{transport}-{case}"
                    print(f"{label} {'PASS' if actual == expected else 'FAIL'}", flush=True)
                    if actual != expected:
                        failures.append(label)
        finally:
            origin.shutdown()
    if failures:
        raise SystemExit(f"Naive checks failed: {', '.join(failures)}")


if __name__ == "__main__":
    main()
