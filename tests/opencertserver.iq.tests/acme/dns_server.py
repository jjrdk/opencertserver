"""
Private authoritative DNS server for the RFC 8555 ACME IQ scenarios (test only).

Standard-library only, so it runs on a stock `python:3-alpine` image with no pip step.

* DNS (UDP + TCP, port 53): authoritative for the zones named in the IQ_DNS_ZONES
  environment variable (comma separated, default `example.com`). Supported types are
  A, AAAA, TXT and CAA. A name inside a zone with no matching record answers NOERROR
  with an empty answer (NODATA), so the CAA tree-climb of RFC 8659 sees "no CAA
  restriction". Names outside every zone answer NXDOMAIN, so nothing ever falls
  through to a public resolver.
* Control API (HTTP, port 8080), used by the harness and by the acme.sh DNS hook:
    GET    /health                         -> 200 "ok"
    GET    /records                        -> JSON dump of the zone data
    POST   /records  {"name","type","value"} -> add a record
    DELETE /records?name=..&type=..[&value=..] -> remove record(s)

Record values use presentation format: A "203.0.113.5", TXT "token" (unquoted),
CAA '0 issue "ca.example"'.
"""
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TYPES = {"A": 1, "TXT": 16, "AAAA": 28, "CAA": 257}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
TTL = 5

ZONES = [z.strip().strip(".").lower() for z in os.environ.get("IQ_DNS_ZONES", "example.com").split(",") if z.strip()]

_lock = threading.Lock()
_records = {}  # name -> {type -> [value, ...]}


def log(msg):
    print(f"[dns] {msg}", file=sys.stderr, flush=True)


def norm(name):
    return name.strip().strip(".").lower()


def in_zone(name):
    return any(name == z or name.endswith("." + z) for z in ZONES)


def add_record(name, rtype, value):
    with _lock:
        values = _records.setdefault(norm(name), {}).setdefault(rtype.upper(), [])
        if value not in values:
            values.append(value)


def remove_records(name, rtype, value=None):
    with _lock:
        by_type = _records.get(norm(name), {})
        if value is None:
            by_type.pop(rtype.upper(), None)
        elif value in by_type.get(rtype.upper(), []):
            by_type[rtype.upper()].remove(value)


def lookup(name, qtype):
    with _lock:
        return list(_records.get(name, {}).get(TYPE_NAMES.get(qtype, ""), []))


def encode_rdata(rtype, value):
    if rtype == "A":
        return socket.inet_pton(socket.AF_INET, value)
    if rtype == "AAAA":
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype == "TXT":
        raw = value.encode()
        chunks = [raw[i:i + 255] for i in range(0, len(raw), 255)] or [b""]
        return b"".join(bytes([len(c)]) + c for c in chunks)
    if rtype == "CAA":
        flags, tag, rest = value.split(" ", 2)
        return bytes([int(flags), len(tag)]) + tag.encode() + rest.strip().strip('"').encode()
    raise ValueError(rtype)


def parse_question(data):
    labels, pos = [], 12
    while True:
        length = data[pos]
        pos += 1
        if length == 0:
            break
        labels.append(data[pos:pos + length].decode("ascii", "replace"))
        pos += length
    qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    return ".".join(labels).lower(), qtype, qclass, pos + 4


def build_response(data):
    (qid, flags, qdcount, _an, _ns, arcount) = struct.unpack("!HHHHHH", data[:12])
    if qdcount != 1:
        return struct.pack("!HHHHHH", qid, 0x8000 | 0x0400 | 1, 0, 0, 0, 0)  # FORMERR
    name, qtype, qclass, qend = parse_question(data)
    question = data[12:qend]
    rd = flags & 0x0100
    answers = []
    if in_zone(name):
        rcode = 0
        for value in lookup(name, qtype):
            try:
                rdata = encode_rdata(TYPE_NAMES[qtype], value)
            except Exception as exc:  # a bad value must never kill the server
                log(f"bad {TYPE_NAMES[qtype]} value {value!r} for {name}: {exc}")
                continue
            answers.append(struct.pack("!HHHIH", 0xC00C, qtype, 1, TTL, len(rdata)) + rdata)
    else:
        rcode = 3  # NXDOMAIN
    # Echo an EDNS(0) OPT record when the query carried one (DnsClientX asks for DNSSEC data).
    opt = struct.pack("!BHHIH", 0, 41, 4096, 0, 0) if arcount > 0 else b""
    header = struct.pack(
        "!HHHHHH", qid, 0x8000 | 0x0400 | rd | 0x0080 | rcode, 1, len(answers), 0, 1 if opt else 0)
    log(f"{TYPE_NAMES.get(qtype, qtype)} {name} -> rcode={rcode} answers={len(answers)}")
    return header + question + b"".join(answers) + opt


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            sock.sendto(build_response(data), self.client_address)
        except Exception as exc:
            log(f"udp error: {exc}")


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                head = self.request.recv(2)
                if len(head) < 2:
                    return
                (length,) = struct.unpack("!H", head)
                data = b""
                while len(data) < length:
                    chunk = self.request.recv(length - len(data))
                    if not chunk:
                        return
                    data += chunk
                reply = build_response(data)
                self.request.sendall(struct.pack("!H", len(reply)) + reply)
        except Exception as exc:
            log(f"tcp error: {exc}")


class ThreadingUdpServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class ThreadingTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ApiHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/health":
            self._send(200, '"ok"')
        elif path == "/records":
            with _lock:
                self._send(200, json.dumps(_records))
        else:
            self._send(404, "{}")

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/records":
            self._send(404, "{}")
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            rtype = str(body["type"]).upper()
            if rtype not in TYPES:
                raise ValueError(f"unsupported type {rtype}")
            encode_rdata(rtype, str(body["value"]))
            add_record(body["name"], rtype, str(body["value"]))
            log(f"added {rtype} {body['name']} = {body['value']}")
            self._send(200, '{"ok":true}')
        except Exception as exc:
            self._send(400, json.dumps({"error": str(exc)}))

    def do_DELETE(self):
        url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url.query)
        if url.path != "/records" or "name" not in query or "type" not in query:
            self._send(400, "{}")
            return
        remove_records(query["name"][0], query["type"][0], query.get("value", [None])[0])
        log(f"removed {query['type'][0]} {query['name'][0]}")
        self._send(200, '{"ok":true}')


def main():
    servers = [
        ThreadingUdpServer(("0.0.0.0", 53), UdpHandler),
        ThreadingTcpServer(("0.0.0.0", 53), TcpHandler),
        ThreadingHTTPServer(("0.0.0.0", 8080), ApiHandler),
    ]
    for server in servers[:-1]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f"authoritative for {ZONES}; dns on :53 (udp+tcp), control api on :8080")
    servers[-1].serve_forever()


if __name__ == "__main__":
    main()
