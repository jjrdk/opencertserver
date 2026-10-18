#!/usr/bin/env python3
"""Drive the deployed MCP executable over real stdio; control stays container-local."""

import base64
import json
import os
import secrets
import select
import socket
import subprocess
import sys
import time
import traceback

SOCKET = "/tmp/iq-mcp.sock"
WORK = "/workspace"


class Session:
    def __init__(self):
        self.process = None
        self.buffer = b""
        self.next_id = 0
        self.stderr = None

    def request(self, method, params):
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.send(request)
        deadline = time.monotonic() + 30
        while True:
            while b"\n" not in self.buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([self.process.stdout], [], [], max(0, remaining))[0]:
                    raise TimeoutError(f"MCP did not respond to {method}")
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError(f"MCP exited before responding to {method}")
                self.buffer += chunk
            line, self.buffer = self.buffer.split(b"\n", 1)
            response = json.loads(line)
            with open(f"{WORK}/transcript.jsonl", "a") as transcript:
                transcript.write(json.dumps(response) + "\n")
            if response.get("id") == self.next_id:
                return response
            if time.monotonic() >= deadline:
                raise TimeoutError(f"MCP did not respond to {method}")

    def send(self, message):
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()

    def start(self, mode):
        if self.process is not None:
            raise RuntimeError("A scenario may launch only one MCP subprocess")
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith(("MCP_", "MCPSERVER__", "CA_DN"))}
        if mode != "default":
            env["McpServer__EnableCaOperations"] = "false" if mode == "disabled" else "true"
        if mode in ("enabled", "missing-token"):
            env["McpServer__AllowSelfSignedTestCa"] = "true"
        if mode == "enabled":
            env["McpServer__AuthenticationToken"] = secrets.token_urlsafe(32)
            env["McpServer__CallerName"] = "mcp-caller"
        self.stderr = open(f"{WORK}/mcp.stderr", "wb")
        self.process = subprocess.Popen(
            ["/opt/iq-mcp/opencertserver.mcp"], cwd=WORK, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr)
        if mode == "missing-token":
            stdout, _ = self.process.communicate(timeout=30)
            return {"exitCode": self.process.returncode, "stdout": stdout.decode(),
                    "stderr": open(f"{WORK}/mcp.stderr").read()}
        response = self.request("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "opencertserver-iq-linux", "version": "1.0"}})
        if "error" in response or "serverInfo" not in response.get("result", {}):
            raise RuntimeError(f"MCP initialization failed: {response}")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return response

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)
        if self.stderr:
            self.stderr.close()


def serve():
    session = Session()
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(SOCKET)
        listener.listen()
        try:
            while True:
                with listener.accept()[0] as connection:
                    command = json.loads(connection.makefile("r").readline())
                    try:
                        action = command["action"]
                        if action == "start":
                            result = session.start(command["mode"])
                        elif action == "request":
                            result = session.request(command["method"], command.get("params", {}))
                        elif action == "stop":
                            session.stop()
                            result = {"stopped": True}
                        else:
                            raise ValueError(f"Unknown action: {action}")
                        connection.sendall(json.dumps({"result": result}).encode())
                    except Exception:
                        connection.sendall(json.dumps({"failure": traceback.format_exc()}).encode())
        finally:
            session.stop()


def control(encoded):
    command = base64.b64decode(encoded)
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(45)
        connection.connect(SOCKET)
        connection.sendall(command + b"\n")
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
    response = json.loads(b"".join(chunks))
    if "failure" in response:
        raise RuntimeError(response["failure"])
    print(json.dumps(response["result"]))


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        control(sys.argv[2])
