"""Minimal stdio MCP client for REA (`rea mcp`): newline-delimited JSON-RPC."""
import json
import os
import subprocess
import threading
import queue


class ReaMcp:
    def __init__(self, env=None, log_path=None):
        e = dict(os.environ)
        e.update(env or {})
        self._log = open(log_path, "ab") if log_path else subprocess.DEVNULL
        self.proc = subprocess.Popen(["rea", "mcp"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=self._log, env=e)
        self._id = 0
        self._q = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "daikon-rea-eval", "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _reader(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                pass
        self._q.put(None)

    def _send(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def request(self, method, params, timeout=1800):
        self._id += 1
        rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        while True:
            msg = self._q.get(timeout=timeout)
            if msg is None:
                raise RuntimeError("rea mcp exited")
            if msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg["result"]
            # server -> client requests (e.g. roots/list): answer empty so it never blocks
            if "method" in msg and "id" in msg:
                self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})

    def call(self, tool, args, timeout=1800):
        res = self.request("tools/call", {"name": tool, "arguments": args}, timeout)
        if res.get("structuredContent") is not None:
            out = res["structuredContent"]
        else:
            text = "".join(c.get("text", "") for c in res.get("content", []))
            try:
                out = json.loads(text)
            except json.JSONDecodeError:
                out = {"text": text}
        if res.get("isError"):
            raise RuntimeError(f"{tool}: {json.dumps(out)[:600]}")
        return out

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=60)
        except Exception:
            self.proc.kill()
