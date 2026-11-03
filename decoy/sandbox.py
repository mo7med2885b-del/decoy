"""Starts one throwaway sandbox per scan and talks to its runner (JSON lines over stdin/stdout).

docker mode: a fresh container with no capabilities, read-only root, CPU/memory/process caps,
no environment secrets, destroyed when the scan ends.
local mode: UNSAFE developer fallback (a plain subprocess). Only for our own demo pages.
"""
import json
import os
import queue
import subprocess
import sys
import threading
import time
import uuid

from .config import ROOT, env

LIMITS = {"memory": "1g", "cpus": "1", "pids": 256, "tmpfs": "256m", "step_timeout_s": 25}


class SandboxError(RuntimeError):
    pass


class Sandbox:
    def __init__(self, mode: str | None = None):
        self.mode = mode or env("DECOY_SANDBOX", "docker")
        self.name = "decoy-" + uuid.uuid4().hex[:10]
        self.proc = None
        self.lines = queue.Queue()
        self.created_at = None
        self.destroyed_at = None
        self.info = {}

    def command(self) -> list[str]:
        if self.mode == "local":
            return [sys.executable, "-u", str(ROOT / "sandbox" / "runner.py")]
        cmd = ["docker", "run", "-i", "--rm", "--name", self.name,
               "--read-only", "--tmpfs", f"/tmp:rw,size={LIMITS['tmpfs']},mode=1777",
               "--memory", LIMITS["memory"], "--memory-swap", LIMITS["memory"], "--cpus", LIMITS["cpus"],
               "--pids-limit", str(LIMITS["pids"]), "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--user", "10001",
               "--add-host", "host.docker.internal:host-gateway", "--shm-size", "256m"]
        runtime = env("DECOY_SANDBOX_RUNTIME")
        if runtime:
            cmd += ["--runtime", runtime]  # e.g. runsc (gVisor) on the Vultr VM
        return cmd + [env("DECOY_SANDBOX_IMAGE", "decoy-sandbox:latest")]

    def start(self):
        # The sandbox gets an EMPTY environment apart from what a browser needs: no keys can leak in.
        clean_env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "HOME", "USERPROFILE",
                                                "APPDATA", "LOCALAPPDATA", "PLAYWRIGHT_BROWSERS_PATH", "DOCKER_HOST")
                     if k in os.environ}
        self.proc = subprocess.Popen(self.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, encoding="utf-8", env=clean_env, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()
        self.created_at = time.time()
        hello = self._wait(timeout=90)  # first docker start can be slow
        if not hello.get("ready"):
            raise SandboxError("sandbox did not start")
        self.info = {"name": self.name, "mode": self.mode, "runtime": env("DECOY_SANDBOX_RUNTIME") or "runc",
                     "user": "10001 (no root)" if self.mode == "docker" else "host user (UNSAFE dev mode)", **LIMITS}
        return self.info

    def _read(self):
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _wait(self, timeout: float) -> dict:
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            raise SandboxError("sandbox step timed out")
        if line is None:
            raise SandboxError("sandbox exited")
        return json.loads(line)

    def send(self, cmd: dict, timeout: float | None = None, on_frame=None) -> dict:
        """Send one command; live frames that arrive before the answer go to on_frame."""
        if not self.proc or self.proc.poll() is not None:
            raise SandboxError("sandbox is not running")
        self.proc.stdin.write(json.dumps(cmd) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + (timeout or LIMITS["step_timeout_s"])
        while True:
            msg = self._wait(max(0.5, deadline - time.time()))
            if "frame" not in msg:
                return msg
            if on_frame:
                try:
                    on_frame(msg["frame"])
                except Exception:
                    pass

    def destroy(self):
        """Always runs, even after errors: the sandbox never outlives its scan."""
        if self.proc and self.proc.poll() is None:
            try:
                self.send({"cmd": "close"}, timeout=8)
            except Exception:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.mode == "docker":
            subprocess.run(["docker", "rm", "-f", self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.destroyed_at = time.time()
        return {"name": self.name, "destroyed": True, "lived_s": round(self.destroyed_at - (self.created_at or self.destroyed_at), 1)}


def docker_ready() -> bool:
    try:
        out = subprocess.run(["docker", "image", "inspect", env("DECOY_SANDBOX_IMAGE", "decoy-sandbox:latest")],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return out.returncode == 0
    except Exception:
        return False
