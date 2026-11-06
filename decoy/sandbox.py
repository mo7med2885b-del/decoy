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

LIMITS = {"memory": "1g", "cpus": "1", "pids": 256, "tmpfs": "256m", "step_timeout_s": 40}


class SandboxError(RuntimeError):
    pass


class Sandbox:
    def __init__(self, mode: str | None = None, memory: str | None = None, scan_id: str = ""):
        self.mode = mode or env("DECOY_SANDBOX", "docker")
        self.memory = memory or LIMITS["memory"]
        self.scan_id = scan_id
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
               "--label", f"decoy-scan={self.scan_id or 'none'}",
               "--memory", self.memory, "--memory-swap", self.memory, "--cpus", LIMITS["cpus"],
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
                     "user": "10001 (no root)" if self.mode == "docker" else "host user (UNSAFE dev mode)", **{**LIMITS, "memory": self.memory}}
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


def kill_scan(scan_id: str):
    """Hard stop: remove every container of a scan, even if its runner is stuck."""
    try:
        ids = subprocess.run(["docker", "ps", "-aq", "--filter", f"label=decoy-scan={scan_id}"],
                             capture_output=True, text=True, timeout=10).stdout.split()
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return len(ids)
    except Exception:
        return 0


class WarmPool:
    """Two sealed browsers kept ready for the laptop visitor, so a scan starts at once instead of after several seconds.
    Each is used by exactly one scan and then destroyed like every other sandbox; a replacement is started right away, and an unused one is replaced every 100 s."""
    MAX_AGE = 100
    SIZE = 2

    def __init__(self, prewarm_msg: dict):
        self.msg, self.lock, self.ready, self.filling = prewarm_msg, threading.Lock(), [], 0
        self.stop = False

    def enabled(self) -> bool:
        return env("DECOY_WARM", "1") == "1" and env("DECOY_SANDBOX", "docker") == "docker"

    def kick(self):
        """Fill the pool now (server start) and keep it fresh in the background."""
        if not self.enabled():
            return
        self._top_up()
        threading.Thread(target=self._loop, daemon=True).start()

    def _top_up(self):
        with self.lock:
            need = self.SIZE - len(self.ready) - self.filling
            self.filling += max(need, 0)
        for _ in range(max(need, 0)):
            threading.Thread(target=self._fill, daemon=True).start()

    def _loop(self):
        while not self.stop:
            time.sleep(20)
            old = []
            with self.lock:
                for sb, t in list(self.ready):
                    if time.time() - t > self.MAX_AGE:
                        self.ready.remove((sb, t))
                        old.append(sb)
            for sb in old:
                sb.destroy()
            self._top_up()

    def _fill(self):
        sb = None
        try:
            sb = Sandbox(scan_id="warm")
            sb.start()
            sb.send({"cmd": "prewarm", **self.msg}, timeout=40)
            with self.lock:
                self.ready.append((sb, time.time()))
        except Exception:
            if sb:
                sb.destroy()
        finally:
            with self.lock:
                self.filling = max(0, self.filling - 1)

    def take(self, scan_id: str):
        """A ready sandbox for this scan, or None (the caller then starts a cold one). A replacement is started either way."""
        if not self.enabled():
            return None
        sb = None
        with self.lock:
            while self.ready:
                cand, t = self.ready.pop(0)
                if time.time() - t <= self.MAX_AGE and cand.proc and cand.proc.poll() is None:
                    sb = cand
                    break
                cand.destroy()
        self._top_up()
        if sb:
            sb.scan_id = scan_id
        return sb
