#!/usr/bin/env python3
"""Separate local profile sharing the maintained V3 application."""

import os
from pathlib import Path
import subprocess
import sys
import venv

HERE = Path(__file__).resolve().parent
APP = HERE.parent / "monitor"


def main():
    args = sys.argv[1:] or ["serve", "--port", "5055"]
    local_python = HERE / ".venv" / "bin" / "python"
    if args == ["setup"]:
        venv.EnvBuilder(with_pip=True).create(HERE / ".venv")
        return subprocess.call([str(local_python), "-m", "pip", "install", "--requirement", str(APP / "requirements.lock")])
    python = next((str(path) for path in (local_python, HERE.parent / ".venv" / "bin" / "python") if path.exists()), sys.executable)
    if args[0] == "report":
        args[0] = "handoff-preview"
        if "--output" not in args:
            args += ["--output", str(HERE / "reports" / "latest")]
    if args[0] == "demo" and "--report-output" not in args:
        args += ["--report-output", str(HERE / "reports" / "demo")]
    environment = os.environ.copy()
    # A local testing profile must not inherit a server's enabled automation API.
    environment.pop("TYPO_MONITOR_API_TOKEN", None)
    command = [python, "-m", "typo_monitor", "--data-dir", str(HERE / "data"), *args]
    try:
        return subprocess.call(command, cwd=APP, env=environment)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
