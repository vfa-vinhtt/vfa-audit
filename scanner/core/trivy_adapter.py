"""
Shared Trivy runner for secret_checker, dependency_checker, and license_checker.

Runs `trivy fs` with the requested --scanners and returns the parsed JSON so
each caller can extract its own section (Secrets / Vulnerabilities / Licenses).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .requirements import resolve_command


def run_trivy(
    root: Path,
    scanners: str,
    *,
    license_full: bool = False,
    timeout: int = 300,
) -> Optional[dict]:
    """Invoke `trivy fs` on *root* with the given comma-separated *scanners*.

    Returns the parsed JSON result dict on success, or None when:
    - Trivy produces no output (scan error, empty project)
    - The output file cannot be parsed as JSON
    - A subprocess timeout occurs

    Raises RuntimeError when trivy is not found on PATH or any known install
    directory — callers should catch this and surface a WARNING finding instead
    of crashing, consistent with how the other external-tool wrappers behave.
    """
    trivy = resolve_command("trivy")
    if not trivy:
        raise RuntimeError("trivy not found on PATH")

    fd, out_path = tempfile.mkstemp(suffix=".json", prefix="trivy-")
    os.close(fd)
    try:
        cmd = [
            trivy, "fs",
            "--scanners", scanners,
            "--format", "json",
            "--output", out_path,
            "--quiet",
        ]
        if license_full:
            cmd.append("--license-full")
        cmd.append(str(root))

        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        # Trivy exits 0 (clean) or 1 (findings); both produce a valid JSON file.
        # Absence or emptiness of the output file indicates a real failure.
        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            return None
        with open(out_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
