"""
Pre-scan requirements check.

Looks at the config (which plugins/tools are enabled) and the detected project
languages, then verifies the external CLIs those features need are on PATH.

External tools are optional — every plugin degrades gracefully when one is missing —
so by default this only reports status and warns. Enable strict mode (config
``preflight.strict: true`` or ``--strict-requirements``) to abort before scanning
when a required, relevant tool is absent.
"""
from __future__ import annotations
import glob
import importlib
import importlib.util
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import List, Optional, Tuple


# Programmatic installers, keyed by tool command. Only tools with a reliable,
# non-interactive installer are listed; anything else (standalone binaries like
# gitleaks/trufflehog, or runtimes like npm/dotnet/composer/go) must be installed
# manually. Toolchain-based installers (go/npm/dotnet/gem) only work if that
# toolchain is already present.
INSTALL_COMMANDS = {
    "pip-audit":               [sys.executable, "-m", "pip", "install", "pip-audit"],
    "pip-licenses":            [sys.executable, "-m", "pip", "install", "pip-licenses"],
    "go-licenses":             ["go", "install", "github.com/google/go-licenses@latest"],
    "govulncheck":             ["go", "install", "golang.org/x/vuln/cmd/govulncheck@latest"],
    "license-checker":         ["npm", "install", "-g", "license-checker"],
    "dotnet-project-licenses": ["dotnet", "tool", "install", "--global", "dotnet-project-licenses"],
    "license_finder":          ["gem", "install", "license_finder"],
    "fonttools":               [sys.executable, "-m", "pip", "install", "fonttools"],
    "Pillow":                  [sys.executable, "-m", "pip", "install", "Pillow"],
    "pytesseract":             [sys.executable, "-m", "pip", "install", "pytesseract"],
}

# Standalone-binary installers via OS package managers, keyed by tool then manager.
# A manager is used only if it is present on the system. (trufflehog is not published
# on winget, so a winget-only machine reports it for manual install.)
BINARY_INSTALL_COMMANDS = {
    "gitleaks": {
        "scoop":  ["scoop", "install", "gitleaks"],
        "winget": ["winget", "install", "-e", "--id", "Gitleaks.Gitleaks",
                   "--accept-source-agreements", "--accept-package-agreements"],
        "choco":  ["choco", "install", "gitleaks", "-y"],
        "brew":   ["brew", "install", "gitleaks"],
    },
    "trufflehog": {
        "scoop":  ["scoop", "install", "trufflehog"],
        "choco":  ["choco", "install", "trufflehog", "-y"],
        "brew":   ["brew", "install", "trufflesecurity/trufflehog/trufflehog"],
    },
    "tesseract": {  # OCR engine for asset_checker's text-in-image check
        "winget": ["winget", "install", "-e", "--id", "UB-Mannheim.TesseractOCR",
                   "--accept-source-agreements", "--accept-package-agreements"],
        "scoop":  ["scoop", "install", "tesseract"],
        "choco":  ["choco", "install", "tesseract", "-y"],
        "brew":   ["brew", "install", "tesseract"],
    },
}

# Official GitHub release-binary download as a last-resort fallback (no package
# manager / runtime needed). Used for tools that publish prebuilt binaries. NOTE:
# `go install` is NOT used for these — trufflehog's go.mod has replace directives so
# `go install ...@latest` fails by design; release binaries are the documented method.
GITHUB_RELEASES = {
    "gitleaks": "gitleaks/gitleaks",
    "trufflehog": "trufflesecurity/trufflehog",
}

# Foundation runtimes we can bootstrap, ONLY via signed package managers (never remote
# scripts). Currently just Go, so `go install` fallbacks can work on a bare machine.
BOOTSTRAP_COMMANDS = {
    "go": {
        "winget": ["winget", "install", "-e", "--id", "GoLang.Go",
                   "--accept-source-agreements", "--accept-package-agreements"],
        "brew":   ["brew", "install", "go"],
        "scoop":  ["scoop", "install", "go"],
        "choco":  ["choco", "install", "golang", "-y"],
    },
}

# Preferred order when binary_installer is "auto" (user-scope managers first).
_MANAGER_PREFERENCE = ["scoop", "brew", "winget", "choco"]

# winget returns this (0x8A15002B) when the package is already installed / no newer
# version exists - that means the tool is present, not that the install failed.
_ALREADY_INSTALLED_CODES = {2316632107}


def _already_satisfied(returncode: int, output: str) -> bool:
    if returncode in _ALREADY_INSTALLED_CODES:
        return True
    low = (output or "").lower()
    return "no newer package versions" in low or "already installed" in low


def _pick_manager_for(cmds: dict, binary_installer: str) -> Optional[str]:
    """Choose an available package manager from a per-manager command dict.

    binary_installer: "auto" (detect), "none" (disable), or a specific manager name.
    """
    if not cmds or binary_installer == "none":
        return None
    if binary_installer and binary_installer != "auto":
        return binary_installer if (binary_installer in cmds and shutil.which(binary_installer)) else None
    for manager in _MANAGER_PREFERENCE:
        if manager in cmds and shutil.which(manager):
            return manager
    return None


def _pick_manager(tool: str, binary_installer: str) -> Optional[str]:
    """Choose an available package manager that can install standalone-binary `tool`."""
    return _pick_manager_for(BINARY_INSTALL_COMMANDS.get(tool, {}), binary_installer)


_EXEC_EXTS = ("", ".exe", ".bat", ".cmd", ".ps1")


def scanner_bin_dir() -> str:
    """Directory where the scanner places release binaries it downloads itself."""
    return os.path.join(os.path.expanduser("~"), ".security-scanner", "bin")


def _tool_dirs() -> List[str]:
    """Directories where installers drop binaries that may not be on PATH yet
    (common right after install). OS-aware so each platform's real locations are
    searched and bogus relative paths aren't probed."""
    home = os.path.expanduser("~")
    # Cross-platform: scanner-downloaded binaries, pip scripts, go install, dotnet tools.
    dirs = [
        scanner_bin_dir(),
        sysconfig.get_path("scripts") or "",
        os.path.join(home, "go", "bin"),
        os.path.join(home, ".dotnet", "tools"),
    ]
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        appdata = os.environ.get("APPDATA", "")
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        if local:
            dirs.append(os.path.join(local, "Microsoft", "WinGet", "Links"))  # winget shims
        if appdata:
            dirs.append(os.path.join(appdata, "npm"))                         # npm -g (Windows)
        dirs.append(os.path.join(home, "scoop", "shims"))                     # scoop
        dirs.append(os.path.join(program_files, "Go", "bin"))                 # Go (winget/MSI)
    else:
        # Linux / macOS: Homebrew, system bins, user-local npm/gem bins, Go.
        dirs += [
            "/usr/local/bin", "/opt/homebrew/bin",                # brew (macOS Intel / ARM)
            "/home/linuxbrew/.linuxbrew/bin", os.path.join(home, ".linuxbrew", "bin"),
            os.path.join(home, ".local", "bin"),                  # pip --user, pipx
            "/usr/local/go/bin",                                  # Go (tarball install)
        ]
    return [d for d in dirs if d]


def _known_install_dirs(command: str) -> List[str]:
    """Fixed locations a specific tool's installer uses that aren't on PATH and aren't
    a winget Links/Packages dir. e.g. the UB-Mannheim Tesseract MSI installs into
    'Program Files\\Tesseract-OCR' (or a user-scope Programs dir), never on PATH."""
    if command != "tesseract":
        return []
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        dirs = [os.path.join(pf, "Tesseract-OCR"), os.path.join(pfx86, "Tesseract-OCR")]
        if local:
            dirs += [os.path.join(local, "Programs", "Tesseract-OCR"),
                     os.path.join(local, "Tesseract-OCR")]
        return dirs
    return ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin"]


def resolve_command(command: str) -> Optional[str]:
    """Full path to `command`, searching PATH then known install dirs (including
    winget's hashed Packages folder and tool-specific install dirs on Windows).
    Returns None if not found anywhere.

    This is why a tool installed moments ago (e.g. via winget) is still found even
    though the current shell's PATH hasn't been refreshed."""
    found = shutil.which(command)
    if found:
        return found
    for directory in _tool_dirs() + _known_install_dirs(command):
        for ext in _EXEC_EXTS:
            candidate = os.path.join(directory, command + ext)
            if os.path.isfile(candidate):
                return candidate
    # winget installs portable packages into hashed subdirs of .../WinGet/Packages
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        pkgs = os.path.join(local, "Microsoft", "WinGet", "Packages") if local else ""
        if pkgs and os.path.isdir(pkgs):
            for ext in _EXEC_EXTS:
                matches = glob.glob(os.path.join(pkgs, "*", command + ext))
                if matches:
                    return matches[0]
    return None


@dataclass
class Requirement:
    command: str          # CLI looked for on PATH (or a label, for network deps)
    feature: str          # which enabled config feature needs it
    install_hint: str
    network_only: bool = False  # informational (no binary to check, e.g. OSV/GHSA)
    optional: bool = False      # listed in preflight.optional -> missing won't block
    module: Optional[str] = None  # python import name; checked instead of PATH

    @property
    def installed(self) -> bool:
        if self.network_only:
            return True
        # Python tools are run via `python -m <module>`, so detect them the same
        # way (importable in the scanner's interpreter) rather than via PATH.
        if self.module:
            return importlib.util.find_spec(self.module) is not None
        return resolve_command(self.command) is not None


def collect_requirements(config: dict, adapter_instances: list) -> List[Requirement]:
    """Build the list of external tools required by the *enabled* config features,
    scoped to the *detected* languages (via adapter_instances)."""
    reqs: List[Requirement] = []
    plugins = config.get("plugins", {})

    def enabled(section: dict) -> bool:
        return section.get("enabled", True)

    # secret_checker runs every enabled tool, so require each enabled external one.
    # (python_regex is built-in and needs nothing.)
    sc = plugins.get("secret_checker", {})
    if enabled(sc):
        ext_tools = {
            "gitleaks": "scoop/winget/choco/brew, or download from https://github.com/gitleaks/gitleaks/releases",
            "trufflehog": (
                "brew install trufflehog | go install github.com/trufflesecurity/trufflehog/v3@latest | "
                "scoop/choco install trufflehog | or download from "
                "https://github.com/trufflesecurity/trufflehog/releases"
            ),
        }
        for tool, settings in (sc.get("tool_config") or {}).items():
            if settings.get("enabled") and tool in ext_tools:
                reqs.append(Requirement(tool, f"secret_checker ({tool})", ext_tools[tool]))

    # dependency_checker
    dep = plugins.get("dependency_checker", {})
    dep_on = enabled(dep)
    dep_tools = dep.get("tools", {})
    audit_on = dep_on and dep_tools.get("project_audit", {}).get("enabled", True)
    osv_on = dep_on and dep_tools.get("osv", {}).get("enabled", True)
    if osv_on:
        reqs.append(Requirement("api.osv.dev", "dependency_checker (OSV CVE lookup)",
                                "Requires outbound network access", network_only=True))

    # license_checker
    lic = plugins.get("license_checker", {})
    lic_tool_on = enabled(lic) and bool(lic.get("tools", {}).get("project_tool"))

    # asset_checker: optional Python libs for reading embedded font/image license
    # metadata (it degrades to filename heuristics without them). OCR is opt-in.
    ac = plugins.get("asset_checker", {})
    if enabled(ac):
        ac_tools = ac.get("tools", {})
        if ac_tools.get("font_metadata", True):
            reqs.append(Requirement("fonttools", "asset_checker (font license metadata)",
                                    "pip install fonttools", module="fontTools"))
        if ac_tools.get("image_metadata", True):
            reqs.append(Requirement("Pillow", "asset_checker (image license metadata)",
                                    "pip install Pillow", module="PIL"))
        if ac_tools.get("ocr_text_in_image", False):
            reqs.append(Requirement("pytesseract", "asset_checker (OCR text-in-image)",
                                    "pip install pytesseract", module="pytesseract"))
            reqs.append(Requirement("tesseract", "asset_checker (OCR engine)",
                                    "winget/scoop/choco/brew install tesseract"))

    # Per-detected-language native tools, declared by each adapter. A tool spec is
    # (command, install_hint) or (command, install_hint, python_module).
    def _make(spec, feature) -> Requirement:
        cmd, hint = spec[0], spec[1]
        module = spec[2] if len(spec) > 2 else None
        return Requirement(cmd, feature, hint, module=module)

    for adapter in adapter_instances:
        tools = getattr(adapter, "REQUIRED_TOOLS", {}) or {}
        if audit_on and "audit" in tools:
            reqs.append(_make(tools["audit"], f"dependency_checker audit ({adapter.name})"))
        if lic_tool_on and "license" in tools:
            reqs.append(_make(tools["license"], f"license_checker tool ({adapter.name})"))

    # Tools the user marked optional won't block a strict scan (still reported).
    optional_set = {str(c).lower() for c in (config.get("preflight", {}).get("optional") or [])}
    for r in reqs:
        if r.command.lower() in optional_set:
            r.optional = True

    return reqs


def print_requirements_report(reqs: List[Requirement], strict: bool = False) -> List[Requirement]:
    """Print the pre-scan requirements table. Returns the list of MISSING (installable)
    requirements (network-only items never count as missing)."""
    # De-duplicate by command, merging feature labels.
    merged: dict[str, Requirement] = {}
    for r in reqs:
        if r.command in merged:
            existing = merged[r.command]
            if r.feature not in existing.feature:
                existing.feature = f"{existing.feature}, {r.feature}"
            # Required wins: only optional if every usage is optional.
            existing.optional = existing.optional and r.optional
        else:
            merged[r.command] = Requirement(
                r.command, r.feature, r.install_hint, r.network_only, r.optional, r.module
            )
    items = sorted(merged.values(), key=lambda x: (x.network_only, x.command))

    if not items:
        print("Requirements check: no external tools needed for the current config.")
        return []

    print("\nChecking tool requirements (enabled config features x detected languages):")
    blocking: List[Requirement] = []
    optional_missing: List[Requirement] = []
    for r in items:
        if r.network_only:
            print(f"  [NOTE]  {r.command:<24} {r.feature} (network)")
        elif r.installed:
            print(f"  [ OK ]  {r.command:<24} {r.feature}")
        elif r.optional:
            optional_missing.append(r)
            print(f"  [WARN]  {r.command:<24} {r.feature} (optional - will be skipped)")
            print(f"          install: {r.install_hint}")
        else:
            blocking.append(r)
            print(f"  [MISS]  {r.command:<24} {r.feature}")
            print(f"          install: {r.install_hint}")

    if blocking:
        if strict:
            print(f"\n{len(blocking)} required tool(s) missing - the scan will be stopped.")
        else:
            print(f"\n{len(blocking)} tool(s) missing - those specific checks will be skipped "
                  "(the scan still runs).")
    elif optional_missing:
        print(f"\n{len(optional_missing)} optional tool(s) missing - those checks are skipped; the scan proceeds.")
    else:
        print("All required tools are installed.")
    return blocking


def print_setup_guide(missing: List[Requirement]) -> None:
    """Print actionable install/setup instructions and how to bypass, on a strict abort."""
    print("\n" + "=" * 64)
    print(f"Scan stopped: {len(missing)} required tool(s) must be installed first.")
    print("=" * 64)
    print("Install the following, then re-run the scan:\n")
    for r in sorted(missing, key=lambda x: x.command):
        print(f"  - {r.command}  ({r.feature})")
        print(f"      {r.install_hint}\n")
    print("To scan without these checks instead:")
    print("  --install-missing           try to auto-install the tools above, then scan")
    print("  --no-strict-requirements    warn about missing tools but scan anyway")
    print("  --skip-requirements-check   skip the requirements check entirely")
    print("  (or set 'preflight.strict: false' in config.yaml)")


def _needs_go(r: "Requirement") -> bool:
    """Does installing this requirement rely on the Go toolchain?"""
    cmd = INSTALL_COMMANDS.get(r.command)
    return cmd is not None and cmd[0] == "go"


def _platform_tokens() -> Tuple[List[str], List[str]]:
    """OS and CPU-arch name tokens used to match a release asset filename."""
    if sys.platform.startswith("win"):
        os_tok = ["windows"]
    elif sys.platform == "darwin":
        os_tok = ["darwin", "macos"]
    else:
        os_tok = ["linux"]
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        arch_tok = ["amd64", "x86_64", "x64"]
    elif machine in ("arm64", "aarch64"):
        arch_tok = ["arm64", "aarch64"]
    else:
        arch_tok = [machine]
    return os_tok, arch_tok


def install_from_github_release(tool: str, repo: str) -> Tuple[bool, str]:
    """Download the official prebuilt binary for `tool` from the latest GitHub release
    of `repo`, matching this OS/arch, and place it in scanner_bin_dir(). Returns
    (ok, detail). Uses GITHUB_TOKEN/GH_TOKEN if set (higher rate limit)."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "security-scanner"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            release = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        return False, f"could not query GitHub releases ({e})"

    os_tok, arch_tok = _platform_tokens()
    assets = release.get("assets", [])
    chosen = None
    for asset in assets:
        name = asset.get("name", "").lower()
        if not name.endswith((".tar.gz", ".tgz", ".zip")):
            continue
        if any(o in name for o in os_tok) and any(a in name for a in arch_tok):
            chosen = asset
            break
    if not chosen:
        return False, f"no prebuilt binary for this OS/arch in {repo} {release.get('tag_name', '')}"

    binname = tool + (".exe" if sys.platform.startswith("win") else "")
    tmp = tempfile.mkdtemp(prefix=f"{tool}_dl_")
    try:
        archive = os.path.join(tmp, chosen["name"])
        dreq = urllib.request.Request(chosen["browser_download_url"], headers={"User-Agent": "security-scanner"})
        with urllib.request.urlopen(dreq, timeout=180) as resp, open(archive, "wb") as fh:
            shutil.copyfileobj(resp, fh)

        extract_dir = os.path.join(tmp, "x")
        os.makedirs(extract_dir, exist_ok=True)
        if archive.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(extract_dir)
        else:
            with tarfile.open(archive) as tf:
                tf.extractall(extract_dir)

        src = None
        for root, _dirs, files in os.walk(extract_dir):
            for fn in files:
                if fn.lower() == binname.lower():
                    src = os.path.join(root, fn)
                    break
            if src:
                break
        if not src:
            return False, f"'{binname}' not found inside {chosen['name']}"

        dest_dir = scanner_bin_dir()
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, binname)
        shutil.copy2(src, dest)
        if not sys.platform.startswith("win"):
            os.chmod(dest, os.stat(dest).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return True, dest
    except (urllib.error.URLError, OSError, tarfile.TarError, zipfile.BadZipFile) as e:
        return False, f"download/extract failed ({e})"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def attempt_auto_install(missing: List[Requirement], binary_installer: str = "auto",
                         bootstrap_runtimes: bool = True) -> List[Requirement]:
    """Try to install each missing tool that has a known installer. Returns the
    requirements still missing afterwards.

    Resolution per tool: pip/toolchain installer (INSTALL_COMMANDS), else an OS
    package manager (BINARY_INSTALL_COMMANDS), else `go install` (GO_INSTALLABLE).
    When a tool needs Go and Go is absent, Go itself is bootstrapped first via a signed
    package manager (winget/brew/scoop/choco) — never via a remote script.
    Tools with no available installer are reported for manual setup.
    """
    print("\nAttempting to auto-install missing tools...")
    installed_ok = set()       # install command returned success
    pkg_mgr_installs = []      # binaries installed via a package manager (PATH may be stale)

    # Bootstrap pass: install Go (signed package manager only) if a missing tool can
    # only be installed via the Go toolchain and Go isn't present.
    if bootstrap_runtimes and any(_needs_go(r) for r in missing) and not resolve_command("go"):
        mgr = _pick_manager_for(BOOTSTRAP_COMMANDS["go"], binary_installer)
        if mgr:
            boot_cmd = BOOTSTRAP_COMMANDS["go"][mgr]
            print(f"  [BOOTSTRAP] go  ->  {' '.join(boot_cmd)}")
            try:
                proc = subprocess.run(boot_cmd, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=900)
                out = (proc.stderr or "") + (proc.stdout or "")
                if proc.returncode == 0 or _already_satisfied(proc.returncode, out):
                    print("              ok")
                else:
                    last = (out.strip().splitlines() or ["see tool output"])[-1]
                    print(f"              failed (exit {proc.returncode}): {last}")
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
                print(f"              could not run ({type(e).__name__})")
            importlib.invalidate_caches()
        else:
            print("  [NOTE] Go is required to install some tools but no package manager "
                  "is available to bootstrap it (winget/brew/scoop/choco). Install Go manually.")

    go_bin = resolve_command("go")

    for r in missing:
        cmd = INSTALL_COMMANDS.get(r.command)
        via_pkg_mgr = False
        if not cmd:
            manager = _pick_manager(r.command, binary_installer)
            if manager:
                cmd = BINARY_INSTALL_COMMANDS[r.command][manager]
                via_pkg_mgr = True
        # Run go-based installers with the resolved Go path (PATH may be stale after a
        # just-completed Go bootstrap).
        if cmd and cmd[0] == "go" and go_bin:
            cmd = [go_bin] + cmd[1:]
        # Last resort: download the official prebuilt release binary (no package
        # manager or runtime needed). Handled here since it's not a subprocess command.
        if not cmd and r.command in GITHUB_RELEASES:
            repo = GITHUB_RELEASES[r.command]
            print(f"  [DOWNLOAD] {r.command}  <-  github.com/{repo} (latest release)")
            ok, detail = install_from_github_release(r.command, repo)
            if ok:
                print(f"            ok -> {detail}")
                installed_ok.add(r.command)
            else:
                print(f"            failed: {detail}")
                print(f"            install manually: {r.install_hint}")
            continue
        if not cmd:
            print(f"  [SKIP]    {r.command} - no automatic installer available; install manually: {r.install_hint}")
            continue

        print(f"  [INSTALL] {r.command}  ->  {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
            print(f"            could not run installer ({type(e).__name__}); install manually: {r.install_hint}")
            continue
        output = (proc.stderr or "") + (proc.stdout or "")
        if proc.returncode == 0 or _already_satisfied(proc.returncode, output):
            print("            ok" if proc.returncode == 0 else "            already installed")
            installed_ok.add(r.command)
            if via_pkg_mgr:
                pkg_mgr_installs.append(r.command)
        else:
            last = output.strip().splitlines()
            print(f"            failed (exit {proc.returncode}): {last[-1] if last else 'see tool output'}")

    if pkg_mgr_installs:
        print(f"  Note: {', '.join(pkg_mgr_installs)} installed via a package manager - if the scan "
              "can't find it yet, open a new terminal so PATH refreshes, then re-run.")

    # New console scripts / modules may have appeared; refresh import caches and re-check.
    # A successful install command counts as resolved even if PATH isn't refreshed in-process.
    importlib.invalidate_caches()
    return [r for r in missing if r.command not in installed_ok and not r.installed]
