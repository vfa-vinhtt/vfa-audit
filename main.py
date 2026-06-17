
import argparse
import datetime
import importlib
import pkgutil
import platform
import re
import shutil
import sys
import zipfile
from pathlib import Path

import yaml

VERSION = "1.0.0"


def detect_environment() -> str:
    """Human-readable OS name + version for the report (e.g. 'Windows 11 (build
    10.0.26200)', 'macOS 14.5', 'Ubuntu 22.04 (kernel 6.5.0)')."""
    system = platform.system()
    try:
        if system == "Darwin":
            return f"macOS {platform.mac_ver()[0] or platform.release()}"
        if system == "Windows":
            return f"Windows {platform.release()} (build {platform.version()})"
        if system == "Linux":
            try:
                info = platform.freedesktop_os_release()
                name = info.get("PRETTY_NAME") or info.get("NAME", "Linux")
            except Exception:
                name = "Linux"
            return f"{name} (kernel {platform.release()})"
    except Exception:
        pass
    return f"{system} {platform.release()}".strip() or "N/A"

from scanner.core.file_scanner import FileScanner
from scanner.core.git_scanner import GitScanner
from scanner.core.report_engine import ReportEngine
from scanner.plugins.base_plugin import BasePlugin, Finding


_KNOWN_PLUGINS = [
    'pii_checker', 'dependency_checker', 'env_checker', 'config_checker',
    'asset_checker', 'gitignore_checker', 'secret_checker', 'license_checker',
]
_KNOWN_ADAPTERS = ['node', 'python', 'go', 'java', 'dotnet', 'swift', 'php']


def _iter_submodule_names(package) -> list[str]:
    """Return submodule names for a package, with a PyInstaller frozen fallback."""
    names = [name for _, name, _ in pkgutil.iter_modules(package.__path__)]
    if not names and getattr(sys, 'frozen', False):
        _known = {
            'scanner.plugins': _KNOWN_PLUGINS,
            'scanner.adapters': _KNOWN_ADAPTERS,
        }
        names = _known.get(package.__name__, [])
    return names


def _resolve_config(config_arg: str) -> Path:
    """Resolve config path: explicit arg → CWD → bundled default (PyInstaller)."""
    p = Path(config_arg).resolve()
    if p.exists():
        return p
    if getattr(sys, 'frozen', False):
        bundled = Path(sys._MEIPASS) / "config.yaml"
        if bundled.exists():
            return bundled
    return p


def load_config(config_path: Path) -> dict:
    """Loads the YAML configuration file."""
    if config_path.exists():
        return yaml.safe_load(config_path.read_text(encoding="utf-8"))
    return {}


def discover_and_load_plugins(config: dict) -> list[BasePlugin]:
    """Dynamically discovers and loads all plugins from the scanner.plugins package."""
    import scanner.plugins

    plugins = []
    plugin_config = config.get("plugins", {})

    for name in _iter_submodule_names(scanner.plugins):
        if name != "base_plugin":
            try:
                module = importlib.import_module(f"scanner.plugins.{name}")
                for item in dir(module):
                    obj = getattr(module, item)
                    if isinstance(obj, type) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                        # Check if plugin is enabled in config
                        if plugin_config.get(obj.name, {}).get("enabled", True):
                            plugins.append(obj(config=plugin_config.get(obj.name)))
            except Exception as e:
                print(f"Error loading plugin {name}: {e}", file=sys.stderr)
    return plugins

def collect_adapter_ignore_dirs() -> set:
    """Union of every adapter's per-language IGNORE_DIRS (e.g. node_modules, vendor,
    target, Pods, bin/obj). Read from the adapter classes so each language's ignore
    dirs live in its adapter; the common, language-agnostic dirs come from config."""
    import scanner.adapters
    from scanner.adapters.base_adapter import BaseAdapter

    dirs: set = set()
    for name in _iter_submodule_names(scanner.adapters):
        if name == "base_adapter":
            continue
        try:
            module = importlib.import_module(f"scanner.adapters.{name}")
        except Exception:
            continue
        for item in dir(module):
            obj = getattr(module, item)
            if isinstance(obj, type) and issubclass(obj, BaseAdapter) and obj is not BaseAdapter:
                dirs |= set(getattr(obj, "IGNORE_DIRS", set()) or set())
    return dirs


def discover_adapter_instances(root: Path, config: dict) -> list:
    """Dynamically discovers and loads all adapter instances from the scanner.adapters package."""
    import scanner.adapters

    adapter_instances = []
    adapter_config = config.get("adapters", {})

    for name in _iter_submodule_names(scanner.adapters):
        if name != "base_adapter":
            try:
                module = importlib.import_module(f"scanner.adapters.{name}")
                for item in dir(module):
                    obj = getattr(module, item)
                    if isinstance(obj, type) and issubclass(obj, scanner.adapters.base_adapter.BaseAdapter) and obj is not scanner.adapters.base_adapter.BaseAdapter:
                        adapter_instance = obj(root)
                        if adapter_instance.detect():
                            adapter_instances.append(adapter_instance)
            except Exception as e:
                print(f"Error loading adapter {name}: {e}", file=sys.stderr)
    return adapter_instances


def main():
    """Main entry point for the security scanner."""
    # Make console output robust across OS / locale / redirection. Windows consoles
    # default to a legacy code page (e.g. cp932) that can't encode the report's
    # box-drawing/emoji characters and crashes when output is piped or redirected;
    # Linux/macOS are already UTF-8 so this is a no-op there.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(description="A multi-language security scanner.")
    parser.add_argument("path", nargs="?", default=".", help="Path to the project to scan. Defaults to current directory.")
    parser.add_argument("--config", default="config.yaml", help="Path to the configuration file.")
    parser.add_argument("-o", "--output", default=None, help="Output basename or directory. Defaults to '<YYYYMMDD_HHmm>_<project-name>' in the current directory.")
    parser.add_argument("--format", choices=["json", "md", "html", "console", "policy"], default="json",
                        help="Output format. 'policy' writes blockers/review-required/warnings JSON files into a directory.")
    parser.add_argument("--zip", action="store_true",
                        help="Compress the generated output (directory for 'policy', file otherwise) into a zip archive.")
    parser.add_argument("--strict-requirements", action="store_true",
                        help="Force-stop the scan if a required external tool is missing (this is the default).")
    parser.add_argument("--no-strict-requirements", action="store_true",
                        help="Warn about missing tools but scan anyway (overrides strict mode for this run).")
    parser.add_argument("--skip-requirements-check", action="store_true",
                        help="Skip the pre-scan tool requirements check entirely.")
    parser.add_argument("--install-missing", action="store_true",
                        help="Attempt to auto-install missing tools (pip/go/npm/dotnet/gem) before scanning.")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    config_path = _resolve_config(args.config)

    if not root.is_dir():
        print(f"Error: Path '{root}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning project at: {root}")

    # 1. Load configuration
    config = load_config(config_path)

    # 2. Initialize scanners. Ignore dirs = a minimal baseline (file_scanner) +
    # language-agnostic dirs from config + per-language dirs declared by the adapters.
    fs_config = dict(config.get("file_scanner", {}))
    fs_config["ignore_dirs"] = sorted(
        set(fs_config.get("ignore_dirs", [])) | collect_adapter_ignore_dirs()
    )
    file_scanner = FileScanner(config=fs_config)
    git_scanner = GitScanner(root)

    # 3. Gather project context
    project_info = {
        "project_name": root.name,
        "path": str(root),
        "scan_path": str(root),
    }
    if git_scanner.is_git_repo():
        git_info = git_scanner.get_info()
        # Normalize git_scanner's keys to the names the report renderers expect.
        project_info.update({
            "git_remote": git_info.get("remote_url", "N/A"),
            "git_branch": git_info.get("branch", "N/A"),
            "git_last_commit": git_info.get("last_commit", "N/A"),
            "git_author": git_info.get("author", "N/A"),
            "repo_name": git_info.get("repo_name", root.name),
        })

    project_info["languages"] = file_scanner.detect_language(root)

    # Resolve output basename early (needed to exclude own report files from scan).
    _timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    _project_slug = re.sub(r"[^\w\-]", "_", project_info.get("project_name", "project"))
    _auto_stem = f"{_timestamp}_{_project_slug}"

    # Default output: <tool_dir>/report/<timestamp>_<project>.
    # Tool dir is the directory containing the frozen binary (sys.executable when
    # PyInstaller) or the directory containing main.py when running from source.
    _tool_dir = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
    _default_output_dir = _tool_dir / "report"

    if args.output is None:
        output_basename = _default_output_dir / _auto_stem
    else:
        _out = Path(args.output)
        if _out.is_dir():
            output_basename = _out / _auto_stem
        else:
            output_basename = _out

    # 4. Scan files
    # Parse .gitignore so plugins (env_checker, gitignore_checker) can reason about
    # which sensitive files are covered. This does NOT prune the scan — a security
    # scanner should still inspect files that were supposed to be ignored.
    file_scanner.load_gitignore(root)
    text_files, asset_files, all_files = file_scanner.scan(root)

    # Don't let the scanner ingest its own report output if it lives in the scan
    # tree (otherwise it re-flags example emails/patterns embedded in the report).
    _own_reports = {output_basename.with_suffix(s).resolve() for s in (".json", ".md", ".html")}
    all_files = [f for f in all_files if f.resolve() not in _own_reports]
    asset_files = [f for f in asset_files if f.resolve() not in _own_reports]

    # 5. Load adapters and get context
    adapter_instances = discover_adapter_instances(root, config)
    adapter_context = {"packages": {}}
    for instance in adapter_instances:
        collected_data = instance.collect()
        if "packages" in collected_data:
            adapter_context["packages"].update(collected_data.pop("packages"))
        adapter_context.update(collected_data)

    # Surface adapter-derived metadata to the report renderers.
    project_info["framework"] = adapter_context.get("framework") or "N/A"
    project_info["files_scanned"] = len(all_files)
    project_info["environment"] = detect_environment()

    # Git tracking state lets gitignore/env checks distinguish "actually committed"
    # from "merely present on disk". Degrades gracefully when not a git repo.
    is_git_repo = git_scanner.is_git_repo()
    git_tracked_files = set(git_scanner.get_tracked_files()) if is_git_repo else set()

    context = {
        "project_info": project_info,
        "gitignore_entries": set(file_scanner._gitignore_patterns),
        "asset_files": asset_files,
        "is_git_repo": is_git_repo,
        "git_tracked_files": git_tracked_files,
        "ignore_dirs": sorted(file_scanner._ignore_dirs),
        "adapter_instances": adapter_instances,
        "adapters": adapter_context,
    }

    # 5.5 Pre-scan requirements check — verify the external tools the enabled config
    # features need (scoped to detected languages) are installed before scanning.
    preflight_cfg = config.get("preflight", {})
    if not args.skip_requirements_check and preflight_cfg.get("enabled", True):
        from scanner.core.requirements import (
            collect_requirements, print_requirements_report, print_setup_guide,
            attempt_auto_install,
        )
        # Strict by default: stop the scan when a required tool is missing so no
        # check is silently skipped. Per-run / config overrides relax it.
        if args.no_strict_requirements:
            strict = False
        elif args.strict_requirements:
            strict = True
        else:
            strict = preflight_cfg.get("strict", True)

        missing, version_mismatches = print_requirements_report(
            collect_requirements(config, adapter_instances), strict=strict
        )

        _installer_kwargs = dict(
            binary_installer=preflight_cfg.get("binary_installer", "auto"),
            bootstrap_runtimes=preflight_cfg.get("bootstrap_runtimes", True),
        )

        # Auto-upgrade tools that are installed but at the wrong version — always,
        # no flag needed. pip/go/npm install with a pinned version spec upgrades
        # or downgrades to the exact pinned release.
        if version_mismatches:
            still_wrong = attempt_auto_install(version_mismatches, **_installer_kwargs)
            if still_wrong:
                names = ", ".join(r.command for r in still_wrong)
                print(f"  Could not upgrade: {names} — scan continues with installed version.")
            else:
                print("  All tools upgraded to pinned versions.")

        # Opt-in auto-install of missing tools, then re-check what remains.
        if missing and (args.install_missing or preflight_cfg.get("auto_install", False)):
            missing = attempt_auto_install(missing, **_installer_kwargs)
            if missing:
                print(f"\n{len(missing)} tool(s) still missing after auto-install.")
            else:
                print("\nAll required tools installed successfully.")

        if missing and strict:
            print_setup_guide(missing)
            sys.exit(2)


    # 6. Load and run plugins
    plugins = discover_and_load_plugins(config)
    all_findings: list[Finding] = []
    
    print(f"Loaded {len(plugins)} plugins: {[p.name for p in plugins]}")

    for plugin in plugins:
        print(f"Running plugin: {plugin.name}...")
        try:
            findings = plugin.scan(root, all_files, context)
            all_findings.extend(findings)
        except Exception as e:
            print(f"Error running plugin {plugin.name}: {e}", file=sys.stderr)

    # 7. Collect tool versions for the info section of the report.
    from scanner.core.requirements import collect_tool_info
    tool_info = collect_tool_info()

    # 8. Generate report
    report_engine = ReportEngine(all_findings, project_info, tool_info, scanner_version=VERSION)

    output_basename.parent.mkdir(parents=True, exist_ok=True)


    _zip_source: Path | None = None

    if args.format == "console":
        report_engine.print_summary()
    elif args.format == "json":
        p = output_basename.with_suffix(".json")
        report_engine.save_json(p)
        print(f"JSON report saved to {p}")
        _zip_source = p
    elif args.format == "md":
        p = output_basename.with_suffix(".md")
        report_engine.save_markdown(p)
        print(f"Markdown report saved to {p}")
        _zip_source = p
    elif args.format == "html":
        p = output_basename.with_suffix(".html")
        report_engine.save_html(p)
        print(f"HTML report saved to {p}")
        _zip_source = p
    elif args.format == "policy":
        policy_dir = output_basename.with_suffix("")
        summary = report_engine.save_policy_report(policy_dir)
        status = summary["status"]
        print(f"Policy report saved to {policy_dir}/")
        print(f"  blockers.json        : {summary['counts']['blockers']} finding(s)")
        print(f"  review-required.json : {summary['counts']['review_required']} finding(s)")
        print(f"  warnings.json        : {summary['counts']['warnings']} finding(s)")
        print(f"  status               : {status}")
        _zip_source = policy_dir

    if args.zip and _zip_source:
        if _zip_source.is_dir():
            zip_base = str(_zip_source)
            shutil.make_archive(zip_base, "zip", _zip_source.parent, _zip_source.name)
            print(f"Zipped to {zip_base}.zip")
        elif _zip_source.is_file():
            zip_path = output_basename.with_suffix(".zip")
            with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as zf:
                zf.write(_zip_source, _zip_source.name)
            print(f"Zipped to {zip_path}")
    elif args.zip:
        print("Note: --zip has no effect for console output.", file=sys.stderr)

    print(f"Scan complete. Found {len(all_findings)} issues.")

    if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
