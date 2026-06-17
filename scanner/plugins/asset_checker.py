"""
Plugin: Asset Checker
Detects:
1. Font files (.ttf, .otf, .woff, .woff2) without associated license files
2. Image files without clear license attribution
3. Common stock photo filename patterns that may indicate unlicensed images
"""
from __future__ import annotations
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import List, Set, Dict

from .base_plugin import BasePlugin, Finding, Severity
from ..core.requirements import resolve_command

# Optional libraries for reading embedded asset metadata. The checker degrades to
# filename/nearby-LICENSE heuristics when any of these is unavailable.
try:
    from fontTools.ttLib import TTFont
except Exception:  # pragma: no cover - import guard
    TTFont = None
try:
    from PIL import Image as _PILImage
except Exception:  # pragma: no cover
    _PILImage = None
try:
    import pytesseract as _pytesseract
except Exception:  # pragma: no cover
    _pytesseract = None

FONT_EXTENSIONS: Set[str] = {".ttf", ".otf", ".woff", ".woff2", ".eot"}
IMAGE_EXTENSIONS: Set[str] = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff"}
SVG_EXTENSION = ".svg"

# License file names to look for alongside assets
LICENSE_FILE_NAMES: Set[str] = {
    "LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "LICENCE.txt",
    "OFL.txt", "OFL-1.1.txt",  # SIL Open Font License
    "NOTICE", "NOTICE.txt",
    "copyright", "copyright.txt",
    "font-license.txt", "font-license.md",
}

# Stock photo / paid asset patterns in filenames
STOCK_PHOTO_PATTERNS = [
    r"(?i)shutterstock[_\-]?\d+",
    r"(?i)getty[_\-]?images?[_\-]?\d*",
    r"(?i)istock[_\-]?\d+",
    r"(?i)adobe[_\-]?stock[_\-]?\d*",
    r"(?i)dreamstime[_\-]?\d+",
    r"(?i)bigstock[_\-]?\d+",
    r"(?i)123rf[_\-]?\d+",
    r"(?i)depositphotos[_\-]?\d+",
    r"(?i)alamy[_\-]?\d+",
    r"(?i)fotolia[_\-]?\d+",
    r"(?i)istockphoto[_\-]?\d+",
]

# Well-known free fonts (no license concern)
FREE_FONTS: Set[str] = {
    "roboto", "opensans", "open-sans", "lato", "montserrat", "raleway",
    "sourcesanspro", "source-sans-pro", "ubuntu", "nunito", "poppins",
    "merriweather", "oswald", "noto", "inter", "firasans", "fira-sans",
    "playfairdisplay", "playfair", "inconsolata", "firacode", "fira-code",
    "sourcecodepro", "source-code-pro", "jetbrainsmono", "jetbrains-mono",
    "liberation", "dejavu", "freefont", "linuslibertine",
    "materialicons", "fontawesome",  # icon fonts — check license
}

# Icon fonts that require specific licenses
COMMERCIAL_RISK_FONTS: Set[str] = {
    "fontawesome",  # Pro version requires license
    "icomoon",
    "glyphicons",   # Bootstrap 3 - check version
    "ionicons",
}

# ExifTool: license text patterns that indicate embedding is blocked
FONT_BLOCK_RE = re.compile(
    r"non[\-\s]?commercial|personal[\-\s]?use|trial|demo|evaluation|restricted|proprietary",
    re.IGNORECASE,
)
# ExifTool: copyleft patterns that require a compatibility review
FONT_REVIEW_RE = re.compile(r"\bgpl\b|sspl", re.IGNORECASE)


def _hash_font_file(path: Path) -> str:
    """SHA256 of a font file — used to identify renamed fonts across projects."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _dir_has_license(directory: Path) -> bool:
    """Check if a directory contains any license file."""
    for child in directory.iterdir():
        if child.name in LICENSE_FILE_NAMES or child.name.lower() in {
            n.lower() for n in LICENSE_FILE_NAMES
        }:
            return True
    return False


def _find_nearest_license(path: Path, root: Path) -> bool:
    """Walk up the directory tree from path to root looking for a license file."""
    current = path.parent
    while current >= root:
        try:
            for item in current.iterdir():
                if item.name in LICENSE_FILE_NAMES or item.name.upper() in {
                    n.upper() for n in LICENSE_FILE_NAMES
                }:
                    return True
        except PermissionError:
            pass
        if current == root:
            break
        current = current.parent
    return False


class AssetChecker(BasePlugin):
    name = "asset_checker"
    description = "Detects potentially unlicensed fonts, images, and other binary assets"

    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        self.findings = []
        asset_files: List[Path] = context.get("asset_files", [])

        fonts: List[Path] = []
        images: List[Path] = []
        svgs: List[Path] = []

        for f in asset_files:
            ext = f.suffix.lower()
            if ext in FONT_EXTENSIONS:
                fonts.append(f)
            elif ext == SVG_EXTENSION:
                svgs.append(f)
            elif ext in IMAGE_EXTENSIONS:
                images.append(f)

        # Also collect SVGs from text files list (they are text-based)
        for f in files:
            if f.suffix.lower() == SVG_EXTENSION:
                svgs.append(f)

        tools = self.config.get("tools", {})
        do_font_meta = tools.get("font_metadata", True) and TTFont is not None
        do_image_meta = tools.get("image_metadata", True) and _PILImage is not None
        do_ocr = tools.get("ocr_text_in_image", False) and _pytesseract is not None and _PILImage is not None
        do_exiftool = tools.get("exiftool_metadata", False)

        # Filename / nearby-LICENSE heuristics (always run, fast). When per-font
        # metadata checking is active it owns the license verdict, so skip the weak
        # directory-LICENSE heuristic to avoid contradictory findings.
        self._check_fonts(fonts, root, skip_license_dir_check=do_font_meta)
        self._check_images(images, root)
        self._check_svgs(svgs, root)

        # Deep metadata checks (read the actual asset) when the libs are available.
        if do_font_meta:
            for f in fonts:
                self._check_font_license(f, str(f.relative_to(root)))
        elif fonts and tools.get("font_metadata", True):
            self.add_finding(
                severity=Severity.INFO, title="Font license deep-check skipped (fonttools not installed)",
                description="Embedded font license/fsType could not be read; using filename heuristics only.",
                recommendation="Install fonttools (pip install fonttools) to verify each font's embedding rights.",
                tags=["asset", "font"],
            )

        if do_exiftool and fonts:
            if resolve_command("exiftool"):
                self._scan_with_exiftool(fonts, root)
            else:
                self.add_finding(
                    severity=Severity.INFO,
                    title="ExifTool font metadata scan skipped (exiftool not installed)",
                    description="ExifTool copyright/license text could not be read from font files.",
                    recommendation=(
                        "Install exiftool (brew install exiftool | "
                        "apt install libimage-exiftool-perl | choco/scoop install exiftool) "
                        "to enable font license-text analysis alongside the fsType check."
                    ),
                    tags=["asset", "font"],
                )

        if do_image_meta:
            for f in images:
                self._check_image_license(f, str(f.relative_to(root)))
        elif images and tools.get("image_metadata", True):
            self.add_finding(
                severity=Severity.INFO, title="Image license deep-check skipped (Pillow not installed)",
                description="Embedded image copyright/usage metadata could not be read; using filename heuristics only.",
                recommendation="Install Pillow (pip install Pillow) to read image EXIF/XMP license metadata.",
                tags=["asset", "image"],
            )

        if do_ocr:
            # Point pytesseract at the resolved tesseract binary so OCR works even when
            # the engine (e.g. winget's Program Files\Tesseract-OCR) isn't on PATH yet.
            tess = resolve_command("tesseract")
            if tess:
                try:
                    _pytesseract.pytesseract.tesseract_cmd = tess
                except Exception:
                    pass
            for f in images:
                self._check_image_text(f, str(f.relative_to(root)))

        if not fonts and not images and not svgs:
            self.add_finding(
                severity=Severity.INFO,
                title="No font or image assets detected",
                description="No font or image files were found in the project.",
                recommendation="If assets are added in future, ensure they have proper licenses.",
                tags=["asset"],
            )

        return self.findings

    def _check_fonts(self, fonts: List[Path], root: Path, skip_license_dir_check: bool = False) -> None:
        # `skip_license_dir_check` is set when per-font embedded-metadata checking is
        # active: fsType is authoritative, so the weak "is there a LICENSE file nearby"
        # heuristic would just add noise/contradiction.
        # Group by directory to avoid per-file noise
        dirs_checked: Dict[Path, bool] = {}
        font_dirs: Dict[Path, List[Path]] = {}

        for f in fonts:
            font_dirs.setdefault(f.parent, []).append(f)

        for directory, font_list in font_dirs.items():
            has_license = _find_nearest_license(font_list[0], root)
            dirs_checked[directory] = has_license
            rel_dir = str(directory.relative_to(root)) if directory != root else "."

            # Check for commercial-risk font names
            for fpath in font_list:
                fname_lower = fpath.stem.lower().replace("-", "").replace("_", "")
                rel = str(fpath.relative_to(root))

                # Stock-photo pattern check on fonts (unusual but possible)
                for pattern in STOCK_PHOTO_PATTERNS:
                    if re.search(pattern, fpath.name):
                        self.add_finding(
                            severity=Severity.HIGH,
                            title=f"Possible paid/stock font: {fpath.name}",
                            description=(
                                f"Font '{rel}' matches a pattern associated with paid font services."
                            ),
                            recommendation="Verify you have a valid commercial license for this font.",
                            file=rel,
                            tags=["asset", "font", "license"],
                        )

                for risk_font in COMMERCIAL_RISK_FONTS:
                    if risk_font in fname_lower:
                        self.add_finding(
                            severity=Severity.MEDIUM,
                            title=f"Font with potential commercial license requirement: {fpath.name}",
                            description=(
                                f"'{rel}' appears to be '{risk_font}'. Some versions or "
                                "feature sets require a paid commercial license."
                            ),
                            recommendation=(
                                f"Verify your license for {risk_font}. "
                                "Free tiers may restrict commercial use or advanced icon sets."
                            ),
                            file=rel,
                            tags=["asset", "font", "commercial"],
                        )

            if skip_license_dir_check:
                continue  # embedded-metadata check (fsType) is authoritative per font

            if not has_license:
                font_names = ", ".join(f.name for f in font_list[:5])
                self.add_finding(
                    severity=Severity.HIGH,
                    title=f"Font files without license in directory: {rel_dir}/",
                    description=(
                        f"Found {len(font_list)} font file(s) ({font_names}) in '{rel_dir}/' "
                        "with no LICENSE file in the directory tree. "
                        "Using fonts without a license may violate font foundry terms."
                    ),
                    recommendation=(
                        "1. Verify the font license from its source.\n"
                        "2. If it's an open license (SIL OFL, Apache-2.0), "
                        "include a copy of the license (e.g., OFL.txt) in the font directory.\n"
                        "3. If it's a commercial font, ensure you have a web/app license.\n"
                        "4. Consider replacing with free alternatives (Google Fonts)."
                    ),
                    file=rel_dir,
                    tags=["asset", "font", "license"],
                )
            else:
                self.add_finding(
                    severity=Severity.INFO,
                    title=f"Font directory has license file: {rel_dir}/",
                    description=f"Fonts in '{rel_dir}/' have an associated license file.",
                    recommendation="Verify the license permits your intended usage (web, app, commercial).",
                    file=rel_dir,
                    tags=["asset", "font"],
                )

    def _check_images(self, images: List[Path], root: Path) -> None:
        if not images:
            return

        stock_matches: List[Path] = []
        for img in images:
            for pattern in STOCK_PHOTO_PATTERNS:
                if re.search(pattern, img.name):
                    stock_matches.append(img)
                    break

        if stock_matches:
            for img in stock_matches:
                rel = str(img.relative_to(root))
                self.add_finding(
                    severity=Severity.CRITICAL,
                    title=f"Possible unlicensed stock image: {img.name}",
                    description=(
                        f"'{rel}' matches a pattern associated with paid stock photo services "
                        "(Shutterstock, Getty Images, iStock, etc.). "
                        "Using these without a valid license violates copyright law."
                    ),
                    recommendation=(
                        "1. Verify you have a valid download receipt/license for this image.\n"
                        "2. If not licensed, replace with free alternatives from:\n"
                        "   - Unsplash (unsplash.com) — free commercial use\n"
                        "   - Pexels (pexels.com) — free commercial use\n"
                        "   - Pixabay (pixabay.com) — free commercial use\n"
                        "3. Store license receipts alongside assets."
                    ),
                    file=rel,
                    tags=["asset", "image", "stock", "license"],
                )

        # Check if there's a licenses/attribution file for images
        has_attribution = _find_nearest_license(images[0], root)
        if not has_attribution and not stock_matches:
            # Only warn if there are a significant number of images
            if len(images) >= 5:
                self.add_finding(
                    severity=Severity.LOW,
                    title=f"{len(images)} image files found without license attribution",
                    description=(
                        f"Found {len(images)} image files. No LICENSE or attribution file was found nearby. "
                        "Images sourced from the web may have copyright restrictions."
                    ),
                    recommendation=(
                        "Create an ASSETS.md or LICENSE file documenting the source and license "
                        "for each image. Use Creative Commons or public domain images."
                    ),
                    tags=["asset", "image"],
                )

    def _check_svgs(self, svgs: List[Path], root: Path) -> None:
        """Check SVG files for embedded license/attribution info and stock patterns."""
        for svg in svgs:
            rel = str(svg.relative_to(root))

            # Check for stock photo patterns in SVG filenames
            for pattern in STOCK_PHOTO_PATTERNS:
                if re.search(pattern, svg.name):
                    self.add_finding(
                        severity=Severity.HIGH,
                        title=f"Possible paid stock SVG: {svg.name}",
                        description=f"'{rel}' matches a stock image service filename pattern.",
                        recommendation="Verify licensing. Replace with freely licensed SVGs if needed.",
                        file=rel,
                        tags=["asset", "svg", "stock"],
                    )

            # Check SVG content for copyright notices
            lines = self._read_lines(svg)
            content = "\n".join(lines[:30])  # Check first 30 lines only
            has_copyright = bool(re.search(r"(?i)copyright|©|\(c\)|license", content))
            has_attribution = bool(re.search(r"(?i)inkscape|illustrator|sketch", content))

            if has_copyright and not any(
                keyword in content.lower() for keyword in ["mit", "apache", "cc0", "public domain", "unlicense", "free"]
            ):
                self.add_finding(
                    severity=Severity.MEDIUM,
                    title=f"SVG contains copyright notice — verify license: {svg.name}",
                    description=(
                        f"'{rel}' contains a copyright notice but the license is unclear. "
                        "Ensure you have permission to use and distribute this SVG."
                    ),
                    recommendation=(
                        "Check the original source for license terms. "
                        "If unclear, replace with a freely licensed alternative."
                    ),
                    file=rel,
                    tags=["asset", "svg", "copyright"],
                )

    # ── Deep metadata checks (read the actual asset) ────────────────────────────

    def _check_font_license(self, fpath: Path, rel: str) -> None:
        """Read a font's embedded license: OS/2 fsType embedding rights + name table
        (copyright / license description / license URL). fsType is the authoritative,
        machine-readable signal for whether the font may be embedded/redistributed."""
        try:
            font = TTFont(str(fpath), fontNumber=0, lazy=True)
        except Exception:
            return  # unreadable (e.g. .woff2 needs brotli) — heuristics still apply

        copyright_ = license_desc = license_url = ""
        fstype = None
        try:
            if "name" in font:
                name = font["name"]

                def _get(nid: int) -> str:
                    rec = name.getName(nid, 3, 1) or name.getName(nid, 1, 0)
                    try:
                        return rec.toUnicode().strip() if rec else ""
                    except Exception:
                        return ""

                copyright_, license_desc, license_url = _get(0), _get(13), _get(14)
            if "OS/2" in font:
                fstype = font["OS/2"].fsType
        except Exception:
            pass
        finally:
            try:
                font.close()
            except Exception:
                pass

        sha256 = _hash_font_file(fpath)
        sha256_suffix = f"\nSHA256: {sha256}" if sha256 else ""
        _ev_base = (license_desc or license_url or copyright_ or "")[:200]
        evidence = (_ev_base + sha256_suffix) or None

        if fstype is None:
            # No OS/2 fsType table — embedding rights can't be read. Surface it so the
            # font isn't silently skipped (the directory heuristic is off in this mode).
            self.add_finding(
                severity=Severity.LOW,
                title=f"Font embedding rights unknown: {fpath.name}",
                description=(
                    f"'{rel}' has no readable fsType embedding flags, so its license/embedding rights "
                    "could not be verified from the file."
                ),
                recommendation="Check the font's source/EULA to confirm it may be embedded and redistributed.",
                file=rel, evidence=evidence, tags=["asset", "font", "license", "unknown"],
            )
            return

        if fstype & 0x0002:  # Restricted License embedding
            self.add_finding(
                severity=Severity.HIGH,
                title=f"Restricted-license font: {fpath.name}",
                description=(
                    f"'{rel}' declares fsType = Restricted License embedding — the foundry forbids "
                    "embedding/redistributing this font without a purchased license."
                ),
                recommendation=(
                    "Do not ship this font as-is. Buy a web/app embedding license, or replace it with an "
                    "OFL/Apache-licensed alternative (e.g. a Google Font)."
                ),
                file=rel, evidence=evidence, tags=["asset", "font", "license", "fstype-restricted"],
            )
        elif (fstype & 0x0004) and not (fstype & 0x0008):  # Preview & Print only
            self.add_finding(
                severity=Severity.MEDIUM,
                title=f"Preview/print-only font: {fpath.name}",
                description=(
                    f"'{rel}' declares fsType = Preview & Print embedding — it may be embedded only for "
                    "viewing/printing, not for editing or use inside an app/website."
                ),
                recommendation="Verify your license covers embedding in your product; otherwise replace it.",
                file=rel, evidence=evidence, tags=["asset", "font", "license", "fstype-preview"],
            )
        else:  # 0 = Installable, or bit 3 = Editable
            level = "Installable" if fstype == 0 else "Editable"
            self.add_finding(
                severity=Severity.INFO,
                title=f"Font embedding allowed ({level}): {fpath.name}",
                description=(
                    f"'{rel}' permits embedding (fsType={fstype}). "
                    f"License: {license_desc or copyright_ or 'see font / accompanying license'}."
                ),
                recommendation="Embedding flags allow use; still confirm the written license permits your distribution.",
                file=rel, evidence=evidence, tags=["asset", "font", "license"],
            )

    def _scan_with_exiftool(self, fonts: List[Path], root: Path) -> None:
        """Read font copyright/license text metadata via ExifTool.

        Runs alongside fonttools: fonttools checks fsType (embedding rights flag),
        ExifTool reads human-readable fields (Copyright, License, UsageTerms, etc.)
        that can catch 'non-commercial', 'trial', or GPL terms the flag alone misses.
        SHA256 of each font is embedded in evidence for renamed-font identification.
        """
        exiftool_bin = resolve_command("exiftool") or "exiftool"
        command = [
            exiftool_bin, "-r", "-json",
            "-ext", "ttf", "-ext", "otf", "-ext", "woff", "-ext", "woff2",
            str(root),
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=120,
            )
        except FileNotFoundError:
            return
        except subprocess.TimeoutExpired:
            self.add_finding(
                severity=Severity.WARNING,
                title="ExifTool font metadata scan timed out",
                description="ExifTool took too long; the font directory may be very large.",
                recommendation="Run exiftool manually or limit the number of fonts in the project.",
                tags=["asset", "font", "tool-failure"],
            )
            return

        if not result.stdout.strip():
            return
        try:
            entries = json.loads(result.stdout)
        except json.JSONDecodeError:
            return

        for entry in entries:
            source = entry.get("SourceFile", "")
            if not source:
                continue
            fpath = Path(source)
            try:
                rel = str(fpath.relative_to(root))
            except ValueError:
                rel = source

            lic_text = " ".join(
                str(entry[k]) for k in ("License", "LicenseInfo", "LicenseURL", "UsageTerms", "Rights")
                if entry.get(k)
            ).strip()
            extra_text = " ".join(
                str(entry[k]) for k in ("Copyright", "CopyrightNotice", "Description")
                if entry.get(k)
            ).strip()

            sha256 = _hash_font_file(fpath)
            sha256_suffix = f"\nSHA256: {sha256}" if sha256 else ""
            combined = (lic_text or extra_text)[:200]

            if FONT_BLOCK_RE.search(lic_text) or FONT_BLOCK_RE.search(extra_text):
                self.add_finding(
                    severity=Severity.HIGH,
                    title=f"Font has restrictive license terms: {fpath.name}",
                    description=(
                        f"ExifTool detected restrictive license text in '{rel}': {combined}"
                    ),
                    recommendation=(
                        "This font appears to prohibit commercial or app use. "
                        "Replace with an OFL/Apache-licensed alternative (e.g. a Google Font)."
                    ),
                    file=rel,
                    evidence=(combined + sha256_suffix) or None,
                    tags=["asset", "font", "license", "exiftool", "restricted"],
                )
            elif FONT_REVIEW_RE.search(lic_text) or FONT_REVIEW_RE.search(extra_text):
                self.add_finding(
                    severity=Severity.MEDIUM,
                    title=f"Font has copyleft license — review required: {fpath.name}",
                    description=(
                        f"ExifTool detected a copyleft license (GPL/SSPL) in '{rel}': {combined}"
                    ),
                    recommendation=(
                        "Copyleft fonts may impose distribution requirements. "
                        "Confirm your project's distribution terms are compatible."
                    ),
                    file=rel,
                    evidence=(combined + sha256_suffix) or None,
                    tags=["asset", "font", "license", "exiftool", "copyleft"],
                )
            elif lic_text or extra_text:
                self.add_finding(
                    severity=Severity.INFO,
                    title=f"Font license metadata found: {fpath.name}",
                    description=f"ExifTool reports license/copyright for '{rel}': {combined}",
                    recommendation="Verify these terms permit your intended usage (web, app, commercial).",
                    file=rel,
                    evidence=(combined + sha256_suffix) or None,
                    tags=["asset", "font", "license", "exiftool"],
                )
            else:
                self.add_finding(
                    severity=Severity.LOW,
                    title=f"Font has no license metadata (ExifTool): {fpath.name}",
                    description=(
                        f"ExifTool found no license, copyright, or usage-terms metadata in '{rel}'. "
                        "Absence of metadata does not mean the font is free — check its source."
                    ),
                    recommendation="Manually verify the font license from its original source or distributor.",
                    file=rel,
                    evidence=sha256_suffix.strip() or None,
                    tags=["asset", "font", "license", "exiftool", "no-metadata"],
                )

    def _check_image_license(self, img_path: Path, rel: str) -> None:
        """Read embedded image provenance: EXIF Copyright/Artist, PNG text chunks, XMP
        rights/usage terms — to verify the image's source and license."""
        try:
            img = _PILImage.open(img_path)
        except Exception:
            return

        meta: Dict[str, str] = {}
        usage = ""
        try:
            exif = img.getexif()
            if exif:
                if exif.get(0x8298):
                    meta["copyright"] = str(exif.get(0x8298))
                if exif.get(0x013B):
                    meta["artist"] = str(exif.get(0x013B))
            info = getattr(img, "info", {}) or {}
            for k in ("Copyright", "copyright", "Author", "Artist", "Comment"):
                if info.get(k):
                    meta.setdefault(k.lower(), str(info[k]))
            xmp = info.get("xmp")
            if xmp:
                x = xmp.decode("utf-8", "ignore") if isinstance(xmp, (bytes, bytearray)) else str(xmp)
                m = re.search(r"(?is)(UsageTerms|dc:rights|WebStatement)[^>]*>(.*?)<", x)
                if m:
                    usage = re.sub(r"<[^>]+>", " ", m.group(2)).strip()[:160]
                if "rights" not in meta and re.search(r"(?i)all rights reserved", x):
                    meta["rights"] = "All Rights Reserved"
        except Exception:
            pass
        finally:
            try:
                img.close()
            except Exception:
                pass

        text = (" ".join(meta.values()) + " " + usage).strip()
        low = text.lower()
        permissive = any(k in low for k in (
            "creative commons", "cc0", "cc-by", "cc by", "public domain",
            "unsplash", "pexels", "pixabay", "royalty-free", "royalty free",
        ))

        if not text:
            self.add_finding(
                severity=Severity.LOW,
                title=f"Image has no license/provenance metadata: {img_path.name}",
                description=(
                    f"'{rel}' carries no EXIF/XMP copyright or usage metadata, so its source and license "
                    "cannot be verified."
                ),
                recommendation=(
                    "Confirm you have the right to use this image and record its source/license, or replace "
                    "it with a CC0 image (Unsplash/Pexels/Pixabay)."
                ),
                file=rel, tags=["asset", "image", "license", "no-metadata"],
            )
        elif permissive:
            self.add_finding(
                severity=Severity.INFO,
                title=f"Image declares an open/usable license: {img_path.name}",
                description=f"'{rel}' metadata: {text[:160]}",
                recommendation="Looks usable; preserve any attribution the license requires.",
                file=rel, tags=["asset", "image", "license"],
            )
        else:
            self.add_finding(
                severity=Severity.MEDIUM,
                title=f"Image asserts copyright — verify license: {img_path.name}",
                description=(
                    f"'{rel}' carries copyright/usage metadata with no clear permissive license: {text[:160]}"
                ),
                recommendation="Verify you hold a license to use and redistribute this image.",
                file=rel, tags=["asset", "image", "license"],
            )

    def _check_image_text(self, img_path: Path, rel: str) -> None:
        """OCR the image; if it contains rendered text, flag it for MANUAL font-license
        review. The typeface itself cannot be auto-identified from a raster image."""
        try:
            text = _pytesseract.image_to_string(_PILImage.open(img_path))
        except Exception:
            return
        words = re.findall(r"[A-Za-z]{3,}", text)
        if len(words) >= 3:
            self.add_finding(
                severity=Severity.MEDIUM,
                title=f"Image contains rendered text — verify font license: {img_path.name}",
                description=(
                    f"'{rel}' appears to contain rendered text (e.g. \"{' '.join(words[:6])}\"…). The typeface "
                    "used cannot be auto-identified from the image, so its license can't be verified automatically."
                ),
                recommendation=(
                    "Confirm the font used to render this text is licensed for embedding/distribution. Keep the "
                    "editable source file (where the font is named) so its license can be checked at the file level."
                ),
                file=rel, tags=["asset", "image", "font", "ocr", "manual-review"],
            )
