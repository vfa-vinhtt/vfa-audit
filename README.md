# audit-scan.sh

Tool kiểm tra bảo mật source code tự động, kết hợp 3 lớp scan:

| Lớp | Tool | Phát hiện |
|-----|------|-----------|
| **Secrets** | [Gitleaks](https://github.com/gitleaks/gitleaks) | API keys, tokens, credentials trong code và git history |
| **CVE** | [Trivy](https://github.com/aquasecurity/trivy) + [Grype](https://github.com/anchore/grype) + GitHub Advisory | Lỗ hổng đã biết trong dependencies, gồm advisory mới/chưa reviewed để review thủ công |
| **License** | [Trivy](https://github.com/aquasecurity/trivy) + [ExifTool](https://exiftool.org/) | License thư viện và metadata bản quyền/license của font |

---

## Yêu cầu

| Tool | Cài đặt thủ công |
|------|-----------------|
| `gitleaks` | `brew install gitleaks` |
| `trivy` | `brew install trivy` |
| `grype` | `brew install grype` |
| `exiftool` | `brew install exiftool` |
| `python3` | Có sẵn trên macOS / Linux |

> **Tự động cài:** Script tự phát hiện tools còn thiếu và cài qua Homebrew (macOS) hoặc official install scripts / package manager (Linux) — không cần cài tay trước.

---

## Cài đặt

```bash
git clone <repo>
cd tools/audits
chmod +x audit-scan.sh
```

---

## Cách dùng

### Cú pháp

```
./audit-scan.sh [OPTIONS] <project-path>
```

### Options

| Option | Mặc định | Mô tả |
|--------|----------|-------|
| `-o, --output <dir>` | `./vfa_audit_output/<timestamp>_<project>` | Thư mục lưu báo cáo (trước khi zip) |
| `-s, --severity <level>` | `LOW` | Mức độ tối thiểu: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `--skip-secrets` | — | Bỏ qua scan secrets (Gitleaks) |
| `--skip-cve` | — | Bỏ qua scan CVE (Trivy + Grype) |
| `--skip-license` | — | Bỏ qua scan license |
| `--no-git-history` | — | Chỉ scan file hiện tại, bỏ qua git history |
| `-v, --verbose` | — | Hiện toàn bộ output của từng tool |
| `-h, --help` | — | Hiển thị hướng dẫn |

---

## Ví dụ

**Scan cơ bản:**
```bash
./audit-scan.sh /path/to/project
```

**Chỉ báo cáo từ HIGH trở lên:**
```bash
./audit-scan.sh --severity HIGH /path/to/project
```

**Scan nhanh, chỉ CVE (bỏ secrets và license):**
```bash
./audit-scan.sh --skip-secrets --skip-license /path/to/project
```

**Scan files hiện tại, không đào git history:**
```bash
./audit-scan.sh --no-git-history /path/to/project
```

**Lưu báo cáo ra thư mục riêng, xem full output:**
```bash
./audit-scan.sh -o /tmp/my-audit --verbose /path/to/project
```

---

## Output

Mỗi lần chạy tạo một file zip tại `vfa_audit_output/<timestamp>_<project-name>.zip`.  
Tên thư mục lấy từ **tên folder gốc của project** được chỉ định.

```
vfa_audit_output/
└── 20250609_143022_my-project.zip
    ├── gitleaks.json        # Secrets findings (Gitleaks — JSON)
    ├── trivy-vuln.json      # CVE findings (Trivy — JSON)
    ├── trivy-vuln.txt       # CVE findings (Trivy — table)
    ├── grype.json           # CVE findings (Grype — JSON)
    ├── grype.txt            # CVE findings (Grype — table)
    ├── fresh-advisory.json  # CVE mới từ GitHub Advisory
    ├── fresh-advisory.txt   # CVE mới dạng text
    ├── trivy-license.json   # License findings (Trivy — JSON)
    ├── trivy-license.txt    # License findings (Trivy — table)
    ├── font-license-exiftool.json # Font metadata (ExifTool — JSON)
    ├── font-license-exiftool.txt  # Review license/copyright font
    ├── summary.md           # Bảng tổng hợp Markdown
    └── summary.json         # Tổng hợp dạng JSON
```

> Nếu lệnh `zip` không khả dụng, script giữ nguyên folder thay vì dừng lại.

### Ví dụ summary.md

```markdown
# Security Audit Summary

| Field | Value |
|---|---|
| Date | 2025-06-09 14:30:22 |
| Project | `/Users/dev/my-project` |
| Severity | `HIGH+` |
| Status | `WARN` |

| Scanner | Findings |
|---|---:|
| Secrets (Gitleaks) | 2 |
| CVE (Trivy) | 14 |
| CVE (Grype) | 11 |
| Fresh CVE (GitHub Advisory) | 1 |
| License (Trivy) | 3 |
| Font License (ExifTool) | 2 |
| **Total** | **33** |
```

### Ví dụ summary.json

```json
{
  "timestamp":          "2025-06-09T07:30:22Z",
  "project":            "/Users/dev/my-project",
  "severity_threshold": "HIGH",
  "findings": {
    "secrets":        2,
    "cve_trivy":      14,
    "cve_grype":      11,
    "fresh_advisories": 1,
    "license_issues": 3,
    "font_files":     8,
    "font_license_issues": 2,
    "total":          33
  },
  "tool_errors": 0,
  "output_dir":  "/path/to/vfa_audit_output/20250609_143022_my-project"
}
```

## Lưu ý quan trọng

### Về Secret Scan (Gitleaks)

- Mặc định Gitleaks **quét toàn bộ git history**, không chỉ code hiện tại. Secrets đã xóa khỏi code nhưng còn trong commit cũ vẫn bị phát hiện.
- Dùng `--no-git-history` nếu chỉ muốn quét file hiện tại (nhanh hơn, ít false positive hơn).
- Kết quả có thể có false positive — nên review thủ công trước khi xử lý.

### Về CVE Scan (Trivy + Grype)

- Trivy và Grype dùng **database khác nhau** (Trivy: GHSA + NVD, Grype: tổng hợp nhiều nguồn). Chạy song song giúp tăng độ phủ.
- Script kiểm tra thêm GitHub Advisory cho dependency Python được pin bằng `==` trong `requirements*.txt`; lớp này giúp note các advisory mới/chưa reviewed để review thủ công.
- GitHub Advisory `reviewed` được match bằng `ecosystem=pip` + `affects=package@version`.
- GitHub Advisory `unreviewed` chưa có package/version range đáng tin, nên script tìm theo tên package trên GitHub Advisory và ghi rõ `unreviewed` trong report để bạn kiểm tra thủ công.
- Chỉ phát hiện CVE trong dependencies khai báo qua package manager (npm, pip, maven, gradle, go.mod, cargo…).
- CVE trong code tự viết không được phát hiện — cần SAST tool riêng (ví dụ: Semgrep, CodeQL).

### Về License Scan (Trivy)

- Sử dụng `--license-full`: Trivy scan cả **nội dung file** lẫn metadata package manager — tăng độ chính xác.
- License bị flag theo category:
  - `restricted` — GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0…
  - `reciprocal` — MPL-2.0, LGPL-2.1, LGPL-3.0, EUPL…
  - `unknown` — không xác định được license

### Về Font License Scan (ExifTool)

- ExifTool đọc metadata trực tiếp từ font độc lập: `.ttf`, `.otf`, `.woff`, `.woff2`.
- Script tạo `font-license-exiftool.json` để lưu metadata gốc và `font-license-exiftool.txt` để review nhanh.
- Font bị flag khi thiếu metadata license/quyền sử dụng hoặc có cụm hạn chế như `personal use`, `non-commercial`, `trial`, `demo`, `restricted`, `proprietary`, `GPL`, `AGPL`, `SSPL`.
- Metadata font không thay thế review pháp lý; nếu font không ghi rõ license, nên kiểm tra lại nguồn tải hoặc file license đi kèm.

---

## Exit Codes

| Code | Ý nghĩa |
|------|---------|
| `0` | Script chạy xong, kể cả khi có findings |
| `2` | Lỗi tham số hoặc không thể cài tools |
