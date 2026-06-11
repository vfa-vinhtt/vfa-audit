# vfa-audit-scan.sh

Tool kiểm tra bảo mật source code tự động, kết hợp 3 lớp scan:

| Lớp | Tool | Phát hiện |
|-----|------|-----------|
| **Secrets** | [Gitleaks](https://github.com/gitleaks/gitleaks) + [Trivy](https://github.com/aquasecurity/trivy) | API keys, tokens, credentials trong code và git history |
| **CVE** | [Trivy](https://github.com/aquasecurity/trivy) + [Grype](https://github.com/anchore/grype) | Lỗ hổng đã biết trong dependencies |
| **License** | [Trivy](https://github.com/aquasecurity/trivy) + [ExifTool](https://exiftool.org/) | License thư viện và metadata bản quyền/license của font |

---

## Yêu cầu

| Tool | Cài đặt thủ công |
|------|-----------------|
| `gitleaks` | `brew install gitleaks` |
| `trivy` | `brew install trivy` |
| `grype` | `brew install grype` |
| `exiftool` | `brew install exiftool` |

> **Tự động cài:** Script tự phát hiện tools còn thiếu và cài qua Homebrew (macOS) hoặc official install scripts / package manager (Linux) — không cần cài tay trước.
>
> **Optional:** `jq` (đếm findings trong summary). Thiếu `jq` → counts hiển thị 0, raw JSON reports vẫn đầy đủ.

---

## Cài đặt

```bash
git clone <repo>
cd tools/audits
chmod +x vfa-audit-scan.sh
```

---

## Cách dùng

### Cú pháp

```
./vfa-audit-scan.sh [OPTIONS] [project-path]
```

Nếu bỏ qua `project-path`, script quét **thư mục hiện tại**.

> **Khuyến nghị:** Để Gitleaks quét được toàn bộ git history, hãy **`cd` vào thư mục gốc của project cần audit** trước khi chạy, hoặc truyền đường dẫn tuyệt đối qua `project-path`. Gitleaks cần truy cập thư mục `.git` — nếu không tìm thấy, script tự chuyển sang quét file hiện tại và bỏ qua lịch sử commit.

### Chạy trực tiếp từ GitHub (không cần clone)

```bash
# Quét thư mục hiện tại
curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash

# Truyền options qua `bash -s --`
curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash -s -- --severity HIGH

# Chỉ định project khác thư mục hiện tại
# ⚠️  Gitleaks sẽ CHỈ quét file hiện tại, KHÔNG quét git history.
#     Để quét đầy đủ cả history: cd vào project rồi chạy lệnh đầu tiên ở trên.
curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash -s -- /path/to/project
```

### Options

| Option | Mặc định | Mô tả |
|--------|----------|-------|
| `-s, --severity <level>` | `UNKNOWN` | Mức độ tối thiểu: `UNKNOWN` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` — mặc định lấy toàn bộ |
| `--skip-secrets` | — | Bỏ qua scan secrets (Gitleaks) |
| `--skip-cve` | — | Bỏ qua scan CVE (Trivy vuln/secret + Grype) |
| `--skip-license` | — | Bỏ qua scan license |
| `-v, --verbose` | — | Hiện toàn bộ output của từng tool |
| `-h, --help` | — | Hiển thị hướng dẫn |

---

## Ví dụ

**Scan cơ bản:**
```bash
./vfa-audit-scan.sh /path/to/project
```

**Chỉ báo cáo từ HIGH trở lên:**
```bash
./vfa-audit-scan.sh --severity HIGH /path/to/project
```

**Scan nhanh, chỉ CVE (bỏ secrets và license):**
```bash
./vfa-audit-scan.sh --skip-secrets --skip-license /path/to/project
```

**Xem full output của từng tool:**
```bash
./vfa-audit-scan.sh --verbose /path/to/project
```

---

## Output

Mỗi lần chạy tạo một file zip tại `/tmp/vfa_audit/<timestamp>_<project-name>.zip`.  
Tên thư mục lấy từ **tên folder gốc của project** được chỉ định.

```
/tmp/vfa_audit/
└── 20250609_143022_my-project.zip
    ├── gitleaks.json               # Secrets findings (Gitleaks)
    ├── trivy.json                  # Vuln + secret + license findings (Trivy)
    ├── grype.json                  # CVE findings (Grype)
    ├── font-license-exiftool.json  # Font license/copyright metadata (ExifTool)
    ├── summary.md                  # Bảng tổng hợp Markdown
    ├── summary.json                # Tổng hợp dạng JSON (machine-readable)
    └── <tool>.log                  # Log lỗi — CHỈ xuất hiện khi scanner đó gặp lỗi
                                    #   ảnh hưởng chất lượng audit; chạy sạch thì không có
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

| Scanner | Status | Findings |
|---|---|---:|
| Secrets (Gitleaks) | findings | 2 |
| Secrets (Trivy) | ok | 0 |
| CVE (Trivy) | findings | 14 |
| CVE (Grype) | findings | 11 |
| License (Trivy) | findings | 3 |
| Font License (ExifTool) | findings | 2 |
| **Total** | | **32** |
```

Cột **Status** cho biết kết quả có tin được hay không: `ok` / `findings` (scanner chạy xong), `failed` (scanner lỗi — kết quả **không đầy đủ**, xem `logs/`), `skipped` (bị bỏ qua theo flag). Status tổng là `FAIL` khi có scanner lỗi, `WARN` khi có findings, `PASS` khi sạch.

### Ví dụ summary.json

```json
{
  "timestamp": "2025-06-09T07:30:22Z",
  "project": "/Users/dev/my-project",
  "severity_threshold": "HIGH",
  "status": "WARN",
  "scanners": {
    "secrets_gitleaks": {"status": "findings", "findings": 2},
    "trivy": {"status": "findings", "cve": 14, "secrets": 0, "license_issues": 3},
    "cve_grype": {"status": "findings", "findings": 11},
    "font_license": {"status": "findings", "files": 8, "issues": 2}
  },
  "total_findings": 32,
  "tool_errors": 0,
  "output_dir": "/tmp/vfa_audit/20250609_143022_my-project"
}
```

## Lưu ý quan trọng

### Về Secret Scan (Gitleaks)

- Mặc định Gitleaks **quét toàn bộ git history**, không chỉ code hiện tại. Secrets đã xóa khỏi code nhưng còn trong commit cũ vẫn bị phát hiện.
- Nếu truyền `project-path` khác thư mục hiện tại, script **tự động bỏ qua git history** để tránh Gitleaks resolve git context từ thư mục đang đứng thay vì project mục tiêu — chỉ quét file hiện tại.
- Nếu project **không phải git repo**, script in `[ NO ] No git in project` và tự chuyển sang quét file hiện tại (không bỏ qua âm thầm).
- Trivy chạy thêm secret scanner như một lớp đối chiếu thứ hai (cột `Secrets (Trivy)` trong summary).
- Kết quả có thể có false positive — nên review thủ công trước khi xử lý.

### Về CVE Scan (Trivy + Grype)

- Trivy và Grype dùng **database khác nhau** (Trivy: GHSA + NVD, Grype: tổng hợp nhiều nguồn). Chạy song song giúp tăng độ phủ.
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
- Script tạo `font-license-exiftool.json` lưu toàn bộ metadata gốc từ ExifTool.
- Font bị flag khi thiếu metadata license/quyền sử dụng hoặc có cụm hạn chế như `personal use`, `non-commercial`, `trial`, `demo`, `restricted`, `proprietary`, `GPL`, `AGPL`, `SSPL`.
- Metadata font không thay thế review pháp lý; nếu font không ghi rõ license, nên kiểm tra lại nguồn tải hoặc file license đi kèm.

---

## Khi nào tool báo lỗi (`[ERR ]` / status `failed`)

Mỗi lỗi đều ghi rõ **scanner nào hỏng** và **log nào cần xem** (`<tool>.log` nằm cùng thư mục báo cáo, có trong file zip). File log **chỉ tồn tại khi scanner đó gặp lỗi ảnh hưởng chất lượng audit** — báo cáo không có file `.log` nào nghĩa là mọi scanner chạy sạch. Status tổng chuyển `FAIL` + dòng "results are INCOMPLETE" để phân biệt với `WARN` (có findings nhưng scan đầy đủ).

| Trường hợp | Thông báo |
|---|---|
| Không tạo được thư mục output | `Cannot create output directory: ...` → exit 2 |
| Tool cài tự động thất bại | `Failed to install <tool>` + layer tương ứng báo `<tool> unavailable — scan NOT performed` |
| Gitleaks lỗi (exit > 1) | `Gitleaks failed (exit N) — see gitleaks.log` |
| Trivy lỗi (DB download, crash…) | `Trivy failed (exit N) — see trivy.log` |
| Grype lỗi | `Grype failed (exit N) — see grype.log` |
| ExifTool lỗi đọc file | `ExifTool failed (exit N) — see exiftool.log` (lỗi lẻ tẻ nhưng vẫn có data → chỉ `[WARN]`) |
| `summary.json` không sinh được | `[WARN]` (summary.md vẫn dùng được) |
| `zip` thiếu / nén lỗi | `[WARN]` — giữ nguyên folder báo cáo |

## Exit Codes

| Code | Ý nghĩa |
|------|---------|
| `0` | Script chạy xong, kể cả khi có findings (status thật nằm trong `summary.json`) |
| `2` | Lỗi tham số hoặc không tạo được thư mục output |
