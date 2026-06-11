# vfa-audit-scan.sh

Tool kiểm tra bảo mật source code tự động, kết hợp 3 lớp scan:

| Lớp | Tool | Phát hiện |
|-----|------|-----------|
| **Secrets** | [Gitleaks](https://github.com/gitleaks/gitleaks) + [Trivy](https://github.com/aquasecurity/trivy) | API keys, tokens, credentials trong code và git history |
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

> **Tự động cài:** Script tự phát hiện tools còn thiếu và cài qua Homebrew (macOS) hoặc official install scripts / package manager (Linux) — không cần cài tay trước.
>
> **Optional:** `jq` (đếm findings trong summary) và `python3` (lớp GitHub Advisory). Thiếu `jq` → counts hiển thị 0, raw JSON reports vẫn đầy đủ. Thiếu `python3` → GitHub Advisory bị skip, 3 lớp còn lại chạy bình thường.

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

### Chạy trực tiếp từ GitHub (không cần clone)

```bash
# Quét thư mục hiện tại
curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash

# Truyền options qua `bash -s --`
curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash -s -- --severity HIGH

# Chỉ định project khác thư mục hiện tại
curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash -s -- /path/to/project
```

### Options

| Option | Mặc định | Mô tả |
|--------|----------|-------|
| `-o, --output <dir>` | `./vfa_audit_output` | Thư mục **gốc** chứa báo cáo; báo cáo luôn nằm trong subfolder `<dir>/<timestamp>_<project>` do script tự tạo (chỉ subfolder này bị xóa sau khi zip, nội dung có sẵn trong `<dir>` không bị đụng tới) |
| `-s, --severity <level>` | `UNKNOWN` | Mức độ tối thiểu: `UNKNOWN` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` — mặc định lấy toàn bộ |
| `--skip-secrets` | — | Bỏ qua scan secrets (Gitleaks) |
| `--skip-cve` | — | Bỏ qua scan CVE (Trivy vuln/secret + Grype + GitHub Advisory) |
| `--skip-license` | — | Bỏ qua scan license |
| `--no-git-history` | — | Chỉ scan file hiện tại, bỏ qua git history |
| `--no-install` | — | Không tự cài tools còn thiếu — báo lỗi và dừng |
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

**Scan files hiện tại, không đào git history:**
```bash
./vfa-audit-scan.sh --no-git-history /path/to/project
```

**Lưu báo cáo ra thư mục riêng, xem full output:**
```bash
./vfa-audit-scan.sh -o /tmp/my-audit --verbose /path/to/project
```

---

## Output

Mỗi lần chạy tạo một file zip tại `vfa_audit_output/<timestamp>_<project-name>.zip`.  
Tên thư mục lấy từ **tên folder gốc của project** được chỉ định.

```
vfa_audit_output/
└── 20250609_143022_my-project.zip
    ├── gitleaks.json               # Secrets findings (Gitleaks)
    ├── trivy.json                  # Vuln + secret + license findings (Trivy)
    ├── grype.json                  # CVE findings (Grype)
    ├── fresh-advisory.json         # CVE mới từ GitHub Advisory (mọi ecosystem)
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
| Fresh CVE (GitHub Advisory) | findings | 1 |
| License (Trivy) | findings | 3 |
| Font License (ExifTool) | findings | 2 |
| **Total** | | **33** |
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
    "fresh_advisories": {"status": "findings", "findings": 1},
    "font_license": {"status": "findings", "files": 8, "issues": 2}
  },
  "total_findings": 33,
  "tool_errors": 0,
  "output_dir": "/path/to/vfa_audit_output/20250609_143022_my-project"
}
```

## Lưu ý quan trọng

### Về Secret Scan (Gitleaks)

- Mặc định Gitleaks **quét toàn bộ git history**, không chỉ code hiện tại. Secrets đã xóa khỏi code nhưng còn trong commit cũ vẫn bị phát hiện.
- Nếu project **không phải git repo**, script in `[ NO ] No git in project` và tự chuyển sang quét file hiện tại (không bỏ qua âm thầm).
- Dùng `--no-git-history` nếu chỉ muốn quét file hiện tại (nhanh hơn, ít false positive hơn).
- Trivy chạy thêm secret scanner như một lớp đối chiếu thứ hai (cột `Secrets (Trivy)` trong summary).
- Kết quả có thể có false positive — nên review thủ công trước khi xử lý.

### Về CVE Scan (Trivy + Grype)

- Trivy và Grype dùng **database khác nhau** (Trivy: GHSA + NVD, Grype: tổng hợp nhiều nguồn). Chạy song song giúp tăng độ phủ.
- Lớp GitHub Advisory quét **mọi ecosystem** mà GitHub hỗ trợ, đọc version đã pin từ manifest/lockfile:

  | Ecosystem | File được đọc |
  |---|---|
  | pip | `requirements*.txt` (pin `==`), `Pipfile.lock`, `poetry.lock` |
  | npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
  | go | `go.mod` |
  | maven | `pom.xml` (bỏ qua version dạng `${property}`) |
  | rubygems | `Gemfile.lock` |
  | composer | `composer.lock` |
  | rust | `Cargo.lock` |
  | nuget | `packages.lock.json`, `*.csproj` |
  | pub | `pubspec.lock` |
  | swift | `Package.resolved` |
  | actions | `.github/workflows/*.yml` (chỉ ref dạng version tag, bỏ qua SHA) |
  | erlang | `mix.lock` |

- Advisory được match bằng `affects=package@version` (batch nhiều package mỗi request để tiết kiệm rate limit), đủ 3 loại `reviewed` / `malware` / `unreviewed`.
- Advisory `unreviewed`/`malware` chưa có package/version range đáng tin, nên script bổ sung text-match trên advisory mới nhất và ghi rõ trong report để bạn kiểm tra thủ công.
- CVE đã có trong kết quả Trivy/Grype được tự động loại trùng — lớp này chỉ báo phần **bổ sung**.
- Lớp GitHub Advisory gọi API **không dùng token** (chủ đích — giới hạn 60 request/giờ). Nếu chạm rate limit, scanner báo `failed` kèm kết quả partial thay vì lặng lẽ trả 0. Project có rất nhiều dependency (lockfile hàng nghìn package) có thể chạm limit — kết quả partial sẽ được ghi rõ trong report.
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
| Thiếu `python3` | `[NO] Skipped — python3 not available` → GitHub Advisory bị skip (không phải lỗi fatal) |
| Gitleaks lỗi (exit > 1) | `Gitleaks failed (exit N) — see gitleaks.log` |
| Report Gitleaks hỏng (JSON parse lỗi) | `Gitleaks report unreadable: ...` |
| Trivy lỗi (DB download, crash…) | `Trivy failed (exit N) — see trivy.log` |
| Report Trivy hỏng | `Trivy report unparsable: ...` |
| Trivy table không sinh được | `[WARN]` (JSON vẫn nguyên vẹn, không tính là failed) |
| Grype lỗi | `Grype failed (exit N) — see grype.log` |
| Report Grype hỏng | `Grype report unparsable: ...` |
| GitHub Advisory đụng rate limit | `rate limit reached (unauthenticated, 60 req/h) — results PARTIAL` |
| GitHub Advisory mất mạng hoàn toàn | `API unreachable (network/DNS?) — NO advisory data` |
| GitHub Advisory lỗi một phần request | `some API requests failed — results PARTIAL` |
| GitHub Advisory crash | `check crashed (exit N) — see fresh-advisory.log` |
| ExifTool lỗi đọc file | `ExifTool failed (exit N) — see exiftool.log` (lỗi lẻ tẻ nhưng vẫn có data → chỉ `[WARN]`) |
| Report font không sinh được | `Font license report generation failed` |
| `summary.json` không sinh được | `[WARN]` (summary.md vẫn dùng được) |
| `zip` thiếu / nén lỗi | `[WARN]` — giữ nguyên folder báo cáo |

File `fresh-advisory.json` ghi rõ `"partial": true`, số request thành công/thất bại và warning message — kết quả không bao giờ bị hiểu nhầm là "sạch".

## Exit Codes

| Code | Ý nghĩa |
|------|---------|
| `0` | Script chạy xong, kể cả khi có findings (status thật nằm trong `summary.json`) |
| `2` | Lỗi tham số, không tạo được thư mục output, hoặc không thể cài tools |
