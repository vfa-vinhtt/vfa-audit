# Kế hoạch Migrate `vinhtt-tool/vfa-audit-scan.sh` → Python Project

## 1. Tổng quan so sánh hai tool

| Chiều | `vinhtt-tool` (bash) | Python project |
|---|---|---|
| **Kiến trúc** | Shell script đơn, invoke CLI tools | Plugin system + adapter per language |
| **CVE scan** | Trivy (`fs --scanners vuln`) | OSV API + native audit (pip-audit, npm audit…) |
| **Secret scan** | Gitleaks (git history) + Trivy secrets | Gitleaks (`--no-git`) + TruffleHog + python_regex |
| **License scan** | Trivy (`--license-full`, full content) | Content từ adapter manifest + native tool (pip-licenses…) |
| **Font scan** | ExifTool (copyright text, license text) | fonttools (OS/2 fsType embedding flag) |
| **Font hash** | SHA256 của mọi font file | Không có |
| **Platform** | macOS (Homebrew only) | Cross-platform (Win/Linux/macOS) |
| **Output** | ZIP + blockers/review-required/warnings.json | console / JSON / HTML / Markdown + score |
| **Policy model** | FAIL / REVIEW\_REQUIRED / WARNING / PASS | CRITICAL–INFO + score 0–100 |
| **Unique features bash** | Trivy CVE với fix-available logic, Trivy license full, font SHA256, policy status tổng | — |
| **Unique features Python** | PII, config checker, env/.gitignore checker, TruffleHog, scoring, HTML report, đa ngôn ngữ | — |

---

## 2. Những gì cần bổ sung vào Python project

### Gap 1 — Trivy CVE scan

`dependency_checker` dùng OSV API + native audit tool, không có Trivy.
Trivy đặc biệt mạnh về: scan không cần install deps, nhận diện CVE theo ecosystem rộng hơn, phân loại fix-available.
→ **Cần thêm Trivy như một tool option trong `dependency_checker`** (song song OSV/audit).

### Gap 2 — Trivy secrets (lớp đối chiếu thứ 2)

vinhtt-tool chạy Trivy secrets song song Gitleaks như double-check.
→ **Cần thêm `trivy` vào `tool_config` của `secret_checker`**.

### Gap 3 — Trivy license full-content scan

Python hiện chỉ đọc license từ manifest (adapter). Trivy `--license-full` scan trực tiếp nội dung file trong thư mục source — bắt được case package không khai báo license trong manifest.
→ **Cần thêm Trivy license như một tool option trong `license_checker`**.

### Gap 4 — Gitleaks scan git history

Python dùng `--no-git` (chỉ scan file hiện tại). vinhtt-tool scan toàn bộ git history nếu là git repo.
→ **Cần bỏ `--no-git` khi project là git repo** (đã có `is_git_repo` trong context).

### Gap 5 — ExifTool font metadata (copyright text, license description)

`asset_checker` dùng fonttools đọc `OS/2.fsType` (embedding rights flag).
ExifTool đọc thêm: Copyright, LicenseInfo, LicenseURL, UsageTerms, Rights — các trường text này bắt được pattern như `non-commercial`, `personal use only`, `trial`.
→ **Cần thêm ExifTool như optional tool trong `asset_checker`**, chạy song song fonttools, map kết quả vào severity model.

### Gap 6 — Font SHA256 hash

Dùng để nhận diện font bị rename (vinhtt-tool §6.3).
→ **Thêm SHA256 hash của mỗi font file vào finding evidence trong `asset_checker`**.

### Gap 7 — Policy status output (FAIL/REVIEW\_REQUIRED/WARNING/PASS)

Python output là severity model + score. vinhtt-tool xuất 3 file phân loại theo policy.
→ **Thêm output format `policy` vào `ReportEngine`**: sinh `blockers.json`, `review-required.json`, `warnings.json` tương đương.

### Gap 8 — policy.md và ZIP archive

`policy.md` hiện ở trong `vinhtt-tool/` — cần đưa ra root.
ZIP archive là feature tiện lợi cho báo cáo bàn giao.
→ Di chuyển `policy.md` lên root; thêm flag `--zip` cho main.py để nén output directory.

---

## 3. Các thay đổi KHÔNG cần thiết

- **Không cần port bash script thành Python** — kiến trúc Python đã tốt hơn.
- **Không xóa OSV/native audit** — Trivy là bổ sung, không thay thế.
- **Không thay đổi scoring model** — giữ CRITICAL–INFO + score; policy status là output layer riêng.
- **Không đổi plugin architecture** — Trivy/ExifTool sẽ tích hợp như tools trong plugin hiện có.

---

## 4. Kế hoạch thực hiện

### Phase 1 — Trivy integration (Gap 1, 2, 3)

**File tạo mới**: `scanner/core/trivy_adapter.py`
Wrapper chung cho Trivy: chạy `trivy fs --scanners <scanners> --format json --output <tmpfile>`, parse kết quả, trả về structured data. Dùng chung cho cả 3 plugin.

**Sửa `scanner/plugins/secret_checker.py`**
- Thêm `"trivy"` vào `dispatch` dict.
- Implement `_scan_with_trivy()`: gọi trivy_adapter với `--scanners secret`, parse `Results[].Secrets[]`, map sang `Severity.HIGH`.

**Sửa `scanner/plugins/dependency_checker.py`**
- Thêm `"trivy"` vào `tools` config.
- Implement `_scan_with_trivy()`: gọi trivy_adapter với `--scanners vuln`, parse `Vulnerabilities[]`, áp dụng logic:
  - `HIGH/CRITICAL + FixedVersion != ""` → CRITICAL
  - `HIGH/CRITICAL + no fix` hoặc `UNKNOWN severity` → HIGH
  - `MEDIUM/LOW` → MEDIUM/LOW

**Sửa `scanner/plugins/license_checker.py`**
- Thêm `"trivy"` vào `tools` config.
- Implement `_scan_with_trivy()`: gọi trivy_adapter với `--scanners license --license-full`, parse `Results[].Licenses[]`, map qua `_classify_license()`.

**Sửa `scanner/core/requirements.py`**
- Thêm `trivy` vào requirements khi bất kỳ plugin nào enable Trivy.

**Sửa `config.yaml`**
- Thêm `trivy: enabled: true` vào `dependency_checker.tools`, `secret_checker.tool_config`, `license_checker.tools`.

---

### Phase 2 — Gitleaks git history mode (Gap 4)

**Sửa `scanner/plugins/secret_checker.py`**
- Trong `_scan_with_gitleaks()`: kiểm tra `context.get("is_git_repo")`.
- Nếu `True`: bỏ `--no-git` flag → gitleaks tự scan git history.
- Nếu `False`: giữ `--no-git`.

---

### Phase 3 — ExifTool + Font SHA256 (Gap 5, 6)

**Sửa `scanner/plugins/asset_checker.py`**
- Thêm method `_scan_with_exiftool(fonts, root)`:
  - Chạy `exiftool -r -json -ext ttf -ext otf -ext woff -ext woff2 <project_path>`.
  - Parse JSON, với mỗi font: build `$lic` (License + LicenseInfo + LicenseURL + UsageTerms + Rights) và `$extra` (Copyright + CopyrightNotice + Description).
  - Match `FONT_BLOCK_RE` (`non-commercial|personal.?use|trial|demo|evaluation|restricted|proprietary`) → HIGH.
  - Match `FONT_REVIEW_RE` (`gpl|sspl`) → MEDIUM.
  - Không có license metadata → LOW (informational, needs manual review).
- Thêm `_hash_font_file(path)`: sinh SHA256, nhúng vào `evidence` của finding.
- Chạy ExifTool song song fonttools (cả hai bổ sung nhau: fsType = embedding rights, ExifTool = copyright/license text).

**Sửa `config.yaml`**
- Thêm `exiftool_metadata: true` vào `asset_checker.tools`.

**Sửa `scanner/core/requirements.py`**
- Thêm `exiftool` vào requirements khi `asset_checker.tools.exiftool_metadata: true`.

---

### Phase 4 — Policy output format (Gap 7)

**Sửa `scanner/core/report_engine.py`**
- Thêm method `save_policy_report(output_dir)`:
  - `blockers.json`: findings severity CRITICAL hoặc HIGH.
  - `review-required.json`: findings severity MEDIUM (license/font context).
  - `warnings.json`: findings severity LOW.
  - `summary_policy.json`: FAIL/REVIEW\_REQUIRED/WARNING/PASS theo logic:
    - FAIL nếu có CRITICAL/HIGH finding hoặc tool error
    - REVIEW\_REQUIRED nếu có MEDIUM từ license/font
    - WARNING nếu chỉ có LOW
    - PASS nếu không có finding nào (trừ INFO)

**Sửa `main.py`**
- Thêm `--format policy` option.
- Thêm `--zip` flag: nén output dir sau khi scan.

---

### Phase 5 — Di chuyển policy.md (Gap 8)

- Move `vinhtt-tool/policy.md` → `policy.md` (root).
- Cập nhật references trong `README.md` và `SPEC.md`.
- Xóa `vinhtt-tool/` directory sau khi mọi thứ migrate xong.

---

## 5. Thứ tự ưu tiên

| Phase | Độ ưu tiên | Lý do |
|---|---|---|
| Phase 2 (Gitleaks git history) | Cao nhất | Một dòng config, impact lớn — secrets trong git history là gap nghiêm trọng nhất |
| Phase 1 (Trivy) | Cao | CVE coverage gap rõ ràng — Trivy bắt được nhiều case OSV bỏ sót |
| Phase 3 (ExifTool + SHA256) | Trung bình | fonttools đã cover fsType; ExifTool bổ sung copyright text — quan trọng nhưng không urgent |
| Phase 4 (Policy output) | Trung bình | Tiện cho bàn giao; không blocking nếu HTML/JSON report đã có |
| Phase 5 (policy.md) | Thấp nhất | Chỉ là tổ chức file |

---

## 6. Ảnh hưởng lên file hiện có

| File | Thay đổi |
|---|---|
| `scanner/plugins/secret_checker.py` | Thêm trivy tool + bỏ `--no-git` khi git repo |
| `scanner/plugins/dependency_checker.py` | Thêm trivy tool option |
| `scanner/plugins/license_checker.py` | Thêm trivy tool option |
| `scanner/plugins/asset_checker.py` | Thêm ExifTool + SHA256 |
| `scanner/core/report_engine.py` | Thêm policy output format |
| `scanner/core/requirements.py` | Thêm `trivy`, `exiftool` |
| `main.py` | Thêm `--format policy`, `--zip` |
| `config.yaml` | Enable Trivy tools, thêm `exiftool_metadata` |
| `policy.md` | Move từ `vinhtt-tool/` lên root |

**File tạo mới**: `scanner/core/trivy_adapter.py`
