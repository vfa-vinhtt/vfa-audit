# vfa-audit-scan.sh

Tool kiểm tra bảo mật source code tự động, kết hợp 3 lớp scan:

| Lớp | Tool | Phát hiện |
|-----|------|-----------|
| **Secrets** | [Gitleaks](https://github.com/gitleaks/gitleaks) + [Trivy](https://github.com/aquasecurity/trivy) | API keys, tokens, credentials trong code và git history |
| **CVE** | [Trivy](https://github.com/aquasecurity/trivy) | Lỗ hổng đã biết trong dependencies |
| **License** | [Trivy](https://github.com/aquasecurity/trivy) + [ExifTool](https://exiftool.org/) | License thư viện và metadata bản quyền/license của font |

---

## Mục đích kiểm tra

Tool giúp trả lời các câu hỏi sau trước khi giao sản phẩm hoặc kiểm tra code nhận từ đối tác / bên thứ ba:

- **Sensitive information** — Source code có chứa thông tin nhạy cảm không? Ví dụ: password, AWS account, access key, private token…
- **CVE** — Các thư viện đang sử dụng có lỗ hổng bảo mật đã biết (CVE) không?
- **Font license** — Project có sử dụng font chưa được cấp phép thương mại không?
- **Library license** — Các thư viện sử dụng có license phù hợp với mục đích thương mại không?

---

## Yêu cầu

macOS với [Homebrew](https://brew.sh/).

| Tool | Cài đặt thủ công |
|------|-----------------|
| `jq` | `brew install jq` |
| `gitleaks` | `brew install gitleaks` |
| `trivy` | `brew install trivy` |
| `exiftool` | `brew install exiftool` |

> **Tự động cài:** Script tự phát hiện tools còn thiếu và cài qua Homebrew khi chạy.

---

## Cách dùng

Script luôn quét **thư mục hiện tại** — `cd` vào project trước khi chạy.

### Chạy trực tiếp

```bash
cd /path/to/project
./vfa-audit-scan.sh
```

### Chạy trực tiếp từ GitHub (không cần clone)

```bash
cd /path/to/project
curl -fsSL https://raw.githubusercontent.com/Vitalify-Asia-Co-Ltd/vfa-audit-governance/main/vfa-audit-scan.sh | bash
```

> **Lưu ý:** Sẽ tự động cài tools còn thiếu qua Homebrew. Cần có Homebrew đã cài sẵn trên máy.

---

## Output

Mỗi lần chạy tạo một file zip tại **thư mục hiện tại** (nơi chạy script), tên theo dạng `<timestamp>_<project-name>.zip`.  
Folder tạm trong `/tmp/vfa_audit/` bị xoá sau khi nén xong.

```
<thư-mục-hiện-tại>/
└── 20250609_143022_my-project.zip
    ├── gitleaks.json               # Raw: secrets findings (Gitleaks)
    ├── trivy.json                  # Raw: vuln + secret + license (Trivy)
    ├── font-license-exiftool.json  # Raw: font license/copyright metadata (ExifTool)
    ├── font-sha256.txt             # SHA256 của mọi font file (nhận diện font bị rename)
    ├── blockers.json               # Đã phân loại: các finding mức FAIL
    ├── review-required.json        # Đã phân loại: các mục cần người review
    ├── warnings.json               # Đã phân loại: finding ưu tiên thấp
    ├── summary.txt                 # Bảng tổng hợp dạng text
    ├── summary.json                # Tổng hợp dạng JSON (machine-readable)
    └── <tool>.log                  # Log lỗi — CHỈ xuất hiện khi scanner đó gặp lỗi
                                    #   ảnh hưởng chất lượng audit; chạy sạch thì không có
```

> Raw evidence (`gitleaks.json`, `trivy.json`, `font-license-exiftool.json`) luôn được giữ nguyên — 3 file `blockers/review-required/warnings` chỉ là lớp kết luận theo policy, để người nhận không phải tự đọc toàn bộ raw JSON.

> Nếu lệnh `zip` không khả dụng, script giữ nguyên folder tại `/tmp/vfa_audit/` thay vì dừng lại.

### Trạng thái kết luận (policy-based)

Mỗi finding được phân loại theo [policy.md](policy.md), kết quả tổng lấy mức cao nhất:

| Status | Ý nghĩa | Hành động |
|--------|---------|-----------|
| `PASS` | Không phát hiện rủi ro đáng kể theo policy | Có thể tiếp tục |
| `WARNING` | Có rủi ro thấp (MEDIUM/LOW CVE) | Không chặn, nhưng ghi nhận |
| `REVIEW_REQUIRED` | Thiếu thông tin hoặc cần người đánh giá (UNKNOWN license, font không metadata, HIGH/CRITICAL CVE chưa có bản vá) | Không kết luận an toàn nếu chưa review |
| `FAIL` | Secret, HIGH/CRITICAL CVE có bản vá, denied license, font hạn chế thương mại — **hoặc scanner lỗi (kết quả không đầy đủ)** | Phải xử lý/phê duyệt trước khi bàn giao |

Quy tắc phân loại chính:

- **Secrets** (Gitleaks/Trivy) → `FAIL`. Nếu secret thật từng commit: phải rotate/revoke, không chỉ xóa khỏi code.
- **CVE**: HIGH/CRITICAL **có** fixed version → `FAIL`; HIGH/CRITICAL **chưa có** bản vá hoặc severity UNKNOWN → `REVIEW_REQUIRED`; MEDIUM/LOW → `WARNING`.
- **License**: AGPL/GPL/SSPL/BUSL/Commons-Clause/CC-BY-NC/CC-BY-ND → `FAIL` (deny-by-default, cần approval — không có nghĩa là cấm dùng thương mại tuyệt đối); LGPL/MPL/EPL/CDDL/OFL/UNKNOWN/NOASSERTION/Custom/Proprietary → `REVIEW_REQUIRED`.
- **Font**: metadata ghi non-commercial/personal-use/trial/demo/restricted/proprietary → `FAIL`; không có metadata license hoặc nhắc GPL/SSPL → `REVIEW_REQUIRED`; **metadata không có flag nào** → `REVIEW_REQUIRED` (metadata sạch không phải bằng chứng license hợp lệ — cần review thủ công).

### Ví dụ summary.txt

```
  Date         2026-06-12 10:00:00
  Project      /Users/dev/my-project
  Status       FAIL

┌─────────────────────────────┬────────────┬────────┬────────┬────────┐
│ Scanner                     │ Status     │   FAIL │ REVIEW │   WARN │
├─────────────────────────────┼────────────┼────────┼────────┼────────┤
│ Secrets (Gitleaks)          │ findings   │      1 │      0 │      0 │
│ Secrets (Trivy)             │ findings   │      3 │      0 │      0 │
│ CVE (Trivy)                 │ findings   │      4 │      0 │      3 │
│ License (Trivy)             │ findings   │      1 │      0 │      0 │
│ Font License (ExifTool)     │ findings   │      0 │      1 │      0 │
├─────────────────────────────┼────────────┼────────┼────────┼────────┤
│ TOTAL                       │            │      9 │      1 │      3 │
└─────────────────────────────┴────────────┴────────┴────────┴────────┘
```

Cột **Status** cho biết kết quả có tin được hay không: `ok` / `findings` / `review` (scanner chạy xong), `failed` (scanner lỗi — kết quả **không đầy đủ**), `skipped` (bị bỏ qua). Giá trị `review` ở dòng Font License nghĩa là có font nhưng không có flag xấu — cần review thủ công.

### Ví dụ summary.json

```json
{
  "timestamp": "2026-06-12T03:00:00Z",
  "project": "/Users/dev/my-project",
  "status": "FAIL",
  "policy": {"fail": 9, "review_required": 1, "warning": 3},
  "scanners": {
    "secrets_gitleaks": {"status": "findings", "fail": 1},
    "trivy": {
      "status": "findings",
      "cve": {"total": 7, "fail": 4, "review": 0, "warn": 3},
      "secrets": {"fail": 3},
      "license": {"fail": 1, "review": 0}
    },
    "font_license": {"status": "findings", "files": 1, "fail": 0, "review": 1}
  },
  "total_findings": 13,
  "tool_errors": 0,
  "output_dir": "/Users/dev/my-project/20260612_100000_my-project.zip"
}
```

---

## Lưu ý quan trọng

### Về Secret Scan (Gitleaks)

- Mặc định Gitleaks **quét toàn bộ git history**, không chỉ code hiện tại. Secrets đã xóa khỏi code nhưng còn trong commit cũ vẫn bị phát hiện.
- Nếu project **không phải git repo**, script in `[ NO ] No git in project` và dùng `gitleaks dir` quét file hiện tại (không bỏ qua âm thầm).
- Script dùng **default rules của Gitleaks, không hard-code allowlist** — file `.env`, `.env.local`, `.env.production` đều bị quét vì đó là nơi hay chứa secret thật. Allowlist (nếu cần) phải nằm trong `.gitleaks.toml` của project, có lý do và người phê duyệt (xem [policy.md](policy.md) §3.4).
- Trivy chạy thêm secret scanner như một lớp đối chiếu thứ hai (dòng `Secrets (Trivy)` trong summary).
- Kết quả có thể có false positive — nên review thủ công trước khi xử lý. Nếu secret thật từng commit: **rotate/revoke**, không chỉ xóa khỏi code.

### Về CVE Scan (Trivy)

- Chỉ phát hiện CVE trong dependencies khai báo qua package manager (npm, pip, maven, gradle, go.mod, cargo…).
- CVE trong code tự viết không được phát hiện — cần SAST tool riêng (ví dụ: Semgrep, CodeQL).

### Về License Scan (Trivy)

- Sử dụng `--license-full`: Trivy scan cả **nội dung file** lẫn metadata package manager — tăng độ chính xác.
- Phân loại theo deny/review list (xem [policy.md](policy.md) §5): deny → `FAIL`, review/UNKNOWN → `REVIEW_REQUIRED`. `FAIL` nghĩa là **không phù hợp policy mặc định, cần legal/security approval** — không có nghĩa license đó cấm dùng thương mại tuyệt đối (GPL vẫn dùng thương mại được nếu đáp ứng nghĩa vụ copyleft).
- Giới hạn: Trivy chỉ báo license của package nó nhận diện được — package **không khai báo license** có thể không xuất hiện trong danh sách. Không thấy license flag ≠ chắc chắn sạch license.

### Về Font License Scan (ExifTool)

- ExifTool đọc metadata trực tiếp từ font độc lập: `.ttf`, `.otf`, `.woff`, `.woff2`.
- Script tạo `font-license-exiftool.json` lưu toàn bộ metadata gốc, và `font-sha256.txt` (gồm cả `.eot`) để nhận diện font bị rename.
- Font → `FAIL` khi metadata có cụm hạn chế: `personal use`, `non-commercial`, `trial`, `demo`, `evaluation`, `restricted`, `proprietary`. Font → `REVIEW_REQUIRED` trong mọi trường hợp còn lại khi có font: thiếu metadata license, nhắc `GPL`/`SSPL`, hoặc **metadata trông sạch nhưng không có flag nào** — metadata sạch không phải bằng chứng license hợp lệ.
- **Metadata không phải bằng chứng pháp lý** — script không thể tự kết luận font PASS. Cần review thủ công với: file license đi kèm, link nguồn chính thức, proof of purchase, hoặc license grant từ vendor.

---

## Khi nào tool báo lỗi (`[ERR ]` / status `failed`)

Mỗi lỗi đều ghi rõ **scanner nào hỏng** và **log nào cần xem** (`<tool>.log` nằm cùng thư mục báo cáo, có trong file zip). File log **chỉ tồn tại khi scanner đó gặp lỗi ảnh hưởng chất lượng audit** — báo cáo không có file `.log` nào nghĩa là mọi scanner chạy sạch. Status tổng chuyển `FAIL` + dòng "results are INCOMPLETE" — vì kết quả không đầy đủ thì không được kết luận an toàn (UNKNOWN ≠ safe).

| Trường hợp | Thông báo |
|---|---|
| Không tạo được thư mục output trong `/tmp` | Script tự thử tạo `~/vfa_audit/` (`$HOME`). Nếu vẫn thất bại: `Cannot create output directory: ...` → exit 2 |
| Tool cài tự động thất bại | `Failed to install <tool>` + layer tương ứng báo `<tool> unavailable — scan NOT performed` |
| Homebrew không có trên máy | `Homebrew not found — cannot install missing tools` + gợi ý cài thủ công |
| Gitleaks lỗi (exit > 1) | `Gitleaks failed (exit N) — see gitleaks.log` |
| Trivy lỗi (DB download, crash…) | `Trivy failed (exit N) — see trivy.log` |
| ExifTool lỗi đọc file | `ExifTool failed (exit N) — see exiftool.log` (lỗi lẻ tẻ nhưng vẫn có data → chỉ `[WARN]`) |
| `summary.json` không sinh được | `[WARN]` (summary.txt vẫn dùng được) |
| `zip` thiếu / nén lỗi | `[WARN]` — giữ nguyên folder báo cáo |

## Exit Codes

| Code | Ý nghĩa |
|------|---------|
| `0` | Script chạy xong, kể cả khi có findings (status thật nằm trong `summary.json`) |
| `2` | Không tạo được thư mục output |
