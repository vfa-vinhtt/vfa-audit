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

- **Sensitive information** — Source code có chứa thông tin nhạy cảm không? Ví dụ: password, AWS account, access key, private token… (bao gồm cả code nhận từ đối tác hoặc bên thứ ba)
- **CVE** — Các thư viện đang sử dụng có lỗ hổng bảo mật đã biết (CVE) không?
- **Font license** — Project có sử dụng font chưa được cấp phép thương mại không?
- **Library / source code license** — Các thư viện hoặc đoạn code sử dụng có license phù hợp với mục đích thương mại không?

---

## Yêu cầu

macOS với [Homebrew](https://brew.sh/).

| Tool | Cài đặt thủ công |
|------|-----------------|
| `jq` | `brew install jq` |
| `gitleaks` | `brew install gitleaks` |
| `trivy` | `brew install trivy` |
| `exiftool` | `brew install exiftool` |

> **Tự động cài:** Script tự phát hiện tools còn thiếu và cài tự động qua Homebrew — không cần cài tay trước.

---

## Cách dùng

### Cú pháp

Script luôn quét **thư mục hiện tại** — `cd` vào project trước khi chạy.

> Gitleaks cần truy cập thư mục `.git` để quét toàn bộ git history. Nếu không tìm thấy, script tự chuyển sang quét file hiện tại.

### Chạy trực tiếp từ GitHub (không cần clone)

```bash
cd /path/to/project
curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash
```

> **Lưu ý:** Sẽ tự động cài tools còn thiếu qua Homebrew. Cần có Homebrew đã cài sẵn trên máy.

---

## Output

Mỗi lần chạy tạo một file zip tại **thư mục hiện tại** (nơi chạy script), tên theo dạng `<timestamp>_<project-name>.zip`.  
Folder tạm trong `/tmp/vfa_audit/` bị xoá sau khi nén xong.

```
<thư-mục-hiện-tại>/
└── 20250609_143022_my-project.zip
    ├── gitleaks.json               # Secrets findings (Gitleaks)
    ├── gitleaks-config.toml        # Config Gitleaks dùng cho lần scan này
    ├── trivy.json                  # Vuln + secret + license findings (Trivy)
    ├── font-license-exiftool.json  # Font license/copyright metadata (ExifTool)
    ├── summary.txt                 # Bảng tổng hợp dạng text
    ├── summary.json                # Tổng hợp dạng JSON (machine-readable)
    └── <tool>.log                  # Log lỗi — CHỈ xuất hiện khi scanner đó gặp lỗi
                                    #   ảnh hưởng chất lượng audit; chạy sạch thì không có
```

> Nếu lệnh `zip` không khả dụng, script giữ nguyên folder tại `/tmp/vfa_audit/` thay vì dừng lại.

### Ví dụ summary.txt

```
  Date         2025-06-09 14:30:22
  Project      /Users/dev/my-project
  Severity     HIGH+
  Status       WARN

┌─────────────────────────────┬────────────┬──────────┐
│ Scanner                     │ Status     │ Findings │
├─────────────────────────────┼────────────┼──────────┤
│ Secrets (Gitleaks)          │ findings   │        2 │
│ Secrets (Trivy)             │ ok         │        0 │
│ CVE (Trivy)                 │ findings   │       14 │
│ License (Trivy)             │ findings   │        3 │
│ Font License (ExifTool)     │ findings   │        2 │
├─────────────────────────────┼────────────┼──────────┤
│ TOTAL                       │            │       21 │
└─────────────────────────────┴────────────┴──────────┘
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
    "font_license": {"status": "findings", "files": 8, "issues": 2}
  },
  "total_findings": 21,
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

### Về CVE Scan (Trivy)

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
| ExifTool lỗi đọc file | `ExifTool failed (exit N) — see exiftool.log` (lỗi lẻ tẻ nhưng vẫn có data → chỉ `[WARN]`) |
| `summary.json` không sinh được | `[WARN]` (summary.txt vẫn dùng được) |
| `zip` thiếu / nén lỗi | `[WARN]` — giữ nguyên folder báo cáo |

## Exit Codes

| Code | Ý nghĩa |
|------|---------|
| `0` | Script chạy xong, kể cả khi có findings (status thật nằm trong `summary.json`) |
| `2` | Lỗi tham số hoặc không tạo được thư mục output |
