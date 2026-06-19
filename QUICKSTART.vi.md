# vfa-audit — Hướng dẫn cài đặt và sử dụng

## Mục đích audit

Trả lời bốn câu hỏi trước khi bàn giao sản phẩm hoặc review code nhận từ đối tác / bên thứ ba:

| Câu hỏi | Plugin | Công cụ |
|---|---|---|
| **Thông tin nhạy cảm** — Source code có chứa secrets không? (passwords, AWS keys, tokens, private keys…) | `secret_checker` | regex + entropy, Gitleaks (git history), TruffleHog, Trivy |
| **CVE** — Các dependency có lỗ hổng bảo mật đã biết không? | `dependency_checker` | OSV API, pip-audit / npm audit / govulncheck / dotnet / composer, Trivy |
| **License font** — Có font nào được dùng không có commercial license không? | `asset_checker` | fonttools (fsType embedding rights), ExifTool (copyright/license text), SHA256 |
| **License thư viện** — License của các dependency có tương thích với commercial use không? | `license_checker` | lockfile/manifest content, pip-licenses / license-checker / go-licenses / …, Trivy `--license-full` |

Kiểm tra bổ sung: **PII** trong source code, **cấu hình không an toàn**, **`.env` bị lộ**, **`.gitignore` thiếu rule**.

---

## Yêu cầu

- Python **3.10** trở lên
- Git

---

## 1. Tạo virtual environment

Tạo venv **một lần duy nhất** ở thư mục cố định ngoài dự án — không tạo trong thư mục dự án cần scan để tránh scanner quét vào.

**macOS / Linux** — đường dẫn khuyến nghị: `~/.venvs/vfa-audit`

```bash
python3 -m venv ~/.venvs/vfa-audit
```

**Windows** — đường dẫn khuyến nghị: `%USERPROFILE%\venvs\vfa-audit`

```bat
# Windows (Command Prompt)
python -m venv %USERPROFILE%\venvs\vfa-audit

# Windows (PowerShell)
python -m venv "$env:USERPROFILE\venvs\vfa-audit"
```

Kích hoạt venv mỗi lần mở terminal mới:

```bash
# macOS / Linux
source ~/.venvs/vfa-audit/bin/activate

# Windows (Command Prompt)
%USERPROFILE%\venvs\vfa-audit\Scripts\activate.bat

# Windows (PowerShell)
# Lần đầu chạy trên PowerShell có thể bị block do execution policy.
# Chạy lệnh sau một lần duy nhất để unlock (chỉ ảnh hưởng user hiện tại, không cần quyền admin):
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
# Sau đó activate bình thường:
~\venvs\vfa-audit\Scripts\Activate.ps1
```

---

## 2. Cài đặt vfa-audit

```bash
pip install git+https://github.com/vfa-vinhtt/vfa-audit.git
```

---

## 3. Chạy scanner

Đảm bảo venv đang active (thấy `(vfa-audit)` ở đầu dòng terminal), sau đó **di chuyển vào thư mục dự án cần scan**. Venv vẫn giữ nguyên khi `cd` — không cần activate lại.

```bash
cd /path/to/your-repo
```

```bash
vfa-audit
```

Scanner sẽ scan thư mục hiện tại và lưu kết quả vào `./vfa-audit-report/`.

---

## 4. Kết quả output

Output được lưu tại:

```
./vfa-audit-report/<YYYYMMDD_HHmm>_<tên-repo>.json
```

---

## 5. Upload report lên Google Drive

Sau khi scan xong, upload file report lên Google Drive chung của team theo cấu trúc sau:

**Link Google Drive:** [vfa-audit-reports](https://drive.google.com/drive/folders/1HPQKqHHeSn2vD7IXAfUYYiG5x1VqFP_W)

**Cấu trúc thư mục:**

```
vfa-audit-reports/
└── 2026-06/              ← folder theo tháng (YYYY-MM)
    ├── MPL/              ← Lab MPL
    │   └── <tên-dự-án>/  ← tạo folder theo tên dự án (project name)
    │       └── <file>.json
    └── SPL/              ← Lab SPL
        └── <tên-dự-án>/
            └── <file>.json
```

> Một dự án có thể có nhiều repo — folder Drive đặt theo **tên dự án**, file report bên trong đặt theo **tên repo**.

**Các bước thực hiện:**

1. Mở link Google Drive ở trên
2. Vào folder tháng hiện tại (ví dụ: `2026-06`)
3. Vào folder Lab của mình (`MPL` hoặc `SPL`)
4. Tạo folder mới đặt tên theo **tên dự án** (nếu chưa có)
5. Upload file report `./vfa-audit-report/<YYYYMMDD_HHmm>_<tên-repo>.json` vào folder đó

---

## 6. Cập nhật lên phiên bản mới nhất

```bash
pip install --upgrade git+https://github.com/vfa-vinhtt/vfa-audit.git
```
