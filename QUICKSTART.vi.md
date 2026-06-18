# vfa-audit — Hướng dẫn cài đặt và sử dụng

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
python -m venv %USERPROFILE%\venvs\vfa-audit
```

Kích hoạt venv mỗi lần mở terminal mới:

```bash
# macOS / Linux
source ~/.venvs/vfa-audit/bin/activate

# Windows (Command Prompt)
%USERPROFILE%\venvs\vfa-audit\Scripts\activate.bat

# Windows (PowerShell)
~\venvs\vfa-audit\Scripts\Activate.ps1
```

---

## 2. Cài đặt vfa-audit

```bash
pip install git+https://github.com/vfa-vinhtt/vfa-audit.git
```

> **Lưu ý:** Các công cụ bổ sung (như `pip-audit`, `fonttools`, `gitleaks`, `trivy`...) **không cần cài trước** — scanner sẽ kiểm tra và báo thiếu khi chạy. Dùng `--install-missing` để tự động cài, hoặc cài thủ công theo hướng dẫn in ra.

---

## 3. Chạy scanner

Đảm bảo venv đang active (thấy `(vfa-audit)` ở đầu dòng terminal), sau đó **di chuyển vào thư mục dự án cần scan**. Venv vẫn giữ nguyên khi `cd` — không cần activate lại.

```bash
cd /path/to/your-project
```

### Lệnh cơ bản

> **Lưu ý:** Phải đảm bảo venv đang active trước khi chạy (thấy `(vfa-audit)` ở đầu dòng terminal). Nếu chưa active, chạy lại lệnh activate ở bước 1.

```bash
vfa-audit
```

Scanner sẽ scan thư mục hiện tại và lưu kết quả vào `./vfa-audit-report/`. Thư mục này được tự động bỏ qua khi scan, tránh scanner quét vào report của chính nó.

### Các tùy chọn thường dùng

| Tùy chọn | Mô tả |
|----------|-------|
| `--format json` | Output JSON *(mặc định)* |
| `--format html` | Output HTML report |
| `--format md` | Output Markdown |
| `--format console` | In kết quả ra terminal |
| `--format policy` | Tách kết quả thành 3 file: blockers / review-required / warnings |
| `-o ./my-report` | Chỉ định tên hoặc thư mục output |
| `--zip` | Nén output thành file `.zip` |
| `--config config.yaml` | Dùng file config tùy chỉnh |
| `--install-missing` | Tự động cài các tool ngoài còn thiếu trước khi scan |
| `--no-strict-requirements` | Bỏ qua tool còn thiếu, vẫn chạy scan |
| `--skip-requirements-check` | Không kiểm tra requirements, chạy thẳng |
| `--version` | In version của scanner |

### Ví dụ

```bash
# Scan và export HTML, tự cài tool còn thiếu
vfa-audit --format html --install-missing

# Scan với config riêng, nén output
vfa-audit --config ./config.yaml --format json --zip

# Scan nhanh, bỏ qua kiểm tra tool
vfa-audit --format console --skip-requirements-check
```

---

## 4. Kết quả output

Output được lưu tại:

```
./vfa-audit-report/<YYYYMMDD_HHmm>_<tên-project>.json
```

Với `--format policy`, output là thư mục chứa 3 file:

```
./vfa-audit-report/<YYYYMMDD_HHmm>_<tên-project>/
├── blockers.json
├── review-required.json
└── warnings.json
```

---

## 5. Cập nhật lên phiên bản mới nhất

```bash
pip install --upgrade git+https://github.com/vfa-vinhtt/vfa-audit.git
```
