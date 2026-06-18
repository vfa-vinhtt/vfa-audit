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
cd /path/to/your-project
```

```bash
vfa-audit
```

Scanner sẽ scan thư mục hiện tại và lưu kết quả vào `./vfa-audit-report/`.

---

## 4. Kết quả output

Output được lưu tại:

```
./vfa-audit-report/<YYYYMMDD_HHmm>_<tên-project>.json
```

---

## 5. Cập nhật lên phiên bản mới nhất

```bash
pip install --upgrade git+https://github.com/vfa-vinhtt/vfa-audit.git
```
