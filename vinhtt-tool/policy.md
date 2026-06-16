# Source Code Security & License Scan Policy

## 1. Mục tiêu

Policy này dùng để phân loại kết quả scan source code khi tiếp nhận, kiểm tra hoặc bàn giao dự án phần mềm.

Tool thực hiện quét tự động trên các nhóm rủi ro sau:

* Secrets
* CVE / dependency vulnerabilities
* Library license
* Font license metadata
* Misconfiguration nếu có
* Source code security pattern nếu tích hợp SAST

Nguyên tắc chính:

```text
Scan toàn bộ.
Không bỏ qua dữ liệu thô.
Kết luận dựa trên policy.
UNKNOWN không được tự động xem là an toàn.
```

---

## 2. Trạng thái kết luận

Mỗi finding sau khi scan phải được phân loại vào một trong bốn trạng thái:

| Status          | Ý nghĩa                                    | Hành động                              |
| --------------- | ------------------------------------------ | -------------------------------------- |
| PASS            | Không phát hiện rủi ro đáng kể theo policy | Có thể tiếp tục                        |
| WARNING         | Có rủi ro thấp hoặc cần theo dõi           | Không chặn, nhưng ghi nhận             |
| REVIEW_REQUIRED | Không đủ thông tin hoặc cần người đánh giá | Không kết luận an toàn nếu chưa review |
| FAIL            | Rủi ro cao hoặc vi phạm policy             | Cần xử lý trước khi bàn giao/sử dụng   |

---

# 3. Secrets Policy

## 3.1 Tool

* Gitleaks
* Trivy secret scanner

## 3.2 Phân loại

| Điều kiện                                                                                           | Status                              |
| --------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Phát hiện private key, cloud key, production token, database password, OAuth secret, webhook secret | FAIL                                |
| Phát hiện secret trong git history                                                                  | FAIL                                |
| Phát hiện test token rõ ràng, dummy value, placeholder                                              | WARNING hoặc PASS nếu có bằng chứng |
| Finding không xác định được thật/giả                                                                | REVIEW_REQUIRED                     |
| Không phát hiện secret                                                                              | PASS                                |

## 3.3 Quy tắc xử lý

Nếu secret thật đã từng commit vào repository:

```text
Không chỉ xóa khỏi code.
Phải rotate/revoke secret.
Phải kiểm tra git history.
Phải ghi nhận trong report.
```

## 3.4 Allowlist

Chỉ allowlist nếu thỏa mãn ít nhất một điều kiện:

* Giá trị là placeholder rõ ràng, ví dụ `example`, `dummy`, `changeme`
* Secret thuộc test fixture và không dùng được ngoài môi trường test
* Có bằng chứng từ owner rằng key đã revoke
* Finding là false positive đã được xác minh

Allowlist phải có lý do:

```yaml
allowlist:
  - id: "SECRET-001"
    file: "tests/fixtures/example.env"
    reason: "Dummy credential used for test fixture only"
    approved_by: "security_owner"
```

---

# 4. CVE / Dependency Vulnerability Policy

## 4.1 Tool

* Trivy

## 4.2 Severity policy

| Severity | Fixed version available | Status                                              |
| -------- | ----------------------: | --------------------------------------------------- |
| CRITICAL |                      Có | FAIL                                                |
| CRITICAL |                   Không | REVIEW_REQUIRED                                     |
| HIGH     |                      Có | FAIL                                                |
| HIGH     |                   Không | REVIEW_REQUIRED                                     |
| MEDIUM   |                      Có | WARNING                                             |
| MEDIUM   |                   Không | WARNING                                             |
| LOW      |                  Bất kỳ | WARNING hoặc PASS                                   |
| UNKNOWN  |                  Bất kỳ | REVIEW_REQUIRED nếu package quan trọng hoặc exposed |

## 4.3 Default gate

Một source/package không đạt nếu có:

```text
CRITICAL hoặc HIGH có fixed version available
```

## 4.4 Không nên fail tự động nếu

* CVE không ảnh hưởng runtime thực tế
* Dependency chỉ dùng trong dev/test
* Package không được load hoặc không reachable
* Vendor advisory đánh giá là not affected
* Không có bản vá và có mitigation tạm thời

Các trường hợp này phải được ghi trong suppression file.

## 4.5 Suppression format

```yaml
suppressions:
  - id: "CVE-YYYY-XXXX"
    package: "package-name"
    version: "1.2.3"
    reason: "Dev dependency only, not included in production build"
    expires_at: "2026-12-31"
    approved_by: "security_owner"
```

Suppression không được để vĩnh viễn nếu không có lý do đặc biệt.

---

# 5. Library License Policy

## 5.1 Tool

* Trivy license scanner
* SBOM nếu có

## 5.2 License normalization

License nên được chuẩn hóa về SPDX identifier nếu có thể.

Ví dụ:

```text
MIT
Apache-2.0
BSD-3-Clause
GPL-3.0-only
GPL-3.0-or-later
LGPL-3.0-only
AGPL-3.0-only
MPL-2.0
```

Nếu scanner trả về license không rõ ràng:

```text
UNKNOWN
NOASSERTION
Custom
Proprietary
Unrecognized
```

thì không được tự động xem là an toàn.

---

## 5.3 License allowlist

Các license sau được phép dùng mặc định trong sản phẩm thương mại, với điều kiện vẫn giữ attribution/notice nếu license yêu cầu:

```yaml
allowed_licenses:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
  - Zlib
  - BSL-1.0
  - Unlicense
  - 0BSD
  - CC0-1.0
```

Status mặc định:

```text
PASS
```

Ngoại lệ:

```text
Nếu package bị copy source trực tiếp, chỉnh sửa nhiều, hoặc thiếu file notice/license, chuyển sang REVIEW_REQUIRED.
```

---

## 5.4 Review-required licenses

Các license sau cần người đánh giá trước khi kết luận phù hợp thương mại:

```yaml
review_required_licenses:
  - LGPL-2.1-only
  - LGPL-2.1-or-later
  - LGPL-3.0-only
  - LGPL-3.0-or-later
  - MPL-2.0
  - EPL-1.0
  - EPL-2.0
  - CDDL-1.0
  - CDDL-1.1
  - Artistic-2.0
  - Unicode-DFS-2016
  - OFL-1.1
  - UNKNOWN
  - NOASSERTION
  - LicenseRef-*
  - Custom
  - Proprietary
```

Status mặc định:

```text
REVIEW_REQUIRED
```

Lý do:

```text
Các license này có thể vẫn dùng được trong sản phẩm thương mại, nhưng cần kiểm tra nghĩa vụ đi kèm, cách link, cách phân phối, sửa đổi source, notice, hoặc điều khoản riêng.
```

---

## 5.5 Deny / block-by-default licenses

Các license sau bị chặn mặc định đối với sản phẩm closed-source hoặc sản phẩm bàn giao thương mại nếu chưa có phê duyệt:

```yaml
denied_by_default_licenses:
  - AGPL-3.0-only
  - AGPL-3.0-or-later
  - GPL-2.0-only
  - GPL-2.0-or-later
  - GPL-3.0-only
  - GPL-3.0-or-later
  - SSPL-1.0
  - BUSL-1.1
  - Commons-Clause
  - CC-BY-NC-*
  - CC-BY-ND-*
```

Status mặc định:

```text
FAIL
```

Ghi chú:

```text
FAIL không có nghĩa là license cấm dùng thương mại tuyệt đối.
FAIL có nghĩa là license không phù hợp với policy mặc định và cần legal/security approval nếu vẫn muốn sử dụng.
```

---

## 5.6 Unknown license rule

Nếu license là một trong các giá trị sau:

```text
UNKNOWN
NOASSERTION
Unrecognized
Custom
Proprietary
LicenseRef-*
```

thì status mặc định là:

```text
REVIEW_REQUIRED
```

Không được tự động chuyển thành PASS chỉ vì không phát hiện license nguy hiểm.

---

# 6. Font License Policy

## 6.1 Tool

* ExifTool
* File discovery
* Manual evidence check nếu cần

## 6.2 File types cần kiểm tra

```text
.ttf
.otf
.woff
.woff2
.eot
```

## 6.3 Metadata cần thu thập

Với mỗi font file, report nên lưu:

```text
file_path
file_hash
font_family
font_subfamily
full_name
postscript_name
copyright
trademark
license_description
license_info_url
manufacturer
designer
vendor_url
```

## 6.4 Phân loại font

| Điều kiện                                                                        | Status          |
| -------------------------------------------------------------------------------- | --------------- |
| Font có license rõ ràng, cho phép commercial use, embedding/distribution phù hợp | PASS            |
| Font là OFL-1.1 nhưng có sửa đổi/rename/subset                                   | REVIEW_REQUIRED |
| Font không có metadata license                                                   | REVIEW_REQUIRED |
| Font có metadata nhưng không có bằng chứng nguồn tải/license file                | REVIEW_REQUIRED |
| Font ghi rõ non-commercial/personal use only                                     | FAIL            |
| Font proprietary nhưng không có proof of purchase hoặc license grant             | FAIL            |
| Font bị rename, subset, hoặc không truy được nguồn                               | REVIEW_REQUIRED |

## 6.5 Quy tắc quan trọng

```text
ExifTool chỉ dùng để thu thập metadata.
Không dùng ExifTool làm bằng chứng pháp lý duy nhất.
```

Để kết luận font PASS, cần ít nhất một bằng chứng:

* File license đi kèm trong source
* Link nguồn font chính thức
* License grant từ vendor
* Proof of purchase
* Tài liệu bàn giao từ đối tác
* Bằng chứng font thuộc bộ open-source hợp lệ

---

# 7. Misconfiguration Policy

## 7.1 Tool

* Trivy misconfig scanner

## 7.2 Phân loại

| Finding                                               | Status                    |
| ----------------------------------------------------- | ------------------------- |
| Secret trong config                                   | FAIL                      |
| Container chạy privileged                             | FAIL hoặc REVIEW_REQUIRED |
| Container chạy root user                              | REVIEW_REQUIRED           |
| Kubernetes manifest thiếu resource limit              | WARNING                   |
| Public S3 bucket / public storage                     | FAIL                      |
| Terraform mở inbound `0.0.0.0/0` cho service nhạy cảm | FAIL                      |
| Dockerfile dùng `latest` tag                          | WARNING                   |
| Dockerfile không pin version base image               | WARNING                   |
| Thiếu healthcheck                                     | WARNING                   |

---

# 8. SAST Policy nếu tích hợp Semgrep hoặc CodeQL

## 8.1 Phân loại

| Finding type                       | Status                    |
| ---------------------------------- | ------------------------- |
| SQL injection                      | FAIL                      |
| Command injection                  | FAIL                      |
| Path traversal                     | FAIL                      |
| Insecure deserialization           | FAIL                      |
| SSRF                               | FAIL hoặc REVIEW_REQUIRED |
| Hardcoded weak crypto              | REVIEW_REQUIRED           |
| Missing authorization check        | REVIEW_REQUIRED           |
| XSS                                | FAIL hoặc REVIEW_REQUIRED |
| Insecure random for security token | FAIL                      |
| Debug endpoint exposed             | REVIEW_REQUIRED           |

## 8.2 Giới hạn

SAST không thay thế manual review.

Các vùng bắt buộc review thủ công nếu project có:

```text
authentication
authorization
role / permission
payment
file upload
password reset
webhook
admin API
JWT/session
external URL fetch
multi-tenant data access
```

---

# 9. Report Policy

## 9.1 Report phải có 3 lớp

### Executive summary

```text
PASS / FAIL / REVIEW_REQUIRED
Số lượng finding theo nhóm
Các blocker cần xử lý
```

### Prioritized findings

Chỉ hiển thị các mục:

```text
FAIL
REVIEW_REQUIRED
HIGH/CRITICAL
UNKNOWN license
font thiếu bằng chứng
secret thật hoặc nghi thật
```

### Raw evidence

Lưu toàn bộ output gốc:

```text
gitleaks.json
trivy.json
font-metadata.json
semgrep.json nếu có
```

---

# 10. Pass / Fail Gate

## 10.1 Source được xem là PASS nếu

```text
Không có secret thật
Không có HIGH/CRITICAL CVE có bản vá mà chưa xử lý
Không có denied license
Không có UNKNOWN/custom/proprietary license chưa review
Không có font thiếu bằng chứng license nếu font được phân phối cùng sản phẩm
Không có SAST finding nghiêm trọng chưa xử lý
```

## 10.2 Source bị FAIL nếu

```text
Có secret thật
Có HIGH/CRITICAL CVE có fixed version available
Có license thuộc denylist mà chưa được phê duyệt
Có font non-commercial/personal-use-only
Có proprietary font không có bằng chứng cấp phép
Có finding SAST nghiêm trọng
```

## 10.3 Source ở trạng thái REVIEW_REQUIRED nếu

```text
Có UNKNOWN license
Có NOASSERTION license
Có custom/proprietary license chưa xác minh
Có font thiếu metadata hoặc thiếu license evidence
Có CVE nghiêm trọng nhưng chưa xác định affected/reachable
Có finding nghiêm trọng nhưng scanner có thể false positive
```

---

# 11. Suppression / Exception Policy

Không được xóa finding khỏi report gốc.

Chỉ được suppress ở lớp kết luận nếu có đủ thông tin:

```yaml
exception:
  id: "EX-001"
  finding_id: "CVE-YYYY-XXXX"
  category: "cve"
  reason: "Package is used only in test environment"
  evidence: "Not included in production build artifact"
  approved_by: "security_owner"
  expires_at: "2026-12-31"
```

Exception bắt buộc có:

```text
reason
evidence
approver
expiry date
```

---

# 12. Mức ưu tiên xử lý

| Priority | Điều kiện                                                                               |
| -------- | --------------------------------------------------------------------------------------- |
| P0       | Secret thật, AGPL/GPL blocker, proprietary font không license, critical CVE exploitable |
| P1       | HIGH/CRITICAL CVE có bản vá, denied license, SAST finding nghiêm trọng                  |
| P2       | UNKNOWN license, custom license, font thiếu bằng chứng, medium CVE                      |
| P3       | Low CVE, notice/attribution thiếu, Dockerfile hygiene issue                             |

---

# 13. Nguyên tắc không kết luận quá mức

Tool không được tự động tuyên bố:

```text
Source code này an toàn tuyệt đối.
Source code này chắc chắn hợp lệ pháp lý.
Font này chắc chắn được dùng thương mại.
Không có CVE nghĩa là không có lỗ hổng.
Không có secret finding nghĩa là chắc chắn không có secret.
```

Tool chỉ được kết luận:

```text
Không phát hiện vấn đề theo phạm vi scan và policy hiện tại.
Các mục cần review đã được liệt kê.
Kết luận pháp lý cuối cùng cần owner/legal xác nhận nếu có license không rõ ràng.
```
