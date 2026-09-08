# DVAS HTML Report Format for Greenbone GVM

Báo cáo bảo mật tương tác chuẩn DVAS (Interactive Security Intelligence HTML Report) tích hợp trực tiếp vào Greenbone Community Edition (GVM/OpenVAS).

---

## 🌟 Tính Năng Nổi Bật

1. **Giao diện Hiện đại & Tương tác Cao:**
   - Hỗ trợ lọc theo mức độ nghiêm trọng (Severity: Critical, High, Medium, Low, Log/Info).
   - Tìm kiếm nhanh theo từ khóa, CVE, CWE, tên dịch vụ hoặc cổng mạng.
   - Thẻ chi tiết phát hiện (Detail Cards) có thể thu gọn / mở rộng.
   - Bảng mục lục điều hướng nhanh theo địa chỉ IP mục tiêu (Host Navigation TOC).

2. **Hoàn Toàn Độc Lập (Self-Contained & Air-gapped Ready):**
   - Không phụ thuộc Internet: Toàn bộ CSS, JavaScript và SVG icons được nhúng trực tiếp trong file HTML (~260 KB).
   - Không sử dụng CDN bên ngoài, phù hợp cho môi trường mạng cô lập (SOC / Offline Lab).

3. **Bảo Mật Ngăn Chặn XSS (Strict XSS Sanitization):**
   - 100% dữ liệu từ máy quét được escape HTML (`html.escape`).
   - Kiểm duyệt scheme an toàn (`is_safe_url`: chỉ cho phép `http://` và `https://`, chặn đứng `javascript:`, `data:`).

4. **Tích Hợp GVM 1-Click:**
   - Tự động nạp qua GMP socket hoặc gvm-tools.
   - Script tự động nâng cấp quyền tin cậy sang `TRUST_YES` (`trust = 1, flags = 1`).

---

## 📂 Cấu Trúc Thư Mục

| File | Mô Tả |
|------|-------|
| `generate` | Executable wrapper được GVM daemon (`gvmd`) gọi khi xuất báo cáo. |
| `generate_html.py` | Động cơ chuyển đổi XML OpenVAS sang báo cáo HTML tương tác DVAS. |
| `report_format.xml` | File định nghĩa siêu dữ liệu Report Format cho Greenbone. |
| `package_plugin.py` | Script đóng gói plugin thành file XML Base64 theo chuẩn Greenbone GMP. |
| `greenbone_dvas_html_report_format.xml` | Gói plugin hoàn chỉnh sẵn sàng nạp trực tiếp vào Greenbone GVM. |

---

## 🚀 Hướng Dẫn Cài Đặt & Kích Hoạt

### Cách 1: Tự động 1-Click (Khuyên dùng)
Khi Greenbone GVM đang chạy qua Docker Compose, chạy lệnh sau từ thư mục gốc của dự án:

```bash
python3 scripts/import_greenbone_report_format.py
```

Lệnh này sẽ:
1. Đóng gói plugin nếu chưa có file package.
2. Gửi lệnh `<create_report_format>` vào GVMD thông qua socket GMP.
3. Cập nhật cơ sở dữ liệu PostgreSQL của Greenbone sang `trust = 1, flags = 1`.
4. Đồng bộ file vào thư mục `/var/lib/gvm/gvmd/report_formats/` trong container `gvmd`.

### Cách 2: Nạp thủ công qua GSA Web UI
1. Truy cập Web UI Greenbone GSA: `https://<ip>:9392` hoặc `https://localhost`.
2. Đi tới: **Configuration** -> **Report Formats**.
3. Nhấn vào biểu tượng **New Report Format** (ngôi sao xanh hoặc biểu tượng thư mục).
4. Tải lên file `greenbone_report_formats/greenbone_dvas_html_report_format.xml`.
5. Nếu trạng thái hiển thị `Trust: Unknown`, chạy:
   ```bash
   python3 scripts/import_greenbone_report_format.py
   ```

---

## 📊 Xuất Báo Cáo Từ Dòng Lệnh

Bạn có thể tạo báo cáo DVAS HTML độc lập từ bất kỳ file XML OpenVAS nào mà không cần Greenbone đang chạy:

```bash
# Cú pháp
python3 scripts/generate_html_report.py data/raw/openvas_report.xml -o data/output/dvas_report.html

# Hoặc dùng trực tiếp bộ sinh
python3 greenbone_report_formats/generate_html.py data/raw/openvas_report.xml > data/output/dvas_report.html
```

---

## 🧪 Kiểm Thử Tự Động

Bộ 7 bài kiểm thử hồi quy được cung cấp trong `tests/test_html_report_format.py`:

```bash
./venv/bin/python3 -m unittest tests/test_html_report_format.py -v
```
