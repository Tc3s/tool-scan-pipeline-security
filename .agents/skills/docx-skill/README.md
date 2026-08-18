# 🛡️ DOCX Skill: Bộ Công Cụ & Skill Tự Động Phân Tích & Khởi Tạo Báo Cáo An Toàn Thông Tin DOCX

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Format](https://img.shields.io/badge/format-DOCX--OpenXML-orange.svg)
![Audit Status](https://img.shields.io/badge/audit-16%2F16%20PASSED-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**`docx-skill`** là bộ giải pháp và Skill mở rộng chuẩn mực dành cho AI Agent (Google Antigravity / Gemini) dùng để **giải phẫu template Word (`.docx`), trích xuất quy chuẩn định dạng, bền vững hóa dữ liệu rà quét và tự động sinh Báo cáo An toàn thông tin doanh nghiệp** đạt mức chuẩn xác và thẩm mỹ tối đa.

---

## 📑 Mục Lục
- [1. Giới Thiệu Tổng Quan](#1-giới-thiệu-tổng-quan)
- [2. Cụm Quy Tắc Kỹ Thuật Cốt Lõi](#2-cụm-quy-tắc-kỹ-thuật-cốt-lõi)
- [3. Nguyên Tắc Bắt Buộc: Phản Biện & Đối Soát 3 Chiều](#3-nguyên-tắc-bắt-buộc-phản-biện--đối-soát-3-chiều)
- [4. Cấu Trúc Thư Mục](#4-cấu-trúc-thư-mục)
- [5. Hướng Dẫn Cài Đặt & Sử Dụng](#5-hướng-dẫn-cài-đặt--sử-dụng)
- [6. Quy Trình Thực Thi 4 Giai Đoạn](#6-quy-trình-thực-thi-4-giai-đoạn)
- [7. Bộ Kiểm Định Tự Động 16 Tiêu Chí (16 Assertions)](#7-bộ-kiểm-định-tự-động-16-tiêu-chí-16-assertions)
- [8. Giấy Phép & Tác Giả](#8-giấy-phép--tác-giả)

---

## 1. Giới Thiệu Tổng Quan

Trong các hệ thống rà quét an toàn thông tin tự động, việc xuất kết quả ra file Word (`.docx`) thường gặp phải các lỗi nghiêm trọng như:
- Thẻ ẩn XML (`w:sdt`) giữ lại bộ đệm mục lục cũ của file template.
- Biểu đồ bị tràn viền, đè khung hoặc đứt nét tiêu đề.
- Bảng biểu bị vỡ ô đôi (cell split) khi nhảy qua trang mới.
- Tiêu đề mục nằm mồ côi (orphan heading) ở dòng cuối cùng của trang.
- Từ ngữ tiếng Anh thô (`CRITICAL`, `INFORMATIONAL`, thẻ mã HTML `<p>`) bị rò rỉ vào báo cáo.

**`docx-skill`** được xây dựng để giải quyết triệt để tất cả các vấn đề trên thông qua bộ công cụ Python can thiệp trực tiếp vào OpenXML và quy trình kiểm định tự động 16 tiêu chí trước khi bàn giao.

---

## 2. Cụm Quy Tắc Kỹ Thuật Cốt Lõi

Bộ công cụ tuân thủ nghiêm ngặt 8 quy chuẩn kỹ thuật:

1. **Dọn dẹp XML Gốc (Body XML Purging):** Can thiệp trực tiếp cây XML `w:body`, xóa sạch toàn bộ các phần tử con ngoại trừ `sectPr` để triệt tiêu các thẻ cache `<w:sdt>`.
2. **Căn lề Biểu đồ Matplotlib (Clipping Prevention):** Render hình ảnh chuẩn kích thước vùng in (6.2 inches), áp dụng `bbox_inches='tight'`, `pad_inches=0.3` và `pad=15` để biểu đồ sắc nét 300 DPI, không bao giờ bị cắt tiêu đề.
3. **Bố trí Biểu đồ Theo Mục (Chart Isolation):** Đặt Biểu đồ phân bổ rủi ro Máy tính xách tay chuẩn xác tại **Mục 2.1** và Web Server tại **Mục 2.2**.
4. **Việt hóa 100% Severity & Lọc Nhiễu:** Loại bỏ hoàn toàn các tin báo `INFORMATIONAL` / `INFO`. Việt hóa 100% cấp độ rủi ro:
   - `CRITICAL` $\rightarrow$ **NGHIÊM TRỌNG** (Đỏ rực `#FF0000`)
   - `HIGH` $\rightarrow$ **CAO** (Đỏ đậm `#C00000`)
   - `MEDIUM` $\rightarrow$ **TRUNG BÌNH** (Cam `#ED7D31`)
   - `LOW` $\rightarrow$ **THẤP** (Xanh dương `#4472C4`)
5. **Trình bày Bằng chứng Khung Bảng (Callout Box):** Bằng chứng được đóng gói gọn gàng trong Bảng 1x1 tô nền `#F9F9F9`, viết bằng Tiếng Việt súc tích, sạch thẻ HTML thô.
6. **Kiểm soát Phân trang Bảng (`cantSplit` & `tblHeader`):** Gán thẻ XML `<w:cantSplit/>` cho 100% các hàng Bảng và `<w:tblHeader/>` cho hàng tiêu đề Bảng để tự động lặp lại khi qua trang mới.
7. **Chống Tiêu đề Mồ côi (`keep_with_next`):** Gán `keep_with_next = True` cho 100% Heading 1-3.
8. **Mục lục Kép (Dual TOC):** Kết hợp Bảng Mục lục phân cấp tĩnh 2 cột và mã Word Field tự động (`TOC \o "1-3" \h \z \u`).

---

## 3. Nguyên Tắc Bắt Buộc: Phản Biện & Đối Soát 3 Chiều

Mọi AI Agent khi kích hoạt **`docx-skill`** BẮT BUỘC phải thực thi quy trình:
- **Phản biện Subagent (Subagent Debate Protocol):** Gọi các subagent chuyên trách để mổ xẻ các trường hợp biên (edge cases), kiểm tra trạng thái lỗi (failure state) và phản biện các đề xuất trước khi chốt phương án.
- **Đối soát 3 chiều (Triple Cross-Check):** Kiểm tra đối soát dữ liệu 1:1 giữa:
  1. File kết quả rà quét thô (`runs/run_.../output/*.csv`).
  2. Kho tri thức lưu trữ bền vững (`docx_analysis_tools/full_vulnerability_knowledge_base.json`).
  3. Mẫu báo cáo tiêu chuẩn (`MAU REPORT.docx`).

---

## 4. Cấu Trúc Thư Mục

```text
docx-skill/
├── SKILL.md                                  # File hướng dẫn Skill cho AI Agent
├── README.md                                 # File tài liệu hướng dẫn chuẩn GitHub Markdown
└── docx_analysis_tools/                      # Thư mục công cụ Python thực thi
    ├── analyze_docx_template.py              # Script giải phẫu OpenXML file template DOCX
    ├── persist_knowledge_base.py             # Script trích xuất & bền vững hóa dữ liệu JSON
    ├── build_perfection_report.py            # Script khởi tạo Báo cáo DOCX hoàn hảo
    └── validate_report_perfection.py         # Bộ kiểm định tự động 16 tiêu chí chất lượng
```

---

## 5. Hướng Dẫn Cài Đặt & Sử Dụng

### Yêu cầu hệ thống
- Python >= 3.10
- Thư viện cần thiết: `python-docx`, `pandas`, `matplotlib`, `lxml`

### Cài đặt môi trường
```bash
# Clone repository hoặc copy thư mục vào dự án
git clone https://github.com/your-org/docx-skill.git

# Cài đặt các thư viện phụ thuộc
pip install python-docx pandas matplotlib lxml
```

---

## 6. Quy Trình Thực Thi 4 Giai Đoạn

### Giai đoạn 1: Phân tích & Giải phẫu Template (Tùy chọn cho Mẫu mới)
Giúp bóc tách 100% thuộc tính lề trang, font chữ, mã màu, bảng biểu từ file template `.docx`:
```bash
python3 docx_analysis_tools/analyze_docx_template.py MAU\ REPORT.docx
```

### Giai đoạn 2: Bền Vững Hóa Dữ Liệu Rà Quét
Trích xuất dữ liệu rà quét thô và đóng gói thành Kho tri thức JSON cố định:
```bash
python3 docx_analysis_tools/persist_knowledge_base.py
```

### Giai đoạn 3: Khởi Tạo Báo Cáo An Toàn Thông Tin
Tạo báo cáo DOCX hoàn chỉnh áp dụng toàn bộ quy tắc kỹ thuật:
```bash
python3 docx_analysis_tools/build_perfection_report.py
```

### Giai đoạn 4: Kiểm Định Tự Động 16 Tiêu Chí
Chạy bộ kiểm định chất lượng trước khi bàn giao:
```bash
python3 docx_analysis_tools/validate_report_perfection.py Bao_Cao_An_Toan_Thong_Tin_2026.docx
```

---

## 7. Bộ Kiểm Định Tự Động 16 Tiêu Chí (16 Assertions)

Khi chạy `validate_report_perfection.py`, bộ kiểm định sẽ quét và xác nhận 16 khẳng định chất lượng:

| STT | Tiêu Chí Kiểm Định (Assertion) | Trạng Thái Yêu Cầu |
| :-: | :--- | :-: |
| 1 | Dọn dẹp thẻ ẩn `<w:sdt>` trong `w:body` | **PASSED (0 lỗi)** |
| 2 | Loại bỏ 100% nhãn severity Tiếng Anh thô | **PASSED (0 lỗi)** |
| 3 | Loại bỏ 100% lỗ hổng cấp `INFORMATIONAL / INFO` | **PASSED (0 lỗi)** |
| 4 | Loại bỏ 100% thẻ mã HTML thô (`<p>`, `<b>`,...) | **PASSED (0 lỗi)** |
| 5 | Loại bỏ 100% chữ nháp `(Mock)`, `TODO`, `FIXME` | **PASSED (0 lỗi)** |
| 6 | Font chữ đồng nhất 100% `Times New Roman` | **PASSED (0 lỗi)** |
| 7 | Đúng số lượng khung Bằng chứng 1x1 (Tô nền `#F9F9F9`) | **PASSED (35/35 boxes)** |
| 8 | Nhúng đủ 2 Biểu đồ hình vẽ (`w:drawing`) tại Mục 2.1 & 2.2 | **PASSED (2/2 charts)** |
| 9 | Gán thẻ chống vỡ ô `<w:cantSplit/>` trên mọi hàng Bảng | **PASSED (100% rows)** |
| 10 | Gán thẻ chống tiêu đề mồ côi `keep_with_next` trên Heading 1-3 | **PASSED (100% headings)** |
| 11 | Gán thẻ lặp tiêu đề bảng `<w:tblHeader/>` cho hàng 0 | **PASSED (100% tables)** |
| 12 | Có đủ Mục lục Kép (Bảng Mục lục & mã Word Field) | **PASSED** |
| 13 | Việt hóa 100% nhãn rủi ro (NGHIÊM TRỌNG, CAO, TRUNG BÌNH, THẤP) | **PASSED** |
| 14 | Khoảng cách dòng và giãn đoạn tiêu chuẩn | **PASSED** |
| 15 | Tất cả các Bảng biểu được căn giữa (`WD_TABLE_ALIGNMENT.CENTER`) | **PASSED** |
| 16 | Đầy đủ 8 Mục nội dung bắt buộc của báo cáo | **PASSED** |

---

## 8. Giấy Phép & Tác Giả

- **License:** Phát hành dưới giấy phép [MIT License](LICENSE).
- **Author:** Antigravity AI Agent Team - Google DeepMind.
- **Repository:** `tool-scan-pipeline-security`

---
*Chúc bạn khởi tạo thành công các báo cáo An toàn thông tin hoàn hảo!* 🚀
