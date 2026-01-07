# 🛡️ Task 4: Automated Vulnerability Management Pipeline (V10 Ultimate)

> **"From Detection to Verification: A Closed-Loop Security Pipeline"**

## 📖 1. Giới thiệu (Overview)

Dự án này là một hệ thống tự động hóa quy trình quản lý lỗ hổng bảo mật (Vulnerability Management), được thiết kế để giải quyết bài toán "Quá tải cảnh báo" (Alert Fatigue) trong SecOps.

Hệ thống tích hợp đa nguồn quét (ZAP, OpenVAS), chuẩn hóa dữ liệu, ánh xạ vào khung **MITRE ATT&CK**, tính điểm rủi ro thông minh và đặc biệt sử dụng **AI Agent (Python-based)** để tự động xác thực lại lỗ hổng, loại bỏ False Positives.

### 🚀 Tính năng nổi bật (Key Features)
- **Hybrid Scanning:** Hợp nhất dữ liệu từ **OWASP ZAP** (Web App) và **OpenVAS** (Infrastructure).
- **MITRE ATT&CK Integration:** Ánh xạ lỗ hổng vào Tactic/Technique (VD: *T1189 - Drive-by Compromise*).
- **Smart Risk Scoring:** Tính điểm ưu tiên (P1-P4) dựa trên ngữ cảnh và trọng số tùy chỉnh.
- **🤖 Auto-Verification Agent (MacGyver Mode):**
  - Tự động phát hiện công cụ môi trường (nmap, curl).
  - Tự động chuyển sang dùng thư viện Python (`socket`, `requests`) nếu thiếu tool CLI.
  - Xác thực thực tế (Active Probing) để khẳng định lỗ hổng là CÓ THẬT.
- **Professional Reporting:** Xuất báo cáo Excel với dashboard, màu sắc trực quan.

---

## 🏗️ 2. Kiến trúc hệ thống (Architecture)

```mermaid
graph TD
    subgraph Scanners
        ZAP[OWASP ZAP Docker]
        OPV[OpenVAS / Greenbone Docker]
    end
    
    subgraph Core Pipeline
        P1[Parsers & Normalization]
        P2[Merge & Deduplication]
        P3[MITRE ATT&CK Mapping]
        P4[Risk Calculation]
    end
    
    subgraph Verification Agent
        AG[🤖 AI Agent / Auto-Verifier]
    end

    ZAP -->|JSON/HTML Report| P1
    OPV -->|XML Report| P1
    P1 --> P2 --> P3 --> P4
    P4 -->|Enriched Data| AG
    AG -->|Self-Correction & Probe| AG
    AG -->|Final Verified Report| XLS[Excel Report .xlsx]
