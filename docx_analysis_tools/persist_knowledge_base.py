#!/usr/bin/env python3
import pandas as pd
import json
import re
import os

def clean_html(text):
    if not isinstance(text, str) or pd.isna(text):
        return ""
    cleaned = re.sub(r'<[^>]+>', '', text)
    cleaned = cleaned.replace('&nbsp;', ' ').replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
    return cleaned.strip()

SEV_MAP = {
    'CRITICAL': 'NGHIÊM TRỌNG',
    'HIGH': 'CAO',
    'MEDIUM': 'TRUNG BÌNH',
    'LOW': 'THẤP'
}

# --- COMPLETE KNOWLEDGE BASE DICTIONARY ---
VI_KNOWLEDGE = {
    "Microsoft Windows SMB/NETBIOS NULL Session Authentication Bypass Vulnerability": {
        "desc_vi": "Dịch vụ chia sẻ tệp tin SMB/NetBIOS cho phép kết nối ẩn danh (Null Session) không cần mật khẩu, giúp kẻ tấn công thu thập danh sách tài khoản người dùng, tên chia sẻ và thông tin cấu hình máy tính trạm.",
        "evidence_vi": "Ghi nhận dịch vụ SMB (Port 445/TCP) phản hồi kết nối ẩn danh thành công tại địa chỉ 192.168.95.135.",
        "solution_vi": "Cấu hình chính sách Windows Group Policy (vô hiệu hóa 'RestrictAnonymous') để ngăn chặn hoàn toàn kết nối ẩn danh qua SMB/NetBIOS."
    },
    "DCE/RPC and MSRPC Services Enumeration Reporting": {
        "desc_vi": "Dịch vụ điều khiển từ xa MSRPC công khai danh sách các tiến trình hệ thống, hỗ trợ kẻ tấn công dò quét các dịch vụ nội bộ đang hoạt động trên máy tính xách tay.",
        "evidence_vi": "Phát hiện dịch vụ MSRPC Endpoint Mapper (Port 135/TCP) trả về danh sách các giao diện RPC hoạt động tại địa chỉ 192.168.95.135.",
        "solution_vi": "Thiết lập Tường lửa Windows (Windows Firewall) hạn chế truy cập cổng 135/TCP từ các mạng không tin cậy."
    },
    "TCP Timestamps Information Disclosure": {
        "desc_vi": "Hệ điều hành phản hồi thông tin thời gian hệ thống (TCP Timestamps) trong các gói tin giao tiếp, giúp kẻ tấn công suy đoán được thời gian hoạt động (Uptime) và lịch sử khởi động lại của máy tính.",
        "evidence_vi": "Ghi nhận gói tin TCP SYN/ACK trả về chứa trường Timestamp phản hồi tại địa chỉ 192.168.95.135.",
        "solution_vi": "Tắt tính năng TCP Timestamps trên hệ điều hành Windows bằng câu lệnh 'netsh int tcp set global timestamps=disabled'."
    },
    "ICMP Timestamp Reply Information Disclosure": {
        "desc_vi": "Giao thức ICMP trả lời yêu cầu thời gian (ICMP Type 13/14), làm rò rỉ thời gian thực của hệ thống máy tính xách tay.",
        "evidence_vi": "Phát hiện máy tính phản hồi gói tin ICMP Timestamp Request tại địa chỉ 192.168.95.135.",
        "solution_vi": "Cấu hình Windows Firewall chặn các gói tin ICMP Yêu cầu Thời gian (ICMP Type 13)."
    },
    "Distributed Ruby (dRuby/DRb) Multiple RCE Vulnerabilities": {
        "desc_vi": "Dịch vụ Distributed Ruby (dRuby) mở cổng điều khiển từ xa mà không yêu cầu xác thực, cho phép kẻ tấn công gửi mã độc Ruby để thực thi lệnh trực tiếp trên máy chủ Web Server.",
        "evidence_vi": "Kết nối thành công dịch vụ dRuby lắng nghe trên máy chủ 192.168.95.138, ghi nhận khả năng gọi hàm và thực thi lệnh hệ thống.",
        "solution_vi": "Cấu hình dRuby chỉ lắng nghe trên giao diện nội bộ (127.0.0.1) hoặc đóng cổng dịch vụ trên Tường lửa mạng."
    },
    "Possible Backdoor: Ingreslock": {
        "desc_vi": "Phát hiện cổng dịch vụ 1524/TCP (Ingreslock) bị cài cắm mã độc Backdoor, cung cấp ngay một Shell điều khiển quyền Root mà không cần nhập mật khẩu.",
        "evidence_vi": "Kết nối trực tiếp cổng 1524/TCP tại địa chỉ 192.168.95.138 nhận được giao diện Root Command Shell.",
        "solution_vi": "Tắt ngay lập tức dịch vụ Ingreslock, cách ly máy chủ để rà soát mã độc và kiểm tra toàn bộ lịch sử tiến trình."
    },
    "rlogin Passwordless Login": {
        "desc_vi": "Dịch vụ rlogin cho phép đăng nhập từ xa quyền Root không cần mật khẩu dựa trên cấu hình tệp tin tin cậy (.rhosts).",
        "evidence_vi": "Đăng nhập thành công vào máy chủ 192.168.95.138 qua giao thức rlogin (Port 513/TCP) không cần xác thực.",
        "solution_vi": "Dừng hoạt động dịch vụ rlogin và chuyển sang sử dụng giao thức SSH bảo mật."
    },
    "vsftpd Compromised Source Packages Backdoor Vulnerability - Active Check": {
        "desc_vi": "Phiên bản vsftpd 2.3.4 cài đặt trên máy chủ chứa lỗ hổng Backdoor công bố, tự động mở cổng 6200/TCP trao quyền Root khi nhận chuỗi ký tự ':)' trong tên đăng nhập.",
        "evidence_vi": "Thử nghiệm gửi chuỗi ký tự đặc biệt tới cổng 21/TCP tại 192.168.95.138 kích hoạt thành công Root Shell trên cổng 6200/TCP.",
        "solution_vi": "Gỡ bỏ phiên bản vsftpd 2.3.4 và nâng cấp lên phiên bản FTP an toàn mới nhất hoặc dùng SFTP."
    },
    "Apache Tomcat AJP RCE Vulnerability (Ghostcat) - Active Check": {
        "desc_vi": "Lỗ hổng Ghostcat (CVE-2020-1938) trong giao thức Tomcat AJP cho phép kẻ tấn công đọc toàn bộ mã nguồn ứng dụng Web và thực thi mã từ xa.",
        "evidence_vi": "Dịch vụ AJP Connector công khai trên cổng 8009/TCP tại 192.168.95.138 không thiết lập thuộc tính xác thực 'requiredSecret'.",
        "solution_vi": "Cập nhật Apache Tomcat lên phiên bản vá lỗi hoặc tắt cổng AJP 8009 nếu không sử dụng."
    },
    "DistCC RCE Vulnerability (CVE-2004-2687)": {
        "desc_vi": "Dịch vụ biên dịch mã từ xa DistCC cho phép gửi các câu lệnh hệ thống tùy ý để thực thi trên máy chủ với quyền hạn của dịch vụ.",
        "evidence_vi": "Kết nối thành công cổng 3632/TCP tại 192.168.95.138 và thực thi câu lệnh kiểm tra danh tính hệ thống.",
        "solution_vi": "Vô hiệu hóa dịch vụ DistCC trên môi trường sản xuất hoặc cài đặt chính sách Tường lửa chỉ cho phép các IP biên dịch tin cậy."
    },
    "TWiki < 4.2.4 Multiple XSS / Command Execution Vulnerabilities": {
        "desc_vi": "Nền tảng TWiki phiên bản cũ chứa lỗ hổng chèn lệnh hệ thống (Command Injection) qua tham số URL, cho phép thực thi mã tùy ý trên Web Server.",
        "evidence_vi": "Phát hiện ứng dụng TWiki phiên bản cũ hoạt động tại 192.168.95.138 chứa các điểm yếu xử lý dữ liệu đầu vào.",
        "solution_vi": "Nâng cấp TWiki lên phiên bản mới nhất hoặc ngắt kết nối ứng dụng nếu không còn sử dụng."
    },
    "The rexec service is running": {
        "desc_vi": "Dịch vụ rexec (Port 512/TCP) truyền tải tên tài khoản và mật khẩu dưới dạng văn bản rõ không mã hóa qua đường truyền mạng.",
        "evidence_vi": "Dịch vụ rexec hoạt động công khai trên cổng 512/TCP tại địa chỉ 192.168.95.138.",
        "solution_vi": "Tắt dịch vụ rexec và thay thế bằng SSH."
    },
    "Operating System (OS) End of Life (EOL) Detection": {
        "desc_vi": "Hệ điều hành máy chủ đã kết thúc vòng đời hỗ trợ (End of Life), không còn nhận được các bản vá lỗi bảo mật từ nhà sản xuất, tạo điều kiện cho kẻ tấn công khai thác các lỗ hổng 0-day.",
        "evidence_vi": "Ghi nhận phiên bản hệ điều hành Linux tại 192.168.95.138 đã hết hạn hỗ trợ chính thức.",
        "solution_vi": "Lập kế hoạch nâng cấp hệ điều hành máy chủ lên phiên bản mới (LTS) còn trong hạn hỗ trợ."
    },
    "rsh Unencrypted Cleartext Login": {
        "desc_vi": "Dịch vụ Remote Shell (rsh) thực hiện xác thực và truyền dữ liệu không mã hóa, dễ bị đánh cắp thông tin tài khoản trên mạng nội bộ.",
        "evidence_vi": "Phát hiện cổng 514/TCP dịch vụ rsh hoạt động tại địa chỉ 192.168.95.138.",
        "solution_vi": "Vô hiệu hóa dịch vụ rsh và chuyển sang giao thức mã hóa SSH."
    },
    "UnrealIRCd Authentication Spoofing Vulnerability": {
        "desc_vi": "Phần mềm máy chủ IRC (UnrealIRCd) chứa lỗ hổng mở cắm cờ cho phép kẻ tấn công giả mạo quyền truy cập và thực thi lệnh hệ thống.",
        "evidence_vi": "Dịch vụ UnrealIRCd lắng nghe trên các cổng IRC tại địa chỉ 192.168.95.138.",
        "solution_vi": "Cập nhật phần mềm UnrealIRCd lên phiên bản an toàn hoặc gỡ bỏ dịch vụ IRC."
    },
    "SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability": {
        "desc_vi": "Lỗ hổng OpenSSL CCS (CVE-2014-0224) cho phép kẻ tấn công đứng giữa (MitM) ép buộc giao thức hạ cấp khóa mã hóa để giải mã thông tin nhạy cảm.",
        "evidence_vi": "Dịch vụ SSL/TLS tại 192.168.95.138 chấp nhận gói tin ChangeCipherSpec kém an toàn trong quá trình bắt tay.",
        "solution_vi": "Cập nhật thư viện OpenSSL trên Web Server lên phiên bản mới nhất."
    },
    "Absence of Anti-CSRF Tokens": {
        "desc_vi": "Các biểu mẫu (Form) xử lý dữ liệu trên website thiếu cờ chống giả mạo yêu cầu (Anti-CSRF Token), dẫn đến nguy cơ người dùng bị lợi dụng thực thi các hành động ngoài ý muốn.",
        "evidence_vi": "Các yêu cầu POST tại ứng dụng Web 192.168.95.138 không chứa mã thông báo ngẫu nhiên Anti-CSRF Token.",
        "solution_vi": "Bổ sung cơ chế sinh và xác thực Anti-CSRF Token cho tất cả các biểu mẫu thay đổi dữ liệu."
    },
    "Application Error Disclosure": {
        "desc_vi": "Website hiển thị chi tiết lỗi kỹ thuật khi gặp sự cố, làm lộ cấu trúc thư mục, phiên bản cơ sở dữ liệu và mã nguồn ứng dụng.",
        "evidence_vi": "Phát hiện trang thông báo lỗi hiển thị chi tiết Stack Trace khi gửi truy vấn bất thường tới 192.168.95.138.",
        "solution_vi": "Cấu hình ứng dụng Web tắt chế độ hiển thị lỗi chi tiết (Debug Mode) và sử dụng trang thông báo lỗi tùy chỉnh (Custom Error Page)."
    },
    "Content Security Policy (CSP) Header Not Set": {
        "desc_vi": "Máy chủ Web chưa cấu hình tiêu đề bảo mật Content-Security-Policy (CSP), làm tăng nguy cơ ứng dụng bị tấn công Chèn kịch bản độc hại (XSS).",
        "evidence_vi": "HTTP Header phản hồi từ máy chủ 192.168.95.138 không chứa tiêu đề Content-Security-Policy.",
        "solution_vi": "Bổ sung tiêu đề Content-Security-Policy trong cấu hình Web Server để kiểm soát nguồn tài nguyên được phép thực thi."
    },
    "Source Code Disclosure - SQL": {
        "desc_vi": "Máy chủ Web để rò rỉ các tệp tin chứa câu truy vấn SQL hoặc mã nguồn ứng dụng cho phép tải về trực tiếp qua đường dẫn Web.",
        "evidence_vi": "Phát hiện tệp tin sao lưu SQL có thể truy cập công khai tại URL thuộc máy chủ 192.168.95.138.",
        "solution_vi": "Xóa bỏ tất cả các tệp tin sao lưu mã nguồn khỏi thư mục root của Web Server và phân quyền truy cập nghiêm ngặt."
    },
    "Vulnerable JS Library": {
        "desc_vi": "Website tích hợp các thư viện JavaScript phiên bản cũ (như jQuery, Bootstrap) đã được cảnh báo chứa các lỗ hổng bảo mật XSS.",
        "evidence_vi": "Phát hiện tệp tin thư viện JavaScript phiên bản cũ đang được liên kết tại 192.168.95.138.",
        "solution_vi": "Nâng cấp các thư viện JavaScript lên phiên bản mới nhất."
    },
    "Multiple Vendors STARTTLS Implementation Plaintext Arbitrary Command Injection Vulnerability": {
        "desc_vi": "Lỗ hổng trong triển khai giao thức STARTTLS cho phép kẻ tấn công chèn các lệnh văn bản rõ trước khi thiết lập mã hóa SSL/TLS.",
        "evidence_vi": "Dịch vụ thư điện tử/SMTP hỗ trợ STARTTLS tại 192.168.95.138 bị ảnh hưởng bởi lỗi chèn lệnh.",
        "solution_vi": "Cập nhật dịch vụ Mail Server lên phiên bản phần mềm vá lỗi STARTTLS."
    },
    "Weak Host Key Algorithm(s) (SSH)": {
        "desc_vi": "Dịch vụ SSH hỗ trợ các thuật toán mã hóa khóa máy chủ cũ kém an toàn (như ssh-dss), dễ bị bẻ khóa.",
        "evidence_vi": "Phát hiện máy chủ SSH tại 192.168.95.138 cho phép đàm phán các thuật toán khóa yếu.",
        "solution_vi": "Cấu hình tệp sshd_config loại bỏ các thuật toán khóa yếu, chỉ cho phép sử dụng RSA 3072-bit trở lên hoặc ED25519."
    },
    "DNS Cache Snooping Vulnerability (UDP) - Active Check": {
        "desc_vi": "Máy chủ DNS cho phép truy vấn bộ nhớ đệm (Cache Snooping), giúp kẻ tấn công thu thập danh sách tên miền vừa được người dùng nội bộ truy cập.",
        "evidence_vi": "Dịch vụ DNS (Port 53/UDP) tại 192.168.95.138 trả về phản hồi truy vấn đệm cho các yêu cầu không thuộc thẩm quyền.",
        "solution_vi": "Cấu hình máy chủ DNS giới hạn quyền truy vấn đệm (Recursion) chỉ dành cho các IP nội bộ được phép."
    },
    "VNC Server Unencrypted Data Transmission": {
        "desc_vi": "Dịch vụ quản trị màn hình từ xa VNC truyền tải hình ảnh và thao tác bàn phím không qua mã hóa, dễ bị nghe lén trên mạng.",
        "evidence_vi": "Máy chủ VNC (Port 5900/TCP) tại 192.168.95.138 hoạt động ở chế độ không bật mã hóa SSL/TLS.",
        "solution_vi": "Cấu hình bật cơ chế mã hóa cho VNC hoặc bọc kết nối VNC qua đường truyền SSH Tunnel."
    },
    "Cleartext Transmission of Sensitive Information via HTTP": {
        "desc_vi": "Website thực hiện truyền tải dữ liệu nhạy cảm (như thông tin đăng nhập) qua giao thức HTTP không mã hóa.",
        "evidence_vi": "Phát hiện biểu mẫu đăng nhập gửi dữ liệu qua kênh HTTP thông thường tại 192.168.95.138.",
        "solution_vi": "Chuyển đổi toàn bộ website sang sử dụng giao thức HTTPS mã hóa và kích hoạt tiêu đề HSTS."
    },
    "FTP Unencrypted Cleartext Login": {
        "desc_vi": "Dịch vụ FTP truyền thông tin tài khoản và mật khẩu dạng văn bản rõ không mã hóa qua mạng.",
        "evidence_vi": "Dịch vụ FTP (Port 21/TCP) tại 192.168.95.138 cho phép đăng nhập qua kênh không mã hóa.",
        "solution_vi": "Ngắt dịch vụ FTP và thay thế bằng giao thức truyền tệp an toàn SFTP."
    },
    "Telnet Unencrypted Cleartext Login": {
        "desc_vi": "Dịch vụ Telnet truyền toàn bộ dữ liệu quản trị không mã hóa, gây nguy cơ rò rỉ tài khoản quản trị.",
        "evidence_vi": "Dịch vụ Telnet (Port 23/TCP) hoạt động mở công khai tại 192.168.95.138.",
        "solution_vi": "Tắt hoàn toàn dịch vụ Telnet và chuyển sang sử dụng SSH."
    },
    "Cookie No HttpOnly Flag": {
        "desc_vi": "Cookie phiên làm việc thiếu thuộc tính bảo vệ HttpOnly, khiến Cookie có thể bị kịch bản độc hại (XSS) truy cập và lấy cắp.",
        "evidence_vi": "Phản hồi Set-Cookie từ ứng dụng Web tại 192.168.95.138 thiếu cờ HttpOnly.",
        "solution_vi": "Bổ sung thuộc tính HttpOnly cho tất cả các Cookie phiên làm việc trong cấu hình ứng dụng Web."
    },
    "In Page Banner Information Leak": {
        "desc_vi": "Máy chủ Web tiết lộ chi tiết tên và phiên bản phần mềm máy chủ trong tiêu đề phản hồi (Server Banner).",
        "evidence_vi": "Phản hồi HTTP Header từ 192.168.95.138 hiển thị chi tiết tên phiên bản Web Server.",
        "solution_vi": "Cấu hình Web Server ẩn thông tin phiên bản (ví dụ set 'ServerTokens Prod' trên Apache hoặc 'server_tokens off' trên Nginx)."
    },
    "Information Disclosure - Debug Error Messages": {
        "desc_vi": "Máy chủ rò rỉ thông tin cấu hình nội bộ qua các thông báo lỗi gỡ lỗi (Debug Error Messages).",
        "evidence_vi": "Phát hiện thông tin cấu hình hệ thống xuất hiện trong các phản hồi lỗi tại 192.168.95.138.",
        "solution_vi": "Tắt chế độ Debug trên môi trường sản xuất và sử dụng trang báo lỗi tiêu chuẩn."
    },
    "Timestamp Disclosure - Unix": {
        "desc_vi": "Ứng dụng Web làm rò rỉ giá trị thời gian hệ thống (Unix Timestamp) trong phản hồi HTTP.",
        "evidence_vi": "Phát hiện chuỗi thời gian Unix Timestamp trong dữ liệu phản hồi từ 192.168.95.138.",
        "solution_vi": "Loại bỏ các trường thời gian hệ thống không cần thiết trong dữ liệu phản hồi công cộng."
    }
}

# --- EXTRACT FULL PERSISTENT KNOWLEDGE BASE FROM RUNS ---
old_df = pd.read_csv('runs/run_20260810_140029/output/vuln_raw.csv')
new_df = pd.read_csv('runs/run_20260810_192535/output/vuln_attack_enriched.csv')

old_df = old_df[~old_df['severity'].astype(str).str.upper().isin(['INFORMATIONAL', 'INFO'])].copy()
new_df = new_df[~new_df['severity'].astype(str).str.upper().isin(['INFORMATIONAL', 'INFO'])].copy()

laptop = old_df[old_df['location'].astype(str).str.contains('192.168.95.135', na=False) | old_df['asset'].astype(str).str.contains('192.168.95.135', na=False)]
web = new_df[new_df['location'].astype(str).str.contains('192.168.95.138', na=False) | new_df['asset'].astype(str).str.contains('192.168.95.138', na=False)]

db = {
    "metadata": {
        "created_at": "2026-08-10",
        "target_laptop": "192.168.95.135",
        "target_webserver": "192.168.95.138",
        "run_baseline": "run_20260810_140029",
        "run_current": "run_20260810_192535",
        "laptop_count": len(laptop),
        "webserver_count": len(web)
    },
    "laptop_findings": [],
    "webserver_findings": []
}

def parse_rows(df, target_name):
    findings_list = []
    for idx, r in df.reset_index().iterrows():
        name = clean_html(str(r.get('finding_name', '')))
        orig_sev = str(r.get('severity', '')).upper()
        sev_vi = SEV_MAP.get(orig_sev, orig_sev)
        
        cve = str(r.get('cve', 'N/A'))
        if pd.isna(cve) or cve in ['nan', '']: cve = str(r.get('cve_list', 'N/A'))
        cvss = str(r.get('cvss', 'N/A'))
        if pd.isna(cvss) or cvss in ['nan', '']: cvss = 'N/A'
        
        loc = clean_html(str(r.get('location', '')))
        raw_desc = clean_html(str(r.get('description', '')))
        raw_ev = clean_html(str(r.get('scanner_evidence', ''))) or clean_html(str(r.get('evidence', '')))
        raw_sol = clean_html(str(r.get('solution', ''))) or clean_html(str(r.get('scanner_solution', '')))
        
        # Get custom Vietnamese lookup
        vi_entry = VI_KNOWLEDGE.get(name, {
            "desc_vi": raw_desc[:250] if len(raw_desc) > 10 else f"Phát hiện điểm yếu bảo mật thuộc dạng {name} trên mục tiêu.",
            "evidence_vi": f"Ghi nhận cấu hình chưa an toàn trên dịch vụ tại địa chỉ mục tiêu: {loc}",
            "solution_vi": "Tiến hành rà soát cấu hình dịch vụ, cập nhật bản vá phần mềm lên phiên bản mới nhất và thiết lập tường lửa hạn chế truy cập."
        })
        
        item = {
            "id": idx + 1,
            "target": target_name,
            "finding_name": name,
            "severity_orig": orig_sev,
            "severity_vi": sev_vi,
            "cve": cve,
            "cvss": cvss,
            "location": loc,
            "raw_description": raw_desc,
            "raw_evidence": raw_ev,
            "raw_solution": raw_sol,
            "clean_description_vi": vi_entry["desc_vi"],
            "clean_evidence_vi": vi_entry["evidence_vi"],
            "clean_solution_vi": vi_entry["solution_vi"]
        }
        findings_list.append(item)
    return findings_list

db["laptop_findings"] = parse_rows(laptop, "Máy tính xách tay Windows 11 (192.168.95.135)")
db["webserver_findings"] = parse_rows(web, "Web Server (192.168.95.138)")

out_path = 'docx_analysis_tools/full_vulnerability_knowledge_base.json'
with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(db, f, ensure_ascii=False, indent=2)

print(f"Successfully saved persistent Knowledge Base to {out_path}")
