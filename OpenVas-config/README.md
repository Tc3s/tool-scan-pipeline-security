
# Bộ cấu hình OpenVAS VA theo nhóm tài sản

Bộ này được dựng từ file export `Full and fast`
Mục tiêu là tạo bốn profile có thể import, giữ phạm vi phát hiện CVE qua HTTP của OpenVAS và giảm tải có chủ đích cho thiết bị mạng, thiết bị bảo mật.

Đây là baseline vận hành, không phải cấu hình đúng cho mọi hệ thống. Phải pilot
trên thiết bị đại diện và điều chỉnh port list, credential, alive test,
`max_hosts` và `max_checks` theo môi trường thực tế.

## Thành phần

```text
OpenVas-config/
├── README.md
├── scan-configs/
│   ├── va-applications.xml
│   ├── va-network-devices.xml
│   ├── va-security-devices.xml
│   └── va-workstations-servers.xml
└── port-lists/
    ├── portlist-applications.xml
    ├── portlist-applications.range.txt
    ├── portlist-full-tcp-udp.xml
    ├── portlist-full-tcp-udp.range.txt
    ├── portlist-network-devices.xml
    ├── portlist-network-devices.range.txt
    ├── portlist-security-devices.xml
    ├── portlist-security-devices.range.txt
    ├── portlist-workstations-servers.xml
    └── portlist-workstations-servers.range.txt
```

Các file `.xml` trong `scan-configs/` và `port-lists/` dùng cấu trúc response
export của Greenbone. Các file `.range.txt` là phương án dự phòng để tạo Port
List thủ công nếu phiên bản GSA không nhận XML export từ phiên bản khác.

## Nội dung bốn Scan Config

| Scan Config | Family | NVT theo snapshot | Nmap wrapper | Services parallel | Request delay |
| --- | ---: | ---: | --- | ---: | ---: |
| Workstations and Servers | 46 | 177.116 | Normal | 4 | 25 ms |
| Network Devices | 21 | 25.023 | Polite | 2 | 200 ms |
| Security Devices | 26 | 26.498 | Polite | 2 | 200 ms |
| Applications | 19 | 25.600 | Normal | 4 | 50 ms |

Số NVT chỉ phản ánh feed snapshot của file nguồn. Sau khi cập nhật Greenbone
Community Feed, số lượng có thể thay đổi mà không phải lỗi.

Thiết lập chung:

- `safe_checks=1`
- `optimize_test=1`
- `auto_enable_dependencies=1`
- `expand_vhosts=1`
- `Disable brute force checks=yes`
- `Disable default account checks=yes`
- `Default Accounts`, `Brute force attacks` và `Denial of Service` không nằm
  trong baseline.
- Một số NVT default-credential/brute-force active nằm trong family khác
  (`CISCO`, `Databases`, `Web application abuses`) được exclude bằng selector
  OID riêng.
- Ping Host `nmap timing policy=Normal` cho Applications và
  Workstations/Servers; `Polite` cho Network/Security Devices.
- Hai Nmap port-scanner NVT từ `Full and fast` được giữ; hai NVT bị loại trong
  file nguồn tiếp tục bị loại.

Nếu cần default credential hoặc brute force có phê duyệt, hãy tạo một Scan
Config riêng và chạy trong maintenance window. Không bật lại trong bốn baseline
này.

### NVT denylist tích hợp

Các OID dưới đây được trích từ Greenbone DB bằng read-only query trên bảng
`nvts`, lọc nhóm `category=4` và tên có dấu hiệu default-credential/brute-force
active nằm ngoài ba family đã loại. Chúng được tích hợp vào XML bằng
`nvt_selector include=0 type=2`, tức là vẫn đúng schema import của Greenbone.

| Nhóm | Số OID exclude thêm | Ghi chú |
| --- | ---: | --- |
| Applications | 8 | `Databases` và `Web application abuses` |
| Network Devices | 14 | `CISCO` và `Web application abuses` |
| Security Devices | 14 | `CISCO` và `Web application abuses` |
| Workstations/Servers | 8 | `Databases` và `Web application abuses` |

Không nhúng catalog NVT chi tiết vào Scan Config XML. Các trường như OID, tên
NVT, CVE, QoD, CVSS, EPSS, tag và solution thuộc sidecar inventory/report; nhét
tùy ý vào XML có thể làm GSA/GVMD reject import hoặc silently ignore dữ liệu.

### Workstations and Servers

Dùng cho Windows, Linux, Unix, macOS, hypervisor và server workload.

- Giữ toàn bộ OS Local Security Checks phù hợp với feed nguồn.
- Giữ `SSL and TLS`, `Web Servers` và `Web application abuses`.
- Loại `Denial of Service`, `Brute force attacks`, `Default Accounts` và các
  OID default-credential/brute-force active ngoài family đó.
- Nmap wrapper dùng `Normal`, service parallelism là 4, request delay là 25 ms.
- File search authenticated được siết lại: không descend filesystem khác, tắt
  WMI file search và giảm depth từ 12 xuống 8.
- Muốn đánh giá patch/package đáng tin cậy phải gắn SSH, SMB hoặc ESXi
  credential thích hợp vào Target.

### Network Devices

Dùng cho router, switch, wireless controller và hạ tầng mạng tương tự.

- Giữ các family CISCO, Huawei và JunOS có trong feed snapshot.
- Giữ `SSL and TLS`, `Web Servers` và `Web application abuses` trong cùng một
  Task. Không thay chúng bằng ZAP.
- Loại các OID default-credential active trong `CISCO` và
  `Web application abuses`.
- Nmap NASL wrapper dùng `Polite`; Ping Host nmap timing cũng dùng `Polite`.
- Preference `Services: Number of connections done in parallel` là 2. Đây chỉ
  là giới hạn của NVT `Services`, không phải concurrency của toàn bộ Task.
- Task-level khởi đầu cho thiết bị mong manh: `max_hosts=1`, `max_checks=2`.

### Security Devices

Dùng cho firewall, WAF, VPN gateway, IDS/IPS, load balancer và security gateway.

- Bao gồm các family mạng và các family F5, FortiOS, Palo Alto, Policy và
  Privilege escalation có trong feed snapshot.
- Giữ `SSL and TLS`, `Web Servers` và `Web application abuses` trong cùng một
  Task để discovery và KB được dùng trong cùng scan lifecycle.
- Loại các OID default-credential active trong `CISCO` và
  `Web application abuses`.
- Nmap NASL wrapper là `Polite`; Services parallel là 2; request delay là
  200 ms.
- Không chạy thêm Scan Config Applications lên cùng thiết bị như một overlay
  mặc định. Việc đó tạo thêm một Task độc lập và lặp lại discovery.
- Task-level khởi đầu cho thiết bị mong manh: `max_hosts=1`, `max_checks=2`.

### Applications

Dùng cho web application, API, database, middleware và application service.

- Bao gồm product/service detection, database, web, TLS và remote CVE checks.
- Không bao gồm OS Local Security Checks, DoS, brute force, default-account
  checks hoặc các OID default-credential active ngoài family đó.
- Nmap NASL wrapper là `Normal`; Services parallel là 4; request delay là
  50 ms.
- Không thay thế authenticated host scan cho server bên dưới.
- Không thay thế ZAP authenticated DAST. OpenVAS kiểm tra product/CVE qua HTTP;
  ZAP bổ sung crawl, input fuzzing, session và application behavior.

## Port List

Port list mặc định theo role là baseline cân bằng giữa coverage và tải. Chúng
quét TCP `1-1024`, cộng các port cao phổ biến theo vai trò và một tập UDP nhỏ.
Chúng không thể biết mọi port tùy chỉnh của môi trường bạn.

| Port List | TCP | UDP | Dùng với |
| --- | ---: | ---: | --- |
| Workstations and Servers - Baseline | 1.059 | 15 | Workstations/Servers |
| Network Devices - Management Baseline | 1.041 | 16 | Network Devices |
| Security Devices - Management and VPN Baseline | 1.039 | 15 | Security Devices |
| Applications - Common Services Baseline | 1.068 | 7 | Applications |
| Full TCP and UDP - Optional Approved Coverage | 65.535 | 65.535 | Maintenance window / approved deep coverage |

Trước production, đối chiếu CMDB, firewall rules, cấu hình vendor và tài liệu
ứng dụng. Phải bổ sung mọi management/application port thực tế, đặc biệt các
panel chạy trên port tùy chỉnh. Port không có trong Target Port List sẽ không
được port scanner kiểm tra.

Đối với đợt kiểm kê exposure rộng hoặc khi cần giảm rủi ro bỏ sót port custom,
có thể dùng `portlist-full-tcp-udp.xml`. Đây là port list optional, không phải
baseline production. Full TCP/UDP sẽ làm scan lâu hơn, tạo nhiều timeout/log
hơn và có thể gây áp lực lên management plane của network/security appliance.
Chỉ dùng khi có approval, maintenance window, target batch nhỏ, `max_hosts` và
`max_checks` thấp.

## Import

`compose.yml` không tự import bộ cấu hình này. Các file XML phải được import
thủ công qua GSA/GMP sau khi Greenbone stack đã chạy ổn định.

1. Chờ scanner, GVMD data và Greenbone feed đồng bộ hoàn tất.
2. Import Port List trước trong **Configuration > Port Lists**.
3. Import Scan Config trong **Configuration > Scan Configs**.
4. Nếu Port List XML bị từ chối do khác phiên bản GMP/GSA, tạo Port List mới và
   dán nguyên chuỗi trong file `.range.txt` tương ứng vào trường Port Ranges.
5. Scan Config XML không bind Port List. Port List nằm ở Target; phải chọn đúng
   port list khi tạo Target.
6. Nếu trong GSA đã có `VA - ...` từ bản cũ, hãy xóa/rename bản cũ hoặc import
   bản mới với tên khác rồi cập nhật Task. Không nhìn tên config để kết luận
   nội dung đã mới.
7. Không import lặp lại cùng UUID. Nếu cần một biến thể, clone config trong GSA
   rồi đổi tên và preference trên bản clone.

Mapping object import:

| Role | Scan Config XML | Port List XML |
| --- | --- | --- |
| Applications | `scan-configs/va-applications.xml` | `port-lists/portlist-applications.xml` |
| Network Devices | `scan-configs/va-network-devices.xml` | `port-lists/portlist-network-devices.xml` |
| Security Devices | `scan-configs/va-security-devices.xml` | `port-lists/portlist-security-devices.xml` |
| Workstations/Servers | `scan-configs/va-workstations-servers.xml` | `port-lists/portlist-workstations-servers.xml` |
| Approved full coverage | Any approved Scan Config | `port-lists/portlist-full-tcp-udp.xml` |

## Tạo Target và Task

1. Phân loại asset vào đúng nhóm; không đoán role chỉ từ địa chỉ IP.
2. Tạo Target với IP/FQDN, Port List tương ứng và credential được phê duyệt.
3. Thêm mọi hostname/vhost của web application. Quét IP đơn thuần có thể bỏ sót
   virtual host và route phụ thuộc Host header.
4. Chọn Alive Test phù hợp. Nếu ICMP bị chặn, dùng TCP service ping hoặc phương
   án đã pilot; không tùy tiện dùng Consider Alive cho dải mạng lớn.
5. Tạo một Task với đúng một Scan Config cho mỗi nhóm thiết bị.
6. Chạy pilot trên một tài sản đại diện trước khi mở rộng phạm vi.

Giá trị khởi đầu để pilot, không phải mặc định bắt buộc:

| Nhóm | `max_hosts` | `max_checks` |
| --- | ---: | ---: |
| Workstations/Servers | 3-5 | 4 |
| Network Devices | 1 | 2 |
| Security Devices | 1 | 2 |
| Applications | 1-2 | 4 |

`max_hosts` và `max_checks` nằm trong Task, không nằm trong Scan Config XML.
Giảm tiếp nếu thấy CPU/memory tăng, packet loss, session-table pressure hoặc
management plane phản hồi chậm.

## Credential

- Windows: SMB credential dành cho assessment; dùng quyền tối thiểu đáp ứng
  Local Security Checks.
- Linux/Unix: SSH credential; dùng elevated credential riêng nếu chính sách và
  Greenbone version hỗ trợ.
- Network/Security: ưu tiên SNMPv3 và SSH read-only/assessment account do
  vendor hỗ trợ. Không dùng credential sản xuất dùng chung nếu có thể tránh.
- Application: database/application credential chỉ khi VT tương ứng hỗ trợ.
  Credential, cookie và session của ZAP được quản lý riêng, giới hạn đúng scope.
- Không đặt mật khẩu, cookie hoặc token trực tiếp trong các XML của bộ này.

## Luồng OpenVAS và ZAP

1. Chạy OpenVAS bằng profile theo role.
2. Xác thực các HTTP(S) endpoint và hostname tìm được.
3. Chỉ đưa endpoint web đã được phê duyệt sang ZAP.
4. Chạy ZAP baseline/passive trước, sau đó authenticated active scan theo policy.
5. Giới hạn spider, active rules, user role và logout endpoint để tránh làm hỏng
   dữ liệu hoặc khóa tài khoản.
6. Hợp nhất kết quả rồi để analyst xác minh, loại false positive và theo dõi
   remediation.

ZAP không thay thế các Greenbone VT kiểm tra CVE/firmware qua HTTP. Ngược lại,
OpenVAS Web NVTs cũng không thay thế DAST đã đăng nhập của ZAP.

## Kiểm tra sau import

Với từng Scan Config:

1. Kiểm tra `safe_checks=1`, `optimize_test=1` và
   `auto_enable_dependencies=1`.
2. Kiểm tra `Disable brute force checks=yes` và
   `Disable default account checks=yes`.
3. Kiểm tra không có family `Default Accounts`, `Brute force attacks`,
   `Denial of Service`.
4. Kiểm tra Network/Security có `SSL and TLS`, `Web Servers`,
   `Web application abuses` cùng các family vendor cần thiết.
5. Kiểm tra Nmap wrapper OID `1.3.6.1.4.1.25623.1.0.14259`, preference ID 7:
   Network/Security phải là `Polite`; Workstations/Servers và Applications là
   `Normal`.
6. Kiểm tra selector include có Ping Host OID
   `1.3.6.1.4.1.25623.1.0.100315` và Nmap wrapper OID
   `1.3.6.1.4.1.25623.1.0.14259`.
7. Kiểm tra selector exclude có hai OID gốc `810002`, `810003` và denylist OID
   default-credential/brute-force active theo role.
8. Chạy pilot và so sánh với `Full and fast` không sửa trên cùng target, cùng
   port list, credential, alive test và thời điểm feed gần nhau.
9. Điều tra finding bị thiếu trước khi phê duyệt profile cho production.

Sau mỗi nâng cấp Greenbone lớn hoặc khi feed xuất hiện family mới, rà lại family
selection. Các NVT mới trong family đã chọn được thêm động; family hoàn toàn mới
không tự động được đưa vào bộ này.

## Tham chiếu kỹ thuật

- Greenbone scanning và Task settings:
  https://docs.greenbone.net/GSM-Manual/gos-24.10/en/scanning.html
- Greenbone GMP Port List:
  https://docs.greenbone.net/API/GMP/gmp-22.5.html
- ZAP Active Scan Rules:
  https://www.zaproxy.org/docs/desktop/addons/active-scan-rules/
