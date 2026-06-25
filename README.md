# Windows DFIR — Mô phỏng tấn công, Thu thập chứng cứ & Phân tích Timeline

> Một bài lab DFIR **end-to-end** trên Windows: mô phỏng chuỗi tấn công theo MITRE ATT&CK bằng Atomic Red Team → thu thập chứng cứ forensic bằng CDIR-Collector → điều tra "mù" bằng Hayabusa theo hướng **Alert Triage → Anchor Event → Pivot** → kết thúc bằng một báo cáo DFIR hoàn chỉnh.

**Tools:** Atomic Red Team · CDIR-Collector · Hayabusa · takajo · Registry Explorer (Eric Zimmerman) · Sysmon · ProcDump

---

## Mục tiêu

Tái hiện trọn vẹn vòng đời một cuộc điều tra sự cố trên endpoint Windows, với ranh giới rõ ràng giữa hai vai trò:

- **Red Team** — tạo ra log **thật** từ hành vi tấn công thật (không dùng log mẫu).
- **Blue Team** — phân tích **độc lập**, chỉ biết "máy bị nghi nhiễm", phải tự dựng lại toàn bộ chuỗi tấn công từ log mà **không** tham chiếu kịch bản đã thực thi.

## Lab & Công cụ

| Giai đoạn | Công cụ |
|---|---|
| Mô phỏng tấn công | Atomic Red Team (`Invoke-AtomicTest`) |
| Thu thập chứng cứ | CDIR-Collector v1.3.7 |
| Phân tích timeline | Hayabusa v3.9.0 (Sigma rules) + takajo |
| Đối chiếu bằng chứng *state* | Registry Explorer |
| Giám sát endpoint | Sysmon (Event ID 1 / 11 / 13) |

---

## Phase 1 — Mô phỏng tấn công

Mô phỏng một chuỗi tấn công 4 bước (LOLBins + công cụ bên thứ ba, không có malware tùy chỉnh):

| MITRE | Tactic | Hành vi |
|---|---|---|
| T1059.003 | Execution | PowerShell/cmd thực thi batch script |
| T1087.001 | Discovery | Liệt kê tài khoản (`net user`, `net localgroup`, `cmdkey /list`) |
| T1003.001 | Credential Access | Dump bộ nhớ LSASS bằng ProcDump |
| T1547.001 | Persistence | Ghi Run Key trong Registry |

## Phase 2 — Thu thập chứng cứ (IR)

Dùng CDIR-Collector thu thập theo nguyên tắc **forensic-safe** (chỉ sao chép artifact, dấu chân tối thiểu, không sửa dữ liệu gốc):

- **Windows Event Logs:** Security, System, PowerShell/Operational, Sysmon/Operational
- **Registry hives:** NTUSER.dat, SOFTWARE, SYSTEM, Amcache.hve
- **Metadata:** hostname, timezone, thời điểm thu thập

> ⏱️ Toàn bộ timestamp trong dự án dùng **giờ local UTC+7**, đã đối chiếu với trường `UtcTime` trong log.

## Phase 3 — Phân tích (điểm cốt lõi của dự án)

Thay vì biết trước kịch bản rồi đi xác nhận từng kỹ thuật, điều tra được dẫn dắt **theo mức độ nghiêm trọng của cảnh báo**:

```
Alert Triage  →  Anchor Event  →  Pivot
```

**1. Triage** — Chạy Hayabusa với ruleset hẹp (Core, level high/critical) trên cả 3 máy. Không chọn máy nghi nhiễm theo *số lượng log* (volume ≠ nguy hiểm) mà theo *severity*: toàn bộ **20 alert High** tập trung tại **PC-MINHLNC**.

**2. Anchor** — Trong các alert High, chọn **"LSASS Dump Keyword In CommandLine"** làm điểm neo, vì:
- Hành vi không có cách giải thích lành tính — không admin/user nào dump toàn bộ vùng nhớ `lsass.exe` trong vận hành bình thường.
- Tác động lớn nhất chuỗi — credential bị lộ mở đường cho lateral movement / chiếm domain.
- Đã thực thi **thành công** (ProcDump ghi `58 MB written` + alert `DMP/HDMP File Creation`).

**3. Pivot** — Mở rộng sang ruleset đầy đủ (vì các bước Discovery chỉ ở mức Low, Persistence ở mức Medium — vô hình nếu chỉ quét High), rồi pivot quanh anchor:
- **Ngược thời gian** → tìm thấy Execution + Discovery dẫn tới dump.
- **Xuôi thời gian** → tìm thấy Persistence ngay 5 phút sau; xác nhận bằng *state* trong Registry Explorer (đối chiếu với Sysmon EID 13).
- **User/Host** → `logon-summary` xác định user bị lợi dụng và loại trừ lateral movement.

---

## Kết quả

### Kill chain
| Thời gian (UTC+7) | Sự kiện | MITRE |
|---|---|---|
| 14:32 | Thực thi PowerShell bất thường | T1059.003 |
| 14:35 | Trinh sát tài khoản (`net user`, `hostname`) | T1087.001, T1082 |
| 14:48 | Dump bộ nhớ `lsass.exe` (**anchor**) | T1003.001 |
| 14:53 | Ghi Run Key để duy trì truy cập | T1547.001 |

### IOCs
- **Command line:** `procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp`
- **File artifact:** `C:\Windows\Temp\lsass_dump.dmp` (58 MB)
- **Registry:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team` → `C:\Path\AtomicRedTeam.exe`
- **Logon:** user `Minhlnc`, Source IP `127.0.0.1` (không có Logon Type 3 từ máy khác → **không** lateral movement)

### Kết luận
Hệ thống **đã bị xâm nhập** — mức độ **Critical**. Chuỗi Execution → Discovery → Credential Access → Persistence hoàn tất; LSASS bị dump thành công nên rủi ro leo thang rất cao nếu không cô lập máy ngay.

---

## Một số hình ảnh

> Đặt screenshot vào thư mục `images/` rồi cập nhật đường dẫn bên dưới.

| | |
|---|---|
| ![Hayabusa high alerts](images/hayabusa_high_alerts.png) | ![Registry Explorer persistence](images/registry_explorer_runkey.png) |
| *20 alert High tập trung tại PC-MINHLNC* | *Run Key xác nhận persistence* |

## Báo cáo đầy đủ

Chi tiết từng bước, đầy đủ screenshot và phân tích: 📄 **[BaoCao_DFIR.pdf](./BaoCao_DFIR.pdf)**

---

## Bài học rút ra

- Định vị máy nhiễm bằng **mức độ nghiêm trọng**, không bằng khối lượng log.
- Một anchor event tốt giúp tổ chức điều tra mạch lạc hơn là kiểm tra rời rạc từng kỹ thuật.
- Bằng chứng *state* (Registry hive) và bằng chứng *log* (Sysmon) **đối chiếu** lẫn nhau cho kết luận chắc chắn hơn dùng một nguồn.
- Hiểu thế mạnh riêng của từng nguồn log (Sysmon vs Security vs PowerShell vs System) để biết nguồn nào trả lời câu hỏi nào.
