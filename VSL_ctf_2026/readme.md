## Data Stolen

<img width="606" height="516" alt="image" src="https://github.com/user-attachments/assets/9de94487-22cb-4fa6-9b7b-2a79550c2b54" />

Link đề: https://drive.google.com/file/d/11Oa3sgSQ45uP-AhE51E0PfpBbXXq_G4S/view?usp=sharing

Mô tả chỉ cho ta biết được là dữ liệu đã bị đánh cắp một cách trái phép, và chúng ta cần tìm ra được cách mà hacker đã tuồng dữ liệu ra bằng cách nào.

Theo thói quen thì mình vẫn sẽ mở `statistic protocol` lên để check xem các giao thức được dùng nhiều nhất, thì mình để ý thấy có giao thức DNS, mình nghĩ có thể kẻ tấn công tuồn dữ liệu bằng kĩ thuật DNS tunneling: giấu dữ liệu bên trong các truy vấn DNS.

<img width="1530" height="851" alt="image" src="https://github.com/user-attachments/assets/9ed6ffca-7472-4dce-aaed-58a36f55a4bf" />

Em thử filter `dns` rồi tìm vài gói tin, thì thấy truy vấn dns này có tên miền khá lạ với một chuỗi ngắn kèm với `.vsl.com`, nên em thử filter theo cấu trúc này thử.

<img width="1883" height="727" alt="image" src="https://github.com/user-attachments/assets/a546c706-1100-4962-bd4f-217917b701ff" />

Ở đây thì em tìm được 3 truy vấn đến 3 tên miền khả nghi, nên em trích xuất thử phần đầu của 3 tên miền này ra và giải mã thử, vì em thấy nó khá giống mã hóa theo base64. em trích xuất bằng lệnh tshark: `tshark -r challenege.pcapng -Y 'dns.qry.name contains "vsl.com" && dns.flags.response == 0' -T fields -e dns.qry.name`

<img width="1886" height="444" alt="image" src="https://github.com/user-attachments/assets/0d1b6560-ca48-4dae-8eda-60ea304e82d5" />

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/VSL_ctf_2026/Data stole]
└─$ tshark -r challenge.pcapng -Y 'dns.qry.name contains "vsl.com" && dns.flags.response == 0' -T fields -e dns.qry.name
VlNMe24z.vsl.com
dHcwcmtf.vsl.com
dHVubjM=.vsl.com
```
Em cắt ra rồi trích xuất lên cyberchef thì được:

<img width="1532" height="565" alt="image" src="https://github.com/user-attachments/assets/4544213b-e347-4965-b697-18ec0738a49d" />

À vậy đây ra là phần đầu của flags, nó sử dụng kĩ thuật `dns tunneling` để giấu một phần dữ liệu bên trong tên miền được truy vấn tới. Giờ em sẽ tiếp tục tìm tiếp, có thể họ vẫn sẽ sử dụng kĩ thuật này. Em dựa vào địa chỉ ip mà nạn nhân bị tuồng dữ liệu ra địa chỉ ip bên ngoài là `ip.src == 172.26.31.148 && ip.dst == 10.23.11.27`. Sau 1 lúc tìm kiếm tiếp thì em thấy địa chỉ ip `172.26.31.148` thực hiện tạo kết nối tcp với ip `10.23.11.27` để thực hiện request POST dữ liệu ra cho ip của kẻ nhận dữ liệu `10.23.11.27`

<img width="1873" height="620" alt="image" src="https://github.com/user-attachments/assets/33dbb074-489b-4e64-9fb2-64306d13115b" />

Ở đây em thử follow theo gói tin mà nó thực hiện POST dữ liệu ra cho ip nhận dữ liệu, thì em thấy có 1 chuỗi nhỏ ở đây.

<img width="1287" height="545" alt="image" src="https://github.com/user-attachments/assets/aaaf3f31-0bf3-496c-b472-51726f657f5b" />

Em thực hiện follow theo 2 gói tin có request POST dữ liệu tiếp thì cũng có 2 chuỗi nhỏ khác.

<img width="1272" height="1031" alt="image" src="https://github.com/user-attachments/assets/9308c508-8126-44dd-8073-93cf7808db82" />

<img width="1281" height="829" alt="image" src="https://github.com/user-attachments/assets/2d30eac5-a433-4a9c-93dd-19259cc705d9" />

Em đem nó lên cyberchef nốt với phần đầu mà em lấy được từ kĩ thuật `dns tunneling`, thì em có 1 chuỗi hoàn chỉnh:

<img width="1532" height="615" alt="image" src="https://github.com/user-attachments/assets/c2778b5e-2136-4f56-af6d-6adf421a13be" />

**flags: VSL{n3tw0rk_tunn34tt4ck_t3chn1qu3}**
