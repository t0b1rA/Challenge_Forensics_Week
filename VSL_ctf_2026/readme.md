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

**part1: VSL{n3tw0rk_tunn3**

À vậy đây ra là phần đầu của flags, nó sử dụng kĩ thuật `dns tunneling` để giấu một phần dữ liệu bên trong tên miền được truy vấn tới. Giờ em sẽ tiếp tục tìm tiếp, có thể họ vẫn sẽ sử dụng kĩ thuật này. Em dựa vào địa chỉ ip mà nạn nhân bị tuồng dữ liệu ra địa chỉ ip bên ngoài là `ip.src == 172.26.31.148 && ip.dst == 10.23.11.27`. Em thấy bên trong mục `statistic protocol` vẫn còn 1 giao thức `icmp`, có thể là kẻ tấn công sẽ sử dụng kĩ thuật icmp exfiltration, để tuồng dữ liệu ra ngoài qua phần lenght dư ra trong dữ liệu thực tế của mỗi gói tin khi ping từ ip `172.26.31.148` tới ip `10.23.11.27`.

<img width="1909" height="417" alt="image" src="https://github.com/user-attachments/assets/327e8cda-98d6-4ad8-86f4-afde3823da41" />

Đây là kết quả khi em nghi ngờ và filter theo icmp, em thấy bên trong các gói tin icmp có các dữ liệu lạ, em nghĩ đây là kĩ thuật `icmp tunneling` kẻ tấn công cố tình chèn vào đó các dữ liệu đã bị đánh cắp và tuồng ra ngoài thực hiện hành vi icmp exfiltration.

Để lấy các dữ liệu bị đóng gói bên trong ra em dùng lệnh tshark `tshark -r challenge.pcapng -Y 'icmp.type == 8' -T fields -e data.data`.

<img width="1915" height="901" alt="image" src="https://github.com/user-attachments/assets/37845cec-f195-4cbb-8e76-31b91f79d6d4" />

Sau đó em thấy các mảnh base64 bị lặp lại và cách nhau từ các kí tự rác, thì em xóa đi các kí tự lặp lại và rác và ghép những mảnh base64 lại với nhau thì được:

<img width="1512" height="827" alt="image" src="https://github.com/user-attachments/assets/f650f159-350a-429f-8eee-c0cd1f43e462" />

Việc mà trong phần em thu được có các bytes rác, là do trong quá trình exfil dữ liệu ra bằng icmp, thì attacker cũng thực hiện chèn thêm các gói tin rác ở giữa các gói tin tuồn dữ liệu ra, nên mới xảy ra có bytes rác bên trong mục dữ liệu, giờ xóa đi các bytes rác, mảnh base64 lặp lại, và ghép các mảnh base64 lại với nhau để thu được dữ liệu intend.

<img width="1509" height="897" alt="image" src="https://github.com/user-attachments/assets/3a72af7b-8e87-4145-965d-84ec80d61828" />

**part2: l1ng_15_c0mm0n_**

Sau 1 lúc tìm kiếm tiếp thì em thấy địa chỉ ip `172.26.31.148` thực hiện tạo kết nối tcp với ip `10.23.11.27` để thực hiện request POST dữ liệu ra cho ip của kẻ nhận dữ liệu `10.23.11.27`

<img width="1873" height="620" alt="image" src="https://github.com/user-attachments/assets/33dbb074-489b-4e64-9fb2-64306d13115b" />

Ở đây em thử follow theo gói tin mà nó thực hiện POST dữ liệu ra cho ip nhận dữ liệu, thì em thấy có 1 chuỗi nhỏ ở đây.

<img width="1287" height="545" alt="image" src="https://github.com/user-attachments/assets/aaaf3f31-0bf3-496c-b472-51726f657f5b" />

Em thực hiện follow theo 2 gói tin có request POST dữ liệu tiếp thì cũng có 2 chuỗi nhỏ khác.

<img width="1272" height="1031" alt="image" src="https://github.com/user-attachments/assets/9308c508-8126-44dd-8073-93cf7808db82" />

<img width="1281" height="829" alt="image" src="https://github.com/user-attachments/assets/2d30eac5-a433-4a9c-93dd-19259cc705d9" />

**part3: 4tt4ck_t3chn1qu3}**

Em đem nó lên cyberchef nốt với phần đầu mà em lấy được từ kĩ thuật `dns tunneling`, kĩ thuật `icmp tunneling` thì em có được phần hoàn chỉnh của dữ liệu được tuồn ra bài này - flags hoàn chỉnh: 

<img width="1498" height="903" alt="image" src="https://github.com/user-attachments/assets/ae89f12f-e93e-426a-9286-94924d74df22" />

**flags: VSL{n3tw0rk_tunn3l1ng_15_c0mm0n_4tt4ck_t3chn1qu3}**
