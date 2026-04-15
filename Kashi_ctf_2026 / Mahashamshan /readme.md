# Mahashamshan

<img width="598" height="811" alt="Screenshot 2026-04-05 121152" src="https://github.com/user-attachments/assets/8a053841-db0f-4ff3-930f-e4f77fe95629" />

Link challenge: https://drive.google.com/file/d/1qLfENy_pwemxQaUdaIEUgtIZdpovdFoE/view?usp=sharing

Description: Một file pcap đã được trích xuất từ một node bị compromised trong 1 mạng lưới liên lạc ngầm. Đặc vụ thu thập được file này và để lại cho chúng ta 1 vài lời nhắn: `The river does not reveal itself. It only flows` và `Not all fields are what they seem. The fragment offset field hides more that offset`. Cùng với một lời nhắc là trong challenge này có rất nhiều fake flag, chúng ta cần làm cẩn thận.

Ok giờ mình sẽ bắt đầu phân tích file pcap này:

<img width="1519" height="858" alt="image" src="https://github.com/user-attachments/assets/0b8f7974-8d23-4314-9b0c-ba92fcd6c4a3" />

Ở đây khi chúng ta nhìn vào `protocol hierachy` sẽ thấy được các fields thường được dùng để exfil data, ra bên ngoài như `dns, tcp payload và icmp`. Và tất cả những cái này đều là fake flag, nên mình sẽ không di sâu vào nó tránh mất thời gian, và mình chỉ nói tới những fields nó giấu flag.

Đầu tiên mình sẽ đi vào dns trước:

<img width="1892" height="352" alt="image" src="https://github.com/user-attachments/assets/cd65d2c0-3f1e-4876-a67b-7324be973296" />

Mình sẽ dùng tshark để lọc ra fields `dns.qry.name` và decode ra:

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/kashi_CTF/Mahashamshan]
└─$ tshark -r mahashamshan_2.pcap -Y "ip.src == 192.168.7.77 && udp" -T fields -e dns.qry.name | cut -d'.' -f1 | tr -d '\n' | base64 -d

3_c1d}kashiCTF{0_s33_h3rn0th1ng_t                                                                                                                                         

```

Mình sử dụng các lệnh như `cut -d'.' -f1` để thực hiện cắt chuỗi phía sau dấu `.` đầu tiên, sau đó là lệnh `tr -d '\n'` để bỏ đi phần xuống dòng trong các chuỗi khi in ra bằng lệnh tshark, và decode bằng base64 luon.

Khi đó chúng ta có fake flag đầu là **kashiCTF{n0th1ng_t0_s33_h3r3_c1d}**

Tiếp theo mình sẽ đi vào protocol `icmp` và với fields là `data.data`, lần này fake flag nó sẽ giấu khó nhìn hơn 1 tí khi chúng ta thực hiện decode ra:

<img width="1900" height="954" alt="image" src="https://github.com/user-attachments/assets/d0043429-847b-43ce-95b4-6615587a245b" />

<img width="1910" height="956" alt="image" src="https://github.com/user-attachments/assets/1f0a00a9-04fe-4936-81ea-661af217ba27" />

Ở đây tác giả sẽ để phần flag fake này bên trong 4 bytes đầu của fields `icmp.data`, mình dùng 1 cái script ngắn để thực hiện decode và bóc bytes ra 

```
import binascii

blocks = [
    "34316c33c432ff4c3df9bdfc0d1134bc",
    "6b617368a3b81d37bf3f96fb40f512ce",
    "33675f6610be937f4bfb5b9094fb7c6e",
    "5f656368fd6c568b599d1de87fbd5b34",
    "647d0000f90e0f334723e495c2c76f3d",
    "6f5f3574d9167c98afecd2f58d09a89f",
    "69435446316c6ca1c5cad9d081ccf3bb"
]

for block in blocks:
    chunk_hex = block[:8]
    
    chunk_ascii = binascii.unhexlify(chunk_hex).decode('ascii', errors='ignore').replace('\x00', '')
    
    print(f"Khối gốc: {block[:12]}...  =>  Hex: {chunk_hex}  =>  ASCII: {chunk_ascii}")
                                                                                                    
```

Sau đó nó sẽ ra các fragment như sau:

```

Khối gốc: 34316c33c432...  =>  Hex: 34316c33  =>  ASCII: 41l3
Khối gốc: 6b617368a3b8...  =>  Hex: 6b617368  =>  ASCII: kash
Khối gốc: 33675f6610be...  =>  Hex: 33675f66  =>  ASCII: 3g_f
Khối gốc: 5f656368fd6c...  =>  Hex: 5f656368  =>  ASCII: _ech
Khối gốc: 647d0000f90e...  =>  Hex: 647d0000  =>  ASCII: d}
Khối gốc: 6f5f3574d916...  =>  Hex: 6f5f3574  =>  ASCII: o_5t
Khối gốc: 69435446316c...  =>  Hex: 69435446  =>  ASCII: iCTF

```

Cùng với 1 mảnh được để trong 1 giao thức `icmp, HiperconTracer` - là 1 công cụ mạng dùng để phân tích đường truyền bằng cách gửi các gói tin `ICMP, TCP, UDP` đặc biệt. Và cũng đồng thời chứa 1 fragment `{1cm` 

<img width="1902" height="680" alt="image" src="https://github.com/user-attachments/assets/b84e5986-60a2-4df5-8e86-a6b0d309e8ab" />

Khi ghép toàn bộ fragment lại thì sẽ ra như này: **kashiCTF{1cm_echo_5t3g_f41l3d}**

Và cái fake flag cuối cùng nằm ở tcp payload, ở packet có length lớn nhất:

<img width="1868" height="570" alt="image" src="https://github.com/user-attachments/assets/82743c0f-c3da-4ed8-81ef-51503d43a135" />

<img width="1286" height="352" alt="image" src="https://github.com/user-attachments/assets/279fa807-bafa-4533-8ba0-8ac080570f9b" />

Lấy chuỗi hex trong `token` và thực hiện decode hex thì có được fake flag cuối trong bài **kashiCTF{h3x_1n_b0dy_15_n0t_1t}**

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/kashi_CTF/Mahashamshan]
└─$ echo "6b617368694354467b6833785f316e5f623064795f31355f6e30745f31747d" | xxd -r -p
kashiCTF{h3x_1n_b0dy_15_n0t_1t}     
```

Bây giờ mình sẽ đi vào phần chính trong bài, là phần message thật sự đã bị leak ra ngoài, mình để ý hầu hết các packet đều từ ip `192.168.7.77`, và khi mình sử dụng conversation ở `ip.src == 192.168.7.77`, mình sẽ thấy nó thực hiện gửi các packet cho 1 ip `172.31.0.1` từ rất nhiều port khác nhau:

<img width="1689" height="732" alt="image" src="https://github.com/user-attachments/assets/7c3185b4-7903-46fc-8674-79ead8f9f688" />

Khi mình nhìn vào mục `tcp` trong khung bên trái mình sẽ thấy có 1 điểm khá đặc biệt nằm trong sequence number raw 

<img width="1901" height="955" alt="image" src="https://github.com/user-attachments/assets/872f67b7-900a-422d-bd80-361a293f09e9" />

Khi mình ngó qua 1 vài sequence number ở đây, thì nó không hề ngẫu nhiên, mà nó có được sự dãn cách nhau đúng bằng `50`. Mình sẽ dùng tshark lọc qua thử cho dễ theo dõi ở đây:

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/kashi_CTF/Mahashamshan]
└─$ tshark -r mahashamshan_2.pcap -Y "ip.src == 192.168.7.77 && tcp" -T fields -e tcp.seq_raw | tr '\n' ','
20850,21400,20400,20950,20300,20900,20750,21150,21300,21050,21100,20000,21000,20050,20500,20250,21200,20700,20450,20200,21450,20100,20150,20800,21250,20650,20600,21350,20350,20550
```
Đặc biệt là khi xuất hiện các giá trị sequence number này, nó thường được sử dụng để sắp xếp cho các payload được sắp xếp lộn xộn. Và khi để ý kĩ mình sẽ thấy được các số được sắp xếp khong xót bất cứ giá trị nào từ `20000 -> 21450` với đúng 1 khoảng bằng 50, mình chắc chắn flag sẽ được sắp xếp theo kiểu này.

Nên mình sẽ lọc ra fields tcp payload, với 1 cột seq number kế bên cho dễ quan sát:

<img width="1059" height="530" alt="image" src="https://github.com/user-attachments/assets/b35b9ffc-13f6-4892-a684-d9278dfc47a7" />

Đấy nó sẽ có các payload tương ứng, với seq number 

> Ở đây thường các giá trị payload tcp sẽ được padding thêm `000`, nên mình sẽ thực thi các lệnh để cắt bỏ phần padding, `sort` lại, bỏ xuống dòng, và decode hex.

```
                             
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/kashi_CTF/Mahashamshan]
└─$ tshark -r mahashamshan_2.pcap -Y "ip.src == 192.168.7.77 && tcp" -T fields -e tcp.seq_raw -e tcp.payload | sort -n | awk '{print $2}' | sed 's/000000$//' | xxd -r -p;echo  
kashiCTF{urg_p01nt3r_1s_4_l13}
                                  
```
**Các lệnh:** 
- `awk 'print $2'` để thực hiện bỏ đi cột đầu tiên bên trái, và chỉ lấy cột thứ 2.
- `seq 's/000000//'` để thực hiện bỏ đi phần padding 6 số 0 chỉ lấy các kí tự để ghép thành chuỗi hex.
- `xxd -r -p` để thực hiện decode hex, sau đó thực hiện lệnh `;echo` để in ra output của cả lệnh trên

**flag: kashiCTF{urg_p01nt3r_1s_4_l13}**










