# Mid Forensics

<img width="609" height="601" alt="Screenshot 2026-04-02 183338" src="https://github.com/user-attachments/assets/27f526a0-f44f-4e89-8943-50b0387356e3" />

Link challenge: https://drive.google.com/file/d/16LXkl_uwaRxifp8Cwhx-aiI35GPpBzHf/view?usp=sharing

Description: Chúng ta được cung cấp 1 file pcap được thu thập từ một phần mạng nội bộ (internal network) trong quá trình giám sát định kì. Không cảnh báo, và lưu lượng trông rất bình thường. Nhiệm vụ của chúng ta là phân tích file `pcap` và xác định xem các thông tin hữu ích và recoverd nó.

<img width="1904" height="1052" alt="image" src="https://github.com/user-attachments/assets/46a0f5e6-d9b4-498a-adfe-e0225186a316" />

Ngay từ đầu file pcap, chúng ta đã xác định được fields cần tập trung chính là phần `ip.ttl` giờ mình bắt đầu trích xuất ra luôn xem sao:

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/kashi_CTF/Mid Forensics]
└─$ tshark -r ttl_stego.pcap -Y "icmp" -T fields -e ip.ttl | tr -d '\n'
6465656465646565646565646464646564656565646465656465656465646464646565646564646564656464646465656465646564656464646564646465656464656565656465656465656564656464646565656465646464656564656564646465646565656565646565656464656564656565646564646465656464656465646565646465656564656564656565656465646565656565646565646564646564656565646465656465646565656565646565646465646564656565646565646465656465646465646565646565646464656565656564656464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464 
```

Ở đây mình có thể thấy được hầu như nó chỉ có 2 giá trị là 64 và 65, nên mình nghĩ đến việc đây là có thể đây là chuyển đổi giá trị `64 = 0` và `65 = 1` để tạo thành 1 chuỗi giá trị nhị phân, và decode nó sang dạng có thể đọc được. 

Mình sử dụng script để thực hiện cả hành động đổi giá trị thành bit `01`, ghép nó thành chuỗi và decode sang dạng ASCII.

```
def dc_exfil_icmp(file_path):
    str = ""
    try:
        with open(file_path, 'r') as f:
            ttls = [line.strip() for line in f if line.strip()]

            for ttl in ttls:
                if ttl == "64":
                    str += "0"
                elif ttl == "65":
                    str += "1"
                else:
                    continue

        flag = ""
        for i in range(0, len(str), 8):
            byte = str[i:i+8]
            if len(byte) == 8:
                flag += chr(int(byte ,2))

        print(f"binary strings: {str}")
        print(f"Flag: {flag}")

    except FileNotFoundError:
        print(f"khong tim thay file")
    except Exception as e:
        print(f"Xay ra loi {e}")

if __name__ == "__main__":
    dc_exfil_icmp("payload2.txt")
```

Sau khi chạy xong chúng ta sẽ có được flag: 
```
t0b1ra@WIN-DT29EAP54RE:/mnt/d/kali-linux/CTF/kashi_CTF/Mid Forensics$ python3 solve.py
binary strings: 01101011011000010111001101101000011010010100001101010100010001100111101101110100011101000110110001011111011100110111010001100101011001110110111101011111011010010111001101011111011001010111011001101001011011000111110100000000000000000000000000000000000000000000000000
Flag: kashiCTF{ttl_stego_is_evil}
```
**flag: Flag: kashiCTF{ttl_stego_is_evil}**























