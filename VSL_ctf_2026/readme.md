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



## Float Precision

<img width="502" height="575" alt="image" src="https://github.com/user-attachments/assets/a08c9bba-6846-4088-8c4d-7d1dc2b6cf41" />

Link đề: https://drive.google.com/file/d/1zbyQqHaltmsd3fxk7ufqmM4DZzqDIzAZ/view?usp=sharing

Bài này author cung cấp cho mình một file `.npy` chứa 32-bit floating-point values, cùng với 1 hint `In floating-point, not all bits are created equal` có nghĩa là trong các dấu phẩy động đó, không phải bits nào cũng được tạo ra giống nhau.

Để làm được bài này thì đầu tiên chúng ta cần phải tìm hiểu file `.npy` là gì? Mục đích của file này là gì?. Cấu trúc của file `.npy` là gì?

- File `.npy` là gì?

  - File `.npy` là một tệp định dạnh nhị phân tiêu chuẩn của thư viện NumPy(Python) để lưu trữ một mảng NumPy đơn lẻ trên ổ đĩa. Định dạng này lưu trữ tất cả thông tin về kích thước(shape), kiểu dữ liệu (dtype) cần thiết để tái tạo lại mảng 1 cách chính xác, ngay cả trên 1 máy tính có kiến trúc khác biệt. Định dạng `.npz` là định dạng tiêu chuẩn để lưu trữ nhiều mảng **NumPy** trên ổ đĩa. Một tệp `.npz` thực chất là 1 tệp zip chứa nhiều tệp `.npy` bên trong, mỗi tệp tương ứng 1 mảng đơn lẻ.

- Mục đích của file `.npy`: Bởi vì nó lưu trữ tất cả thông tin cần thiết để tái tạo mảng, bao gồm kích thước (shape) và kiểu dữ liệu (dtype) trên 1 máy có kiến trúc khác. Cả mảng little-endian và big-endian đều được hỗ trợ, 1 tệp chứa các số little-endian sẽ tạo ra một mảng little-endian trên bất kì máy nào đọc tệp đó.

> `Little-endian` là 1 phương thức lưu trữ dữ liệu mà ở đó byte có giá trị nhỏ nhất (Least Significant Byte - LSB) được đặt tại địa chỉ bộ nhớ thấp nhất và byte lớn nhất (MSB) sẽ được đặt ở địa chỉ cao hơn.
> `Big-endian` là phương thức lưu trữ dữ liệu đa byte (như số nguyên 16/32 bit) trong bộ nhớ, nơi byte quan trọng nhất (MSB - Most Significant Byte) được đặt tại địa chỉ thấp nhất, còn byte ít quan trọng nhất (LSB) được đặt ở địa chỉ cao nhất

- Cấu trúc của file `.npy`:
  - Phần header của file `.npy`, chứa các metadata (thông tin mô tả dữ liệu). Trong file `.npy`, header có dạng:

    `“NUMPY v {'descr': '<f4', 'fortran_order': False, 'shape': (64, 64), }`

    - `NUMPY` chính là signature byte giúp chúng ta nhận dạng được đây là file `.npy`.
   
    - `descr': '<f4'`: quy định kiểu dữ liệu của các phần tử trong mảng
      - `<`: Little-endian (thứ tự byte, byte LSB thì được đặt ở địa chỉ thấp, byte MSB được đặt ở địa chỉ cao hơn)
      - `f`: là số thực
      - 4 là tương ứng với 32 bit

      => Dữ liêu 32-bits floating Point - như đề đã đề cập.
  - Phần data (nội dung): Ngay sau header là dữ liệu nhị phân thô (raw binary), đây là lý do mà khi chúng ta mở file `.npy` bằng các trình đọc văn bản thông thường, thì đều sẽ in ra các kí tự không đọc được, vì trình soạn thảo văn bản cố gắng chuyển các byte nhị phân đó sang dạng ASCII/Unicode.
 
<img width="1535" height="788" alt="image" src="https://github.com/user-attachments/assets/0be62bc1-a03e-4764-a474-302bce37d21f" />

Đây là nội dung của file `.npy` là các số thực với khuôn 64x64 số

Sau khi tìm hiểu sơ lược về file `.npy`, em dựa vào phần hint của author về câu này: `Not all bits are created equal` và `Accurancy is everything`. 

Hint đầu tiên mình có thể phân tích rằng author đang ám chỉ đến việc mỗi bits của 1 số thực sẽ khác nhau hoàn toàn về vai trò và mức độ biến đổi của nó, em sẽ phân tích sơ qua về cấu trúc số thực `float32` để mình có thể hình dung được:

- Trong 1 số `float32` được chia thành 3 phần riêng biệt:
  - Phần **Bit dấu** (Sign Bit -1 bit) 1 bit này có thể là 0 hoặc 1 nó tương ứng với giá trị âm hoặc dương, việc thay đổi 1 bit ở đây để giấu dữ liệu có thể biến 1 số thực từ âm thành dương, tác động rất lớn đến số thực đó -> ảnh hưởng đến file `.npy`.

  - Phần **Bit mũ (Exponent - 8 bit)**, quyết định đến độ lớn của 1 số thực, việc thay đổi 1 bit ở đây có thể biến 1 số thực trở nên nhỏ đi gấp đôi hoặc lớn lên gấp đôi -> cũng sẽ ảnh hưởng lớn đến file `.npy`.
 
  - Phần **Định trị (Mantissa - 23 bit)**: Quyết định độ chính xác (phần lẻ sau giấu phẩy), mức độ ảnh hưởng của nó sẽ nhỏ dần từ trái sang phải, khi các giá trị cuối là các giá trị cực nhỏ -> không ảnh hưởng lớn đến file `.npy`
 
Qua đây em có thể hiểu được rằng nếu chúng ta thay đổi các bit LSB của phần Mantissa thì con số chỉ thay đổi rất ít và sẽ không thể làm hỏng cáu trúc của file, sẽ phù hợp cho việc author giấu dữ liệu trong những bit này. Cùng với hint thứ 2 `Accurancy is everything`, em nghĩ là đang ám chỉ đến Bit quyết định độ chính xác Mantissa này.

Bây giờ em có thể xác định được dữ liệu được giấu vào đâu sẽ ít thay đổi cấu trúc của file nhất, em viết 1 script nhỏ với hành động lần lượt là: 

`đọc file .npy lấy mảng dữ liệu gốc -> chuyển đổi mảng 2 chiều 64x64 thành mảng 1 chiều gồm 4096 phần tử -> chuyển đổi kiểu dữ liệu float32 sang int32 để thao tác trên được từng bit -> trích xuất bit cuối ra -> gom nhóm thành 1 nhóm 8 bit liên tiếp (1 byte kí tự ASCII) -> và ghép thành chuỗi`

```
import numpy as np

# 1. Load file npy
data = np.load('image.npy')

# 2. Chuyển đổi các số thực sang dạng bit (view dưới dạng số nguyên 32-bit để lấy bit)
flatten_data = data.flatten()
binary_data = flatten_data.view(np.int32)

# 3. Trích xuất bit cuối cùng (LSB) của mỗi số
extracted_bits = []
for val in binary_data:
    extracted_bits.append(str(val & 1))

# 4. Gom nhóm 8 bit thành 1 ký tự (Byte)
bit_string = "".join(extracted_bits)
chars = []
for i in range(0, len(bit_string), 8):
    byte = bit_string[i:i+8]
    chars.append(chr(int(byte, 2)))

# 5. In kết quả để tìm Flag
flag = "".join(chars)
print(flag)
```
<img width="1970" height="420" alt="image" src="https://github.com/user-attachments/assets/72e9eb7c-fb48-4c9a-aac4-ecda4ab486cc" />

**Flag: VSL{1EEE_754_m4nt1ss4_h1d1ng_1s_r34lly_tr1cky_112211!}**


