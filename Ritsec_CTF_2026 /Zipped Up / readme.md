# Zipped Up 

<img width="1114" height="653" alt="Screenshot 2026-04-04 135846" src="https://github.com/user-attachments/assets/05c3a371-6a45-4d34-9ae6-b224aceacdbd" />

Link challenge: https://drive.google.com/file/d/1Ew_oes_GNMvJ2WRQzvhBd69Rau2rHiIk/view?usp=sharing

Description: Cố gắng để unzip ra =))

Với 1 challenge chỉ cho chúng ta 1 file zip như thế này, và khi mình thử dùng lệnh `xxd` để xem được phần tên các files được nén bên trong:

<img width="904" height="470" alt="image" src="https://github.com/user-attachments/assets/bf5de586-2df3-452f-8133-f8b6e344f457" />

Ở đây chúng ta sẽ biết được bên trong sẽ có 1 file `.txt` và 1 file ảnh `png`. Với những challenge yêu cầu unzip với 1 nội dung cho trước thì chúng ta sẽ dùng công cụ tên là `bkcrack`. 

Trước khi mình thực hiện làm tiếp, mình sẽ nói qua về công cụ `bkcrack` này, cùng với kĩ thuật `Knowing Plaintext` - Đoán được 1 phần nội dung bên trong 1 file được nén bên trong file zip:

**Bcrack** là 1 công cụ dùng để thực hiện 1 cuộc tấn công **Known-Plaintext Attack (KPA)**, công cụ `bcrack` sử dụng thuật toán ZipCrypto cũ yêu cầu attacker biết được ít nhất 12 bytes của 1 file gốc bị nén bên trong file zip, trong đó yêu cầu ít nhất 8 bytes liên tục, để thực hiện khôi phục lại 3 khóa mã nội bộ **internal keys**

Khi có được 3 khóa này, chúng ta có thể:
- Lấy toàn bộ nội dung của 2 file được nén mà không cần mật khẩu gốc là gì.
- Có thể đổi mật khẩu cho file zip này luôn.

Giờ mình sẽ nói sâu hơn về kĩ thuật **KPA - Known Plaintext Attack**
- Thuật toán **ZipCrypto** không sử dụng mã hóa khối (Block Cipher) như AES mà nó sử dụng mã hóa dòng `Stream Cipher`. Nó duy trì 1 trạng thái hệ thống bằng 3 khóa nội bộ **Internal Keys**, gọi là Key0-Key1-Key2.
  - Mỗi khóa có kích thước 32-bit
  - Tổng cộng là 3 khóa sẽ có kích thước đúng bằng 96-bits tương đương với 12 bytes.

- Ví dụ khi chúng ta biết được 1 byte (knows plaintext), thì chúng ta có thể lấy nó để xor với bytes bản mã (ciphertext) tương ứng trong file zip để có được 1 bytes bên trong (luồng khóa)
  - 1 bytes = 8 bít.
  - Khi đó chúng ta nếu biết được 12 bytes `known plaintext` thì có thể xor với bản mã để có được 12 bytes của khóa đúng bằng 96-bits.
  - Đó là lý do mà `bkcrack` yêu cầu tối thiểu 12 bytes (và có ít nhất 8 bytes liên tục) để nó có thể dùng thuật toán đảo ngược **CRC32** dò ngược lại ra 3 khóa gốc.

Cách mà thuật toán trả về 3 khóa gốc:
- **Keystream:** Máy tính lấy 12 bytes plaintext xor với 12 bytes ciphertext tương ứng để ra được 12 bytes Keystream.
- 

















