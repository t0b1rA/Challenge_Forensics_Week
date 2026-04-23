# Neptune Authority

<img width="552" height="676" alt="Screenshot 2026-04-21 155137" src="https://github.com/user-attachments/assets/45b3b51a-2441-47c0-bee8-39ddee9e4c91" />

**Link challenge**: https://ctf.jerseyctf.com/files/950d58e9fa57894da27e68ebac211231/04-neptune-authority.zip?token=eyJ1c2VyX2lkIjo2NzA3LCJ0ZWFtX2lkIjoyNzQ4LCJmaWxlX2lkIjozMTR9.aehI6w.5gjSYsKuF_KOXvbeEf4qjyXEk_M

**Description**: A network capture from Neptune's orbital defense perimeter shows the system entering escalation mode after the relay network reawakened. A shutdown authorization was transmitted over an encrypted channel before the perimeter locked down. Recover the materials needed to decrypt the exchange and stop the quarantine from closing around you.

Flow của bài này chúng ta sẽ có được 2 địa chỉ ip `10.20.0.10` sẽ liên tục thực hiện kết nối tcp tới `10.20.0.99` với nhiều phiên khác nhau, với mỗi session kết nối tcp thì ip `10.20.0.10` sẽ gửi các http request `GET` tới `status http` để kiểm tra trạng thái hiện tại của server và hầu hết nó đều trả về `404 not found`, nhưng khi chúng ta chú ý vào 1 điểm nhỏ ở mỗi packet server trả về `404` thì đều có 1 đoạn note nhỏ và nó sẽ rất hữu ích cho phần sau của bài. 

<img width="1019" height="216" alt="image" src="https://github.com/user-attachments/assets/005b1ed3-64d1-461e-83a2-dc3c50833ebe" />

 Sau 1 lúc attacker liên tục gửi các request đến các url khong tồn tại, thì attacker đã tải về 2 file cả 2 đều đã bị encrypt, và sau khi tải được 1 file chứa `key` và `crt - certificate` thì đoạn traffic phía sau đã bị encrypt. Sau đó chúng ta sẽ dùng key từ file `ode.key` để decrypt các streams tls, để tìm ra được code thực hiện mã code shutdown authorization trước khi toàn bộ traffic bị mã hóa, tức là mình nên chú ý vào các luồng đầu tiên được mã hóa bằng `TLS`.

<img width="1843" height="421" alt="image" src="https://github.com/user-attachments/assets/ca4defd6-9c4a-454e-a1a8-276ff3a753fd" />

Kiểm tra `protocol hierachy`, chúng ta có thể thấy được, hầu như lượng lớn traffic đều tập trung ở giao thức vận `TCP`, và cả bài đều xoay quanh các protocol `tcp`, `http`, `tls`.

<img width="1538" height="337" alt="image" src="https://github.com/user-attachments/assets/891529f2-e846-4f5d-a718-5c53e3c8484e" />

 Khi chúng ta xem phần magic byte ở đầu của 2 file `.enc` nó đều bắt đầu với magic byte là `Salted` - đây là magic bytes của mã hóa openssl, nên mình sẽ dùng openssl để thực hiện decrypt 2 file `.enc` này:

Mình dùng các tham số như `aes256-cbc` và `-md` là **sha256**, ở đây việc lựa chọn kiểu decrypt và cách băm cái password `oldorbit` khá quan trọng, bởi vì nếu chúng ta thực hiện sai kiểu băm `sha256` như lại dùng `md5` sẽ sinh ra 2 recipe hoàn toàn sai cho `aes-256-cbc` là `key - IV` sai.

> Trong **openssl** dùng cơ chế `EVP-BytesToKey` tức là sẽ lấy passwords ghép với **salt** thực hiện băm nhiều lần cho đến khi đủ độ dài (48 bytes) và cắt ra thành 2 recipe cho kiểu decrypt `key (32 bytes) - IV (16 bytes)`:
>
> **Salt** trong bài sẽ được nằm ngay phía sau magic bytes của file được encrypt.
> - Khi đó 8 bytes đầu sẽ là `Salted__`
> - Sau đó 8 bytes tiếp theo sẽ là salt của file enc, và phần còn lại sẽ là ciphertext.
> 
```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/jersey_CTF/Neptune Authority]
└─$ openssl enc -d -aes-256-cbc -md sha256 -in ods.key.enc -pass pass:oldorbit 

```
 
Sau khi thực hiện decrypt file chúng ta sẽ nhận được file `ods,key` chứa private key:

```
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCwNU457yX3tFFT
VYRRudEZEODwDFX9OPC8yzdSmB0cGwUcy8f8sB0iuojPDv201iURDjC3tSjJ/8NK
q66CA6IwtIopDJBR4ZT3J9Y2DEShL+B79WVsxrkePVcDtBxVjbWabDF5c8U/J0oW
FBvnpzhg25NSAVeUbLXuoaZBje3VBDbfCsbOZ9u+afbIxhWK42+BGe4DELB5SbKX
bRNDuO8F4en699fzfLmhrSkeA8oaB6EjyXVQlesM01wonNLqyHC1hnRvyZU5eElo
cVOheBOvfvT8aUfdq6czArU8jD1HLVpd4BIK07ucniXUnt1cb/sskCBsOQSI2Ztw
XDFzNfIRAgMBAAECggEAN+jqBcriXqrJxSnUvsO5W302CiS34g1/oT/PsXbPgbv3
DtCAB6bvz7WlNCHbEVaDU1qPzbJ/Gzz6f8ZirCEwBMk8L1Mrtbdgd12eA+83lXdm
AJ74DCAv26713Zh4BxNcRH/A4PsBYoz6XnAJ/KJb6quxHmuLmO43edyzrog0pwpU
6txDgLBloibeOTpzUUHwFNPO735wkEgwaASNqSBZPBxd7mpq9qwVfbXtqZoQ68Vg
xLUVo6O7uV6MJo+FuzH/DX1vFfLTP2/0schQ/Bzl3FkFV4Fp0OVH0VZ2NO1/fxFE
YR752hmHLlWsrxuf50zwlg5zScP+NV+UR3uRXwSBGwKBgQDcEMtrHHZysMNw8VMy
y+5qUZUb7QS0o/WAX0uMZhvp7AMElIu3+XrBOGxEmB/K2iouqP/TM/9XHE4RNGSJ
4dlC/hOefzDl8A635TPLvOln66znXtIf/3j0lD6PwH9C+TqY8tUXUluNRefPi8Nv
It0Xy+spbdRJYqDYV+lvOU2fBwKBgQDM+y4jCNdQNyNrPhuNIg6d4AKK/72sTtpx
2hzda/b4uQ/y0+4a+ixeBBOzY7/h85ByqDeCpfYjG8Jw5rG0XxI5jC6SEJsh1j9C
nXGu0JJp721nF1raTiDDo3vnvYlIRmq4YIseQuhUjbgnFkxm3rohd8OPN0dmia2n
FMgQJCGIJwKBgExmCDjHSNfIRhGPtjKMWdjPOdTYFCoiQbivXKsBR++N3/5XE6pr
EhLCY9PsfB0QYFSSlz3bb2nuiauvZLf5kFORoX4E6hTpojJ1f+XbT6ykRQKOCKTT
LEq8rHt7eLLnk1BF/XR7Qw1ol3GWM+MBV4BLaviXCHvxoaV537CdVDVBAoGAHRDc
+PDO/zviVNmotHmI0xAprCYZci54QT6payhdC+XKAifVEpQ46FfxpzVUxyhvaiK6
RFdeMJpGFxZPSoFUpz5eeC3MoZ6st7h1n1FKAaWGwOCJ7Hy5nqQ29KRmrA34Ig7m
izL3mM3DuB8sVEXu5MIDw/IVuM97BT8oI0nMS28CgYAU/Ls1+QFQqwzQEKWPV4Tt
eRJ8snBCLobbY0MuKCJkURF9ivN2HKUFxA6GE0efnMkG11sq+UFDLZV5+3jPCsdW
xvoDt1xvpY0UlblQvzD2LTmNnmyclwWrcF78m/oSjh+sFzpVUqt/US4yLsb9gX8K
ZoHmnj2YoRSJRjco7D9OUA==
-----END PRIVATE KEY-----

```
Private key ở đây chính là khóa dùng để decrypt phần stream ở phía sau, bởi vì chúng ta có thể thấy server và client negotiates `TLS_RSA_WITH_AES_256_CBC_SHA`

<img width="1038" height="556" alt="image" src="https://github.com/user-attachments/assets/ca4bb886-75de-40d4-bdab-7cc76c5db4c7" />

Ở đây mình hiểu cipher suite là gì:
- Khi client bắt đầu thực hiện kết nối đến server, thì cả 2 bên cần thống nhát với nhau kiểu bộ thuật toán mà cả 2 bên có trong suốt quá trình `negotiate` để bảo đảm kết nối dữ liệu an toàn và tương thích.

Trong challenge cả 2 thực hiện chốt với nhau cipher suite là `TLS_RSA_WITH_AES_256_CBC_SHA`, để hiểu chúng ta sẽ chia nhỏ các thuật toán bên trong với mỗi thuật toán thì được sử dụng cho 1 mục đích khác nhau trong quá trình handshake và transmited data encrypt:

`TLS-RSA`: Phần này nói về key exchange giữa 2 bên
- Server sẽ gửi certificate chứa RSA public key cho client
    
<img width="597" height="157" alt="image" src="https://github.com/user-attachments/assets/bc5f8590-77c9-467f-b146-ac9489225cf2" />

- Client tự tạo ra 1 giá trị private gọi là **pre-master secret**
- Client dùng **RSA public key** của server để mã hóa **pre-master secret**, sau đó gửi nó sang server.
- Server sẽ dùng private key để giải mã.
Khi đó, nếu chúng ta có được private key của server chúng ta có thể giải được `pre-master secret` khi đó có thể dựng lại khóa phiên decrypt được traffic phía sau.

`WITH_AES_256_CBC`: Sau khi 2 bên có cùng bí mật chung, họ sinh ra các khóa đối xứng. Phần dữ liệu phía sau được mã hóa bằng:
- AES mode CBC
- Khóa dài 256 bit (32 bytes) cùng với IV (16 bytes)

`SHA` sử dụng HCMAC_SHA1 để kiểm tra tính toàn vẹn bản ghi TLS, và phần **SHA1** ở đây chỉ để đảm bảo tính toàn vẹn, chứ nó khong dùng để mã hóa **TLS**.

Khi chúng ta hiểu được kiểu cipher suite được kết nối là như thế nào, chúng ta sẽ biết được khóa private key vừa crack được có tác dụng làm gì - chính là để decrypt session.

Bây giờ mình sẽ thực hiện decrypt stream đầu tiên, khi bắt đầu thực hiện handshake của client với server, bởi vì như description của bài có đề cập đến, `A shutdown authorization was transmitted over an encrypted channel before the perimeter locked down.` giai đoạn shutdown authorization đã được truyền đi trong kênh mã hóa, trước khi perimeter bị đóng hoàn toàn - tức là được truyền đi trong kênh mã hóa đầu tiên khi bắt đầu thực hiện encrypt traffic còn lại bằng TLS, perimeter locked down mình nghĩ chính là traffic bị encrypt hoàn toàn phía sau.

<img width="1903" height="914" alt="image" src="https://github.com/user-attachments/assets/aed81afd-64de-4cf6-8ba2-b15652410cff" />

Nên mình chọn `tcp stream 71`, là stream bắt đầu việc handshake encrypt traffic phía sau, với protocol là `http, port server 8443, và private key lưu trong ods.key`.
```bash
tshark -r neptune-defense.pcap \
  -o 'uat:rsa_keys:"ods.key",""' \
  -d tcp.port==8443,tls \
  -o tls.debug_file:tls_debug.txt \
  -q -V > /dev/null
                            
```
- `-o` truyền vào rsa_key là file: `ods.key`.
- `-d` decrypt các traffic với port là 8443 và protocol `tls`.
- `-o` ghi file `tls debug` vào file `tls_debug.txt`.
- `-q` , `-V` đưa toàn bộ output trên màn hình vào /dev/null vì số lượng packet khá lớn, nó làm bừa trên terminal.

Giờ mình thực hiện đọc nội dung của phần được decrypt, nhưng để đọc đúng phần trọng tâm, thì mình cat ra chuỗi `decrypt` trước, sau đó mới lọc ra chuỗi export ra xem:

<img width="1376" height="792" alt="image" src="https://github.com/user-attachments/assets/48e716c9-8a1d-485e-97a5-f9314f28b2f2" />

Mình nghĩ là nên xem nội dung của phần `decrypt app data fragments`

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/jersey_CTF/Neptune Authority]
└─$ grep -n "decrypted app data fragment" -A 10 tls_debug.txt
340:decrypted app data fragment[113]:
341-| 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d |HTTP/1.1 200 OK.|
342-| 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 |.Content-Type: t|
343-| 65 78 74 2f 70 6c 61 69 6e 0d 0a 0d 0a 53 54 41 |ext/plain....STA|
344-| 54 55 53 3a 20 45 53 43 41 4c 41 54 49 4f 4e 5f |TUS: ESCALATION_|
345-| 41 43 54 49 56 45 0a 43 4f 55 4e 54 44 4f 57 4e |ACTIVE.COUNTDOWN|
346-| 3a 20 41 43 54 49 56 45 0a 53 48 55 54 44 4f 57 |: ACTIVE.SHUTDOW|
347-| 4e 5f 43 4f 44 45 3a 20 34 38 31 37 33 39 32 36 |N_CODE: 48173926|
348-| 0a                                              |.               |
349-packet_from_server: is from server - TRUE
350-process_ssl_payload: found heuristics dissector http_tls, app_handle is (nil) ((null))
--
387:decrypted app data fragment[92]:
388-| 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a |GET / HTTP/1.1..|
389-| 48 6f 73 74 3a 20 6f 64 73 2d 6e 65 70 2d 70 65 |Host: ods-nep-pe|
390-| 72 69 6d 65 74 65 72 0d 0a 55 73 65 72 2d 41 67 |rimeter..User-Ag|
391-| 65 6e 74 3a 20 73 74 61 74 69 6f 6e 2d 63 6f 72 |ent: station-cor|
392-| 65 2f 31 2e 30 0d 0a 43 6f 6e 6e 65 63 74 69 6f |e/1.0..Connectio|
393-| 6e 3a 20 63 6c 6f 73 65 0d 0a 0d 0a             |n: close....    |
394-packet_from_server: is from server - FALSE
395-process_ssl_payload: found heuristics dissector http_tls, app_handle is (nil) ((null))
396-
397-dissect_ssl enter frame #1046 (first time)
--
3473:decrypted app data fragment[79]:
3474-| 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a |GET / HTTP/1.1..|
3475-| 48 6f 73 74 3a 20 31 30 2e 32 30 2e 30 2e 35 30 |Host: 10.20.0.50|
3476-| 3a 38 34 34 33 0d 0a 55 73 65 72 2d 41 67 65 6e |:8443..User-Agen|
3477-| 74 3a 20 63 75 72 6c 2f 37 2e 37 36 2e 31 0d 0a |t: curl/7.76.1..|
3478-| 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a    |Accept: */*.... |
3479-packet_from_server: is from server - FALSE
3480-process_ssl_payload: found heuristics dissector http_tls, app_handle is (nil) ((null))
3481-
3482-dissect_ssl enter frame #1657 (first time)
3483-packet_from_server: is from server - FALSE

```

Ở đây chúng ta sẽ thấy 1 lệnh `SHUTDOWN code: 48173926` chính là lệnh authorization dùng để tắt hệ thống đã được transmit đi trong kênh mã hóa mà des đã nhắc đến. Và đề yêu cầu mã code ủy quyền cho lệnh đó, chính là code cho lệnh SHUTDOWN hệ thống:

**flag: jctf{48173926}**








