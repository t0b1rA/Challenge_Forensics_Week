Đây là writeup của em về những challenge forensics trong giải eschaton vừa rồi, mà em giải được ạ

## 1. Old School Messaging 

<img width="1728" height="672" alt="Screenshot 2026-02-03 152123" src="https://github.com/user-attachments/assets/31212396-12fd-4d56-b9bd-42b67c2bbc88" />

Link đề: https://drive.google.com/file/d/1A8TK5BvWhLV06u8QOv7PH-tsuHkz3F4N/view?usp=sharing

Chall này cung cấp cho em một file pcapng, và với context là đây là một tin nhắn đã được mã hóa theo một cách mã hóa khá cổ rồi, cùng với 1 câu là `56k handshake`, nên em có nghĩ tới các gói tin chứa tin nhắn này sẽ được đóng gói và chuyển đi qua giao thức tcp.

Như mọi challenge `pcapng`, thì em sẽ thực hiện xem tất cả các giao thức được sử dụng cả file `pcapng` trên, trong mục `statistic protocol hierrachy`:

<img width="1528" height="284" alt="image" src="https://github.com/user-attachments/assets/0343aef9-b374-4264-94a6-63b8b87a4d9e" />

Ở đây em có nhìn thấy có giao thức `SMTP`, đây là một giao thức dùng mô hình `TCP/IP` để gửi, chuyển tiếp, nhận các email trên internet, thường được sử dụng khá phổ biến ngày trước. Mình nghĩ thì ở trong các gói tin với giao thức `SMTP` sẽ chứa những thông tin mình sẽ cần tiếp theo. Em sẽ filter theo giao thức `SMTP`, để tìm kiếm tiếp. Thì sau 1 lúc xem về các luồng gửi đi, và nội dung của các gói tin, thì em thấy có 2 địa chỉ ip là `192.168.1.100` và ip server `10.0.0.25`, thực hiện thiết lập 1 phiên trò chuyện:


<img width="1919" height="787" alt="image" src="https://github.com/user-attachments/assets/378bbb41-e6e9-4df1-b234-59c91cb6b61d" />

Địa chỉ ip `192.168.1.100` thực hiện tạo một phiên trò chuyện gửi email đến cho **Mail Server**, để chuẩn bị cho quá trình gửi email đến cho server xong sau đó server mới thực hiện việc ` bóc tách ` các metadata được đính với gói tin, để tìm kiếm người nhận. 

<img width="1273" height="1048" alt="image" src="https://github.com/user-attachments/assets/dc30cd04-133a-4f1c-9dbf-43a75175f8ee" />

Ở đây mình sẽ phân tích qua 1 chút về quá trình gửi email trong giao thức `SMTP` này:

`220 mail.retro-bbs.net ESMTP Sendmail 8.14.7; ready`

Đây là 1 thông báo cho thấy rằng quá trình nhận email từ máy gửi đến server đã sẳn sàng, và sẽ bắt đầu nhận email tới, và `mail.retro-bbs.net` chính là đại diện cho `Mail Server`.

`EHLO bbs.retro-bbs.net`

Tin nhắn này thông báo cho `mail server` rằng _toi là máy gửi `bbs.retro-bbs.net`_.

```
250-mail.retro-bbs.net Hello bbs.retro-bbs.net
250-SIZE 52428800
250-8BITMIME
250 HELP
```

Dòng đầu tiên, chính là bước cuối xác định quá trình `handshake` thành công giữa `client` và `web server`. Sau đó, server tiếp tục gửi đi thông báo về mức size của email mà server hỗ trợ, mã hóa 8-bit.

```
MAIL FROM:<sysadmin@retro-bbs.net>

250 2.1.0 Sender OK

RCPT TO:<user42@dial-up.com>

250 2.1.5 Recipient OK
```

Tiếp theo người gửi bắt đầu, thêm các metadata về mail của người nhận và người gửi cho server biết.

```
DATA

354 Start mail input; end with <CRLF>.<CRLF>
```

Đây là bước bắt đầu cho quá trình, địa chỉ ip `192.168.1.100` thực hiện gửi email đến cho server, cho server thực hiện lưu trữ và kiểm tra người nhận có tồn tại không, sau đó sẽ thực hiện truyền email đi.

<img width="956" height="803" alt="image" src="https://github.com/user-attachments/assets/d766725e-2dc4-4cb8-87b8-497ee21e8fbd" />

```
From: SysOp Dave <sysadmin@retro-bbs.net>
To: New User <user42@dial-up.com>
Subject: RE: BBS Account Verification - Action Required
Date: Sun, 18 Jan 2026 13:33:50 +0530
Message-ID: <20260118133350.rr3bh9wgzvip@retro-bbs.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="ZHaKJtfvnq34SIrYr57kutNOKrsdUUCG"
X-Mailer: Pine 4.64
X-Priority: 3 (Normal)

```

Phần đầu là các metatdata của email trên, gồm người gửi, người nhận, ngày gửi đi, Messages-ID, kiểu nội dung và mỗi phần nội dung sẽ được tách ra bởi 1 chuỗi `ZHaKJtfvnq34SIrYr57kutNOKrsdUUCG`.

Ngay bên dưới là một đoạn giới thiệu của người gửi đến với người nhận, kèm với 1 dòng liên quan đến 1 đoạn mã hóa bên dưới đó:

`If the image doesn't open, your mail client might have corrupted it 
during transmission.`

Và 1 tấm hình đã được mã hóa bằng base64, trong quá trình gửi đi, ở đây chúng ta còn sẽ biết thêm là tấm hình đã bị hỏng trong quá trình gửi đi. Bây giờ mình sẽ thực hiện, giải mã và fix lại bức ảnh được gửi đi.

<img width="903" height="883" alt="image" src="https://github.com/user-attachments/assets/ab7c5854-42af-4c2f-bf60-851986bada62" />

Ở đây chúng ta có thể thấy rằng, đây là một file ảnh `.png`, mình sẽ tải nó xuống xem có thể mở được không.

<img width="1786" height="1052" alt="image" src="https://github.com/user-attachments/assets/505bdd75-160c-47d9-ac95-19d858bc471b" />

Vậy thì chúng ta cần phải chỉnh sửa các chunk bị lỗi bằng, `hexd.it` trước mới có thể mở được.

<img width="1481" height="900" alt="image" src="https://github.com/user-attachments/assets/fab65801-c1ed-434f-8808-b66f55b68321" />

Ở đầu chúng ta thấy ngay `signature byte` của png đã sai, đúng phải là `89 50 4E 47 0D 0A 1A 0A`

<img width="843" height="160" alt="image" src="https://github.com/user-attachments/assets/a4702fdf-9c64-4efa-9857-0be5db479141" />

Sau khi chỉnh sửa ở phần `signature byte` xong, mình sử dụng công cụ `pngcheck` để kiểm tra nhanh qua còn lỗi nào nữa không, thì nó đã xác nhận file đã chuẩn rồi, nên mình sẽ mở file lại:

<img width="695" height="561" alt="image" src="https://github.com/user-attachments/assets/289aeb47-1100-4a30-8d1a-8d91c2feedf2" />

Quét mã xong thì em có được flag:

<img width="828" height="1792" alt="image" src="https://github.com/user-attachments/assets/9b21a488-5733-453a-ac20-19f32797cf18" />

**FLAG: esch{c0mmunicat1on_d3c0d3d_th3_0ld_way}**

## 2. Exfil 

<img width="1713" height="666" alt="Screenshot 2026-02-03 152131" src="https://github.com/user-attachments/assets/44888874-31a8-4767-88ef-7d309768af15" />

Link đề: https://drive.google.com/file/d/1PnaQCd7bpNg4Xm1ibM043BY6uEU6qRcE/view?usp=sharing

## Retro Recall

<img width="1201" height="559" alt="Screenshot 2026-02-03 152136" src="https://github.com/user-attachments/assets/01f01259-69f3-4200-815c-899a8e3da7cc" />

Đề bài của challenge này khá lạ, author chỉ cho chúng ta một source như thế này để chúng ta thực hiện giải mã thôi:

```
begin 755 FLGPRNTR.COM
MN@L!M G-(;1,S2%E<V-H>T0Q9%]Y,'5?57,S7T%N7S-M=6PT=#!R7T]R7V0S
*8S!M<#%L17)])
`
end
```

Đọc qua mô tả chúng ta cũng có thể hiểu được là author cần chúng ta giải mã ra đoạn `source` trên để có được flag. 

Và đây cũng là một dạng `encode` khá lạ, khi mà đưa lên `cipher identify`, thì decode ra không có gì:

<img width="893" height="877" alt="image" src="https://github.com/user-attachments/assets/5f51e00a-c623-4f51-a1d3-aebc2d62c270" />

Mình thử decode theo kết quả đầu tiên, thì nó không ra được những kí tự có thể đọc được.

<img width="894" height="708" alt="image" src="https://github.com/user-attachments/assets/ee4b006d-06c5-4638-a2d8-e7fc0012b1ad" />

Nhưng mà, chúng ta để ý thấy rằng, ở bên dưới còn có 1 dạng `encode` khác nửa là `UUencode`. Và khi mình thử `decrypt` theo cách này, thì họ đề xuất nên sử dụng công cụ decrypt `UUencode`.

<img width="885" height="502" alt="image" src="https://github.com/user-attachments/assets/1319436f-81e3-4099-b4a8-1c7c512ed909" />

Em có lên tìm hiểu về dạng `encrypt` này, thì em thấy format `encrypt` nó khá giống với source được cung cấp:

<img width="880" height="349" alt="image" src="https://github.com/user-attachments/assets/6e7cc589-9e7c-4534-964f-a6dc7668e997" />

Đặc biệt là chúng ta có một công cụ riêng biệt để decrypt loại encode `UUencode` này. 

<img width="1572" height="565" alt="image" src="https://github.com/user-attachments/assets/f35c5c05-bad2-4cbc-abfa-e6dff67f16bb" />

Đầu tiên em thực hiện tải xuống bộ công cụ decrypt `uuencode` này trước, sau đó em tạo một file tên là `text.uu` để lưu source dưới dạng encode `.uu`, _`- extention của loại decode trên`_. Và thực hiện chạy công cụ `uudecode` để giải mã source trên, và nó sẽ tự tạo ra 1 file mới tự đặt tên nó với phần begin trong source là `FLGPRNTR.COM`
```
┌──(nhduydeptrai㉿tobi)-[~]
└─$ cat text.uu 
begin 755 FLGPRNTR.COM

MN@L!M G-(;1,S2%E<V-H>T0Q9%]Y,'5?57,S7T%N7S-M=6PT=#!R7T]R7V0S

*8S!M<#%L17)])

`

end    
┌──(nhduydeptrai㉿tobi)-[~]
└─$ nano text.uu   
┌──(nhduydeptrai㉿tobi)-[~]
└─$ uudecode flag.uu
```

<img width="1868" height="204" alt="image" src="https://github.com/user-attachments/assets/66835974-9ad4-4c4f-99f3-66b3b6496725" />

Cuối cùng em đọc nội dung file sau khi được decrypt có dạng như sau:
```  
┌──(nhduydeptrai㉿tobi)-[~]
└─$ cat FLGPRNTR.COM 
              �
               �        �!�L�!esch{D1d_y0u_Us3_An_3mul4t0r_Or_d3�
                                                                 �      �!�L�!esch{D1d_y0u_Us3_An_3mul4t0r_Orc0mp1lEr}&�0mp1lEr}&�%sch{D1d_y0u_Us3_An_3mul4t0r_Or
```
Mặc dù nó có bị tách ra nhưng nhìn kĩ chúng ta cũng có thể nhìn thấy được **flag là: esch{D1d_y0u_Us3_An_3mul4t0r_Or_d3c0mp1lEr}**

Nói qua về loại mã hóa `UUencode`, thì đây là một kỹ thuật khá cổ, được dùng để chuyển đổi dữ liệu nhị phân sang dạng văn bản ASCII để truyền tải qua các hệ thống email, hoặc bản tin điện tử (Usenet) ngày xưa, vốn chỉ hỗ trợ văn bản 7-bit.

**Header** của loại mã hóa này luôn bắt đầu 

`begin <mode> <file_name>`.

**Body** là các kí tự mã hóa lộn xộn, nếu nhìn sơ qua chúng ta có thể dễ nhầm lẫn với các byte rác.

**Footer**: kết thúc bằng 1 dấu nháy `'`, và kèm với chữ `end` ở cuối cùng.

Nguyên lí mà thuật toán này hoạt động, khá giống với cách hoạt động của loại mã hóa **base64**, khi mà:

- Đầu tiên nó sẽ nhóm 3 byte 1 lại với nhau, (24 bits).

- Sau đó nó thực hiện nhóm 4 nhóm nhỏ, tạo thành 1 nhóm 6 bits 1.

- Cuối cùng các giá trị nhị phân của nhóm 6 bits sẽ chuyển thành giá trị thập phân sau đó **cộng với 32**, để tạo thành 1 kí tự mới.

Lý do tại sao cộng với giá trị `32` là bởi vì, các giá trị thập phân từ `1-31` là các giá trị không in ra màn hình được trong bảng ASCII, nên mới bắt buộc phải cộng với 32.
