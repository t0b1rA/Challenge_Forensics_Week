Đây là writeup của em về những challenge forensics trong giải eschaton vừa rồi, mà em giải được ạ

## Old School Messaging 

<img width="1728" height="672" alt="Screenshot 2026-02-03 152123" src="https://github.com/user-attachments/assets/31212396-12fd-4d56-b9bd-42b67c2bbc88" />

Link đề: https://drive.google.com/file/d/1A8TK5BvWhLV06u8QOv7PH-tsuHkz3F4N/view?usp=sharing

Chall này cung cấp cho em một file pcapng, và với context là đây là một tin nhắn đã được mã hóa theo một cách mã hóa khá cổ rồi, cùng với 1 câu là `56k handshake`, nên em có nghĩ tới các gói tin chứa tin nhắn này sẽ được đóng gói và chuyển đi qua giao thức tcp.

Như mọi challenge `pcapng`, thì em sẽ thực hiện xem tất cả các giao thức được sử dụng cả file `pcapng` trên, trong mục `statistic protocol hierrachy`:

<img width="1528" height="284" alt="image" src="https://github.com/user-attachments/assets/0343aef9-b374-4264-94a6-63b8b87a4d9e" />

Ở đây em có nhìn thấy có giao thức `SMTP`, đây là một giao thức dùng mô hình `TCP/IP` để gửi, chuyển tiếp, nhận các email trên internet, thường được sử dụng khá phổ biến ngày trước. Mình nghĩ thì ở trong các gói tin với giao thức `SMTP` sẽ chứa những thông tin mình sẽ cần tiếp theo. Em sẽ filter theo giao thức `SMTP`, để tìm kiếm tiếp. Thì sau 1 lúc xem về các luồng gửi đi, và nội dung của các gói tin, thì em thấy có 2 địa chỉ ip là `192.168.1.100` và địa chỉ ip `10.0.0.25`, thực hiện thiết lập 1 phiên trò chuyện, 




