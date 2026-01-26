


## Reconnaissance

<img width="862" height="985" alt="image" src="https://github.com/user-attachments/assets/0b5f1037-d65b-480b-ac56-0b08ebb48f49" />

Link file 1: [pcap1.pcapng](https://drive.google.com/file/d/1O_9s8lGxmc11XQFjHrs812wye1vqJbIx/view?usp=sharing)

Trong tình huống của đề thì, ta biết được rằng một công ty tên là "Knight Blog" đã bị các kẻ khác tấn công vào, và công ty đang cần điều tra xem toàn bộ vụ việc tấn công này là gì. Trong yêu cầu đầu tiên thì chúng ta được nhận một báo cáo là, hệ thống `IDS` phát hiện xâm nhập, đã phát hiện ra một cuộc dò quét các `port` mạng đang được mở của công ty này, và cần chúng ta điều tra xem là có tổng cộng bao nhiêu cổng đã bị phát hiện đang mở.

Bây giờ mình sẽ mở file `pcapng` của đề và theo dõi các cuộc trò chuyện của các ip với nhau, để xem có gì bất thường không. 

<img width="1893" height="834" alt="image" src="https://github.com/user-attachments/assets/e3fffbea-fbd0-49bb-8035-5ffe8a6dc7ed" />

Khi bật tools `Statistic Conversation` chúng ta sẽ thấy được lượng lớn cuộc trò chuyện nằm ở hai địa chỉ ip là `192.168.1.104` và ip `192.168.1.102`. Và mình cũng tìm hiểu trên mạng được thì để có thể biết được 1 cổng đã mở để bắt đầu trò chuyện, thì chúng ta cần xác định xem là 2 ip đó đã hoàn thành `3 bước bắt tay tcp` ở những `port` nào, thì port đó sẽ ở trạng thái mở.

**filter**: `tcp.flags.syn == 1 && ip.addr == 192.168.1.104 && ip.addr == 192.168.1.102`, mục đích em muốn xem địa chỉ ip nào thực hiện gửi kết nối tcp đầu tiên, để kiểm tra xem đâu là nạn nhân đang bị quét `port`. Có thể attacker sử dụng các công cụ phổ biến như `nmap`, để quét nhanh các cổng được mở.

<img width="1906" height="732" alt="image" src="https://github.com/user-attachments/assets/fd8ccca0-eed7-405c-a6b6-a1872f39f977" />

Ở đây, nhìn sơ qua thì mình thấy các gói tin hầu như bất đầu thực hiện gửi kết nối tcp từ địa chỉ ip `192.168.1.104`, và địa chỉ ip `192.168.1.102` sẽ thực hiện trả lời `syn,ack` lại, có lẽ mình cũng đoán được phần nào rồi, nhưng để chắc chắn, mình sẽ follow thử theo 1 vài gói tin. 

<img width="1919" height="498" alt="image" src="https://github.com/user-attachments/assets/4f24572a-04ff-4c54-91e7-3cf81a3746d6" />

<img width="1919" height="368" alt="image" src="https://github.com/user-attachments/assets/3197f837-d3ba-4e4f-a94d-9466caa3d537" />

Sau khi filter qua nhiều gói tin, mình lấy 2 gói này làm `proof`, vì đây là một dạng quét cổng trong option của `nmap`, `nmap -sT -p <port> <target>` đây là option đó của `nmap`. Nó thực hiện hoàn tất 3 bước bắt tay sau đó gửi 1 gói tin `RST,ACK` để hủy kết nối ngay lập tức 

=> `port1` đầu là 80.

Tiếp theo, em scan theo filter cũ nhưng lần này vì biết được kẻ scan là ip `192.168.1.104` em sẽ filter nó làm `ip.src` còn `192.168.1.102` là `ip.dst` để dễ kiếm hơn.

**filter**: `tcp.flags.ack == 1 && ip.src == 192.168.1.104 && ip.dst == 192.168.1.102`

<img width="1919" height="361" alt="image" src="https://github.com/user-attachments/assets/3e6f6200-47e9-459b-aab8-0e347d35794a" />

Đây là cổng thứ 2 được mở kết nối

=> `port2` là 22.

Sau 1 lượt tìm kiếm thì mình không thấy có cổng nào được `scan tcp` thành công nữa nên mình kết luận câu trả lời là **2 port**.

**flag: KCTF{2}** 

## Gateway Identification

<img width="861" height="981" alt="image" src="https://github.com/user-attachments/assets/3cdf8080-af9e-42a2-a53d-45df3b287118" />

Câu này chúng ta sẽ sử dụng lại file `pcap` cũ để tiếp tục điều tra. Lần này `report` cho thấy rằng công ty đã bị kẻ tấn công thu thập được các thông tin từ cơ sở hạ tầng mạng, và họ cần chúng ta để tìm kiếm `vendor name` của default gateway của dải mạng công ty này.

Theo như mình tìm hiểu thì, cuộc tấn công đang bắt đầu ở 2 địa chỉ ip là `192.168.1.0/16`, và theo mình biết trong mạng máy tính, thì `default gateway` của một dải mạng sẽ thường là ip đầu tiên của dải mạng đó tức nó sẽ là `192.168.1.1`. 

<img width="1238" height="597" alt="image" src="https://github.com/user-attachments/assets/8adf1230-f9be-412c-a51f-5039cecb6284" />

Giờ mình sẽ filter địa chỉ ip `192.168.1.1`, và để tìm `vendor name` của cơ sở hạ tầng mạng, chúng ta sẽ dựa vào 3 octet đầu của địa chỉ MAC.

<img width="1250" height="725" alt="image" src="https://github.com/user-attachments/assets/815cda00-50ed-471c-a2ed-a097db739b94" />

Theo cấu trúc của địa chỉ MAC thì 3 octet đầu sẽ là (OUI - Organizationally Unique Identifier) mã định danh duy nhất cho nhà sản xuất, còn 3 octet sau chính là `NIC (Network Interface Controller)` mã định danh duy nhất mà nhà sản xuất gán cho từng thiết bị.

Để tìm được `vendor_name` của default gateway thì chỉ cần tìm được địa chỉ MAC là được.

**filter**: `arp.src.proto_ipv4 == 192.168.1.1`, thông thường default gateway sẽ cần biết địa chỉ MAC của các ip để có thể trả dữ liệu về đúng nơi.

<img width="1837" height="1006" alt="image" src="https://github.com/user-attachments/assets/0aa013d2-9f59-4d88-ba22-459e28befdbf" />

Ở đây ta có thể thấy được 3 octet đầu của địa chỉ MAC của default gateway `192.168.1.1` là vendor name của nó: 

<img width="630" height="81" alt="image" src="https://github.com/user-attachments/assets/499c1a24-48a1-4be9-aa70-fb7adbc4ef88" />

Em lấy địa chỉ MAC này, đem lên OUI lookup để xem tên vendor chuẩn là gì.

<img width="959" height="267" alt="image" src="https://github.com/user-attachments/assets/53f365f8-c96e-454d-a661-b2480b2b65f3" />

**KCTF{Netis_Technology}**

## Exploitation

<img width="861" height="764" alt="image" src="https://github.com/user-attachments/assets/5ee7a67a-830a-464e-95a3-53d732dc9a82" />

Link file 2: **https://drive.google.com/file/d/1r5Huq9jVrcNGMP-eX2qMgaHoD6bQpV6U/view?usp=sharing**

Trong câu này, thì kẻ tấn công đã xác định được ứng dụng Web của công ty này, bây giờ chúng ta cần xác định được tên của người dùng liên quan đến ứng dụng Web này cùng với version của trang web.

<img width="1539" height="576" alt="image" src="https://github.com/user-attachments/assets/f91830ec-b7ec-48cd-b659-e44e71056f0e" />

Ở đây có vẻ kẻ tấn công, đang cố gắng tấn công và đánh cắp dữ liệu của trang web này, theo kĩ thuật `fuzzing`, hắn dùng các đường dẫn tới các thư mục liên quan đến `passwd, history,...`, mục đích là hắn xem có file nào bị bỏ xót trên server không để đánh cắp đi các thông tin nhạy cảm, cùng với kĩ thuật `SQL Injection`. 

<img width="1748" height="224" alt="image" src="https://github.com/user-attachments/assets/18c80d92-f6f4-4ad0-a308-063d52c8f578" />

Hắn cố gắng bypass qua trang login.php thông qua cách tấn công `SQL Injection` bằng cách hắn thực hiện `wp-login.php?redirect_to=%27%20OR%20%271%27=%271`. Nhưng khi em đọc log bên trong trang Web này thì hầu hết mọi payload của attacker cố tình tiêm sql vào đều bị server đã thực hiện vệ sinh `%27%20OR%20%271%27=%271`, đoạn mã độc này sang, dạng các dấu `/` để có thể làm sạch đoạn mã độc `'`.

`<input type="hidden" name="redirect_to" value="\&#039; OR \&#039;1\&#039;=\&#039;1" />`


Sau 1 lúc tìm kiếm thì mình có thấy kẻ tấn công sử dụng REST API: `/wp-json/wp/v2/users` để liệt kê danh sách user công khai trên trang web, có thể tìm hiểu thêm về [JSON_API_USERS](https://vi.wordpress.org/plugins/json-api-user/).

Tiếp theo, khi em filter qua `http.request.method == POST`, thì em thấy:

<img width="1912" height="203" alt="image" src="https://github.com/user-attachments/assets/402cd491-926a-4525-aebc-448c3d219793" />

Em follow vào trong cả 3 packet thì em tìm được thông tin ở packet thứ 2 như sau:

<img width="1243" height="697" alt="image" src="https://github.com/user-attachments/assets/71fdb202-83e4-47d9-ad68-5892903f6dac" />

Ở đây có thể kẻ tấn công đã tìm dược tên user bên trong API Users kia và đã có được tên users này, cùng với việc bruteforce mật khẩu thử, đặc biệt hơn là server đã trả về kết quả là tên users đã đúng, qua dòng log này:

<img width="1238" height="267" alt="image" src="https://github.com/user-attachments/assets/05caf644-5dbe-4a55-a9e3-d28d44772936" />

Vậy thì hiện tại chúng ta đã xác định được tên người dùng của ứng dụng web này lầ: `kadmin_user`. Đồng thời thì chúng ta cũng xác định được version của trang web là `6.9` thông qua phần header của trang `login.php` này.

<img width="1258" height="360" alt="image" src="https://github.com/user-attachments/assets/ee687c65-496a-4b13-b5b1-f08198ac4c66" />

Đây là bước mà kẻ tấn công đang thực hiện, dùng users đã dò được từ trước để bắt đầu brute force, xem mình có thể truy cập trái phép vào được một tài khoản của trang web để thực hiện cài mã độc thông qua cách này không.



## Vulnerability Exploitation

<img width="863" height="785" alt="image" src="https://github.com/user-attachments/assets/932e1f72-6249-4589-acee-04a4671b6f46" />

Tình huống tiếp theo trong chains tấn công này, là kẻ tấn công đã bắt đầu có thâm nhập vào được trang web thông qua một lỗ hổng plugins. Bây giờ chúng ta cần điều tra xem lỗ hổng đã được khai thác là gì.

Em dựa vào thông tin mình biết được tên ứng dụng Web là `WordPress` cùn với biết được là lỗ hổng của plugins, thì em tìm hiểu được trên mạng 1 lỗ hổng của plugins: `Social Warface`, tình cờ trong lúc em phân tích trang `login.php` mà kẻ tấn công đã thực hiện đăng nhập cũng có hiển thị plugins này trên thanh url: `http://192.168.1.102/wordpress/wp-content/plugins/social-warfare/assets/js/post-editor/dist/blocks.style.build.css?ver=6.9`. Cách kẻ tấn công lợi dụng lỗ hổng này, em lên mạng tìm hiểu thêm thì nó nằm ở trong logic code của chức năng nằm trong file: `wp-admin/admin-post.php`. Đây là chức năng giúp trang web WordPress có thể tự động debug và cập nhập cấu hình từ xa.

Khi server kiểm tra tham số `swp_debug` trên thanh url nếu nó được set `swp_debug=load_options`, thì lúc này nó sẽ tiếp tục thực hiện đọc tham số `swp_url` để lấy 1 đường dẫn. Và server sẽ tự động truy cập vào đường dẫn đó để tải nội dung về. Nội dung của nó sẽ nằm trong 1 thẻ `<pre>  </pre>` và thực hiện chạy hàm `eval()` nội dung trong thẻ đó. Đặc biệt là hàm `eval()` sẽ thực thi mã ngay lập tức mà không đi qua khâu kiểm tra thử. Đó là điểm mà attacker khai thác vào.



## Post-Exploitation

<img width="866" height="799" alt="image" src="https://github.com/user-attachments/assets/33135283-4789-47a2-b90c-25104cfdb110" />




