# Liberty 

<img width="1734" height="1217" alt="image" src="https://github.com/user-attachments/assets/7e977e1b-42b1-4ba1-be81-c1e9e9abbe7b" />

**Link lab**: https://app.hackthebox.com/sherlocks/Liberty

**Description**: Liberty launched a massive project with a budget exceeding $100 million, with the goal of granting true freedom to humanity.One day, a system administrator discovered a shared folder configured with “Full Control” permissions granted to “Everyone”, raising concerns about a potential security incident.You have been tasked with investigating evidence collected from the affected endpoint to determine what occurred. Threat Intelligence has previously identified that an employee’s credentials were harvested by a RedLine Stealer, which is suspected to have been used for initial access to this system.

Context của lab này, bên trong một server, administrator của họ tìm thấy một folder được shared với `full control` và cho phép truy cập bởi tất cả mọi người, sau đó `Threat Intelligence` đã xác nhận các thông tin bảo mật của các nhân viên bên trong công ty đã bị một mã độc tên là `Redline Stealer` - một mã độc đánh cắp thông tin được rao bán trên `Dark Web`, đóng vai trò cho phép attacker thực hiện các bước đầu xâm nhập vào hệ thống, và bây giờ cần chúng ta tiếp nhận điều tra

### Task 1: You suspect that a threat actor might conduct password spraying attack on this server, How many failed logon attempts identified before successfully identifying the correct pair of the credential?

Để biết được có bao nhiêu lần đăng nhập thất bại trước khi có lần thành công, chúng ta sẽ cần dựa vào file `Security.evtx`, được lấy từ bên trong path đến folder `Liberty/Windows/System32/winevt/Logs/Security.evtx`, khi đó mình sẽ dựa vào event id đăng nhập thất bại và thành công vào hệ thống trong windows là `4624, 4625`, để thực hiện tìm kiếm, đến 1 lúc thì mình nhìn thấy:

<img width="2729" height="239" alt="image" src="https://github.com/user-attachments/assets/a171359f-ca9b-4f04-9b4f-321d5348c12d" />

Chúng ta có thể thấy xuất hiện 6 logs thực hiện đăng nhập vào 1 hệ thống vào cùng 1s, đặc biệt hơn là nó đăng nhập 6 users account khác nhau, chứng minh được attacker sau khi đánh cấp được các thông tin của người dùng bằng mã độc `redline stealer` thì đã thực hiện rải mật khẩu để đăng nhập vào 1 trong các user, ở đây trong 6 logs thì có được 1 log sussessfully và 5 log failed.

<img width="1601" height="354" alt="image" src="https://github.com/user-attachments/assets/1c73ccb5-1ac1-4036-93f0-040c096cdc9a" />

### Task 2: What is the user that was identified by the threat actor?

Như chúng ta đã phân tích bên trên thì có 1 user account đã bị attacker thực hiện logon thành công từ mật khẩu đánh cấp được.

<img width="2753" height="1267" alt="image" src="https://github.com/user-attachments/assets/9f51eee7-ac69-4573-bcb3-5c73612533a9" />

Người may mắn ấy là `v.hunter`

<img width="1614" height="331" alt="image" src="https://github.com/user-attachments/assets/06acd662-41ca-4597-a5a9-d313b10e9c57" />

### Task 3: There is a shared folder that can be accessed by all users, what is the name of this shared folder?

Để tìm được name của share folder, bên trong một system windows, chúng ta cần export ra được hive registry `SYSTEM` trước, hive này thì nằm bên trong path `Liberty/Windows/System32/config/System`, sau đó thì để xem được name share folder chúng ta sẽ check registry key sau: `HKLM\SYSTEM\CURRENTCONTROLSET\SERVICE\LAMMANSERVER\SHARED` 

<img width="2440" height="780" alt="image" src="https://github.com/user-attachments/assets/c34b1128-5a1c-46bc-88c7-e505cb709367" />

Ở đây mình sẽ thấy được, mục **Share nameL: Proposal** 

<img width="1596" height="311" alt="image" src="https://github.com/user-attachments/assets/595397f7-4394-4514-a3aa-0660814e92e4" />

### Task 4: The threat actor uploaded several files to the previously identified shared folder. One of these files can be used to capture the hash of a user who opens it. What is the name of that file?

Trong câu này, mình sẽ có nhiều cách để tìm được file dùng để thu thập hash của user trong system mà những người mở nó, đây là 1 trong những kỹ thuật sub trong kỹ thuật **Hash leakage**, mà sau vài câu nữa, mình sẽ nói ra đầy đủ một chain attack khi sử dụng kỹ thuật này kết hợp với **CVE-2024‑43451**, bây giờ mình sẽ tìm file này trước. Theo cách của mình, thì theo mình đã tìm hiểu khi attacker đã tạo ra 1 folder cho phép mọi người có `full control` và `accessed` thoải mái vào, thì chắc chắn file thu thập hash cần nằm bên trong này.

Khi đó mình sẽ export file `$MFT` sau đó mình sẽ dùng `ctrl f` để tìm folder được dùng để share trước tên là `proposal` với tên gốc bên trong hệ thống là `project proposal`.

<img width="992" height="84" alt="image" src="https://github.com/user-attachments/assets/9cd2a9ae-adf4-48ef-a9a4-96ce9349ada9" />

Sau đó thì mình được 1 file tên là `proposal.url` nó nằm bên trong thư mục shared cho mọi người, và cũng trùng với 1 trong những điểm nhận dạng của 1 file được dùng cho kỹ thuật `Hash Leakage` thu thập NTLMv2 hash.

<img width="1591" height="364" alt="image" src="https://github.com/user-attachments/assets/3ca005ab-4e8b-4959-9b3d-a325ff0fb746" />

### Task 5: What is the full URL used by threat actor to mimic the fake proposal of the project?

Ở đây để chúng ta có thể tìm được full url được attacker sử dụng cho việc dựng nên 1 trang web khi người dùng click vào file `proposal.url` khi đó nó sẽ hiển thị ra 1 trang web fake, giúp cho hắn trông sẽ legit hơn so với việc nhập vào 1 file `.url` nhưng lại khong hiển thị ra gì, làm cho victim có thể nghi ngờ máy tính đã bị xâm nhập hoặc nhiễm virus.

Ở đây để tìm được full url, chúng ta cần sẽ truy cập vào folder chứa các database của `edge` bên trong path `Liberty/Users/l.texus/Appdata/Local/Microsoft/Edge/User data/Default` sau đó export file `History` ra để xem các `url` được sử dụng gần đây, nó sẽ lưu cả `url` fake được windows lưu lại mà attacker đã sử dụng để thiết kế ra 1 trang web giả mạo để qua mặt user.

<img width="1584" height="772" alt="image" src="https://github.com/user-attachments/assets/e0c56865-7f4c-48b8-b097-ad432903a57b" />

Sau đó, mình sẽ mở nó bằng `sqlite_database`, để xem nội dung database của lịch sử url, mà file này lưu lại:

<img width="1890" height="486" alt="image" src="https://github.com/user-attachments/assets/806d1c8d-1f65-4570-a647-aabea6275b37" />

Ở đây chúng ta sẽ thấy 1 url có tên là `proposal.html`, cùng tên với file `proposal.url` mà attacker dùng để thu thập hash của người dùng.

<img width="1136" height="225" alt="image" src="https://github.com/user-attachments/assets/4d11c781-f8d3-457d-9842-8226451e69be" />

## Task 6: What is the full UNC path of the network share that the threat actor used to capture hash of the victim?

Trước khi vào tìm đường dẫn `unc` của attacker đã sử dụng, mình sẽ nói qua 1 chút về kỹ thuật cũng như là lỗ hổng mà ở đây attacker đã khai thác dùng để triển khai được cách thức thu thập `hash NTLMv2` của user này khá hay

> Lỗ hổng `CVE-2024-43451` là 1 lỗ hổng trên Microsoft Windows, cho phép rò rỉ mã băm mật khẩu `NTLMv2 password hashes` của người dùng, với sự tương tác rất ít hoặc khong tương tác `Zero-click` từ người dùng cũng có thể thu thập được hash.
>
> Lỗ hổng này tồn tại do engine **MSHTML**- một thành phần cũ được sử dụng cho Internet Explorer (IE). Mặc dù **IE** đã bị khai tử, nhưng engine **MSHTML** vẫn được sử dụng trên các phiên bản Windows 10,11 để đảm bảo khả năng tương thích ngược. Đặc biệt là với các ứng dụng và giao diện vẫn còn dựa vào khả năng hiển thị web hoặc xử lý liên kết với file của người dùng.
>
> Một điều đặc biệt trên **IE** nó cho phép hiển thị path thư mục trong ổ đĩa trên thanh tìm kiếm của Explorer, và lưu các file chứa các đường dẫn `url` giúp cho việc truy cập vào 1 trang web, có thể diễn ra qua việc truy cập vào 1 file.
>
> Dựa vào sự phụ thuộc này cho phép các file `.url` âm thầm gọi các proccess xác thực `NTLM` thông qua đường link được attacker design đặc biệt, mà không nhất thiết phải nhấn open.
>
> Kẻ tấn công khai thác vào điểm yếu này, bằng cách ép Windows khởi tạo 1 quá tình xác thực NTLM qua giao thức SMB đến 1 máy chủ từ xa (C2 server) bằng định dạng 1 path **UNC**, khi đó mỗi khi người dùng đơn giản là _chuột phải vào file, kéo file qua folder khác, xóa file_ đều sẽ kích hoạt path `UNC` và thực hiện yêu cầu 1 quá trình identify và bắt đầu thu thập hash và gửi về server `SMB` giả mạo của attacker `vdu \\attacker.com\<username>`
> 

Chúng ta cũng hiểu được `chain exploit`, của `CVE-2024-43451` này rồi, bên trong file `url` sẽ chứa 1 đường dẫn `UNC` khác bên trong, để khi victim vô tình interact với file `url` này, sẽ thu thập ngay hash của victim và gửi về cho server của attacker, vậy chúng ta cần xem được nội dung file `url`.

Bên trong file FTK imager, thì attacker đã xóa di cả file `proposal.url` này rồi, nhưng vì **$MFT** có 1 cơ chế cho phép đọc được nội dung của 1 file, nếu size của file nhỏ hơn `900 bytes`, nên file $MFT sẽ lưu lại nội dung thô của file đó, và vì file `.url` này mình đã check bên trong `mft.csv` nó chỉ khoảng `139 bytes`

<img width="850" height="84" alt="image" src="https://github.com/user-attachments/assets/40ad8703-8e83-4e46-8a60-d8aab21fb117" />

Nên mình sẽ dùng công cụ `MFTECmd.exe` của Eric Zicmerman để dump toàn bộ nội dung thô của file `$MFT` ra 1 folder tên là `Resident` sau đó vào tìm file `proposal.url`.

<img width="1908" height="436" alt="image" src="https://github.com/user-attachments/assets/5a8254b4-8f8d-4e94-a343-04b4d74a0fc0" />

<img width="599" height="173" alt="image" src="https://github.com/user-attachments/assets/04b19666-b250-42e7-a4f2-a284e607198a" />

OK vậy, chúng ta có được **UNC path** chính là `\\192.168.189.129\%USERNAME%.icon`. Ở đây attacker sử dụng biến môi trường `%USERNAME%` đều là có lý do cả:

> Vì khi sử dụng biến môi trường là `%USERNAME%`, mỗi khi 1 người dùng vdu như `k.texus`, hay `nhatduy` bấm vào file này, nó sẽ gửi di một request với server của attacker với dạng `SMB Client <ip> request file \nhatduy.icon`, và kèm theo là hash của victim, để attacker có thể dễ dàng nhận dạng được các victim hắn đã gom được.


### Task 7: What is the format of the hash that the threat actor captured via this method?

Ở đây thì hash được sử dụng cho mật khẩu của người dùng trong version Windows 10,11 là **Net-NTLMv2**

<img width="742" height="239" alt="image" src="https://github.com/user-attachments/assets/1c32634a-ca8c-416b-a8c2-c5b3c238e647" />

### Task 8: What is the full name of the second compromised user?

Ở câu này, mình cũng dựa vào suy luận của mình, thì theo cách thu thập hash của attacker là bất kì ai sử dụng vào folder share `Project Proposal` đều sẽ bị thu thập hash, và hơn nữa khi phân tích file `HISTORY`  database của user `k.texus` chúng ta cũng thấy được người dùng này đã truy cập vào `url:  http://argonaut.ark/proposal.html` và mình nghĩ khả năng cao là user này đã bị thu thập hash, và attacker đã thực hiện brute force hash mk này và vào được máy của user này, biến `k.texus` thành user t2 bị compromised.

Sau đó mình vào folder `config` export hive registry `SAM` ra để lấy full name của user này:

<img width="1229" height="251" alt="image" src="https://github.com/user-attachments/assets/6311aa27-31e6-44f2-93b8-7652efa71a9b" />

**Kuneo Texus**

<img width="746" height="245" alt="image" src="https://github.com/user-attachments/assets/aa44d921-4688-4376-a749-4418cda98a24" />

### Task 9: When was the time that the threat actor connected to the server via RDP in UTC?

Chúng ta biết user `k.texus` này đã bị compromised rồi và với câu hỏi này có thể hắn đã đăng nhập qua giao thức RDP `Remote desktop protocol`, mình sẽ vào file `security.evtx` tìm event id đăng nhập success là `4624` cùng với logon type `10` và user account là `k.texus`:

<img width="1296" height="493" alt="image" src="https://github.com/user-attachments/assets/b590cd9f-6ce4-4fb7-ae50-ef63f36578ba" />

<img width="741" height="250" alt="image" src="https://github.com/user-attachments/assets/34178b77-0f10-4d55-a847-1296ac8aaf3b" />

> Bởi vì công cụ `event viewer` sẽ tự động chuyển giờ UTC về giờ khu vực miền ở Việt Nam, nên để đổi lại về giờ UTC chúng ta cần -7h đi sẽ ra giờ gốc.


### Task 10: The threat actor discovered a folder that stores files about the project, What is the full path of this folder?

Ở câu này, khi chúng ta để ý vào folder recent, mình cũng sẽ thấy được bên trong có 1 file `ProjectArk.lnk`, khi mình thực hiện dùng `LECmd.exe` để parse file này ra, thì sẽ có được đường dẫn của file này:

<img width="899" height="478" alt="image" src="https://github.com/user-attachments/assets/c9c0c48b-af49-4ef1-bc3a-1ae622a72d48" />

Việc mình nghi ngờ đây là folder attacker create cho việc lưu trữ các files trong dự án tấn công của hắn, là vì nó có phần `ark` giống với tên `url` fake mà hắn đã sử dụng, và cũng đồng thời user `k.texus` này đã có sử dụng nó nhiều lần nên mới tạo thành 1 file `.lnk`

<img width="741" height="248" alt="image" src="https://github.com/user-attachments/assets/07609bad-8b44-43d2-ab0c-6055488242af" />

## Task 11: The threat actor created an archive file containing all files of the previously identified folder, What is the name of this archive file?

Xét tiếp bên trong thư mục recent của user `k.texus` chúng ta sẽ thấy người này đã tạo ra 1 file `arkproj.zip` 

<img width="1590" height="528" alt="image" src="https://github.com/user-attachments/assets/41bd1391-e176-400c-be21-adc13ac78cd5" />

<img width="740" height="246" alt="image" src="https://github.com/user-attachments/assets/2ef9bb0d-bacb-422b-9b67-83e22f0191c8" />

### Task 12: What is the total bytes of all files on that folder which were compressed into previously identified archive file? (not including Zone Identifier)

Để tìm được các file nằm bên trong file zip này, vì các folder bên trong user `k.texus` khá ít, và trong mục `recent` cũng có khá ít file có khả năng, nên mình sẽ tận dụng file `$MFT`. 

Trước tiên thì mình nghĩ khả năng cao là attacker sẽ gom các file trong cùng 1 thư mục rồi nén lại, nên mình sẽ tìm thư mục chứa file `arkproj.zip` trước, bằng cách parse nó bằng `LECmd`

<img width="951" height="306" alt="image" src="https://github.com/user-attachments/assets/a7fd2013-5e74-4448-ae67-703089225352" />

Ở đây mình sẽ có được file `arkproj.zip` nằm bên trong thư mục `Projectark`, bởi vì theo hướng ban đầu mình sẽ check qua các file trong thư mục này bằng cách filter tên folder, trong file `$MFT`, khi đó kế bên nó sẽ hiện cả những file nằm trong `parrents folder`:

<img width="1016" height="141" alt="image" src="https://github.com/user-attachments/assets/eabb178a-8c54-4c2c-a191-afb98caa2ee3" />

- File đầu tiên `Allocated Budget planning.xlsx`

<img width="994" height="122" alt="image" src="https://github.com/user-attachments/assets/42cf3925-7b1f-465d-a79e-6a19df00ca0a" />

- File thứ 2 `Full timeline GANTT.xlsx`

<img width="1190" height="160" alt="image" src="https://github.com/user-attachments/assets/e9522164-5464-4758-b04d-deec108c164a" />

- File 3,4: `Project Ark Present to board.pptx`, `Project Ark Scope and Planing.docx`

<img width="1072" height="110" alt="image" src="https://github.com/user-attachments/assets/2b65f513-51e8-4e1b-8b67-b4f1ab7dba0e" />

- File 5,6: `Project Ark Scope and Planing.pdf`, `Strakeholders.xlsx`

<img width="1181" height="108" alt="image" src="https://github.com/user-attachments/assets/3356b679-b3a1-4349-b0fe-84826fb67a87" />

File cuối: `diagram.png`

Sau đó thực hiện cộng toàn bộ byte của tất cả các file lại mình sẽ có được: 

```
132,675 + 74,110 + 16,395 + 255,143 + 5,380 + 286,347 + 13,857 = 783,907
```
Và ghi theo format của bài sẽ bỏ phẩy nên là `783907`.

<img width="747" height="259" alt="image" src="https://github.com/user-attachments/assets/31048778-4ce0-4b56-a6fe-da5b57bf04aa" />

### Task 13: The threat actor uploaded the previously identified file to C2 website, What is the domain of this website?

Khi chúng ta phân tích file `HISTORY` database của user `k.texus` mình thấy user này có vẽ đã bị kết nối C2 về máy chủ của attacker, vì nhìn vào title của `url` này chúng ta sẽ thấy nó ghi là `upload file and download` - Các hành động đưa data của victim về server C2 của attacker, và thực hiện tải payload về máy victim.

<img width="1899" height="532" alt="image" src="https://github.com/user-attachments/assets/0353a49f-98ba-4e7b-a315-f59179df4c18" />

<img width="747" height="255" alt="image" src="https://github.com/user-attachments/assets/41379a52-4e90-4dce-ac79-35f56ae125bf" />

### Task 14: While reviewing users on this server, you found a suspicious user on this server, What is the name of this user?

Sau 1 lúc mình tìm kiếm thêm vào các file log bên trong hệ thống, thì mình có tìm thấy 3 file log ghi lại các hoạt động truy cập hoặc đăng nhập vào máy chủ web **IIS (Internet Information Service)**, một tính năng hợp lệ trên Windows, folder này chính là nơi mà một doanh nghiệp hay công ty đặt host server của web đang sử dụng dịch vụ **IIS** vào bên trong đây.

Vì vậy khi vào folder `inetpub` mình sẽ có được các file **Access Log** ghi lại các hoạt động đăng nhập vào hệ thống, và sau 1 lúc tìm kiếm bên trong các log thì mình tìm thấy 1 file log vào ngày xảy ra cuộc tấn công/compromissed của attacker ghi lại rất nhiều log

<img width="1161" height="901" alt="image" src="https://github.com/user-attachments/assets/025068e6-bbc8-4f3b-9d76-b30105ab47b1" />

Mình export ra, mở bằng notepad xem thử, thì thấy được bên trong ghi lại các hoạt động giữa server-ip (s-ip): `192.168.189.131` máy chủ **IIS** của hệ thống này, và client-ip (c-ip): `192.168.189.129`, chính là địa chỉ IP của attacker, mình dựa vào đường dẫn UNC path thu thập hash của kẻ tấn công từ trước đã có sử dụng địa chỉ ip này.

Các log ban đầu chỉ là quá trình tải về giao diện web trên màn hình của attacker thôi:

Sau đó, server đã trả về màn hình của attacker một trang `logon.aspx` để tiếp tục sử dụng, và hắn đã sử dụng user `t.minami` và đã đăng nhập thành công vào hệ thống. Sau đó thì hắn sử dụng account của user này thực thi khởi tạo một phiên kết nối để thực thi lệnh với server. 

Đầu tiên attacker yêu cầu tải về file `powershell.console.ui.js` (giao diện powershell) và gọi hàm `GetClientConfiguration` để khởi tạo 1 phiên kết nối.

Sau đó thì attacker bắt đầu quá trình tấn công bằng cách gọi hàm `ExecuteCommand` để thực hiện các lệnh powershell vào hệ thống, mình có check tại thời điểm này bên trong file log để kiểm tra file `Microsoft-Windows-PowerShell%4Operational.evtx` xem attacker đã thực hiện execute lệnh gì, thì vào thời điểm đó, trong log khong ghi lại được bất cứ cái gì:

<img width="1305" height="688" alt="image" src="https://github.com/user-attachments/assets/76cffe9e-c7b1-4f80-9435-ba68f22db3dc" />

Và cuối cùng là attacker thực hiện terminatedsession để chấm dứt phiên trò chuyện sau.

Qua log này thì mình cũng có thể nắm được users thứ 3 trở thành users bị attacker khai thác.

<img width="730" height="253" alt="image" src="https://github.com/user-attachments/assets/6d6fa3fd-a5b0-4965-929d-a395601dcd91" />

### Task 15: The threat actor installed a web-based gateway as a backdoor to the server. What is the full command used to install this feature?

Bây giờ mình quay lại với user `k.texus` và xem phần log consoles của user này xem đã thực thi những lệnh gi

```
Install-WindowsFeature -Name WindowsPowerShellWebAccess -IncludeManagementTools
Install-PswaWebApplication -UseTestCertificate
Add-PswaAuthorizationRule -UserName * -ComputerName * -ConfigurationName *
Enable-PSRemoting -Force
Test-WSMan
Get-Service -Name WinRM
net localgroup "remote management users" t.minami /add
net user t.minami

```
Đây chính là các lệnh để bắt đầu cho quá trình thực thi lệnh được ghi lại bên trong log của folder `inetpub` ban nãy mình có nói đến

```
Install-WindowsFeature -Name WindowsPowerShellWebAccess -IncludeManagementTools
Install-PswaWebApplication -UseTestCertificate
```
- Đầu tiên thì lệnh `Install-WindowsFeature -Name WindowsPowerShellWebAccess -IncludeManagementTools`, yêu cầu máy chủ Windows cài đặt thêm tính năng `PowerShell Web Access (PSWA)` cùng với các công cụ quản lý kèm theo. - Đây chính là lý do mà nãy chúng ta thấy attacker đã dùng hàm `ExecuteCommand` để có thể chạy được lệnh bên trong máy chủ web.

- Tiếp theo attacker dùng lệnh `Add-PswaAuthorizationRule -UserName * -ComputerName * -ConfigurationName *` để thực hiện cho phép mọi user đều có quyền truy cập vào bất cứ máy tính nào trong mạng, với bất cứ cấu hình nào.
> Bởi thông thường thì **PSWA** chặn các user khác có thể truy cập vào một máy tính khác để đảm bảo cơ chế bảo mật, thế nhưng ở đây attacker đã cấu hình cho phép mọi user đều có thể truy cập tùy ý.

- Sau đó là 3 lệnh thực hiện khởi động giao thức `WinRM`, mở các cổng 5985/5986 cho phép nhận lệnh từ xa. Cùng với tham số `force` ép hệ thống thực thi ngay.
```
Enable-PSRemoting -Force
Test-WSMan
Get-Service -Name WinRM
```
- Cuối cùng là lệnh thực hiện aduser `t.minami` vào nhóm đặc quyền **Remote Management Control User** cho phép sử dụng các quyền quản trị từ xa.

> Ở đây attacker đã sử dụng kĩ thuật **Living off the Land (LotL)** hắn khong dùng các công cụ độc hại hay gắn malware vào hệ thống để thực hiện persistence trong hệ thống, mà sử dụng chính các công cụ quản trị hệ thống hợp pháp của Windows xây dựng persistence.
>
>  Thay vì sử dụng 1 tài khoảng `k.texus` mặc dù với quyền quản trị cao, nhưng có thể user này sẽ đổi mật khẩu hoặc có thể phát hiện mình đã bị xâm nhập và khắc phục ngay. Thì attacker đã tạo cho mình cửa hậu `backdoor` bằng cách sử dụng chính mã băm NTLMv2 hash mà thu thập được của cả user `t.minami` để thực hiện truy cập vào hệ thống bằng 1 user khác để tránh bị phát hiện.

Command ở đây được sử dụng để tải thêm 1 tính năng `PowershellWebAccess`, để thực hiện quản lý truy cập từ xa bằng giao diện dòng lệnh là:

`Install-WindowsFeature -Name WindowsPowerShellWebAccess -IncludeManagementTools`.

<img width="747" height="260" alt="image" src="https://github.com/user-attachments/assets/94c84f2f-1642-4cd0-b319-b366c681a4dd" />

### Task 16: Which protocol has to be enabled to use this feature?

Như ở trên mình cũng đề cập tới 1 giao thức cho phép attacker thực thi được lệnh từ xa qua các cấu hình với firewall là `WinRM`.

<img width="760" height="223" alt="image" src="https://github.com/user-attachments/assets/93c4e56d-3e50-4328-a567-4604aac75777" />

### Task 17: Provide the UTC timestamp when the threat actor confirmed successful backdoor access through the previously identified user account.

```
2025-06-11 14:54:55 192.168.189.131 POST /pswa/en-US/logon.aspx ReturnUrl=%2fpswa%2f 443 - 192.168.189.129 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 https://192.168.189.131/pswa/en-US/logon.aspx?ReturnUrl=%2fpswa%2f 302 0 0 5389
2025-06-11 14:54:55 192.168.189.131 GET /pswa/ - 443 LIBERYSV08\t.minami 192.168.189.129 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 https://192.168.189.131/pswa/en-US/logon.aspx?ReturnUrl=%2fpswa%2f 302 0 0 58
```

2 log ghi lại attacker đã dùng account của `t.minami` truy cập thành công vào hệ thống để thực hiện tạo cửa hậu.

Time: `2025-06-11 14:54:55`

### Task 18: What is the Session ID of this connection?

Để biết được session id của một kết nối đến web server, ban đầu mình có check qua các file log như `SMB Client connectively`, `SMB server security`, `SMB Server Connectively` đều khong có kết quả gì, lúc này mình check kĩ lại thì thấy có 1 file log tên là `Web Access.evtx` nó sẽ lưu lại các truy cập của người dùng để bất kể trang web nào, và cũng có luôn cả server C2 của attacker tạo ra 1 log bên trong này:

<img width="1284" height="702" alt="image" src="https://github.com/user-attachments/assets/fc6ee82d-f601-4939-9da8-005293e465b1" />

Vào bên trong check chúng ta sẽ thấy ngay một session id được thiết lập cho user `t.minami` **LIBERYSV08\t.minami.250611.075455**.

### Task 19: Provide the UTC timestamp When was this session terminated by the threat actor

Mình check qua file log đã tìm được bên trong folder `Logfile\W3SVC1\`, trong file `u_ex250611.log`, khi lướt xuống bên dưới mình sẽ thấy 1 dòng log ghi lại thời điểm attacker thực hiện terminated session 
```
2025-06-11 14:55:40 192.168.189.131 POST /pswa/en-US/console.aspx/TerminateSession - 443 LIBERYSV08\t.minami 192.168.189.129 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 https://192.168.189.131/pswa/en-US/console.aspx 200 0 0 6
2025
```
Khoảng thời gian attacker thực hiện terminated session là: **2025-06-11 14:55:40**

### Task 20: What is the name of shared folder that was created by the threat actor during the invasion?

Khi chúng ta vào lại bên trong registry key `LammanServer`, và tìm vào subkey `security` mình sẽ thấy được bên trong đây ngoài folder `proposal`, vẫn còn 1 folder khác là `ProjectArk` cũng nằm trong phần **share folder** qua network, và chúng ta cũng đã phân tích qua 1 hoạt động bên trong thư mục này chính là việc chứa 1 file `arkproj.zip` bên trong chứa các bản dự án dì đấy.

Quá trình kẻ tấn công, trong bài này sau khi kẻ tấn công đã logon successfull vào user account `k.texus`, thì kẻ tấn công đã thực hiện tạo một share folder tên là `ProjectArk` sau đó gom toàn bộ các file dự án đưa vào trong thư mục share folder này, cũng có thể attacker đã tạo thư mục này, và đánh lừa các nhân viên khác đây là 1 folder chứa các file dự án chung, để mọi người gửi vào, sau đó hắn compress thành zip sau đó thực hiện upload lên server C2.

Còn share folder đầu tiên chúng ta phân tích `Proposal` - `Project Proposal` mục đích của folder này là để cho những user khác trong hệ thống, access vào file `proposal.url` dùng cho quá trình thu thập hash `NTLMv2` thông qua **path UNC**.

<img width="737" height="245" alt="image" src="https://github.com/user-attachments/assets/5ee38cbd-f05b-4a6c-a04d-2dab12bcc5d7" />

