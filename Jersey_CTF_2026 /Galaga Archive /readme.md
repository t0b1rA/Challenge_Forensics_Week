# Galaga Archive

<img width="612" height="672" alt="Screenshot 2026-04-19 012526" src="https://github.com/user-attachments/assets/9f4b86df-d73f-4cbd-a521-ab0d86061052" />

Link challenge: https://github.com/sajjadium/ctf-archives/tree/main/ctfs/JerseyCTF/2026/forensic/Galaga_Archive

Description: I heard rumors that there has been work on a second sequel to the original 1980's Galaga game! I was able to listen to some activity on their network, but it looks like I needed some authentication to reach the shared archive.

Flow của bài này, sẽ là ban đầu 1 client (ở đây là người sẽ leak thông tin ra sẽ có địa chỉ ip: `192.168.0.3`, máy này ngay từ ban đầu bên trong gói tin gửi request `AS-REQ` bằng giao thức kerberos đến cho `domain-controller - DC01` để được cung cấp ticket sử dụng các dịch vụ của server, thì nó đã là một máy trạm bên trong domain: 

<img width="1919" height="843" alt="image" src="https://github.com/user-attachments/assets/9a5a7de4-b6e6-4f86-bce4-f58f4b646a3c" />

Bởi vì việc cấp các ticket trong giao thức kerberos chỉ được thực hiện bởi `domain-controller`, và tất nhiên là để sử dụng các dịch vụ trong `domain-controller` thì attacker có thể đã đăng nhập vào được 1 máy bên trong, và đang sử dụng account `cname: galatic`, nó khác với context là một client bên ngoài internet cố gắng truy cập vào 1 máy chủ. 

Sau khi có được ticket, thì client này gửi các request tiếp tục xin các ticket để sử dụng 2 dịch vụ cụ thể bên trong `domain controller` là:

<img width="1683" height="774" alt="image" src="https://github.com/user-attachments/assets/2ede837b-f326-4565-89b0-a14beec11e85" />

> Ticket yêu cầu được sử dụng service (`cifs/DC01`) dùng để tải và upload lên bằng giao thức SMB.

<img width="1683" height="774" alt="image" src="https://github.com/user-attachments/assets/c18ede3e-f70e-4165-9350-1bf2f206478c" />

Tức là ở các bước ban đầu này,attacker đang thực hiện kết nối vào 1 tài khoản client bên trong server, sau đó xin được ticket `TGT` - đây là ticket được lấy từ bước client gửi `AS-REQ`, sau đó là sử dụng `TGT` để gửi đi các request sử dụng các dịch vụ khác bên trong `domain` từ ticket `TGS` - ticket được lấy từ khi client gửi các packet `TGS-REQ` lúc này client mới có thể sử dụng các dịch vụ như `smb` của domain để thực hiện tải file về máy mình cho quá trình leak dữ liệu.

<img width="2550" height="1224" alt="image" src="https://github.com/user-attachments/assets/57e0d98f-51c2-4be4-a5da-7d18bb496410" />

Sau 1 giai đoạn client này thực hiện kết nối đến các domain khong quá quan trọng trong challenge này như `\\DC-1\IPC$`, `\\DC-01\SYSVOl`, thì client bắt đầu đi tới giao thức `SMB` để thực hiện tải các file trong domain chia sẽ dữ liệu trong hệ thống này là `\\DC-01\GalaTwo`

<img width="2550" height="1224" alt="image" src="https://github.com/user-attachments/assets/6a2f6c55-34e2-4aeb-843d-300c9aae3828" />

Ở đây mình sẽ thấy client tải xuống 4 file sau:
- `Sharefolder_Meeting_Linkedin_POST.txt`
- `galatic_galaga_sequel.txt`
- `ideas1.txt`
- `ideas2.txt`

Thì bên trong đây các file quan trọng mình cần focus tới nó là `galatic_galaga_sequel.txt` và `ideas1,2.txt`:

Bên trong file `galatic_galaga_sequel.txt` chúng ta sẽ được cung cấp một hint quan trọng để làm bài này:

<img width="740" height="126" alt="image" src="https://github.com/user-attachments/assets/862f5f7b-ec73-449a-8eec-44eb8b0fa746" />

> _Để đọc được nội dung bên trong 2 file `ideas1,2.txt` chúng ta cần có password của client "tech developer account" để có thể thực hiện phép xor ra nội dung bên trong._

Và trong challenge này tech developer account chính là tài khoản galatic, để có được password có user này, thì mình đã tìm kiếm khá lâu trong tất cả các packet, thì mình mới phát hiện được 1 điểm quan trọng, trong request `AS-REQ` trước đó mà user galatic thực hiện tải về các file quan trọng:

<img width="1169" height="552" alt="image" src="https://github.com/user-attachments/assets/ea87390e-c468-47c9-894a-7d3a99bb1fe6" />

Server trả về 1 packet `AS-REP` chứa 1 đoạn ciphertext, đã được mã hóa bằng key mà server có được từ key của client, chính vì đoạn ciphertext này, chúng ta có thử crack được password thông qua cái ciphertext (asrep `enc-part`). Hơn nữa chúng ta cũng thấy được dạng mã hóa của ciphertext này là `etype = 23` tức là dạng `md5` dễ dàng crack được hơn, so với các packet ở phía trên, cũng có các thông tin như (cname = galatic, asrep `enc-part`,..., nhưng lại sử dụng etype = 18 mã hóa bằng thuật toán AES256). 

Giờ mình thực hiện trích xuất đoạn ciphertext đó ra bằng tshark:

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/jersey_CTF/galaga archive]
└─$ tshark -r galaga_galaxy_invaders2.pcap -Y 'kerberos && frame.number == 636' -T fields -e kerberos.encryptedKDCREPData_cipher 
6543d0743a6b31aa2cda4bc375da77c263c89aecbb673806a79be8e0a1880474939eaff30ce502ff48d6d89bc3f361e4d09a031b7b9f32ce96a8d9cba17774c4e4c6737764ea2f57e639334fad93d6b9269255749a67b0b4bfd7ca97a057e973516bf44d34cc19a95f5b9a6fac03be04fe3c1db5d95e5c45bad2335687f834b799e9b82fb74c6821ca3e62c03794c70958cc3b1a2d7c9fe327acf9ccb151bc1e459a2416da03bcec8a26e2427d14985998dfc40403c0d4e78090bcf7aa5375109c4f7b10c0dc29a63ecc25adb00418f9f283407a563131ec98516e3f0234907e62c36684f71762a7a37d894e8c8421a5a056e29cfee410a550df27eb2d94348a7f3e239f17ad

```

Sau đó sử dụng john để thực hiện crack theo format as-rep:

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/jersey_CTF/galaga archive]
└─$ john --format=krb5asrep asrep.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
galagalogz       ($krb5asrep$23$galatic@GALAGA.GALAXY.ORG)     
1g 0:00:00:05 DONE (2026-04-21 02:46) 0.1841g/s 1467Kp/s 1467Kc/s 1467KC/s galdoteamo..galabu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Sau khi có password ròi, mình bắt đầu thực hiện chuyển nó sang dạng sha256(password) `187b40e4bb750f5da6d92d137870c7ddabcb86c620f57f8cd8a332e6ae8fa587` và đem đi xor:

<img width="1014" height="859" alt="image" src="https://github.com/user-attachments/assets/fc87e0f2-f469-4cbf-8a5f-be6b61b743f0" />

Nhưng khi nếu đem đi xor với cùng key này với `ideas2.txt`, thì nó sẽ không thành công, mà chúng ta phải thực hiện lùi đi 10 offsets cho cái key vừa nãy, đây là 1 kỹ thuật của author dùng để làm cho challenge này khó hơn

Key sau khi lùi 10 offsets: `2d137870c7ddabcb86c620f57f8cd8a332e6ae8fa587187b40e4bb750f5da6d9`:

<img width="1026" height="850" alt="image" src="https://github.com/user-attachments/assets/67a401e2-389b-4f28-8c09-ef4fef941052" />

**flag: jctf{roasted_galatic_invaders}**



















