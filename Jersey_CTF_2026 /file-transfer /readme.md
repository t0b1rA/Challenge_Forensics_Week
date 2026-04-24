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















