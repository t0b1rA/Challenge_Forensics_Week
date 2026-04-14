# Davy Jones Messages 

<img width="1123" height="692" alt="Screenshot 2026-04-04 123516" src="https://github.com/user-attachments/assets/8f467fb3-1b90-4650-8591-9e23dbb2cb57" />

Link challenge: 

Description: When sailors get lost, sometimes they will put a message in a bottle and set it off to sea in search of help. You sailor, have come across one of these bottles. Only thing is- it's broken. Something might be hidden here, if you can figure it out...
dịch

Challenge này mình sẽ cung cấp cho chúng ta 1 file pcap, và mình cần phân tích qua các gói tin trong đây và tìm ra thông điệp ẩn được xé nhỏ ra trong từng packet. Đầu tiên khi mở file pcap lên, thì mình sẽ thấy được ip `10.42.0.11` đang thực hiện dùng ICMP protocol, cho mục đích quét các cổng hiện đang mở của ip `10.42.0.10`. 

<img width="1892" height="1052" alt="image" src="https://github.com/user-attachments/assets/ebfddf2c-0206-4f5a-9729-76566f7b5eb5" />


> 1 đặc điểm của cách dò cổng này nhanh hơn so với cách sử dụng giao thức TCP, bởi vì các packet với protocol ICMP, thì hầu hết đều được vận đi bằng giao thức UDP, và 1 đặc điểm của UDP là khong resend, và khi thực hiện gửi 1 packet di đến 1 port mà bị chặn, nó sẽ được đánh dấu là `Unreachable Port` tức là port đó đang đóng.

Sau đó, mình vào `statistic protocol hierachy` thì mình thấy được hầu hết các gói tin đều được hầu hết các packet được vận đi bằng giao thức UDP, đều sử dụng giao thức `RTPS` 

> Một giao thức mạng lõi được sử dụng bởi hệ thống **DDS**. Phổ biến trong môi trường `ROS2` yêu cầu thời gian thực. Mình thấy nó có sự liên kết với 1 câu trước đó, cũng là giao thức được sử dụng trong môi trường `ROS2` này, nên mình nghĩ thông điệp hoặc payload sẽ chứa data liên quan đến tọa độ. Và các data được gửi đi đều phải tuân theo thời gian thực, vì giao thức này chuyên dùng để `live` nên cần tuân theo thời gian thực

<img width="1824" height="932" alt="image" src="https://github.com/user-attachments/assets/41e436ff-fa9c-4d89-a45f-858dfc4b418c" />

Tiếp theo, khi mình xét các luồng trong packet thì mình thấy được là: 

<img width="1856" height="582" alt="image" src="https://github.com/user-attachments/assets/18c57863-1fdf-416e-b7b7-bd82dbc0a401" />

Ở đây các gói tin từ `17-20` là quá trình mà giao thức `RTPS` đang thực hiện quá trình xác nhận kết nối, bởi vì giao thức `RTPS` là protocol ở tầng ứng dụng, còn packet được encapsulate ở tầng vận là giao thức `UDP` mà bản chất của UDP là không có cơ chế bắt tay như TCP để tạo 1 kết nối ổn định.  

- Các packet `INFO_DST, HEARTBEAT`: Mang ý nghĩa là đang kiểm tra và nhận diện nhau trong mạng, để chuẩn bị thực hiện gửi dữ liệu. 
- Packet `INFO_DST, ACKNACK`: là các gói tin được gửi đi từ 2 máy để xác nhận kết nối giữa các máy.

Lúc này thì 2 ip `10.42.0.11` và `10.42.0.10` thực hiện đồng bộ dữ liệu chuẩn bị được gửi đi bằng 2 packet `INFO_DST, INFO_TS, DATA, HEARTBREAK`:

- `INFO_TS` (infomation timestamp): đóng dấu thời gian chuẩn xác cho gói tin, bởi vì việc gửi các cục dữ liệu `live` yêu cầu khung thời gian phải được đồng bộ giữa 2 ip.
-  `DATA`: chính là cục chứa dữ liệu messages mà chúng ta cần tìm nằm ở đây.
-  `HEARTBEAT`: đi ngay sau chuỗi `DATA` để kêu các máy `dst` cần trả lời lại gói tin này để bắt đầu quá trình gửi dữ liệu.

Sau đó là quá trình ip `10.0.42.11` bắt đầu thực hiện gửi cho ip `10.42.0.10` các gói tin chứa dữ liệu, và phần data đó được nhét bên trong trường `serialization data` bên trong `RTPS`, nếu chúng ta để ý kĩ ban đầu chúng ta sẽ thấy ip này gửi bao gồm tổng 13 packet, được đánh số `writenumber 2-14`. Giờ mình sẽ thử trích xuất cục dữ liệu đây ra xem nó là gì:

```
                                                                                                                                        
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/RITSEC_CTF_2026/Davy Jones' Message]
└─$ tshark -r davy_jones_message.pcap -Y "ip.src == 10.42.0.11 && rtps.issueData" -T fields -e rtps.issueData > data_of_11.bin
```
<img width="1493" height="857" alt="image" src="https://github.com/user-attachments/assets/62244620-d039-406f-8f6e-7696b482f752" />

Cục dữ liệu này từ ip `10.42.0.11` này gửi đi không chứa gì đặc biệt bên trong, nó chỉ làm nhiệm vụ khai báo tên Node `computer_control`, cùng với các kí tự null bytes.

Nhưng chúng ta cũng vẫn còn 1 luồng gửi dữ liệu từ `10.42.0.10` gửi cho `10.42.0.11`, đây chính là cục payload chính, và nó cực kì lớn. Ở đây chúng ta thấy cục payload mà `10.42.0.10` gửi đi, được khai báo bên trong trường `ipv4` với total leangth tổng gần `14k bytes`, nhưng trong 1 packet chứa 1 rules về **MTU - Maximum Transmission Unit** là lượng bytes tổng mà 1 packet có thể chứa là 1500 bytes.

<img width="1890" height="924" alt="image" src="https://github.com/user-attachments/assets/5916caf2-61e0-4f7c-bbda-3776cf613114" />

Vì vậy chúng ta có thể thấy được giao thức IP đã tách cục dữ liệu đó thành các fragments và đưa nó vào các tổng 9 packet, cũng đã được khai báo bên trong phần `Ipv4 fragments`. Bên trong đây sẽ chứa các bitmap để dựng nên thành 1 bức ảnh 3d, bây giờ mình sẽ bắt đầu thực hiện trích xuất các cục dữ liệu này ra. 

<img width="1111" height="733" alt="image" src="https://github.com/user-attachments/assets/371fd5f9-259f-45d4-a674-a9acb617525d" />

Sau đó, mình sẽ viết 1 script thực hiện ghép các bitmap này tạo thành 1 ảnh 3d, chứa messages của challenge này:
<details>
  <summary> Script davy messages views </summary>
  
```
#!/usr/bin/env python3
import argparse
import math
import struct
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
from mpl_toolkits.mplot3d import Axes3D


class CDRReader:
    def __init__(self, data: bytes, offset: int = 0, endian: str = '<'):
        self.data = data
        self.off = offset
        self.endian = endian

    def align(self, n: int) -> None:
        self.off = (self.off + (n - 1)) & ~(n - 1)

    def u8(self) -> int:
        self.align(1)
        v = self.data[self.off]
        self.off += 1
        return v

    def bool(self) -> bool:
        return bool(self.u8())

    def u32(self) -> int:
        self.align(4)
        v = struct.unpack_from(self.endian + 'I', self.data, self.off)[0]
        self.off += 4
        return v

    def i32(self) -> int:
        self.align(4)
        v = struct.unpack_from(self.endian + 'i', self.data, self.off)[0]
        self.off += 4
        return v

    def string(self) -> str:
        self.align(4)
        n = self.u32()
        raw = self.data[self.off:self.off + n]
        self.off += n
        if n and raw.endswith(b'\x00'):
            raw = raw[:-1]
        return raw.decode('utf-8', errors='replace')

    def bytes_seq(self) -> bytes:
        self.align(4)
        n = self.u32()
        raw = self.data[self.off:self.off + n]
        self.off += n
        return raw


def iter_pcap(path: str):
    with open(path, 'rb') as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise ValueError('Not a valid PCAP file')

        magic = gh[:4]
        if magic == b'\xd4\xc3\xb2\xa1':
            rec_fmt = '<IIII'
        elif magic == b'\xa1\xb2\xc3\xd4':
            rec_fmt = '>IIII'
        else:
            raise ValueError('Unsupported PCAP magic')

        idx = 0
        while True:
            ph = f.read(16)
            if not ph:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(rec_fmt, ph)
            data = f.read(incl_len)
            idx += 1
            yield idx, ts_sec + ts_usec / 1e6, data


def iter_reassembled_ip_payloads(path: str):
    fragments = defaultdict(list)

    for idx, ts, frame in iter_pcap(path):
        if len(frame) < 14:
            continue
        eth_type = struct.unpack('!H', frame[12:14])[0]
        if eth_type != 0x0800:
            continue

        if len(frame) < 34:
            continue

        ip = frame[14:]
        version_ihl = ip[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or len(ip) < ihl:
            continue

        total_length = struct.unpack('!H', ip[2:4])[0]
        if len(ip) < total_length:
            continue

        ident = struct.unpack('!H', ip[4:6])[0]
        flags_frag = struct.unpack('!H', ip[6:8])[0]
        proto = ip[9]
        src = ip[12:16]
        dst = ip[16:20]

        more_frags = bool(flags_frag & 0x2000)
        frag_offset = (flags_frag & 0x1FFF) * 8
        ip_payload = ip[ihl:total_length]

        if more_frags or frag_offset:
            key = (src, dst, proto, ident)
            fragments[key].append((frag_offset, more_frags, idx, ts, ip_payload))
        else:
            yield {
                'idx': idx,
                'ts': ts,
                'src': src,
                'dst': dst,
                'proto': proto,
                'payload': ip_payload,
            }

    for (src, dst, proto, ident), parts in sorted(
        fragments.items(), key=lambda kv: min(p[2] for p in kv[1])
    ):
        parts.sort(key=lambda x: x[0])
        payload = b''.join(p[4] for p in parts)
        yield {
            'idx': parts[0][2],
            'ts': parts[0][3],
            'src': src,
            'dst': dst,
            'proto': proto,
            'payload': payload,
            'fragment_count': len(parts),
        }


def parse_rtps_messages(rtps_bytes: bytes):
    if not rtps_bytes.startswith(b'RTPS') or len(rtps_bytes) < 20:
        return []

    out = []
    pos = 20  # RTPS header = 4 magic + 2 version + 2 vendor + 12 GUID prefix
    while pos + 4 <= len(rtps_bytes):
        submsg_id = rtps_bytes[pos]
        flags = rtps_bytes[pos + 1]
        endian = '<' if (flags & 0x01) else '>'
        octets_to_next = struct.unpack(endian + 'H', rtps_bytes[pos + 2:pos + 4])[0]

        if octets_to_next == 0:
            body = rtps_bytes[pos + 4:]
            out.append((submsg_id, flags, body))
            break

        body = rtps_bytes[pos + 4:pos + 4 + octets_to_next]
        out.append((submsg_id, flags, body))
        pos += 4 + octets_to_next

    return out


def parse_data_frag(body: bytes):
    if len(body) < 32:
        return None

    extra_flags, octets_to_inline_qos = struct.unpack('<HH', body[:4])
    reader_id = body[4:8]
    writer_id = body[8:12]
    sn_high = struct.unpack('<I', body[12:16])[0]
    sn_low = struct.unpack('<I', body[16:20])[0]
    writer_sn = (sn_high << 32) | sn_low
    fragment_starting_num = struct.unpack('<I', body[20:24])[0]
    fragments_in_submessage, fragment_size = struct.unpack('<HH', body[24:28])
    sample_size = struct.unpack('<I', body[28:32])[0]
    data = body[32:]

    return {
        'writer_sn': writer_sn,
        'fragment_starting_num': fragment_starting_num,
        'fragments_in_submessage': fragments_in_submessage,
        'fragment_size': fragment_size,
        'sample_size': sample_size,
        'data': data,
        'writer_id': writer_id,
        'reader_id': reader_id,
        'extra_flags': extra_flags,
        'octets_to_inline_qos': octets_to_inline_qos,
    }


def reconstruct_samples_from_pcap(path: str):
    sample_fragments = defaultdict(dict)
    sample_meta = {}

    for pkt in iter_reassembled_ip_payloads(path):
        if pkt['proto'] != 17 or len(pkt['payload']) < 8:
            continue

        udp = pkt['payload']
        src_port, dst_port, udp_len, udp_cksum = struct.unpack('!HHHH', udp[:8])
        udp_payload = udp[8:]

        if not udp_payload.startswith(b'RTPS'):
            continue

        for submsg_id, flags, body in parse_rtps_messages(udp_payload):
            if submsg_id != 0x16:  # DATA_FRAG
                continue

            df = parse_data_frag(body)
            if df is None:
                continue

            sn = df['writer_sn']
            sample_meta[sn] = (df['sample_size'], df['fragment_size'])
            start = df['fragment_starting_num']
            frag_size = df['fragment_size']
            blob = df['data']

            for i in range(df['fragments_in_submessage']):
                frag_num = start + i
                frag_bytes = blob[i * frag_size:(i + 1) * frag_size]
                if not frag_bytes:
                    break
                sample_fragments[sn][frag_num] = frag_bytes

    samples = {}
    for sn in sorted(sample_fragments):
        sample_size, frag_size = sample_meta[sn]
        total_frags = (sample_size + frag_size - 1) // frag_size
        if len(sample_fragments[sn]) != total_frags:
            missing = [i for i in range(1, total_frags + 1) if i not in sample_fragments[sn]]
            raise RuntimeError(f'writerSN={sn} is missing fragments: {missing[:10]}')

        joined = b''.join(sample_fragments[sn][i] for i in range(1, total_frags + 1))
        samples[sn] = joined[:sample_size]

    return samples


def parse_pointcloud2_sample(sample_bytes: bytes):
    if len(sample_bytes) < 4:
        raise ValueError('Sample too small')

    encapsulation = sample_bytes[:4]
    # For this PCAP it is 00 01 00 00 => little-endian CDR.
    cdr = CDRReader(sample_bytes, offset=4, endian='<')

    sec = cdr.i32()
    nanosec = cdr.u32()
    frame_id = cdr.string()
    height = cdr.u32()
    width = cdr.u32()
    field_count = cdr.u32()

    fields = []
    for _ in range(field_count):
        name = cdr.string()
        offset = cdr.u32()
        datatype = cdr.u8()
        cdr.align(4)
        count = cdr.u32()
        fields.append((name, offset, datatype, count))

    is_bigendian = cdr.bool()
    cdr.align(4)
    point_step = cdr.u32()
    row_step = cdr.u32()
    data = cdr.bytes_seq()
    is_dense = cdr.bool()

    return {
        'stamp_sec': sec,
        'stamp_nanosec': nanosec,
        'frame_id': frame_id,
        'height': height,
        'width': width,
        'fields': fields,
        'is_bigendian': is_bigendian,
        'point_step': point_step,
        'row_step': row_step,
        'data': data,
        'is_dense': is_dense,
        'encapsulation': encapsulation,
    }


def pointcloud2_to_xyz_rgb(pc):
    if pc['point_step'] != 16:
        raise ValueError(f"Unexpected point_step={pc['point_step']} (expected 16)")

    arr = np.frombuffer(pc['data'], dtype='<f4').reshape(-1, 4)
    xyz = arr[:, :3]
    rgb_u32 = arr[:, 3].view('<u4')
    rgb = np.stack([
        (rgb_u32 >> 16) & 0xFF,
        (rgb_u32 >> 8) & 0xFF,
        rgb_u32 & 0xFF,
    ], axis=1).astype(np.uint8)

    finite = np.isfinite(xyz).all(axis=1)
    return xyz[finite], rgb[finite]


def load_all_points(path: str, sn_min: int = None, sn_max: int = None):
    samples = reconstruct_samples_from_pcap(path)
    xyz_list = []
    rgb_list = []

    sns = sorted(samples)
    if sn_min is not None:
        sns = [sn for sn in sns if sn >= sn_min]
    if sn_max is not None:
        sns = [sn for sn in sns if sn <= sn_max]

    for sn in sns:
        pc = parse_pointcloud2_sample(samples[sn])
        xyz, rgb = pointcloud2_to_xyz_rgb(pc)
        xyz_list.append(xyz)
        rgb_list.append(rgb)

    if not xyz_list:
        raise RuntimeError('No point clouds loaded')

    return np.concatenate(xyz_list, axis=0), np.concatenate(rgb_list, axis=0)


def plot_3d(xyz: np.ndarray, rgb: np.ndarray, stride: int = 1, size: float = 0.2):
    pts = xyz[::stride]
    cols = (rgb[::stride] / 255.0)

    fig = plt.figure(figsize=(12, 8))
    ax = fig.add_subplot(111, projection='3d')
    ax.scatter(pts[:, 0], pts[:, 1], pts[:, 2], c=cols, s=size, depthshade=False)
    ax.set_xlabel('x')
    ax.set_ylabel('y')
    ax.set_zlabel('z')
    ax.set_title('Reconstructed RTPS PointCloud2 (3D)')
    plt.tight_layout()
    plt.show()


def plot_wall_projection(xyz: np.ndarray, rgb: np.ndarray, wall_y: float = 0.0, eps: float = 0.02, size: float = 1.0):
    mask = np.abs(xyz[:, 1] - wall_y) <= eps
    wall = xyz[mask]
    wall_rgb = rgb[mask]

    if len(wall) == 0:
        raise RuntimeError('No wall points matched the y-filter')

    plt.figure(figsize=(16, 4))
    plt.scatter(wall[:, 0], wall[:, 2], c=wall_rgb / 255.0, s=size, marker='.')
    plt.gca().set_aspect('equal')
    plt.xlabel('x')
    plt.ylabel('z')
    plt.title(f'Wall projection (|y - {wall_y}| <= {eps})')
    plt.tight_layout()
    plt.show()


def main():
    ap = argparse.ArgumentParser(description='View the hidden 3D flag from davy_jones_message.pcap')
    ap.add_argument('pcap', help='Path to the PCAP file')
    ap.add_argument('--mode', choices=['3d', 'wall', 'both'], default='both', help='Which view to show')
    ap.add_argument('--sn-min', type=int, default=None, help='Minimum writerSN to include')
    ap.add_argument('--sn-max', type=int, default=None, help='Maximum writerSN to include')
    ap.add_argument('--stride', type=int, default=4, help='Take every Nth point in the 3D plot')
    ap.add_argument('--size3d', type=float, default=0.2, help='Marker size for 3D scatter')
    ap.add_argument('--wall-y', type=float, default=0.0, help='Y plane used for the wall projection')
    ap.add_argument('--wall-eps', type=float, default=0.02, help='Tolerance for selecting wall points')
    ap.add_argument('--wall-size', type=float, default=1.0, help='Marker size for wall projection')
    args = ap.parse_args()

    xyz, rgb = load_all_points(args.pcap, sn_min=args.sn_min, sn_max=args.sn_max)

    print(f'[+] Loaded {len(xyz):,} points')
    print(f'[+] x range: {xyz[:,0].min():.3f} .. {xyz[:,0].max():.3f}')
    print(f'[+] y range: {xyz[:,1].min():.3f} .. {xyz[:,1].max():.3f}')
    print(f'[+] z range: {xyz[:,2].min():.3f} .. {xyz[:,2].max():.3f}')

    if args.mode in ('3d', 'both'):
        plot_3d(xyz, rgb, stride=max(1, args.stride), size=args.size3d)

    if args.mode in ('wall', 'both'):
        plot_wall_projection(xyz, rgb, wall_y=args.wall_y, eps=args.wall_eps, size=args.wall_size)


if __name__ == '__main__':
    main()
```
</details>

<img width="1430" height="862" alt="image" src="https://github.com/user-attachments/assets/a74296be-b28a-420a-b7a6-f9de796b2df5" />

**flag: RS{D4vy_J0nes_Sp3aks_1n_51l3nce}**
---

<img width="1872" height="886" alt="image" src="https://github.com/user-attachments/assets/9080719f-c860-4dd9-980e-a086c0f82cf9" />

> Ở đây mình sẽ tìm hiểu qua cấu trúc của 1 packet `RTPS` được gửi từ ip `10.42.0.10` qua các data fragments là gì, để thực hiện hiểu rõ hơn về cách giao thức này hoạt động
> Đầu tiên chúng ta sẽ có 20 bytes đầu của packet RTPS: `52 54 50 53 02 01 01 10 01 10 35 9f 35 82 3e fb b1 1a 8b 20`
> - `52 54 50 53` ( 4 bytes - Magic bytes) **RTPS**, phần signatures để các công cụ phân tích lưu lượng mạng có thể nhận ra được.
> - `02 01` ( 2 bytes - version).
> - `01 10` (2 bytes - vendor ID): Chứa mã định danh của nhà phát triển phần mềm DDS.
> - `01 10 35 ... 8b 20` (12 bytes - GUID Prefix) Chứa unique ID của máy gửi packet này trên toàn lưới mạng.
> 
> Tiếp theo là phần Submessages. Mỗi Submessages luôn có một `Submessages Header` dài 4 bytes để mô tả hàng này dài bao nhiêu và chứa những gì.
> Structures ( 4 bytes ):
> 
> - `Submessages ID` (1 byte) Xác định packet này sẽ chứa phần nào (`0x15` = DATA, `0x09` = INFO_TS, `0x07` = HEARTBEAT).\
> - `flags` (1 byte) Các flags trạng thái.
> - `Length` (2 bytes) Độ dài của packet này.
> 
> **INFO_TS - (Infomation timestamp)**: là 20 bytes đầu `09 01 08 00 f1 1d ca 69 cc b6 79 9f`
> - `09` (ID) Mã unique của **INFO_TS**
> - `01` (flags) báo hiệu hệ thống đang dùng little-endian.
> - `08 00` (Length) Phần này dài 8 bytes (`0x0008`)
> - `f1 1d ca 69 cc b6 79 9f` ( 8 bytes data): chứa timestamp ghi lại chính xác thời gian gói tin này được gửi đi. Để đảm bảo việc đồng bộ dữ liệu gửi theo thời gian thực (real-time).
>
> **DATA**: là phần chuỗi còn lại với mở đầu là `15 05 50 01`
> - `15` (ID) của DATA.
> - `05` (flags) Chứa các cờ liên quan đến phần dữ liệu thực tế, và có attachment các tham số (Inline QoS).
> - `50 01` (Length): Độ dài của khối data.
