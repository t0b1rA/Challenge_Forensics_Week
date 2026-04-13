<img width="1919" height="974" alt="image" src="https://github.com/user-attachments/assets/8045d19c-4090-45ad-b4fd-9189cf6b3d17" /># Ocean Wildlife 

<img width="1113" height="651" alt="Screenshot 2026-04-04 133110" src="https://github.com/user-attachments/assets/cac66f7a-2683-4ac9-8f24-a93f4ae619ad" />

Link challenge: 

Description: Họ nói là đã nhặt được 1 cái chai và bên trong có 1 lời nhắn đến 1 điều gì đó khá lạ bên ngoài biển, và tự hỏi nó là gì. 

Trong challenge này mình sẽ được cung cấp 1 file `.yaml` - Một file cấu hình được viết bằng ngôn ngữ `YAML`, là dạng ngôn ngữ lập trình `human-readable` chứa các dữ liệu tuần tự, cùng với đó là 1 file database.

Mình thử mở xem nội dung của file database này chứa gi:

<img width="1919" height="974" alt="image" src="https://github.com/user-attachments/assets/996bdee1-18ab-4c3c-b704-9875afefee47" />

Bên trong file database này, chứa 1 bản ghi dữ liệu `ROS2` - (**Robot Operational System 2** một framework mã nguồn mở dùng để phát triển các phần mềm, ứng dụng của robot. Nó cung cấp các công cụ thư viện, quy ước đơn giản hóa việc tạo ra các phần mềm và ứng dụng liên quan đến robot. Và ben trong file database này cũng chứa các nội dung liên quan đến 1 robot `turtle`. Bên trong mục `topic` chứa các thông tin như:
- `turtlesim/pose` : chứa các giá trị **x/y** các góc quay và hướng di chuyển của con rùa.
- `turtle/color_sensor`: chứa các cảm biến màu được đặt trên nó.
- `draw_commands`: chứa các lệnh vẽ dưới dạng strings.

Và khi mình đọc thử file `.yaml` xem nó chứa các cấu hình cho các topic trên như thế nào thì nó chỉ chứa những file cấu hình giống với file `database`. Bây giờ mình thử xem nội dung thô của file `database` thử xem còn có thể giấu thêm thông tin ở đâu được khong

<img width="1469" height="750" alt="image" src="https://github.com/user-attachments/assets/13be3578-5819-4325-9d5f-855dee702822" />

Ngoài việc bên trong đây có chứa các giá trị `x/y` chứa tọa độ di chuyển của con rùa ra, thì chúng ta thấy bên trong đây chứa 1 flag được nhét bên trong giá trị `Finishing Draw`, mà bên trong file `database` không chứa các giá trị này. Mà chỉ chứa các cấu trúc định nghĩa phần cấu hình của từng topic bên trong database. Thực chất thì dữ liệu `finishing draw` chính là chuỗi sẽ được in ra trong dòng `std_msgs/msg/String`, nhưng việc chúng ta thấy nó bị kẹp bởi các kí tự rác, nên sqlite đã bỏ qua việc parse chuỗi trên, khiến cho dòng strings, lại thiết mất 1 dòng chuỗi của `draw_command`.

**flags: RS{f0ll0w_th3_5ea_Turtles}**




















