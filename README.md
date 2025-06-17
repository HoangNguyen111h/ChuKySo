# ChuKySo
Bai tap
📝 Giới thiệu
Ứng dụng web Ký Số & Xác Thực File giúp người dùng:

Tạo cặp khóa RSA (Private Key và Public Key)

Ký số file bằng Private Key

Xác thực chữ ký file bằng Public Key

Hiển thị lịch sử file đã ký và cho phép tải xuống

Hỗ trợ sao chép Private Key nhanh chóng chỉ bằng 1 click

Ứng dụng được phát triển với:

Python (Flask)

Cryptography (RSA + SHA-256)

HTML + TailwindCSS (giao diện hiện đại)


⚡ Cách sử dụng
🔑 Tạo cặp khóa
Nhấn Tạo Cặp Khóa Mới

Private Key hiển thị → Click vào để tự sao chép

Public Key hiển thị → Dùng để xác thực
https://github.com/HoangNguyen111h/ChuKySo/blob/main/Screenshot%202025-06-17%20234354.png

✍️ Ký số file
Chọn file cần ký

Nhập hoặc dán Private Key

(Tùy chọn) Nhập email nếu có chức năng gửi

Nhấn Tải lên và Ký số

Nhận file chữ ký .sig + public key .pub

🔍 Xác thực chữ ký
Chọn file gốc

Chọn file chữ ký (.sig)

Nhập Public Key

Nhấn Xác thực

Ứng dụng trả về kết quả:

🟢 Chữ ký hợp lệ

🔴 Chữ ký không hợp lệ

📜 Lịch sử
Hiển thị các file đã ký số

Cho phép tải về file gốc / chữ ký / public key
