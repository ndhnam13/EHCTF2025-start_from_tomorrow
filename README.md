# 5 Forensic, 1 RE
# Forensic: Me ni mieru tokoro ni kakusarete iru
![image](https://github.com/user-attachments/assets/09062877-cbfb-41ba-8c3f-56dab0a00fc4)

![FOR_2](https://github.com/user-attachments/assets/00b50a26-ba28-41c2-9f29-a6f92ae70d81)

https://stackoverflow.com/questions/29529771/position-of-width-and-height-in-jpeg-header-structure

Phần mô tả nhắc đến "Một bản tàng hình", "Hình dạng không có trong ảnh", "Cây tre, chỉ kích thước" và dạng stego nên nghĩ đến việc làm cho hình ảnh cao ra như cây tre

Có thể thay đổi chiều cao của ảnh bằng cách chỉnh hex của file, 2 byte chiều cao thường nằm sau các byte `FF C0 08` nằm ở dòng 290

![image](https://github.com/user-attachments/assets/bb6594be-305f-4550-9e2b-3222448ee539)

Chỉnh 2 byte chiều cao bằng ghex

![image](https://github.com/user-attachments/assets/ef22af7a-2caf-4003-be6f-d9163e9a71d2)  ![image](https://github.com/user-attachments/assets/430861ba-76dd-4b03-8f3d-4d2828571e62)

Lưu lại và ra flag

![FOR_2](https://github.com/user-attachments/assets/2892445c-27bf-4782-b5cc-262c1815916c)

EHC{b13t_fl4g5tructur3_r01_d0}

# DFIR 01
https://ehctf-2025-public.s3.ap-southeast-1.amazonaws.com/Evidence.rar
![image](https://github.com/user-attachments/assets/874eb7a0-cca9-43f4-8e20-afdd37506d13)

https://www.foxtonforensics.com/browser-history-examiner/chrome-history-location

https://medium.com/@laurent.mandine/browser-forensics-89429fe0749f

Để kiểm tra disk image có thể dùng FTK imager

ABQ tải xuống một file lạ, nếu kiểm trong thư mục download của user `anhyeuem` sẽ không thấy gì, có thể file độc đã bị xoá

Các trình duyệt thường lưu trữ lịch sử của người dùng trong thư mục `C:\Users\<username>\AppData\...`, kiểm tra qua các file của ổ đĩa này ta chỉ thấy có Google Chrome, không có opera (Nên ghi nhớ, sẽ liên quan đến DFIR 04), firefox 

Export file `C:\Users\anhyeuem\AppData\Local\Google\Chrome\User Data\Default\History` ra và có thể xem = phần mềm DB browser

Open database và vào phần download ta thấy link tải phần mềm và tên của phần mềm độc cũng là flag

![image](https://github.com/user-attachments/assets/3ba7f74f-47c5-4902-a065-bada08b36bbf)

EHCTF{https://files.sakamoto.moe/a83fc152b20b_miku%20haiten.exe}
# Forensic: DFIR 02
![image](https://github.com/user-attachments/assets/bc06d1d3-806e-41e1-978b-de4acc2dc3da)

Ta có thể tải file về = cách nhấn vào url hoặc xem phần đuôi của url đó (Dấu cách trong một cái url = %20 nên bỏ %20 đi) `a83fc152b20b_miku haiten.exe` 

EHCTF{a83fc152b20b_miku haiten.exe}

# Forensic: DFIR 03
![image](https://github.com/user-attachments/assets/09b48541-3ae4-4c47-916d-4895945d1079)

https://attack.mitre.org/techniques/enterprise/

Máy ABQ bị dính mã độc persistence, mô tả nói rằng máy gặp vấn đề khi khởi động lại => Tìm kiếm trên https://attack.mitre.org/techniques/enterprise/ ta thấy có T1547.001 khá khớp với mô tả

![image](https://github.com/user-attachments/assets/dbad2c8e-62e8-40a7-937c-48c81dc19938)

EHCTF{T1547.001}

# Forensic: DFIR 04
![image](https://github.com/user-attachments/assets/00827da1-55cf-4e49-9baf-158de5e1d99e)

Để tìm ra path của file thực thi persistent T1547.001 "Registry Run Keys / Startup Folder" theo https://attack.mitre.org/techniques/T1547/001/ sẽ thường nằm trong

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

"HKEY_CURRENT_USER",... được gọi là các registry hive ta có thể tìm thấy chúng trong file `NTUSER.DAT` (Thực ra đoạn này a tmq bảo là xem NTUSER.DAT) https://answers.microsoft.com/en-us/windows/forum/all/what-is-the-ntuserdat-file/fd3f2951-1691-4caf-ba1e-97864b1e2a57

Nói chung là `NTUSER.DAT` được Windows tự tạo trong thư mục của người dùng `C:\Users\anhyeuem\NTUSER.DAT` lưu thông tin về các settings của người dùng - Mã độc persistence này chạy một phần mềm trên máy mỗi khi startup nên ta có thể sẽ tìm được path đến file đó tại đây

Để xem `NTUSER.DAT` ta dùng phần mềm `Registry Explorer`, đoạn này a tmq có hint lần nữa là các phần chứa flag sẽ thường có tên khác thường cho nên trong phần `Software\Microsoft\Windows\CurrentVersion\Run` ta thấy một cột có value khá lạ dẫn đến file `opera_update.exe` (Mà trong máy ABQ còn không tải trình duyệt opera về)

![image](https://github.com/user-attachments/assets/2c358258-23b5-4dd0-894c-37794d9f92b8)

`opera_update.exe` sẽ tự động chạy mỗi khi mở máy - Nếu export file này ra và chạy trên máy ảo sẽ tự động bật chrome lên và liên tục mở các tab 2ten mới cùng với đó là đặt hình nền thành màu đen => Flag

EHCTF{C:\Users\anhyeuem\AppData\Local\Temp\opera_update.exe}

# RE: DIFR 05
