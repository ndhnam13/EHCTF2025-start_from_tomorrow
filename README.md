# 5 Forensic, 1 RE
## Mục lục
- [Forensic: Me ni mieru tokoro ni kakusarete iru](#forensic-me-ni-mieru-tokoro-ni-kakusarete-iru)
- [Forensic: DFIR 01](#forensic-dfir-01)
- [Forensic: DFIR 02](#forensic-dfir-02)
- [Forensic: DFIR 03](#forensic-dfir-03)
- [Forensic: DFIR 04](#forensic-dfir-04)
- [RE: DFIR 05](#re-dfir-05)
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

# Forensic: DFIR 01
https://ehctf-2025-public.s3.ap-southeast-1.amazonaws.com/Evidence.rar
![image](https://github.com/user-attachments/assets/874eb7a0-cca9-43f4-8e20-afdd37506d13)

https://www.foxtonforensics.com/browser-history-examiner/chrome-history-location

https://medium.com/@laurent.mandine/browser-forensics-89429fe0749f

Để kiểm tra disk image có thể dùng FTK imager

ABQ tải xuống một file lạ, nếu kiểm trong thư mục download của user `anhyeuem` sẽ không thấy gì, có thể file độc đã bị xoá

Các trình duyệt thường lưu trữ lịch sử của người dùng trong thư mục `C:\Users\<username>\AppData\...`, kiểm tra qua các file của ổ đĩa này ta chỉ thấy có Google Chrome, không có opera (vẫn có thư mục opera ở trong `Program Files (x86)` nhưng trong đó lại chứa một file .exe rất lạ? `kumi.exe`-sẽ dùng để làm bài dfir05), firefox 

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

# RE: DFIR 05
![image](https://github.com/user-attachments/assets/cb876cab-750e-4a1e-b210-a36bc61330de)

Quay trở lại với file `a83fc152b20b_miku haiten.exe` nếu mở lên sẽ bảo tải một file gì đó vào thư mục `C:\Program Files (x86)\Opera\miku haiten\`

![image](https://github.com/user-attachments/assets/8b533b40-51d1-4277-b4eb-1ab1ab530a5f)

![image](https://github.com/user-attachments/assets/182ceece-af32-47a7-8938-5f3c0f6a80ed)

`kumi.exe` là file chứa mã độc cần phải phân tích

Muốn biết `kumi.exe` sử dụng phần mềm gì để download background thì cần đưa nó vào một trình dịch ngược để phân tích code gốc, nếu muốn biết file được viết bằng gì có thể dùng phần mềm DiE-detect it easy

PHÂN TÍCH `kumi.exe`:
- Đưa vào DiE để tự động scan
- ![image](https://github.com/user-attachments/assets/fe961475-5617-485b-820d-2f3f20163919)
- Kết quả trả về là 1 file C/C++, nếu load file này trong IDA sẽ mất rất lâu?
- Đoạn này được a tmq hint là DiE báo là C/C++ nhưng có thể file đã đánh lừa tool
- Nghe xong thấy cũng hợp lí bởi vì `kumi.exe` hoạt động khá đơn giản, add `opera_update.exe` vào registry run key, start up folder khiến nó chạy mỗi khi mở máy. Mà cả 2 file này lại nặng tận 64,3MB chúng tỏ đã bị thêm gì đó vào
- Nếu đưa chatgpt phân tích trả về 3 kq Pascal, C#, Rust
- ![image](https://github.com/user-attachments/assets/2063b8c5-9aee-45b9-9ecc-75291ccf5bbd)
- Sử dụng 1 loại scan khác là Yara rules trên DiE ở mục packer có được kết quả `NETDLLMicrosoft`, ở đây em đoán là file .NET này đã bị đóng gói và chèn dữ liệu vào header khiến DiE scan ra 1 file C++ compiled = VS
- ![image](https://github.com/user-attachments/assets/f1494964-f75d-4cdd-baa4-d357d818d140)
- Hmmm vậy đây có thể là một file Microsoft .NET, tìm trên [google](https://www.moserware.com/2007/11/mz-bsjb-and-joys-of-magic-constants-in.html) ta biết một file .NET bị packed/obfuscated sẽ có signature BSJB(0x425A4342)
- ![image](https://github.com/user-attachments/assets/14c40492-356a-4270-9703-81751f731eee)
- Khá hay nếu ta google [v4.0.30.319](https://www.google.com/search?q=v4.0.30.319&oq=v4.0.30.319&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBBzM1NmowajeoAgiwAgHxBTFjh4m3H0BA&sourceid=chrome&ie=UTF-8) đây là 1 phiên bản của netframework, tới đây khá chắc chắn `kumi.exe` là file .NET rồi
- Cho vào trong Jetbrains dotPeek tại phần namespace ta thấy được code gốc của `kumi.exe` và cách nó hoạt động, sử dụng file `certutil.exe` để download background 
- ![image](https://github.com/user-attachments/assets/90da5be6-793a-4b08-b80b-04c7110c9c5d)

EHCTF{certutil.exe}
