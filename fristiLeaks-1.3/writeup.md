
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
浏览器查看一下主页

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
<img src="https://raw.githubusercontent.com/eagleatman/mywriteup/main/fristiLeaks-1.3/images/1.png" width="56%" display="block">

同时/images/存在目录遍历，可以列出该目录下的所有内容。

# Exploitation

# Post-Exploitation

# Privilege Escalation

# Conclusion

