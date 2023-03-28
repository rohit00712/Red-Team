
# Introduction to Antivirus

Understand how antivirus software works and what detection techniques are used to bypass malicious file checks.

Antivirus (AV) software is one of the essential host-based security solutions available to detect and prevent malware attacks within the end-user's machine. AV software consists of different modules, features, and detection techniques, which are discussed in this room.

As a red teamer or pentester, it is essential to be familiar with and understand how AV software and its detection techniques work. Once this knowledge is acquired, it will be easier to work toward AV evasion techniques.

## AV Testing Environment 

* [VirusTotal](https://www.virustotal.com/) 

### VirusTotal alternatives

* [AntiscanMe](https://antiscan.me/) (6 free scans a day)
* [Virus Scan Jotti's malware scan](https://virusscan.jotti.org/)

## Fingerprinting AV software

As a red teamer, we do not know what AV software is in place once we gain initial access to a target machine. Therefore, it is important to find and identify what host-based security products are installed, including AV software. AV fingerprinting is an essential process to determine which AV vendor is present. Knowing which AV software is installed is also quite helpful in creating the same environment to test bypass techniques.  

This section introduces different ways to look at and identify antivirus software based on static artifacts, including service names, process names, domain names, registry keys, and filesystems.

The following table contains well-known and commonly used AV software. 

| Antivirus Name | Service Name     | Process Name                |
| :-------- | :------- | :------------------------- |
| Microsoft Defender | WinDefend | MSMpEng.exe |
| Trend Micro |	TMBMSRV	| TMBMSRV.exe |
|Avira	| AntivirService, Avira.ServiceHost |	avguard.exe, Avira.ServiceHost.exe |
| Bitdefender |	VSSERV	| bdagent.exe, vsserv.exe |
| Kaspersky |	AVP<Version #> |	avp.exe, ksde.exe |
|AVG |	AVG Antivirus |	AVGSvc.exe |
| Norton |	Norton Security |	NortonSecurity.exe |
| McAfee |	McAPExe, Mfemms |	MCAPExe.exe, mfemms.exe |
| Panda |	PavPrSvr |	PavPrSvr.exe |
| Avast	 |Avast Antivirus |	afwServ.exe, AvastSvc.exe |

## SharpEDRChecker

One way to fingerprint AV is by using public tools such as [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker). It is written in C# and performs various checks on a target machine, including checks for AV software, like running processes, files' metadata, loaded DLL files, Registry keys, services, directories, and files.

We have pre-downloaded the SharpEDRChecker from the [GitHub repo](https://github.com/PwnDexter/SharpEDRChecker) so that we can use it in the attached VM. Now we need to compile the project, and we have already created a shortcut to the project on the desktop (SharpEDRChecker). To do so, double-click on it to open it in Microsoft Visual Studio 2022. Now that we have our project ready, we need to compile it, as shown in the following screenshot:

### 1.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

Once it is compiled, we can find the path of the compiled version in the output section, as highlighted in step 3. We also added a copy of the compiled version in the C:\Users\thm\Desktop\Files directory. Now let's try to run it and see the result as follows:

### 2.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

As a result, the Windows Defender is found based on folders and services. Note that this program may be flagged by AV software as malicious since it does various checks and APIs calls. 

## C# Fingerprint checks

Another way to enumerate AV software is by coding our own program. We have prepared a C# program in the provided Windows 10 Pro VM, so we can do some hands-on experiments! You can find the project's icon on the desktop (AV-Check) and double-click it to open it using Microsoft Visual Studio 2022. 

The following C# code is straightforward, and its primary goal is to determine whether AV software is installed based on a predefined list of well-known AV applications.

```C#
using System;
using System.Management;

internal class Program
{
    static void Main(string[] args)
    {
        var status = false;
        Console.WriteLine("[+] Antivirus check is running .. ");
        string[] AV_Check = { 
            "MsMpEng.exe", "AdAwareService.exe", "afwServ.exe", "avguard.exe", "AVGSvc.exe", 
            "bdagent.exe", "BullGuardCore.exe", "ekrn.exe", "fshoster32.exe", "GDScan.exe", 
            "avp.exe", "K7CrvSvc.exe", "McAPExe.exe", "NortonSecurity.exe", "PavFnSvr.exe", 
            "SavService.exe", "EnterpriseService.exe", "WRSA.exe", "ZAPrivacyService.exe" 
        };
        var searcher = new ManagementObjectSearcher("select * from win32_process");
        var processList = searcher.Get();
        int i = 0;
        foreach (var process in processList)
        {
            int _index = Array.IndexOf(AV_Check, process["Name"].ToString());
            if (_index > -1)
            {
                Console.WriteLine("--AV Found: {0}", process["Name"].ToString());
                status = true;
            }
            i++;
        }
        if (!status) { Console.WriteLine("--AV software is not found!");  }
    }
}
```

Let's explain the code a bit more. We have predefined a list of well-known AV applications in the `AV_Check` array within our code, which is taken from the previous section, where we discussed fingerprinting AV software (table above). Then, we use the Windows Management Instrumentation Command-Line (WMIC) query (`select * from win32_process`) to list all currently running processes in the target machine and store them in the `processList` variable. Next, we go through the currently running processes and compare if they exist in the predefined array. If a match is found, then we have AV software installed.

The C# program utilizes a WMIC object to list current running processes, which may be monitored by AV software. If AV software is poorly implemented to monitor the WMIC queries or Windows APIs, it may cause false-positive results in scanning our C# program.

Let's compile an x86 version of the C# program, upload it to the VirusTotal website, and check the results! To compile the C# program in the Microsoft Visual Studio 2022, select **Build** from the bar menu and choose the **Build Solution** option. Then, if it complied correctly, you can find the path of the compiled version in the output section, as highlighted in step 3 in the screenshot below.

### 3.png

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

f we upload the AV-Check program to the VirusTotal website and check the result, surprisingly, VirusTotal showed that two AV vendors (MaxSecure and SecureAge APEX) flagged our program as malicious! Thus, this is a false-positive result where it incorrectly identifies a file as malicious where it is not. One of the possible reasons is that these AV vendors' software uses a machine-learning classifier or rule-based detection method that is poorly implemented. For more details about the actual submission report, see here. There are four main sections: Detection, Details, Behavior, and Community. If we check the Behavior section, we can see all calls of Windows APIs, Registry keys, modules, and the WMIC query.







