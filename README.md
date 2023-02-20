![image](https://user-images.githubusercontent.com/10872139/219940912-8e93f54c-f6dd-4cd6-84d8-b1afd9d0f916.png)

#### What can you do with FIRP (Firt Incident Response Powershell)?            

 #### Security Logs
+ Analyze Security Logs for brute force attempts, time-frame -> **Get-BruteForce**
+ Analyze Security failed logons and successess, time-frame -> **Get-FailedAndSuccessLogons**
+ Analyze Security suspicious IP connections to the machine, time-frame -> **Get-LogonInfo**
+ Analyze Security scheduled tasks, time-frame -> **Get-ScheduledTaskEventLogs4698**
+ Analyze Security failed RDP sessions, time-frame -> **Get-FailedRDP**
+ Analyze Security failed network logons -> **Get-FailedNetworkLogons**
+ Analyze Security success network logons -> **Get-SuccessNetworkLogons**
+ Analyze Security Pass The Hash Attack -> **Get-PassTheHash**
+ Analyze Security Windows Services -> **Get-Services**
+ Analyze Security Local Account Created -> **Get-LocalAccountCreated**
+ Analyze Security Local Account Added to Administrator Group -> **Get-LocalAccountAddedToAdmin**
+ Analyze Security Local Account Password changed -> **Get-LocalAccountPwdChanged**
+ Analyze Security Local Account Disabled -> **Get-LocalAccountDisabled**
+ Analyze Security Local Account Lockout -> **Get-LocalAccountLockout**
+ Analyze Security Local Account Changed -> **Get-LocalAccountChanged**
+ Analyze Security Local Account Enabled -> **Get-LocalAccountEnabled**
+ Analyze Security User Added or Removed from Security Group -> **Get-UserAddedGlobalGroup** 


 #### Windows Defender Logs
+ Analyze Win Defender logs for malware -> **Get-DetectedMalware**
+ Analyze Win Defender logs for Real Time disabled -> **Get-DefenderAVRealTimeDisabled**
+ Analyze Win Defender logs, antimalware configuration changed.-> **Get-DefenderAVChanged**
+ Analyze Win Defender logs, antimalware engine found malware -> **Get-DefenderAntimalware** 

 #### Powershell Logs
+ Analyze PowerShell logs using keywords, time-frame -> **Get-PowerShellLog**
+ Analyze PowerShell base64 scripts used, time-frame -> **Get-PowerShellLogb64**
+ Analyze PowerShell malicious keywords as a database (keywords.txt) -> **Get-PowerShellMaldev**

 #### Sysmon Logs
+ Analyze Sysmon Processes using suspicious paths -> **Get-SysmonProcess**
+ Analyze Sysmon Network Activity -> **Get-SysmonNetwork**
+ Analyze Sysmon Zone Identifier files -> **Get-SysmonFileStreamCreate**
+ Analyze Sysmon Process Injection activity -> **Get-SysmonCreateRemoteThread**
+ Analyze Sysmon File Creation -> **Get-SysmonFileCreate**
+ Analyze Sysmon Process Termination -> **Get-SysmonProcessTerminate**
+ Analyze Sysmon Registry key and value create and delete operations -> **Get-SysmonRegAddDelete**
+ Analyze Sysmon value rename operations -> **Get-SysmonRegRename**
+ Analyze Sysmon Registry event records DWORD and QWORD -> **Get-SysmonReg**
+ Analyze Sysmon DNS query -> **Get-SysmonDNS**
+ Analyze Sysmon Pipe Created -> **Get-SysmonPipe**
+ Analyze Sysmon Pipe Connected -> **Get-SysmonPipeConnected**
+ Analyze Sysmon WMI filters -> **Get-SysmonWMIFilter**
+ Analyze Sysmon WMI Consumers -> **Get-SysmonWMIConsumer**
+ Analyze Sysmon WMI binding -> **Get-SysmonWMIBinding**
+ Analyze Sysmon Drivers -> **Get-SysmonDriver**

- **FIRP** (Firt Incident Response PowerShell) is a PowerShell-based framework designed to help with incident response activities. The framework is capable of analyzing a variety of security logs and incident response artifacts, including PowerShell and Sysmon logs, as well as Windows event logs, and  hope in future to extend to memory.

- **FIRP** provides a comprehensive set of PowerShell cmdlets that can be used to automate the analysis of these artifacts. The framework can be used to quickly identify and investigate suspicious activities on a system, including malware infections, network intrusions, and other security incidents.


Overall, this framework can be used to automate many of the incident response tasks, making the process faster and more efficient. However, it's important to note that this is just a high-level overview and the actual implementation of such a framework may involve many more steps and considerations depending on the specific requirements of the organization.

# How to use it

**Open PowerShell with administrative privileges.** `Import-Module -Force .\firp.ps1`

# Functions

**Get-bruteforce**  ->  Get-bruteforce -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219942642-f42d7fb4-3bd4-43ca-9acd-c47ba4b845d3.png)

**Get-DetectedMalware**  ->  Get-DetectedMalware -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219968698-c197e41f-9987-45c1-9029-8bcc4f8e08a7.png)

**Get-DefenderAVRealTimeDisabled**  ->  Get-DefenderAVRealTimeDisabled -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219969964-9be28715-caa0-4abd-ac9e-2ad27b61fab5.png)

 **Get-DefenderAVChange**  ->  Get-DefenderAVChanged -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219970342-ffb3a645-5487-4fac-abf5-69aaee679ff0.png)

**Get-DefenderAntimalware** -> Get-DefenderAntimalware -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'
 
**Get-FailedAndSuccessLogons** -> Get-FailedAndSuccessLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00' > failed.txt

![image](https://user-images.githubusercontent.com/10872139/219942596-8465f1f1-cf71-4b47-ba56-ce7a55cffa07.png)

**Get-PassTheHash** -> Get-PassTheHash -StartTime '2023-01-01T08:06:00' -EndTime '2023-02-19T23:57:00'

**Get-ScheduledTaskEventLogs4698** -> Get-ScheduledTaskEventLogs4698 -StartTime '2021-02-14 00:00:00' -EndTime '2023-02-17 23:59:59'

![image](https://user-images.githubusercontent.com/10872139/219942514-2b5b89f5-8130-4641-ace7-f7726ac67e50.png)

**Get-FailedRDP**  -> Get-FailedRDP -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

**Get-FailedNetworkLogons**  -> Get-FailedNetworkLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

![image](https://user-images.githubusercontent.com/10872139/219980398-3303113e-9dbd-41ab-88e3-7feaa3df09cb.png)

**Get-SuccessNetworkLogons**   -> Get-SuccessNetworkLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-19 23:54:00'

![image](https://user-images.githubusercontent.com/10872139/219980444-9b154538-34ae-42b3-af01-b4aee61a891b.png)

**Get-LocalAccountDisabled** -> Get-LocalAccountDisabled -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219983502-23fd5eb7-32d3-44f0-86b4-1865d909d9e9.png)

**Get-LocalAccountLockout** -> Get-LocalAccountLockout -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

**Get-LocalAccountChanged** -> Get-LocalAccountChanged -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/220028849-16142026-cb04-4328-93e7-577807a5ccf2.png)

**Get-Get-LocalAccountEnabled** -> Get-Get-LocalAccountEnabled -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/220029061-b5029e60-1657-48b9-b2cd-aeedff548823.png)

![image](https://user-images.githubusercontent.com/10872139/220028849-16142026-cb04-4328-93e7-577807a5ccf2.png)

**Get-LogonInfo** -> Get-LogonInfo -StartTime "2023-02-15T00:00:00" -EndTime "2023-02-16T00:00:00"
 
![image](https://user-images.githubusercontent.com/10872139/219942447-94d3b51c-af95-4693-88d3-147b674a719e.png)

**Get-LocalAccountCreated** -> Get-LocalAccountCreated  -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219982538-b125b1a0-4ed7-42f7-b41b-54d3fba85581.png)

**Get-LocalAccountAddedToAdmin** -> Get-LocalAccountAddedToAdmin  -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219982729-891567d7-66d0-4c86-be72-cb6df790c0fb.png)

**Get-LocalAccountPwdChanged** -> Get-LocalAccountPwdChanged -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219983344-23fea06d-202e-4559-b7ad-40fd31272543.png)


**Get-PowerShellLog** -> Get-PowerShellLog -Keywords "Invoke-WebRequest" -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219940512-85a33055-826e-42fc-bd99-63b298d1f5d4.png )

**Get-PowerShellLogb64** -> Get-PowerShellLogb64 -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219941486-dd201510-f9e5-4236-9f1b-2c288200b570.png)

**Get-PowerShellMaldev** -> Get-PowerShellMaldev -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219942195-8c391f71-4c10-401b-b1f5-72083a4ef51e.png)

**Get-SysmonProcess** -> Get-SysmonProcess -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219943261-d07046c1-b174-4477-bf6f-f5a111b3556d.png)

**Get-SysmonNetwork** -> Get-SysmonNetwork -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944178-d9615da9-7730-4ab4-8d59-855825346df4.png)

**Get-SysmonFileStreamCreate** -> Get-SysmonFileStreamCreate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944235-9d97d844-5254-4199-9ce7-abf92868b862.png)

**Get-SysmonCreateRemoteThread** -> Get-SysmonCreateRemoteThread -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944285-29aaf2cd-fe85-4085-ba31-ab7c73f29b60.png)

**Get-SysmonFileCreate** -> Get-SysmonFileCreate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944437-8e4fca58-68ce-4fbd-9726-1ddcb530eac5.png)

**Get-SysmonProcessTerminate** -> Get-SysmonProcessTerminate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944507-4d87bf4c-7dc7-4fa1-97d1-6b61217efae3.png)

**Get-SysmonRegAddDelete** -> Get-SysmonRegAddDelete -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219946455-d2b12b5a-69d0-42a2-aa09-7b3154c486f6.png)

**Get-SysmonReg** -> Get-SysmonReg -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219946569-e3105cc9-2344-4b7d-a1f9-1f89f67c530e.png)

**Get-SysmonRegRename** -> Get-SysmonRegRename -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

**Get-SysmonDNS** -> Get-SysmonDNS -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219946774-a4f8e823-75e0-478c-a796-a51b30b7c79e.png)

**Get-SysmonPipe** -> Get-SysmonPipe -StartTime '2023-02-19T15:06:00' -EndTime '2023-02-19T17:57:00'

![image](https://user-images.githubusercontent.com/10872139/219960141-6b209120-7ef3-4098-889b-a59c95e3e7a7.png)

**Get-SysmonPipeConnected** -> Get-SysmonPipeConnected -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

**Get-SysmonWMIFilter** ->  Get-SysmonWMIFilter -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

**Get-SysmonWMIConsumer** -> Get-SysmonWMIConsumer -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

**Get-SysmonWMIBinding** -> Get-SysmonWMIBinding -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

**Get-SysmonDriver** -> Get-SysmonDriver -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

**Get-Services** -> Get-Services -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'



Overall, this PowerShell framework can be used to automate many incident response tasks, making the process faster and more efficient. It's important to note that this is just a high-level overview, and the actual implementation of such a framework may involve many more steps and considerations depending on the specific requirements of the organization.
