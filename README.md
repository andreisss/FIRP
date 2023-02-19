![image](https://user-images.githubusercontent.com/10872139/219940912-8e93f54c-f6dd-4cd6-84d8-b1afd9d0f916.png)

- **FIRP** (Firt Incident Response PowerShell) is a PowerShell-based framework designed to help with incident response activities. The framework is capable of analyzing a variety of security logs and incident response artifacts, including PowerShell and Sysmon logs, as well as Windows event logs, and  hope in future to extend to memory.

- **FIRP** provides a comprehensive set of PowerShell cmdlets that can be used to automate the analysis of these artifacts. The framework can be used to quickly identify and investigate suspicious activities on a system, including malware infections, network intrusions, and other security incidents.


Overall, this framework can be used to automate many of the incident response tasks, making the process faster and more efficient. However, it's important to note that this is just a high-level overview and the actual implementation of such a framework may involve many more steps and considerations depending on the specific requirements of the organization.

# How to use it
- **Open PowerShell with administrative privileges.** `Import-Module -Force .\firp.ps1`

# Functions

- **Get-bruteforce**  ->  Get-bruteforce -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219942642-f42d7fb4-3bd4-43ca-9acd-c47ba4b845d3.png)
 
- **Get-FailedAndSuccessLogons** -> Get-FailedAndSuccessLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00' > failed.txt

![image](https://user-images.githubusercontent.com/10872139/219942596-8465f1f1-cf71-4b47-ba56-ce7a55cffa07.png)

- **Get-ScheduledTaskEventLogs4698** -> Get-ScheduledTaskEventLogs4698 -StartTime '2021-02-14 00:00:00' -EndTime '2023-02-17 23:59:59'

![image](https://user-images.githubusercontent.com/10872139/219942514-2b5b89f5-8130-4641-ace7-f7726ac67e50.png)

- **Get-FailedRDP**  -> Get-FailedRDP -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

- **Get-FailedNetworkLogons**  -> Get-FailedNetworkLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

- **Get-LogonInfo** -> Get-LogonInfo -StartTime "2023-02-15T00:00:00" -EndTime "2023-02-16T00:00:00"
 
![image](https://user-images.githubusercontent.com/10872139/219942447-94d3b51c-af95-4693-88d3-147b674a719e.png)

- **Get-PowerShellLog** -> Get-PowerShellLog -Keywords "Invoke-WebRequest" -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219940512-85a33055-826e-42fc-bd99-63b298d1f5d4.png )

- **Get-PowerShellLogb64** -> Get-PowerShellLogb64 -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219941486-dd201510-f9e5-4236-9f1b-2c288200b570.png)

- **Get-PowerShellMaldev** -> Get-PowerShellMaldev -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219942195-8c391f71-4c10-401b-b1f5-72083a4ef51e.png)

- **Get-SysmonProcess** -> Get-SysmonProcess -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219943261-d07046c1-b174-4477-bf6f-f5a111b3556d.png)

-**Get-SysmonNetwork** -> Get-SysmonNetwork -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944178-d9615da9-7730-4ab4-8d59-855825346df4.png)

-**Get-SysmonFileStreamCreate** -> Get-SysmonFileStreamCreate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944235-9d97d844-5254-4199-9ce7-abf92868b862.png)

-**Get-SysmonCreateRemoteThread** -> Get-SysmonCreateRemoteThread -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944285-29aaf2cd-fe85-4085-ba31-ab7c73f29b60.png)

-**Get-SysmonFileCreate** -> Get-SysmonFileCreate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944437-8e4fca58-68ce-4fbd-9726-1ddcb530eac5.png)

-**Get-SysmonProcessTerminate** -> Get-SysmonProcessTerminate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219944507-4d87bf4c-7dc7-4fa1-97d1-6b61217efae3.png)

-**Get-SysmonRegAddDelete** -> Get-SysmonRegAddDelete -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219946455-d2b12b5a-69d0-42a2-aa09-7b3154c486f6.png)

-**Get-SysmonReg** -> Get-SysmonReg -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219946569-e3105cc9-2344-4b7d-a1f9-1f89f67c530e.png)

-**Get-SysmonRegRename** -> Get-SysmonRegRename -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

-**Get-SysmonDNS** -> Get-SysmonDNS -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

![image](https://user-images.githubusercontent.com/10872139/219946774-a4f8e823-75e0-478c-a796-a51b30b7c79e.png)

-**Get-SysmonWMIFilter** ->  Get-SysmonWMIFilter -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

-**Get-SysmonWMIConsumer** -> Get-SysmonWMIConsumer -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

-**Get-SysmonWMIBinding** -> Get-SysmonWMIBinding -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

-**Get-SysmonDriver** -> Get-SysmonDriver -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

-**Get-Services** -> Get-Services -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'


#### What can you do with FIRP (Firt Incident Response Powershell)?            

+ Analyze brute force attempts in a specific time-frame -> **Get-BruteForce**
+ Analyze failed logons and successes in a specific time-frame -> **Get-FailedAndSuccessLogons**
+ Analyze suspicious IP connections to the machine in a specific time-frame -> **Get-LogonInfo**
+ Analyze scheduled tasks in a specific time-frame -> **Get-ScheduledTaskEventLogs4698**
+ Analyze failed RDP sessions in a specific time-frame -> **Get-FailedRDP**
+ Analyze failed network logons in a specific time-frame -> **Get-FailedNetworkLogons**
+ Analyze PowerShell logs using keywords in a specific time-frame -> **Get-PowerShellLog**
+ Analyze PowerShell base64 scripts used in a specific time-frame -> **Get-PowerShellLogb64**
+ Analyze PowerShell malicious keywords as a database (keywords.txt) -> **Get-PowerShellMaldev**
+ Analyze Sysmon Processes filtering for the malicious path abused by malware and threat actors -> **Get-SysmonProcess**
+ Analyze Sysmon Network Activity -> **Get-SysmonNetwork**
+ Analyze Sysmon Zone Identifier files and Content appended with all details -> **Get-SysmonFileStreamCreate**
+ Analyze Sysmon Process Injection activity -> **Get-SysmonCreateRemoteThread**
+ Analyze Sysmon File Creation -> **Get-SysmonFileCreate**
+ Analyze Sysmon Process Termination -> **Get-SysmonProcessTerminate**
+ Analyze Sysmon Registry key and value create and delete operations -> **Get-SysmonRegAddDelete**
+ Analyze Sysmon value rename operations, recording the new name of the key or value that was renamed-> **Get-SysmonRegRename**
+ Analyze Sysmon Registry event records the value written for Registry values of type DWORD and QWORD -> **Get-SysmonReg**
+ Analyze Sysmon DNS query -> **Get-SysmonDNS**
+ Analyze Sysmon WMI filters -> **Get-SysmonWMIFilter**
+ Analyze Sysmon WMI Consumers -> **Get-SysmonWMIConsumer**
+ Analyze Sysmon WMI binding -> **Get-SysmonWMIBinding**
+ Analyze Sysmon Drivers -> **Get-SysmonDriver**
+ Analyze Security Windows Services -> **Get-Services**


Overall, this PowerShell framework can be used to automate many incident response tasks, making the process faster and more efficient. It's important to note that this is just a high-level overview, and the actual implementation of such a framework may involve many more steps and considerations depending on the specific requirements of the organization.
