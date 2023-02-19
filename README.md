![image](https://user-images.githubusercontent.com/10872139/219940912-8e93f54c-f6dd-4cd6-84d8-b1afd9d0f916.png)

- **FIRP** (Firt Incident Response PowerShell) is a PowerShell-based framework designed to help with incident response activities. The framework is capable of analyzing a variety of security logs and incident response artifacts, including PowerShell and Sysmon logs, as well as Windows event logs, and  hope in future to extend to memory.

- **FIRP** provides a comprehensive set of PowerShell cmdlets that can be used to automate the analysis of these artifacts. The framework can be used to quickly identify and investigate suspicious activities on a system, including malware infections, network intrusions, and other security incidents.


Overall, this framework can be used to automate many of the incident response tasks, making the process faster and more efficient. However, it's important to note that this is just a high-level overview and the actual implementation of such a framework may involve many more steps and considerations depending on the specific requirements of the organization.

# How to use it
- **Open PowerShell with administrative privileges.** `Import-Module -Force .\firp.ps1`

# Functions

- **Get-bruteforce**  ->  Get-bruteforce -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

![image](https://user-images.githubusercontent.com/10872139/219938879-24e497ab-cdaf-4ebb-9e4b-1427f7e6bc4e.png)

 
- **Get-FailedAndSuccessLogons** -> Get-FailedAndSuccessLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00' > failed.txt

![image](https://user-images.githubusercontent.com/10872139/219939037-372194eb-7e91-4fa8-a6b8-bbf70b5e4d5b.png)

- **Get-ScheduledTaskEventLogs4698** -> Get-ScheduledTaskEventLogs4698 -StartTime '2021-02-14 00:00:00' -EndTime '2023-02-17 23:59:59'

![image](https://user-images.githubusercontent.com/10872139/219939083-32a356ae-9208-49f8-b71d-74de79329614.png)

- **Get-FailedRDP**  -> Get-FailedRDP -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

- **Get-FailedNetworkLogons**  -> Get-FailedNetworkLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

- **Get-LogonInfo** -> Get-LogonInfo -StartTime "2023-02-15T00:00:00" -EndTime "2023-02-16T00:00:00"

![image](https://user-images.githubusercontent.com/10872139/219939238-12b72646-46ff-49ec-aef4-aa8d64783662.png)

- **Get-PowerShellLog** -> Get-PowerShellLog -Keywords "Invoke-WebRequest" -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'
![image](https://user-images.githubusercontent.com/10872139/219940512-85a33055-826e-42fc-bd99-63b298d1f5d4.png )

- **Get-PowerShellLogb64** -> Get-PowerShellLogb64 -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'
![image][image](https://user-images.githubusercontent.com/10872139/219941486-dd201510-f9e5-4236-9f1b-2c288200b570.png)

- **Get-PowerShellMaldev**

Get-PowerShellMaldev -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

- **Get-SysmonProcess**

Get-SysmonProcess -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'


#### What can you do?
                
+ Analyze bruteforce attemps in a specific time-frame -> Get-bruteforce
+ Analyze failed logons and success in a specific time-frame -> Get-FailedAndSuccessLogons
+ Analyze suspicious Ip connections to the machine in a specific time-frame -> Get-LogonInfo
+ Analyze schedule tasks in a specific timeframe -> Get-ScheduledTaskEventLogs4698
+ Analyze Failed RDP sessions in a specific timeframe -> Get-FailedRDP
+ Analyze failed network logons in a specific timeframe -> Get-FailedNetworkLogons
+ Analyze powershell logs using keywords in a specific timeframe -> Get-PowerShellLog
+ Analyze Powershell base64 scripts used in a specific timeframe -> Get-PowerShellLogb64
+ Analyze Powershell malicious keywords as database (keywords.txt) -> Get-PowerShellMaldev



Overall, this framework can be used to automate many of the incident response tasks, making the process faster and more efficient. However, it's important to note that this is just a high-level overview and the actual implementation of such a framework may involve many more steps and considerations depending on the specific requirements of the organization.
