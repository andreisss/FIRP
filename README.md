### FIRP 

PowerShell framework that can be used to analyze security, PowerShell, Sysmon logs, and other incident response artifacts.

- Analyze data: After the data is normalized, it can be analyzed to detect security events and anomalies. PowerShell can be used to automate the analysis process and generate reports that highlight potential security issues.

- Correlate data: Correlation involves linking events and data from different sources to identify patterns and relationships. PowerShell can be used to correlate data and help identify security incidents.


Overall, this framework can be used to automate many of the incident response tasks, making the process faster and more efficient. However, it's important to note that this is just a high-level overview and the actual implementation of such a framework may involve many more steps and considerations depending on the specific requirements of the organization.

# How to use it
- **Open PowerShell with administrative privileges.**
- **Run the following command:**

`Import-Module -Force .\firp.ps1`

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

- **Get-PowerShellLog**

Get-PowerShellLog -Keywords "HTTP://" -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

- **Get-PowerShellLogb64**

Get-PowerShellLogb64 -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

- **Get-PowerShellMaldev**

Get-PowerShellMaldev -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

- **Get-SysmonProcess**

Get-SysmonProcess -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'


#### What can you do?
                
+ Analyze bruteforce attemps in a specific time-frame - Get-bruteforce
+ Analyze failed logons and success in a specific time-frame - Get-FailedAndSuccessLogons
+ Analyze suspicious Ip connections to the machine in a specific time-frame - Get-LogonInfo
+ Analyze schedule tasks in a specific timeframe - Get-ScheduledTaskEventLogs4698
+ Analyze Failed RDP sessions in a specific timeframe - Get-FailedRDP
+ Analyze failed network logons in a specific timeframe - Get-FailedNetworkLogons
+ Analyze powershell logs using keywords in a specific timeframe - Get-PowerShellLog
+ Analyze Powershell base64 scripts used in a specific timeframe - Get-PowerShellLogb64
+ Analyze Powershell malicious keywords as database (keywords.txt) - Get-PowerShellMaldev



Overall, this framework can be used to automate many of the incident response tasks, making the process faster and more efficient. However, it's important to note that this is just a high-level overview and the actual implementation of such a framework may involve many more steps and considerations depending on the specific requirements of the organization.

# Editor.md
