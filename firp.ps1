Function Get-bruteforce {
	<#
.SYNOPSIS
    The 'Get-bruteforce' use case is designed to extract failed logon attempts that may indicate a brute force attack.
.DESCRIPTION
    Query the event log to detect more than 20 failed logons in a short timeframe. 
	The output log is one of the brute-force attempts.

.PARAMETER 
    Please provide start time : -StartTime and end time: -EndTime

.EXAMPLE
    Get-bruteforce -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

.NOTES
#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

    $EventIds = @("4625")

    $FailedLogons = Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=4625} |
  Where-Object {
            $_.Properties[5].Value -notmatch '^(S-1-5-21-\d+-\d+-\d+-\d+|S-1-5-18|S-1-5-19)$'
        }

    $BruteForceAttempts = @()
    for ($i = 0; $i -lt $FailedLogons.Count; $i++) {
        $FailedLogon = $FailedLogons[$i]
        $FailedAttempts = 1
        for ($j = $i + 1; $j -lt $FailedLogons.Count; $j++) {
            $NextFailedLogon = $FailedLogons[$j]
            $TimeDiff = New-TimeSpan -Start $FailedLogon.TimeCreated -End $NextFailedLogon.TimeCreated
            if ($TimeDiff.TotalMinutes -le 5) {
                $FailedAttempts++
            } else {
                break
            }
        }
        if ($FailedAttempts -ge 20) {
            $BruteForceAttempts += $FailedLogon
        }
        $i += $FailedAttempts - 1
    }

    if ($BruteForceAttempts.Count -gt 0) {
        Write-Output "Brute Force Attempts detected with more of 20 failed logons :"
        $BruteForceAttempts  | Format-List
    } else {
        Write-Output "No Brute Force Attempts found."
    }
}


Function Get-FailedAndSuccessLogons {
<#
.SYNOPSIS
    The 'Get-FailedAndSuccessLogons' use case is designed to extract failed and success Logons.
.DESCRIPTION
    FailedAndSuccessLogons: queries the Windows Security event log to retrieve both successful and failed logon events 
    (with event IDs 4624 and 4625) for a specific time frame, and excludes logon events for system accounts.

.PARAMETER 
    You can write the output of a PowerShell command to a file and filter by a specific time frame.

.EXAMPLE
    Get-FailedAndSuccessLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

.NOTES
#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

    $EventIds = @("4624", "4625")

    Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Where-Object {
            $_.Properties[5].Value -notmatch '^(S-1-5-21-\d+-\d+-\d+-\d+|S-1-5-18|S-1-5-19)$'
        } |
        Select-Object * -ExcludeProperty Description |
        Format-List
}

function Get-ScheduledTaskEventLogs4698 {
	<#
.SYNOPSIS
    The Get-ScheduledTaskEventLogs4698 function is a PowerShell function that retrieves Windows event logs related to the creation of scheduled tasks with the Event ID 4698
	
.DESCRIPTION
    The function takes three parameters:
 
    $EventId: This is the ID of the event log that the function should search for. In this case, it is set to 4698, which corresponds to the creation of a scheduled task.
    $StartTime: This is the start time of the window within which the function should search for event logs.
    $EndTime: This is the end time of the window within which the function should search for event logs.

.PARAMETER 
     It filters the event logs by log name, event ID, start time, and end time.

.EXAMPLE
    Get-ScheduledTaskEventLogs4698 -StartTime '2021-02-14 00:00:00' -EndTime '2023-02-17 23:59:59

.NOTES
#>
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTime
    )
    
    $LogName = 'Security'
    $EventId = 4698
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $LogName
        ID = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

    $result = @()
    $events | ForEach-Object {
        $event = $_.ToXml()
        $xml = [xml]$event
        $properties = @{}
        foreach ($property in $xml.Event.EventData.Data) {
            $name = $property.Name
            $value = $property.'#text'

            if ($properties.Contains($name)) {
                $index = 1
                while ($properties.Contains("$name$index")) {
                    $index++
                }
                $name = "$name$index"
            }

            $properties[$name] = $value
        }
        $result += New-Object -TypeName PSObject -Property $properties
    }
    return $result
}



Function Get-FailedRDP {
	<#
.SYNOPSIS
    This is a PowerShell function named Get-FailedRDP which retrieves failed RDP login attempts
	from the Windows Security event log within a specified timeframe.
.DESCRIPTION
     The function accepts two mandatory parameters: $StartTime and $EndTime, which specify the start and end time for the log search.
	 The function filters events with ID 4625 (indicating a failed login attempt) and logon type 10 (indicating an RDP login attempt).

.PARAMETER 
    "Get-FailedRDP" is a PowerShell function that extracts information about failed logon attempts from the Security event logs.
 	 It specifically targets event ID 4625, which is generated when a logon attempt fails

.EXAMPLE
    Get-FailedRDP -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

.NOTES
#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

    $EventIds = @("4625")

    Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Where-Object {
            $_.Properties[5].Value -notmatch '^(S-1-5-21-\d+-\d+-\d+-\d+|S-1-5-18|S-1-5-19)$'
        } |
        Where-Object {
            $_.Id -eq 4625 -and $_.Properties[8].Value -eq 10
        } |
        Select-Object -Property TimeCreated, @{Name='Logon Type';Expression={$_.Properties[8].Value}}, @{Name='Status';Expression={$_.Properties[3].Value}}, @{Name='Substatus';Expression={$_.Properties[4].Value}}, @{Name='Target User Name';Expression={$_.Properties[5].Value}}, @{Name='Workstation Name';Expression={$_.Properties[12].Value}}, @{Name='IP Address';Expression={$_.Properties[13].Value}} |
        Format-List
}


Function Get-FailedNetworkLogons {
    <#
    .SYNOPSIS
    This is a PowerShell function that retrieves failed logon events from the Windows Security event log within a specified time range.
    .DESCRIPTION
    The function takes two parameters: $StartTime and $EndTime, both of which are mandatory and must be of type DateTime.
    The function then uses the Get-WinEvent cmdlet to filter the Security event log for event ID 4625 (failed logon events)
    that have a logon type of 3 (network logon) and a non-zero status code.
    .PARAMETER
    "Get-FailedNetworkLogons" is a PowerShell function that extracts information about failed logon attempts from the Security event logs.
    It specifically targets event ID 4625 and filters for events that have a non-zero status code.
    .EXAMPLE
    Get-FailedNetworkLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'
    .NOTES
    #>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

    Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=4625} |
        Where-Object {
            ($_.Properties[10].Value -eq "3")
        } | Format-List
}


Function Get-SuccessNetworkLogons {
		<#
.SYNOPSIS
     This is a PowerShell function that retrieves failed logon events from the Windows Security event log within a specified time range.
.DESCRIPTION
     The function takes two parameters: $StartTime and $EndTime, both of which are mandatory and must be of type DateTime.
	 The function then uses the Get-WinEvent cmdlet to filter the Security event log for event ID 4624 (successful logon events)
	 that have a logon type of 3 (network logon).

.PARAMETER 
    "Get-SuccessNetworkLogons" is a PowerShell function that extracts information about failed logon attempts from the Security event logs.
 	 It specifically targets event ID 4624,It also filters for events that have a non-zero status code

.EXAMPLE
    Get-SuccessNetworkLogons -StartTime '2023-02-12 00:00:00' -EndTime '2023-02-13 23:24:00'

.NOTES
#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

    Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=4624} |
        Where-Object {
            ($_.Properties[8].Value -eq "3")
        } | Format-List
}


Function Get-LogonInfo {
<#
.SYNOPSIS
    Get-LogonInfo extracts all Loon Events [Evt 4624] from the Security Event log for a specified timeframe
.DESCRIPTION
    Query the event log and pull back all Logon Events. 
    Event 4624
    Query and filter
.PARAMETER
    Specifies the start time to search for logon events.

.PARAMETER
    Specifies the end time to search for logon events.

.EXAMPLE
    Get-LogonInfo -StartTime "2023-02-15T00:00:00" -EndTime "2023-02-16T00:00:00"

.NOTES
#>

[cmdletbinding()]
param (
    [Parameter(Mandatory=$true,
               ValueFromPipeline=$True,
               HelpMessage="Enter the start time")]
    [datetime]$StartTime,

    [Parameter(Mandatory=$true,
               ValueFromPipeline=$True,
               HelpMessage="Enter the end time")]
    [datetime]$EndTime
)

$RawEvents = Get-WinEvent -FilterHashtable @{Logname="Security"; ID=4624} | Where-Object {$_.TimeCreated -ge $StartTime -and $_.TimeCreated -le $EndTime}
    
$RawEvents | ForEach-Object {
    $SelectorStrings = [string[]]@(
    'Event/EventData/Data[@Name="TargetUserName"]',
    'Event/EventData/Data[@Name="TargetDomainName"]',
    'Event/EventData/Data[@Name="TargetLogonId"]',
    'Event/EventData/Data[@Name="LogonType"]',
    'Event/EventData/Data[@Name="WorkstationName"]',
    'Event/EventData/Data[@Name="ProcessId"]',
    'Event/EventData/Data[@Name="ProcessName"]',
    'Event/EventData/Data[@Name="IpAddress"]',
    'Event/EventData/Data[@Name="IpPort"]'
    )
    $PropertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($SelectorStrings)

    $UserName,$Domain,$LogonId,$LogonType,$ComputerName,$ProcessId,$ProcessName,$IPAddress,$Port = $_.GetPropertyValues($PropertySelector)

    [PSCustomObject]@{
    TimeCreated  = $_.TimeCreated
    UserName     = $UserName
    Domain       = $Domain
    LogonId      = $LogonId
    LogonType    = $LogonType
    ComputerName = $ComputerName
    ProcessId    = $ProcessId
    ProcessName  = $ProcessName
    IPAddress    = $IPAddress
    Port         = $Port
    Message      = ($_.Message).split(".")[0]       
    }     
}
}

function Get-PowerShellLog {
				<#
.SYNOPSIS
     The function Get-PowerShellLog retrieves events with ID 4104 from the Microsoft-Windows-PowerShell
	 provider within a specified time frame,and filters the events based on one or more provided keywords.
.DESCRIPTION
    The function returns the log messages that contain at least one of the provided keywords.
.EXAMPLE
    Get-PowerShellLog -Keywords "HTTP://" -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'

.NOTES
#>
	
	
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,
        [DateTime]$StartTime,
        [DateTime]$EndTime
    )

    $events = Get-WinEvent -FilterHashtable @{
        ProviderName='Microsoft-Windows-PowerShell'
        ID=4104
        StartTime=$StartTime
        EndTime=$EndTime
    }

$events | ForEach-Object {
    $message = $_.Properties[2].Value

    foreach ($keyword in $Keywords) {
        if ($message -like "*$keyword*") {
            $message
            break
        }
    }
}
}


function Get-PowerShellLogb64 {
    <#
    .SYNOPSIS
         The function Get-PowerShellLog retrieves events with ID 4104 from the Microsoft-Windows-PowerShell
         provider within a specified time frame,and filters the events based on base64 encode.
    .DESCRIPTION
        The function returns the base64 encoded code from the log messages that contain at least one base64-encoded string.
    .EXAMPLE
        Get-PowerShellLogb64 -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'
    .NOTES
    #>

    [CmdletBinding()]
    param(
        [DateTime]$StartTime,
        [DateTime]$EndTime
    )

    $events = Get-WinEvent -FilterHashtable @{
        ProviderName='Microsoft-Windows-PowerShell'
        ID=4104
        StartTime=$StartTime
        EndTime=$EndTime
    }

    $base64Regex = '\-[Ee^]{1,2}[NnCcOoDdEeMmAa^]+ [A-Za-z0-9+/=]{5,}'



    $events | ForEach-Object {
        $message = $_.Properties[2].Value
        $base64Matches = [regex]::Matches($message, $base64Regex)
        foreach ($match in $base64Matches) {
            $match.Value
        }
    }
}



function Get-PowerShellMaldev {
    <#
    .SYNOPSIS
         The function Get-PowerShellMaldev retrieves events with ID 4104 from the Microsoft-Windows-PowerShell
         provider within a specified time frame,and filters the events based on database of malicious keywords.
    .DESCRIPTION
        The function returns the log messages that contain at least one log where is detected the key.
		
    .EXAMPLE
         Get-PowerShellMaldev -StartTime '2023-02-10T12:00:00' -EndTime '2023-02-15T21:58:00'
    .NOTES
    #>

    [CmdletBinding()]
    param(
        [DateTime]$StartTime,
        [DateTime]$EndTime
    )

    $events = Get-WinEvent -FilterHashtable @{
        ProviderName='Microsoft-Windows-PowerShell'
        ID=4104
        StartTime=$StartTime
        EndTime=$EndTime
    }
	
	    $maliciousKeywords = Get-Content -Path ".\keywords.txt"


    #$maliciousKeywords = @()

    $events | ForEach-Object {
        $message = $_.Properties[2].Value
        foreach ($keyword in $maliciousKeywords) {
            if ($message -like "*$keyword*") {
                $message -replace $keyword, "$(Write-Host $keyword -ForegroundColor Red)"
                break
            }
        }
    }
}

function Get-SysmonProcess {
	    <#

RuleName: The name of the rule that triggered the process creation event.
UtcTime: The UTC timestamp when the process was created.
ProcessGuid: A unique identifier for the process.
ProcessId: The process ID of the created process.
Image: The full path of the executable file that was launched.
FileVersion: The version of the executable file.
Description: A description of the executable file.
Product: The name of the product associated with the executable file.
Company: The name of the company that produced the executable file.
OriginalFileName: The original name of the executable file.
CommandLine: The command line arguments used to launch the executable file.
CurrentDirectory: The current working directory of the launched process.
User: The username of the user that launched the process.
LogonGuid: A unique identifier for the user's logon session.
LogonId: A numerical identifier for the user's logon session.
TerminalSessionId: A numerical identifier for the user's terminal services session.
IntegrityLevel: The integrity level of the process (e.g. low, medium, high).
Hashes: The SHA-256 hash of the launched executable file.
ParentProcessGuid: A unique identifier for the parent process that launched the process.
ParentProcessId: The process ID of the parent process.
ParentImage: The full path of the executable file for the parent process.
ParentCommandLine: The command line arguments used to launch the parent process.

Example :  Get-SysmonProcess -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'
	    #>
		
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 1
    )
    $ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime.AddMinutes(-5)
        EndTime = $EndTime.AddMinutes(5)
		
    }
	
	
    $suspiciousEvents = foreach ($event in $events) {
        $Properties = [xml]$event.ToXml()
        $User = $Properties.Event.EventData.Data | where {$_.Name -eq 'User'} | select -ExpandProperty '#text'
		$Product = $Properties.Event.EventData.Data | where {$_.Name -eq 'Product'} | select -ExpandProperty '#text'
        $Description = $Properties.Event.EventData.Data | where {$_.Name -eq 'Description'} | select -ExpandProperty '#text'
        $Company = $Properties.Event.EventData.Data | where {$_.Name -eq 'Company'} | select -ExpandProperty '#text'
        $ProcessId = $Properties.Event.EventData.Data | where {$_.Name -eq 'ProcessId'} | select -ExpandProperty '#text'
        $Image = $Properties.Event.EventData.Data | where {$_.Name -eq 'Image'} | select -ExpandProperty '#text'
        $OriginalFilename = $Properties.Event.EventData.Data | where {$_.Name -eq 'OriginalFilename'}
        if ($OriginalFilename) {$OriginalFilename = $OriginalFilename.'#text'}
        $CommandLine = $Properties.Event.EventData.Data | where {$_.Name -eq 'CommandLine'} | select -ExpandProperty '#text'
        $CurrentDirectory = $Properties.Event.EventData.Data | where {$_.Name -eq 'CurrentDirectory'} | select -ExpandProperty '#text'
        $ParentProcessGuid = $Properties.Event.EventData.Data | where {$_.Name -eq 'ParentProcessGuid'} | select -ExpandProperty '#text'
        $ParentProcessId = $Properties.Event.EventData.Data | where {$_.Name -eq 'ParentProcessId'} | select -ExpandProperty '#text'
        $ParentImage = $Properties.Event.EventData.Data | where {$_.Name -eq 'ParentImage'} | select -ExpandProperty '#text'
        $ParentCommandLine = $Properties.Event.EventData.Data | where {$_.Name -eq 'ParentCommandLine'} | select -ExpandProperty '#text'


		
		
		$ImageSuspicious = $false
        if ($Image -match 'Temp' -or $Image -match 'ProgramData' -or $Image -match 'Users' -or $Image -match 'Downloads' -or $Image -match 'Documents' -or $Image -match 'Roaming') {
        $ImageSuspicious = $true
        }

        $CurrentDirectorySuspicious = $false
        if ($CurrentDirectory -match 'Temp' -or $CurrentDirectory -match 'ProgramData' -or $CurrentDirectory -match 'Roaming' -or $CurrentDirectory -match 'Users' -or $CurrentDirectory -match 'Downloads' -or $CurrentDirectory -match 'Documents') {
        $CurrentDirectorySuspicious = $true
        }

        $CommandLineSuspicious = $false
        if ($CommandLine -match 'AppData' -or $CommandLine -match 'Roaming' -or
		$CommandLine -match 'Temp' -or $CommandLine -match 'Users' -or $CommandLine -match 'ProgramData' -or $CommandLine -match 'Downloads'-or $CommandLine -match 'Documents') {
        $CommandLineSuspicious = $true
        }

        if ($ImageSuspicious -or $CommandLineSuspicious -or $CurrentDirectorySuspicious) {
			
            $Hash = (Get-FileHash -Algorithm MD5 (Resolve-Path $Image -ErrorAction SilentlyContinue).Path).Hash

            [PSCustomObject]@{
				
                TimeCreated = $event.TimeCreated
                ProcessId = $ProcessId
				User = $User
				Product = $Product
				Description = $Description
				Company = $Company
                Image = $Image
                ImageSuspicious = $ImageSuspicious
                OriginalFilename = $OriginalFilename
                OriginalFilenameSuspicious = $OriginalFilenameSuspicious
                CommandLine = $CommandLine
                CommandLineSuspicious = $CommandLineSuspicious
                CurrentDirectory = $CurrentDirectory
                CurrentDirectorySuspicious = $CurrentDirectorySuspicious
                ParentProcessGuid = $ParentProcessGuid
                ParentProcessId = $ParentProcessId
                ParentImage = $ParentImage
                ParentCommandLine = $ParentCommandLine
                Hash = $Hash
				
            }
			

        }
		

    }  


    return $suspiciousEvents
	
}



Function Get-SysmonNetwork {
    <#
    .SYNOPSIS
    Retrieves Sysmon network event logs within a specified time range
		
RuleName            : technique_id=T1021,technique_name=Remote Services
HostName            : LAPTOP-HAK\Andrea
DateUTC             : 2023-02-18 11:01:08.365
ProcessGuid         : 6c4ade50-aff2-63f0-f95b-00000000ad00
ProcessId           : 14108
Image               : C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe
User                : LAPTOP-HAK\Andrea
Protocol            : tcp
Initiated           : True
SourceIsIpv6        : False
SourceIp            : 192.168.1.34
SourceHostname      : -
SourcePort          : 4861
SourcePortName      : -
DestinationIsIpv6   : False
DestinationIp       : 212.119.29.177
DestinationHostname : -
DestinationPort     : 443
DestinationPortName : -

    .EXAMPLE
        Get-SysmonNetwork -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 3
    )

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }
	

    $events | ForEach-Object {  
        $PropertyBag = @{
    HostName = $_.Properties[1].Value
    DateUTC = $_.Properties[2].Value
    ProcessGuid = $_.Properties[2].Value
    ProcessId = $_.Properties[3].Value
    Image = $_.Properties[4].Value
    User = $_.Properties[5].Value
    Protocol = $_.Properties[6].Value
    Initiated = $_.Properties[7].Value
    SourceIsIpv6 = $_.Properties[8].Value
    SourceIp = $_.Properties[9].Value
    SourceHostname = $_.Properties[10].Value
    SourcePort = $_.Properties[11].Value
    SourcePortName = $_.Properties[12].Value
    DestinationIsIpv6 = $_.Properties[13].Value
    DestinationIp = $_.Properties[14].Value
    DestinationHostname = $_.Properties[15].Value
    DestinationPort = $_.Properties[16].Value
    DestinationPortName = $_.Properties[17].Value
}


        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName, HostName, DateUTC, ProcessGuid, ProcessId, Image, User, Protocol, Initiated, SourceIsIpv6, SourceIp, SourceHostname, SourcePort, SourcePortName, DestinationIsIpv6, DestinationIp, DestinationHostname, DestinationPort, DestinationPortName
    }
}


Function Get-SysmonFileStreamCreate {
<#

.SYNOPSIS
    Get-SysmonFileStreamCreate extracts all Sysmon File Stream Create Events [Evt 15] from the Sysymon Operational Event log for a specified timeframe

.DESCRIPTION
    Query the event log and pull back all Sysmon File Stream Creation events.
    Event 15 or downloaded files the content field would be empty and only the hashes can be checked against virus total to identify if the FileStreamHash is malicious or clean.
    For events where the system creates Zone Identifier files and Content field is completely appended with all details, it should be parsed properly and Referral URL and Host URL should be checked for maliciousness.

RuleName       : -
HostName       : LAPTOP-HDFRT
DateUTC        : 2023-02-18 12:34:24.347
ProcessGuid    : 6c4ade50-c5c8-63f0-375d-00000000ad00
ProcessId      : 11420
Image          : C:\Program Files\Mozilla Firefox\firefox.exe
TargetFilename : D:\mimikatz.exe
CreationUTC    : 2023-02-18 12:34:24.056
SHA1           : {SHA1=D1F7832035C3E8A73CC78AFD28CFD7F4CECE6D20, MD5=E930B05EFE23891D19BC354A4209BE3E, SHA256=92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50, IMPHASH=1355327F6CA3430B3DDBE6E0ACDA71EA}
User           : LAPTOP-HDFRT\Andrea

    .EXAMPLE
       Get-SysmonFileStreamCreate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'
    #>
	
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 15
    )
	$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }
    $SHA1 = (Get-FileHash -Algorithm MD5 (Resolve-Path $SHA1 -ErrorAction SilentlyContinue).Path).SHA1


    $events | ForEach-Object {  
        $PropertyBag = @{
        HostName = $_.MachineName
		User = $_.Properties[9].Value
        EventID = $_.Id
        DateUTC = $_.Properties[1].Value
        ProcessGuid = $_.Properties[2].Value
        ProcessId = $_.Properties[3].Value
        Image = $_.Properties[4].Value
        TargetFilename = $_.Properties[5].Value
        CreationUTC = $_.Properties[6].Value
        SHA1 = ($_.Properties[7].Value.ToString().Split(","))
		RuleName = $_.Properties[0].Value	
        
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName, HostName, DateUTC, ProcessGuid, ProcessId, Image, TargetFilename, CreationUTC, SHA1, User
    }
}

Function Get-SysmonCreateRemoteThread {
<#
.SYNOPSIS
    The function Get-SysmonCreateRemoteThread retrieves Sysmon Create Remote Thread Events [Evt 8] within a specified timeframe from the Sysmon Operational Event log.
.DESCRIPTION
    Query the event log and pull back all Sysmon File Stream Creation events. Event 8

RuleName        : technique_id=T1055,technique_name=Process Injection
DateUTC         : 2023-02-18 16:54:03.874
SourceProcessId : 24040
ProcessGuid     : 6c4ade50-02ab-63f1-5e60-00000000ad00
SourceImage     : C:\Users\Andrea\Desktop\Injector.exe
TargetImage     : C:\Windows\System32\notepad.exe
SourceUser      : LAPTOP-HL1G97FB\Andrea
TargetUser      : LAPTOP-HL1G97FB\Andrea
StartFunction   : LoadLibraryW
StartModule     : C:\WINDOWS\System32\KERNEL32.DLL

    .EXAMPLE
       Get-SysmonCreateRemoteThread -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'
    #>
	
	
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 8
    )
	$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }
    $SHA1 = (Get-FileHash -Algorithm MD5 (Resolve-Path $SHA1 -ErrorAction SilentlyContinue).Path).SHA1

   $events | ForEach-Object {  
        $PropertyBag = @{
	    RuleName = $_.Properties[0].Value	
		DateUTC = $_.Properties[1].Value
		SourceProcessId = $_.Properties[3].Value
		SourceImage = $_.Properties[4].Value
		TargetImage  = $_.Properties[7].Value
		CreationUTC = $_.Properties[2].Value
        SourceUser = $_.Properties[12].Value
		TargetUser = $_.Properties[13].Value
		User = $_.Properties[9].Value
		TargetProcessId = $_.Properties[7].Value
		NewThreadId = $_.Properties[9].Value
        ProcessGuid = $_.Properties[2].Value
		StartModule = $_.Properties[10].Value
		StartFunction = $_.Properties[11].Value
        
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName, DateUTC, SourceProcessId, ProcessGuid, SourceImage,   TargetImage , SourceUser, 
		SourceUser, TargetUser, StartFunction, StartModule
    }
}



Function Get-SysmonFileCreate {
<#
.SYNOPSIS
    Get-SysmonFileCreate extracts all Sysmon File Create Events [Evt 11] from the Sysymon Operational Event log for a specified timeframe
.DESCRIPTION

RuleName        : technique_id=T1574.010,technique_name=Services File Permissions Weakness
DateUTC         : 2023-02-18 10:53:00.499
SourceProcessId : 4740
ProcessGuid     : 6c4ade50-3808-63dd-5e00-00000000ad00
Image           : C:\WINDOWS\System32\svchost.exe
TargetFilename  : C:\Windows\System32\sru\SRUtmp.log
CreationUtcTime : 2020-08-26 12:32:09.752
User            : NT AUTHORITY\LOCAL SERVICE

.EXAMPLE
    Get-SysmonFileCreate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>

   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 11
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }
    $SHA1 = (Get-FileHash -Algorithm MD5 (Resolve-Path $SHA1 -ErrorAction SilentlyContinue).Path).SHA1

   $events | ForEach-Object {  
        $PropertyBag = @{
	    RuleName = $_.Properties[0].Value	
		DateUTC = $_.Properties[1].Value
		ProcessGuid = $_.Properties[2].Value
		SourceProcessId = $_.Properties[3].Value
		Image = $_.Properties[4].Value
        TargetFilename = $_.Properties[5].Value
        CreationUtcTime = $_.Properties[6].Value
		User  = $_.Properties[7].Value
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName, DateUTC, SourceProcessId, ProcessGuid,Image,   TargetFilename, CreationUtcTime,User
    }
}


Function Get-SysmonProcessTerminate {
<#
.SYNOPSIS
    The function Get-SysmonProcessTerminate retrieves Sysmon File Create Events [Evt 5] within a specified timeframe from the Sysmon Operational Event log.

.DESCRIPTION

RuleName        : technique_id=T1574.010,technique_name=Services File Permissions Weakness
DateUTC         : 2023-02-18 10:53:00.499
SourceProcessId : 4740
ProcessGuid     : 6c4ade50-3808-63dd-5e00-00000000ad00
Image           : C:\WINDOWS\System32\svchost.exe
TargetFilename  : C:\Windows\System32\sru\SRUtmp.log
CreationUtcTime : 2020-08-26 12:32:09.752
User            : NT AUTHORITY\LOCAL SERVICE

.EXAMPLE
    Get-SysmonProcessTerminate -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>

   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 5
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    RuleName = $_.Properties[0].Value	
		DateUTC = $_.Properties[1].Value
		ProcessGuid = $_.Properties[2].Value
		ProcessId = $_.Properties[3].Value
		Image = $_.Properties[4].Value
		User  = $_.Properties[5].Value
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName, DateUTC, ProcessGuid, ProcessId,Image,   User
    }
}

Function Get-SysmonRegAddDelete {
<#
.SYNOPSIS
    The function Get-SysmonRegAddDelete retrieves Sysmon File Create Events [Evt 12] within a specified timeframe from the Sysmon Operational Event log.

.DESCRIPTION

RuleName     : technique_id=T1553.004,technique_name=Install Root Certificate
EventType    : CreateKey
ProcessGuid  : 6c4ade50-aeae-63f0-e05b-00000000ad00
ProcessId    : 13240
Image        : C:\Program Files\Mozilla Firefox\firefox.exe
TargetObject : HKU\S-1-5-21-3292112416-2004140554-2480127568-1001\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates
User         : LAPTOP-HL1G97FB\Andrea

.EXAMPLE
    Get-SysmonRegAddDelete -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 12
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    RuleName = $_.Properties[0].Value	
		EventType = $_.Properties[1].Value
		UtcTime = $_.Properties[2].Value
		ProcessGuid = $_.Properties[3].Value
		ProcessId = $_.Properties[4].Value
	    Image   = $_.Properties[5].Value
		TargetObject   = $_.Properties[6].Value
		User   = $_.Properties[7].Value	  
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName, EventType, ProcessGuid, ProcessId,ProcessId,Image,TargetObject, User
    }
}

Function Get-SysmonReg {
<#
.SYNOPSIS
    Get-SysmonReg extracts all Sysmon Registry Value Set Events [Evt 13] from the Sysymon Operational Event log for a specified timeframe
.DESCRIPTION
    Query the event log and pull back all Sysmon Process Creation events. 

.EXAMPLE
     Get-SysmonReg -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'


#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 13
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    RuleName = $_.Properties[0].Value	
		EventType = $_.Properties[1].Value
		UtcTime = $_.Properties[2].Value
		ProcessGuid = $_.Properties[3].Value
		ProcessId = $_.Properties[4].Value
	    Image   = $_.Properties[5].Value
		TargetObject   = $_.Properties[6].Value
		User   = $_.Properties[7].Value	  
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName, EventType, ProcessGuid, ProcessId,ProcessId,Image,TargetObject, User
    }
}

Function Get-SysmonRegRename {
<#
.SYNOPSIS
    Get-SysmonRegRename extracts all Sysmon Registry Value Set Events [Evt 14] from the Sysymon Operational Event log for a specified timeframe
.DESCRIPTION
    Registry key and value rename operations map to this event type, recording the new name of the key or value that was renamed.

.EXAMPLE
     Get-SysmonRegRename -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'


#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 14
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    EventType = $_.Properties[0].Value	
		UtcTime = $_.Properties[1].Value
		ProcessGuid = $_.Properties[2].Value
		ProcessId = $_.Properties[3].Value
	    Image   = $_.Properties[5].Value
		TargetObject   = $_.Properties[6].Value
		NewName   = $_.Properties[7].Value	  
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object EventType, UtcTime, ProcessGuid, ProcessId,ProcessId,Image,TargetObject, NewName
    }
}


Function Get-SysmonDNS {
<#
.SYNOPSIS
    The function Get-SysmonDNS retrieves Sysmon DNS Events [Evt 22] within a specified timeframe from the Sysmon Operational Event log.

.DESCRIPTION
    Query the event log and pull back all Sysmon Process Creation events

.EXAMPLE
     Get-SysmonDNS -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 22
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    RuleName = $_.Properties[0].Value	
		UtcTime = $_.Properties[1].Value
		ProcessGuid = $_.Properties[2].Value
		ProcessId  = $_.Properties[3].Value
		QueryName = $_.Properties[4].Value
	    QueryStatus   = $_.Properties[5].Value
		QueryResults   = $_.Properties[6].Value
		Image = $_.Properties[7].Value
		User   = $_.Properties[8].Value	  
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName,UtcTime, ProcessGuid, ProcessId,QueryName,QueryStatus,QueryResults,Image, User
    }
}

Function Get-SysmonPipe {
<#
.SYNOPSIS
    The function Get-SysmonPipe retrieves Sysmon DNS Events [Evt 17] within a specified timeframe from the Sysmon Operational Event log.

.DESCRIPTION
    This event generates when a named pipe is created. Malware often uses named pipes for interprocess communication.

.EXAMPLE
     Get-SysmonPipe -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 17
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }
	}
	
	
Function Get-SysmonPipeConnected {
<#
.SYNOPSIS
    The function Get-SysmonPipeConnected retrieves Sysmon DNS Events [Evt 18] within a specified timeframe from the Sysmon Operational Event log.

.DESCRIPTION
    This event logs when a named pipe connection is made between a client and a server.

.EXAMPLE
     Get-SysmonPipeConnected -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 18
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    RuleName = $_.Properties[0].Value	
		EventType = $_.Properties[1].Value
		UtcTime = $_.Properties[2].Value
		ProcessGuid  = $_.Properties[3].Value
		ProcessId = $_.Properties[4].Value
		PipeName = $_.Properties[5].Value
		Image = $_.Properties[6].Value
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object RuleName,EventType, UtcTime, ProcessGuid,ProcessId,PipeName,Image
    }
}

Function Get-SysmonWMIFilter {
<#
.SYNOPSIS
   The Get-SysmonWMIFilter function is a PowerShell function that retrieves the WMI filter associated with a given Sysmon configuration.

.DESCRIPTION
    Query the event log and pull back all Sysmon Process Creation events

.EXAMPLE
     Get-SysmonWMIFilter -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 19
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    EventType = $_.Properties[0].Value	
		UtcTime = $_.Properties[1].Value
		Operation = $_.Properties[2].Value
		User  = $_.Properties[3].Value
		EventNamespace = $_.Properties[4].Value
	    Name   = $_.Properties[5].Value
		Query = $_.Properties[6].Value
		
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object EventType,UtcTime, Operation, User,EventNamespace,Name,Query
    }
}

Function Get-SysmonWMIConsumer {
<#
.SYNOPSIS
   The Get-SysmonWMIConsumer function is a PowerShell cmdlet that retrieves information about Windows Management Instrumentation (WMI) consumers configured for the Sysmon event logging tool. 

.DESCRIPTION
    Query the event log and pull back all Sysmon Process Creation events

.EXAMPLE
     Get-SysmonWMIConsumer -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 20
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    EventType = $_.Properties[0].Value	
		UtcTime = $_.Properties[1].Value
		Operation = $_.Properties[2].Value
		User  = $_.Properties[3].Value
		Typeo = $_.Properties[4].Value
	    Destination   = $_.Properties[5].Value
		
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object EventType,UtcTime, Operation, User,Name,Typeo,Destination
    }
}

Function Get-SysmonWMIBinding {
<#
.SYNOPSIS
    SysmonWMIBinding is a PowerShell function used to create a WMI event consumer for a specified Sysmon event filter.
	It creates a binding between a Sysmon event filter and a WMI event consumer, which allows the Sysmon events to be sent to the WMI consumer when the filter is triggered.
.DESCRIPTION
    Query the event log and pull back all Sysmon WMI FIlter/Consumer Binding events.

.EXAMPLE
     Get-SysmonWMIBinding -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 21
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    EventType = $_.Properties[0].Value	
		UtcTime = $_.Properties[1].Value
		Operation = $_.Properties[2].Value
		User  = $_.Properties[3].Value
		Consumer = $_.Properties[4].Value
	    Filtero   = $_.Properties[5].Value
		
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object EventType,UtcTime, Operation, User,Consumer,Filtero
    }
}

Function Get-SysmonDriver {
<#
.SYNOPSIS
    The Get-SysmonDriver function is a PowerShell function used to retrieve data from the Windows event log related to driver loads, as monitored by the Sysmon driver.
	The Sysmon driver is a system service and device driver that monitors system activity for security and forensic purposes.
.DESCRIPTION
    Query the event log and pull back all Sysmon Driver Load events. 

.EXAMPLE
     Get-SysmonDriver -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$StartTime = (Get-Date).AddMinutes(-5),

        [Parameter(Mandatory=$false)]
        [DateTime]$EndTime = (Get-Date).AddMinutes(5),

        [Parameter(Mandatory=$false)]
        [int]$EventId = 6
    )
		$ErrorActionPreference = 'SilentlyContinue'

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = $EventId
        StartTime = $StartTime
        EndTime = $EndTime
    }

   $events | ForEach-Object {  
        $PropertyBag = @{
	    UtcTime = $_.Properties[0].Value	
		ImageLoaded = $_.Properties[1].Value
		Hashes = $_.Properties[2].Value
		Signed  = $_.Properties[3].Value
		Signature = $_.Properties[4].Value
		SignatureStatus = $_.Properties[5].Value

        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
        $Output | Select-Object UtcTime,ImageLoaded, Hashes, Signed,Signature,SignatureStatus
    }
}

Function Get-DetectedMalware {
<#
.SYNOPSIS
    Get-DetectedMalware retrieves all "Microsoft Defender Antivirus" service installation events (Event ID 1116 and 1117) from the Windows Defender event log for a specified time frame.
.DESCRIPTION
    The antimalware platform detected malware or other potentially unwanted software.
    The antimalware platform performed an action to protect your system from malware or other potentially unwanted software.
.EXAMPLE
   Get-DetectedMalware -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'
#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

    $EventIds = @("1116", "1117")

    Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-Windows Defender/Operational';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
Select-Object TimeCreated, 
                      @{Name='Product Name';Expression={$_.Properties[0].Value}},
                      @{Name='Product Version';Expression={$_.Properties[1].Value}},
                      @{Name='Detection ID';Expression={$_.Properties[2].Value}},
                      @{Name='Detection Time';Expression={[datetime]::ParseExact($_.Properties[3].Value, 'yyyy-MM-ddTHH:mm:ss.fffZ', $null)}},
                      @{Name='Threat ID';Expression={$_.Properties[6].Value}},
                      @{Name='Threat Name';Expression={$_.Properties[7].Value}},
                      @{Name='Severity ID';Expression={$_.Properties[8].Value}},
                      @{Name='Severity Name';Expression={$_.Properties[9].Value}},
                      @{Name='Category ID';Expression={$_.Properties[10].Value}},
                      @{Name='Category Name';Expression={$_.Properties[11].Value}},
                      @{Name='FWLink';Expression={$_.Properties[12].Value}},
                      @{Name='Process Name';Expression={$_.Properties[18].Value}},
                      @{Name='Detection User';Expression={$_.Properties[19].Value}},
                      @{Name='Path';Expression={$_.Properties[21].Value}},
                      @{Name='Origin ID';Expression={$_.Properties[22].Value}},
                      @{Name='Origin Name';Expression={$_.Properties[23].Value}},
                      @{Name='Pre Execution Status';Expression={$_.Properties[28].Value}},
					  @{Name='Action Name';Expression={$_.Properties[30].Value}},
					  @{Name='Error Description';Expression={$_.Properties[33].Value}},
					  @{Name='Post Clean Status';Expression={$_.Properties[35].Value}},
					  @{Name='Additional Actions ID';Expression={$_.Properties[36].Value}},
					  @{Name='Additional Actions String';Expression={$_.Properties[37].Value}},
					  @{Name='Remediation User';Expression={$_.Properties[38].Value}},
					  @{Name='Security intelligence Version';Expression={$_.Properties[40].Value}},
					  @{Name='Engine Version';Expression={$_.Properties[41].Value}}
					 
					  
					  
}




Function Get-DefenderAVRealTimeDisabled{
<#
.SYNOPSIS
    Get-DefenderAVRealTimeDisabled extracts events [Evt 5001] from the Microsoft Defender AV.
.DESCRIPTION
    Real-time protection is disabled.
.EXAMPLE
   Get-DefenderAVRealTimeDisabled -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("5001")

    Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-Windows Defender/Operational';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * -ExcludeProperty Description |
        Format-List
}


Function Get-DefenderAntimalware{
<#
.SYNOPSIS
    Get-DefenderAntimalware extracts events [Evt 5001] from the Microsoft Defender AV.
.DESCRIPTION
    The antimalware engine found malware or other potentially unwanted software.

.EXAMPLE
   Get-DefenderAntimalware -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("1006", "1007")

    Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-Windows Defender/Operational';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * -ExcludeProperty Description |
        Format-List
}


Function Get-DefenderAVChanged{
<#
.SYNOPSIS
    Get-DefenderAVChanged extracts events [Evt 5007] from the Microsoft Defender AV.
.DESCRIPTION
    The antimalware platform configuration changed.
.EXAMPLE
   Get-DefenderAVChanged -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("5007")

    Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-Windows Defender/Operational';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * -ExcludeProperty Description |
        Format-List
}


Function Get-PassTheHash{
<#
.SYNOPSIS
    Get-PassTheHash extracts events [Evt 4624] from the Security Logs.
.DESCRIPTION
     This event now has a Logon Type of 9, which is NewCredential.
.EXAMPLE
   Get-PassTheHash -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4624")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Where-Object {
            $_.Properties[8].Value -match '9',
			$_.Properties[9].Value -match 'Seclogo'
        } |
        Select-Object TimeCreated, MachineName, ProviderName, Id, LevelDisplayName, Message, TaskDisplayName |
        Format-List
}


Function Get-LocalAccountCreated {
<#
.SYNOPSIS
    LocalAccountCreatedextracts events [Evt 4720] from the Security Logs.
.DESCRIPTION
     4720(S) A user account was created. (Windows 10) 
.EXAMPLE
   Get-LocalAccountCreated  -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4720")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * |
        Format-List
}


Function Get-LocalAccountAddedToAdmin {
<#
.SYNOPSIS
    Get-LocalAccountAddedToAdmin extracts events [Evt 4732] from the Security Logs.
.DESCRIPTION
     This event generates every time a new member was added to a security-enabled (security) local group 
.EXAMPLE
   Get-LocalAccountAddedToAdmin  -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-19T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4732")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * |
        Format-List
}

Function Get-LocalAccountPwdChanged {
<#
.SYNOPSIS
    Get-LocalAccountPwdChanged extracts events [Evt 4724] from the Security Logs.
.DESCRIPTION
     Event ID 4724 is generated every time an account attempts to reset the password for another account (both user and computer accounts). 
.EXAMPLE
   Get-LocalAccountPwdChanged -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4724")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * |
        Format-List
}


Function Get-LocalAccountDisabled {
<#
.SYNOPSIS
    Get-LocalAccountDisabled extracts events [Evt 4725] from the Security Logs.
.DESCRIPTION
     When a user account is disabled in Active Directory, event ID 4725 gets logged.

.EXAMPLE
   Get-LocalAccountDisabled -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4725")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * |
        Format-List
}


Function Get-LocalAccountLockout {
<#
.SYNOPSIS
    Get-LocalAccountLockout extracts events [Evt 4740] from the Security Logs.
.DESCRIPTION
     4740: A user account was locked out

.EXAMPLE
   Get-LocalAccountLockout -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4740")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * |
        Format-List
}


Function Get-LocalAccountChanged {
<#
.SYNOPSIS
    Event ID 4738 - A user account was changed

.DESCRIPTION
    Event ID 4738 - A user account was changed

.EXAMPLE
   Get-LocalAccountChanged -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4738")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * |
        Format-List
}


Function Get-LocalAccountEnabled {
<#
.SYNOPSIS
    Get-LocalAccountEnabled extracts events [Evt 4722] from the Security Logs.
.DESCRIPTION
    Event ID 4722 - A user account was enabled.

.EXAMPLE
   Get-LocalAccountEnabled -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4722")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * |
        Format-List
}

Function Get-UserAddedGlobalGroup {
<#
.SYNOPSIS
    Get-UserAddedGlobalGroup extracts events [Evt 4728-4729] from the Security Logs.
.DESCRIPTION
    Event ID 4728-4729 when User Added or Removed from Security-Enabled Global Group

.EXAMPLE
   Get-UserAddedGlobalGroup -StartTime '2023-02-18T08:06:00' -EndTime '2023-02-20T11:57:00'

#>
    param (
        [parameter(Mandatory = $true)]
        [DateTime]$StartTime,
        [parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

 $EventIds = @("4728", "4729")


Get-WinEvent -FilterHashTable @{LogName='Security';StartTime=$StartTime; EndTime=$EndTime; ID=$EventIds} |
        Select-Object * |
        Format-List
}
