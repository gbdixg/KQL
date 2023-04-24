# KQL
KQL queries for reference

## EXAMPLES

### Autostart modification

// A file in XLStart folder was modified, excluding by MDE itself
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath contains "AppData\\Roaming\\Microsoft\\Excel\\XLSTART"
| where ActionType in ('FileCreated','FileModified')
| where InitiatingProcessFileName != 'MsMpEng.exe'
| project Timestamp,DeviceName,ActionType,FolderPath,InitiatingProcessFileName


### Finding Local Admins

// User is logged on with administrative rights. Also, identify if its a local account
DeviceLogonEvents
| where Timestamp > ago(30d)
| where IsLocalAdmin == 1
| extend locallogon = extractjson(“$.IsLocalLogon”,AdditionalFields, typeof(string))
| project Timestamp, DeviceName, AccountDomain, AccountName, LogonType, ActionType, locallogon
| distinct AccountDomain, AccountName, DeviceName
| sort by AccountDomain asc

### Show ASR events

// Attack Surface Reduction events
DeviceEvents 
| where Timestamp > ago(20d)   
| where ActionType startswith "Asr"
| project DeviceName,ActionType,FileName,FolderPath,ProcessCommandLine,AccountName


### Users accessing OneDrive and network home share

// Find users accessing files on OneDrive and a mapped home drive
let days = 21d;
let onPremDomain = 'Contoso';
(DeviceProcessEvents
| where Timestamp > ago(days)
| where ProcessCommandLine contains "OneDrive - " and AccountDomain == onPremDomain
| summarize onedrive_count = count() by AccountName)
| join (DeviceProcessEvents
  | where Timestamp > ago(days)
  | where ProcessCommandLine has_any ('h:\\','u:\\')
  | summarize homedrive_count = count() by AccountName)
on AccountName
| where homedrive_count > 0 and onedrive_count > 0
| sort by homedrive_count desc 
| project AccountName,homedrive_count,onedrive_count

### Uncommon PowerShell commands

// PowerShell Commands
let powershellCommands = DeviceEvents
| where Timestamp > ago(5d)
| where ActionType == "PowerShellCommand"
| extend PowerShellCommand=extractjson("$.Command", AdditionalFields, typeof(string))
| where PowerShellCommand !endswith ".ps1" and PowerShellCommand !endswith ".exe";
let commonCommands =
    powershellCommands
    | summarize MachineCount=dcount(DeviceId) by PowerShellCommand
    | where MachineCount > 20;
powershellCommands
| where Timestamp > ago (5d)
| join kind=leftanti (commonCommands) on PowerShellCommand
| sort by Timestamp desc


