﻿# DEFENDER KQL

## MDE Device Health

```kql
// Type: MDE Advanced Hunting
// Purpose: List Devices with sendor health information and impaired communication
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ('scid-91', 'scid-2000', 'scid-2001', 'scid-2002', 'scid-2003', 'scid-2010', 'scid-2011', 'scid-2012', 'scid-2013', 'scid-2014', 'scid-2016')
| extend Test = case(
    ConfigurationId == "scid-2000", "SensorEnabled",
    ConfigurationId == "scid-2001", "SensorDataCollection",
    ConfigurationId == "scid-2002", "ImpairedCommunications",
    ConfigurationId == "scid-2003", "TamperProtection",
    ConfigurationId == "scid-2010", "AntivirusEnabled",
    ConfigurationId == "scid-2011", "AntivirusSignatureVersion",
    ConfigurationId == "scid-2012", "RealtimeProtection",
    ConfigurationId == "scid-91", "BehaviorMonitoring",
    ConfigurationId == "scid-2013", "PUAProtection",
    ConfigurationId == "scid-2014", "AntivirusReporting",
    ConfigurationId == "scid-2016", "CloudProtection",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| extend packed = pack(Test, Result)
| summarize Tests = make_bag(packed), DeviceName = any(DeviceName) by DeviceId
| evaluate bag_unpack(Tests)

```

### Show ASR events

```kql
// Type: MDE Advanced Hunting
// Purpose: List all Attack Surface Reduction events in the last 20 days
DeviceEvents 
| where Timestamp > ago(20d)   
| where ActionType startswith "Asr"
| project DeviceName,ActionType,FileName,FolderPath,ProcessCommandLine,AccountName
```

### MDAV Scan Completed

```kql
// Type: MDE Advanced Hunting
// Purpose: List all MDE scans in the last n days for a specific device, with scan type - Full, Quick or Custom
// Note: EDR data only contains the scan end event. The start event is available in the client event log
let dName = "PC123456";
DeviceEvents
| where TimeStamp > ago(7d)
| where DeviceName startswith dName
| where ActionType contains "AntiVirusScan"
| extend Scantype = parse_json(AdditionalFields).ScanTypeIndex
| order by Timestamp desc
| project Timestamp, DeviceName,ActionType,ScanType
```

### Scheduled MDAV scans not running

```kql
// Type: MDE Advanced Hunting
// Purpose: List Windows Devices without a successful AV scan in the last n days
let Timerange = 14d;
DeviceInfo
| where OnboardingStatus == "Onboarded"
| where isnotempty( OSVersion)
| where Timestamp > ago(Timerange)
| summarize LastSeen = arg_max(Timestamp, *) by DeviceId
| extend LastSuccessfulAVScan = strcat("Not in the last ",format_timespan(Timerange,'d')," days")
| project LastSeen, DeviceId, DeviceName, MachineGroup, OSPlatform, OSVersion, DeviceType, LastSuccessfulAVScan, JoinType
// use rightsemi to return all devices that had a successful AV scan in the last n days
// use leftanti to return all devices that NOT had a successful AV scan in the last n days
| join kind=leftanti (
    DeviceEvents
    | where ActionType == "AntivirusScanCompleted"
    | where Timestamp > ago(Timerange)
    | summarize LastSuccessfulAVScan = max(Timestamp) by DeviceName, DeviceId
    | join kind=innerunique (
        DeviceInfo
        | where isnotempty( OSVersion )
    ) on DeviceId
    | summarize LastSeen = arg_max(Timestamp,*) by DeviceName
    | project LastSeen, DeviceId, DeviceName, MachineGroup, OSPlatform, OSVersion, DeviceType, LastSuccessfulAVScan, JoinType
) on DeviceId
| where OSPlatform in ("Windows10","Windows10WVD","Windows11","WindowsServer2012R2","WindowsServer2016","WindowsServer2019","WindowsServer2022")
| sort by DeviceType, MachineGroup, OSPlatform
```

### MDAV version and running mode

```kql
// Type: MDE Advanced Hunting
// Purpose: List devices with the platform, engine and signature version, and whether they are running in Active or Passive mode
let avmodetable = DeviceTvmSecureConfigurationAssessment
  | where Timestamp > ago(14d)
  | where ConfigurationId == "scid-2010" and isnotnull(Context)
  | extend avdata=parsejson(Context)
  | extend AVMode = iif(tostring(avdata[0][0]) == '0', 'Active' , iif(tostring(avdata[0][0]) == '1', 'Passive' ,iif(tostring(avdata[0][0]) == '4', 'EDR Blocked' ,'Unknown')))
  | project DeviceId, AVMode;
  DeviceTvmSecureConfigurationAssessment
  | where ConfigurationId == "scid-2011" and isnotnull(Context)
  | extend avdata=parsejson(Context)
  | extend AVSigVersion = tostring(avdata[0][0])
  | extend AVEngineVersion = tostring(avdata[0][1])
  | extend AVSigLastUpdateTime = tostring(avdata[0][2])
  | extend AVProductVersion = tostring(avdata[0][3]) 
  | project DeviceId, DeviceName, OSPlatform, AVSigVersion, AVEngineVersion, AVSigLastUpdateTime, AVProductVersion, IsCompliant, IsApplicable
  | join avmodetable on DeviceId
  | project-away DeviceId1
```

### Troubleshooting Mode times

```kql
// Type: MDE Advanced Hunting
// Purpose: List start and end times for MDE Troubleshooting Mode
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "AntivirusTroubleshootModeEvent"
| extend StateChange = tostring(parse_json(AdditionalFields).TroubleshootingStateChangeReason)
| extend StartTime = tostring(parse_json(AdditionalFields).TroubleshootingStartTime)
| extend EndTime = tostring(parse_json(AdditionalFields).TroubleshootingEndTime)
| order by Timestamp desc
| project Timestamp,DeviceName,ActionType,StateChange,StartTime,EndTime

```

### USB Printer Connected

```kql
// Type: MDE Advanced Hunting
// Purpose: List PnP Device Events for USB Printers
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "PnPDeviceConnected"
| extend json = parse_json(AdditionalFields)
| extend Description = tostring(json.DeviceDescription)
| extend DeviceId = tostring(json.DeviceId)
| extend ClassId = tostring(json.ClassId)
| project Timestamp, DeviceId,ClassId,Description,ActionType,json

```
