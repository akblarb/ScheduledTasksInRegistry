param (
    [string]$taskCachePath="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
)

$timeStamp = Get-Date -Format "yyyy.MM.dd_HH.mm.ss.ffff"
$global:myLog = "$($PSScriptRoot)\$($($MyInvocation.MyCommand.Name).Split(".")[0])_$($timeStamp).log"


$usage = @'
Usage: ThisScript.ps1 -taskCachePath REGISTRYPATH


Optional:
  -taskCachePath REGISTRYPATH        Supply the registry path to \Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
                                        If not specified, default path is: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
                                        Specifying a path allows you to look at manually loaded offline registry hives like: HKEY_USERS\ALT_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks

  -h, -help                 Show this message and exit.
                                        
Examples:
  Look at manually loaded SOFTWARE hive
    ThisScript.ps1 -taskCachePath "HKEY_USERS\ALT_HKLM_SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
'@
Function myLogger() {
    param (
    [string]$myStr,
    [validateSet('info','warn','threat')][string]$warnLvl="info",
    [string]$logFile=$global:myLog
    )
    $myStr | Out-File -LiteralPath $logFile -Append
    If ($warnLvl -eq "info") {
        Write-host $myStr
    } ElseIf ($warnLvl -eq "warn") {
        Write-host $myStr -ForegroundColor Yello
    } ElseIf ($warnLvl -eq "threat") {
        Write-host $myStr -ForegroundColor DarkRed
    }
    
}


If (-not $taskCachePath.StartsWith("HKEY_LOCAL_MACHINE\SOFTWARE")) {
    myLogger -myStr "!!!Operating in Offline Forensic Mode!!!`r`n`t- Logged Registry Keys will reference the offline hives.`r`n`t- Commands to fix will be what need to be run on the infected computer.`r`n`t- Logging of TaskOnDisk will be irrelevant." -warnLvl "warn"
}

#Convert args to lowercase
If ($args.Count -eq 0) {
    [Array]$argsLC = @()
}Else{
    [Array]$argsLC = $args.ToLower()
}
#list all parameters specified in command
myLogger -myStr "Using $($PSBoundParameters.Keys.count) Parameters"
foreach ($i in $PSBoundParameters.GetEnumerator()) {
    myLogger -myStr " Parameter: $($i.key) = $($PSBoundParameters[$i.key])"
}
If ($argsLC.count -ne 0){
    If ($argsLC[0] -eq "-h" `
      -Or $argsLC[0] -eq "-help" `
      -Or $argsLC[0] -eq "--help" `
      -Or ($PSBoundParameters.Values.Count -eq 0 -and $args.count -eq 0)) {
        myLogger -myStr $usage
        Exit
    }
}
#start looking at the TaskCache
myLogger -myStr "`r`nExamining Registry $($taskCachePath)Path: "
$allTaskCache = (ls "Registry::$($taskCachePath)\").Name
$countFound = 0
$regCommandClean = ""
$mainTaskCachePath = (($taskCachePath.split("\"))[0..6] -join "\")
$allTreeCachePath = $mainTaskCachePath+"\Tree"
foreach ($key in $allTaskCache) {
    $authorStr = "null"
    $dateStr = "null"
    $existsOnDisk = "null"
    $relatedTreeKey = "null"
    $allTreeCache = "null"
    $treeKey = "null"
    $actionsByte = (Get-ItemProperty -Path "Registry::$($Key)").Actions
    #myLogger -myStr "`t`tBytes: $($actionsByte)"
    $actionsStr = (-join ([System.Text.Encoding]::ASCII.GetChars($actionsByte))) -replace '[^\x20-\x7e]+', ''#Gets the action executed by the task, strips all non-printable ASCII characters.
    If ( $actionsStr.ToLower().Contains("powershell")) {
        $countFound++
        $authorStr = (Get-ItemProperty -Path "Registry::$($Key)" -ErrorAction SilentlyContinue).Author
        $dateStr = (Get-ItemProperty -Path "Registry::$($Key)" -ErrorAction SilentlyContinue).Date
        myLogger -myStr "`r`n  Found Item[ID_$($countFound)]:"
        myLogger -myStr "`tKey: $($key)"
        $regCommandClean = "$($regCommandClean)REG EXPORT ""$($key)"" ""$($PSScriptRoot)\ID_$($countFound)_TASK_$($timeStamp).reg""`r`nREG DELETE ""$($key)"" /f`r`n"
        myLogger -myStr "`t`tCommand(Action): $($actionsStr)" -warnLvl "threat"
        myLogger -myStr "`t`t`tCreatedByUser(Author): $($authorStr)"
        myLogger -myStr "`t`t`tCreatedOn(Date)[MightBeLastRun]: $($dateStr)"
        $allTreeCache = (ls "Registry::$($allTreeCachePath)" -recurse)
        $allTreeCache | ForEach-Object {
            $treeKey = $_
            If (-not [string]::IsNullOrEmpty($treeKey.GetValue("Id"))) {
                If ($treeKey.GetValue("Id").Contains("{73BD3E1C-DABE-4DF5-A7A6-63906C2CFF11}")){
                    $relatedTreeKey = $treeKey.Name
                    myLogger -myStr "`tRelatedKey(Tree): $($relatedTreeKey)"
                    $regCommandClean = "$($regCommandClean)REG EXPORT ""$($relatedTreeKey)"" ""$($PSScriptRoot)\ID_$($countFound)_TREE_$($timeStamp).reg""`r`nREG DELETE ""$($relatedTreeKey)"" /f`r`n"
                    myLogger -myStr "`t`tTaskOnDisk: $($relatedTreeKey.Replace("$($allTreeCachePath)", "$($env:SystemRoot)\System32\Tasks"))"
                    $existsOnDisk = Test-Path "$($relatedTreeKey.Replace("$($allTreeCachePath)", "$($env:SystemRoot)\System32\Tasks"))" -PathType Leaf
                    myLogger -myStr "`t`t`tExistsOnDisk: $($existsOnDisk)"
                    If ($existsOnDisk){
                        $regCommandClean = "$($regCommandClean)DEL ""$($relatedTreeKey.Replace("$($allTreeCachePath)", "$($env:SystemRoot)\System32\Tasks"))"" /f /q`r`n"
                    }
                }
            }
        }
        
    }
}

If ($countFound -ne 0){
    $outcome = "threat"
}Else{
    $outcome = "info"
}
myLogger -myStr "`r`n`r`n-------------------------`r`n Count of found items: $($countFound)`r`n-------------------------`r`n" -warnLvl $outcome
If ($countFound -ne 0){
    myLogger -myStr "The following commands will clean up the found items:`r`n`r`n----------------------------------------------------------------------------------------------------"
    myLogger -myStr "$($regCommandClean)".Replace("HKEY_USERS\ALT2_HKLM_SOFTWARE", "HKEY_LOCAL_MACHINE\SOFTWARE")
    myLogger -myStr "NET STOP SCHEDULER"
    myLogger -myStr "NET START SCHEDULER"
    
    myLogger -myStr "----------------------------------------------------------------------------------------------------"
    myLogger -myStr "After running the above commands, you should reboot as soon as possible and run a full scan with ESET`r`n`r`n"
}
myLogger -myStr "Information logged to: $($global:myLog)`r`n" -warnLvl "warn"