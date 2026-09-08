$listener = Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction Stop | Select-Object -First 1
$process = Get-Process -Id $listener.OwningProcess -ErrorAction Stop
$task = Get-ScheduledTask -TaskName "CAPE Agent" -ErrorAction Stop
[ordered]@{
    process_id = $process.Id
    session_id = $process.SessionId
    run_as = $task.Principal.UserId
    logon_type = $task.Principal.LogonType.ToString()
    trigger_type = $task.Triggers[0].CimClass.CimClassName
    listener = "$($listener.LocalAddress):$($listener.LocalPort)"
} | ConvertTo-Json