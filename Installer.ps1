Add-Type -AssemblyName PresentationFramework

$msgBoxTitle = "PS Login Monitor"

$ScriptPath = "$env:ProgramFiles\WindowsPowerShell\Modules\PS Login Monitor"
New-Item -ItemType directory -Path $ScriptPath -Force
Copy-Item -Path $PSScriptRoot\PSLoginMonitor.ps1 -Destination $ScriptPath -Force
    
$messageBoxMsg = "Do you want to set up RDP/RDS login monitoring?"
$installRdpMonitor = [System.Windows.MessageBox]::Show($messageBoxMsg, $msgBoxTitle, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)
    
if($installRdpMonitor -eq "Yes")
{
    auditpol /set /subcategory:Logon /success:enable /failure:enable
    Register-ScheduledTask -Xml (get-content "$PSScriptRoot\PS Login Monitor - RDP.xml" | out-string) -TaskName "PS Login Monitor - RDP" -Force
}

$messageBoxMsg = "Do you want to set up MSSQL login monitoring?"
$installMssqlMonitor = [System.Windows.MessageBox]::Show($messageBoxMsg, $msgBoxTitle, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)

if($installMssqlMonitor -eq "Yes")
{
    Register-ScheduledTask -Xml (get-content "$PSScriptRoot\PS Login Monitor - MSSQL.xml" | out-string) -TaskName "PS Login Monitor - MSSQL" -Force
}

if($installRdpMonitor -eq "Yes" -or $installMssqlMonitor -eq "Yes")
{
    Register-ScheduledTask -Xml (get-content "$PSScriptRoot\PS Login Monitor - Update Firewall Rules.xml" | out-string) -TaskName "PS Login Monitor - Update Firewall Rules" -Force
    [System.Windows.MessageBox]::Show("Tasks registered", "Title", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
}