<# Configuration variables #>

<#
    Number of failed logins before an IP address is blocked. Values less than or
    equal to 1 are treated as 1 (block on first failed login). Recommended value is
    3-10. Note that some brute-force attacks can initiate several login attempts per second,
    so some IPs will be able to attempt a handful of logins beyond the block threshold before
    being stopped by the Windows firewall. From testing this is usually at most 3-4 beyond
    the set block count.
#>
$BlockCount = 3

<# 
    Once an IP address is blocked, how many hours before it is unblocked. Values less than 0
    are treated as infinite (never unblock). Recommended value is 24 hours to prevent Windows
    firewall from filling up.
#>
$BlockTimeHours = 24

 <# 
    After a failed login, how long before the failed login counter is "reset". Intended to
    prevent one-off login failures from blocking an IP over a long period of time. From testing
    1 - 3 hours appears to work best.
 #>
$ResetCounterTimeHours = 3

<#
   List of IPs to ignore login failures. Ranges must be in CIDR notation. Default list is all
   private IPv4 ranges.
#>
$WhiteList = @(
               "127.0.0.0/8",
               "192.168.0.0/16",
               "172.16.0.0/12",
               "10.0.0.0/8"
              )

<# Configuration variables #>


<# Constants #>
$dtFormat = "yyyy-MM-dd HH:mm:ss"
$ruleNameTemplate = "PS Login Monitor block for {0}"
$FirewallGroup = "PS Login Monitor"

[xml]$LoginData = 
“<LoginData>
    <IpAddress></IpAddress>
    <FailedLoginCount></FailedLoginCount>
    <LastLoginTime></LastLoginTime>
    <CounterResetTime></CounterResetTime>
    <UnblockTime></UnblockTime>
</LoginData>”

$EventIdsToProcess = @(
                        4625,  # Failed windows/RDP login
                        18456, # Failed MSSQL login, but can also be triggered by other connection failures that are filtered out by $MssqlTextFilters array
                        17828, # Usually the result of some kind of port scan on MSSQL port
                        17832, # Usually the result of some kind of port scan on MSSQL port
                        17836  # Usually the result of some kind of port scan on MSSQL port
                      )

#For MSSQL event 18456 there are some login failures that a block is not desired and are filtered out based on message text.
$MssqlTextFilters = @(
                        "Login is valid login, but server access failed.",
                        "Login is valid, but server access failed.",
                        "Password must be changed."
                      )
<# Constants #>

<#
    IP address functions. Thanks to the author of this code here: http://www.gi-architects.co.uk/2016/02/powershell-check-if-ip-or-subnet-matchesfits/
#>
function Check-Subnet ([string]$addr1, [string]$addr2)
{
    # Separate the network address and length
    $network1, [int]$subnetlen1 = $addr1.Split('/')
    $network2, [int]$subnetlen2 = $addr2.Split('/')

 
    #Convert network address to binary
    [uint32] $unetwork1 = NetworkToBinary $network1
 
    [uint32] $unetwork2 = NetworkToBinary $network2
 
 
    #Check if subnet length exists and is less then 32(/32 is host, single ip so no calculation needed) if so convert to binary
    if($subnetlen1 -lt 32)
    {
        [uint32] $mask1 = SubToBinary $subnetlen1
    }
 
    if($subnetlen2 -lt 32)
    {
        [uint32] $mask2 = SubToBinary $subnetlen2
    }
 
    #Compare the results
    if($mask1 -and $mask2)
    {
        # If both inputs are subnets check which is smaller and check if it belongs in the larger one
        if($mask1 -lt $mask2)
        {
            return CheckSubnetToNetwork $unetwork1 $mask1 $unetwork2
        }
        else
        {
            return CheckNetworkToSubnet $unetwork2 $mask2 $unetwork1
        }
    }
    ElseIf($mask1)
    {
        # If second input is address and first input is subnet check if it belongs
        return CheckSubnetToNetwork $unetwork1 $mask1 $unetwork2
    }
    ElseIf($mask2)
    {
        # If first input is address and second input is subnet check if it belongs
        return CheckNetworkToSubnet $unetwork2 $mask2 $unetwork1
    }
    Else
    {
        # If both inputs are ip check if they match
        CheckNetworkToNetwork $unetwork1 $unetwork2
    }
}

function CheckNetworkToSubnet ([uint32]$un2, [uint32]$ma2, [uint32]$un1)
{
    $ReturnArray = "" | Select-Object -Property Condition,Direction

    if($un2 -eq ($ma2 -band $un1))
    {
        $ReturnArray.Condition = $True
        $ReturnArray.Direction = "Addr1ToAddr2"
        return $ReturnArray
    }
    else
    {
        $ReturnArray.Condition = $False
        $ReturnArray.Direction = "Addr1ToAddr2"
        return $ReturnArray
    }
}

function CheckSubnetToNetwork ([uint32]$un1, [uint32]$ma1, [uint32]$un2)
{
    $ReturnArray = "" | Select-Object -Property Condition,Direction

    if($un1 -eq ($ma1 -band $un2))
    {
        $ReturnArray.Condition = $True
        $ReturnArray.Direction = "Addr2ToAddr1"
        return $ReturnArray
    }
    else
    {
        $ReturnArray.Condition = $False
        $ReturnArray.Direction = "Addr2ToAddr1"
        return $ReturnArray
    }
}

function CheckNetworkToNetwork ([uint32]$un1, [uint32]$un2)
{
    $ReturnArray = "" | Select-Object -Property Condition,Direction

    if($un1 -eq $un2)
    {
        $ReturnArray.Condition = $True
        $ReturnArray.Direction = "Addr1ToAddr2"
        return $ReturnArray
    }
    else
    {
        $ReturnArray.Condition = $False
        $ReturnArray.Direction = "Addr1ToAddr2"
        return $ReturnArray
    }
}

function SubToBinary ([int]$sub)
{
    return ((-bnot [uint32]0) -shl (32 - $sub))
}

function NetworkToBinary ($network)
{
    $a = [uint32[]]$network.split('.')
    return ($a[0] -shl 24) + ($a[1] -shl 16) + ($a[2] -shl 8) + $a[3]
}

function Get-UnblockTime
{
    if($BlockTimeHours -lt 1)
    {
        $unblockTime = [DateTime]::ParseExact("9999-12-31 23:23:59", $dtFormat, $null).ToString($dtFormat)
    }
    else
    {
        $unblockTime = (Get-Date).AddHours($BlockTimeHours).ToString($dtFormat)
    }
    $unblockTime
}

<#Task Scheduler functions#>

<#
    Called by scheduled task to remove/clean up firewall rules.
#>
function UpdateFirewallRules
{
    # Delete firewall rules with the following conditions:
    # 1) Block time has expired for enabled firewall rules
    # 2) Counter reset time has expired for disabled firewall rules
    if($BlockTimeHours -gt 0)
    {
        Get-NetFirewallRule -Group $FirewallGroup -Enabled True | Where-Object {
            [DateTime]::ParseExact(([xml]$_.Description).LoginData.UnblockTime, $dtFormat, $null) -lt (Get-Date)
        } | ForEach { Remove-NetFirewallRule -Name $_.Name }
    }
    Get-NetFirewallRule -Group $FirewallGroup -Enabled False | Where-Object {
        [DateTime]::ParseExact(([xml]$_.Description).LoginData.CounterResetTime, $dtFormat, $null) -lt (Get-Date)
    } | ForEach { Remove-NetFirewallRule -Name $_.Name }

    # Clean up multiple firewall rules for same IP, block as needed.
    # This happens when a client attempts a low number of logins in quick
    # succession such that multiple disabled rules are created. This process groups
    # these rules up and sums the recorded login attempts to compare with the block
    # threshold value then enables as needed.
    Get-NetFirewallRule -Group $FirewallGroup -Enabled False | ForEach-Object {
        New-Object -Type PSObject -Property @{
            'DisplayName' =  $_.DisplayName
            'FailedLoginCount'  =  [int]([xml]$_.Description).LoginData.FailedLoginCount
        }
    } | Group-Object DisplayName | ForEach-Object {
        New-Object -Type PSObject -Property @{
            'DisplayName' = $_.Group | Select -Expand DisplayName -First 1
            'FailedLoginCount'   = ($_.Group | Measure-Object FailedLoginCount -Sum).Sum
        }
    } | Where-Object { $_.FailedLoginCount -ge $BlockCount } | ForEach-Object {
        Enable-NetFirewallRule -DisplayName $_.DisplayName
    }

    #Removes duplicate firewall rules created by the previous process
    (Get-NetFirewallRule -Group $FirewallGroup -Enabled True) | ForEach-Object {
        New-Object -Type PSObject -Property @{
            'DisplayName' =  $_.DisplayName
            'Name'  =  $_.Name
        }
    } | Group-Object DisplayName | Where-Object {$_.Count -gt 1} | ForEach-Object {
        $_.Group | Select-Object -SkipLast 1 | ForEach-Object { Remove-NetFirewallRule -Name $_.Name }
    }
}

function On-FailedRdpLogin
{
    [cmdletbinding()]
    Param
    (
        [parameter(position = 0, Mandatory=$true)]
        [int]
        $EventId,

        [parameter(position = 1, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $SubjectUserSid,

        [parameter(position = 2, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $SubjectUserName,

        [parameter(position = 3, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $SubjectDomainName,

        [parameter(position = 4, Mandatory=$true)]
        [int]
        $SubjectLogonId,

        [parameter(position = 5, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $TargetUserSid,

        [parameter(position = 6, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $TargetUserName,

        [parameter(position = 7, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $TargetDomainName,

        [parameter(position = 8, Mandatory=$true)]
        [int]
        $Status,

        [parameter(position = 9, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $FailureReason,

        [parameter(position = 10, Mandatory=$true)]
        [int]
        $SubStatus,

        [parameter(position = 11, Mandatory=$true)]
        [int]
        $LogonType,

        [parameter(position = 12, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $LogonProcessName,

        [parameter(position = 13, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $AuthenticationPackageName,

        [parameter(position = 14, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $WorkstationName,

        [parameter(position = 15, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $TransmittedServices,

        [parameter(position = 16, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $LmPackageName,

        [parameter(position = 17, Mandatory=$true)]
        [int]
        $KeyLength,

        [parameter(position = 18, Mandatory=$true)]
        [int]
        $ProcessId,

        [parameter(position = 19, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $ProcessName,

        [parameter(position = 20, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $IpAddress,

        [parameter(position = 21, Mandatory=$true)]
        [int]
        $IpPort
    )
    # Only capture these login types (from https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events):
    #  3 - Network - A user or computer logged on to this computer from the network.
    # 10 - RemoteInteractive - A user logged on to this computer remotely using Terminal Services or Remote Desktop.

    $loginTypesToProcess = @(3, 10);
    
    if($loginTypesToProcess.Contains($LogonType))
    {
        ProcessFailedLogin $EventId $IpAddress
    }
}

function On-FailedMssqlLogin
{
    [cmdletbinding()]
    Param
    (
        [parameter(position = 0, Mandatory=$true)]
        [int]
        $EventId,
        [parameter(position = 1, Mandatory=$true)]
        [string]
        $EventData
    )
    foreach($msg in $MssqlTextFilters)
    {
        if($EventData.Contains($msg) -eq $true)
        {
            return
        }
    }
    $EventDataArray = $EventData.Split(',')
    $IpAddress = ''

    # Use Regex to extract client IP address
    $Regex = [Regex]::new('(?<=\[CLIENT: )(.*)(?=\])')
    foreach ($data in $EventDataArray)
    {
        $Match = $Regex.Match($data)
        if ($Match.Success)
        {
            $IpAddress = $Match.Value.Trim()
            break
        }
    }
    ProcessFailedLogin $EventId $IpAddress
}

function ProcessFailedLogin
{
    [cmdletbinding()]
    Param
    (
        [parameter(position = 0, Mandatory=$true)]
        [int]
        $EventID,

        [parameter(position = 1, Mandatory=$true)]
        [AllowEmptyString()]
        [string]
        $IpAddress
    )

    if($EventIdsToProcess.Contains($EventId) -eq $false)
    {
        return
    }

    if($IpAddress -eq '' -or $IpAddress.Contains("localhost") -eq $true)
    {
        return
    }

    foreach($ip in $WhiteList)
    {
        if((Check-Subnet $IpAddress $ip).Condition -eq $true)
        {
            return
        }   
    }

    $RuleName = [string]::Format($ruleNameTemplate, $IpAddress)

    $FWRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Select-Object -First 1

    $counterResetTime = (Get-Date).AddHours([System.Math]::Max($ResetCounterTimeHours, 1)).ToString($dtFormat)

    if($FWRule -eq $null) #First failed login
    {
        #Login data saved to rule description field
        [xml]$description = $LoginData

        $description.LoginData.FailedLoginCount = "1"
        $description.LoginData.IpAddress = $IpAddress
        $description.LoginData.CounterResetTime = $counterResetTime
        $description.LoginData.UnblockTime = Get-UnblockTime
        $description.LoginData.LastLoginTime = (Get-Date).ToString($dtFormat)

        #Set placeholder rule that will be enabled when failed login threshold met
        $enabled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False

        if($BlockCount -le 1) #Block on first failed attempt
        {
            $enabled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True
        }

        New-NetFirewallRule -DisplayName $RuleName `
        -Direction Inbound `
        -Description $description.OuterXml `
        -InterfaceType Any `
        -Group $FirewallGroup `
        -Action Block `
        -RemoteAddress $IpAddress `
        -Enable $enabled
    }
    else #Subsequent login failures
    {
        $description = [xml]($FWRule.Description) #Pull XML from rule description field
        $description.PreserveWhitespace = $true
        $loginCount = [int]$description.LoginData.FailedLoginCount
        $loginCount = $loginCount + 1 #increment failed login count

        $description.LoginData.CounterResetTime = $counterResetTime
        $description.LoginData.UnblockTime = Get-UnblockTime
        $description.LoginData.FailedLoginCount = $loginCount.ToString()
        $description.LoginData.LastLoginTime = (Get-Date).ToString($dtFormat)

        if($loginCount -ge $BlockCount)
        {
            Enable-NetFirewallRule -Name $FWRule.Name
        }

        Set-NetFirewallRule -Name $FWRule.Name -Description $description.OuterXml #Update XML in description field
    }
}
<#
    Displays data stored in firewall rules for recent failed login attempts by client IP address
#>
function Show-FirewallRuleStats
{
    Get-NetFirewallRule -Group $FirewallGroup | ForEach-Object {
        New-Object -Type PSObject -Property @{
            'IPAddress' =  ([xml]$_.Description).LoginData.IpAddress
            'Failed Login Count'  =  [int]([xml]$_.Description).LoginData.FailedLoginCount
            'Last Login Attempt' = [DateTime]([xml]$_.Description).LoginData.LastLoginTime
            'Unblock Time' = [DateTime]([xml]$_.Description).LoginData.UnblockTime
            'Counter Reset Time' = [DateTime]([xml]$_.Description).LoginData.CounterResetTime
            'Blocked' = (&{If($_.Enabled -eq "True") {"Yes"} Else {"No"}})
        } 
    } | Sort-Object -Descending {$_."Last Login Attempt"
    } | Format-Table -AutoSize -Property 'IPAddress', 'Failed Login Count', 'Last Login Attempt', 'Unblock Time', 'Counter Reset Time', 'Blocked'
}