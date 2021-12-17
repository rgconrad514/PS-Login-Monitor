# PS Login Monitor
## Simple brute force login protection for RDP/RDS and MS SQL Server using PowerShell and Windows task scheduler.

# Foreword
Obviously opening either RDP or MSSQL to the internet is a bad idea. But sometimes it's unavoidable, particularly with RDP when a remote worker needs quick access to their office machine and setting up a VPN or standing up a proper RDS server isn't possible. Here is a simple and effective Powershell script for tracking and quickly blocking malicious IPs attempting to brute force your RDP or MSSQL server.

# Introduction
If for one reason or another you need a remotely accessible MSSQL database (lab environment, legacy software, etc.) or RDP/RDS server, it will inevitably become the target of brute force login attempts. Fortunately, Windows provides auditing mechanisms for these services that capture the source IP along with other information in the event log, and task scheduler provides a means for triggering a program to run when an event is captured, and even allows you to pass the event data to the program.

There are many Powershell scripts that can be found on the internet that provide auditing and IP address blocking functionality, but most rely on periodic scanning of the windows event log to extract a list of IP addresses with some minimum number of login attempts, and then create the necessary block rules in Windows firewall. Scanning the event log is a slow process and many brute force programs can attempt several logins per second. Many also fail to provide some automated process to unblock an IP address after a certain amount of time to prevent the Windows firewall from filling up with too many rules. So here is a solution that solves all of that requiring only Powershell, an enabled Windows firewall and task scheduler.

# Setup
For RDP/RDS logon auditing must be turned on either using a GPO or local security policy. This can also be done by running `auditpol /set /subcategory:Logon /success:enable /failure:enable` from an elevated command prompt. The [installer.ps1](https://github.com/rgconrad514/PS-Login-Monitor/blob/main/Installer.ps1) script turns this auditing on.

<img src="https://user-images.githubusercontent.com/24600116/146600886-9b55711a-8b61-4a51-81a2-3a6242901b82.PNG" width=50% height=50%>

For MSSQL under the server properties, failed logins must be enabled (service must be restarted for changes to take effect).

![MSSQL Auditing](https://user-images.githubusercontent.com/24600116/146601280-4de5a758-3a81-4a85-99b5-70744955472a.PNG)

# How it works
For each service a Windows Task Scheduler task is created which is triggered off the relevant event IDs that indicate failed login attempts. The event data are extracted using task scheduler's [XPath](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/7c233179-1ce9-4b0f-a579-e2baac430025?redirectedfrom=MSDN) functionality and then passed to the powershell script. This allows for real-time tracking of failed login attempts and quicker blocking of malicious IPs. On the first failed login attempt the script creates a disabled firewall rule for the IP as a placeholder and saves information in the description field as XML. The important data saved are number of failed login attempts, the unblock date/time and a counter reset date/time. For each subsequent attempt, the firewall rule is retreived, the counter incremented and if the number of failed logins exceeds the preset threshold, the firewall rule is enabled. The event-triggered tasks are set to run in parallel and with the highest priorty to capture frequent login attempts quickly.

An additional scheduled task is run every minute and scans existing firewall rules and cleans up duplicates. For each rule the unblock time and counter reset time are extracted from the XML saved in the description field. Any enabled rules with expired unblock times are removed as well as disabled rules with expired counter reset times. In some cases multiple login attempts that don't exceed the block threshold will lead to the creation of more than one disabled firewall rule. This task will iterate through these, tally up the login attempts then create a single enabled rule and delete the duplicates.

# Installing
From an elevated PowerShell console run the [installer.ps1](https://github.com/rgconrad514/PS-Login-Monitor/blob/main/Installer.ps1) script (`.\Installer.ps1`). By default a folder is created at `%ProgramFiles%\WindowsPowerShell\Modules\PS Login Monitor\` and the script placed there with the options to track RDP/RDS and MSSQL logins. All tasks are run under the `SYSTEM` account. For RDP/RDS the script will attempt to enable the login auditing automatically. All parameters are at the top of the [PSLoginMonitor.ps1](https://github.com/rgconrad514/PS-Login-Monitor/blob/main/PSLoginMonitor.ps1) file. A whitelist of private IPv4 address ranges is contained in the `$WhiteList` array object; modify as needed but make sure at the bare minimum the subnet of your server is whitelisted or you can lock yourself out! By default blocked IPs are unblocked after 24 hours, login counters are reset after 15 minutes and IPs blocked after 3 failed logins.

![Firewall](https://user-images.githubusercontent.com/24600116/146605235-084fc26a-3ae8-4da8-8251-8362f96c285f.PNG)

# Tested On
* Windows Server 2016
* Windows 10

# Acknowledgements
Thanks to the author of [this bit of IP address code](http://www.gi-architects.co.uk/2016/02/powershell-check-if-ip-or-subnet-matchesfits/) that I used for checking IPs in the whitelist.
