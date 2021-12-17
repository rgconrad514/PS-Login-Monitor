# PS-Login-Monitor
Simple brute force login protection for RDP/RDS and MS SQL Server using PowerShell and Windows task scheduler.

# Foreword
First off, opening either RDP or MSSQL to the internet is inherently insecure and should not be done unless absolutely necessary. However, if it must here is a simple solution for protecting these services from brute force login attempts.

# Introduction
If for one reason or another you need a remotely accessible MSSQL database (lab environment, legacy software, etc.) or RDP/RDS server, it will inevitably become the target of brute force login attempts. Fortunately, Windows provides auditing mechanisms for these services that capture the source IP along with other information in the event log, and task scheduler provides a means for triggering a program to run when an event is captured, and even allows you to pass the event data to the program.

There are many Powershell scripts that can be found on the internet that provide auditing and IP address blocking functionality, but most rely on periodic scanning of the windows event log to extract a list of IP addresses with some minimum number of login attempts, and then create the necessary block rules in Windows firewall. Scanning the event log is a slow process and many brute force programs can attempt several logins per second. Many also fail to provide some automated process to unblock an IP address after a certain amount of time to prevent the Windows firewall from filling up with too many rules.
