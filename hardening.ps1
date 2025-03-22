# ============================================
# CYBERSTRIKE RvB BLUE TEAM: DEFENDER TOOLKIT
# Interactive Menu-Driven Script
# ============================================

function Show-Menu {
    Clear-Host
    Write-Host "========== BLUE TEAM DEFENSE MENU ==========" -ForegroundColor Cyan
    Write-Host "1. Password Hardening"
    Write-Host "2. Disable Unnecessary Services"
    Write-Host "3. Exchange Security Audit"
    Write-Host "4. Check for Red Team Persistence"
    Write-Host "5. Check for Security Updates"
    Write-Host "6. Harden SMB"
    Write-Host "7. Harden DNS"
    Write-Host "8. Exit"
    Write-Host "9. Harden Firewall"

}



function Password-Hardening {
    $basePassword1 = Read-Host "Enter base password" -AsSecureString
    $basePassword2 = Read-Host "Re-enter base password to confirm" -AsSecureString

    $plainPassword1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($basePassword1))
    $plainPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($basePassword2))

    if ($plainPassword1 -ne $plainPassword2) {
        Write-Host "Passwords do not match. Exiting." -ForegroundColor Red
        return
    }

    $finalPassword = "$plainPassword1`12!"
    $securePassword = ConvertTo-SecureString -AsPlainText $finalPassword -Force

    $users = @("johncyberstrike", "joecyberstrike", "janecyberstrike", "janicecyberstrike")
    foreach ($user in $users) {
        Set-ADAccountPassword -Identity $user -NewPassword $securePassword -Reset
        Write-Host "Password updated for: $user" -ForegroundColor Green
    }

    $updateAdmin = Read-Host "Update Administrator password? (yes/no)"
    if ($updateAdmin -eq "yes") {
        $adminPassword = Read-Host "Enter new Administrator password" -AsSecureString
        Set-ADAccountPassword -Identity "Administrator" -NewPassword $adminPassword -Reset
        Write-Host "Administrator password updated." -ForegroundColor Green
    }

    $authorizedUsers = @("Administrator", "johncyberstrike", "joecyberstrike", "janecyberstrike", "janicecyberstrike")
    $allUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
    $unauthorized = $allUsers | Where-Object { $authorizedUsers -notcontains $_ -and $_ -ne "krbtgt" }
    foreach ($user in $unauthorized) {
        Disable-ADAccount -Identity $user
        Write-Host "Disabled unauthorized user: $user" -ForegroundColor Red
    }
}

function Disable-Services {
    $servicesToDisable = @(
        "RemoteRegistry", "WinRM", "LanmanWorkstation",
        "Spooler", "SNMP", "FDResPub", "fdPHost",
        "bthserv", "WerSvc", "wuauserv"
    )
    $disableSMB = Read-Host "Disable SMB on this server? (yes/no)"
    if ($disableSMB -eq "yes") { $servicesToDisable += "LanmanServer" }
    foreach ($service in $servicesToDisable) {
        try {
            Set-Service -Name $service -StartupType Disabled
            Write-Host "Disabled: $service" -ForegroundColor Green
        } catch {
            Write-Host "Failed to disable: $service. $_" -ForegroundColor Red
        }
    }
}

function Audit-Exchange {
    Write-Host "===== EXCHANGE SECURITY AUDIT =====" -ForegroundColor Cyan
    $owa = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME
    Write-Host "OWA Enabled: $($owa.Enabled)"
    $ecp = Get-EcpVirtualDirectory -Server $env:COMPUTERNAME
    Write-Host "ECP Enabled: $($ecp.Enabled)"
    $orgConfig = Get-OrganizationConfig
    Write-Host "Modern Auth Enabled: $($orgConfig.OAuth2ClientProfileEnabled)"
    $remoteDomain = Get-RemoteDomain -Identity "Default"
    Write-Host "Auto-Forwarding Enabled: $($remoteDomain.AutoForwardEnabled)"
    Write-Host "Mailbox FullAccess Audit:" -ForegroundColor Yellow
    Get-Mailbox | Get-MailboxPermission | Where-Object {
        $_.AccessRights -like "*FullAccess*" -and $_.User -ne "NT AUTHORITY\SELF" -and $_.IsInherited -eq $false
    } | Format-Table Identity, User, AccessRights
    $remotePS = Get-User -ResultSize Unlimited | Where-Object { $_.RemotePowerShellEnabled -eq $true }
    if ($remotePS) {
        Write-Host "Users with Remote PowerShell Enabled:" -ForegroundColor Red
        $remotePS | Select Name, UserPrincipalName | Format-Table
    }
}

function Check-Persistence {
    Write-Host "===== PERSISTENCE CHECK =====" -ForegroundColor Cyan
    Write-Host "--- Local Admins ---"
    Get-LocalGroupMember -Group "Administrators" | Format-Table Name, ObjectClass
    Write-Host "--- Scheduled Tasks ---"
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Format-Table TaskName, TaskPath, State
    Write-Host "--- Suspicious Services ---"
    Get-Service | Where-Object {
        $_.StartType -eq "Automatic" -and $_.Status -eq "Running" -and
        $_.DisplayName -notmatch "Exchange|Active|DNS|Windows|Network|Defender|Update"
    } | Format-Table Name, DisplayName, Status
    Write-Host "--- Startup Folder ---"
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($path in $startupPaths) {
        if (Test-Path $path) { Get-ChildItem $path }
    }
    Write-Host "--- Registry Run Keys ---"
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    Write-Host "--- WMI Persistence ---"
    Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Format-Table Name, Query
    Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer | Format-Table Name, CommandLineTemplate
    Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Format-Table Filter, Consumer
    Write-Host "--- Listening Ports ---"
    Get-NetTCPConnection -State Listen | ForEach-Object {
        try {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Port = $_.LocalPort
                PID = $_.OwningProcess
                ProcessName = $proc.Name
                Path = $proc.Path
            }
        } catch {}
    } | Format-Table -AutoSize
}

function Apply-SecurityUpdates {
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
    if (-not (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -Force
        Install-Module -Name PSWindowsUpdate -Force
        Import-Module PSWindowsUpdate
    }
    Write-Host "--- Checking for Security/Critical Updates ---"
    $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -Category "SecurityUpdates", "CriticalUpdates"
    if ($updates.Count -eq 0) {
        Write-Host "✅ System is up to date." -ForegroundColor Green
    } else {
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Category "SecurityUpdates", "CriticalUpdates" -IgnoreReboot -AutoReboot:$false -Confirm:$false
        Write-Host "⚠️ Updates applied. Reboot may be needed." -ForegroundColor Yellow
    }
    Write-Host "Exchange Version:"
    Get-Command ExSetup | ForEach-Object { $_.FileVersionInfo }
}

function Harden-SMB {
    Write-Host "===== SMB HARDENING =====" -ForegroundColor Cyan

    # 1. Disable SMBv1
    Write-Host "--- Disabling SMBv1 ---"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
    Write-Host "✔ SMBv1 disabled." -ForegroundColor Green

    # 2. Block Anonymous Access
    Write-Host "--- Blocking Anonymous Access ---"
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
    Write-Host "✔ Anonymous access restricted." -ForegroundColor Green

    # 3. Audit Share Permissions
    Write-Host "--- Auditing Share Permissions ---"
    Get-SmbShare | Where-Object { $_.Name -ne "IPC$" } | ForEach-Object {
        $acl = Get-SmbShareAccess -Name $_.Name
        Write-Host "`n[$($_.Name)]" -ForegroundColor Yellow
        $acl | Format-Table -AutoSize
    }

    # 4. Enforce SMB Signing
    Write-Host "--- Enforcing SMB Signing ---"
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
    Write-Host "✔ SMB signing enforced for both server and client." -ForegroundColor Green

    # 5. Disable Guest Account
    Write-Host "--- Disabling Guest Account ---"
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Write-Host "✔ Guest account disabled." -ForegroundColor Green

    # 6. Block Outbound SMB (Ports 445 and 139)
    Write-Host "--- Blocking Outbound SMB ---"
    New-NetFirewallRule -DisplayName "Block Outbound SMB TCP 445" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block -Profile Any -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Block Outbound SMB TCP 139" -Direction Outbound -Protocol TCP -RemotePort 139 -Action Block -Profile Any -ErrorAction SilentlyContinue
    Write-Host "✔ Outbound SMB blocked." -ForegroundColor Green

    # 7. Password Hardening Reminder
    Write-Host "--- Reminder: Ensure all SMB accounts use strong passwords." -ForegroundColor Yellow

    # 8. Disable NetBIOS over TCP/IP (all interfaces)
    Write-Host "--- Disabling NetBIOS over TCP/IP ---"
    $nics = Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True"
    foreach ($nic in $nics) {
        $nic.SetTcpipNetbios(2) | Out-Null
    }
    Write-Host "✔ NetBIOS over TCP/IP disabled." -ForegroundColor Green

    # 9. Disable LLMNR (via registry)
    Write-Host "--- Disabling LLMNR ---"
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Force
    Write-Host "✔ LLMNR disabled." -ForegroundColor Green

    Write-Host "✅ SMB hardening complete." -ForegroundColor Cyan
}

function Harden-DNS {
    Write-Host "===== DNS HARDENING =====" -ForegroundColor Cyan

    # 1. Disable Zone Transfers
    Write-Host "--- Disabling Zone Transfers ---"
    $zones = Get-DnsServerZone -ErrorAction SilentlyContinue
    foreach ($zone in $zones) {
        Set-DnsServerPrimaryZone -Name $zone.ZoneName -ZoneTransferType None -ErrorAction SilentlyContinue
        Write-Host "Zone transfers disabled for: $($zone.ZoneName)" -ForegroundColor Green
    }

    # 2. Disable Recursion (if this server is not forwarding/caching)
    Write-Host "--- Disabling DNS Recursion ---"
    Set-DnsServerRecursion -Enable $false -ErrorAction SilentlyContinue
    Write-Host "Recursion disabled." -ForegroundColor Green

    # 3. Enable DNS Logging and Diagnostics
    Write-Host "--- Enabling DNS Diagnostic Logging ---"
    Set-DnsServerDiagnostics -All $true -ErrorAction SilentlyContinue
    Set-DnsServerDiagnostics -EventLogLevel 0xFFFF -ErrorAction SilentlyContinue
    Write-Host "Full DNS diagnostics and event logging enabled." -ForegroundColor Green

    # 4. Enable Response Rate Limiting to Mitigate DNS Amplification
    Write-Host "--- Enabling DNS Response Rate Limiting ---"
    Set-DnsServerResponseRateLimiting -ResponsesPerSec 5 -WindowSec 1 -ErrorAction SilentlyContinue
    Write-Host "Response rate limiting enabled (5 responses/sec)." -ForegroundColor Green

    Write-Host "✅ DNS hardening complete." -ForegroundColor Cyan
}

function Harden-Firewall {
    Write-Host "===== FIREWALL HARDENING =====" -ForegroundColor Cyan

    # 1. Enable Windows Defender Firewall on all network profiles
    Write-Host "--- Enabling Windows Firewall for Domain, Private, and Public profiles ---"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "✔ Firewall enabled." -ForegroundColor Green

    # 2. Set default policy: block inbound traffic, allow outbound
    Write-Host "--- Setting default policies (Block Inbound / Allow Outbound) ---"
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Host "✔ Default firewall policies applied." -ForegroundColor Green

    # 3. Allow scored service ports (Exchange, DNS, AD, SMB)
    $inboundRules = @(
        @{Name="Allow DNS (TCP)"; Ports=53; Protocol="TCP"},
        @{Name="Allow DNS (UDP)"; Ports=53; Protocol="UDP"},
        @{Name="Allow SMB (445)"; Ports=445; Protocol="TCP"},
        @{Name="Allow LDAP (389)"; Ports=389; Protocol="TCP"},
        @{Name="Allow Secure LDAP (636)"; Ports=636; Protocol="TCP"},
        @{Name="Allow Kerberos (TCP)"; Ports=88; Protocol="TCP"},
        @{Name="Allow Kerberos (UDP)"; Ports=88; Protocol="UDP"},
        @{Name="Allow Global Catalog (3268)"; Ports=3268; Protocol="TCP"},
        @{Name="Allow GC over SSL (3269)"; Ports=3269; Protocol="TCP"},
        @{Name="Allow SMTP (25)"; Ports=25; Protocol="TCP"},
        @{Name="Allow SMTP Auth (587)"; Ports=587; Protocol="TCP"},
        @{Name="Allow POP3 (110)"; Ports=110; Protocol="TCP"},
        @{Name="Allow IMAP (143)"; Ports=143; Protocol="TCP"},
        @{Name="Allow Exchange HTTPS (443)"; Ports=443; Protocol="TCP"}
    )

    foreach ($rule in $inboundRules) {
        try {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -LocalPort $rule.Ports `
                -Protocol $rule.Protocol -Action Allow -Profile Any -ErrorAction SilentlyContinue
            Write-Host "✔ Allowed inbound port $($rule.Ports)/$($rule.Protocol) - $($rule.Name)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to allow $($rule.Name): $_" -ForegroundColor Red
        }
    }

    # 4. Block outbound SMB (to prevent Red Team exfiltration/beaconing)
    Write-Host "--- Blocking outbound SMB ---"
    New-NetFirewallRule -DisplayName "Block Outbound SMB TCP 445" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block -Profile Any -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Block Outbound SMB TCP 139" -Direction Outbound -Protocol TCP -RemotePort 139 -Action Block -Profile Any -ErrorAction SilentlyContinue
    Write-Host "✔ Outbound SMB blocked." -ForegroundColor Green

    # 5. Enable logging for allowed and blocked connections
    Write-Host "--- Enabling firewall logging ---"
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" `
        -LogMaxSizeKilobytes 32767 -LogAllowed True -LogBlocked True
    Write-Host "✔ Logging enabled for allowed and blocked connections." -ForegroundColor Green

    Write-Host "✅ Firewall hardening complete." -ForegroundColor Cyan
}




# Main Menu Loop
switch ($choice) {
    '1' { Password-Hardening }
    '2' { Disable-Services }
    '3' { Audit-Exchange }
    '4' { Check-Persistence }
    '5' { Apply-SecurityUpdates }
    '6' { Harden-SMB }
    '7' { Harden-DNS }
    '8' { Harden-Firewall }
    '9' { break }

    default { Write-Host "Invalid choice. Please select 1-9." -ForegroundColor Red }
}

