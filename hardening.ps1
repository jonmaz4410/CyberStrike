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
    Write-Host "6. Exit"
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

# Main Menu Loop
while ($true) {
    Show-Menu
    $choice = Read-Host "Enter choice number"
    switch ($choice) {
        '1' { Password-Hardening }
        '2' { Disable-Services }
        '3' { Audit-Exchange }
        '4' { Check-Persistence }
        '5' { Apply-SecurityUpdates }
        '6' { break }
        default { Write-Host "Invalid choice. Please select 1-6." -ForegroundColor Red }
    }
    Read-Host "Press Enter to return to the menu"
}
