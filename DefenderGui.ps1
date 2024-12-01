<#
.SYNOPSIS
    Enhanced GUI Script to Disable or Enable Microsoft Defender and Related Components on Windows 10/11.

.DESCRIPTION
    - This script provides a graphical user interface to manage Microsoft Defender settings and related security features.
    - Additional features include Tamper Protection check, backup and restore of Defender settings, and enhanced user feedback.
    - More features will be added such as the following list of 25 as they pertain to the management of the Windows Defender feature itself, not including things like backup or nonsense like errors or logging, more so, new, novel, mechanisms to disable windows defender and other security features:

    1. Tamper Protection check
    2. Disable Windows Defender
    3. Disable Windows Defender SmartScreen
    4. Disable Controlled Folder Access
    5. Disable Exploit Protection
    6. Disable Network Protection
    7. Disable Real-Time Protection
    8. Disable Cloud Protection
    9. Disable Automatic Sample Submission
    10. Disable Scheduled Scans
    11. Disable Defender Services
    12. Disable Firewall
    13. Disable Automatic Updates
    14. Disable SmartScreen
    15. Disable Security Notifications
    16. Disable Core Isolation / Memory Integrity
    17. Disable Ransomware Protection
    18. Disable Delivery Optimization
    19. Disable Attack Surface Reduction (ASR) Rules
    20. Disable Network Protection
    21. Disable Application Control Policies (AppLocker)
    22. Disable Credential Guard
    23. Disable Exploit Guard
    24. Disable Exploit Protection
    25. Disable Microsoft Defender Antivirus

.NOTES
    Author: Umair Akbar
    Date: 12/01/2024
#>

# Ensure the script runs with administrative privileges
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator"))
{
    [System.Windows.Forms.MessageBox]::Show("Please run this script as Administrator.", "Administrator Privileges Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    Exit
}

# Import necessary assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Variables
$LogFile = "$env:USERPROFILE\Desktop\DefenderScriptLog.txt"
$BackupFile = "$env:USERPROFILE\Desktop\DefenderSettingsBackup.reg"
$TamperProtectionEnabled = $null

# Function to Log Messages
Function LogMessage($Message)
{
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $FullMessage = "$Timestamp - $Message"
    Add-Content -Path $LogFile -Value $FullMessage
    Write-Host $FullMessage
}

# Function to Check Tamper Protection
Function CheckTamperProtection
{
    Try
    {
        $TPRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        $TPValue = Get-ItemProperty -Path $TPRegistryPath -Name TamperProtection -ErrorAction Stop
        If ($TPValue.TamperProtection -eq 5)
        {
            $TamperProtectionEnabled = $true
            [System.Windows.Forms.MessageBox]::Show("Tamper Protection is enabled. Please disable it manually before proceeding." + [Environment]::NewLine + [Environment]::NewLine + "Go to Windows Security > Virus & threat protection > Manage settings, and turn off Tamper Protection.", "Tamper Protection Enabled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            LogMessage "Tamper Protection is enabled. Script cannot proceed."
            Exit
        }
        Else
        {
            $TamperProtectionEnabled = $false
            LogMessage "Tamper Protection is disabled."
        }
    }
    Catch
    {
        LogMessage "Error checking Tamper Protection status: $_"
        [System.Windows.Forms.MessageBox]::Show("Error checking Tamper Protection status. Please ensure you have the necessary permissions.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        Exit
    }
}

# Function to Backup Defender Settings
Function BackupDefenderSettings
{
    Try
    {
        LogMessage "Backing up Defender registry settings."
        reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" $BackupFile /y > $null 2>&1
        LogMessage "Backup completed: $BackupFile"
    }
    Catch
    {
        LogMessage "Error backing up Defender settings: $_"
        [System.Windows.Forms.MessageBox]::Show("Error backing up Defender settings. Check the log for details.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Function to Restore Defender Settings
Function RestoreDefenderSettings
{
    Try
    {
        If (Test-Path $BackupFile)
        {
            LogMessage "Restoring Defender registry settings from backup."
            reg import $BackupFile > $null 2>&1
            LogMessage "Restore completed."
            [System.Windows.Forms.MessageBox]::Show("Defender settings have been restored. Please restart your computer for changes to take effect.", "Restore Completed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        Else
        {
            [System.Windows.Forms.MessageBox]::Show("Backup file not found. Cannot restore settings.", "Restore Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            LogMessage "Backup file not found. Restore failed."
        }
    }
    Catch
    {
        LogMessage "Error restoring Defender settings: $_"
        [System.Windows.Forms.MessageBox]::Show("Error restoring Defender settings. Check the log for details.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Function to Get Status Text
Function GetStatusText($status)
{
    if ($status) { return "Enabled" } else { return "Disabled" }
}

# Function to Check Component Status
Function GetComponentStatus
{
    $ComponentStatus = @{}

    # Real-Time Protection
    Try
    {
        $RTPStatus = (Get-MpPreference).DisableRealtimeMonitoring
        $ComponentStatus["RealTimeProtection"] = -not $RTPStatus
    }
    Catch
    {
        $ComponentStatus["RealTimeProtection"] = $false
    }

    # Cloud Protection
    Try
    {
        $CloudStatus = (Get-MpPreference).MAPSReporting
        $ComponentStatus["CloudProtection"] = $CloudStatus -ne 0
    }
    Catch
    {
        $ComponentStatus["CloudProtection"] = $false
    }

    # Automatic Sample Submission
    Try
    {
        $SampleStatus = (Get-MpPreference).SubmitSamplesConsent
        $ComponentStatus["SampleSubmission"] = $SampleStatus -ne 2
    }
    Catch
    {
        $ComponentStatus["SampleSubmission"] = $false
    }

    # Scheduled Scans
    Try
    {
        $ScheduledTasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" }
        $ComponentStatus["ScheduledScans"] = $ScheduledTasks.Count -gt 0
    }
    Catch
    {
        $ComponentStatus["ScheduledScans"] = $false
    }

    # Defender Services
    Try
    {
        $WinDefendStatus = (Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status
        $WdNisSvcStatus = (Get-Service -Name WdNisSvc -ErrorAction SilentlyContinue).Status
        $ComponentStatus["Services"] = ($WinDefendStatus -eq "Running") -and ($WdNisSvcStatus -eq "Running")
    }
    Catch
    {
        $ComponentStatus["Services"] = $false
    }

    # Firewall
    Try
    {
        $FirewallStatus = (Get-NetFirewallProfile -Profile Domain,Public,Private).Enabled -contains "True"
        $ComponentStatus["Firewall"] = $FirewallStatus
    }
    Catch
    {
        $ComponentStatus["Firewall"] = $false
    }

    # Automatic Updates
    Try
    {
        $AUStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
        $ComponentStatus["AutomaticUpdates"] = ($AUStatus -ne 1)
    }
    Catch
    {
        $ComponentStatus["AutomaticUpdates"] = $true
    }

    # SmartScreen
    Try
    {
        $SmartScreenStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue).SmartScreenEnabled
        $ComponentStatus["SmartScreen"] = $SmartScreenStatus -ne "Off"
    }
    Catch
    {
        $ComponentStatus["SmartScreen"] = $false
    }

    # Security Notifications
    Try
    {
        $NotificationsStatus = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        $ComponentStatus["SecurityNotifications"] = $NotificationsStatus -ne 0
    }
    Catch
    {
        $ComponentStatus["SecurityNotifications"] = $true
    }

    # Controlled Folder Access
    Try
    {
        $CFAStatus = (Get-MpPreference).EnableControlledFolderAccess
        $ComponentStatus["ControlledFolderAccess"] = $CFAStatus -eq "Enabled"
    }
    Catch
    {
        $ComponentStatus["ControlledFolderAccess"] = $false
    }

    # Core Isolation / Memory Integrity
    Try
    {
        $CIPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        If (Test-Path $CIPath)
        {
            $CIStatus = (Get-ItemProperty -Path $CIPath -Name "Enabled" -ErrorAction Stop).Enabled
            $ComponentStatus["CoreIsolation"] = $CIStatus -eq 1
        }
        Else
        {
            $ComponentStatus["CoreIsolation"] = $false
        }
    }
    Catch
    {
        $ComponentStatus["CoreIsolation"] = $false
    }

    # Exploit Protection Settings
    Try
    {
        $EPStatus = (Get-ProcessMitigation -System).SystemMitigationPolicy
        $ComponentStatus["ExploitProtection"] = ($EPStatus.DEP -eq "ON") -and ($EPStatus.SEHOP -eq "ON") -and ($EPStatus.ASLR -eq "ON")
    }
    Catch
    {
        $ComponentStatus["ExploitProtection"] = $false
    }

    # Ransomware Protection (Same as Controlled Folder Access)
    $ComponentStatus["RansomwareProtection"] = $ComponentStatus["ControlledFolderAccess"]

    # Delivery Optimization
    Try
    {
        $DOStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue).DODownloadMode
        $ComponentStatus["DeliveryOptimization"] = ($DOStatus -ne 0) -and ($DOStatus -ne $null)
    }
    Catch
    {
        $ComponentStatus["DeliveryOptimization"] = $true
    }

    # Attack Surface Reduction (ASR) Rules
    Try
    {
        $ASRStatus = (Get-MpPreference).AttackSurfaceReductionRules_Actions
        $ComponentStatus["ASRRules"] = $ASRStatus.Values -contains 1
    }
    Catch
    {
        $ComponentStatus["ASRRules"] = $false
    }

    # Network Protection
    Try
    {
        $NPStatus = (Get-MpPreference).EnableNetworkProtection
        $ComponentStatus["NetworkProtection"] = $NPStatus -eq 1
    }
    Catch
    {
        $ComponentStatus["NetworkProtection"] = $false
    }

    # Application Control Policies (AppLocker)
    Try
    {
        $AppLockerStatus = (Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue)
        $ComponentStatus["AppLocker"] = $AppLockerStatus -ne $null
    }
    Catch
    {
        $ComponentStatus["AppLocker"] = $false
    }

    # Credential Guard
    Try
    {
        $CGStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
        $ComponentStatus["CredentialGuard"] = $CGStatus -eq 1
    }
    Catch
    {
        $ComponentStatus["CredentialGuard"] = $false
    }

    # Windows Defender Firewall Advanced Security
    Try
    {
        $FirewallAdvancedStatus = (Get-NetFirewallProfile -Profile Domain,Public,Private).DefaultInboundAction -contains "Block"
        $ComponentStatus["FirewallAdvanced"] = $FirewallAdvancedStatus
    }
    Catch
    {
        $ComponentStatus["FirewallAdvanced"] = $false
    }

    Return $ComponentStatus
}

# Function to Disable Defender Components
Function DisableDefenderComponents
{
    Try
    {
        LogMessage "Disabling selected Defender components."

        # Disable Real-Time Protection
        If ($chkRealTimeProtection.Checked)
        {
            Try
            {
                # Primary method
                Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
                Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Stop
                Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop
                Set-MpPreference -DisablePrivacyMode $true -ErrorAction Stop
                Set-MpPreference -DisableScriptScanning $true -ErrorAction Stop

                # Fallback methods
                $paths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
                )
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "DisableRealtimeMonitoring" -Value 1 -Force
                    Set-ItemProperty -Path $path -Name "DisableBehaviorMonitoring" -Value 1 -Force
                    Set-ItemProperty -Path $path -Name "DisableOnAccessProtection" -Value 1 -Force
                    Set-ItemProperty -Path $path -Name "DisableScanOnRealtimeEnable" -Value 1 -Force
                }

                # Additional service-based approach
                Stop-Service "WinDefend" -Force -ErrorAction SilentlyContinue
                Set-Service "WinDefend" -StartupType Disabled -ErrorAction SilentlyContinue

                LogMessage "Real-Time Protection disabled."
            }
            Catch
            {
                LogMessage "Error in primary method for Real-Time Protection, attempting fallback: $_"
            }
        }

        # Disable Cloud Protection
        If ($chkCloudProtection.Checked)
        {
            Try
            {
                # Primary method
                Set-MpPreference -MAPSReporting 0 -ErrorAction Stop
                Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction Stop
                Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop

                # Fallback registry methods
                $paths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
                    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet"
                )
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "SpynetReporting" -Value 0 -Force
                    Set-ItemProperty -Path $path -Name "SubmitSamplesConsent" -Value 2 -Force
                }

                # Disable cloud-based protection via Windows Defender Security Center
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "EnableNetworkProtection" -Value 0 -Force

                LogMessage "Cloud-Delivered Protection disabled."
            }
            Catch
            {
                LogMessage "Error in primary method for Cloud Protection, attempting fallback: $_"
            }
        }

        # Disable SmartScreen (Multiple layers)
        If ($chkSmartScreen.Checked)
        {
            Try
            {
                # Windows Security SmartScreen
                $paths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer",
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
                )
                
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "EnableSmartScreen" -Value 0 -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $path -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction SilentlyContinue
                }

                # Edge SmartScreen
                $edgePaths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                    "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
                )
                foreach ($path in $edgePaths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "SmartScreenEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $path -Name "EnabledV9" -Value 0 -Force -ErrorAction SilentlyContinue
                }

                LogMessage "SmartScreen disabled across all layers."
            }
            Catch
            {
                LogMessage "Error disabling SmartScreen: $_"
            }
        }

        # Disable Exploit Protection with fallbacks
        If ($chkExploitProtection.Checked)
        {
            Try
            {
                # Try PowerShell module first
                Import-Module ProcessMitigations -ErrorAction SilentlyContinue
                Set-ProcessMitigation -System -Disable DEP,SEHOP,ASLR -ErrorAction SilentlyContinue

                # Registry fallback method
                $paths = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
                )
                
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                }

                # Disable DEP
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                    -Name "MoveImages" -Value 0 -Force
                
                # Disable SEHOP
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
                    -Name "DisableExceptionChainValidation" -Value 1 -Force
                
                # Disable via BCDEdit
                Start-Process "bcdedit.exe" -ArgumentList "/set nx AlwaysOff" -WindowStyle Hidden -Wait

                LogMessage "Exploit Protection disabled through multiple methods."
            }
            Catch
            {
                LogMessage "Error in exploit protection disable process: $_"
            }
        }

        # Disable Automatic Sample Submission with fallbacks
        If ($chkSampleSubmission.Checked)
        {
            Try
            {
                # Primary method
                Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop

                # Registry fallbacks
                $paths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
                    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet"
                )
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "SubmitSamplesConsent" -Value 0 -Force
                    Set-ItemProperty -Path $path -Name "SpynetReporting" -Value 0 -Force
                }

                # Additional registry keys
                $addPaths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
                )
                foreach ($path in $addPaths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "DisableIOAVProtection" -Value 1 -Force
                }

                LogMessage "Automatic Sample Submission disabled."
            }
            Catch
            {
                LogMessage "Error in sample submission disable process: $_"
            }
        }

        # Disable Scheduled Scans with fallbacks
        If ($chkScheduledScans.Checked)
        {
            Try
            {
                # Primary method - Disable scheduled tasks
                Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | Disable-ScheduledTask -ErrorAction SilentlyContinue

                # Registry fallbacks
                $paths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan",
                    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan"
                )
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "DisableScheduledScans" -Value 1 -Force
                    Set-ItemProperty -Path $path -Name "ScheduleDay" -Value 8 -Force # Never
                }

                # Disable via Task Scheduler direct registry
                $taskPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Windows Defender"
                )
                foreach ($path in $taskPaths) {
                    if (Test-Path $path) {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }

                LogMessage "Scheduled scans disabled."
            }
            Catch
            {
                LogMessage "Error in scheduled scans disable process: $_"
            }
        }

        # Disable Network Protection with fallbacks
        If ($chkNetworkProtection.Checked)
        {
            Try
            {
                # Primary method
                Set-MpPreference -EnableNetworkProtection 0 -ErrorAction Stop

                # Registry fallbacks
                $paths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection",
                    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
                )
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "EnableNetworkProtection" -Value 0 -Force
                }

                # Additional network protection disabling
                $wdPaths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
                    "HKLM:\SOFTWARE\Microsoft\Windows Defender"
                )
                foreach ($path in $wdPaths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "DisableRoutinelyTakingAction" -Value 1 -Force
                }

                # Disable Windows Filtering Platform
                $services = @("BFE", "mpssvc")
                foreach ($service in $services) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                }

                LogMessage "Network Protection disabled through multiple methods."
            }
            Catch
            {
                LogMessage "Error in network protection disable process: $_"
            }
        }

        # Disable Credential Guard with fallbacks
        If ($chkCredentialGuard.Checked)
        {
            Try
            {
                # Primary registry method
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Value 0 -Force

                # Additional registry keys
                $paths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                    "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
                )
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "EnableVirtualizationBasedSecurity" -Value 0 -Force
                    Set-ItemProperty -Path $path -Name "RequirePlatformSecurityFeatures" -Value 0 -Force
                    Set-ItemProperty -Path $path -Name "LsaCfgFlags" -Value 0 -Force
                }

                # Disable via BCDEdit
                Start-Process "bcdedit.exe" -ArgumentList "/set hypervisorlaunchtype off" -WindowStyle Hidden -Wait
                Start-Process "bcdedit.exe" -ArgumentList "/set virtualization off" -WindowStyle Hidden -Wait

                # Disable related services
                $services = @("SecurityHealthService", "SgrmBroker")
                foreach ($service in $services) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                }

                LogMessage "Credential Guard disabled through multiple methods."
            }
            Catch
            {
                LogMessage "Error in credential guard disable process: $_"
            }
        }

        # Disable Ransomware Protection with fallbacks
        If ($chkRansomwareProtection.Checked)
        {
            Try
            {
                # Primary method
                Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction Stop

                # Registry fallbacks
                $paths = @(
                    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
                    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
                )
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "EnableControlledFolderAccess" -Value 0 -Force
                }

                # Remove protected folders
                $protectedFolders = Get-MpPreference | Select-Object -ExpandProperty ControlledFolderAccessProtectedFolders
                if ($protectedFolders) {
                    foreach ($folder in $protectedFolders) {
                        Remove-MpPreference -ControlledFolderAccessProtectedFolders $folder
                    }
                }

                # Remove allowed applications
                $allowedApps = Get-MpPreference | Select-Object -ExpandProperty ControlledFolderAccessAllowedApplications
                if ($allowedApps) {
                    foreach ($app in $allowedApps) {
                        Remove-MpPreference -ControlledFolderAccessAllowedApplications $app
                    }
                }

                LogMessage "Ransomware Protection disabled through multiple methods."
            }
            Catch
            {
                LogMessage "Error in ransomware protection disable process: $_"
            }
        }

        [System.Windows.Forms.MessageBox]::Show("Selected Defender components have been disabled. Please restart your computer for changes to take effect.", "Operation Completed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        LogMessage "Defender components disabled successfully."
        RefreshStatus
    }
    Catch
    {
        $ErrorMessage = "An error occurred while disabling Defender components: $_"
        [System.Windows.Forms.MessageBox]::Show($ErrorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        LogMessage $ErrorMessage
    }
}

# Function to Enable Defender Components
Function EnableDefenderComponents
{
    Try
    {
        LogMessage "Enabling selected Defender components."

        # Enable Real-Time Protection
        If ($chkRealTimeProtection.Checked)
        {
            Try
            {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
                Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
                Set-MpPreference -DisablePrivacyMode $false -ErrorAction Stop
                Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
                LogMessage "Real-Time Protection enabled."
            }
            Catch
            {
                LogMessage "Error enabling Real-Time Protection: $_"
            }
        }

        # Enable Cloud Protection
        If ($chkCloudProtection.Checked)
        {
            Try
            {
                Set-MpPreference -MAPSReporting 2 -ErrorAction Stop
                Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction Stop
                Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction Stop
                LogMessage "Cloud-Delivered Protection enabled."
            }
            Catch
            {
                LogMessage "Error enabling Cloud Protection: $_"
            }
        }

        # Enable Automatic Sample Submission
        If ($chkSampleSubmission.Checked)
        {
            Try
            {
                Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction Stop
                LogMessage "Automatic Sample Submission enabled."
            }
            Catch
            {
                LogMessage "Error enabling Automatic Sample Submission: $_"
            }
        }

        # Enable Scheduled Tasks
        If ($chkScheduledScans.Checked)
        {
            Try
            {
                Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | Enable-ScheduledTask -ErrorAction Stop
                LogMessage "Scheduled scans enabled."
            }
            Catch
            {
                LogMessage "Error enabling Scheduled Scans: $_"
            }
        }

        # Enable Defender Services via Group Policy Registry Keys
        If ($chkServices.Checked)
        {
            LogMessage "Enabling Defender services via registry Group Policy keys."
            Try
            {
                # Enable Windows Defender Antivirus
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -ErrorAction SilentlyContinue

                # Set services to Automatic and start them
                Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name WinDefend -ErrorAction SilentlyContinue
                Set-Service -Name WdNisSvc -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name WdNisSvc -ErrorAction SilentlyContinue

                LogMessage "Defender services enabled via registry and service control."
            }
            Catch
            {
                LogMessage "Error enabling Defender services: $_"
            }
        }

        # Enable Firewall
        If ($chkFirewall.Checked)
        {
            Try
            {
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
                LogMessage "Firewall enabled."
            }
            Catch
            {
                LogMessage "Error enabling Firewall: $_"
            }
        }

        # Enable Automatic Updates
        If ($chkAutomaticUpdates.Checked)
        {
            Try
            {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Force
                LogMessage "Automatic Updates enabled."
            }
            Catch
            {
                LogMessage "Error enabling Automatic Updates: $_"
            }
        }

        # Enable Windows Defender SmartScreen
        If ($chkSmartScreen.Checked)
        {
            Try
            {
                LogMessage "Enabling Windows Defender SmartScreen."
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Force
                LogMessage "Windows Defender SmartScreen enabled."
            }
            Catch
            {
                LogMessage "Error enabling Windows Defender SmartScreen: $_"
            }
        }

        # Enable Security Notifications
        If ($chkSecurityNotifications.Checked)
        {
            Try
            {
                LogMessage "Enabling Windows Security Notifications."
                Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 1 -Force
                LogMessage "Windows Security Notifications enabled."
            }
            Catch
            {
                LogMessage "Error enabling Windows Security Notifications: $_"
            }
        }

        # Enable Controlled Folder Access
        If ($chkControlledFolderAccess.Checked)
        {
            Try
            {
                LogMessage "Enabling Controlled Folder Access."
                Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
                LogMessage "Controlled Folder Access enabled."
            }
            Catch
            {
                LogMessage "Error enabling Controlled Folder Access: $_"
            }
        }

        # Enable Core Isolation / Memory Integrity
        If ($chkCoreIsolation.Checked)
        {
            Try
            {
                LogMessage "Enabling Core Isolation Memory Integrity."
                $CIPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
                If (-Not (Test-Path $CIPath))
                {
                    New-Item -Path $CIPath -Force | Out-Null
                }
                Set-ItemProperty -Path $CIPath -Name "Enabled" -Value 1 -Force
                LogMessage "Core Isolation Memory Integrity enabled."
            }
            Catch
            {
                LogMessage "Error enabling Core Isolation Memory Integrity: $_"
            }
        }

        # Enable Exploit Protection Settings
        If ($chkExploitProtection.Checked)
        {
            Try
            {
                LogMessage "Enabling Exploit Protection."
                Set-ProcessMitigation -System -Enable DEP,SEHOP,ASLR
                LogMessage "Exploit Protection enabled."
            }
            Catch
            {
                LogMessage "Error enabling Exploit Protection: $_"
            }
        }

        # Enable Ransomware Protection
        If ($chkRansomwareProtection.Checked)
        {
            Try
            {
                LogMessage "Enabling Ransomware Protection."
                Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
                LogMessage "Ransomware Protection enabled."
            }
            Catch
            {
                LogMessage "Error enabling Ransomware Protection: $_"
            }
        }

        # Enable Delivery Optimization
        If ($chkDeliveryOptimization.Checked)
        {
            Try
            {
                LogMessage "Enabling Windows Update Delivery Optimization."
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 3 -Force
                LogMessage "Windows Update Delivery Optimization enabled."
            }
            Catch
            {
                LogMessage "Error enabling Delivery Optimization: $_"
            }
        }

        # Enable Attack Surface Reduction (ASR) Rules
        If ($chkASRRules.Checked)
        {
            Try
            {
                LogMessage "Enabling Attack Surface Reduction Rules."
                $ASRRuleIds = @(
                    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
                    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
                    "3B576869-A4EC-4529-8536-B80A7769E899",
                    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
                    "D3E037E1-3EB8-44C8-A917-57927947596D",
                    "D1E49AAC-8F56-4280-B9BA-993A6D77406C",
                    "26190899-1602-49E8-8B27-EB1D0A1CE869",
                    "B2B3F03D-6A65-4F15-B69A-2EECB462D9E3",
                    "9E6AB005-2734-4CB1-A28C-3164716C05BD",
                    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
                )
                Set-MpPreference -AttackSurfaceReductionRules_Ids $ASRRuleIds -AttackSurfaceReductionRules_Actions 1 -ErrorAction Stop
                LogMessage "Attack Surface Reduction Rules enabled."
            }
            Catch
            {
                LogMessage "Error enabling ASR Rules: $_"
            }
        }

        # Enable Network Protection
        If ($chkNetworkProtection.Checked)
        {
            Try
            {
                LogMessage "Enabling Network Protection."
                Set-MpPreference -EnableNetworkProtection 1 -ErrorAction Stop
                LogMessage "Network Protection enabled."
            }
            Catch
            {
                LogMessage "Error enabling Network Protection: $_"
            }
        }

        # Enable AppLocker
        If ($chkAppLocker.Checked)
        {
            Try
            {
                LogMessage "Enabling AppLocker."
                # Create default AppLocker policy
                Set-AppLockerPolicy -PolicyFilePath (New-AppLockerPolicy -DefaultRule -RuleType All) -Merge -ErrorAction Stop
                LogMessage "AppLocker enabled."
            }
            Catch
            {
                LogMessage "Error enabling AppLocker: $_"
            }
        }

        # Enable Credential Guard
        If ($chkCredentialGuard.Checked)
        {
            Try
            {
                LogMessage "Enabling Credential Guard."
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Value 1 -Force
                LogMessage "Credential Guard enabled."
            }
            Catch
            {
                LogMessage "Error enabling Credential Guard: $_"
            }
        }

        # Enable Firewall Advanced Security
        If ($chkFirewallAdvanced.Checked)
        {
            Try
            {
                LogMessage "Enabling Windows Defender Firewall with Advanced Security."
                Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction Stop
                LogMessage "Firewall Advanced Security enabled."
            }
            Catch
            {
                LogMessage "Error enabling Firewall Advanced Security: $_"
            }
        }

        [System.Windows.Forms.MessageBox]::Show("Selected Defender components have been enabled. Please restart your computer for changes to take effect.", "Operation Completed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        LogMessage "Defender components enabled successfully."
        RefreshStatus
    }
    Catch
    {
        $ErrorMessage = "An error occurred while enabling Defender components: $_"
        [System.Windows.Forms.MessageBox]::Show($ErrorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        LogMessage $ErrorMessage
    }
}

# Function to Refresh Status Indicators
Function RefreshStatus
{
    $Status = GetComponentStatus

    # Update status labels using the GetStatusText function
    $lblRTPStatus.Text = "Status: " + (GetStatusText $Status["RealTimeProtection"])
    $lblCloudStatus.Text = "Status: " + (GetStatusText $Status["CloudProtection"])
    $lblSampleStatus.Text = "Status: " + (GetStatusText $Status["SampleSubmission"])
    $lblScheduledStatus.Text = "Status: " + (GetStatusText $Status["ScheduledScans"])
    $lblServicesStatus.Text = "Status: " + (GetStatusText $Status["Services"])
    $lblFirewallStatus.Text = "Status: " + (GetStatusText $Status["Firewall"])
    $lblAUStatus.Text = "Status: " + (GetStatusText $Status["AutomaticUpdates"])
    $lblSmartScreenStatus.Text = "Status: " + (GetStatusText $Status["SmartScreen"])
    $lblNotificationsStatus.Text = "Status: " + (GetStatusText $Status["SecurityNotifications"])
    $lblCFAStatus.Text = "Status: " + (GetStatusText $Status["ControlledFolderAccess"])
    $lblCoreIsolationStatus.Text = "Status: " + (GetStatusText $Status["CoreIsolation"])
    $lblExploitProtectionStatus.Text = "Status: " + (GetStatusText $Status["ExploitProtection"])
    $lblRansomwareStatus.Text = "Status: " + (GetStatusText $Status["RansomwareProtection"])
    $lblDOStatus.Text = "Status: " + (GetStatusText $Status["DeliveryOptimization"])
    $lblASRStatus.Text = "Status: " + (GetStatusText $Status["ASRRules"])
    $lblNPStatus.Text = "Status: " + (GetStatusText $Status["NetworkProtection"])
    $lblAppLockerStatus.Text = "Status: " + (GetStatusText $Status["AppLocker"])
    $lblCredentialGuardStatus.Text = "Status: " + (GetStatusText $Status["CredentialGuard"])
    $lblFirewallAdvancedStatus.Text = "Status: " + (GetStatusText $Status["FirewallAdvanced"])
}

# Build the GUI
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')

# Create Form
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Microsoft Defender Management"
$Form.Size = New-Object System.Drawing.Size(600, 1200)
$Form.StartPosition = "CenterScreen"

# Labels
$lblInstructions = New-Object System.Windows.Forms.Label
$lblInstructions.Location = New-Object System.Drawing.Point(10, 10)
$lblInstructions.Size = New-Object System.Drawing.Size(580, 40)
$lblInstructions.Text = "Select the Defender components you wish to disable or enable."

$Form.Controls.Add($lblInstructions)

# Checkboxes and Status Labels
$Components = @(
    @{Name="Real-Time Protection"; Variable="chkRealTimeProtection"; StatusLabel="lblRTPStatus"; Location=60},
    @{Name="Cloud-Delivered Protection"; Variable="chkCloudProtection"; StatusLabel="lblCloudStatus"; Location=90},
    @{Name="Automatic Sample Submission"; Variable="chkSampleSubmission"; StatusLabel="lblSampleStatus"; Location=120},
    @{Name="Scheduled Scans"; Variable="chkScheduledScans"; StatusLabel="lblScheduledStatus"; Location=150},
    @{Name="Defender Services"; Variable="chkServices"; StatusLabel="lblServicesStatus"; Location=180},
    @{Name="Firewall"; Variable="chkFirewall"; StatusLabel="lblFirewallStatus"; Location=210},
    @{Name="Automatic Updates"; Variable="chkAutomaticUpdates"; StatusLabel="lblAUStatus"; Location=240},
    @{Name="Windows Defender SmartScreen"; Variable="chkSmartScreen"; StatusLabel="lblSmartScreenStatus"; Location=270},
    @{Name="Security Notifications"; Variable="chkSecurityNotifications"; StatusLabel="lblNotificationsStatus"; Location=300},
    @{Name="Controlled Folder Access"; Variable="chkControlledFolderAccess"; StatusLabel="lblCFAStatus"; Location=330},
    @{Name="Core Isolation Memory Integrity"; Variable="chkCoreIsolation"; StatusLabel="lblCoreIsolationStatus"; Location=360},
    @{Name="Exploit Protection"; Variable="chkExploitProtection"; StatusLabel="lblExploitProtectionStatus"; Location=390},
    @{Name="Ransomware Protection"; Variable="chkRansomwareProtection"; StatusLabel="lblRansomwareStatus"; Location=420},
    @{Name="Delivery Optimization"; Variable="chkDeliveryOptimization"; StatusLabel="lblDOStatus"; Location=450},
    @{Name="Attack Surface Reduction Rules"; Variable="chkASRRules"; StatusLabel="lblASRStatus"; Location=480},
    @{Name="Network Protection"; Variable="chkNetworkProtection"; StatusLabel="lblNPStatus"; Location=510},
    @{Name="AppLocker"; Variable="chkAppLocker"; StatusLabel="lblAppLockerStatus"; Location=540},
    @{Name="Credential Guard"; Variable="chkCredentialGuard"; StatusLabel="lblCredentialGuardStatus"; Location=570},
    @{Name="Firewall Advanced Security"; Variable="chkFirewallAdvanced"; StatusLabel="lblFirewallAdvancedStatus"; Location=600}
)

Foreach ($Component in $Components)
{
    # Checkbox
    Set-Variable -Name $Component.Variable -Value (New-Object System.Windows.Forms.CheckBox)
    $CheckBox = Get-Variable -Name $Component.Variable -ValueOnly
    $CheckBox.Location = New-Object System.Drawing.Point(10, $Component.Location)
    $CheckBox.Size = New-Object System.Drawing.Size(400, 20)
    $CheckBox.Text = $Component.Name
    $CheckBox.Checked = $true

    # Status Label
    Set-Variable -Name $Component.StatusLabel -Value (New-Object System.Windows.Forms.Label)
    $StatusLabel = Get-Variable -Name $Component.StatusLabel -ValueOnly
    $StatusLabel.Location = New-Object System.Drawing.Point(420, $Component.Location)
    $StatusLabel.Size = New-Object System.Drawing.Size(150, 20)
    $StatusLabel.Text = "Status: Unknown"

    $Form.Controls.Add($CheckBox)
    $Form.Controls.Add($StatusLabel)
}

# Buttons
$btnDisable = New-Object System.Windows.Forms.Button
$btnDisable.Location = New-Object System.Drawing.Point(10, 650)
$btnDisable.Size = New-Object System.Drawing.Size(280, 30)
$btnDisable.Text = "Disable Selected"
$btnDisable.Add_Click({
    BackupDefenderSettings
    DisableDefenderComponents
})

$btnEnable = New-Object System.Windows.Forms.Button
$btnEnable.Location = New-Object System.Drawing.Point(310, 650)
$btnEnable.Size = New-Object System.Drawing.Size(280, 30)
$btnEnable.Text = "Enable Selected"
$btnEnable.Add_Click({
    EnableDefenderComponents
})

$btnRestore = New-Object System.Windows.Forms.Button
$btnRestore.Location = New-Object System.Drawing.Point(10, 700)
$btnRestore.Size = New-Object System.Drawing.Size(580, 30)
$btnRestore.Text = "Restore Settings from Backup"
$btnRestore.Add_Click({
    RestoreDefenderSettings
})

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Location = New-Object System.Drawing.Point(10, 750)
$btnRefresh.Size = New-Object System.Drawing.Size(580, 30)
$btnRefresh.Text = "Refresh Status"
$btnRefresh.Add_Click({
    RefreshStatus
})

$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Location = New-Object System.Drawing.Point(10, 800)
$btnExit.Size = New-Object System.Drawing.Size(580, 30)
$btnExit.Text = "Exit"
$btnExit.Add_Click({
    $Form.Close()
})

$Form.Controls.Add($btnDisable)
$Form.Controls.Add($btnEnable)
$Form.Controls.Add($btnRestore)
$Form.Controls.Add($btnRefresh)
$Form.Controls.Add($btnExit)

# Run initial checks
CheckTamperProtection

# Refresh Status Indicators
RefreshStatus

# Show Form
$Form.Add_Shown({$Form.Activate()})
[void]$Form.ShowDialog()

# End of Script
LogMessage "Script execution completed."
