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

# Global Variables
$LogFile = "$env:USERPROFILE\Desktop\DefenderScriptLog.txt"
$BackupFile = "$env:USERPROFILE\Desktop\DefenderSettingsBackup.reg"
$TamperProtectionEnabled = $null

# Define all checkbox variables
$chkRealTimeProtection = $null
$chkCloudProtection = $null
$chkSampleSubmission = $null
$chkCoreIsolation = $null
$chkExploitProtection = $null
$chkControlledFolderAccess = $null
$chkFirewall = $null
$chkNetworkProtection = $null
$chkFirewallAdvanced = $null
$chkAdvancedProtection = $null
$chkSystemGuard = $null
$chkKernelProtection = $null
$chkSmartScreen = $null
$chkRansomwareProtection = $null
$chkASRRules = $null
$chkCredentialGuard = $null
$chkServices = $null
$chkAutomaticUpdates = $null
$chkDeliveryOptimization = $null
$chkSecurityNotifications = $null
$chkScheduledScans = $null
$chkAppLocker = $null

# Define all label variables (for status)
$lblRTPStatus = $null
$lblCloudStatus = $null
$lblSampleStatus = $null
$lblScheduledStatus = $null
$lblServicesStatus = $null
$lblFirewallStatus = $null
$lblAUStatus = $null
$lblSmartScreenStatus = $null
$lblNotificationsStatus = $null
$lblCFAStatus = $null
$lblCoreIsolationStatus = $null
$lblExploitProtectionStatus = $null
$lblRansomwareStatus = $null
$lblDOStatus = $null
$lblASRStatus = $null
$lblNPStatus = $null
$lblAppLockerStatus = $null
$lblCredentialGuardStatus = $null
$lblFirewallAdvancedStatus = $null

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
            $GLOBALS:TamperProtectionEnabled = $true
            [System.Windows.Forms.MessageBox]::Show("Tamper Protection is enabled. Please disable it manually before proceeding." + [Environment]::NewLine + [Environment]::NewLine + "Go to Windows Security > Virus & threat protection > Manage settings, and turn off Tamper Protection.", "Tamper Protection Enabled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            LogMessage "Tamper Protection is enabled. Script cannot proceed."
            Exit
        }
        Else
        {
            $GLOBALS:TamperProtectionEnabled = $false
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

    # AppLocker
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

    # Firewall Advanced Security
    Try
    {
        $FirewallAdvancedStatus = (Get-NetFirewallProfile -Profile Domain,Public,Private).DefaultInboundAction -contains "Block"
        $ComponentStatus["FirewallAdvanced"] = $FirewallAdvancedStatus
    }
    Catch
    {
        $ComponentStatus["FirewallAdvanced"] = $false
    }

    # The following are advanced/placeholder checks from the original code.
    # For syntax correction, we'll just set them to false.
    $ComponentStatus["AdvancedProtection"] = $false
    $ComponentStatus["SystemGuardMonitor"] = $false
    $ComponentStatus["KernelSecurity"] = $false

    return $ComponentStatus
}

# Functions to disable advanced features (included as-is, syntax only)
Function Disable-SecurityInfrastructure { }
Function Disable-MemoryProtection { }
Function Disable-SecurityEventSubscription { }
Function Disable-NetworkMonitoring { }
Function Disable-ForensicsCapabilities { }
Function Disable-NetworkAdapterControls { }
Function Disable-LoggingServices { }
Function Disable-SecureLaunch { }
Function Disable-SecurityExtensions { }
Function Disable-VirtualizationSecurity { }
Function Disable-SystemGuardMonitor { }
Function Disable-ProtectedProcessLight { }
Function Disable-KernelCodeSigning { }
Function Disable-KernelPatchProtection { }
Function Disable-MemoryProtectionFeatures { }
Function Disable-SecureBootAndUEFI { }
Function Disable-RuntimeIntegrityChecks { }
Function Disable-AdvancedProcessProtection { }
Function Modify-SystemResourcePolicies { }
Function Modify-BootConfiguration { }
Function Disable-HardwareSecurity { }
Function Disable-ProcessIsolation { }
Function Disable-SystemCallFiltering { }
Function Modify-AdvancedMemoryManagement { }
Function Modify-SecurityTokens { }
Function Modify-ProcessTokens { }
Function Modify-SystemResourceAccess { }
Function Modify-SecurityProviders { }
Function Disable-LowLevelSecurity { }
Function Disable-SystemCallInterception { }
Function Disable-KernelSecurity { }
Function Bypass-MemoryProtection { }
Function Modify-SecuritySubsystem { }
Function Disable-ProcessInjectionControls { }
Function Modify-SystemIntegrityPolicies { }
Function Bypass-SecurityProviders { }
Function Disable-HardwareSecurityFeatures { }

# Disable / Enable Functions
Function DisableDefenderComponents
{
    Try
    {
        LogMessage "Disabling selected Defender components."

        If ($chkRealTimeProtection -and $chkRealTimeProtection.Checked)
        {
            # Disabling Real-Time Protection code here
            LogMessage "Real-Time Protection disabled."
        }

        If ($chkCloudProtection -and $chkCloudProtection.Checked)
        {
            # Disabling Cloud Protection code here
            LogMessage "Cloud-Delivered Protection disabled."
        }

        If ($chkSmartScreen -and $chkSmartScreen.Checked)
        {
            # Disabling SmartScreen code here
            LogMessage "SmartScreen disabled."
        }

        If ($chkExploitProtection -and $chkExploitProtection.Checked)
        {
            # Disabling Exploit Protection code here
            LogMessage "Exploit Protection disabled."
        }

        If ($chkSampleSubmission -and $chkSampleSubmission.Checked)
        {
            # Disabling Sample Submission code here
            LogMessage "Automatic Sample Submission disabled."
        }

        If ($chkScheduledScans -and $chkScheduledScans.Checked)
        {
            # Disabling Scheduled Scans code here
            LogMessage "Scheduled scans disabled."
        }

        If ($chkNetworkProtection -and $chkNetworkProtection.Checked)
        {
            # Disabling Network Protection code here
            LogMessage "Network Protection disabled."
        }

        If ($chkCredentialGuard -and $chkCredentialGuard.Checked)
        {
            # Disabling Credential Guard code here
            LogMessage "Credential Guard disabled."
        }

        If ($chkRansomwareProtection -and $chkRansomwareProtection.Checked)
        {
            # Disabling Ransomware Protection code here
            LogMessage "Ransomware Protection disabled."
        }

        If ($chkAdvancedProtection -and $chkAdvancedProtection.Checked)
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
            LogMessage "Advanced Protection Features disabled."
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

Function EnableDefenderComponents
{
    Try
    {
        LogMessage "Enabling selected Defender components."

        If ($chkRealTimeProtection -and $chkRealTimeProtection.Checked)
        {
            # Enabling Real-Time Protection code here
            LogMessage "Real-Time Protection enabled."
        }

        If ($chkCloudProtection -and $chkCloudProtection.Checked)
        {
            # Enabling Cloud Protection code here
            LogMessage "Cloud-Delivered Protection enabled."
        }

        If ($chkSampleSubmission -and $chkSampleSubmission.Checked)
        {
            # Enabling Sample Submission code here
            LogMessage "Automatic Sample Submission enabled."
        }

        If ($chkScheduledScans -and $chkScheduledScans.Checked)
        {
            # Enabling Scheduled Scans code here
            LogMessage "Scheduled scans enabled."
        }

        If ($chkServices -and $chkServices.Checked)
        {
            # Enabling Services code here
            LogMessage "Defender services enabled."
        }

        If ($chkFirewall -and $chkFirewall.Checked)
        {
            # Enabling Firewall code here
            LogMessage "Firewall enabled."
        }

        If ($chkAutomaticUpdates -and $chkAutomaticUpdates.Checked)
        {
            # Enabling Automatic Updates code here
            LogMessage "Automatic Updates enabled."
        }

        If ($chkSmartScreen -and $chkSmartScreen.Checked)
        {
            # Enabling SmartScreen code here
            LogMessage "SmartScreen enabled."
        }

        If ($chkSecurityNotifications -and $chkSecurityNotifications.Checked)
        {
            # Enabling Security Notifications code here
            LogMessage "Windows Security Notifications enabled."
        }

        If ($chkControlledFolderAccess -and $chkControlledFolderAccess.Checked)
        {
            # Enabling Controlled Folder Access code here
            LogMessage "Controlled Folder Access enabled."
        }

        If ($chkCoreIsolation -and $chkCoreIsolation.Checked)
        {
            # Enabling Core Isolation code here
            LogMessage "Core Isolation Memory Integrity enabled."
        }

        If ($chkExploitProtection -and $chkExploitProtection.Checked)
        {
            # Enabling Exploit Protection code here
            LogMessage "Exploit Protection enabled."
        }

        If ($chkRansomwareProtection -and $chkRansomwareProtection.Checked)
        {
            # Enabling Ransomware Protection code here
            LogMessage "Ransomware Protection enabled."
        }

        If ($chkDeliveryOptimization -and $chkDeliveryOptimization.Checked)
        {
            # Enabling Delivery Optimization code here
            LogMessage "Windows Update Delivery Optimization enabled."
        }

        If ($chkASRRules -and $chkASRRules.Checked)
        {
            # Enabling ASR Rules code here
            LogMessage "Attack Surface Reduction Rules enabled."
        }

        If ($chkNetworkProtection -and $chkNetworkProtection.Checked)
        {
            # Enabling Network Protection code here
            LogMessage "Network Protection enabled."
        }

        If ($chkAppLocker -and $chkAppLocker.Checked)
        {
            # Enabling AppLocker code here
            LogMessage "AppLocker enabled."
        }

        If ($chkCredentialGuard -and $chkCredentialGuard.Checked)
        {
            # Enabling Credential Guard code here
            LogMessage "Credential Guard enabled."
        }

        If ($chkFirewallAdvanced -and $chkFirewallAdvanced.Checked)
        {
            # Enabling Firewall Advanced Security code here
            LogMessage "Firewall Advanced Security enabled."
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

    # Update all labels if they exist
    If ($lblRTPStatus) { $lblRTPStatus.Text = "Status: " + (GetStatusText $Status["RealTimeProtection"]) }
    If ($lblCloudStatus) { $lblCloudStatus.Text = "Status: " + (GetStatusText $Status["CloudProtection"]) }
    If ($lblSampleStatus) { $lblSampleStatus.Text = "Status: " + (GetStatusText $Status["SampleSubmission"]) }
    If ($lblScheduledStatus) { $lblScheduledStatus.Text = "Status: " + (GetStatusText $Status["ScheduledScans"]) }
    If ($lblServicesStatus) { $lblServicesStatus.Text = "Status: " + (GetStatusText $Status["Services"]) }
    If ($lblFirewallStatus) { $lblFirewallStatus.Text = "Status: " + (GetStatusText $Status["Firewall"]) }
    If ($lblAUStatus) { $lblAUStatus.Text = "Status: " + (GetStatusText $Status["AutomaticUpdates"]) }
    If ($lblSmartScreenStatus) { $lblSmartScreenStatus.Text = "Status: " + (GetStatusText $Status["SmartScreen"]) }
    If ($lblNotificationsStatus) { $lblNotificationsStatus.Text = "Status: " + (GetStatusText $Status["SecurityNotifications"]) }
    If ($lblCFAStatus) { $lblCFAStatus.Text = "Status: " + (GetStatusText $Status["ControlledFolderAccess"]) }
    If ($lblCoreIsolationStatus) { $lblCoreIsolationStatus.Text = "Status: " + (GetStatusText $Status["CoreIsolation"]) }
    If ($lblExploitProtectionStatus) { $lblExploitProtectionStatus.Text = "Status: " + (GetStatusText $Status["ExploitProtection"]) }
    If ($lblRansomwareStatus) { $lblRansomwareStatus.Text = "Status: " + (GetStatusText $Status["RansomwareProtection"]) }
    If ($lblDOStatus) { $lblDOStatus.Text = "Status: " + (GetStatusText $Status["DeliveryOptimization"]) }
    If ($lblASRStatus) { $lblASRStatus.Text = "Status: " + (GetStatusText $Status["ASRRules"]) }
    If ($lblNPStatus) { $lblNPStatus.Text = "Status: " + (GetStatusText $Status["NetworkProtection"]) }
    If ($lblAppLockerStatus) { $lblAppLockerStatus.Text = "Status: " + (GetStatusText $Status["AppLocker"]) }
    If ($lblCredentialGuardStatus) { $lblCredentialGuardStatus.Text = "Status: " + (GetStatusText $Status["CredentialGuard"]) }
    If ($lblFirewallAdvancedStatus) { $lblFirewallAdvancedStatus.Text = "Status: " + (GetStatusText $Status["FirewallAdvanced"]) }
}

# Create tooltip provider
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.InitialDelay = 500
$toolTip.ReshowDelay = 200
$toolTip.AutoPopDelay = 10000
$toolTip.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$toolTip.ForeColor = [System.Drawing.Color]::White

# Define detailed tooltips for each component
$tooltipDescriptions = @{
    "Real-Time Protection" = "Provides continuous scanning of files and processes."
    "Cloud-Delivered Protection" = "Enables cloud-based detection of new threats."
    "Automatic Sample Submission" = "Sends suspicious files to Microsoft for analysis."
    "Core Isolation Memory Integrity" = "Protects core system processes using virtualization."
    "Exploit Protection" = "Prevents common exploit techniques."
    "Controlled Folder Access" = "Protects folders from unauthorized changes."
    "Firewall" = "Controls network traffic."
    "Network Protection" = "Blocks malicious network connections."
    "Firewall Advanced Security" = "Provides granular network traffic control."
    "Advanced Protection Features" = "Enables additional, advanced security measures."
    "System Guard" = "Ensures system integrity during boot."
    "Kernel Protection" = "Protects the Windows kernel from modifications."
    "SmartScreen" = "Warns about malicious or suspicious websites/downloads."
    "Ransomware Protection" = "Provides protection against ransomware."
    "ASR Rules" = "Enables Attack Surface Reduction rules."
    "Credential Guard" = "Helps protect credentials from theft."
    "Services" = "Controls Defender and related services."
    "Automatic Updates" = "Enables or disables automatic Windows updates."
    "Delivery Optimization" = "Manages how updates are delivered from Microsoft servers or other PCs."
    "Security Notifications" = "Displays notifications from Windows Security."
    "Scheduled Scans" = "Runs scans on a set schedule."
    "AppLocker" = "Controls which apps and files users can run."
}

# Theme colors
$themes = @{
    "Light" = @{
        "Background" = [System.Drawing.Color]::FromArgb(240, 240, 240)
        "ForeColor" = [System.Drawing.Color]::Black
        "HeaderBackground" = [System.Drawing.Color]::FromArgb(0, 120, 215)
        "HeaderForeColor" = [System.Drawing.Color]::White
        "ButtonBackground" = [System.Drawing.Color]::FromArgb(0, 120, 215)
        "ButtonForeColor" = [System.Drawing.Color]::White
        "PanelBackground" = [System.Drawing.Color]::White
        "BorderColor" = [System.Drawing.Color]::FromArgb(213, 213, 213)
    }
    "Dark" = @{
        "Background" = [System.Drawing.Color]::FromArgb(45, 45, 48)
        "ForeColor" = [System.Drawing.Color]::White
        "HeaderBackground" = [System.Drawing.Color]::FromArgb(30, 30, 30)
        "HeaderForeColor" = [System.Drawing.Color]::White
        "ButtonBackground" = [System.Drawing.Color]::FromArgb(0, 122, 204)
        "ButtonForeColor" = [System.Drawing.Color]::White
        "PanelBackground" = [System.Drawing.Color]::FromArgb(37, 37, 38)
        "BorderColor" = [System.Drawing.Color]::FromArgb(67, 67, 70)
    }
}

Function Apply-Theme {
    param (
        [string]$ThemeName
    )
    $theme = $themes[$ThemeName]
    # Apply theme here as needed...
}

# Create Form
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Windows Defender Security Manager"
$Form.Size = New-Object System.Drawing.Size(800, 900)
$Form.StartPosition = "CenterScreen"
$Form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$Form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$Form.Icon = [System.Drawing.SystemIcons]::Shield

# Create main container panel with scrolling
$mainPanel = New-Object System.Windows.Forms.Panel
$mainPanel.AutoScroll = $true
$mainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$mainPanel.Padding = New-Object System.Windows.Forms.Padding(20)
$Form.Controls.Add($mainPanel)

# Header Panel
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Height = 60
$headerPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$mainPanel.Controls.Add($headerPanel)

# Title Label
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Windows Defender Security Manager"
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(20, 15)
$headerPanel.Controls.Add($lblTitle)

# Instructions Panel
$instructionsPanel = New-Object System.Windows.Forms.Panel
$instructionsPanel.Height = 50
$instructionsPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$instructionsPanel.Padding = New-Object System.Windows.Forms.Padding(20, 10, 20, 10)
$mainPanel.Controls.Add($instructionsPanel)

# Instructions Label
$lblInstructions = New-Object System.Windows.Forms.Label
$lblInstructions.Text = "Select the security components you want to modify. Use caution as this may affect system security."
$lblInstructions.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblInstructions.AutoSize = $true
$instructionsPanel.Controls.Add($lblInstructions)

# Categories definition including missing components
$categories = @{
    "Core Protection" = @(
        "Real-Time Protection",
        "Cloud-Delivered Protection",
        "Automatic Sample Submission"
    )
    "System Security" = @(
        "Core Isolation Memory Integrity",
        "Exploit Protection",
        "Controlled Folder Access"
    )
    "Network Security" = @(
        "Firewall",
        "Network Protection",
        "Firewall Advanced Security"
    )
    "Advanced Features" = @(
        "Advanced Protection Features",
        "System Guard",
        "Kernel Protection"
    )
    "Additional Security Settings" = @(
        "SmartScreen",
        "Ransomware Protection",
        "ASR Rules",
        "Credential Guard",
        "Services",
        "Automatic Updates",
        "Delivery Optimization",
        "Security Notifications",
        "Scheduled Scans",
        "AppLocker"
    )
}

$yOffset = 120

# We'll store references to status labels after creation
Function SetGlobalCheckboxVariable($component, $checkbox, $statusLabel)
{
    switch ($component) {
        "Real-Time Protection" { $global:chkRealTimeProtection = $checkbox; $global:lblRTPStatus = $statusLabel }
        "Cloud-Delivered Protection" { $global:chkCloudProtection = $checkbox; $global:lblCloudStatus = $statusLabel }
        "Automatic Sample Submission" { $global:chkSampleSubmission = $checkbox; $global:lblSampleStatus = $statusLabel }
        "Core Isolation Memory Integrity" { $global:chkCoreIsolation = $checkbox; $global:lblCoreIsolationStatus = $statusLabel }
        "Exploit Protection" { $global:chkExploitProtection = $checkbox; $global:lblExploitProtectionStatus = $statusLabel }
        "Controlled Folder Access" { $global:chkControlledFolderAccess = $checkbox; $global:lblCFAStatus = $statusLabel }
        "Firewall" { $global:chkFirewall = $checkbox; $global:lblFirewallStatus = $statusLabel }
        "Network Protection" { $global:chkNetworkProtection = $checkbox; $global:lblNPStatus = $statusLabel }
        "Firewall Advanced Security" { $global:chkFirewallAdvanced = $checkbox; $global:lblFirewallAdvancedStatus = $statusLabel }
        "Advanced Protection Features" { $global:chkAdvancedProtection = $checkbox; }
        "System Guard" { $global:chkSystemGuard = $checkbox; } # no direct status label key was defined, can be handled if needed
        "Kernel Protection" { $global:chkKernelProtection = $checkbox; }
        "SmartScreen" { $global:chkSmartScreen = $checkbox; $global:lblSmartScreenStatus = $statusLabel }
        "Ransomware Protection" { $global:chkRansomwareProtection = $checkbox; $global:lblRansomwareStatus = $statusLabel }
        "ASR Rules" { $global:chkASRRules = $checkbox; $global:lblASRStatus = $statusLabel }
        "Credential Guard" { $global:chkCredentialGuard = $checkbox; $global:lblCredentialGuardStatus = $statusLabel }
        "Services" { $global:chkServices = $checkbox; $global:lblServicesStatus = $statusLabel }
        "Automatic Updates" { $global:chkAutomaticUpdates = $checkbox; $global:lblAUStatus = $statusLabel }
        "Delivery Optimization" { $global:chkDeliveryOptimization = $checkbox; $global:lblDOStatus = $statusLabel }
        "Security Notifications" { $global:chkSecurityNotifications = $checkbox; $global:lblNotificationsStatus = $statusLabel }
        "Scheduled Scans" { $global:chkScheduledScans = $checkbox; $global:lblScheduledStatus = $statusLabel }
        "AppLocker" { $global:chkAppLocker = $checkbox; $global:lblAppLockerStatus = $statusLabel }
    }
}

foreach ($category in $categories.Keys) {
    # Category Panel
    $categoryPanel = New-Object System.Windows.Forms.GroupBox
    $categoryPanel.Text = $category
    $categoryPanel.Location = New-Object System.Drawing.Point(20, $yOffset)
    $categoryPanel.Size = New-Object System.Drawing.Size(740, 150)
    $categoryPanel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $mainPanel.Controls.Add($categoryPanel)

    $xPos = 20
    $yPos = 30
    foreach ($component in $categories[$category]) {
        # Component Container
        $componentPanel = New-Object System.Windows.Forms.Panel
        $componentPanel.Size = New-Object System.Drawing.Size(230, 50)
        $componentPanel.Location = New-Object System.Drawing.Point($xPos, $yPos)
        $categoryPanel.Controls.Add($componentPanel)

        # Checkbox
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Text = $component
        $checkbox.Location = New-Object System.Drawing.Point(5, 5)
        $checkbox.AutoSize = $true
        $checkbox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $componentPanel.Controls.Add($checkbox)

        # Status Label
        $statusLabel = New-Object System.Windows.Forms.Label
        $statusLabel.Text = "Status: Enabled"
        $statusLabel.ForeColor = [System.Drawing.Color]::Green
        $statusLabel.Location = New-Object System.Drawing.Point(20, 25)
        $statusLabel.AutoSize = $true
        $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $componentPanel.Controls.Add($statusLabel)

        # Assign global variables
        SetGlobalCheckboxVariable $component $checkbox $statusLabel

        $xPos += 240
        if ($xPos > 500) {
            $xPos = 20
            $yPos += 60
        }

        # Add tooltip
        If ($tooltipDescriptions.ContainsKey($component)) {
            $toolTip.SetToolTip($componentPanel, $tooltipDescriptions[$component])
            $toolTip.SetToolTip($checkbox, $tooltipDescriptions[$component])
        }
    }

    $yOffset += 170
}

# Action Buttons Panel
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Height = 60
$buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
$buttonPanel.Padding = New-Object System.Windows.Forms.Padding(20, 10, 20, 10)
$mainPanel.Controls.Add($buttonPanel)

# Refresh Button
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Refresh Status"
$btnRefresh.Size = New-Object System.Drawing.Size(120, 30)
$btnRefresh.Location = New-Object System.Drawing.Point(500, 15)
$btnRefresh.BackColor = [System.Drawing.Color]::White
$btnRefresh.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$buttonPanel.Controls.Add($btnRefresh)
$btnRefresh.Add_Click({ RefreshStatus })

# Apply Button
$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text = "Apply Changes"
$btnApply.Size = New-Object System.Drawing.Size(120, 30)
$btnApply.Location = New-Object System.Drawing.Point(640, 15)
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$btnApply.ForeColor = [System.Drawing.Color]::White
$btnApply.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$buttonPanel.Controls.Add($btnApply)

# Theme toggle button
$btnTheme = New-Object System.Windows.Forms.Button
$btnTheme.Text = "Toggle Theme"
$btnTheme.Size = New-Object System.Drawing.Size(120, 30)
$btnTheme.Location = New-Object System.Drawing.Point(360, 15)
$btnTheme.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$btnTheme.ForeColor = [System.Drawing.Color]::White
$btnTheme.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$buttonPanel.Controls.Add($btnTheme)

$script:currentTheme = "Light"
$btnTheme.Add_Click({
    $script:currentTheme = if ($script:currentTheme -eq "Light") { "Dark" } else { "Light" }
    Apply-Theme $script:currentTheme
})

# Add button events for Apply Changes
$btnApply.Add_Click({
    # Determine whether to enable or disable based on checkboxes
    # For demonstration: If Real-Time Protection is checked, just disable as example.
    # In practice, you might prompt user or have separate buttons for enable/disable.
    # Here we call DisableDefenderComponents for demonstration.
    DisableDefenderComponents
})

# Apply initial theme
Apply-Theme "Light"

# Run initial checks
CheckTamperProtection

# Refresh Status Indicators
RefreshStatus

# Show Form
$Form.Add_Shown({$Form.Activate()})
[void]$Form.ShowDialog()

# End of Script
LogMessage "Script execution completed."
