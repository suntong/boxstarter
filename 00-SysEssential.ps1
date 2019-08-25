# Description: Boxstarter Script
# Author: suntong
# Based on 0-SystemConfiguration.ps1

#########################################
# Set Execution Policy			#
#########################################

# Boxstarter options
$Boxstarter.RebootOk=$true # Allow reboots?
$Boxstarter.NoPassword=$false # Is this a machine with no login password?
$Boxstarter.AutoLogin=$true # Save my password securely and auto-login after a reboot

# Basic setup
Write-Host "Setting execution policy"

#---- TEMPORARY ---
Update-ExecutionPolicy Unrestricted
Disable-UAC

##################
# Privacy Settings
##################

Enable-RemoteDesktop

# Disabling Internet Explorer Enhanced Security Configuration
# https://www.ibm.com/support/knowledgecenter/en/SSSHRK_3.9.0/com.ibm.networkmanagerip.doc_3.9/tip/ttip_trouble_esc.html
Write-Host "Disable IE ESC"
Disable-InternetExplorerESC

# Disabling User Account Control (UAC)
# https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works
#Write-Host "Disable UAC"
#Disable-UAC

Disable-BingSearch
Disable-GameBarTips

#--- Windows Settings ---
# Some from: @NickCraver's gist https://gist.github.com/NickCraver/7ebf9efbfd0c3eab72e9

# Privacy: Let apps use my advertising ID: Disable
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0

# Privacy: SmartScreen Filter for Store Apps: Disable
If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0
If (-Not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost")) {
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Force | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0

# WiFi Sense: HotSpot Sharing: Disable
If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0
If (-Not (Test-Path "HKCU:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path HKCU:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Force | Out-Null
}
Set-ItemProperty -Path HKCU:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
    New-Item -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0
If (-Not (Test-Path "HKCU:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
    New-Item -Path HKCU:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Force | Out-Null
}
Set-ItemProperty -Path HKCU:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0


# Start Menu: Disale Cortana (Commented out by default - this is personal preference)
# TODO: Figure this out - need another VM to test, mine's already disabled via domain, etc.


# Disable Telemetry (requires a reboot to take effect)
If (-Not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
If (-Not (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
    New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Force | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0

Get-Service DiagTrack,Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled


############################
# Personal Preferences on UI
############################

# Change Explorer home screen back to "This PC"
If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
If (-Not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Force | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1

# ## Win8
Set-StartScreenOptions -EnableBootToDesktop
Set-StartScreenOptions -EnableListDesktopAppsFirst
Set-CornerNavigationOptions -EnableUsePowerShellOnWinX

# ## Win10

# Change it back to "Quick Access" (Windows 10 default)
#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2

# These make "Quick Access" behave much closer to the old "Favorites"
# Disable Quick Access: Recent Files
#If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")) {
#  New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Force | Out-Null#
#}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0

###########################################
#       	 Set explorer options     #
###########################################

Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar -EnableExpandToOpenFolder -EnableOpenFileExplorerToQuickAccess -EnableShowRecentFilesInQuickAccess -EnableShowFrequentFoldersInQuickAccess

# Better File Explorer
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1		
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1		
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name MMTaskbarMode -Value 2

Set-TaskbarOptions -Size Small -Dock Bottom -Combine Full -Lock -AlwaysShowIconsOn


#--- Restore Temporary Settings ---
Enable-UAC

###########################################
# Update Windows and reboot if necessary  #
###########################################

Write-Host "Enable MicrosoftUpdate"
Enable-MicrosoftUpdate

Write-Host "Change Windows Updates to 'Notify to schedule restart'"
# Change Windows Updates to "Notify to schedule restart"
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
    New-Item -Path HKCU:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Force | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1

Write-Host "Disable P2P Update downlods outside of local network"
# Disable P2P Update downlods outside of local network
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Force | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3

Write-Host "Install WindowsUpdate"
Install-WindowsUpdate -AcceptEula -GetUpdatesFromMS


#Need a check to see if this reboot has already been done...
if (Test-PendingReboot) { Write-Host "System reboot necessary. Type:`nInvoke-Reboot" }
