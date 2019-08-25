# Description: Boxstarter Script
# Author: suntong
# Based on 0-SystemConfiguration.ps1

# Install chocolatey/choco first, then
# Run the following from an **elevated** powershell command-prompt:
#      md C:\Temp
#      Start-Transcript -NoClobber -Path C:\Temp\00-SysEssential.txt 
# Note that you may need to lift the execution policy restriction:
#      Set-ExecutionPolicy Bypass -Scope Process -Force
# 1) install boxstarter
#      choco upgrade chocolatey
#      CINST Boxstarter
# 2) run boxstarter (Install-BoxstarterPackage -PackageName <URL-TO-RAW-GIST>)
#      Install-BoxstarterPackage -PackageName https://raw.githubusercontent.com/suntong/boxstarter/master/00-SysEssential.ps1
# To terminate the recording
#      Stop-Transcript

#########################################
# Set Basic directories                 #
#########################################
New-Item -ItemType directory -Path C:\Temp
md C:\Tmp
md C:\Tools
md C:\Programs

# Save all the commands and their output to a file in PowerShell, from outside instead.
# Start-Transcript -NoClobber -Path C:\Temp\00-SysEssential.txt

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

# Disable the Lock Screen (the one before password prompt - to prevent dropping the first character)
If (-Not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization)) {
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name Personalization | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1

# Privacy: Let apps use my advertising ID: Disable
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0

# Privacy: SmartScreen Filter for Store Apps: Disable
If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0

# WiFi Sense: HotSpot Sharing: Disable
If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
    New-Item -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0

# Disable Telemetry (requires a reboot to take effect)
If (-Not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0

Get-Service DiagTrack,Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled


############################
# Personal Preferences on UI
############################

# Change Explorer home screen back to "This PC"
If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1

# ## Win8
Set-StartScreenOptions -EnableBootToDesktop -EnableListDesktopAppsFirst
Set-CornerNavigationOptions -EnableUsePowerShellOnWinX

# ## Win10

# Change it back to "Quick Access" (Windows 10 default)
#Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2

# These make "Quick Access" behave much closer to the old "Favorites"
# Disable Quick Access: Recent Files
#If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")) {
#  New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Force | Out-Null#
#}
#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0

###########################################
#       	 Set explorer options         #
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

Write-Host "Disable P2P Update downlods outside of local network"
# Disable P2P Update downlods outside of local network
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
    New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Force | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3

Write-Host "Install WindowsUpdate"
Install-WindowsUpdate -AcceptEula -GetUpdatesFromMS


#Need a check to see if this reboot has already been done...
if (Test-PendingReboot) { Write-Host "System reboot necessary. Type:`nInvoke-Reboot" }
