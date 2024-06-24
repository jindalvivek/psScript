    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

    # Logging function
    function Write-Log {
        param (
            [string]$Message,
            [string]$LogLevel = "INFO"
        )
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$LogLevel] $Message"
        if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") { 
            $ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition 
        } else { 
            $ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0]) 
            if (!$ScriptPath){ $ScriptPath = "." }
        }
        $logFile = Join-Path $ScriptPath "IT_Audit_Policy.log"
        Add-Content -Path $logFile -Value $logMessage
    }
    




    Write-Log "Script started" -LogLevel "INFO"

    # Check if the script is running with administrative privileges (unchanged)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if (-not $isAdmin) {
        Write-Log "Script not running with administrative privileges. Exiting." -LogLevel "ERROR"
        [System.Windows.MessageBox]::Show("Please run this script with administrative privileges.", "Admin Access Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        exit
    }

    Write-Log "Script running with administrative privileges." -LogLevel "INFO"

    # XAML for the main window
    # XAML for the main window
    [xml]$xaml = @"
    <Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="IT Audit Policy - Apply Restrictions" Height="700" Width="600" WindowStartupLocation="CenterScreen">
    <Window.Resources>
        <Style x:Key="MaterialCheckBox" TargetType="CheckBox">
            <Setter Property="Margin" Value="0,8,0,8"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="Foreground" Value="#212121"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <Grid>
                            <ContentPresenter VerticalAlignment="Center" Margin="0,0,28,0"/>
                            <Border x:Name="Border" BorderBrush="#757575" BorderThickness="2" CornerRadius="2" Width="18" Height="18" VerticalAlignment="Center" HorizontalAlignment="Right">
                                <Path x:Name="CheckMark" Width="10" Height="10" Fill="#2196F3" Data="M 0 5 L 3 8 L 8 3" Stretch="Fill" Visibility="Collapsed"/>
                            </Border>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="CheckMark" Property="Visibility" Value="Visible"/>
                                <Setter TargetName="Border" Property="Background" Value="#2196F3"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="#2196F3"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="BorderBrush" Value="#1976D2"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="MaterialButton" TargetType="Button">
            <Setter Property="Margin" Value="16"/>
            <Setter Property="Padding" Value="32,24"/>
            <Setter Property="FontSize" Value="16"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="Background" Value="#2196F3"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="MinWidth" Value="100"/>
            <Setter Property="MinHeight" Value="30"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="8">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#1976D2"/>
                </Trigger>
                <Trigger Property="IsPressed" Value="True">
                    <Setter Property="Background" Value="#0D47A1"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Border Grid.Row="0" Background="#2196F3" Padding="16">
            <TextBlock Text="IT Audit Policy - Apply Restrictions" FontSize="24" Foreground="White" FontWeight="Medium" HorizontalAlignment="Center"/>
        </Border>
        <TextBlock Grid.Row="1" Text="Copyright (c) 2024 VRCredX. All rights reserved. Version: June 24, 2024" FontSize="12" Margin="16,8,16,16" HorizontalAlignment="Center"/>
        <Border Grid.Row="2" Margin="16,0,16,16" BorderThickness="1" BorderBrush="#E0E0E0" CornerRadius="4">
            <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="16">
                <StackPanel x:Name="CheckBoxPanel"/>
            </ScrollViewer>
        </Border>
        <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,0,0,16">
            <Button x:Name="ApplyButton" Content="Apply" Style="{StaticResource MaterialButton}"/>
            <Button x:Name="RemoveButton" Content="Remove All Restrictions" Style="{StaticResource MaterialButton}"/>
            <Button x:Name="NewAccountButton" Content="New Account" Style="{StaticResource MaterialButton}"/>
        </StackPanel>
    </Grid>
</Window>
"@


    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)

    Write-Log "Main window created" -LogLevel "DEBUG"

    # Get controls
    $checkBoxPanel = $window.FindName("CheckBoxPanel")
    $applyButton = $window.FindName("ApplyButton")
    $removeButton = $window.FindName("RemoveButton")
    $newAccountButton = $window.FindName("NewAccountButton")

    Write-Log "Controls retrieved" -LogLevel "DEBUG"
    # Define options with tooltips
    $options = @(
        @{Name="Disable USB Devices"; Tooltip="Prevents the use of USB storage devices"},
        @{Name="Disable Registry Editor"; Tooltip="Blocks access to the Windows Registry Editor"},
        @{Name="Disable File Sharing"; Tooltip="Turns off file and printer sharing"},
        @{Name="Set Password Policy"; Tooltip="Enforces strong password requirements"},
        @{Name="Enable Windows Defender"; Tooltip="Activates Windows Defender antivirus"},
        @{Name="Disable Control Panel"; Tooltip="Restricts access to the Control Panel"},
        @{Name="Disable Changing Wallpaper"; Tooltip="Prevents users from changing desktop background"},
        @{Name="Enable Idle Timeout"; Tooltip="Automatically locks the computer after a period of inactivity"},
        @{Name="Disable Removable Media"; Tooltip="Blocks access to removable storage devices"},
        @{Name="Disable Guest Account"; Tooltip="Deactivates the built-in Guest account"},
        @{Name="Disable AutoPlay"; Tooltip="Turns off AutoPlay for all media and devices"},
        @{Name="Enable Windows Firewall"; Tooltip="Activates Windows Firewall for all network profiles"},
        @{Name="Disable RDP"; Tooltip="Turns off Remote Desktop Protocol"},
        @{Name="Disable Unnecessary Services"; Tooltip="Stops and disables non-essential Windows services"},
        @{Name="Enable UAC"; Tooltip="Activates User Account Control"},
        @{Name="Disable PowerShell Script Execution"; Tooltip="Prevents execution of PowerShell scripts"},
        @{Name="Disable Command Prompt"; Tooltip="Restricts access to the Command Prompt"},
        @{Name="Lock After Wrong Passwords"; Tooltip="Locks the account after multiple failed login attempts"},
        @{Name="Remove History"; Tooltip="Clears command and search history"},
        @{Name="Remove Recent Files from MS Office Apps"; Tooltip="Deletes recent file lists from Microsoft Office applications"},
        @{Name="Remove Recent Files from Windows Explorer"; Tooltip="Clears recent files list from Windows Explorer"},
        @{Name="Remove Temp Files"; Tooltip="Deletes temporary files from the system"},
        @{Name="Remove Saved Passwords from Browsers"; Tooltip="Clears saved passwords from web browsers"},
        @{Name="Remove Access to cmd and registry for all users"; Tooltip="Restricts access to Command Prompt and Registry Editor for all users"}
    )



    # Function to set restrictions
    function Set-Restrictions {
        param (
            [hashtable]$Options
        )

        Write-Log "Entering Set-Restrictions function" -LogLevel "INFO"
        Write-Log "Options received: $($Options | Out-String)" -LogLevel "DEBUG"

        foreach ($option in $Options.Keys) {
            if ($Options[$option]) {
                Write-Log "Processing option: $option" -LogLevel "INFO"
                
                switch ($option) {
                    "Disable USB Devices" {
                        try {
                            Write-Log "Attempting to disable USB devices..." -LogLevel "DEBUG"
                            $usbStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start").Start
                            if ($usbStatus -ne 4) {
                                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
                                Write-Log "USB devices have been successfully disabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "USB devices are already disabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error disabling USB devices: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable Registry Editor" {
                        try {
                            Write-Log "Attempting to disable Registry Editor..." -LogLevel "DEBUG"
                            $regStatus = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -ErrorAction SilentlyContinue).DisableRegistryTools
                            if ($regStatus -ne 1) {
                                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -Value 1 -PropertyType DWord -Force | Out-Null
                                Write-Log "Registry Editor has been successfully disabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "Registry Editor is already disabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error disabling Registry Editor: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable File Sharing" {
                        try {
                            Write-Log "Attempting to disable file and folder sharing..." -LogLevel "DEBUG"
                            $shareStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks").AutoShareWks
                            if ($shareStatus -ne 0) {
                                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0
                                Write-Log "File and folder sharing has been successfully disabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "File and folder sharing is already disabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error disabling file and folder sharing: $_" -LogLevel "ERROR"
                        }
                    }
                    "Set Password Policy" {
                        try {
                            Write-Log "Attempting to set user password policy..." -LogLevel "DEBUG"
                            $securityPolicy = [System.IO.Path]::GetTempFileName()
                            secedit /export /cfg $securityPolicy /quiet
                            (Get-Content $securityPolicy) -Replace "PasswordComplexity = 0", "PasswordComplexity = 1" | Out-File $securityPolicy
                            (Get-Content $securityPolicy) -Replace "MinimumPasswordLength = 0", "MinimumPasswordLength = 8" | Out-File $securityPolicy
                            (Get-Content $securityPolicy) -Replace "MaximumPasswordAge = -1", "MaximumPasswordAge = 30" | Out-File $securityPolicy
                            secedit /configure /db c:\windows\security\local.sdb /cfg $securityPolicy /areas SECURITYPOLICY
                            Remove-Item -Path $securityPolicy
                            Write-Log "User password policy has been successfully set." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error setting user password policy: $_" -LogLevel "ERROR"
                        }
                    }
                    "Enable Windows Defender" {
                        try {
                            Write-Log "Attempting to enable Windows Defender..." -LogLevel "DEBUG"
                            $defenderStatus = (Get-MpPreference).DisableRealtimeMonitoring
                            if ($defenderStatus -ne $false) {
                                Set-MpPreference -DisableRealtimeMonitoring $false
                                Write-Log "Windows Defender has been successfully enabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "Windows Defender is already enabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error enabling Windows Defender: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable Control Panel" {
                        try {
                            Write-Log "Attempting to disable Control Panel and Settings..." -LogLevel "DEBUG"
                            $controlPanelPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                            $settingsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

                            if (!(Test-Path $controlPanelPath)) {
                                New-Item -Path $controlPanelPath -Force | Out-Null
                            }
                            Set-ItemProperty -Path $controlPanelPath -Name "NoControlPanel" -Value 1 -Type DWord -Force

                            if (!(Test-Path $settingsPath)) {
                                New-Item -Path $settingsPath -Force | Out-Null
                            }
                            Set-ItemProperty -Path $settingsPath -Name "NoSystemSettings" -Value 1 -Type DWord -Force

                            Write-Log "Control Panel and Settings have been successfully disabled for all users." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error disabling Control Panel and Settings: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable Changing Wallpaper" {try {
                        Write-Log "Attempting to disable Changing Wallpaper..." -LogLevel "DEBUG"
                        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"
                        if (!(Test-Path $path)) {
                            New-Item -Path $path -Force | Out-Null
                        }
                        Set-ItemProperty -Path $path -Name "NoChangingWallpaper" -Value 1 -Type DWord -Force
                        Write-Log "Changing Wallpaper has been successfully disabled." -LogLevel "INFO"
                    }
                    catch {
                        Write-Log "Error disabling Changing Wallpaper: $_" -LogLevel "ERROR"
                    }
                    }
                    "Enable Idle Timeout" {
                        try {
                            Write-Log "Attempting to implement Idle Timeout and Automatic Lock..." -LogLevel "DEBUG"
                            $idleTimeoutStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue).InactivityTimeoutSecs
                            if ($idleTimeoutStatus -ne 300) {
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 300 -PropertyType DWord -Force | Out-Null
                                Write-Log "Idle Timeout and Automatic Lock have been successfully set." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "Idle Timeout and Automatic Lock are already set. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error implementing Idle Timeout and Automatic Lock: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable Removable Media" {
                        try {
                            Write-Log "Attempting to disable Removable Media..." -LogLevel "DEBUG"
                            $removableMediaStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -ErrorAction SilentlyContinue).Deny_All
                            if ($removableMediaStatus -ne 1) {
                                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Force | Out-Null
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -Value 1 -PropertyType DWord -Force | Out-Null
                                Write-Log "Removable Media has been successfully disabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "Removable Media is already disabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error disabling Removable Media: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable Guest Account" {
                        try {
                            Write-Log "Attempting to disable Guest Account..." -LogLevel "DEBUG"
                            $guestStatus = (Get-LocalUser -Name "Guest").Enabled
                            if ($guestStatus -ne $false) {
                                Disable-LocalUser -Name "Guest"
                                Write-Log "Guest Account has been successfully disabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "Guest Account is already disabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error disabling Guest Account: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable AutoPlay" {
                        try {
                            Write-Log "Attempting to disable AutoPlay..." -LogLevel "DEBUG"
                            $autoPlayStatus = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -ErrorAction SilentlyContinue).DisableAutoplay
                            if ($autoPlayStatus -ne 1) {
                                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
                                Write-Log "AutoPlay has been successfully disabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "AutoPlay is already disabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error disabling AutoPlay: $_" -LogLevel "ERROR"
                        }
                    }
                    "Enable Windows Firewall" {
                        try {
                            Write-Log "Attempting to enable Windows Firewall..." -LogLevel "DEBUG"
                            $firewallStatus = (Get-NetFirewallProfile -Profile Domain, Public, Private).Enabled
                            if ($firewallStatus -contains $false) {
                                Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
                                Write-Log "Windows Firewall has been successfully enabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "Windows Firewall is already enabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error enabling Windows Firewall: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable RDP" {
                        try {
                            Write-Log "Attempting to disable Remote Desktop Protocol (RDP)..." -LogLevel "DEBUG"
                            $rdpStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections
                            if ($rdpStatus -ne 1) {
                                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
                                Write-Log "Remote Desktop Protocol (RDP) has been successfully disabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "Remote Desktop Protocol (RDP) is already disabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error disabling Remote Desktop Protocol (RDP): $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable Unnecessary Services" {
                        try {
                            Write-Log "Attempting to disable Unnecessary Services..." -LogLevel "DEBUG"
                            $unnecessaryServices = @("Fax", "Telnet", "SNMP", "SSDP Discovery", "Remote Registry")
                            foreach ($service in $unnecessaryServices) {
                                if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                                    Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                                    Write-Log "$service has been successfully disabled." -LogLevel "INFO"
                                } else {
                                    Write-Log "Service $service not found. Skipping." -LogLevel "WARN"
                                }
                            }
                        }
                        catch {
                            Write-Log "Error disabling Unnecessary Services: $_" -LogLevel "ERROR"
                        }
                    }
                    "Enable UAC" {
                        try {
                            Write-Log "Attempting to enable User Account Control (UAC)..." -LogLevel "DEBUG"
                            $uacStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
                            if ($uacStatus -ne 1) {
                                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
                                Write-Log "User Account Control (UAC) has been successfully enabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "User Account Control (UAC) is already enabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error enabling User Account Control (UAC): $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable PowerShell Script Execution" {
                        try {
                            Write-Log "Attempting to disable PowerShell Script Execution..." -LogLevel "DEBUG"
                            $psScriptStatus = (Get-ExecutionPolicy).ToString()
                            if ($psScriptStatus -ne "Restricted") {
                                Set-ExecutionPolicy -ExecutionPolicy Restricted -Force
                                Write-Log "PowerShell Script Execution has been successfully disabled." -LogLevel "INFO"
                            }
                            else {
                                Write-Log "PowerShell Script Execution is already disabled. No changes made." -LogLevel "INFO"
                            }
                        }
                        catch {
                            Write-Log "Error disabling PowerShell Script Execution: $_" -LogLevel "ERROR"
                        }
                    }
                    "Disable Command Prompt" {
                        try {
                            Write-Log "Attempting to disable Command Prompt..." -LogLevel "DEBUG"
                            New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null
                            New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Name "DisableCMD" -Value 1 -PropertyType DWord -Force | Out-Null
                            Write-Log "Command Prompt has been successfully disabled." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error disabling Command Prompt: $_" -LogLevel "ERROR"
                        }
                    }
                    "Lock After Wrong Passwords" {
                        try {
                            Write-Log "Attempting to set account lockout policy..." -LogLevel "DEBUG"
                            $accountLockoutThreshold = 5
                            $accountLockoutDuration = 5
                            $accountLockoutWindow = 5
                        
                            net accounts /lockoutthreshold:$accountLockoutThreshold /lockoutduration:$accountLockoutDuration /lockoutwindow:$accountLockoutWindow
                        
                            Write-Log "Account lockout policy has been successfully set." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error setting account lockout policy: $_" -LogLevel "ERROR"
                        }
                    }
                    "Remove History" {
                        try {
                            Write-Log "Attempting to remove command history..." -LogLevel "DEBUG"
                            Remove-Item -Path (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
                            Write-Log "Command history has been successfully removed." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error removing command history: $_" -LogLevel "ERROR"
                        }
                    }
                    "Remove Recent Files from MS Office Apps" {
                        try {
                            Write-Log "Attempting to remove recent files from MS Office apps..." -LogLevel "DEBUG"
                            $officeApps = @("Word", "Excel", "PowerPoint", "Access")
                            foreach ($app in $officeApps) {
                                $regPath = "HKCU:\Software\Microsoft\Office\16.0\$app\File MRU"
                                Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                            }
                            Write-Log "Recent files from MS Office apps have been successfully removed." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error removing recent files from MS Office apps: $_" -LogLevel "ERROR"
                        }
                    }
                    "Remove Recent Files from Windows Explorer" {
                        try {
                            Write-Log "Attempting to remove recent files from Windows Explorer..." -LogLevel "DEBUG"
                            Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Log "Recent files from Windows Explorer have been successfully removed." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error removing recent files from Windows Explorer: $_" -LogLevel "ERROR"
                        }
                    }
                    "Remove Temp Files" {
                        try {
                            Write-Log "Attempting to remove temporary files..." -LogLevel "DEBUG"
                            Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Log "Temporary files have been successfully removed." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error removing temporary files: $_" -LogLevel "ERROR"
                        }
                    }
                    "Remove Saved Passwords from Browsers" {
                        try {
                            Write-Log "Attempting to remove browser data (history, cookies, and saved passwords)..." -LogLevel "DEBUG"
                            $Loggedon = Get-CimInstance -Class Win32_Computersystem | Select-Object UserName
                            $Domain, $User = $Loggedon.Username.split('\', 2)
                            $browsers = @(
                                @{Name="Chrome"; Path="Google\Chrome\User Data"},
                                @{Name="Firefox"; Path="Mozilla\Firefox\Profiles"},
                                @{Name="Edge"; Path="Microsoft\Edge\User Data"}
                            )
                            $locations = @("Local", "Roaming")
                    
                            foreach ($browser in $browsers) {
                                foreach ($location in $locations) {
                                    $dataPath = "C:\Users\$User\AppData\$location\$($browser.Path)"
                                    if (Test-Path $dataPath) {
                                        switch ($browser.Name) {
                                            "Chrome" {
                                                Remove-Item "$dataPath\Default\History" -Force -ErrorAction SilentlyContinue
                                                Remove-Item "$dataPath\Default\Cookies" -Force -ErrorAction SilentlyContinue
                                                Remove-Item "$dataPath\Default\Login Data" -Force -ErrorAction SilentlyContinue
                                            }
                                            "Firefox" {
                                                Get-ChildItem $dataPath -Directory | ForEach-Object {
                                                    Remove-Item "$($_.FullName)\places.sqlite" -Force -ErrorAction SilentlyContinue
                                                    Remove-Item "$($_.FullName)\cookies.sqlite" -Force -ErrorAction SilentlyContinue
                                                    Remove-Item "$($_.FullName)\logins.json" -Force -ErrorAction SilentlyContinue
                                                }
                                            }
                                            "Edge" {
                                                Remove-Item "$dataPath\Default\History" -Force -ErrorAction SilentlyContinue
                                                Remove-Item "$dataPath\Default\Cookies" -Force -ErrorAction SilentlyContinue
                                                Remove-Item "$dataPath\Default\Login Data" -Force -ErrorAction SilentlyContinue
                                            }
                                        }
                                        Write-Log "Removed browser data for $($browser.Name) in $location AppData" -LogLevel "INFO"
                                    }
                                }
                            }
                            Write-Log "Browser data has been successfully removed." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error removing browser data: $_" -LogLevel "ERROR"
                        }
                    }
                    "Remove Access to cmd and registry for all users" {
                        try {
                            Write-Log "Attempting to remove access to cmd.exe and regedit.exe for all users..." -LogLevel "DEBUG"
                            $files = @("C:\Windows\System32\cmd.exe", "C:\Windows\regedit.exe")
                            foreach ($file in $files) {
                                if (Test-Path $file) {
                                    # Take ownership of the file
                                    $takeownOutput = takeown /F $file /A 2>&1
                                    if ($LASTEXITCODE -ne 0) {
                                        throw "Failed to take ownership of $file. Error: $takeownOutput"
                                    }
                    
                                    # Remove all existing permissions and add deny permission for Everyone
                                    $icaclsOutput = icacls $file /inheritance:r /deny "*S-1-1-0:(X)" 2>&1
                                    if ($LASTEXITCODE -ne 0) {
                                        throw "Failed to set permissions on $file. Error: $icaclsOutput"
                                    }
                    
                                    Write-Log "Successfully denied execution for $file" -LogLevel "INFO"
                                } else {
                                    Write-Log "File not found: $file" -LogLevel "WARN"
                                }
                            }
                    
                            # Disable CMD through Registry (works on all Windows editions)
                            $regPaths = @(
                                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                            )
                            foreach ($regPath in $regPaths) {
                                if (!(Test-Path $regPath)) {
                                    New-Item -Path $regPath -Force | Out-Null
                                }
                                Set-ItemProperty -Path $regPath -Name "DisableCMD" -Value 2 -Type DWord -Force
                            }
                    
                            # Disable Registry Editor through Registry (works on all Windows editions)
                            $regPaths = @(
                                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                            )
                            foreach ($regPath in $regPaths) {
                                if (!(Test-Path $regPath)) {
                                    New-Item -Path $regPath -Force | Out-Null
                                }
                                Set-ItemProperty -Path $regPath -Name "DisableRegistryTools" -Value 1 -Type DWord -Force
                            }
                    
                            Write-Log "Access to cmd.exe and regedit.exe has been successfully removed for all users." -LogLevel "INFO"
                        }
                        catch {
                            Write-Log "Error removing access to cmd.exe and regedit.exe: $_" -LogLevel "ERROR"
                        }
                    }
                }
            }
        }

        Write-Log "Exiting Set-Restrictions function" -LogLevel "DEBUG"
    }
    function Remove-Restrictions {
        Write-Log "Entering Remove-Restrictions function" -LogLevel "INFO"

    # Create a new window for password entry
    $passwordWindow = New-Object System.Windows.Window
    $passwordWindow.Title = "Remove All Restrictions"
    $passwordWindow.Width = 400
    $passwordWindow.Height = 400
    $passwordWindow.WindowStartupLocation = "CenterScreen"
    $passwordWindow.Background = "#F0F0F0"

    $passwordGrid = New-Object System.Windows.Controls.Grid
    $passwordWindow.Content = $passwordGrid

    $passwordGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
    $passwordGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
    $passwordGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
    $passwordGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{Width = "Auto"}))
    $passwordGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{Width = "*"}))

    $titleLabel = New-Object System.Windows.Controls.Label
    $titleLabel.Content = "Enter Password to Remove Restrictions"
    $titleLabel.FontSize = 18
    $titleLabel.FontWeight = "Bold"
    $titleLabel.HorizontalAlignment = "Center"
    $titleLabel.Margin = "0,20,0,20"
    $passwordGrid.Children.Add($titleLabel)
    [System.Windows.Controls.Grid]::SetRow($titleLabel, 0)
    [System.Windows.Controls.Grid]::SetColumnSpan($titleLabel, 2)

    $passwordLabel = New-Object System.Windows.Controls.Label
    $passwordLabel.Content = "Password:"
    $passwordLabel.Margin = "20,10,10,10"
    $passwordLabel.VerticalAlignment = "Center"
    $passwordGrid.Children.Add($passwordLabel)
    [System.Windows.Controls.Grid]::SetRow($passwordLabel, 1)
    [System.Windows.Controls.Grid]::SetColumn($passwordLabel, 0)

    $passwordBox = New-Object System.Windows.Controls.PasswordBox
    $passwordBox.Margin = "10,10,20,10"
    $passwordBox.Padding = "5"
    $passwordBox.FontSize = 14
    $passwordGrid.Children.Add($passwordBox)
    [System.Windows.Controls.Grid]::SetRow($passwordBox, 1)
    [System.Windows.Controls.Grid]::SetColumn($passwordBox, 1)

    $removeButton = New-Object System.Windows.Controls.Button
    $removeButton.Content = "Remove Restrictions"
    $removeButton.Margin = "20"
    $removeButton.Padding = "10,5"
    $removeButton.FontSize = 14
    $removeButton.Background = "#FF4136"
    $removeButton.Foreground = "White"
    $removeButton.BorderThickness = 0
    $passwordGrid.Children.Add($removeButton)
    [System.Windows.Controls.Grid]::SetRow($removeButton, 2)
    [System.Windows.Controls.Grid]::SetColumnSpan($removeButton, 2)

    $removeButton.Add_Click({
        $enteredPassword = $passwordBox.Password

        if ($enteredPassword -ne "vijay") {
            Write-Log "Incorrect password entered. Restrictions cannot be removed." -LogLevel "WARNING"
            [System.Windows.MessageBox]::Show("Incorrect password. Restrictions cannot be removed.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }

        Write-Log "Correct password entered. Proceeding with restriction removal." -LogLevel "INFO"
    
        # Enable USB devices
        try {
            Write-Log "Attempting to enable USB devices..." -LogLevel "DEBUG"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 3
            Write-Log "USB devices have been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling USB devices: $_" -LogLevel "ERROR"
        }
    
        # Enable Registry Editor
        try {
            Write-Log "Attempting to enable Registry Editor..." -LogLevel "DEBUG"
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -ErrorAction SilentlyContinue
            Write-Log "Registry Editor has been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling Registry Editor: $_" -LogLevel "ERROR"
        }
    
        # Enable file and folder sharing
        try {
            Write-Log "Attempting to enable file and folder sharing..." -LogLevel "DEBUG"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 1
            Write-Log "File and folder sharing has been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling file and folder sharing: $_" -LogLevel "ERROR"
        }
    
        # Remove user password policy
        try {
            Write-Log "Attempting to remove user password policy..." -LogLevel "DEBUG"
            $securityPolicy = [System.IO.Path]::GetTempFileName()
            secedit /export /cfg $securityPolicy /quiet
            (Get-Content $securityPolicy) -Replace "PasswordComplexity = 1", "PasswordComplexity = 0" | Out-File $securityPolicy
            (Get-Content $securityPolicy) -Replace "MinimumPasswordLength = 8", "MinimumPasswordLength = 0" | Out-File $securityPolicy
            (Get-Content $securityPolicy) -Replace "MaximumPasswordAge = 30", "MaximumPasswordAge = -1" | Out-File $securityPolicy
            secedit /configure /db c:\windows\security\local.sdb /cfg $securityPolicy /areas SECURITYPOLICY
            Remove-Item -Path $securityPolicy
            Write-Log "User password policy has been successfully removed." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error removing user password policy: $_" -LogLevel "ERROR"
        }
    
        # Disable Windows Defender
        try {
            Write-Log "Attempting to disable Windows Defender..." -LogLevel "DEBUG"
            Set-MpPreference -DisableRealtimeMonitoring $true
            Write-Log "Windows Defender has been successfully disabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error disabling Windows Defender: $_" -LogLevel "ERROR"
        }
    
        # Enable Control Panel and Settings
        try {
            Write-Log "Attempting to enable Control Panel and Settings..." -LogLevel "DEBUG"
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSystemSettings" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSystemSettings" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -Value 0 -Type DWord -Force
            Write-Log "Control Panel and Settings have been successfully enabled for all users." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling Control Panel and Settings: $_" -LogLevel "ERROR"
        }
    
     # Enable Changing Wallpaper
    try {
        Write-Log "Attempting to enable Changing Wallpaper..." -LogLevel "DEBUG"
        $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"
        if (Test-Path $path) {
            Remove-ItemProperty -Path $path -Name "NoChangingWallpaper" -ErrorAction SilentlyContinue
        }
        Write-Log "Changing Wallpaper has been successfully enabled." -LogLevel "INFO"
    }
    catch {
        Write-Log "Error enabling Changing Wallpaper: $_" -LogLevel "ERROR"
    }
    
        # Disable Idle Timeout and Automatic Lock
        try {
            Write-Log "Attempting to disable Idle Timeout and Automatic Lock..." -LogLevel "DEBUG"
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue
            Write-Log "Idle Timeout and Automatic Lock have been successfully disabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error disabling Idle Timeout and Automatic Lock: $_" -LogLevel "ERROR"
        }
    
        # Remove Account Lockout Policy
        try {
            Write-Log "Attempting to remove account lockout policy..." -LogLevel "DEBUG"
            $accountLockoutThreshold = 0
            $accountLockoutDuration = 0
            $accountLockoutWindow = 0
            net accounts /lockoutthreshold:$accountLockoutThreshold /lockoutduration:$accountLockoutDuration /lockoutwindow:$accountLockoutWindow
            Write-Log "Account lockout policy has been successfully removed." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error removing account lockout policy: $_" -LogLevel "ERROR"
        }
    
        # Enable Removable Media
        try {
            Write-Log "Attempting to enable Removable Media..." -LogLevel "DEBUG"
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -ErrorAction SilentlyContinue
            Write-Log "Removable Media has been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling Removable Media: $_" -LogLevel "ERROR"
        }
    
        # Enable Guest Account
        try {
            Write-Log "Attempting to enable Guest Account..." -LogLevel "DEBUG"
            Enable-LocalUser -Name "Guest"
            Write-Log "Guest Account has been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling Guest Account: $_" -LogLevel "ERROR"
        }
    
        # Enable AutoPlay
        try {
            Write-Log "Attempting to enable AutoPlay..." -LogLevel "DEBUG"
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 0
            Write-Log "AutoPlay has been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling AutoPlay: $_" -LogLevel "ERROR"
        }
    
        # Disable Windows Firewall
        try {
            Write-Log "Attempting to disable Windows Firewall..." -LogLevel "DEBUG"
            Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
            Write-Log "Windows Firewall has been successfully disabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error disabling Windows Firewall: $_" -LogLevel "ERROR"
        }
    
        # Enable Remote Desktop Protocol (RDP)
        try {
            Write-Log "Attempting to enable Remote Desktop Protocol (RDP)..." -LogLevel "DEBUG"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
            Write-Log "Remote Desktop Protocol (RDP) has been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling Remote Desktop Protocol (RDP): $_" -LogLevel "ERROR"
        }
    
        # Enable Unnecessary Services
        try {
            Write-Log "Attempting to enable Unnecessary Services..." -LogLevel "DEBUG"
            $unnecessaryServices = @("Fax", "Telnet", "SNMP", "SSDP Discovery", "Remote Registry")
            foreach ($service in $unnecessaryServices) {
                if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                    Set-Service -Name $service -StartupType Manual -ErrorAction Stop
                    Write-Log "$service has been successfully enabled." -LogLevel "INFO"
                } else {
                    Write-Log "Service $service not found. Skipping." -LogLevel "WARN"
                }
            }
        }
        catch {
            Write-Log "Error enabling Unnecessary Services: $_" -LogLevel "ERROR"
        }
    
        # Disable User Account Control (UAC)
        try {
            Write-Log "Attempting to disable User Account Control (UAC)..." -LogLevel "DEBUG"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
            Write-Log "User Account Control (UAC) has been successfully disabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error disabling User Account Control (UAC): $_" -LogLevel "ERROR"
        }
    
        # Enable PowerShell Script Execution
        try {
            Write-Log "Attempting to enable PowerShell Script Execution..." -LogLevel "DEBUG"
            Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
            Write-Log "PowerShell Script Execution has been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling PowerShell Script Execution: $_" -LogLevel "ERROR"
        }
    
        # Enable Command Prompt
        try {
            Write-Log "Attempting to enable Command Prompt..." -LogLevel "DEBUG"
            Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Name "DisableCMD" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCMD" -ErrorAction SilentlyContinue
            Write-Log "Command Prompt has been successfully enabled." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error enabling Command Prompt: $_" -LogLevel "ERROR"
        }
    
        # Restore access to cmd.exe and regedit.exe
        try {
            Write-Log "Attempting to restore access to cmd.exe and regedit.exe..." -LogLevel "DEBUG"
            $files = @("C:\Windows\System32\cmd.exe", "C:\Windows\regedit.exe")
            foreach ($file in $files) {
                icacls $file /grant Everyone:RX
                Write-Log "Successfully allowed execution for $file" -LogLevel "INFO"
                $adminGroup = "BUILTIN\Administrators"
                takeown /F $file /A /R
                icacls $file /setowner $adminGroup
                icacls $file /grant Administrators:F
            }
            Write-Log "Access to cmd.exe and regedit.exe has been restored for all users." -LogLevel "INFO"
        }
        catch {
            Write-Log "Error restoring access to cmd.exe and regedit.exe: $_" -LogLevel "ERROR"
        }
    
        [System.Windows.MessageBox]::Show("Restrictions removed successfully!", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        $passwordWindow.Close()
    })

    $passwordWindow.ShowDialog()
    Write-Log "Exiting Remove-Restrictions function" -LogLevel "INFO"
    }
    
    # Create checkboxes
    $selectAllCheckbox = New-Object System.Windows.Controls.CheckBox
    $selectAllCheckbox.Content = "Select All"
    $selectAllCheckbox.Margin = "0,0,0,16"
    $selectAllCheckbox.FontSize = 16
    $selectAllCheckbox.FontWeight = "Medium"
    $selectAllCheckbox.Style = $window.FindResource("MaterialCheckBox")
    $selectAllCheckbox.ToolTip = "Select or deselect all options"
    $null = $checkBoxPanel.Children.Add($selectAllCheckbox)

    foreach ($option in $options) {
        $checkbox = New-Object System.Windows.Controls.CheckBox
        $checkbox.Content = $option.Name
        $checkbox.Style = $window.FindResource("MaterialCheckBox")
        
        # Add tooltip
        $tooltip = New-Object System.Windows.Controls.ToolTip
        $tooltip.Content = $option.Tooltip
        $checkbox.ToolTip = $tooltip
        
        $null = $checkBoxPanel.Children.Add($checkbox)
    }

    # Select All functionality
    $selectAllCheckbox.Add_Checked({
        foreach ($checkbox in $checkBoxPanel.Children) {
            if ($checkbox -is [System.Windows.Controls.CheckBox] -and $checkbox -ne $selectAllCheckbox) {
                $checkbox.IsChecked = $true
            }
        }
    })

    $selectAllCheckbox.Add_Unchecked({
        foreach ($checkbox in $checkBoxPanel.Children) {
            if ($checkbox -is [System.Windows.Controls.CheckBox] -and $checkbox -ne $selectAllCheckbox) {
                $checkbox.IsChecked = $false
            }
        }
    })


    # Apply button click event
    $applyButton.Add_Click({
        Write-Log "Apply button clicked" -LogLevel "INFO"
        $selectedOptions = @{}
        foreach ($checkbox in $checkBoxPanel.Children) {
            if ($checkbox -is [System.Windows.Controls.CheckBox] -and $checkbox -ne $selectAllCheckbox) {
                $selectedOptions[$checkbox.Content] = $checkbox.IsChecked
                Write-Log "Option selected: $($checkbox.Content) = $($checkbox.IsChecked)" -LogLevel "DEBUG"
            }
        }
        Set-Restrictions -Options $selectedOptions
        [System.Windows.MessageBox]::Show("Restrictions applied successfully!", "Success")
        Write-Log "Restrictions applied successfully" -LogLevel "INFO"
    })



    # New Account button click event
    $newAccountButton.Add_Click({
        Write-Log "New Account button clicked" -LogLevel "INFO"
        $newAccountWindow = New-Object System.Windows.Window
        $newAccountWindow.Title = "Create New Account"
        $newAccountWindow.Width = 400
        $newAccountWindow.Height = 300
        $newAccountWindow.WindowStartupLocation = "CenterScreen"
        $newAccountWindow.Background = "#F0F0F0"

        $newAccountGrid = New-Object System.Windows.Controls.Grid
        $newAccountWindow.Content = $newAccountGrid

        $newAccountGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
        $newAccountGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
        $newAccountGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
        $newAccountGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{Height = "Auto"}))
        $newAccountGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{Width = "Auto"}))
        $newAccountGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{Width = "*"}))

        $titleLabel = New-Object System.Windows.Controls.Label
        $titleLabel.Content = "Create New User Account"
        $titleLabel.FontSize = 20
        $titleLabel.FontWeight = "Bold"
        $titleLabel.HorizontalAlignment = "Center"
        $titleLabel.Margin = "0,20,0,20"
        $newAccountGrid.Children.Add($titleLabel)
        [System.Windows.Controls.Grid]::SetRow($titleLabel, 0)
        [System.Windows.Controls.Grid]::SetColumnSpan($titleLabel, 2)

        $usernameLabel = New-Object System.Windows.Controls.Label
        $usernameLabel.Content = "Username:"
        $usernameLabel.Margin = "20,10,10,10"
        $usernameLabel.VerticalAlignment = "Center"
        $newAccountGrid.Children.Add($usernameLabel)
        [System.Windows.Controls.Grid]::SetRow($usernameLabel, 1)
        [System.Windows.Controls.Grid]::SetColumn($usernameLabel, 0)

        $usernameTextBox = New-Object System.Windows.Controls.TextBox
        $usernameTextBox.Margin = "10,10,20,10"
        $usernameTextBox.Padding = "5"
        $usernameTextBox.FontSize = 14
        $newAccountGrid.Children.Add($usernameTextBox)
        [System.Windows.Controls.Grid]::SetRow($usernameTextBox, 1)
        [System.Windows.Controls.Grid]::SetColumn($usernameTextBox, 1)

        $passwordLabel = New-Object System.Windows.Controls.Label
        $passwordLabel.Content = "Password:"
        $passwordLabel.Margin = "20,10,10,10"
        $passwordLabel.VerticalAlignment = "Center"
        $newAccountGrid.Children.Add($passwordLabel)
        [System.Windows.Controls.Grid]::SetRow($passwordLabel, 2)
        [System.Windows.Controls.Grid]::SetColumn($passwordLabel, 0)

        $passwordBox = New-Object System.Windows.Controls.PasswordBox
        $passwordBox.Margin = "10,10,20,10"
        $passwordBox.Padding = "5"
        $passwordBox.FontSize = 14
        $newAccountGrid.Children.Add($passwordBox)
        [System.Windows.Controls.Grid]::SetRow($passwordBox, 2)
        [System.Windows.Controls.Grid]::SetColumn($passwordBox, 1)

        $createButton = New-Object System.Windows.Controls.Button
        $createButton.Content = "Create Account"
        $createButton.Margin = "20"
        $createButton.Padding = "10,5"
        $createButton.FontSize = 14
        $createButton.Background = "#2196F3"
        $createButton.Foreground = "White"
        $createButton.BorderThickness = 0
        $newAccountGrid.Children.Add($createButton)
        [System.Windows.Controls.Grid]::SetRow($createButton, 3)
        [System.Windows.Controls.Grid]::SetColumnSpan($createButton, 2)

        $createButton.Add_Click({
            $username = $usernameTextBox.Text
            $password = $passwordBox.Password
            Write-Log "Attempting to create new user account: $username" -LogLevel "INFO"
            
            try {
                # Create the new user account
                $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
                New-LocalUser -Name $username -Password $securePassword -PasswordNeverExpires
                Add-LocalGroupMember -Group "Users" -Member $username
                Write-Log "New user account '$username' created successfully" -LogLevel "INFO"
        
                # Modify default user profile
                $defaultUserKey = "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
                $capabilities = @(
                    "location", "webcam", "microphone", "userNotificationListener", "userAccountInformation",
                    "contacts", "calendar", "phoneCall", "callHistory", "email", "tasks", "messaging",
                    "radios", "bluetoothSync", "appDiagnostics", "documentsLibrary", "picturesLibrary",
                    "videosLibrary", "broadFileSystemAccess", "gazeInput"
                )
        
                foreach ($capability in $capabilities) {
                    $path = "$defaultUserKey\$capability"
                    if (!(Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "Value" -Value "Deny" -Type String
                    Write-Log "Disabled $capability in default user profile" -LogLevel "DEBUG"
                }
        
                # Disable advertising ID in default user profile
                $adPath = "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
                if (!(Test-Path $adPath)) {
                    New-Item -Path $adPath -Force | Out-Null
                }
                Set-ItemProperty -Path $adPath -Name "Enabled" -Value 0 -Type DWord
                Write-Log "Disabled advertising ID in default user profile" -LogLevel "DEBUG"
        
                # Disable app launch tracking in default user profile
                $trackPath = "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                if (!(Test-Path $trackPath)) {
                    New-Item -Path $trackPath -Force | Out-Null
                }
                Set-ItemProperty -Path $trackPath -Name "Start_TrackProgs" -Value 0 -Type DWord
                Write-Log "Disabled app launch tracking in default user profile" -LogLevel "DEBUG"
        
                Write-Log "All privacy settings set to 'no' in default user profile" -LogLevel "INFO"
                [System.Windows.MessageBox]::Show("New user account '$username' has been created successfully with privacy settings disabled.", "Success")
            }
            catch {
                Write-Log "Error creating user account or setting privacy settings: $_" -LogLevel "ERROR"
                [System.Windows.MessageBox]::Show("An error occurred while creating the user account or setting privacy settings. Please check the log for details.", "Error")
            }
            finally {
                $newAccountWindow.Close()
            }
        })
        
        
        

        Write-Log "New Account window opened" -LogLevel "DEBUG"
        $newAccountWindow.ShowDialog()
        Write-Log "New Account window closed" -LogLevel "DEBUG"
    })






    # Remove button click event
    $removeButton.Add_Click({
        Write-Log "Remove button clicked" -LogLevel "INFO"
        $result = [System.Windows.MessageBox]::Show("Enter the password to remove restrictions:", "Password Required", [System.Windows.MessageBoxButton]::OKCancel)
        if ($result -eq "OK") {
            Remove-Restrictions
            [System.Windows.MessageBox]::Show("Restrictions removed successfully!", "Success")
            Write-Log "Restrictions removed successfully" -LogLevel "INFO"
        }
        else {
            Write-Log "Restriction removal cancelled by user" -LogLevel "INFO"
        }
    })

    function Create-SystemBackup {
        Write-Log "Creating system backup..." -LogLevel "INFO"
        
        $backupFolder = "C:\backupForScript"
        $date = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupPath = Join-Path $backupFolder $date
        
        # Create backup folder if it doesn't exist
        if (!(Test-Path $backupFolder)) {
            New-Item -ItemType Directory -Path $backupFolder | Out-Null
        }
        
        # Create folder for this backup
        New-Item -ItemType Directory -Path $backupPath | Out-Null
        
        try {
            # Backup Registry
            $registryBackupPath = Join-Path $backupPath "RegistryBackup"
            reg export HKLM $registryBackupPath"_HKLM.reg" /y
            reg export HKCU $registryBackupPath"_HKCU.reg" /y
            Write-Log "Registry backup created successfully" -LogLevel "INFO"
            
            # Backup important system files
            $systemFiles = @(
                "$env:windir\system32\drivers\etc\hosts",
                "$env:windir\system32\config\SAM",
                "$env:windir\system32\config\SECURITY",
                "$env:windir\system32\config\SOFTWARE",
                "$env:windir\system32\config\SYSTEM"
            )
            
            foreach ($file in $systemFiles) {
                if (Test-Path $file) {
                    Copy-Item -Path $file -Destination $backupPath -Force
                    Write-Log "Backed up $file" -LogLevel "DEBUG"
                }
                else {
                    Write-Log "File not found: $file" -LogLevel "WARN"
                }
            }
            
            # Create a system restore point
            Checkpoint-Computer -Description "IT Audit Policy Backup" -RestorePointType "MODIFY_SETTINGS"
            Write-Log "System restore point created successfully" -LogLevel "INFO"
            
            Write-Log "System backup completed successfully" -LogLevel "INFO"
            return $true
        }
        catch {
            Write-Log "Error creating system backup: $_" -LogLevel "ERROR"
            return $false
        }
    }

    $applyButton.Add_Click({
        Write-Log "Apply button clicked" -LogLevel "INFO"
        
        # Create system backup
        $backupSuccess = Create-SystemBackup
        if (-not $backupSuccess) {
            [System.Windows.MessageBox]::Show("Failed to create system backup. Aborting operation.", "Error")
            return
        }
        
        $selectedOptions = @{}
        foreach ($checkbox in $checkBoxPanel.Children) {
            if ($checkbox -is [System.Windows.Controls.CheckBox] -and $checkbox -ne $selectAllCheckbox) {
                $selectedOptions[$checkbox.Content] = $checkbox.IsChecked
                Write-Log "Option selected: $($checkbox.Content) = $($checkbox.IsChecked)" -LogLevel "DEBUG"
            }
        }
        Set-Restrictions -Options $selectedOptions
        [System.Windows.MessageBox]::Show("Restrictions applied successfully!", "Success")
        Write-Log "Restrictions applied successfully" -LogLevel "INFO"
    })
    

    Write-Log "Main window displayed" -LogLevel "INFO"
    $window.ShowDialog()

    Write-Log "Script execution completed" -LogLevel "INFO"
