# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`""
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

# Check SMBv1 status and ask only if it's not enabled
$rebootNeeded = $false
$SMBv1Status = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"
if ($SMBv1Status.State -ne "Enabled") {
    $enableSMBv1 = $host.UI.PromptForChoice(
        "SMBv1 Configuration",
        "SMBv1 is not enabled. Do you want to enable it? (Not recommended for security)",
        @(
            [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Enable SMBv1")
            [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Do not enable SMBv1")
        ),
        1  # Default is No
    )

    if ($enableSMBv1 -eq 0) {
        Write-Host "Enabling SMBv1..."
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart | Out-Null
        $rebootNeeded = $true
    } else {
        Write-Host "Skipping SMBv1 configuration"
    }
} else {
    Write-Host "SMBv1 is already enabled"
}

# Create new local user 'Scan' if it doesn't exist
$Password = ConvertTo-SecureString "1234" -AsPlainText -Force
try {
    Get-LocalUser -Name "Scan" -ErrorAction Stop
    Write-Host "User 'Scan' already exists"
} catch {
    New-LocalUser -Name "Scan" -Password $Password -PasswordNeverExpires -UserMayNotChangePassword
    Write-Host "Created new user 'Scan'"
}

# Create Scan folder if it doesn't exist
$FolderPath = Join-Path $env:SystemDrive "Scan"
if (-not (Test-Path $FolderPath)) {
    New-Item -Path $FolderPath -ItemType Directory -Force
    Write-Host "Created folder $FolderPath"
} else {
    Write-Host "Folder $FolderPath already exists"
}

# Set folder permissions for Scan user
$Acl = Get-Acl -Path $FolderPath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Scan", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($AccessRule)
Set-Acl -Path $FolderPath -AclObject $Acl

# Remove existing share if it exists
$ShareName = "Scan"
try {
    Get-SmbShare -Name $ShareName -ErrorAction Stop | Remove-SmbShare -Force
    Write-Host "Removed existing share $ShareName"
} catch {
    Write-Host "No existing share to remove"
}

# Create new share with Scan user permissions
New-SmbShare -Name $ShareName -Path $FolderPath | Out-Null
Grant-SmbShareAccess -Name $ShareName -AccountName "Scan" -AccessRight Full -Force | Out-Null
Write-Host "Created share with scan user permissions"

# Create desktop shortcut with correct icon
$DesktopPath = Join-Path $env:USERPROFILE "Desktop"
$ShortcutPath = Join-Path $DesktopPath "Scan.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $FolderPath
$Shortcut.IconLocation = "shell32.dll,201"
$Shortcut.Save()

# Get and display share path
$SharePath = "\\$env:COMPUTERNAME\$ShareName"
Write-Host "Share path: $SharePath"

# Copy share path to clipboard
Set-Clipboard -Value $SharePath

# Ask for reboot if needed
if ($rebootNeeded) {
    $reboot = $host.UI.PromptForChoice(
        "System Restart Required",
        "A restart is required to complete SMBv1 configuration. Restart now?",
        @(
            [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Restart now")
            [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Restart later")
        ),
        1  # Default is No
    )
    
    if ($reboot -eq 0) {
        Write-Host "Restarting computer..."
        Restart-Computer -Force
    } else {
        Write-Host "Please remember to restart your computer to complete SMBv1 configuration."
    }
}
