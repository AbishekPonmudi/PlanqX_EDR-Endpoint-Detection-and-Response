function Initialize-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()
}

# Function to check existing antivirus software
function Get-RegisteredAntivirus {
    try {
        $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Select-Object displayName, productState
        if ($avProducts) {
            Write-Host "Detected antivirus products:" -ForegroundColor Cyan
            $avProducts | ForEach-Object {
                Write-Host " - $($_.displayName) (State: $($_.productState))" -ForegroundColor Cyan
            }
        } else {
            Write-Host "No antivirus products detected." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Error retrieving antivirus products: $_" -ForegroundColor Red
    }
}

function Register-AMSIProvider {
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}"
        # Always set properties, even if the path exists, to ensure they’re present
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $registryPath -Name "(Default)" -Value "Planqx Professional Detection Response" -Force
        Set-ItemProperty -Path $registryPath -Name "ProviderName" -Value "Planqx Security" -Force
        Set-ItemProperty -Path $registryPath -Name "Version" -Value "1.0.0.0" -Type String -Force
        Write-Host "AMSI Provider registered successfully at $registryPath" -ForegroundColor Green
        
        # Verify properties explicitly
        $regProps = Get-ItemProperty -Path $registryPath
        Write-Host "Registered properties:" -ForegroundColor Cyan
        Write-Host "  (Default): $($regProps.'(default)')" -ForegroundColor Cyan
        Write-Host "  ProviderName: $($regProps.ProviderName)" -ForegroundColor Cyan
        Write-Host "  Version: $($regProps.Version)" -ForegroundColor Cyan
    } catch {
        Write-Host "Error registering AMSI Provider: $_" -ForegroundColor Red
    }
}

# Function to register PlanqX EDR in Windows Security Center
function Register-SecurityCenterProvider {
    try {
        # Ensure script runs with admin privileges
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "This function requires administrative privileges."
        }

        $wmiNamespace = "root\SecurityCenter2"
        $wmiClass = "AntiVirusProduct"
        $obj = New-Object -ComObject WbemScripting.SWbemLocator
        $service = $obj.ConnectServer($env:COMPUTERNAME, $wmiNamespace)
        $newInstance = $service.Get($wmiClass).SpawnInstance_()
        
        # Set required properties for PlanqX Security EDR
        $newInstance.displayName = "PlanqX Security EDR"
        $newInstance.productState = 397312  # Enabled, up-to-date, real-time protection on
        $newInstance.instanceGuid = "{$(New-Guid)}"  # Unique GUID
        $newInstance.pathToSignedProductExe = "$env:SystemRoot\System32\PlanqxEDR.exe"  # Placeholder path
        $newInstance.pathToSignedReportingExe = "$env:SystemRoot\System32\PlanqxEDR.exe"  # Additional required field
        
        $newInstance.Put_()
        
        Write-Host "PlanqX Security EDR registered in Windows Security Center" -ForegroundColor Green
    } catch {
        Write-Host "Error registering PlanqX EDR in Security Center: $_" -ForegroundColor Red
        Write-Host "Note: Full Security Center integration may require a real EDR service." -ForegroundColor Yellow
    }
}

try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Write-Host "Execution policy set successfully" -ForegroundColor Green
} catch {
    Write-Host "Error setting execution policy: $_" -ForegroundColor Red
    exit 1
}

# Trigger Certificate Installation
$scriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptPath) { $scriptPath = Get-Location | Select-Object -ExpandProperty Path }
$certScript = Join-Path $scriptPath "Install-Certificate.ps1"
$certLocation = Join-Path $scriptPath "certificate.p12"
Write-Host "Script Path: $scriptPath" -ForegroundColor Cyan
Write-Host "Cert Script: $certScript" -ForegroundColor Cyan
Write-Host "Cert Location: $certLocation" -ForegroundColor Cyan
if (Test-Path $certScript) {
    Write-Host "Installing certificate..." -ForegroundColor Cyan
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$certScript`" -CertPath `"$certLocation`"" -NoNewWindow -Wait
} else {
    Write-Host "Certificate installation script not found at: $certScript" -ForegroundColor Yellow
}

function Install-Python {
    try {
        if (-not (Get-Command python -ErrorAction SilentlyContinue) -or -not (Get-Command pip -ErrorAction SilentlyContinue)) {
            Write-Host "Installing Python..." -ForegroundColor Cyan
            $pythonUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
            $pythonInstaller = "$env:TEMP\python-3.11.9-amd64.exe"
            
            Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller
            Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
            Remove-Item $pythonInstaller -Force
            Write-Host "Python installed successfully" -ForegroundColor Green
            
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        } else {
            Write-Host "Python is already installed" -ForegroundColor Green
        }
    } catch {
        Write-Host "Error installing Python: $_" -ForegroundColor Red
    }
}

function Install-Scoop {
    try {
        if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
            Write-Host "Installing Scoop..." -ForegroundColor Cyan
            $env:SCOOP_ALLOW_ADMIN = 'true'
            Invoke-Expression "& {$(Invoke-RestMethod -Uri https://get.scoop.sh)} -RunAsAdmin"
            $scoopPath = "$env:USERPROFILE\scoop\shims"
            [System.Environment]::SetEnvironmentVariable("PATH", "$env:PATH;$scoopPath", [System.EnvironmentVariableTarget]::User)
            Write-Host "Scoop installed successfully" -ForegroundColor Green
        } else {
            Write-Host "Scoop is already installed" -ForegroundColor Green
        }
    } catch {
        Write-Host "Error installing Scoop: $_" -ForegroundColor Red
    }
}

function Install-YARA {
    try {
        if (Get-Command scoop -ErrorAction SilentlyContinue) {
            Write-Host "Installing YARA..." -ForegroundColor Cyan
            $scoopPath = "$env:USERPROFILE\scoop\shims\scoop.exe"
            if (Test-Path $scoopPath) {
                Start-Process -FilePath $scoopPath -ArgumentList "install yara" -NoNewWindow -Wait
            } else {
                Invoke-Expression "scoop install yara"
            }
            Write-Host "YARA installed successfully" -ForegroundColor Green
        } else {
            Write-Host "Scoop not installed, skipping YARA installation" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Error installing YARA: $_" -ForegroundColor Red
    }
}

function Install-PythonLibraries {
    try {
        if (Get-Command python -ErrorAction SilentlyContinue) {
            Write-Host "Upgrading pip..." -ForegroundColor Cyan
            Start-Process -FilePath "python" -ArgumentList "-m pip install --upgrade pip" -NoNewWindow -Wait
            
            Write-Host "Installing Python libraries..." -ForegroundColor Cyan
            $libraries = @("pefile", "yara-python", "pywin32", "tqdm", "psutil", "pandas", "scapy", "mitmproxy")
            foreach ($lib in $libraries) {
                Write-Host "Installing $lib..."
                Start-Process -FilePath "python" -ArgumentList "-m pip install $lib" -NoNewWindow -Wait
            }
            Write-Host "Python libraries installed successfully" -ForegroundColor Green
        } else {
            Write-Host "Python not found, skipping library installation" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Error installing Python libraries: $_" -ForegroundColor Red
    }
}

function Install-Npcap {
    try {
        $npcapUrl = "https://npcap.com/dist/npcap-1.79.exe"
        $npcapInstaller = "$env:TEMP\npcap-1.79.exe"
        
        Write-Host "Downloading Npcap..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller
        
        Write-Host "Installing Npcap..." -ForegroundColor Cyan
        Start-Process -FilePath $npcapInstaller
        
        Remove-Item $npcapInstaller -Force
        Write-Host "Npcap installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "Error installing Npcap: $_" -ForegroundColor Red
    }
}

function Show-RestartNotification {
    Initialize-GUI
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Planqx Professional Detection Response"
    $form.Size = New-Object System.Drawing.Size(450,250)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon("$env:SystemRoot\System32\shell32.dll")

    $header = New-Object System.Windows.Forms.Label
    $header.Location = New-Object System.Drawing.Point(20,20)
    $header.Size = New-Object System.Drawing.Size(400,30)
    $header.Text = "Installation Complete"
    $header.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $header.TextAlign = "MiddleCenter"
    $form.Controls.Add($header)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20,60)
    $label.Size = New-Object System.Drawing.Size(400,80)
    $label.Text = "The installation has completed successfully!`nYour system will restart in 5 minutes.`nPlease save all your work and close all applications."
    $label.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $label.TextAlign = "MiddleCenter"
    $form.Controls.Add($label)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(175,160)
    $okButton.Size = New-Object System.Drawing.Size(100,30)
    $okButton.Text = "OK"
    $okButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $okButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $okButton.ForeColor = [System.Drawing.Color]::White
    $okButton.FlatStyle = "Flat"
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $form.ShowDialog()
    
    shutdown -r -t 300 -c "System restart required for Planqx Professional Detection Response installation"
}

# Execute all functions
Write-Host "Checking existing antivirus solutions..." -ForegroundColor Cyan
Get-RegisteredAntivirus

Install-Python
Install-Scoop
Install-YARA
Install-PythonLibraries
Install-Npcap

Write-Host "Registering AMSI Provider..." -ForegroundColor Cyan
Register-AMSIProvider

Write-Host "Registering PlanqX EDR in Windows Security Center..." -ForegroundColor Cyan
Register-SecurityCenterProvider

Write-Host "Setup completed!" -ForegroundColor Green
Show-RestartNotification