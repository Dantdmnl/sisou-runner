
# Function to install the latest Python version
function Install-LatestPython {
    Write-Host "Python not found. Installing the latest version of Python..."
    $latestPythonVersionPage = Invoke-WebRequest -Uri "https://www.python.org/downloads/"
    $latestVersionUrl = ($latestPythonVersionPage.ParsedHtml.getElementsByTagName("a") | Where-Object { $_.href -like "*python-*amd64.exe" }).href | Select-Object -First 1
    $pythonInstaller = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri $latestVersionUrl -OutFile $pythonInstaller
    Start-Process -FilePath $pythonInstaller -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait
    Remove-Item -Path $pythonInstaller
    Write-Host "Python installed successfully."
    Write-Host "Please reopen PowerShell for the path changes to take effect, then rerun the script."
    Read-Host -Prompt "Press Enter to exit"
    exit 0
}

# Function to get the Python path
function Get-PythonPath {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($pythonExe -and $pythonExe -like "*Microsoft\WindowsApps*") {
        return $null
    }
    return $pythonExe
}

# Function to ensure pip is installed and updated
function Ensure-Pip {
    Write-Host "Ensuring pip is installed and updated..."
    python -m ensurepip --upgrade
    python -m pip install --upgrade pip
    Write-Host "pip installation and update completed."
}

# Function to ensure SISOU is installed or updated
function Ensure-SISOU {
    Write-Host "Ensuring SISOU is installed or updated..."
    python -m pip install --upgrade sisou
    Write-Host "SISOU installation or update completed."
}

# Function to detect or prompt for Ventoy drive
function Get-VentoyDrive {
    $ventoyDrive = Get-WmiObject Win32_Volume | Where-Object { $_.Label -eq 'Ventoy' } | Select-Object -ExpandProperty DriveLetter
    if (-not $ventoyDrive) {
        $ventoyDrive = Read-Host "Ventoy drive not detected. Please enter the drive letter (e.g., E:)"
    }
    return $ventoyDrive
}

# Main logic

# Step 1: Check for Python and install if not found
$pythonPath = Get-PythonPath
if (-not $pythonPath) {
    Install-LatestPython
    $pythonPath = Get-PythonPath
}

Write-Host "Python is installed at $pythonPath."

# Step 2: Ensure pip is installed and updated
Ensure-Pip

# Step 3: Ensure SISOU is installed or updated
Ensure-SISOU

# Step 4: Detect or prompt for Ventoy drive
$ventoyDrive = Get-VentoyDrive
if (-not $ventoyDrive) {
    Write-Host "No Ventoy drive selected. Exiting..."
    exit 1
}

# Step 5: Run SISOU on the Ventoy drive
Write-Host "Running SISOU on drive $ventoyDrive..."
python -m sisou $ventoyDrive

Write-Host "ISO update process completed."
pause
