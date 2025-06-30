# Stop on any error
$ErrorActionPreference = "Stop"

# Function to log messages with timestamp
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
}

try {
    # Check Python installation
    Write-Log "Checking Python installation..."
    $pythonVersion = python --version
    Write-Log "Found $pythonVersion"

    # Create virtual environment if it doesn't exist
    if (-not (Test-Path ".venv")) {
        Write-Log "Creating virtual environment..."
        python -m venv .venv
    }

    # Activate virtual environment
    Write-Log "Activating virtual environment..."
    .\.venv\Scripts\Activate

    # Upgrade pip
    Write-Log "Upgrading pip..."
    python -m pip install --upgrade pip

    # Install requirements
    Write-Log "Installing requirements..."
    pip install -r requirements.txt

    # Verify AWS CLI installation
    Write-Log "Verifying AWS CLI installation..."
    aws --version

    # Verify Docker installation
    Write-Log "Checking Docker installation..."
    try {
        $dockerVersion = docker --version
        Write-Log "Found $dockerVersion"
        
        Write-Log "Checking Docker daemon..."
        docker ps | Out-Null
        Write-Log "Docker daemon is running"
    } catch {
        Write-Log "Docker not found or daemon not running. Please install Docker Desktop and ensure it's running." -Level Error
        exit 1
    }

    Write-Log "Setup completed successfully!" -Level Info
    Write-Log "You can now use 'docker-compose build' and 'docker-compose up' to run the application."

} catch {
    Write-Log "Setup failed: $_" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
} finally {
    # Deactivate virtual environment if it was activated
    if ($env:VIRTUAL_ENV) {
        deactivate
    }
} 