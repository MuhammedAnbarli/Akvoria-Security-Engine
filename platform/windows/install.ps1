# AKVORIA ASE — Windows setup. No administrator rights required.
$ErrorActionPreference = 'Stop'

$python = $null
foreach ($candidate in @('py -3', 'python')) {
    try {
        $version = & cmd /c "$candidate -c `"import sys;print(sys.version_info >= (3,10))`"" 2>$null
        if ($version -eq 'True') { $python = $candidate; break }
    } catch { }
}
if (-not $python) {
    Write-Error 'Python 3.10 or newer is required.'
    exit 1
}

& cmd /c "$python -m venv .venv"
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host ''
Write-Host 'Environment ready.'
Write-Host '  Verify  : .\.venv\Scripts\python.exe main.py self-test'
Write-Host '  Optional: .\.venv\Scripts\python.exe -m pip install -r requirements-optional.txt'
Write-Host ''
Write-Host 'Scope note: monitoring uses polling on Windows; network inventory is not available.'
