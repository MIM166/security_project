param(
    [switch]$Quick,
    [switch]$IncludeKernel,
    [ValidateRange(1, 3)][int]$Repeats = 1,
    [string]$Distribution = "Ubuntu-24.04"
)
$ErrorActionPreference = "Stop"
$projectLinuxPath = (& wsl.exe -d $Distribution -- wslpath -a -u $PSScriptRoot).Trim()
if ($LASTEXITCODE -ne 0) { throw "Cannot access the project in WSL distribution $Distribution" }
$labArguments = @("-d", $Distribution, "-u", "root", "--", "python3", "$projectLinuxPath/run_trial.py", "--repeats", "$Repeats")
if ($Quick) { $labArguments += "--quick" }
if ($IncludeKernel) { $labArguments += "--include-kernel" }
& wsl.exe @labArguments
if ($LASTEXITCODE -ne 0) { throw "Lab failed; inspect the evidence directory printed above." }
$latestLabRun = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot "results") -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "summary.json") } | Sort-Object Name -Descending | Select-Object -First 1
Write-Host "Open report: $(Join-Path $latestLabRun.FullName 'report.html')"
