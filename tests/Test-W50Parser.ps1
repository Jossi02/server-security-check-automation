$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'windows/W-50.Parser.ps1')

$english = ConvertFrom-NetAccountsMaximumAge -Lines (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/net-accounts-en.txt'))
if ($english.Status -ne 'OK' -or $english.Age -ne 90) { throw 'English fixture failed.' }

$korean = ConvertFrom-NetAccountsMaximumAge -Lines (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/net-accounts-ko.txt'))
if ($korean.Status -ne 'OK' -or $null -ne $korean.Age -or $korean.Display -ne 'Unlimited') { throw 'Korean fixture failed.' }

$invalid = ConvertFrom-NetAccountsMaximumAge -Lines (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/net-accounts-invalid.txt'))
if ($invalid.Status -ne 'ERROR') { throw 'Invalid fixture must return ERROR.' }

Write-Host 'PowerShell fixture tests passed.'
