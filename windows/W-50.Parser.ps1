function ConvertFrom-NetAccountsMaximumAge {
    param([Parameter(Mandatory)][string[]]$Lines)

    $line = $Lines | Where-Object { $_ -match '^\s*(Maximum password age|최대 암호 사용 기간)(\s*\([^)]*\))?\s*:' } | Select-Object -First 1
    if (-not $line) {
        return [PSCustomObject]@{ Status = 'ERROR'; Age = $null; Display = 'Unknown (field not found)' }
    }

    $value = ($line -split ':', 2)[1].Trim()
    if ($value -match '^(Unlimited|제한 없음)$') {
        return [PSCustomObject]@{ Status = 'OK'; Age = $null; Display = 'Unlimited' }
    }
    if ($value -notmatch '^\d+$') {
        return [PSCustomObject]@{ Status = 'ERROR'; Age = $null; Display = "Unknown ($value)" }
    }

    return [PSCustomObject]@{ Status = 'OK'; Age = [int]$value; Display = "$value days" }
}
