param(
    [Parameter(Mandatory = $true)][string]$Bundle
)

$ErrorActionPreference = "Stop"
$files = Get-ChildItem -LiteralPath $Bundle -Recurse -File |
    Where-Object { $_.Extension -in @(".exe", ".dll", ".pyd") }
if (-not $files) {
    throw "The Windows bundle contains no Authenticode-verifiable files."
}
foreach ($file in $files) {
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "$($file.FullName) failed Authenticode verification: $($signature.Status)"
    }
}

$signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($signTool) {
    foreach ($file in $files) {
        & $signTool.Source verify /pa /all /v $file.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool verification failed for $($file.FullName)."
        }
    }
}
