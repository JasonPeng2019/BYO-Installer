param(
    [string]$Bundle,
    [string]$Version,
    [string]$BaseUrl,
    [string]$Sha256,
    [string]$InstallDir
)

$ErrorActionPreference = "Stop"

function Expand-BoundedByoZip {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $maximumEntries = 20000
    $maximumFileBytes = 512MB
    $maximumExpandedBytes = 2GB
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $root = [System.IO.Path]::GetFullPath($Destination)
    $rootPrefix = $root.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt $maximumEntries) {
            throw "Downloaded ZIP is empty or contains too many entries."
        }
        [long]$expandedBytes = 0
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            $normalized = $name.TrimEnd("/")
            $segments = $normalized.Split("/")
            if (
                -not $normalized -or
                $name.Contains("\") -or
                $name.StartsWith("/") -or
                $normalized -match '^[A-Za-z]:' -or
                ($segments | Where-Object { -not $_ -or $_ -eq "." -or $_ -eq ".." }) -or
                -not $seen.Add($normalized)
            ) {
                throw "Downloaded ZIP contains an unsafe or duplicate path: $name"
            }

            $attributes = [BitConverter]::ToUInt32(
                [BitConverter]::GetBytes([int]$entry.ExternalAttributes),
                0
            )
            $unixType = ($attributes -shr 16) -band 0xF000
            if ($unixType -notin @(0, 0x4000, 0x8000)) {
                throw "Downloaded ZIP contains a forbidden non-file entry: $name"
            }
            $isDirectory = $name.EndsWith("/")
            if (
                ($isDirectory -and $unixType -eq 0x8000) -or
                (-not $isDirectory -and $unixType -eq 0x4000) -or
                ($isDirectory -and $entry.Length -ne 0)
            ) {
                throw "Downloaded ZIP entry type is inconsistent: $name"
            }
            if ($entry.Length -gt $maximumFileBytes) {
                throw "Downloaded ZIP contains an oversized file."
            }
            $expandedBytes += $entry.Length
            if ($expandedBytes -gt $maximumExpandedBytes) {
                throw "Downloaded ZIP expands beyond the allowed size."
            }

            $relative = $normalized.Replace(
                [char]"/",
                [System.IO.Path]::DirectorySeparatorChar
            )
            $target = [System.IO.Path]::GetFullPath((Join-Path $root $relative))
            if (-not $target.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Downloaded ZIP entry escapes its extraction directory."
            }
            if ($isDirectory) {
                [System.IO.Directory]::CreateDirectory($target) | Out-Null
                continue
            }
            [System.IO.Directory]::CreateDirectory(
                [System.IO.Path]::GetDirectoryName($target)
            ) | Out-Null
            $source = $entry.Open()
            $output = [System.IO.File]::Open(
                $target,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
            try {
                $source.CopyTo($output)
            }
            finally {
                $output.Dispose()
                $source.Dispose()
            }
            if ((Get-Item -LiteralPath $target).Length -ne $entry.Length) {
                throw "Downloaded ZIP entry size does not match its metadata."
            }
        }
    }
    finally {
        $zip.Dispose()
    }
}

$temporary = $null
try {
    if (-not $Bundle) {
        if (-not $Version -or -not $BaseUrl -or -not $Sha256) {
            throw "Supply -Bundle, or supply -Version, -BaseUrl, and -Sha256."
        }
        if ($Version -notmatch '^[0-9A-Za-z.+-]+$') {
            throw "Version must be an exact safe release identifier."
        }
        if ($BaseUrl -notmatch '^https://') {
            throw "The release base URL must use HTTPS."
        }
        if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw "The SHA-256 digest is invalid."
        }
        $architecture = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
            "X64" { "x86_64" }
            "Arm64" { "aarch64" }
            default { throw "Unsupported Windows architecture." }
        }
        $archiveName = "byo-$Version-windows-$architecture.zip"
        $archiveUrl = "$($BaseUrl.TrimEnd('/'))/$archiveName"
        $temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("byo-install-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $temporary | Out-Null
        $archive = Join-Path $temporary $archiveName
        Invoke-WebRequest -Uri $archiveUrl -OutFile $archive -MaximumRedirection 5
        $actualSha = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualSha -ne $Sha256.ToLowerInvariant()) {
            throw "Downloaded archive SHA-256 mismatch."
        }
        Expand-BoundedByoZip -Archive $archive -Destination $temporary
        $Bundle = Join-Path $temporary "byo-$Version-windows-$architecture"
    }

    $launcher = Join-Path $Bundle "byo.exe"
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        throw "Bundle launcher is missing: $launcher"
    }
    if ($temporary) {
        $signedFiles = Get-ChildItem -LiteralPath $Bundle -Recurse -File |
            Where-Object { $_.Extension -in @(".exe", ".dll", ".pyd") }
        if (-not $signedFiles) {
            throw "Downloaded bundle contains no Authenticode-verifiable files."
        }
        foreach ($signedFile in $signedFiles) {
            $signature = Get-AuthenticodeSignature -LiteralPath $signedFile.FullName
            if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
                throw "$($signedFile.FullName) has no valid Authenticode signature: $($signature.Status)"
            }
        }
    }
    $installArguments = @("install-runtime", "--bundle", $Bundle)
    if ($InstallDir) {
        $installArguments += @(
            "--install-dir",
            [System.IO.Path]::GetFullPath($InstallDir)
        )
    }
    & $launcher @installArguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    Write-Host "BYO installed. Add the bin path reported by 'byo paths' to PATH if needed."
}
finally {
    if ($temporary -and (Test-Path -LiteralPath $temporary)) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}
