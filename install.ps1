param(
    [string]$Bundle,
    [string]$Version,
    [string]$BaseUrl,
    [string]$Sha256,
    [string]$InstallDir,
    # Kept only so older copied commands remain valid. PATH setup is now
    # automatic for every install.
    [switch]$ModifyPath,
    [switch]$AllowUnsigned
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
    $topLevel = $null
    $hasNestedEntry = $false
    try {
        if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt $maximumEntries) {
            throw "ZIP archive is empty or contains too many entries."
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
                throw "ZIP archive contains an unsafe or duplicate path: $name"
            }
            if ($null -eq $topLevel) {
                $topLevel = $segments[0]
            }
            elseif (
                -not [string]::Equals(
                    $topLevel,
                    $segments[0],
                    [System.StringComparison]::Ordinal
                )
            ) {
                throw "ZIP archive contains more than one top-level path."
            }
            if ($segments.Count -gt 1) {
                $hasNestedEntry = $true
            }

            $attributes = [BitConverter]::ToUInt32(
                [BitConverter]::GetBytes([int]$entry.ExternalAttributes),
                0
            )
            $unixType = ($attributes -shr 16) -band 0xF000
            if ($unixType -notin @(0, 0x4000, 0x8000)) {
                throw "ZIP archive contains a forbidden non-file entry: $name"
            }
            $isDirectory = $name.EndsWith("/")
            if (
                ($isDirectory -and $unixType -eq 0x8000) -or
                (-not $isDirectory -and $unixType -eq 0x4000) -or
                ($isDirectory -and $entry.Length -ne 0)
            ) {
                throw "ZIP archive entry type is inconsistent: $name"
            }
            if ($entry.Length -gt $maximumFileBytes) {
                throw "ZIP archive contains an oversized file."
            }
            $expandedBytes += $entry.Length
            if ($expandedBytes -gt $maximumExpandedBytes) {
                throw "ZIP archive expands beyond the allowed size."
            }

            $relative = $normalized.Replace(
                [char]"/",
                [System.IO.Path]::DirectorySeparatorChar
            )
            $target = [System.IO.Path]::GetFullPath((Join-Path $root $relative))
            if (-not $target.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "ZIP archive entry escapes its extraction directory."
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
                throw "ZIP archive entry size does not match its metadata."
            }
        }
    }
    finally {
        $zip.Dispose()
    }
    if (-not $topLevel -or -not $hasNestedEntry) {
        throw "ZIP archive does not contain one top-level bundle directory."
    }
    return $topLevel
}

$temporary = $null
$verifyDownloadedSignatures = $false
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
        # Detect the true OS architecture from the environment rather than
        # RuntimeInformation.OSArchitecture: a 32-bit PowerShell process (WOW64)
        # on 64-bit Windows reports the process architecture there, which
        # surfaced as a spurious "Unsupported Windows architecture".
        # PROCESSOR_ARCHITEW6432 holds the real OS architecture only under WOW64;
        # otherwise PROCESSOR_ARCHITECTURE already is the OS architecture.
        $osArchitecture = $env:PROCESSOR_ARCHITEW6432
        if (-not $osArchitecture) { $osArchitecture = $env:PROCESSOR_ARCHITECTURE }
        $architecture = switch ($osArchitecture) {
            "AMD64" { "x86_64" }
            "ARM64" { "aarch64" }
            "X64" { "x86_64" }
            default {
                throw "BYO ships 64-bit Windows builds only (x64 or ARM64); 32-bit Windows is not supported. Detected architecture '$osArchitecture' (PROCESSOR_ARCHITECTURE=$($env:PROCESSOR_ARCHITECTURE); PROCESSOR_ARCHITEW6432=$($env:PROCESSOR_ARCHITEW6432))."
            }
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
        $Bundle = $archive
        # Unsigned preview: the pinned -Sha256 already fixes the exact archive
        # bytes out of band, so -AllowUnsigned skips the Authenticode check a
        # signed channel would otherwise enforce.
        if ($AllowUnsigned) {
            Write-Host "Skipping Authenticode verification (-AllowUnsigned); the pinned SHA-256 fixes the exact archive."
        }
        else {
            $verifyDownloadedSignatures = $true
        }
    }

    if (Test-Path -LiteralPath $Bundle -PathType Leaf) {
        $archive = (Get-Item -LiteralPath $Bundle).FullName
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zipCheck = [System.IO.Compression.ZipFile]::OpenRead($archive)
            $zipCheck.Dispose()
        }
        catch {
            throw "Windows bundle must be a valid ZIP archive: $archive"
        }
        if (-not $temporary) {
            $temporary = Join-Path (
                [System.IO.Path]::GetTempPath()
            ) ("byo-install-" + [guid]::NewGuid())
            New-Item -ItemType Directory -Path $temporary | Out-Null
        }
        $extractionRoot = Join-Path $temporary "extracted"
        New-Item -ItemType Directory -Path $extractionRoot | Out-Null
        $bundleRoot = Expand-BoundedByoZip `
            -Archive $archive `
            -Destination $extractionRoot
        $Bundle = Join-Path $extractionRoot $bundleRoot
        if (-not (Test-Path -LiteralPath $Bundle -PathType Container)) {
            throw "ZIP archive did not create its declared bundle directory."
        }
    }
    elseif (Test-Path -LiteralPath $Bundle -PathType Container) {
        $Bundle = (Get-Item -LiteralPath $Bundle).FullName
    }
    else {
        throw "Bundle path is not a ZIP archive or extracted directory: $Bundle"
    }

    $launcher = Join-Path $Bundle "byo.exe"
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        throw "Bundle launcher is missing: $launcher"
    }
    if ($verifyDownloadedSignatures) {
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
    $installArguments += "--modify-path"
    & $launcher @installArguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    $installRoot = if ($InstallDir) {
        [System.IO.Path]::GetFullPath($InstallDir)
    }
    else {
        Join-Path $env:LOCALAPPDATA "BYO"
    }
    $byoBin = Join-Path $installRoot "bin"
    if (-not (($env:Path -split ';') -contains $byoBin)) {
        $env:Path = "$byoBin;$env:Path"
    }
    Write-Host "BYO installed and added to PATH. Run 'byo' now; restart other terminal apps that were already open."
}
finally {
    if ($temporary -and (Test-Path -LiteralPath $temporary)) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}
