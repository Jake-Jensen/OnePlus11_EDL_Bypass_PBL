[CmdletBinding()]
param(
    [ValidateSet('debug', 'release', 'release-debug')]
    [string]$Profile = 'release',
    [switch]$Package,
    [switch]$Launch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Push-Location -LiteralPath $PSScriptRoot
$staging = $null
try {
    $firehoses = Join-Path $PSScriptRoot 'Firehoses'
    if (-not (Test-Path -LiteralPath $firehoses -PathType Container)) {
        throw 'The entire Firehoses directory is required for distribution. Restore it before building.'
    }
    $metadataText = & cargo metadata --no-deps --format-version 1 --locked
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
    $metadata = ($metadataText -join "`n") | ConvertFrom-Json
    $version = ($metadata.packages | Where-Object name -eq 'edl-studio').version

    # Cargo reports actual executable paths, including custom CARGO_TARGET_DIR/target settings.
    $artifacts = @{}
    & cargo build --profile $Profile --locked --workspace --bins --message-format=json-render-diagnostics |
        ForEach-Object {
            $message = $_ | ConvertFrom-Json
            if ($message.reason -eq 'compiler-artifact' -and $message.executable) {
                $artifacts[$message.target.name] = $message.executable
            }
        }
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed.' }
    foreach ($binary in @('edl-studio', 'edl-inspect')) {
        if (-not $artifacts.ContainsKey($binary) -or -not (Test-Path -LiteralPath $artifacts[$binary])) {
            throw "Cargo did not produce the required $binary executable."
        }
        if ([IO.Path]::GetExtension($artifacts[$binary]) -ne '.exe') {
            throw 'Build.ps1 packages Windows executables. Select a Windows MSVC toolchain.'
        }
    }

    $dist = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'dist'))
    $destination = if ($Profile -eq 'release') { $dist } else { Join-Path $dist $Profile }
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $staging = Join-Path $dist ('.staging-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging | Out-Null
    foreach ($entry in @(@('edl-studio', 'SaharaStudio.exe'), @('edl-inspect', 'edl-inspect.exe'))) {
        Copy-Item -LiteralPath $artifacts[$entry[0]] -Destination (Join-Path $staging $entry[1])
        if ($Profile -ne 'release') {
            $symbols = [IO.Path]::ChangeExtension($artifacts[$entry[0]], '.pdb')
            if (Test-Path -LiteralPath $symbols) {
                Copy-Item -LiteralPath $symbols -Destination (Join-Path $staging ([IO.Path]::ChangeExtension($entry[1], '.pdb')))
            }
        }
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $staging
    $docs = Join-Path $PSScriptRoot 'Docs'
    if (Test-Path -LiteralPath $docs -PathType Container) {
        Copy-Item -LiteralPath $docs -Destination (Join-Path $staging 'Docs') -Recurse -Force
    }
    $license = Join-Path $PSScriptRoot 'LICENSE'
    if (Test-Path -LiteralPath $license) { Copy-Item -LiteralPath $license -Destination $staging }
    # Copy the directory itself: all nested files, hidden files and empty directories.
    Copy-Item -LiteralPath $firehoses -Destination (Join-Path $staging 'Firehoses') -Recurse -Force
    $sourceFiles = @(Get-ChildItem -LiteralPath $firehoses -Recurse -File -Force)
    foreach ($source in $sourceFiles) {
        $relative = $source.FullName.Substring($firehoses.Length).TrimStart('\', '/')
        $copied = Join-Path (Join-Path $staging 'Firehoses') $relative
        if ((Get-FileHash -LiteralPath $source.FullName).Hash -ne (Get-FileHash -LiteralPath $copied).Hash) {
            throw "Firehoses copy verification failed: $relative"
        }
    }
    Get-ChildItem -LiteralPath $staging -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($staging.Length + 1).Replace('\', '/')
        '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    } | Set-Content -LiteralPath (Join-Path $staging 'SHA256SUMS.txt') -Encoding utf8

    # Publish only generated assets; keep existing captures and preferences intact.
    Get-ChildItem -LiteralPath $staging -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force
    }
    if ($Package) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = Join-Path $dist "SaharaStudio-$version-windows-$Profile.zip"
        # Create from clean staging so old output and personal data cannot enter the ZIP.
        $temporaryArchive = "$staging.zip"
        [IO.Compression.ZipFile]::CreateFromDirectory($staging, $temporaryArchive)
        Move-Item -LiteralPath $temporaryArchive -Destination $archive -Force
        Write-Output "Package: $archive"
    }
    Write-Output "Native application: $destination\SaharaStudio.exe"
    Write-Output "Included and SHA-256 verified all $($sourceFiles.Count) Firehoses files."
    if ($Launch) {
        Start-Process -FilePath (Join-Path $destination 'SaharaStudio.exe') -WorkingDirectory $destination -WindowStyle Normal
    }
} finally {
    if ($staging -and (Test-Path -LiteralPath $staging)) {
        # Only remove the unique staging child created by this invocation.
        $resolvedStaging = [IO.Path]::GetFullPath($staging)
        if ([IO.Path]::GetDirectoryName($resolvedStaging) -eq $dist -and
            [IO.Path]::GetFileName($resolvedStaging) -match '^\.staging-[0-9a-f]{32}$') {
            Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
            if (Test-Path -LiteralPath "$resolvedStaging.zip") { Remove-Item -LiteralPath "$resolvedStaging.zip" -Force }
        }
    }
    Pop-Location
}
