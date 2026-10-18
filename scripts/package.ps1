# Builds the plugin in Release and creates dist/Jellyfin.Plugin.TwoFactor_<version>.zip
# containing the plugin DLL(s) and a meta.json, ready to unzip into Jellyfin's plugins folder.
# Metadata is read from build.yaml (same fields as the official jellyfin-plugin-template).
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'src/Jellyfin.Plugin.TwoFactor/Jellyfin.Plugin.TwoFactor.csproj'
$publishDir = Join-Path $root 'dist/publish'
$dist = Join-Path $root 'dist'

function Get-YamlScalar([string]$text, [string]$key) {
    $match = [regex]::Match($text, "(?m)^${key}:\s*`"?([^`"\r\n]*)`"?\s*$")
    if (-not $match.Success) { throw "Key '$key' not found in build.yaml" }
    return $match.Groups[1].Value
}

function Get-YamlFolded([string]$text, [string]$key) {
    $match = [regex]::Match($text, "(?ms)^${key}:\s*>\s*\r?\n((?:[ \t]+[^\r\n]*\r?\n?)+)")
    if (-not $match.Success) { return '' }
    return (($match.Groups[1].Value -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' ')
}

$yaml = Get-Content -Raw -Path (Join-Path $root 'build.yaml')
$version = Get-YamlScalar $yaml 'version'

if (Test-Path $publishDir) { Remove-Item -Recurse -Force $publishDir }
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

dotnet publish $project -c Release -o $publishDir
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed' }

# Only the plugin assembly is shipped: Jellyfin provides every other dependency.
$artifacts = [regex]::Matches($yaml, '(?m)^- "([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
$stage = Join-Path $dist 'stage'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
foreach ($artifact in $artifacts) {
    Copy-Item -Path (Join-Path $publishDir $artifact) -Destination $stage
}

$meta = [ordered]@{
    category    = Get-YamlScalar $yaml 'category'
    guid        = Get-YamlScalar $yaml 'guid'
    name        = Get-YamlScalar $yaml 'name'
    description = Get-YamlFolded $yaml 'description'
    overview    = Get-YamlScalar $yaml 'overview'
    owner       = Get-YamlScalar $yaml 'owner'
    targetAbi   = Get-YamlScalar $yaml 'targetAbi'
    timestamp   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    version     = $version
    status      = 'Active'
    autoUpdate  = $true
    assemblies  = @($artifacts)
}
$json = $meta | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText((Join-Path $stage 'meta.json'), $json, (New-Object System.Text.UTF8Encoding($false)))

$zip = Join-Path $dist "Jellyfin.Plugin.TwoFactor_$version.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip

Remove-Item -Recurse -Force $stage, $publishDir
Write-Host "Created $zip"

