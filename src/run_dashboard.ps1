param(
  [ValidateRange(1024, 65535)][int]$Port = 8765,
  [string]$BuildDirectory = 'build/dashboard',
  [string]$OpenSSLRoot,
  [string]$ToolchainFile,
  [ValidateSet('Debug', 'Release', 'RelWithDebInfo')][string]$Configuration = 'Release',
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildPath = if ([IO.Path]::IsPathRooted($BuildDirectory)) {
  [IO.Path]::GetFullPath($BuildDirectory)
} else {
  [IO.Path]::GetFullPath((Join-Path $projectRoot $BuildDirectory))
}

if (-not $SkipBuild) {
  $cmakePath = (Get-Command cmake -ErrorAction Stop).Source
  $configureArguments = @('-S', $projectRoot, '-B', $buildPath,
    '-Dlib_desfire_build_dashboard=ON', "-DCMAKE_BUILD_TYPE=$Configuration")
  if ($OpenSSLRoot) { $configureArguments += "-DOPENSSL_ROOT_DIR=$OpenSSLRoot" }
  if ($ToolchainFile) { $configureArguments += "-DCMAKE_TOOLCHAIN_FILE=$ToolchainFile" }
  & $cmakePath @configureArguments
  if ($LASTEXITCODE -ne 0) { throw 'Dashboard configuration failed.' }
  & $cmakePath --build $buildPath --config $Configuration --target desfire_dashboard_assets --parallel
  if ($LASTEXITCODE -ne 0) { throw 'Dashboard build failed.' }
}

$executableCandidates = @(
  (Join-Path $buildPath "$Configuration/desfire_dashboard.exe"),
  (Join-Path $buildPath 'desfire_dashboard.exe')
)
$executablePath = $executableCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $executablePath) { throw 'Dashboard executable not found. Build it before using -SkipBuild.' }
& $executablePath --port $Port
if ($LASTEXITCODE -ne 0) { throw 'Dashboard stopped with an error.' }
