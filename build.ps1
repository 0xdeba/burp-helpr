$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$LibDir = Join-Path $ProjectRoot 'lib'
$ClassesDir = Join-Path $ProjectRoot 'build\classes'
$ResourcesDir = Join-Path $ProjectRoot 'src\main\resources'
$DistDir = Join-Path $ProjectRoot 'dist'
$MontoyaVersion = '2026.7'
$MontoyaJar = Join-Path $LibDir "montoya-api-$MontoyaVersion.jar"
$MontoyaUrl = "https://repo.maven.apache.org/maven2/net/portswigger/burp/extensions/montoya-api/$MontoyaVersion/montoya-api-$MontoyaVersion.jar"
$OutputJar = Join-Path $DistDir 'helpr.jar'

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. Install a JDK and ensure its bin directory is on PATH."
    }
}

Write-Host '== Helpr build ==' -ForegroundColor Cyan
Require-Command 'java'
Require-Command 'javac'
Require-Command 'jar'

New-Item -ItemType Directory -Force -Path $LibDir, $ClassesDir, $DistDir | Out-Null

if (-not (Test-Path $MontoyaJar)) {
    Write-Host "Downloading Burp Montoya API $MontoyaVersion..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $MontoyaUrl -OutFile $MontoyaJar
    }
    catch {
        throw "Could not download the Montoya API. Check your internet connection or place montoya-api-$MontoyaVersion.jar in '$LibDir'. Details: $($_.Exception.Message)"
    }
}

if ((Get-Item $MontoyaJar).Length -lt 10000) {
    throw "Montoya API JAR appears invalid or incomplete: $MontoyaJar"
}

Remove-Item $ClassesDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $ClassesDir | Out-Null

$Sources = @(Get-ChildItem (Join-Path $ProjectRoot 'src\main\java') -Filter '*.java' -Recurse | ForEach-Object { $_.FullName })
if ($Sources.Count -eq 0) { throw 'No Java source files found under src\main\java.' }

Write-Host "Compiling $($Sources.Count) Java source files for Java 21 compatibility..." -ForegroundColor Cyan
& javac --release 21 -encoding UTF-8 -classpath $MontoyaJar -d $ClassesDir @Sources
if ($LASTEXITCODE -ne 0) { throw "javac failed with exit code $LASTEXITCODE" }

if (Test-Path $ResourcesDir) {
    Copy-Item (Join-Path $ResourcesDir '*') $ClassesDir -Recurse -Force
}

Remove-Item $OutputJar -Force -ErrorAction SilentlyContinue
Write-Host 'Packaging dist\helpr.jar...' -ForegroundColor Cyan
& jar --create --file $OutputJar -C $ClassesDir .
if ($LASTEXITCODE -ne 0) { throw "jar failed with exit code $LASTEXITCODE" }

Write-Host ''
Write-Host 'Helpr built successfully.' -ForegroundColor Green
Write-Host "Output: $OutputJar" -ForegroundColor Green
Write-Host 'Load this JAR in Burp Suite: Extensions > Installed > Add.'
