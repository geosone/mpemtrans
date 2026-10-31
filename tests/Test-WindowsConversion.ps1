param(
    [Parameter(Mandatory)] [string] $Archive,
    [Parameter(Mandatory)] [string] $Library,
    [Parameter(Mandatory)] [string] $FixtureDirectory,
    [Parameter(Mandatory)] [string] $TestDirectory
)
$ErrorActionPreference = 'Stop'
if (Test-Path $TestDirectory) {
    throw 'Use a fresh test directory.'
}
New-Item -ItemType Directory -Path $TestDirectory | Out-Null
Expand-Archive -LiteralPath $Archive -DestinationPath $TestDirectory
$files = @(Get-ChildItem $TestDirectory -File)
if ($files.Count -ne 2) {
    throw 'Archive must contain exactly the executable and README.'
}
$exe = Join-Path $TestDirectory 'mpemtrans.exe'
$dll = Join-Path $TestDirectory (Split-Path $Library -Leaf)
Copy-Item -LiteralPath $Library -Destination $dll
$key = Join-Path $FixtureDirectory 'key.pem'
$cert = Join-Path $FixtureDirectory 'cert.pem'
$password = Join-Path $FixtureDirectory 'password.txt'
$first = Join-Path $TestDirectory 'auto.p15'
$second = Join-Path $TestDirectory 'explicit.p15'
# Run outside the executable directory to exercise DLL discovery rather than CWD.
Push-Location $FixtureDirectory
try {
    & $exe --key $key --cert $cert --out $first --label ssl_cert --password-file $password
    if ($LASTEXITCODE -ne 0 -or !(Test-Path $first)) {
        throw 'Automatic DLL discovery/conversion failed.'
    }
    & $exe --library $dll --key $key --cert $cert --out $second --label ssl_cert --password-file $password
    if ($LASTEXITCODE -ne 0 -or !(Test-Path $second)) {
        throw 'Explicit DLL conversion failed.'
    }
    $chainOutput = Join-Path $TestDirectory 'fullchain.p15'
    $encrypted = Join-Path $FixtureDirectory 'encrypted.pem'
    $chain = Join-Path $FixtureDirectory 'fullchain.pem'
    & $exe --key $encrypted --cert $chain --out $chainOutput --label ssl_cert --password-file $password --input-password-file $password
    if ($LASTEXITCODE -ne 0 -or !(Test-Path $chainOutput)) {
        throw 'Encrypted PKCS8/fullchain conversion failed.'
    }
    $before = (Get-FileHash -LiteralPath $first).Hash
    & $exe --key $key --cert $cert --out $first --label ssl_cert --password-file $password
    if ($LASTEXITCODE -eq 0 -or (Get-FileHash -LiteralPath $first).Hash -ne $before) {
        throw 'Existing output protection failed.'
    }
    if (@(Get-ChildItem $TestDirectory -Force -Directory -Filter '.mpemtrans-*').Count -ne 0) {
        throw 'Temporary staging was not cleaned.'
    }
} finally {
    Pop-Location
}
Write-Output 'PASS native Windows single/fullchain conversion, encrypted PKCS8/reopen, executable-local DLL discovery, explicit DLL path, overwrite refusal and staging cleanup.'
