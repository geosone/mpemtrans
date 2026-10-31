#Requires -Version 7.4
param(
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$Library,
    [Parameter(Mandatory)][string]$CaptureDirectory,
    [Parameter(Mandatory)][int]$Port
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or (Get-Content -LiteralPath (Join-Path $FixtureRoot '.mpemtrans-setup-fixture') -Raw) -ne 'Fresh vendor fixture') {
    throw 'Fresh Windows setup fixture required.'
}
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = Join-Path $FixtureRoot 'mis.exe'
$info.Arguments = 'server'
$info.WorkingDirectory = $FixtureRoot
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$info.Environment['MPEMTRANS_REAL_LIBRARY'] = (Resolve-Path -LiteralPath $Library).Path
$info.Environment['MPEMTRANS_CAPTURE_DIRECTORY'] = (Resolve-Path -LiteralPath $CaptureDirectory).Path
$process = [Diagnostics.Process]::new()
$process.StartInfo = $info
$client = $null
$secure = $null
try {
    $process.Start() | Out-Null
    # Drain the interactive screen without logging captured interface values.
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ($true) {
        if ($process.HasExited) {
            throw 'Synthetic Windows MIS exited.'
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync('127.0.0.1', $Port)
            if (!$task.Wait(2000)) {
                throw 'Synthetic connection timed out.'
            }
            break
        } catch {
            $client.Dispose()
            $client = $null
            if ([DateTime]::UtcNow -ge $deadline) {
                throw 'Synthetic Windows MIS did not open TLS.'
            }
            Start-Sleep -Milliseconds 100
        }
    }
    # This is a fresh synthetic loopback certificate, used only to trigger the
    # observed keyset API. Capture files must come from this fixture's shim.
    $callback = [Net.Security.RemoteCertificateValidationCallback]{ $true }
    $secure = [Net.Security.SslStream]::new($client.GetStream(), $false, $callback)
    $secure.ReadTimeout = 5000
    $secure.WriteTimeout = 5000
    $secure.AuthenticateAsClient('localhost')
    if (!$secure.RemoteCertificate) {
        throw 'Synthetic TLS peer did not present a certificate.'
    }
    $buffer = [byte[]]::new(2048)
    if ($secure.Read($buffer, 0, $buffer.Length) -lt 1) {
        throw 'Synthetic BinkP greeting missing.'
    }
    foreach ($name in @('label.capture', 'password.capture')) {
        if (!(Test-Path -LiteralPath (Join-Path $CaptureDirectory $name) -PathType Leaf)) {
            throw 'Native keyset interface was not captured.'
        }
    }
    Write-Output 'PASS isolated Windows fixture capture; profile values are not displayed'
} finally {
    if ($secure) {
        $secure.Dispose()
    }
    if ($client) {
        $client.Dispose()
    }
    if ($process.Id -and !$process.HasExited) {
        $stopInfo = [Diagnostics.ProcessStartInfo]::new()
        $stopInfo.FileName = $info.FileName
        $stopInfo.Arguments = 'shutdown'
        $stopInfo.WorkingDirectory = $FixtureRoot
        $stopInfo.UseShellExecute = $false
        $stopInfo.CreateNoWindow = $true
        $stopInfo.RedirectStandardOutput = $true
        $stopInfo.RedirectStandardError = $true
        $stop = [Diagnostics.Process]::Start($stopInfo)
        if (!$stop.WaitForExit(10000)) {
            $stop.Kill()
        }
        $stop.Dispose()
        if (!$process.WaitForExit(10000)) {
            $process.Kill()
            $process.WaitForExit()
        }
    }
    $process.Dispose()
}
