# SPDX-License-Identifier: GPL-3.0-only
# Windows PowerShell 5.1。送信はこのPC内だけ（TCP loopback / multicast TTL 0）。
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputDirectory)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$observer = Join-Path $PSScriptRoot 'fence-observer.ps1'
$process = $null
$clients = New-Object 'System.Collections.Generic.List[System.Net.Sockets.TcpClient]'
$sender = $null
$pipeline = $null

function Assert-True([bool]$Condition, [string]$Label) {
    if (-not $Condition) { Write-Output ('CHECK FAILED: ' + $Label); throw 'Check failed' }
}
function Read-Rows([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        # 観測中は共有読み取り。書き終わっていない最後の行は対象にしない。
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8)
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $last = $text.LastIndexOf("`n")
        if ($last -gt 0) { return @($text.Substring(0, $last + 1) | ConvertFrom-Csv) }
    }
    return @()
}
function Wait-For([scriptblock]$Check, [string]$Label) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 8) {
        if (& $Check) { return }
        if ($process.HasExited) { throw 'Observer exited before the test finished' }
        Start-Sleep -Milliseconds 30
    }
    throw $Label
}
function New-LocalClient([int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    $client.Connect([Net.IPAddress]::Loopback, $Port)
    $clients.Add($client)
    return $client
}
function Send-Bytes([Net.Sockets.TcpClient]$Client, [byte[]]$Bytes) {
    $Client.GetStream().Write($Bytes, 0, $Bytes.Length)
}

try {
    Assert-True (Test-Path -LiteralPath $observer) 'Observer script is missing (expected red before implementation)'
    $OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    [void][IO.Directory]::CreateDirectory($OutputDirectory)
    $log = Join-Path $OutputDirectory 'counts.csv'
    $stdout = Join-Path $OutputDirectory 'stdout.txt'
    $stderr = Join-Path $OutputDirectory 'stderr.txt'
    foreach ($path in @($log, $stdout, $stderr)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }

    $reserve = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $reserve.Start()
    $tcpPort = $reserve.LocalEndpoint.Port
    $reserve.Stop()
    $reserveUdp = New-Object Net.Sockets.UdpClient(0)
    $udpPort = ([Net.IPEndPoint]$reserveUdp.Client.LocalEndPoint).Port
    $reserveUdp.Dispose()
    $group1 = '239.2.3.1'
    $group2 = '224.10.10.1'
    $quotedObserver = $observer.Replace("'", "''")
    $quotedLog = $log.Replace("'", "''")
    $command = "`$ProgressPreference = 'SilentlyContinue'; & '$quotedObserver' -InterfaceAddress 127.0.0.1 -TcpPort $tcpPort -Multicast @('${group1}:$udpPort','${group2}:$udpPort') -Minutes 0.25 -OutputFile '$quotedLog'"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-OutputFormat', 'Text', '-InputFormat', 'Text', '-EncodedCommand', $encoded) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [void]$process.Handle
    Wait-For { @(Read-Rows $log).Count -ge 3 } 'Listeners did not become ready'

    $fixture = [Text.Encoding]::ASCII.GetBytes('distributak-fence-fixture-v1')
    $half = [int][Math]::Floor($fixture.Length / 2)
    [byte[]]$first = $fixture[0..($half - 1)]
    [byte[]]$second = $fixture[$half..($fixture.Length - 1)]
    $a = New-LocalClient $tcpPort
    $b = New-LocalClient $tcpPort
    $c = New-LocalClient $tcpPort
    Send-Bytes $a $first
    Send-Bytes $b $second
    Send-Bytes $c ([Text.Encoding]::ASCII.GetBytes('PRIVATE_TEST_CONTENT_NO_MATCH'))
    Wait-For { @((Read-Rows $log) | Where-Object { $_.Port -like 'TCP/*' -and [long]$_.Packets -ge 3 }).Count -gt 0 } 'First TCP pieces were not read'
    Assert-True (@((Read-Rows $log) | Where-Object { [long]$_.FixtureHits -gt 0 }).Count -eq 0) 'Negative input or another connection completed a UID'
    Send-Bytes $a $second
    Wait-For { @((Read-Rows $log) | Where-Object { $_.Port -like 'TCP/*' -and [long]$_.FixtureHits -eq 1 }).Count -gt 0 } 'Split UID was not counted once'
    Write-Output 'PASS TCP split UID: 1; negative input and separate connections: 0'

    # 返事を1バイトも受けないことを全接続で確認（FINはデータとして数えない）。
    foreach ($client in $clients) {
        $client.ReceiveTimeout = 300
        $reply = New-Object byte[] 1
        $received = 0
        try { $received = $client.GetStream().Read($reply, 0, 1) }
        catch [IO.IOException] {
            $inner = $_.Exception.InnerException
            Assert-True ($inner -is [Net.Sockets.SocketException] -and $inner.SocketErrorCode -eq [Net.Sockets.SocketError]::TimedOut) 'TCP read failed for a reason other than no response'
        }
        Assert-True ($received -eq 0) 'Observer wrote TCP response data'
    }
    Write-Output 'PASS receive-only TCP: response bytes 0 on all connections'

    # TTL 0 と loopback の送信インタフェースを固定。家のLANへ送信しない。
    $sender = New-Object Net.Sockets.UdpClient
    $sender.Client.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Loopback, 0)))
    $sender.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastInterface, [Net.IPAddress]::Loopback.GetAddressBytes())
    $sender.MulticastLoopback = $true
    $sender.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastTimeToLive, 0)
    Assert-True ([int]$sender.Client.GetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastTimeToLive) -eq 0) 'Multicast TTL must stay zero'
    foreach ($group in @($group1, $group2)) {
        $destination = New-Object Net.IPEndPoint([Net.IPAddress]::Parse($group), $udpPort)
        [void]$sender.Send($fixture, $fixture.Length, $destination)
    }
    # UDPでは、別パケットの末尾と先頭をつながない。
    $destination = New-Object Net.IPEndPoint([Net.IPAddress]::Parse($group1), $udpPort)
    [void]$sender.Send($first, $first.Length, $destination)
    [void]$sender.Send($second, $second.Length, $destination)
    # 同じUDPポートあてのユニキャストは、指定したマルチキャストの件数に含めない。
    $unicast = New-Object Net.IPEndPoint([Net.IPAddress]::Loopback, $udpPort)
    [void]$sender.Send($fixture, $fixture.Length, $unicast)
    $sender.Client.ReceiveTimeout = 300
    $remote = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
    try {
        $reply = $sender.Receive([ref]$remote)
        throw 'Observer wrote UDP response data'
    } catch [Net.Sockets.SocketException] {
        Assert-True ($_.Exception.SocketErrorCode -eq [Net.Sockets.SocketError]::TimedOut) 'UDP read failed for a reason other than no response'
    }
    Write-Output 'PASS receive-only UDP: response datagrams 0'
    foreach ($client in $clients) { $client.Dispose() }
    $clients.Clear()
    Assert-True ($process.WaitForExit(20000)) 'Observer did not stop at Minutes'
    $process.Refresh()
    Assert-True ($process.ExitCode -eq 0) 'Observer exit code is not zero'
    Assert-True ((Get-Item -LiteralPath $stderr).Length -eq 0) 'Observer wrote unexpected error output'
    $rows = @(Read-Rows $log)
    $summary = @($rows | Where-Object { $_.Port -eq 'ALL' })
    Assert-True ($summary.Count -eq 1) 'Final total is missing'
    $tcp = @($rows | Where-Object { $_.Port -like 'TCP/*' })[-1]
    Assert-True ([long]$tcp.Connections -eq 3 -and [long]$tcp.FixtureHits -eq 1) 'TCP final counts differ'
    $udpHits = 0L
    foreach ($group in @($group1, $group2)) {
        $udp = @($rows | Where-Object { $_.Port -eq "UDP/${group}:$udpPort" })[-1]
        if ([long]$udp.Packets -gt 0) {
            Assert-True ([long]$udp.FixtureHits -eq 1) 'Multicast hits differ (or datagrams were joined)'
            $udpHits += [long]$udp.FixtureHits
        }
    }
    if ($udpHits -eq 2) { Write-Output 'PASS both multicast groups: 1 hit each; split UDP packets: 0' }
    else { Write-Output 'ENV multicast loopback did not deliver on every group; TCP gates passed' }
    Assert-True ([long]$summary[0].FixtureHits -eq (1 + $udpHits) -and $summary[0].Result -eq '不合格') 'Final total or failure verdict differs'
    $allowed = 'Time', 'Port', 'SourceIP', 'Connections', 'Packets', 'Bytes', 'FixtureHits', 'Result'
    Assert-True (@($rows[0].PSObject.Properties.Name | Where-Object { $_ -notin $allowed }).Count -eq 0) 'Unexpected output field'
    foreach ($path in @($log, $stdout, $stderr)) {
        $text = [IO.File]::ReadAllText($path)
        Assert-True (-not $text.Contains([Text.Encoding]::ASCII.GetString($fixture)) -and -not $text.Contains('PRIVATE_TEST_CONTENT_NO_MATCH')) 'Payload leaked to output'
    }
    Write-Output 'PASS Minutes cleanup, summaries, destination filtering, and output fields (no received content)'

    # Ctrl+Cと同じPowerShellパイプライン停止でfinallyがまとめと片付けを行うことを確かめる。
    $negativeLog = Join-Path $OutputDirectory 'cancel-zero.csv'
    if (Test-Path -LiteralPath $negativeLog) { Remove-Item -LiteralPath $negativeLog }
    $pipeline = [PowerShell]::Create()
    [void]$pipeline.AddCommand($observer).AddParameter('InterfaceAddress', '127.0.0.1').AddParameter('TcpPort', $tcpPort).AddParameter('Multicast', [string[]]@()).AddParameter('Uid', 'ABABA').AddParameter('Minutes', 1).AddParameter('OutputFile', $negativeLog)
    $async = $pipeline.BeginInvoke()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (@(Read-Rows $negativeLog).Count -eq 0 -and $timer.Elapsed.TotalSeconds -lt 8 -and -not $async.IsCompleted) { Start-Sleep -Milliseconds 30 }
    Assert-True (@(Read-Rows $negativeLog).Count -eq 1) 'Cancellation observer did not start with UDP disabled'
    $client = New-LocalClient $tcpPort
    Send-Bytes $client ([Text.Encoding]::ASCII.GetBytes('PRIVATE_TEST_CONTENT_NO_MATCH'))
    $timer.Restart()
    while (@((Read-Rows $negativeLog) | Where-Object { [long]$_.Packets -gt 0 }).Count -eq 0 -and $timer.Elapsed.TotalSeconds -lt 4) { Start-Sleep -Milliseconds 30 }
    Assert-True (@((Read-Rows $negativeLog) | Where-Object { [long]$_.Packets -gt 0 }).Count -gt 0) 'Cancellation negative input was not read'
    $pipeline.Stop()
    try { [void]$pipeline.EndInvoke($async) } catch [Management.Automation.PipelineStoppedException] { }
    Assert-True ($pipeline.Streams.Error.Count -eq 0) 'Cancellation emitted a runtime error'
    $negativeRows = @(Read-Rows $negativeLog)
    $negativeSummary = @($negativeRows | Where-Object { $_.Port -eq 'ALL' })
    Assert-True ($negativeSummary.Count -eq 1 -and [long]$negativeSummary[0].FixtureHits -eq 0 -and $negativeSummary[0].Result -eq '見えなかった') 'Cancellation lost the zero-hit summary'
    $client.Dispose()
    $clients.Clear()
    $reserve = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $tcpPort)
    $reserve.Start()
    $reserve.Stop()
    Write-Output 'PASS pipeline cancellation cleanup and zero-hit summary; UDP disabled; custom ASCII UID'

    $helpText = (& $observer -Help | Out-String)
    foreach ($term in @('InterfaceAddress', 'TcpPort', 'Multicast', 'Uid', 'Minutes', 'OutputFile', 'New-NetFirewallRule', 'Remove-NetFirewallRule', '8087', '6969', '17012')) {
        Assert-True ($helpText.Contains($term)) 'Help is missing a required option or firewall instruction'
    }
    Write-Output 'PASS Help includes usage, all options, firewall permission and removal commands'
} catch {
    # 試験で扱った中身や例外の文を表示しない。
    Write-Output ('FAIL fence observer self-test at line ' + $_.InvocationInfo.ScriptLineNumber)
    exit 1
} finally {
    foreach ($client in $clients) { $client.Dispose() }
    if ($null -ne $sender) { $sender.Dispose() }
    if ($null -ne $pipeline) { $pipeline.Dispose() }
    if ($null -ne $process) {
        if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
    }
}
