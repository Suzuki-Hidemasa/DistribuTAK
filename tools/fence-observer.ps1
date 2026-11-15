# SPDX-License-Identifier: GPL-3.0-only
<#
柵の確かめ (i) の受信専用の口。Windows PowerShell 5.1、Windows標準の.NETとNetAdapterを使用。
使い方とファイアウォールの一時の許可・外し方は -Help を参照。
#>
[CmdletBinding()]
param(
    [string]$InterfaceAddress,
    [int]$TcpPort = 8087,
    [string[]]$Multicast = @('239.2.3.1:6969', '224.10.10.1:17012'),
    [string]$Uid = 'distributak-fence-fixture-v1',
    [double]$Minutes = 10,
    [string]$OutputFile = '.\fence-observer-counts.csv',
    [switch]$Help
)

if ($Help) {
    @'
柵の確かめの観測の口（Windows PowerShell 5.1）
例: .\fence-observer.ps1 -InterfaceAddress 192.168.1.20 -Minutes 10 -OutputFile .\counts.csv

-InterfaceAddress 参加するローカルのIPv4アドレス。TCPもこのアドレスだけで待つ。
                  省略時は、稼働中の物理Wi-Fi/有線でIPv4のゲートウェイがある候補を使う。
                  候補がない・複数ある場合は開始せず、明示指定が必要。試験は127.0.0.1。
-TcpPort          TCPの待ち受けポート。既定8087。複数の接続を受け、何も書き返さない。
-Multicast        受けるIPv4のマルチキャスト宛先の配列。指定すると既定の一覧を置き換える。
                  既定 @('239.2.3.1:6969','224.10.10.1:17012')。@() でUDPなし。
                  例 -Multicast @('239.2.3.1:6969') で2つ目を外す。
                  同じポートの複数のグループも指定できる。指定インタフェースと宛先を照合。
-Uid              探す固定のASCII uid。既定はCotPort.FIXTURE_UIDと同じ試験用の値。
                  uid自体は表示・保存しない。大文字と小文字は区別する。
-Minutes          観測する分数（正の数、小数可）。既定10。Ctrl+Cでも終了する。
-OutputFile       件数だけのUTF-8 CSV。既定 .\fence-observer-counts.csv。
                  既存のファイルは上書きしない。親フォルダは先に用意する。
-Help             この説明だけを表示する。ソケットやファイルは開かない。

画面とCSVは同じ列: Time,Port,SourceIP,Connections,Packets,Bytes,FixtureHits,Result。
TimeはUTC。PortはTCPの待ち受け先/UDPの宛先。SourceIPは送り元のIPv4だけ。
Connectionsは受け入れたTCP接続の累計（UDPは0）。PacketsはUDPのデータグラム数、
TCPではReadで取り出した塊の数であり、IP/TCPセグメント数ではない。Bytesは受信量。
FixtureHitsはuidの出現回数。TCPは接続ごとに前の塊の末尾を引き継ぎ、UDPは1パケット内だけ。
繰り返し現れたuidはそのたび数える。複数の出現がある塊もすべて数える。
各行の件数は口ごとの累計。開始時の0件、受信・接続時、終了時のまとめを出す。
終了時は各口とALLの行に結果を出す。合計1以上は「不合格」、0は「見えなかった」。
未検出で開始・継続できない場合は「観測未完了」。検出済みなら「不合格」を保つ。
異常終了のコードは1。通常終了は0（不合格も結果に記録）。
「見えなかった」は未観測という意味であり、ATAKの全経路を止めた証明にはならない。
受信した中身・他のuid・位置・名前は文字列に変換せず、表示も保存もしない。
返事のアプリケーションデータは送らない。OSのTCP制御やマルチキャスト参加は発生する。

家のLANの中だけで使用。ATAKの平文TAKサーバーの宛先はこのPCのIPv4とTCPポート。
スクリプトはファイアウォールやATAKの設定を変更しない。
必要なら利用者が管理者のPowerShellで、家のネットワークがPrivateであることを確かめて実行:
New-NetFirewallRule -Name DistribuTAK-Fence-TCP -DisplayName DistribuTAK-Fence-TCP -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8087 -RemoteAddress LocalSubnet -Profile Private
New-NetFirewallRule -Name DistribuTAK-Fence-UDP -DisplayName DistribuTAK-Fence-UDP -Direction Inbound -Action Allow -Protocol UDP -LocalPort 6969,17012 -RemoteAddress LocalSubnet -Profile Private
ポートを変えた場合は、上のLocalPortも合わせる。試験のあとはATAKのサーバー登録を外し、
PCの一時の許可も外す（自分で追加した上の名前の規則だけを対象にする）:
Remove-NetFirewallRule -Name DistribuTAK-Fence-TCP,DistribuTAK-Fence-UDP

WSLのUNCパスで実行ポリシーにより止まる場合は、その起動だけに指定できる:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File <このスクリプトのWindowsパス> <引数>
永続の実行ポリシーは変更しない。
'@
    return
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# 受信データは保持しない。KMPの一致した長さだけがTCPの塊の境界をまたぐ。
class FenceUidMatcher {
    [byte[]]$Pattern
    [int[]]$Failure
    [int]$Matched
    FenceUidMatcher([byte[]]$pattern) {
        $this.Pattern = $pattern
        $this.Failure = New-Object int[] $pattern.Length
        $prefix = 0
        for ($i = 1; $i -lt $pattern.Length; $i++) {
            while ($prefix -gt 0 -and $pattern[$i] -ne $pattern[$prefix]) { $prefix = $this.Failure[$prefix - 1] }
            if ($pattern[$i] -eq $pattern[$prefix]) { $prefix++ }
            $this.Failure[$i] = $prefix
        }
    }
    [long] Consume([byte[]]$buffer, [int]$length, [bool]$reset) {
        if ($reset) { $this.Matched = 0 }
        $hits = 0L
        for ($i = 0; $i -lt $length; $i++) {
            while ($this.Matched -gt 0 -and $buffer[$i] -ne $this.Pattern[$this.Matched]) {
                $this.Matched = $this.Failure[$this.Matched - 1]
            }
            if ($buffer[$i] -eq $this.Pattern[$this.Matched]) { $this.Matched++ }
            if ($this.Matched -eq $this.Pattern.Length) {
                $hits++
                $this.Matched = $this.Failure[$this.Matched - 1]
            }
        }
        return $hits
    }
}

function Get-ObserverInterface {
    $candidates = New-Object 'System.Collections.Generic.List[object]'
    $physical = @()
    if ([string]::IsNullOrEmpty($InterfaceAddress)) {
        # Windows標準のNetAdapter。追加のモジュールの導入や設定変更はしない。
        $physical = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty ifIndex)
    }
    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) { continue }
        $properties = $nic.GetIPProperties()
        if (-not $nic.Supports([Net.NetworkInformation.NetworkInterfaceComponent]::IPv4)) { continue }
        $index = $properties.GetIPv4Properties().Index
        if ([string]::IsNullOrEmpty($InterfaceAddress)) {
            if ($index -notin $physical -or @($properties.GatewayAddresses | Where-Object {
                $_.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and -not $_.Address.Equals([Net.IPAddress]::Any)
            }).Count -eq 0) { continue }
        }
        foreach ($unicast in $properties.UnicastAddresses) {
            $address = $unicast.Address
            if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
            if (-not [string]::IsNullOrEmpty($InterfaceAddress) -and $address.ToString() -ne $InterfaceAddress) { continue }
            $candidates.Add([pscustomobject]@{ Address = $address; Index = $index })
        }
    }
    if ($candidates.Count -ne 1) { throw 'Interface selection failed' }
    return $candidates[0]
}
function New-Counter([string]$Port) {
    return [pscustomobject]@{ Port = $Port; Connections = 0L; Packets = 0L; Bytes = 0L; FixtureHits = 0L }
}
function Write-Counts($Counter, [string]$SourceIP = '', [string]$Result = '') {
    # 全項目は自分で作った宛先・数値・固定の結果。受信データや例外は使わない。
    $line = [string]::Join(',', @([DateTime]::UtcNow.ToString('o'), $Counter.Port, $SourceIP,
        $Counter.Connections.ToString(), $Counter.Packets.ToString(), $Counter.Bytes.ToString(),
        $Counter.FixtureHits.ToString(), $Result))
    if ($null -ne $script:writer) { $script:writer.WriteLine($line); $script:writer.Flush() }
    [Console]::WriteLine($line)
}

$writer = $null
$listener = $null
$connections = New-Object 'System.Collections.Generic.List[object]'
$udpSockets = New-Object 'System.Collections.Generic.List[object]'
$counters = [ordered]@{}
$buffer = New-Object byte[] 65535
$started = $false
$failed = $false
$oldEncoding = [Console]::OutputEncoding
try {
    [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
    if ($TcpPort -lt 1 -or $TcpPort -gt 65535 -or $Minutes -le 0 -or [double]::IsNaN($Minutes) -or [double]::IsInfinity($Minutes)) { throw 'Invalid option' }
    if ([string]::IsNullOrEmpty($Uid)) { throw 'Invalid fixture' }
    foreach ($character in $Uid.ToCharArray()) { if ([int]$character -gt 127 -or [int]$character -eq 0) { throw 'Invalid fixture' } }
    $pattern = [Text.Encoding]::ASCII.GetBytes($Uid)
    $network = Get-ObserverInterface
    $groups = [ordered]@{}
    foreach ($specification in $Multicast) {
        if ($specification -notmatch '^([0-9.]+):([0-9]{1,5})$') { throw 'Invalid multicast' }
        $address = [Net.IPAddress]::Parse($Matches[1])
        $port = [int]$Matches[2]
        if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.GetAddressBytes()[0] -lt 224 -or $address.GetAddressBytes()[0] -gt 239 -or $port -lt 1 -or $port -gt 65535) { throw 'Invalid multicast' }
        $key = "UDP/$($address.ToString()):$port"
        if (-not $groups.Contains($key)) { $groups[$key] = [pscustomobject]@{ Address = $address; Port = $port } }
    }
    $logPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    $file = [IO.File]::Open($logPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $writer = New-Object IO.StreamWriter($file, (New-Object Text.UTF8Encoding($false))) }
    catch { $file.Dispose(); throw }
    $header = 'Time,Port,SourceIP,Connections,Packets,Bytes,FixtureHits,Result'
    $writer.WriteLine($header)
    [Console]::WriteLine($header)
    $tcpKey = "TCP/$($network.Address.ToString()):$TcpPort"
    $counters[$tcpKey] = New-Counter $tcpKey
    $listener = New-Object Net.Sockets.TcpListener($network.Address, $TcpPort)
    $listener.Start()
    foreach ($group in $groups.Values) {
        $socket = @($udpSockets | Where-Object { $_.Port -eq $group.Port })
        if ($socket.Count -eq 0) {
            $udp = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
            # 開いた直後からfinallyの片付けの対象にする。
            $entry = [pscustomobject]@{ Socket = $udp; Port = $group.Port }
            $udpSockets.Add($entry)
            $udp.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket, [Net.Sockets.SocketOptionName]::ReuseAddress, $true)
            $udp.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::PacketInformation, $true)
            $udp.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Any, $group.Port)))
            $udp.Blocking = $false
        } else { $udp = $socket[0].Socket }
        $membership = New-Object Net.Sockets.MulticastOption($group.Address, $network.Address)
        $udp.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::AddMembership, $membership)
        $key = "UDP/$($group.Address.ToString()):$($group.Port)"
        $counters[$key] = New-Counter $key
    }
    $udpMatcher = [FenceUidMatcher]::new($pattern)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $started = $true
    foreach ($counter in $counters.Values) { Write-Counts $counter }
    while ($timer.Elapsed.TotalMinutes -lt $Minutes) {
        # 1周で1接続・各口の1塊ずつを処理し、時間切れとCtrl+Cを確認する。
        if ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            try {
                $client.Client.Blocking = $false
                $source = ([Net.IPEndPoint]$client.Client.RemoteEndPoint).Address.ToString()
                $connection = [pscustomobject]@{ Client = $client; SourceIP = $source; Matcher = [FenceUidMatcher]::new($pattern) }
                $connections.Add($connection)
            } catch { $client.Dispose(); throw }
            $counters[$tcpKey].Connections++
            Write-Counts $counters[$tcpKey] $source
        }
        foreach ($connection in $connections.ToArray()) {
            $socket = $connection.Client.Client
            if (-not $socket.Poll(0, [Net.Sockets.SelectMode]::SelectRead)) { continue }
            $length = 0
            try { $length = $socket.Receive($buffer) }
            catch [Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -notin @([Net.Sockets.SocketError]::ConnectionReset, [Net.Sockets.SocketError]::ConnectionAborted)) { throw }
            }
            if ($length -eq 0) {
                $connection.Client.Dispose()
                [void]$connections.Remove($connection)
                continue
            }
            try {
                $counter = $counters[$tcpKey]
                $counter.Packets++
                $counter.Bytes += $length
                $counter.FixtureHits += $connection.Matcher.Consume($buffer, $length, $false)
                Write-Counts $counter $connection.SourceIP
            } finally { [Array]::Clear($buffer, 0, $buffer.Length) }
        }
        foreach ($entry in $udpSockets) {
            if (-not $entry.Socket.Poll(0, [Net.Sockets.SelectMode]::SelectRead)) { continue }
            $remote = [Net.EndPoint](New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0))
            $flags = [Net.Sockets.SocketFlags]::None
            $info = New-Object Net.Sockets.IPPacketInformation
            try {
                $length = $entry.Socket.ReceiveMessageFrom($buffer, 0, $buffer.Length, [ref]$flags, [ref]$remote, [ref]$info)
                $key = "UDP/$($info.Address.ToString()):$($entry.Port)"
                if ($info.Interface -ne $network.Index -or -not $groups.Contains($key)) { continue }
                $counter = $counters[$key]
                $counter.Packets++
                $counter.Bytes += $length
                $counter.FixtureHits += $udpMatcher.Consume($buffer, $length, $true)
                Write-Counts $counter ([Net.IPEndPoint]$remote).Address.ToString()
            } finally { [Array]::Clear($buffer, 0, $buffer.Length) }
        }
        Start-Sleep -Milliseconds 10
    }
} catch {
    # 例外の文・オブジェクトは、引数や受信した値を含む可能性があるので出さない。
    $failed = $true
} finally {
    if ($null -ne $listener) { $listener.Stop() }
    foreach ($connection in $connections) { $connection.Client.Dispose() }
    foreach ($entry in $udpSockets) { $entry.Socket.Dispose() }
    [Array]::Clear($buffer, 0, $buffer.Length)
    # Ctrl+Cでもfinallyを通る。Console/StreamWriterを直接使い、停止したパイプへは出さない。
    $total = New-Counter 'ALL'
    foreach ($counter in $counters.Values) {
        $total.Connections += $counter.Connections
        $total.Packets += $counter.Packets
        $total.Bytes += $counter.Bytes
        $total.FixtureHits += $counter.FixtureHits
    }
    $result = '見えなかった'
    if ($total.FixtureHits -gt 0) { $result = '不合格' }
    elseif (-not $started -or $failed) { $result = '観測未完了' }
    try {
        foreach ($counter in $counters.Values) { Write-Counts $counter '' $result }
        Write-Counts $total '' $result
    } catch {
        $failed = $true
        if ($total.FixtureHits -gt 0) { $result = '不合格' } else { $result = '観測未完了' }
        [Console]::WriteLine([string]::Join(',', @([DateTime]::UtcNow.ToString('o'), 'ALL', '',
            $total.Connections.ToString(), $total.Packets.ToString(), $total.Bytes.ToString(),
            $total.FixtureHits.ToString(), $result)))
    } finally {
        if ($null -ne $writer) { $writer.Dispose() }
        [Console]::OutputEncoding = $oldEncoding
    }
}
if ($failed) { exit 1 }
