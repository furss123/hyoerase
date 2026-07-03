#Requires -Version 5.1
<#
  HyoErase (지우개) — 학교/공용 PC 초강력 정리·관리 도구
  © 2026 HyoT. All rights reserved. | hyot.dev

  "강력하되 안전하게" — 무엇을 지우는지 명확하고, 위험한 건 절대 자동 선택하지 않습니다.

  ● 강력 프로그램 제거: 실행 중 프로세스 종료 → 정식 제거 → 잔여 폴더·바로가기 삭제
  ● 스토어(UWP) 게임·블로트웨어 제거 (+재설치 방지 프로비저닝 제거)
  ● 딥 시스템 청소: Windows Update 캐시·전송최적화·WER·메모리덤프·썸네일·
     모든 사용자 임시폴더·모든 드라이브 휴지통·DNS 캐시·폰트캐시·Prefetch
  ● 수업 초기화: 최근/실행 기록·클립보드·(옵션)브라우저 로그인/방문기록·다운로드
  ● 감사 로그 파일 저장

  절대 건드리지 않음(보호): 오피스(한컴/MS)·문서·그림 파일·드라이버·백신·
     브라우저·런타임·은행/공인인증 보안모듈.

  STA + 관리자 권한 필요:  HyoErase 실행.cmd 를 더블클릭하세요(권한 자동 요청).
  -Auto 스위치로 실행하면 창 없이 기본 항목만 조용히 정리합니다(작업 스케줄러용).
  -Watchdog 스위치로 실행하면 게임/VPN 프로세스를 한 번 검사해 즉시 종료하고
  끝냅니다(실시간 감시용 반복 작업 스케줄러가 짧은 주기로 호출).
#>
param([switch]$Auto, [switch]$Watchdog)

# ------------------------------------------------------------------
#  관리자 권한 자동 승격
# ------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin -and -not $env:HYOERASE_NOELEV) {
  try {
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    if ($Auto) { $relaunch += '-Auto' }
    if ($Watchdog) { $relaunch += '-Watchdog' }
    Start-Process powershell.exe -Verb RunAs -ErrorAction Stop -ArgumentList $relaunch
    return
  } catch { }
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$AppVersion = '1.4.0'
$FooterText = "HyoErase (지우개) v$AppVersion | © 2026 HyoT. All rights reserved. | hyot.dev"
$script:log = New-Object System.Collections.Generic.List[string]

# ------------------------------------------------------------------
#  분류 키워드
# ------------------------------------------------------------------
$PROTECT_KW = @(
  'office','microsoft 365','한컴','한글','hancom','hwp','hnc','한셀','한쇼',
  'excel','word','powerpoint','outlook','onenote','access','publisher','visio',
  'windows','microsoft visual c++','.net','directx','redistributable','runtime',
  'driver','nvidia','geforce','intel','amd','radeon','realtek','qualcomm','synaptics',
  'defender','antivirus','anti-virus','v3','ahnlab','안랩','알약','alyac','estsoft',
  'malwarebytes','sophos','trend micro','kaspersky','norton','mcafee','bitdefender',
  'avast','avg','avira','windows security',
  'adobe acrobat','adobe reader','acrobat','adobe air',
  'java','python','node.js','git','powershell','wsl','visual studio','ssms',
  'microsoft edge','google chrome','naver whale','whale','mozilla firefox','opera',
  'microsoft teams','zoom','webex','onedrive','dropbox','google drive',
  'hp ','canon','epson','samsung printer','brother','kies','printer','스캔',
  'notepad++','7-zip','반디집','bandizip','알집','alzip','winrar','winzip',
  '곰플레이어','gom','팟플레이어','potplayer','vlc','pdf','뷰어','viewer','한글뷰어',
  'windows sdk','windows app','microsoft update','microsoft store','xbox game bar',
  'realtek audio','nahimic','armoury','myasus','lenovo','dell','hp support',
  'inisafe','crossex','crossweb','markany','anysign','keysharp','veraport','magicline',
  'nprotect','wizvera','touchen','xecure','initech','raonsecure','delfino','인증','공인'
)
$GAME_KW = @(
  'steam','epic games','epicgames','riot','valorant','league of legends','battle.net',
  'blizzard','origin','ea app','ea desktop','ea games','electronic arts','ubisoft','uplay',
  'gog galaxy','gog.com','rockstar games','playnite',
  'roblox','minecraft','mojang','among us','fortnite','apex','overwatch','hearthstone',
  'nexon','넥슨','메이플','maplestory','서든','sudden attack','던전앤파이터','dungeon fighter',
  '카트라이더','kartrider','피망','pmang','netmarble','넷마블','garena','wargaming','world of tanks',
  'mihoyo','hoyoverse','genshin','honkai','krafton','pubg','배틀그라운드','lost ark','로스트아크',
  'crossfire','크로스파이어','smilegate','스마일게이트','wemade','위메이드','com2us','컴투스',
  'kakao games','kakaogames','카카오게임','tera','테라','gameforge','wargame','game launcher',
  'geforce now'
)
$VPN_KW = @(
  'vpn','nordvpn','expressvpn','surfshark','proton vpn','protonvpn','windscribe','tunnelbear',
  'hotspot shield','cyberghost','hola','betternet','psiphon','openvpn','wireguard',
  'cloudflare warp','cloudflare one','lantern','urban vpn','touch vpn','hide.me','zenmate','browsec',
  'speedify','mullvad','ivpn','privado','1clickvpn','free vpn','freevpn','turbo vpn','x-vpn'
)
# 스토어(UWP) 제거 대상 — 확실한 게임·엔터테인먼트 블로트웨어만 (정밀 매칭)
# 주의: 'xbox'/'gaming' 같은 넓은 키워드는 쓰지 않음 — 컨트롤러 지원(XboxDevices)·
# 로그인(XboxIdentityProvider)·오버레이(GameOverlay/TCUI) 등 다른 프로그램이 의존하는
# 시스템 프레임워크 구성요소까지 걸려서 지우면 관련 기능이 깨질 수 있음.
$UWP_REMOVE = @(
  'king.com','candycrush','bubblewitch','marchofempires','microsoft.microsoftsolitairecollection',
  'microsoft.microsoftmahjong','microsoft.microsoftsudoku','microsoft.gamingapp',
  'zunemusic','zunevideo','disney','netflix','spotify','tiktok','facebook','instagram','twitter',
  'clipchamp','3dviewer','mixedreality','skypeapp','yourphone','phonelink','bingnews','bingweather',
  'microsoft.people','wallet','duolingo','roblox','asphalt','hiddencity','cookingfever'
)
# 위 목록에 걸려도 절대 제거하지 않는 시스템 프레임워크(다른 앱이 의존)
$UWP_PROTECT = @(
  'xboxidentityprovider','xboxgameoverlay','xboxgamingoverlay','xbox.tcui','xboxgamecallableui',
  'xboxdevices','xboxspeechtotextoverlay','gamingservices','xboxgamebar'
)
# 워치독(실시간 감시)이 즉시 종료할 프로세스 이름(.exe 제외) — 확실한 게임/VPN 클라이언트만
$WATCHDOG_PROCESS_NAMES = @(
  'steam', 'steamwebhelper', 'epicgameslauncher', 'riotclientservices', 'riotclientservicesux',
  'leagueclient', 'leagueclientux', 'battle.net', 'javaw', 'minecraftlauncher', 'robloxplayerbeta',
  'kartrider', 'maplestory', 'dnf', 'sudden attack', 'crossfire',
  'nordvpn', 'nordvpn-service', 'expressvpn', 'surfshark', 'surfshark-service',
  'protonvpn', 'protonvpn-service', 'windscribe', 'tunnelbear', 'cyberghost8', 'hotspotshield',
  'openvpn-gui', 'openvpn', 'wireguard', 'psiphon3', 'hola'
)
# 방화벽 차단 대상 — 흔히 쓰이는 VPN 프로토콜/포트(아웃바운드)
$FIREWALL_VPN_RULES = @(
  @{ Name = 'OpenVPN-UDP'; Protocol = 'UDP'; Port = 1194 }
  @{ Name = 'OpenVPN-TCP'; Protocol = 'TCP'; Port = 1194 }
  @{ Name = 'WireGuard';   Protocol = 'UDP'; Port = 51820 }
  @{ Name = 'IKEv2-500';   Protocol = 'UDP'; Port = 500 }
  @{ Name = 'IKEv2-4500';  Protocol = 'UDP'; Port = 4500 }
  @{ Name = 'L2TP';        Protocol = 'UDP'; Port = 1701 }
  @{ Name = 'PPTP-Ctrl';   Protocol = 'TCP'; Port = 1723 }
  @{ Name = 'PPTP-GRE';    Protocol = '47';  Port = $null }
)
# hosts 재설치 차단 대상 — 잘 알려진 게임/VPN 배포·로그인 도메인만(정상 사이트 오차단 방지)
$HOSTS_BLOCK_DOMAINS = @(
  'store.steampowered.com','steamcommunity.com','steampowered.com','cdn.steamstatic.com',
  'epicgames.com','store.epicgames.com','www.epicgames.com',
  'battle.net','us.battle.net','eu.battle.net','ea.com','origin.com','www.ea.com',
  'ubisoft.com','ubisoftconnect.com','riotgames.com','na.leagueoflegends.com',
  'minecraft.net','www.minecraft.net','roblox.com','www.roblox.com',
  'nordvpn.com','www.nordvpn.com','expressvpn.com','www.expressvpn.com',
  'surfshark.com','www.surfshark.com','protonvpn.com','windscribe.com','www.windscribe.com',
  'tunnelbear.com','www.tunnelbear.com','cyberghostvpn.com','www.hotspotshield.com',
  'openvpn.net','mullvad.net','psiphon3.com','hola.org','betternet.co'
)

function Test-KwHit([string]$s, [string[]]$kws) { foreach ($k in $kws) { if ($s.Contains($k)) { return $true } } ; $false }
function Get-AppCategory($app) {
  $s = ('{0} {1}' -f $app.Name, $app.Publisher).ToLower()
  if (Test-KwHit $s $PROTECT_KW) { return 'protected' }
  if (Test-KwHit $s $VPN_KW)     { return 'vpn' }
  if (Test-KwHit $s $GAME_KW)    { return 'game' }
  'unknown'
}

# ------------------------------------------------------------------
#  설치 프로그램 (레지스트리) + 강력 제거
# ------------------------------------------------------------------
function Get-InstalledApps {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  $apps = @()
  foreach ($p in $paths) {
    Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | ForEach-Object {
      $n = $_.DisplayName
      if (-not $n) { return }
      if ($_.SystemComponent -eq 1) { return }
      if ($_.ParentKeyName)         { return }
      if ($n -match '^(KB\d{6,}|Security Update|Update for|Hotfix)') { return }
      $uq = $_.QuietUninstallString; $u = $_.UninstallString
      if (-not $u -and -not $uq) { return }
      $apps += [pscustomobject]@{
        Name = $n.Trim(); Publisher = $_.Publisher
        UninstallString = $u; QuietUninstallString = $uq
        InstallLocation = $_.InstallLocation
        Size = if ($_.EstimatedSize) { [long]$_.EstimatedSize * 1024 } else { 0 }
      }
    }
  }
  $apps | Sort-Object Name -Unique
}

function Test-SafeToDelete([string]$path) {
  if (-not $path) { return $false }
  $p = $path.TrimEnd('\')
  if ($p.Length -lt 12) { return $false }                      # 루트/짧은 경로 방지
  $guard = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
             $env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, "$env:SystemDrive\", "$env:SystemDrive\Users")
  foreach ($g in $guard) { if ($g -and ($p -ieq $g.TrimEnd('\'))) { return $false } }  # 보호 루트 자체면 금지
  if ($p -like "$env:SystemRoot\*") { return $false }          # 윈도우 폴더 하위 금지
  $true
}

function Stop-AppProcesses($app) {
  $loc = $app.InstallLocation
  if (-not $loc) { return }
  $loc = $loc.TrimEnd('\')
  if ($loc -like "$env:SystemRoot*") { return }
  try {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $pp = $_.Path
        if ($pp -and $pp.StartsWith($loc, [System.StringComparison]::OrdinalIgnoreCase)) {
          Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
      } catch { }
    }
  } catch { }
}

function Remove-Leftovers($app) {
  $loc = $app.InstallLocation
  if ($loc -and (Test-Path -LiteralPath $loc) -and (Test-SafeToDelete $loc)) {
    try { Remove-Item -LiteralPath $loc -Recurse -Force -ErrorAction SilentlyContinue } catch { }
  }
  # 시작메뉴/바탕화면 바로가기 정리
  $shortcutDirs = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
    "$env:PUBLIC\Desktop", "$env:USERPROFILE\Desktop")
  $needle = ($app.Name -replace '[^\w가-힣]', '').ToLower()
  if ($needle.Length -ge 3) {
    foreach ($d in $shortcutDirs) {
      Get-ChildItem -LiteralPath $d -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
        $bn = ($_.BaseName -replace '[^\w가-힣]', '').ToLower()
        if ($bn -and ($bn.Contains($needle) -or $needle.Contains($bn))) {
          try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch { }
        }
      }
    }
  }
}

function Get-SilentUninstall($app) {
  if ($app.QuietUninstallString) { return $app.QuietUninstallString }
  $u = $app.UninstallString
  if (-not $u) { return $null }
  if ($u -match 'msiexec' -and $u -match '\{[0-9A-Fa-f\-]+\}') { return "msiexec.exe /x $($Matches[0]) /qn /norestart" }
  $u
}

function Uninstall-App($app, [bool]$leftovers) {
  Stop-AppProcesses $app
  $cmd = Get-SilentUninstall $app
  $ok = $false; $code = $null
  if ($cmd) {
    try {
      $p = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $cmd" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
      $code = $p.ExitCode
      $ok = ($code -eq 0 -or $code -eq 3010 -or $code -eq 1605)
    } catch { }
  }
  if ($leftovers) { Remove-Leftovers $app }
  $script:log.Add(("[프로그램] {0}  ->  {1} (code={2})" -f $app.Name, ($(if($ok){'제거'}else{'실패/부분'})), $code))
  [pscustomobject]@{ Ok = $ok; Code = $code }
}

# ------------------------------------------------------------------
#  스토어(UWP) 앱
# ------------------------------------------------------------------
function Get-UwpApps {
  $pkgs = $null
  try { $pkgs = Get-AppxPackage -AllUsers -ErrorAction Stop } catch { try { $pkgs = Get-AppxPackage -ErrorAction SilentlyContinue } catch { $pkgs = @() } }
  $out = @()
  foreach ($p in $pkgs) {
    if ($p.IsFramework) { continue }
    $nl = $p.Name.ToLower()
    if (Test-KwHit $nl $UWP_PROTECT) { continue }
    if (-not (Test-KwHit $nl $UWP_REMOVE)) { continue }
    $out += [pscustomobject]@{ Name = $p.Name; Full = $p.PackageFullName }
  }
  $out | Sort-Object Name -Unique
}

function Remove-Uwp($u) {
  $ok = $false
  try { Remove-AppxPackage -Package $u.Full -AllUsers -ErrorAction Stop; $ok = $true }
  catch { try { Remove-AppxPackage -Package $u.Full -ErrorAction Stop; $ok = $true } catch { } }
  # 새 사용자 계정에 재설치되지 않도록 프로비저닝 제거
  try {
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -eq $u.Name } |
      ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null }
  } catch { }
  $script:log.Add(("[스토어앱] {0}  ->  {1}" -f $u.Name, ($(if($ok){'제거'}else{'실패'}))))
  $ok
}

# ------------------------------------------------------------------
#  정리 액션(레지스트리/명령) 스크립트블록
# ------------------------------------------------------------------
$Act_DnsFlush = { ipconfig /flushdns | Out-Null }
$Act_HostsBlock = { Set-HostsBlock }
$Act_InstallLock = { Set-InstallLockdown }
$Act_AutorunLock = { Set-AutorunBlock }
$Act_ExecWhitelist = { Set-ExecWhitelist }
$Act_FirewallVpn = { Set-FirewallVpnBlock }
$Act_AdminToolsLock = { Set-AdminToolsLock }
$Act_ScriptExecBlock = { Set-ScriptExecBlock }
$Act_HashBlock = { Set-HashBlock }
$Act_Clipboard = { try { Set-Clipboard -Value ' ' -ErrorAction SilentlyContinue } catch { } }
$Act_Mru = {
  $keys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery')
  foreach ($k in $keys) { Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue }
}
$Act_EventLogs = {
  try { wevtutil el | ForEach-Object { wevtutil cl "$_" 2>$null } } catch { }
}
$Act_BrowserData = {
  $profiles = @()
  foreach ($pat in @("$env:LOCALAPPDATA\Google\Chrome\User Data\*",
                     "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*",
                     "$env:LOCALAPPDATA\Naver\Naver Whale\User Data\*")) {
    $profiles += (Resolve-Path -Path $pat -ErrorAction SilentlyContinue | ForEach-Object { $_.Path })
  }
  $targets = @('History', 'Cookies', 'Web Data', 'Login Data', 'Network\Cookies', 'Sessions',
               'Current Session', 'Current Tabs', 'Last Session', 'Last Tabs', 'Visited Links', 'Shortcuts')
  foreach ($pr in $profiles) {
    if ($pr -notmatch '\\User Data\\') { continue }
    foreach ($t in $targets) { Remove-Item -LiteralPath (Join-Path $pr $t) -Recurse -Force -ErrorAction SilentlyContinue }
  }
}

# ------------------------------------------------------------------
#  재설치 차단 (hosts 파일) — 되돌리기 가능(마커로 구간 관리)
# ------------------------------------------------------------------
$HOSTS_MARK_BEGIN = '# ===== HyoErase 차단 시작 (자동 생성 - 지우지 마세요) ====='
$HOSTS_MARK_END   = '# ===== HyoErase 차단 끝 ====='
function Get-HostsPath { "$env:SystemRoot\System32\drivers\etc\hosts" }
function Remove-HostsBlock {
  $path = Get-HostsPath
  if (-not (Test-Path -LiteralPath $path)) { return }
  $lines = Get-Content -LiteralPath $path -ErrorAction SilentlyContinue
  if (-not $lines) { return }
  $out = New-Object System.Collections.Generic.List[string]
  $skip = $false
  foreach ($l in $lines) {
    if ($l.Trim() -eq $HOSTS_MARK_BEGIN) { $skip = $true; continue }
    if ($l.Trim() -eq $HOSTS_MARK_END)   { $skip = $false; continue }
    if (-not $skip) { $out.Add($l) }
  }
  try { Set-Content -LiteralPath $path -Value $out -Force -ErrorAction Stop } catch { }
}
function Set-HostsBlock {
  Remove-HostsBlock
  $path = Get-HostsPath
  $block = @($HOSTS_MARK_BEGIN) + ($HOSTS_BLOCK_DOMAINS | ForEach-Object { "0.0.0.0 $_" }) + @($HOSTS_MARK_END)
  try { Add-Content -LiteralPath $path -Value $block -Force -ErrorAction Stop } catch { }
  $script:log.Add("[hosts 차단] $($HOSTS_BLOCK_DOMAINS.Count)개 도메인 차단 적용")
}
function Test-HostsBlockActive {
  $path = Get-HostsPath
  if (-not (Test-Path -LiteralPath $path)) { return $false }
  $c = Get-Content -LiteralPath $path -ErrorAction SilentlyContinue
  [bool]($c -and ($c -contains $HOSTS_MARK_BEGIN))
}

# ------------------------------------------------------------------
#  설치 잠금 (레지스트리 정책) — 되돌리기 가능
# ------------------------------------------------------------------
$REG_STORE   = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
$REG_APPX    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx'
$REG_EXPLORER = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

function Set-InstallLockdown {
  New-Item -Path $REG_STORE -Force -ErrorAction SilentlyContinue | Out-Null
  Set-ItemProperty -Path $REG_STORE -Name 'RemoveWindowsStore' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
  New-Item -Path $REG_APPX -Force -ErrorAction SilentlyContinue | Out-Null
  Set-ItemProperty -Path $REG_APPX -Name 'BlockNonAdminUserInstall' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
  $script:log.Add('[설치 잠금] Microsoft Store 비활성화 + 표준사용자 앱 설치 차단 적용')
}
function Remove-InstallLockdown {
  Remove-ItemProperty -Path $REG_STORE -Name 'RemoveWindowsStore' -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path $REG_APPX -Name 'BlockNonAdminUserInstall' -ErrorAction SilentlyContinue
  $script:log.Add('[설치 잠금] 해제 완료')
}
function Test-InstallLockdownActive {
  try { (Get-ItemProperty -Path $REG_STORE -Name 'RemoveWindowsStore' -ErrorAction Stop).RemoveWindowsStore -eq 1 } catch { $false }
}
function Set-AutorunBlock {
  New-Item -Path $REG_EXPLORER -Force -ErrorAction SilentlyContinue | Out-Null
  Set-ItemProperty -Path $REG_EXPLORER -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -Force -ErrorAction SilentlyContinue
  $script:log.Add('[자동실행 차단] USB 자동실행(Autorun) 비활성화')
}
function Remove-AutorunBlock {
  Remove-ItemProperty -Path $REG_EXPLORER -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------
#  방화벽 기반 VPN 프로토콜 차단 — 되돌리기 가능(규칙 그룹으로 관리)
#  hosts 차단(도메인)보다 견고함: IP가 바뀌어도 프로토콜/포트 자체를 막음.
# ------------------------------------------------------------------
$FW_GROUP = 'HyoErase-VPNBlock'
function Set-FirewallVpnBlock {
  Remove-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue
  foreach ($r in $FIREWALL_VPN_RULES) {
    try {
      if ($r.Port) {
        New-NetFirewallRule -Group $FW_GROUP -DisplayName "HyoErase VPN 차단 - $($r.Name)" `
          -Direction Outbound -Action Block -Protocol $r.Protocol -RemotePort $r.Port `
          -Profile Any -ErrorAction Stop | Out-Null
      } else {
        New-NetFirewallRule -Group $FW_GROUP -DisplayName "HyoErase VPN 차단 - $($r.Name)" `
          -Direction Outbound -Action Block -Protocol $r.Protocol `
          -Profile Any -ErrorAction Stop | Out-Null
      }
    } catch { }
  }
  $script:log.Add('[방화벽 VPN 차단] OpenVPN·WireGuard·IKEv2·L2TP·PPTP 프로토콜 아웃바운드 차단 적용')
}
function Remove-FirewallVpnBlock {
  Remove-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue
  $script:log.Add('[방화벽 VPN 차단] 해제 완료')
}
function Test-FirewallVpnBlockActive {
  [bool](Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue)
}

# ------------------------------------------------------------------
#  레지스트리 편집기·작업관리자 접근 차단  ⚠⚠
#  주의: 이 두 정책은 HKLM에 적용 시 관리자 계정도 예외 없이 함께 막힙니다.
#  잠그면 regedit/작업관리자로는 되돌릴 수 없으니, HyoErase를 다시 실행해
#  "🔓 모든 잠금 해제"로만 원복하세요(이 앱 자체는 이 정책의 영향을 받지 않음).
# ------------------------------------------------------------------
$REG_SYSPOLICY = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
function Set-AdminToolsLock {
  New-Item -Path $REG_SYSPOLICY -Force -ErrorAction SilentlyContinue | Out-Null
  Set-ItemProperty -Path $REG_SYSPOLICY -Name 'DisableRegistryTools' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
  Set-ItemProperty -Path $REG_SYSPOLICY -Name 'DisableTaskMgr' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
  $script:log.Add('[레지스트리·작업관리자 차단] 활성화 (관리자 계정도 함께 적용됨 — 해제는 HyoErase의 잠금 해제 버튼으로)')
}
function Remove-AdminToolsLock {
  Remove-ItemProperty -Path $REG_SYSPOLICY -Name 'DisableRegistryTools' -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path $REG_SYSPOLICY -Name 'DisableTaskMgr' -ErrorAction SilentlyContinue
  $script:log.Add('[레지스트리·작업관리자 차단] 해제 완료')
}
function Test-AdminToolsLockActive {
  try { (Get-ItemProperty -Path $REG_SYSPOLICY -Name 'DisableTaskMgr' -ErrorAction Stop).DisableTaskMgr -eq 1 } catch { $false }
}

# ------------------------------------------------------------------
#  실행 화이트리스트 (소프트웨어 제한 정책/SRP) — 되돌리기 가능
#  전략: 모든 프로그램을 일일이 허용 목록에 넣는 대신, 학생 계정이 새
#  파일을 쓸 수 있는 위치(바탕화면·다운로드·임시폴더·USB)에서만 "실행"을
#  차단한다. 이미 Program Files/Windows에 설치된 정상 프로그램(오피스 등)은
#  학생이 그 폴더에 새 파일을 쓸 수 없으므로 자동으로 안전하게 유지된다.
#  관리자(로컬 Administrators) 계정은 PolicyScope=1 로 정책에서 예외 처리.
# ------------------------------------------------------------------
$SRP_SAFER = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer'
$SRP_ROOT  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'

function Initialize-SrpBase {
  New-Item -Path $SRP_ROOT -Force -ErrorAction SilentlyContinue | Out-Null
  Set-ItemProperty -Path $SRP_ROOT -Name 'DefaultLevel' -Value 262144 -Type DWord -Force -ErrorAction SilentlyContinue
  Set-ItemProperty -Path $SRP_ROOT -Name 'PolicyScope' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
  Set-ItemProperty -Path $SRP_ROOT -Name 'TransparentEnabled' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
  $disallowKey = Join-Path $SRP_ROOT '0\Paths'
  New-Item -Path $disallowKey -Force -ErrorAction SilentlyContinue | Out-Null
  $disallowKey
}
function Add-SrpDisallowRule([string]$disallowKey, [string]$pathPattern, [string]$desc) {
  $guid = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
  $key = Join-Path $disallowKey $guid
  New-Item -Path $key -Force -ErrorAction SilentlyContinue | Out-Null
  Set-ItemProperty -Path $key -Name 'ItemData' -Value $pathPattern -Type String -Force -ErrorAction SilentlyContinue
  Set-ItemProperty -Path $key -Name 'SaferFlags' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
  Set-ItemProperty -Path $key -Name 'Description' -Value $desc -Type String -Force -ErrorAction SilentlyContinue
}

function Set-ExecWhitelist {
  $disallowKey = Initialize-SrpBase
  $blockPaths = @()
  foreach ($profile in (Get-UserProfileRoots)) {
    $blockPaths += @(
      "$profile\Desktop", "$profile\Downloads",
      "$profile\AppData\Local\Temp", "$profile\AppData\Roaming"
    )
  }
  $blockPaths += @("$env:PUBLIC\Desktop", "$env:PUBLIC\Downloads")
  foreach ($letter in @('D', 'E', 'F', 'G', 'H', 'I')) { $blockPaths += "$letter`:\" }

  foreach ($p in ($blockPaths | Select-Object -Unique)) {
    Add-SrpDisallowRule $disallowKey "$p\*" 'HyoErase 실행 차단 규칙'
  }
  $script:log.Add('[실행 화이트리스트] 활성화 - 바탕화면/다운로드/임시폴더/이동식드라이브 실행 차단, 관리자 계정 예외')
}
function Remove-ExecWhitelist {
  Remove-Item -Path $SRP_SAFER -Recurse -Force -ErrorAction SilentlyContinue
  $script:log.Add('[실행 화이트리스트] 해제 완료')
}
function Test-ExecWhitelistActive {
  $pathsKey = Join-Path $SRP_ROOT '0\Paths'
  if (-not (Test-Path -LiteralPath $pathsKey)) { return $false }
  [bool](Get-ChildItem -LiteralPath $pathsKey -ErrorAction SilentlyContinue |
    Where-Object { (Get-ItemProperty -LiteralPath $_.PSPath -Name Description -ErrorAction SilentlyContinue).Description -eq 'HyoErase 실행 차단 규칙' })
}

# ------------------------------------------------------------------
#  cmd·PowerShell 실행 제한 (표준 사용자)  ⚠⚠ — SRP 경로 규칙 재사용
#  주의: 정상적인 배치파일 기반 수업 도구·설치 프로그램이 내부적으로
#  cmd/PowerShell을 호출하는 경우까지 함께 막힐 수 있습니다.
# ------------------------------------------------------------------
function Set-ScriptExecBlock {
  $disallowKey = Initialize-SrpBase
  $targets = @(
    "$env:SystemRoot\System32\cmd.exe",
    "$env:SystemRoot\SysWOW64\cmd.exe",
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
    "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_ise.exe",
    "$env:ProgramFiles\PowerShell\7\pwsh.exe"
  )
  foreach ($t in $targets) {
    Add-SrpDisallowRule $disallowKey $t 'HyoErase 스크립트 실행 차단 규칙'
  }
  $script:log.Add('[스크립트 실행 차단] cmd·PowerShell 실행 차단 적용, 관리자 계정 예외')
}
function Remove-ScriptExecBlock {
  Remove-Item -Path $SRP_SAFER -Recurse -Force -ErrorAction SilentlyContinue
  $script:log.Add('[스크립트 실행 차단] 해제 완료')
}
function Test-ScriptExecBlockActive {
  $pathsKey = Join-Path $SRP_ROOT '0\Paths'
  if (-not (Test-Path -LiteralPath $pathsKey)) { return $false }
  [bool](Get-ChildItem -LiteralPath $pathsKey -ErrorAction SilentlyContinue |
    Where-Object { (Get-ItemProperty -LiteralPath $_.PSPath -Name Description -ErrorAction SilentlyContinue).Description -eq 'HyoErase 스크립트 실행 차단 규칙' })
}

# ------------------------------------------------------------------
#  해시 기반 실행 차단 (AppLocker) — Windows Pro/Education/Enterprise 전용  ⚠⚠
#  SRP의 원시 해시 레지스트리 구조는 문서화가 부실해 잘못 만들면 조용히
#  아무 효과가 없을 위험이 있어, 대신 Microsoft가 제공하는 정식 AppLocker
#  cmdlet으로 구현한다. Home 에디션이나 서비스 시작 실패 시 안전하게 건너뜀.
# ------------------------------------------------------------------
function Test-AppLockerAvailable { [bool](Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue) }

function Set-HashBlock {
  if (-not (Test-AppLockerAvailable)) {
    $script:log.Add('[해시 기반 차단] 건너뜀 — 이 Windows 에디션은 AppLocker를 지원하지 않음(Pro/Education/Enterprise 필요)')
    return $false
  }
  try {
    Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue

    $exeFiles = @()
    foreach ($a in (Get-InstalledApps)) {
      $cat = Get-AppCategory $a
      if (($cat -eq 'game' -or $cat -eq 'vpn') -and $a.InstallLocation -and (Test-Path -LiteralPath $a.InstallLocation)) {
        $exeFiles += Get-ChildItem -LiteralPath $a.InstallLocation -Recurse -Filter '*.exe' -File -ErrorAction SilentlyContinue
      }
    }
    if ($exeFiles.Count -eq 0) {
      $script:log.Add('[해시 기반 차단] 대상 실행파일을 찾지 못해 건너뜀 (현재 설치된 게임/VPN 없음)')
      return $false
    }
    $fileInfo = $exeFiles | Select-Object -Unique -Property FullName | ForEach-Object { Get-AppLockerFileInformation -Path $_.FullName -ErrorAction SilentlyContinue }
    $fileInfo = @($fileInfo | Where-Object { $_ })
    if ($fileInfo.Count -eq 0) {
      $script:log.Add('[해시 기반 차단] 파일 해시 정보를 만들지 못해 건너뜀')
      return $false
    }
    $newPolicyXml = New-AppLockerPolicy -FileInformation $fileInfo -RuleType Hash -User Everyone -RuleNamePrefix 'HyoErase' -Xml
    # New-AppLockerPolicy는 기본적으로 Allow 규칙을 생성 — 우리가 원하는 건
    # "이 파일들만 차단"이므로 Action을 Deny로 뒤집는다 (직접 만든 XML만 대상).
    $denyXml = $newPolicyXml -replace 'Action="Allow"', 'Action="Deny"'
    Set-AppLockerPolicy -XmlPolicy $denyXml -Merge -ErrorAction Stop
    $script:log.Add("[해시 기반 차단] $($fileInfo.Count)개 실행파일 해시 차단 규칙 적용")
    return $true
  } catch {
    $script:log.Add("[해시 기반 차단] 실패: $($_.Exception.Message)")
    return $false
  }
}
function Remove-HashBlock {
  if (-not (Test-AppLockerAvailable)) { return }
  try {
    [xml]$xml = (Get-AppLockerPolicy -Effective -Xml)
    $nodes = $xml.SelectNodes("//*[starts-with(@Name, 'HyoErase')]")
    if ($nodes.Count -gt 0) {
      foreach ($n in @($nodes)) { $n.ParentNode.RemoveChild($n) | Out-Null }
      Set-AppLockerPolicy -XmlPolicy $xml.OuterXml -ErrorAction SilentlyContinue
    }
    $script:log.Add('[해시 기반 차단] 해제 완료')
  } catch { }
}
function Test-HashBlockActive {
  if (-not (Test-AppLockerAvailable)) { return $false }
  try {
    [xml]$xml = (Get-AppLockerPolicy -Effective -Xml)
    [bool]$xml.SelectNodes("//*[starts-with(@Name, 'HyoErase')]").Count
  } catch { $false }
}

# ------------------------------------------------------------------
#  자동 정리 예약 (작업 스케줄러) — 되돌리기 가능
# ------------------------------------------------------------------
$TASK_NAME = 'HyoErase-AutoClean'
function Test-AutoTaskExists { [bool](Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue) }
function Register-AutoTask {
  try {
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Auto"
    $trigger   = New-ScheduledTaskTrigger -Daily -At 19:00
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $TASK_NAME -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    $true
  } catch { $false }
}
function Unregister-AutoTask { try { Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue } catch { } }

# ------------------------------------------------------------------
#  실시간 감시(워치독)  ⚠⚠ — 짧은 주기로 게임/VPN 프로세스를 즉시 종료
#  하루 한 번이 아니라 몇 분마다 검사·강제종료해 "상시 감시"에 가깝게 동작.
#  -Watchdog 스위치로 한 번 검사하고 종료 → 작업 스케줄러의 반복 트리거가
#  주기적으로 재호출(짧게 실행되고 끝나므로 상주 프로세스가 남지 않음).
# ------------------------------------------------------------------
$WATCHDOG_TASK_NAME = 'HyoErase-Watchdog'
function Invoke-Watchdog {
  foreach ($name in $WATCHDOG_PROCESS_NAMES) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  }
}
function Test-WatchdogTaskExists { [bool](Get-ScheduledTask -TaskName $WATCHDOG_TASK_NAME -ErrorAction SilentlyContinue) }
function Register-WatchdogTask {
  try {
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Watchdog"
    $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration ([TimeSpan]::MaxValue)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $WATCHDOG_TASK_NAME -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    $true
  } catch { $false }
}
function Unregister-WatchdogTask { try { Unregister-ScheduledTask -TaskName $WATCHDOG_TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue } catch { } }

# ------------------------------------------------------------------
#  정리 전 시스템 복원 지점 (안전장치)
# ------------------------------------------------------------------
function New-SafetyCheckpoint {
  try {
    Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description 'HyoErase 정리 전 복원 지점' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
    $script:log.Add('[복원지점] 생성 완료')
  } catch {
    $script:log.Add('[복원지점] 생성 실패/생략 (24시간 제한 또는 비활성화 상태일 수 있음)')
  }
}

# ------------------------------------------------------------------
#  포터블(설치 없는) 실행파일 감지 — 바탕화면·다운로드의 게임/VPN .exe
# ------------------------------------------------------------------
function Get-PortableExeFindings {
  $roots = @("$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop", "$env:USERPROFILE\Downloads")
  $kws = @($GAME_KW) + @($VPN_KW)
  $found = @()
  foreach ($r in $roots) {
    if (-not (Test-Path -LiteralPath $r)) { continue }
    Get-ChildItem -LiteralPath $r -Recurse -Depth 2 -Filter '*.exe' -File -ErrorAction SilentlyContinue | ForEach-Object {
      if (Test-KwHit $_.FullName.ToLower() $kws) { $found += $_ }
    }
  }
  $found | Sort-Object FullName -Unique
}

# ------------------------------------------------------------------
#  여러 사용자 계정 임시파일 청소 (예약 작업이 SYSTEM 권한으로 실행되어도
#  실제 학생 계정 폴더까지 처리하기 위함)
# ------------------------------------------------------------------
function Get-UserProfileRoots {
  Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
    ForEach-Object { $_.FullName }
}

# ------------------------------------------------------------------
#  정리 카테고리 (Group: basic / deep / reset / lockdown)
# ------------------------------------------------------------------
function Get-Categories {
  @(
    # ---- 기본 ----
    [pscustomobject]@{ Key='temp';    Group='basic'; Name='임시 파일';        On=$true;  Type='files'; Desc='Windows·앱 임시 파일'; Roots=@("$env:TEMP","$env:LOCALAPPDATA\Temp","$env:SystemRoot\Temp"); Action=$null }
    [pscustomobject]@{ Key='browser'; Group='basic'; Name='브라우저 캐시';    On=$true;  Type='files'; Desc='Chrome·Edge·Whale·Firefox 캐시(기록·비번 유지)'; Roots=@("$env:LOCALAPPDATA\Google\Chrome\User Data\*\Cache","$env:LOCALAPPDATA\Google\Chrome\User Data\*\Code Cache","$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Cache","$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Code Cache","$env:LOCALAPPDATA\Naver\Naver Whale\User Data\*\Cache","$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\cache2"); Action=$null }
    [pscustomobject]@{ Key='recent';  Group='basic'; Name='최근 문서 기록';   On=$true;  Type='files'; Desc='최근 사용 목록·점프리스트(흔적)'; Roots=@("$env:APPDATA\Microsoft\Windows\Recent"); Action=$null }
    [pscustomobject]@{ Key='dumps';   Group='basic'; Name='오류 덤프 파일';   On=$true;  Type='files'; Desc='크래시 덤프'; Roots=@("$env:LOCALAPPDATA\CrashDumps"); Action=$null }
    [pscustomobject]@{ Key='recycle'; Group='basic'; Name='휴지통 비우기(전체 드라이브)'; On=$true; Type='recycle'; Desc='모든 드라이브의 휴지통을 비웁니다'; Roots=@(); Action=$null }

    # ---- 딥 시스템 청소 ----
    [pscustomobject]@{ Key='alltemp';   Group='deep'; Name='모든 사용자 임시폴더'; On=$true;  Type='files'; Desc='C:\Users\*\AppData\Local\Temp (관리자)'; Roots=@("$env:SystemDrive\Users\*\AppData\Local\Temp"); Action=$null }
    [pscustomobject]@{ Key='winupdate'; Group='deep'; Name='Windows Update 캐시'; On=$true;  Type='files'; Desc='SoftwareDistribution\Download'; Roots=@("$env:SystemRoot\SoftwareDistribution\Download"); Action=$null }
    [pscustomobject]@{ Key='delivery';  Group='deep'; Name='전송 최적화 캐시';   On=$true;  Type='files'; Desc='Delivery Optimization 파일'; Roots=@("$env:SystemRoot\SoftwareDistribution\DeliveryOptimization","$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization"); Action=$null }
    [pscustomobject]@{ Key='wer';       Group='deep'; Name='오류 보고(WER)';     On=$true;  Type='files'; Desc='Windows 오류 보고 큐/보관'; Roots=@("$env:ProgramData\Microsoft\Windows\WER\ReportQueue","$env:ProgramData\Microsoft\Windows\WER\ReportArchive","$env:LOCALAPPDATA\Microsoft\Windows\WER"); Action=$null }
    [pscustomobject]@{ Key='memdump';   Group='deep'; Name='메모리 덤프';        On=$true;  Type='files'; Desc='C:\Windows\Minidump'; Roots=@("$env:SystemRoot\Minidump"); Action=$null }
    [pscustomobject]@{ Key='thumb';     Group='deep'; Name='썸네일·아이콘 캐시'; On=$true;  Type='files'; Desc='탐색기 캐시(자동 재생성)'; Roots=@("$env:LOCALAPPDATA\Microsoft\Windows\Explorer"); Action=$null }
    [pscustomobject]@{ Key='dnsflush';  Group='deep'; Name='DNS 캐시 비우기';    On=$true;  Type='action'; Desc='ipconfig /flushdns'; Roots=@(); Action=$Act_DnsFlush }
    [pscustomobject]@{ Key='fontcache'; Group='deep'; Name='폰트 캐시  ⚠';       On=$false; Type='files'; Desc='폰트 캐시(재생성, 잠겨있으면 건너뜀)'; Roots=@("$env:LOCALAPPDATA\FontCache","$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\FontCache"); Action=$null }
    [pscustomobject]@{ Key='prefetch';  Group='deep'; Name='Prefetch  ⚠';        On=$false; Type='files'; Desc='부팅 가속 데이터(재생성됨)'; Roots=@("$env:SystemRoot\Prefetch"); Action=$null }
    [pscustomobject]@{ Key='eventlog';  Group='deep'; Name='이벤트 로그 전체 삭제  ⚠'; On=$false; Type='action'; Desc='모든 Windows 이벤트 로그 비우기(되돌릴 수 없음)'; Roots=@(); Action=$Act_EventLogs }

    # ---- 수업 초기화·흔적 ----
    [pscustomobject]@{ Key='mru';        Group='reset'; Name='최근/실행 기록 지우기'; On=$true;  Type='action'; Desc='최근문서·실행창·주소창·검색 기록'; Roots=@(); Action=$Act_Mru }
    [pscustomobject]@{ Key='clipboard';  Group='reset'; Name='클립보드 비우기';       On=$true;  Type='action'; Desc='복사해둔 내용 제거'; Roots=@(); Action=$Act_Clipboard }
    [pscustomobject]@{ Key='browserdat'; Group='reset'; Name='브라우저 로그인·방문기록 초기화  ⚠'; On=$false; Type='action'; Desc='저장된 비밀번호·쿠키·기록 삭제(학생 로그인 초기화)'; Roots=@(); Action=$Act_BrowserData }
    [pscustomobject]@{ Key='downloads';  Group='reset'; Name='다운로드 폴더 비우기  ⚠'; On=$false; Type='files'; Desc='내 다운로드 폴더의 파일 삭제'; Roots=@("$env:USERPROFILE\Downloads"); Action=$null }

    # ---- 설치 잠금·재설치 차단 (강력, 기본 꺼짐) ----
    [pscustomobject]@{ Key='hostsblock';   Group='lockdown'; Name='재설치 차단(hosts)  ⚠'; On=$false; Type='action'; Desc='Steam·Epic·주요 VPN 배포 사이트 접속을 막아 재설치를 어렵게 함'; Roots=@(); Action=$Act_HostsBlock }
    [pscustomobject]@{ Key='installlock';  Group='lockdown'; Name='설치 잠금  ⚠'; On=$false; Type='action'; Desc='Microsoft Store 비활성화 + 표준사용자 새 프로그램 설치 차단'; Roots=@(); Action=$Act_InstallLock }
    [pscustomobject]@{ Key='autorunlock';  Group='lockdown'; Name='USB 자동실행 차단'; On=$true; Type='action'; Desc='USB로 게임을 자동 실행하지 못하게 막음 (안전, 되돌리기 쉬움)'; Roots=@(); Action=$Act_AutorunLock }
    [pscustomobject]@{ Key='execwhitelist'; Group='lockdown'; Name='실행 화이트리스트 — 바탕화면·다운로드·USB 실행 차단  ⚠⚠'; On=$false; Type='action'; Desc='학생 계정이 새로 내려받은 프로그램을 실행하는 것 자체를 차단(관리자 계정 예외, 재로그인 후 적용)'; Roots=@(); Action=$Act_ExecWhitelist }
    [pscustomobject]@{ Key='firewallvpn';   Group='lockdown'; Name='방화벽 VPN 프로토콜 차단  ⚠'; On=$false; Type='action'; Desc='OpenVPN·WireGuard·IKEv2·L2TP·PPTP 프로토콜/포트 자체를 차단 (IP가 바뀌어도 유지, hosts보다 견고)'; Roots=@(); Action=$Act_FirewallVpn }
    [pscustomobject]@{ Key='admintoolslock'; Group='lockdown'; Name='레지스트리·작업관리자 접근 차단  ⚠⚠'; On=$false; Type='action'; Desc='regedit·작업관리자 실행 차단 — 관리자 계정도 함께 막힘. 해제는 반드시 HyoErase의 잠금 해제 버튼으로'; Roots=@(); Action=$Act_AdminToolsLock }
    [pscustomobject]@{ Key='scriptexecblock'; Group='lockdown'; Name='cmd·PowerShell 실행 차단  ⚠⚠'; On=$false; Type='action'; Desc='명령 프롬프트·PowerShell 실행 차단(관리자 예외) — 배치파일 기반 정상 프로그램도 함께 막힐 수 있음'; Roots=@(); Action=$Act_ScriptExecBlock }
    [pscustomobject]@{ Key='hashblock';     Group='lockdown'; Name='해시 기반 실행 차단 (Pro/Education 전용)  ⚠'; On=$false; Type='action'; Desc='현재 설치된 게임/VPN 실행파일을 경로와 무관하게 해시로 차단 (Windows Home에서는 자동 건너뜀)'; Roots=@(); Action=$Act_HashBlock }
  )
}

# ------------------------------------------------------------------
#  측정/삭제 공통
# ------------------------------------------------------------------
function Resolve-Roots($patterns) {
  $out = @()
  foreach ($p in $patterns) {
    try {
      if ($p -match '[\*\?]') { $out += (Resolve-Path -Path $p -ErrorAction SilentlyContinue | ForEach-Object { $_.Path }) }
      elseif (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) { $out += $p }
    } catch { }
  }
  $out | Select-Object -Unique
}
function Format-Size([long]$b) {
  if     ($b -ge 1GB) { '{0:N2} GB' -f ($b / 1GB) }
  elseif ($b -ge 1MB) { '{0:N1} MB' -f ($b / 1MB) }
  elseif ($b -ge 1KB) { '{0:N0} KB' -f ($b / 1KB) }
  else                { "$b B" }
}
function Measure-Category($cat) {
  if ($cat.Type -eq 'action') { return [pscustomobject]@{ Bytes = 0; Count = 0 } }
  if ($cat.Type -eq 'recycle') {
    $count = 0; [long]$bytes = 0
    try { $bin = (New-Object -ComObject Shell.Application).NameSpace(0xA); if ($bin) { foreach ($i in $bin.Items()) { $count++; try { $bytes += [long]$i.Size } catch { } } } } catch { }
    return [pscustomobject]@{ Bytes = $bytes; Count = $count }
  }
  [long]$bytes = 0; $count = 0
  foreach ($root in (Resolve-Roots $cat.Roots)) {
    try { Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $bytes += $_.Length; $count++ } } catch { }
  }
  [pscustomobject]@{ Bytes = $bytes; Count = $count }
}
function Clear-Category($cat) {
  if ($cat.Type -eq 'action') {
    try { & $cat.Action } catch { }
    $script:log.Add("[정리] $($cat.Name)")
    return [pscustomobject]@{ Freed = 0; Removed = 1; Failed = 0 }
  }
  if ($cat.Type -eq 'recycle') {
    $before = Measure-Category $cat
    try { Clear-RecycleBin -Force -ErrorAction Stop } catch { }
    $script:log.Add("[정리] 휴지통 $(Format-Size $before.Bytes)")
    return [pscustomobject]@{ Freed = $before.Bytes; Removed = $before.Count; Failed = 0 }
  }
  [long]$freed = 0; $removed = 0; $failed = 0
  foreach ($root in (Resolve-Roots $cat.Roots)) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | ForEach-Object {
      $item = $_; [long]$sz = 0
      try { if ($item.PSIsContainer) { $sz = (Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum } else { $sz = $item.Length } } catch { }
      try { Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop; $freed += $sz; $removed++ } catch { $failed++ }
    }
  }
  $script:log.Add("[정리] $($cat.Name)  $(Format-Size $freed) ($removed개)")
  [pscustomobject]@{ Freed = $freed; Removed = $removed; Failed = $failed }
}

function Save-Log {
  try {
    $dir = Join-Path $PSScriptRoot 'logs'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $file = Join-Path $dir "HyoErase-$stamp.txt"
    (@("HyoErase v$AppVersion  정리 로그  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", '') + $script:log) | Out-File -FilePath $file -Encoding UTF8
    return $file
  } catch { return $null }
}

# ------------------------------------------------------------------
#  -Auto 모드: 창 없이 조용히 기본 항목만 정리 (작업 스케줄러가 호출)
#  주의: 예약 작업은 SYSTEM 권한으로 실행되므로 $env:* 은 SYSTEM 프로필을
#  가리킴 — 그래서 임시파일/캐시는 아래처럼 모든 학생 계정 폴더를 직접
#  순회해서 처리한다. 잠금(hosts/설치잠금) 항목은 자동 실행에 포함하지 않음.
# ------------------------------------------------------------------
function Invoke-AutoClean {
  $script:log.Clear()
  foreach ($a in (Get-InstalledApps)) {
    $cat = Get-AppCategory $a
    if ($cat -eq 'game' -or $cat -eq 'vpn') { Uninstall-App $a $true | Out-Null }
  }
  foreach ($u in (Get-UwpApps)) { Remove-Uwp $u | Out-Null }

  foreach ($profile in (Get-UserProfileRoots)) {
    $roots = @(
      "$profile\AppData\Local\Temp",
      "$profile\AppData\Local\Google\Chrome\User Data\*\Cache",
      "$profile\AppData\Local\Google\Chrome\User Data\*\Code Cache",
      "$profile\AppData\Local\Microsoft\Edge\User Data\*\Cache",
      "$profile\AppData\Local\Microsoft\Edge\User Data\*\Code Cache",
      "$profile\AppData\Local\Naver\Naver Whale\User Data\*\Cache",
      "$profile\AppData\Roaming\Microsoft\Windows\Recent",
      "$profile\AppData\Local\CrashDumps"
    )
    foreach ($root in (Resolve-Roots $roots)) {
      Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch { }
      }
    }
  }

  foreach ($c in (Get-Categories | Where-Object { $_.On -eq $true -and $_.Group -in @('basic', 'deep') })) {
    Clear-Category $c | Out-Null
  }
  Save-Log | Out-Null
}
if ($Auto) { Invoke-AutoClean; exit }
if ($Watchdog) { Invoke-Watchdog; exit }

# ------------------------------------------------------------------
#  UI
# ------------------------------------------------------------------
$mainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="HyoErase" Width="600" Height="880" WindowStartupLocation="CenterScreen"
        FontFamily="Pretendard, Segoe UI, Malgun Gothic" Background="{DynamicResource BgBrush}">
  <Window.Resources>
    <SolidColorBrush x:Key="BgBrush" Color="#07090C"/><SolidColorBrush x:Key="CardBrush" Color="#0D1117"/>
    <SolidColorBrush x:Key="BorderBrush" Color="#1E2A38"/><SolidColorBrush x:Key="TextPrimary" Color="#EEF2FF"/>
    <SolidColorBrush x:Key="TextSecondary" Color="#8896AA"/><SolidColorBrush x:Key="AccentBrush" Color="#4A9FE0"/>
    <Style x:Key="Accent" TargetType="Button">
      <Setter Property="Foreground" Value="White"/><Setter Property="FontSize" Value="15"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="46"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" CornerRadius="10" Background="{DynamicResource AccentBrush}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#2B7CC7"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Background" Value="#39485C"/></Trigger>
        </ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Ghost" TargetType="Button">
      <Setter Property="Foreground" Value="{DynamicResource AccentBrush}"/><Setter Property="FontSize" Value="14"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="46"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" CornerRadius="10" BorderThickness="1" BorderBrush="{DynamicResource AccentBrush}" Background="Transparent"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#152230"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <Grid Margin="22">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Grid Grid.Row="0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0">
        <TextBlock Text="HyoErase" FontSize="26" FontWeight="Bold" Foreground="{DynamicResource TextPrimary}"/>
        <TextBlock Text="지우개 — 학교 PC 초강력 정리·관리" FontSize="13" Margin="0,2,0,0" Foreground="{DynamicResource AccentBrush}"/>
      </StackPanel>
      <Button x:Name="ThemeBtn" Grid.Column="1" Content="◐  테마" Style="{StaticResource Ghost}" Width="92" Height="36" VerticalAlignment="Top"/>
    </Grid>
    <TextBlock Grid.Row="1" TextWrapping="Wrap" Margin="0,14,0,10" FontSize="12" Foreground="{DynamicResource TextSecondary}"
               Text="오피스·문서·그림·드라이버·백신·은행인증은 목록에 없고 삭제되지 않습니다. ⚠ 표시 항목은 영향이 크니 확인 후 선택하세요."/>
    <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto"><StackPanel x:Name="CatHost"/></ScrollViewer>
    <Border Grid.Row="3" CornerRadius="10" Margin="0,4,0,12" Padding="14,10" Background="{DynamicResource CardBrush}" BorderThickness="1" BorderBrush="{DynamicResource BorderBrush}">
      <TextBlock x:Name="StatusText" TextWrapping="Wrap" FontSize="13" Foreground="{DynamicResource TextPrimary}" Text="시스템을 검사하는 중…"/>
    </Border>
    <Grid Grid.Row="4">
      <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <Button x:Name="ScanBtn" Grid.Column="0" Content="다시 검사" Width="130" Style="{StaticResource Ghost}"/>
      <Button x:Name="CleanBtn" Grid.Column="2" Content="🧹  선택 항목 싹 정리" Style="{StaticResource Accent}"/>
    </Grid>
    <Grid Grid.Row="5" Margin="0,10,0,0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <Button x:Name="ScheduleBtn" Grid.Column="0" Content="⏱ 자동 정리 예약" Style="{StaticResource Ghost}" Height="38" FontSize="12"/>
      <Button x:Name="WatchdogBtn" Grid.Column="2" Content="👁 실시간 감시" Style="{StaticResource Ghost}" Height="38" FontSize="12"/>
      <Button x:Name="UnlockBtn" Grid.Column="4" Content="🔓 잠금 해제" Style="{StaticResource Ghost}" Height="38" FontSize="12"/>
    </Grid>
    <TextBlock x:Name="Footer" Grid.Row="6" Margin="0,14,0,0" FontFamily="JetBrains Mono, Consolas" FontSize="10.5" TextAlignment="Center" Foreground="{DynamicResource TextSecondary}"/>
  </Grid>
</Window>
'@

$window     = [Windows.Markup.XamlReader]::Parse($mainXaml)
$CatHost    = $window.FindName('CatHost')
$StatusText = $window.FindName('StatusText')
$ScanBtn    = $window.FindName('ScanBtn')
$CleanBtn   = $window.FindName('CleanBtn')
$ThemeBtn   = $window.FindName('ThemeBtn')
$ScheduleBtn = $window.FindName('ScheduleBtn')
$WatchdogBtn = $window.FindName('WatchdogBtn')
$UnlockBtn   = $window.FindName('UnlockBtn')
$Footer     = $window.FindName('Footer'); $Footer.Text = $FooterText

$script:cats     = Get-Categories
$script:measured = @{}
$script:items    = @()
$script:optLeftover = $null
$script:optRestore  = $null

function New-TB([string]$text, [double]$size, $weight, [string]$brushKey, [bool]$wrap) {
  $tb = New-Object System.Windows.Controls.TextBlock; $tb.Text = $text; $tb.FontSize = $size
  if ($weight) { $tb.FontWeight = $weight }
  if ($brushKey) { $tb.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $brushKey) }
  if ($wrap) { $tb.TextWrapping = 'Wrap' }
  $tb
}
function New-Header([string]$text) { $tb = New-TB $text 13 'SemiBold' 'AccentBrush' $false; $tb.Margin = New-Object System.Windows.Thickness(2, 12, 0, 6); $tb }
function New-Row([bool]$checked, [string]$title, [string]$subtitle, [string]$rightText) {
  $border = New-Object System.Windows.Controls.Border
  $border.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'CardBrush')
  $border.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BorderBrush')
  $border.BorderThickness = 1; $border.CornerRadius = New-Object System.Windows.CornerRadius(10)
  $border.Padding = New-Object System.Windows.Thickness(12, 8, 12, 8); $border.Margin = New-Object System.Windows.Thickness(0, 0, 0, 8)
  $grid = New-Object System.Windows.Controls.Grid
  $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
  $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = [System.Windows.GridLength]::Auto
  $grid.ColumnDefinitions.Add($c1); $grid.ColumnDefinitions.Add($c2)
  $chk = New-Object System.Windows.Controls.CheckBox; $chk.IsChecked = $checked; $chk.VerticalAlignment = 'Center'
  $chk.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'TextPrimary')
  $sp = New-Object System.Windows.Controls.StackPanel; $sp.Margin = New-Object System.Windows.Thickness(4, 0, 0, 0)
  $sp.Children.Add((New-TB $title 13.5 'SemiBold' 'TextPrimary' $true)) | Out-Null
  if ($subtitle) { $t = New-TB $subtitle 11 $null 'TextSecondary' $true; $t.Margin = New-Object System.Windows.Thickness(0, 1, 0, 0); $sp.Children.Add($t) | Out-Null }
  $chk.Content = $sp; [System.Windows.Controls.Grid]::SetColumn($chk, 0); $grid.Children.Add($chk) | Out-Null
  $tag = New-TB $rightText 11 'SemiBold' 'TextSecondary' $false; $tag.VerticalAlignment = 'Center'
  $tag.Margin = New-Object System.Windows.Thickness(10, 0, 0, 0); $tag.FontFamily = New-Object System.Windows.Media.FontFamily('JetBrains Mono, Consolas')
  [System.Windows.Controls.Grid]::SetColumn($tag, 1); $grid.Children.Add($tag) | Out-Null
  $border.Child = $grid
  [pscustomobject]@{ Border = $border; Check = $chk }
}
function Add-AppSection([string]$title, $list, [bool]$autocheck, [string]$tag) {
  $CatHost.Children.Add((New-Header ("$title  ($($list.Count)개)"))) | Out-Null
  if ($list.Count -eq 0) { $CatHost.Children.Add((New-TB '감지된 항목이 없습니다.' 11 $null 'TextSecondary' $false)) | Out-Null; return }
  foreach ($a in ($list | Sort-Object Name)) {
    $parts = @(); if ($a.Publisher) { $parts += $a.Publisher }; if ($a.Size) { $parts += (Format-Size $a.Size) }
    $row = New-Row $autocheck $a.Name ($parts -join '  ·  ') $tag
    $script:items += [pscustomobject]@{ Chk = $row.Check; Kind = 'app'; Payload = $a }
    $CatHost.Children.Add($row.Border) | Out-Null
  }
}
function Add-CatGroup([string]$title, [string]$group) {
  $CatHost.Children.Add((New-Header $title)) | Out-Null
  foreach ($c in ($script:cats | Where-Object { $_.Group -eq $group })) {
    $m = Measure-Category $c; $script:measured[$c.Key] = $m
    $right = switch ($c.Type) { 'action' { '실행' } 'recycle' { "$($m.Count)개" } default { Format-Size $m.Bytes } }
    $row = New-Row $c.On $c.Name $c.Desc $right
    $script:items += [pscustomobject]@{ Chk = $row.Check; Kind = 'temp'; Payload = $c }
    $CatHost.Children.Add($row.Border) | Out-Null
  }
}

function Build-List {
  $StatusText.Text = '시스템을 검사하는 중…'
  $window.Dispatcher.Invoke([action] { }, [System.Windows.Threading.DispatcherPriority]::Render)
  $CatHost.Children.Clear(); $script:items = @()

  # 옵션
  $CatHost.Children.Add((New-Header '⚙ 옵션')) | Out-Null
  $opt = New-Row $true '제거 후 잔여 파일·폴더·바로가기까지 삭제 (강력)' '설치 폴더와 시작메뉴/바탕화면 바로가기 정리' '옵션'
  $script:optLeftover = $opt.Check
  $CatHost.Children.Add($opt.Border) | Out-Null
  $optR = New-Row $true '정리 전 시스템 복원 지점 생성 (안전장치)' '문제가 생기면 복원 지점으로 되돌릴 수 있습니다' '옵션'
  $script:optRestore = $optR.Check
  $CatHost.Children.Add($optR.Border) | Out-Null

  $games = @(); $vpns = @(); $others = @()
  foreach ($a in (Get-InstalledApps)) {
    switch (Get-AppCategory $a) { 'game' { $games += $a } 'vpn' { $vpns += $a } 'protected' { } default { $others += $a } }
  }
  Add-AppSection '🎮 게임' $games $true '게임'
  Add-AppSection '🛡 VPN'  $vpns  $true 'VPN'

  $uwp = @(Get-UwpApps)
  $CatHost.Children.Add((New-Header ("🕹 스토어 앱·게임 (UWP)  ($($uwp.Count)개)"))) | Out-Null
  if ($uwp.Count -eq 0) { $CatHost.Children.Add((New-TB '감지된 항목이 없습니다.' 11 $null 'TextSecondary' $false)) | Out-Null }
  foreach ($u in $uwp) {
    $row = New-Row $true $u.Name '스토어 기본앱/게임' '스토어'
    $script:items += [pscustomobject]@{ Chk = $row.Check; Kind = 'uwp'; Payload = $u }
    $CatHost.Children.Add($row.Border) | Out-Null
  }

  Add-CatGroup '🧹 기본 정리' 'basic'
  Add-CatGroup '🚀 딥 시스템 청소 (관리자)' 'deep'
  Add-CatGroup '♻ 수업 초기화·흔적 제거' 'reset'
  Add-CatGroup '🔒 설치 잠금·재설치 차단 (강력, 되돌리기 가능)' 'lockdown'

  $portables = @(Get-PortableExeFindings)
  $CatHost.Children.Add((New-Header ("💽 포터블 실행파일 — 설치 없는 게임/VPN 의심  ($($portables.Count)개)"))) | Out-Null
  if ($portables.Count -eq 0) {
    $CatHost.Children.Add((New-TB '감지된 항목이 없습니다.' 11 $null 'TextSecondary' $false)) | Out-Null
  } else {
    foreach ($f in $portables) {
      $row = New-Row $false $f.Name $f.FullName '포터블'
      $script:items += [pscustomobject]@{ Chk = $row.Check; Kind = 'portable'; Payload = $f }
      $CatHost.Children.Add($row.Border) | Out-Null
    }
  }

  $CatHost.Children.Add((New-Header ("📦 기타 설치된 프로그램 — 직접 선택  ($($others.Count)개)"))) | Out-Null
  $CatHost.Children.Add((New-TB '확실히 불필요한 것만 체크하세요. 잘 모르면 그대로 두는 게 안전합니다. 목록을 다 훑어봤다면 아래 버튼으로 한 번에 선택할 수 있습니다.' 11 $null 'TextSecondary' $true)) | Out-Null
  $othersChecks = New-Object System.Collections.Generic.List[object]
  foreach ($a in ($others | Sort-Object Name)) {
    $parts = @(); if ($a.Publisher) { $parts += $a.Publisher }; if ($a.Size) { $parts += (Format-Size $a.Size) }
    $row = New-Row $false $a.Name ($parts -join '  ·  ') '기타'
    $script:items += [pscustomobject]@{ Chk = $row.Check; Kind = 'app'; Payload = $a }
    $othersChecks.Add($row.Check)
    $CatHost.Children.Add($row.Border) | Out-Null
  }
  if ($others.Count -gt 0) {
    $selAllBtn = New-Object System.Windows.Controls.Button
    $selAllBtn.Content = '⚠ 기타 전체 선택 / 해제 (신중하게 확인 후 사용)'
    $selAllBtn.Height = 36
    $selAllBtn.Margin = New-Object System.Windows.Thickness(0, 2, 0, 10)
    $selAllBtn.Background = [System.Windows.Media.Brushes]::Transparent
    $selAllBtn.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'AccentBrush')
    $selAllBtn.SetResourceReference([System.Windows.Controls.Control]::BorderBrushProperty, 'AccentBrush')
    $selAllBtn.BorderThickness = New-Object System.Windows.Thickness(1)
    $selAllBtn.Add_Click({
      $anyUnchecked = @($othersChecks | Where-Object { -not $_.IsChecked }).Count -gt 0
      foreach ($c in $othersChecks) { $c.IsChecked = $anyUnchecked }
    }.GetNewClosure())
    $CatHost.Children.Add($selAllBtn) | Out-Null
  }

  $note = if ($isAdmin -or $env:HYOERASE_NOELEV) { '' } else { '  (⚠ 관리자 아님 — 일부 항목 제한)' }
  $lockState = @()
  if (Test-HostsBlockActive)        { $lockState += 'hosts 차단' }
  if (Test-InstallLockdownActive)   { $lockState += '설치 잠금' }
  if (Test-ExecWhitelistActive)     { $lockState += '실행 화이트리스트' }
  if (Test-ScriptExecBlockActive)   { $lockState += '스크립트 차단' }
  if (Test-FirewallVpnBlockActive)  { $lockState += '방화벽 VPN 차단' }
  if (Test-AdminToolsLockActive)    { $lockState += '레지스트리/작업관리자 차단' }
  if (Test-HashBlockActive)         { $lockState += '해시 차단' }
  if (Test-AutoTaskExists)          { $lockState += '자동 예약' }
  if (Test-WatchdogTaskExists)      { $lockState += '워치독' }
  $lockNote = if ($lockState.Count) { "  |  🔒 적용중: $($lockState -join ', ')" } else { '' }
  $StatusText.Text = "게임 $($games.Count) · VPN $($vpns.Count) · 스토어 $($uwp.Count) · 포터블 $($portables.Count) · 기타 $($others.Count) 감지됨$note$lockNote"
}

$script:dark = $true
function New-Brush($hex) { New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($hex)) }
function Set-Theme($dark) {
  if ($dark) { $s = @{ Bg='#07090C'; Card='#0D1117'; Border='#1E2A38'; T1='#EEF2FF'; T2='#8896AA' } }
  else       { $s = @{ Bg='#F6F8FC'; Card='#FFFFFF'; Border='#DCE4EE'; T1='#1A2230'; T2='#5A6A80' } }
  $window.Resources['BgBrush'] = New-Brush $s.Bg; $window.Resources['CardBrush'] = New-Brush $s.Card
  $window.Resources['BorderBrush'] = New-Brush $s.Border; $window.Resources['TextPrimary'] = New-Brush $s.T1; $window.Resources['TextSecondary'] = New-Brush $s.T2
}

$ScanBtn.Add_Click({ Build-List })
$ThemeBtn.Add_Click({ $script:dark = -not $script:dark; Set-Theme $script:dark })

$ScheduleBtn.Add_Click({
  if (Test-AutoTaskExists) {
    $ans = [System.Windows.MessageBox]::Show('자동 정리 예약이 이미 설정되어 있습니다. 해제할까요?', 'HyoErase', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($ans -eq [System.Windows.MessageBoxResult]::Yes) { Unregister-AutoTask; [System.Windows.MessageBox]::Show('예약이 해제되었습니다.') | Out-Null }
  } else {
    $ans = [System.Windows.MessageBox]::Show("매일 저녁 7시(19:00)에 게임·VPN·스토어앱 제거와 기본+딥 시스템 청소를 자동으로 실행하도록 예약할까요?`n(⚠ 표시·잠금 항목은 예약 실행에 포함되지 않습니다)", 'HyoErase — 자동 정리 예약', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($ans -eq [System.Windows.MessageBoxResult]::Yes) {
      if (Register-AutoTask) { [System.Windows.MessageBox]::Show('예약 완료: 매일 19:00 자동 정리') | Out-Null }
      else { [System.Windows.MessageBox]::Show('예약 등록에 실패했습니다. 관리자 권한으로 실행 중인지 확인하세요.') | Out-Null }
    }
  }
  Build-List
})

$WatchdogBtn.Add_Click({
  if (Test-WatchdogTaskExists) {
    $ans = [System.Windows.MessageBox]::Show('실시간 감시(워치독)가 이미 켜져 있습니다. 끌까요?', 'HyoErase', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($ans -eq [System.Windows.MessageBoxResult]::Yes) { Unregister-WatchdogTask; [System.Windows.MessageBox]::Show('실시간 감시를 껐습니다.') | Out-Null }
  } else {
    $ans = [System.Windows.MessageBox]::Show("2분마다 게임/VPN 프로세스를 검사해 즉시 강제 종료하도록 켤까요?`n(하루 한 번이 아니라 상시 감시에 가깝게 동작합니다)", 'HyoErase — 실시간 감시', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($ans -eq [System.Windows.MessageBoxResult]::Yes) {
      if (Register-WatchdogTask) { [System.Windows.MessageBox]::Show('실시간 감시를 켰습니다 (2분 간격).') | Out-Null }
      else { [System.Windows.MessageBox]::Show('등록에 실패했습니다. 관리자 권한으로 실행 중인지 확인하세요.') | Out-Null }
    }
  }
  Build-List
})

$UnlockBtn.Add_Click({
  $ans = [System.Windows.MessageBox]::Show('hosts 차단 · 설치 잠금 · 실행 화이트리스트 · 방화벽 VPN 차단 · 레지스트리/작업관리자 차단 · 스크립트 실행 차단 · 해시 차단 · USB 자동실행 차단 · 자동 정리/워치독 예약을 모두 해제할까요?', 'HyoErase — 잠금 해제', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
  if ($ans -ne [System.Windows.MessageBoxResult]::Yes) { return }
  Remove-HostsBlock; Remove-InstallLockdown; Remove-AutorunBlock; Remove-ExecWhitelist
  Remove-FirewallVpnBlock; Remove-AdminToolsLock; Remove-ScriptExecBlock; Remove-HashBlock
  Unregister-AutoTask; Unregister-WatchdogTask
  [System.Windows.MessageBox]::Show('모든 잠금이 해제되었습니다. (실행 화이트리스트·스크립트 차단은 재로그인 후 완전히 반영됩니다)') | Out-Null
  Build-List
})

$CleanBtn.Add_Click({
  $sel = @($script:items | Where-Object { $_.Chk.IsChecked })
  if ($sel.Count -eq 0) { [System.Windows.MessageBox]::Show('정리할 항목을 선택하세요.', '안내') | Out-Null; return }
  $apps     = @($sel | Where-Object { $_.Kind -eq 'app' })
  $uwps     = @($sel | Where-Object { $_.Kind -eq 'uwp' })
  $temps    = @($sel | Where-Object { $_.Kind -eq 'temp' })
  $portables = @($sel | Where-Object { $_.Kind -eq 'portable' })
  [long]$tempBytes = ($temps | ForEach-Object { $script:measured[$_.Payload.Key].Bytes } | Measure-Object -Sum).Sum
  $riskyKeys = @('downloads','browserdat','eventlog','prefetch','fontcache','hostsblock','installlock','execwhitelist','firewallvpn','admintoolslock','scriptexecblock','hashblock')
  $risky = @($temps | Where-Object { $riskyKeys -contains $_.Payload.Key })
  $warn = if ($risky.Count) { "`n`n⚠ 영향 큰 항목 포함: " + (($risky | ForEach-Object { $_.Payload.Name.Replace(' ⚠','') }) -join ', ') } else { '' }
  $preview = if ($apps.Count) { ($apps | Select-Object -First 10 | ForEach-Object { "· $($_.Payload.Name)" }) -join "`n" } else { '(없음)' }
  if ($apps.Count -gt 10) { $preview += "`n· … 외 $($apps.Count - 10)개" }
  $msg = "■ 프로그램 제거: $($apps.Count)개`n$preview`n`n■ 스토어 앱 제거: $($uwps.Count)개`n■ 포터블 실행파일 삭제: $($portables.Count)개`n■ 시스템/초기화/잠금 항목: $($temps.Count)개 (약 $(Format-Size $tempBytes))$warn`n`n※ 문서·그림·오피스는 삭제되지 않습니다. 되돌릴 수 없습니다.`n계속할까요?"
  $ans = [System.Windows.MessageBox]::Show($msg, 'HyoErase — 정리 확인', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
  if ($ans -ne [System.Windows.MessageBoxResult]::Yes) { return }

  $CleanBtn.IsEnabled = $false; $script:log.Clear()
  if ([bool]$script:optRestore.IsChecked) {
    $StatusText.Text = '복원 지점 생성 중…'
    $window.Dispatcher.Invoke([action] { }, [System.Windows.Threading.DispatcherPriority]::Render)
    New-SafetyCheckpoint
  }
  $leftovers = [bool]$script:optLeftover.IsChecked
  $okA = 0; $failA = 0; $i = 0
  foreach ($it in $apps) {
    $i++; $StatusText.Text = "프로그램 제거 중…  ($i/$($apps.Count))  $($it.Payload.Name)"
    $window.Dispatcher.Invoke([action] { }, [System.Windows.Threading.DispatcherPriority]::Render)
    $r = Uninstall-App $it.Payload $leftovers; if ($r.Ok) { $okA++ } else { $failA++ }
  }
  $okU = 0; $i = 0
  foreach ($it in $uwps) {
    $i++; $StatusText.Text = "스토어 앱 제거 중…  ($i/$($uwps.Count))  $($it.Payload.Name)"
    $window.Dispatcher.Invoke([action] { }, [System.Windows.Threading.DispatcherPriority]::Render)
    if (Remove-Uwp $it.Payload) { $okU++ }
  }
  [long]$freed = 0
  foreach ($it in $temps) { $r = Clear-Category $it.Payload; $freed += $r.Freed }
  $okP = 0
  foreach ($it in $portables) {
    try { Remove-Item -LiteralPath $it.Payload.FullName -Force -ErrorAction Stop; $okP++; $script:log.Add("[포터블] $($it.Payload.FullName)  ->  삭제") } catch { }
  }
  $logFile = Save-Log
  Build-List
  $failNote = if ($failA) { " · $failA개 실패" } else { '' }
  $StatusText.Text = "✅ 완료 · 프로그램 $okA + 스토어 $okU + 포터블 $okP 제거$failNote · 시스템 $(Format-Size $freed) 정리" + $(if ($logFile) { " · 로그 저장됨" } else { '' })
  $CleanBtn.IsEnabled = $true
})

$window.Add_ContentRendered({ Build-List })
$window.ShowDialog() | Out-Null
