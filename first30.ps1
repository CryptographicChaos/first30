<#
    first30.ps1 - the Windows "first 30 minutes" kit for CCDC.
    Counterpart to first30.sh.

    NEW PLAYER? Right-click PowerShell > Run as administrator, go to the folder
    with this file, then type:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\first30.ps1
    With no mode it opens a menu. Each choice says what it does and whether it
    changes anything. Learn mode (on in the menu) shows, for every check, where
    to click in Windows to see the same thing yourself, and the PowerShell
    command behind it.

    Modes for the command line (the mode can be the first word, or -Mode):
        ... -File .\first30.ps1 hunt              (add -Learn for learn mode)
        all       start of game: snapshot + baseline + config copies + every check
        recon     a quick picture of the box + every check (read only)
        backup    snapshot + config copies (the first one becomes the baseline)
        hunt      what changed since the last hunt + every check (every 30 minutes)
        c2        programs calling out to a C2 server (watches for 30 seconds)
        trace     -Ip <address>   where an address shows up in the logs
        evidence  -Path <file>    copy a suspicious file into the vault, with its fingerprint
        note      -Text "..."     add a line to the team notes;  notes  shows them
        nets      -OurNets 10.100.130.0/24,192.168.220.0/24   save your team's networks
        block     -Ip <address>   cut an address off, in and out (no -Ip: put saved blocks back)
        unblock   -Ip <address>   remove a block
        bait      -Path <file>    plant a bait file (anyone who opens it is logged)
        quiet     stop pop-up spam (msg.exe from other machines) and RDP screen watching;  undo-quiet
        sos       something is wrong right now: walks you through it (menu S)
        why       -Text "error message"   what an error means and the next step
        harden    hardening, one step at a time, each step asks;  undo-harden
        bugs      known bugs: missing updates and loose settings (read only)
        domain    is AD / the DC the real problem? (read only)
        ad        AD rescue on a DC: restore, enable, unlock users, passwords, krbtgt
        kick      -Ip <address> or -Text <user>   end a session and block the address
        restore   put firewall rules, hosts, startup keys, GPOs or web files back
        findpass  find where a password is written down
        facts     -Ip / -Text / -Path   incident facts and proof (your team writes the report)
        trip      -Text on|off   log port scanners (no -Text: who scanned)
        protect   -Ip <addresses>   block and kick never touch these;  unprotect
        reminders PCRs to file, reports to write, what you were doing
        audit     turn on the logging the hunt needs, and the Game Day view
        advuln    every well-known AD weak spot, with the fix (on a DC; read only)
        plumbing  what breaks if you change a password (read only)
        decoy     -Path <file> [-Text admin]   plant another bait file (several allowed)
        lock-svc  -Text <service>   fence in a service your team installed;  undo-lock-svc
        scrub     remove a leaked password from PowerShell history files
        report    one block for the packet and incident reports: every address, evidence with
                  fingerprints, blocked addresses, the latest findings with MITRE ATT&CK names
        (the hunt now also checks: the clock, every address, Group Policy tasks and scripts in
         SYSVOL on a DC, IIS modules, WMI providers, and SQL Server backdoors)
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('menu','recon','backup','all','hunt','c2','trace','evidence','note','notes','nets','block','unblock','bait','quiet','undo-quiet','sos','why','harden','undo-harden','bugs','domain','ad','kick','restore','findpass','facts','trip','protect','unprotect','reminders','audit','advuln','plumbing','decoy','lock-svc','undo-lock-svc','scrub','report')]
    [string]$Mode = 'menu',

    [string]$Vault = 'C:\ProgramData\bk',

    [ValidateSet('dc','server','desktop','auto')]
    [string]$Role = 'auto',

    [string[]]$Ip = @(),

    [string[]]$OurNets = @(),

    [string]$Path = '',

    [string]$Text = '',

    [switch]$Learn
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# output helpers. Everything printed goes through Clean: red team can put hidden
# characters in names (escape codes that rewrite the screen, look-alike letters
# from other alphabets). Here every one of them shows as a ?.
# ---------------------------------------------------------------------------
function Clean { param($m) if ($null -eq $m) { return '' }; return (([string]$m) -replace '[^\x09\x20-\x7E]', '?') }
function Say  { param($m) foreach ($l in (([string]$m) -split "`r?`n")) { Write-Host (Clean $l) } }
function Warn { param($m) foreach ($l in (([string]$m) -split "`r?`n")) { Write-Host ('[!] ' + (Clean $l)) -ForegroundColor Yellow } }
function Good { param($m) Write-Host ('[ok] ' + (Clean $m)) -ForegroundColor Green }
function Nxt  { param($m) Write-Host ('  Next: ' + (Clean $m)) -ForegroundColor Cyan }
function Head { param($m) Write-Host ''; Write-Host ('==== ' + (Clean $m) + ' ====') }
function Show { param($Rows) if ($Rows) { Say (($Rows | Format-Table -AutoSize -Wrap | Out-String -Width 220).Trim()) } }

# Every check starts with Sec. Flag marks it as "something to look at" for the
# summary at the end.
$script:Found = New-Object System.Collections.ArrayList
$script:Cur = ''
$script:LearnOn = [bool]$Learn
function Sec  { param([string]$Key, [string]$Title) $script:Cur = $Title; Head $Title; if ($script:LearnOn) { Show-Learn $Key } }
function Flag { if (-not $script:Found.Contains($script:Cur)) { [void]$script:Found.Add($script:Cur) } }

# Learn mode: where to click to see it yourself, the PowerShell command, and why.
$LearnText = @{
    'self'     = @('(nothing to click)', 'Get-Command Get-Process | Format-List CommandType,Source',
                   'a planted profile or module can swap a command for a fake that hides things. -NoProfile stops that.')
    'last'     = @('File Explorer: C:\ProgramData\bk, open two snapshot folders and compare a file', 'Compare-Object (Get-Content old\services.txt) (Get-Content new\services.txt)',
                   'shows only the newest changes, so what red team did 10 minutes ago is not buried under the morning.')
    'files'    = @('File Explorer: C:\Windows\System32, View > Details, sort by Date modified', 'Get-ChildItem C:\Windows\System32 -File | Sort-Object LastWriteTime -Descending | Select-Object -First 10',
                   'new programs and scripts in system and user folders are how tools and backdoors arrive.')
    'events'   = @('Event Viewer > Windows Logs > Security > Filter Current Log > type 4720,4732,1102', 'Get-WinEvent -FilterHashtable @{LogName=''Security''; Id=4720}',
                   'Windows writes down new accounts, group changes, new services and cleared logs. Reports ask for these.')
    'base'     = @('File Explorer: compare C:\ProgramData\bk\baseline with the newest snapshot folder', 'Compare-Object (Get-Content baseline\services.txt) (Get-Content <newest>\services.txt)',
                   'everything that changed since the start of the game. Long by now; read part 1 first.')
    'rat'      = @('Task Manager > Details; services.msc; Settings > Apps', 'Get-Process; Get-Service',
                   'a remote-access tool is a way back in that survives password changes. It was the way in at the invitational.')
    'c2'       = @('Resource Monitor (resmon) > Network > TCP Connections', 'Get-NetTCPConnection -State Established',
                   'an agent has to call home. A program that keeps calling the same outside address is the one to check.')
    'progs'    = @('Task Manager > Details > right-click a program > Properties > Digital Signatures', 'Get-AuthenticodeSignature C:\path\to\program.exe',
                   'Windows and real software are signed. An unsigned program in a user or temp folder is how most tools arrive.')
    'cmdline'  = @('Task Manager > Details > right-click the column headers > Select columns > Command line', 'Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,CommandLine',
                   'red team hides commands in encoded PowerShell, and runs shells from the web server or SQL server.')
    'svc'      = @('services.msc > double-click a service > Path to executable', 'Get-CimInstance Win32_Service | Select-Object Name,State,PathName',
                   'a fake service gets a normal-sounding name. Where its program lives gives it away.')
    'drivers'  = @('msinfo32 > Software Environment > System Drivers', 'Get-CimInstance Win32_SystemDriver | Select-Object Name,State,PathName',
                   'a driver runs inside Windows itself. A rootkit is usually a driver.')
    'tasks'    = @('Task Scheduler (taskschd.msc) > Task Scheduler Library > Actions tab', 'Get-ScheduledTask | Select-Object TaskName,TaskPath,State',
                   'a scheduled task brings a backdoor back after you remove it.')
    'persist'  = @('regedit > HKLM\SYSTEM\CurrentControlSet\Control\Lsa (and the other keys named below)', 'Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
                   'these registry spots load a DLL into Windows at logon or boot. Password stealers and logon-screen backdoors live here.')
    'wmi'      = @('(no built-in window; use PowerShell)', 'Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer',
                   'a WMI subscription runs a command when something happens, with no Run key and no task to find.')
    'profiles' = @('File Explorer: C:\Windows\System32\WindowsPowerShell\v1.0 (look for profile.ps1)', 'Test-Path $PROFILE.AllUsersAllHosts',
                   'a profile runs every time PowerShell starts, and can swap commands for fakes.')
    'defender' = @('Windows Security > Virus and threat protection > Manage settings, and Exclusions', 'Get-MpComputerStatus; Get-MpPreference | Select-Object Exclusion*',
                   'red team turns Defender off or adds an exclusion for their folder (T1562.001).')
    'firewall' = @('wf.msc (Windows Defender Firewall with Advanced Security)', 'Get-NetFirewallProfile | Select-Object Name,Enabled',
                   'a firewall that is off, or a new allow rule, opens the door. A new block rule can take a scored service down.')
    'rootkit'  = @('Task Manager vs Resource Monitor; services.msc vs regedit HKLM\SYSTEM\CurrentControlSet\Services', 'Get-Process vs Get-CimInstance Win32_Process; netstat -ano vs Get-NetTCPConnection',
                   'a rootkit can fool one way of looking, rarely all of them. When two views disagree, something is hiding.')
    'accounts' = @('lusrmgr.msc (on a DC: Active Directory Users and Computers)', 'Get-LocalUser | Select-Object Name,Enabled,PasswordRequired',
                   'an enabled Guest, an account with no password, or a new admin is a quiet way back in.')
    'logins'   = @('Task Manager > Users; Computer Management > Shared Folders > Sessions', 'quser; Get-SmbSession; Get-NetTCPConnection -LocalPort 3389 -State Established',
                   'red team logs in with real accounts (T1078). Know who is on your box, and from where.')
    'bits'     = @('(no built-in window; use PowerShell)', 'Get-BitsTransfer -AllUsers',
                   'BITS downloads files in the background and can run a command when it is done (T1197).')
    'ads'      = @('(File Explorer hides them; in cmd: dir /r)', 'Get-Item C:\Users\Public\file.txt -Stream *',
                   'a file can hide a second file inside it (an alternate data stream). Tools get hidden this way (T1564.004).')
    'web'      = @('IIS Manager > Sites > Explore; or open C:\inetpub\wwwroot', 'Select-String -Path C:\inetpub\wwwroot\*.aspx -Pattern Process.Start',
                   'a web shell runs any command typed into a web page, as the web server account.')
    'ransom'   = @('File Explorer: look for .locked or .encrypted files and ransom notes', 'vssadmin list shadows',
                   'locked files and deleted shadow copies (T1486, T1490) mean you need your backups now.')
    'dc'       = @('Active Directory Users and Computers > right-click the domain > Find', 'Search-ADAccount -LockedOut; Get-ADUser Administrator',
                   'locked-out users and a disabled Administrator mean red team is going after accounts (T1110, T1531).')
    'kerberos' = @('Event Viewer > Security > Filter: 4769, then look for Ticket Encryption Type 0x17', 'Get-WinEvent -FilterHashtable @{LogName=''Security''; Id=4769} -MaxEvents 20',
                   'many RC4 (0x17) service tickets for real accounts is Kerberoasting (T1558.003), from your AD session.')
    'bait'     = @('Event Viewer > Security > Filter: 4663', 'Get-WinEvent -FilterHashtable @{LogName=''Security''; Id=4663} -MaxEvents 20',
                   'nobody on your team opens the bait. If someone did, it was red team, and the log says which account and program.')
    'spam'     = @('Event Viewer > Applications and Services Logs > Microsoft > Windows > TerminalServices-RemoteConnectionManager > Operational', 'Get-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'' | Select-Object AllowRemoteRPC',
                   'msg.exe floods every session with pop-ups, and RDP shadowing lets someone watch your screen while you type passwords.')
    'audit'    = @('Event Viewer > Security (empty or tiny means auditing is off)', 'auditpol /get /category:*',
                   'with auditing off, Windows writes down nothing for you to hunt.')
    'clock'    = @('the clock in the taskbar ; ncpa.cpl > the adapter > Properties > IPv4 > Advanced (every address)', 'w32tm /query /status ; Get-NetIPAddress -AddressFamily IPv4',
                   'Kerberos refuses a login when clocks differ by 5 minutes, and the packet must list every address the box answers on.')
    'gpofiles' = @('Group Policy Management > a GPO > Settings tab > Preferences > Scheduled Tasks, and Scripts (Startup/Shutdown)', 'Get-ChildItem \\$env:USERDNSDOMAIN\SYSVOL -Recurse -Include ScheduledTasks.xml,scripts.ini',
                   'a task inside a Group Policy runs as SYSTEM on every computer, and never shows in the DC''s own task list.')
    'iismod'   = @('inetmgr > the server > Modules', '& $env:windir\System32\inetsrv\appcmd.exe list modules',
                   'a module sees every web request. The site keeps working, so the scoreboard stays green while it runs commands.')
    'db'       = @('SQL Server Management Studio > Security > Logins ; Server Objects > Linked Servers', 'sqlcmd -E -Q "select name from sys.server_principals where is_srvrolemember(''sysadmin'', name) = 1"',
                   'a SQL admin login or xp_cmdshell survives every Windows password change.')
    'tamper'   = @('Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational (greyed out = off)', '$env:PSModulePath -split ";"   and   Get-ChildItem HKLM:\SOFTWARE\Microsoft\AMSI\Providers',
                   'red team read this script. The quiet move is not to hide from it, but to blind Windows underneath it.')
    'udp'      = @('Resource Monitor (resmon) > Network > Listening Ports, Protocol column', 'Get-NetUDPEndpoint ; netsh interface portproxy show all ; [IO.Directory]::GetFiles("\\.\pipe\")',
                   'C2 does not need TCP. UDP, a port forward or a named pipe carries it past a TCP-only check.')
    'masq'     = @('File Explorer: right-click the program > Properties > Details > Original filename', '(Get-Item <path>).VersionInfo.OriginalFilename',
                   'renaming a file does not change the name stored inside it.')
    'advuln'   = @('ADUC: a user > Attribute Editor > servicePrincipalName ; Account tab > "Do not require Kerberos preauthentication"', 'Get-ADUser -Filter * -Properties ServicePrincipalName,DoesNotRequirePreAuth | Format-Table Name,ServicePrincipalName,DoesNotRequirePreAuth',
                   'these are the first things red team looks for with one normal account. Each one fixed is a path to Domain Admin closed.')
    'adevents' = @('Event Viewer > Security > Filter Current Log > 4769 (look for Ticket Encryption Type 0x17)', 'Get-EventLog Security -InstanceId 4769 -Message "*0x17*" -Newest 10',
                   'last year we were Kerberoasted and nobody saw it. It was in this log the whole time.')
    'plumbing' = @('services.msc: sort by the "Log On As" column', 'Get-CimInstance Win32_Service | Where-Object { $_.StartName -notmatch "Local|NT " } | Format-Table Name,StartName',
                   'at Invitational 2 one changed password broke several scored services at once.')
    'decoy'    = @('Event Viewer > Security > Filter Current Log > 4663', 'Get-EventLog Security -InstanceId 4663 -Newest 20',
                   'nothing real opens a decoy, so any open is someone searching the box for passwords.')
    'domain'   = @('Server Manager > Local Server: the Domain line ; a DC: Tools > Active Directory Users and Computers opens without an error', 'Test-ComputerSecureChannel ; nltest /dsgetdc:<domain> ; w32tm /query /status',
                   'a box in the domain fails when AD fails. Fix the DC, DNS or the clock once instead of ten services.')
    'trip'     = @('Windows Firewall with Advanced Security > Properties > Logging', 'Get-Content C:\Windows\System32\LogFiles\Firewall\pfirewall.log -Tail 30',
                   'one address knocking on many closed ports is a scan. That is red team looking around.')
    'bugs'     = @('Settings > Windows Update > Update history (newest date)', 'Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 3',
                   'red team scans for famous old holes and default settings first.')
}
function Show-Learn {
    param([string]$Key)
    $t = $LearnText[$Key]
    if (-not $t) { return }
    Write-Host ('  [learn] click: ' + $t[0]) -ForegroundColor DarkCyan
    Write-Host ('  [learn] type:  ' + $t[1]) -ForegroundColor DarkCyan
    Write-Host ('  [learn] why:   ' + $t[2]) -ForegroundColor DarkCyan
}

# ---------------------------------------------------------------------------
# basics
# ---------------------------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-Role {
    if ($Role -ne 'auto') { return $Role }
    # Win32_OperatingSystem ProductType: 1 = workstation, 2 = domain controller, 3 = server
    switch ((Get-CimInstance Win32_OperatingSystem).ProductType) {
        2       { return 'dc' }
        3       { return 'server' }
        default { return 'desktop' }
    }
}

function UtcNow { return (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC' }

# Only Administrators and SYSTEM may open the vault. ProgramData lets every user
# read new folders by default, and the vault holds the baseline, notes and bait.
function Lock-Vault {
    $acl = Get-Acl -Path $Vault
    if (-not $acl) { return }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
    foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {
        $who = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Vault -AclObject $acl
}

# A short fingerprint of a snapshot folder, like 3f9a-21c0-77de. Write the
# baseline's on paper. If it ever changes, someone edited the baseline.
function Get-Seal {
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path $Dir)) { return 'none' }
    $lines = Get-ChildItem -Path $Dir -File -Recurse -Force | Sort-Object FullName | ForEach-Object {
        (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash + ' ' + $_.FullName.Substring($Dir.Length)
    }
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($lines -join "`n")))
    $hex   = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    return ($hex.Substring(0,4) + '-' + $hex.Substring(4,4) + '-' + $hex.Substring(8,4))
}

# Red team can read this script, so they know which commands it uses. A planted
# PowerShell profile or module can replace one with a fake that hides things.
function Test-Hijack {
    $names = 'Get-CimInstance','Get-NetTCPConnection','Get-NetUDPEndpoint','Get-NetFirewallRule','Get-NetFirewallProfile',
             'Get-ScheduledTask','Get-ItemProperty','Get-ChildItem','Get-Item','Get-FileHash','Get-LocalUser',
             'Get-LocalGroupMember','Get-Process','Get-Service','Get-Content','Get-Acl','Set-Acl','Get-WinEvent',
             'Get-AuthenticodeSignature','Get-MpPreference','Get-MpComputerStatus','Get-MpThreatDetection',
             'Get-SmbSession','Get-SmbShare','Get-BitsTransfer','Get-ADUser','Get-ADGroupMember','Get-ADComputer',
             'Get-ADObject','Search-ADAccount','Compare-Object','Select-Object','Where-Object','Sort-Object',
             'ForEach-Object','Group-Object','Format-Table','Out-String','Write-Host','Test-Path','Set-Content',
             'Add-Content','Copy-Item','New-NetFirewallRule','Remove-NetFirewallRule','Start-Transcript'
    $bad = @()
    foreach ($n in $names) {
        $c = Get-Command $n -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $c) { continue }
        if ($c.CommandType -eq 'Alias') { $bad += ($n + ' (an alias for ' + $c.Definition + ')'); continue }
        if ($c.CommandType -eq 'Function' -and -not $c.ModuleName) { $bad += ($n + ' (defined in this window)'); continue }
        $base = ''
        if ($c.Module) { $base = [string]$c.Module.ModuleBase }
        if ($base -and $base -notlike "$env:windir\*" -and $base -notlike "$PSHOME*") { $bad += ($n + ' (loaded from ' + $base + ')') }
    }
    return $bad
}

# ---------------------------------------------------------------------------
# addresses: checking them, your networks, and the saved block list
# ---------------------------------------------------------------------------
function Test-IPv4 {
    param([string]$Text)
    $parts = $Text -split '/'
    if ($parts.Count -gt 2) { return $false }
    if ($parts[0] -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    foreach ($o in ($parts[0] -split '\.')) { if ([int]$o -gt 255) { return $false } }
    if ($parts.Count -eq 2 -and -not ($parts[1] -match '^\d{1,2}$' -and [int]$parts[1] -le 32)) { return $false }
    return $true
}

# is the IPv4 address $Addr inside $Net (an address, or address/bits)?
function Test-InNet {
    param([string]$Addr, [string]$Net)
    $p = $Net -split '/'
    $bits = 32
    if ($p.Count -eq 2) { $bits = [int]$p[1] }
    $x = $null; $y = $null
    if (-not [System.Net.IPAddress]::TryParse($Addr, [ref]$x)) { return $false }
    if (-not [System.Net.IPAddress]::TryParse($p[0], [ref]$y)) { return $false }
    if ($x.AddressFamily -ne 'InterNetwork' -or $y.AddressFamily -ne 'InterNetwork') { return $false }
    $xb = $x.GetAddressBytes(); [Array]::Reverse($xb)
    $yb = $y.GetAddressBytes(); [Array]::Reverse($yb)
    $xi = [int64][BitConverter]::ToUInt32($xb, 0)
    $yi = [int64][BitConverter]::ToUInt32($yb, 0)
    if ($bits -eq 0) { return $true }
    $mask = [int64]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $bits))
    return (($xi -band $mask) -eq ($yi -band $mask))
}

# outside your networks? (no networks saved: never marked; IPv6: not compared)
function Test-Outside {
    param([string]$Addr)
    if ($script:Nets.Count -eq 0) { return $false }
    $a = ([string]$Addr) -replace '^::ffff:', ''
    if ($a -match ':' -or -not $a) { return $false }
    foreach ($n in $script:Nets) { if (Test-InNet $a $n) { return $false } }
    return $true
}

function Get-BlockList {
    if (-not (Test-Path $BlockFile)) { return @() }
    return @(Get-Content $BlockFile | ForEach-Object { ($_ -split '\s+')[0] } | Where-Object { $_ } | Sort-Object -Unique)
}

# ---------------------------------------------------------------------------
# programs: where a command line's program is, signatures, risky folders
# ---------------------------------------------------------------------------
function Get-ExeFromCmd {
    param([string]$Cmd)
    if (-not $Cmd) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim())
    if ($c.StartsWith('"')) {
        $e = $c.IndexOf('"', 1)
        if ($e -gt 0) { $c = $c.Substring(1, $e - 1) }
    } elseif ($c -match '^(?i)(.+?\.(exe|sys|dll|com|bat|cmd|ps1|vbs|js))(\s|$)') {
        $c = $Matches[1]
    } else {
        $c = ($c -split ' ')[0]
    }
    $c = $c -replace '^\\\?\?\\', ''
    $c = $c -replace '^(?i)\\SystemRoot\\', ($env:windir + '\')
    if ($c -match '^(?i)system32\\') { $c = Join-Path $env:windir $c }
    return $c
}

# Signature status of a file, remembered in the vault by path, size and date so
# later hunts do not check every file again.
$script:SigCache = $null
function Get-SigStatus {
    param([string]$File)
    if (-not $File -or -not (Test-Path -LiteralPath $File)) { return 'Missing' }
    if ($null -eq $script:SigCache) {
        $script:SigCache = @{}
        $cf = Join-Path $Vault '.sigcache.txt'
        if (Test-Path $cf) { foreach ($l in (Get-Content $cf)) { $k = $l.LastIndexOf('|'); if ($k -gt 0) { $script:SigCache[$l.Substring(0, $k)] = $l.Substring($k + 1) } } }
    }
    $fi = Get-Item -LiteralPath $File -Force
    $key = $File.ToLower() + '|' + $fi.Length + '|' + $fi.LastWriteTimeUtc.Ticks
    if ($script:SigCache.ContainsKey($key)) { return $script:SigCache[$key] }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $st = [string](Get-AuthenticodeSignature -LiteralPath $File).Status
    if ($sw.Elapsed.TotalSeconds -gt 6 -and -not $script:SigSlowTold) {
        $script:SigSlowTold = $true
        Say '  (signature checks are slow: Windows is waiting for a certificate download that cannot arrive without internet. Results are saved, so the next run is fast. To stop the waiting: harden, step "certificate lists".)'
    }
    if (-not $st) { $st = 'Unknown' }
    $script:SigCache[$key] = $st
    Add-Content -Path (Join-Path $Vault '.sigcache.txt') -Value ($key + '|' + $st)
    return $st
}

$script:BadPath = @('\temp\', '\tmp\', '\appdata\', '\users\public\', '\programdata\', '\downloads\', '\$recycle.bin\', '\perflogs\', '\windows\tasks\', '\windows\debug\', '\windows\fonts\')
function Test-UserWritable {
    param([string]$P)
    $low = ([string]$P).ToLower()
    if ($low -like '*\programdata\microsoft\windows defender\*') { return $false }
    foreach ($b in $script:BadPath) { if ($low.Contains($b)) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------
# events: "what happened since the last hunt" straight from the Windows logs
# ---------------------------------------------------------------------------
function XSince {
    param([int[]]$Ids, [datetime]$Since, [string]$Extra = '')
    $ms = [int64]((Get-Date) - $Since).TotalMilliseconds
    if ($ms -lt 60000) { $ms = 60000 }
    $idq = ($Ids | ForEach-Object { 'EventID=' + $_ }) -join ' or '
    $q = '*[System[(' + $idq + ') and TimeCreated[timediff(@SystemTime) <= ' + $ms + ']]]'
    if ($Extra) { $q += ' and *[EventData[' + $Extra + ']]' }
    return $q
}
function Get-Evt {
    param([string]$Log, [string]$XPath, [int]$Max = 500)
    try { return @(Get-WinEvent -LogName $Log -FilterXPath $XPath -MaxEvents $Max -ErrorAction Stop) } catch { return @() }
}
function EvMap {
    param($E)
    $h = @{}
    try { $x = [xml]$E.ToXml(); foreach ($d in @($x.Event.EventData.Data)) { if ($d.Name) { $h[[string]$d.Name] = [string]$d.'#text' } } } catch {}
    $h['Time'] = $E.TimeCreated
    return $h
}
function EvData {
    param($E, [string]$Name)
    try {
        $x = [xml]$E.ToXml()
        foreach ($d in @($x.Event.EventData.Data)) { if ($d.Name -eq $Name) { return [string]$d.'#text' } }
        $n = $x.SelectSingleNode("//*[local-name()='" + $Name + "']")
        if ($n) { return [string]$n.InnerText }
    } catch {}
    return ''
}

# ---------------------------------------------------------------------------
# listening ports with the program and account behind each one
# ---------------------------------------------------------------------------
# For a Windows service the account is its logon account: LocalSystem,
# NT AUTHORITY\NetworkService, NT SERVICE\..., or a real account like
# DOMAIN\svc_sql. Real accounts that run services are what Kerberoasting targets.
# TCP: every listener. UDP: well-known ports only (under 1024), because a DNS
# server alone opens thousands of high UDP ports.
function Get-ListenInfo {
    param([switch]$NoPid)
    $svcByPid = @{}
    foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 })) {
        $k = [int]$s.ProcessId
        if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = @() }
        $svcByPid[$k] += $s
    }
    $procById = @{}
    foreach ($p in @(Get-CimInstance Win32_Process)) { $procById[[int]$p.ProcessId] = $p }
    $ends = @()
    $ends += @(Get-NetTCPConnection -State Listen | ForEach-Object {
        [pscustomobject]@{ Proto = 'TCP'; Address = $_.LocalAddress; Port = [int]$_.LocalPort; ProcId = [int]$_.OwningProcess } })
    $ends += @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 1024 } | ForEach-Object {
        [pscustomobject]@{ Proto = 'UDP'; Address = $_.LocalAddress; Port = [int]$_.LocalPort; ProcId = [int]$_.OwningProcess } })
    $rows = @()
    foreach ($e in $ends) {
        $svcs = $svcByPid[$e.ProcId]
        $proc = $procById[$e.ProcId]
        $acct = ''
        if ($e.ProcId -eq 4) {
            $acct = 'SYSTEM (kernel)'        # PID 4: SMB 445, WinRM 5985 and other HTTP.sys ports
        } elseif ($svcs) {
            $acct = (@($svcs | ForEach-Object { $_.StartName }) | Sort-Object -Unique) -join ', '
        } elseif ($proc) {
            $o = Invoke-CimMethod -InputObject $proc -MethodName GetOwner
            if ($o -and $o.User) { if ($o.Domain) { $acct = $o.Domain + '\' + $o.User } else { $acct = $o.User } }
        }
        $row = [ordered]@{ Proto = $e.Proto; Port = $e.Port; Address = $e.Address }
        if (-not $NoPid) { $row['PID'] = $e.ProcId }
        if ($proc) { $row['Process'] = $proc.Name } else { $row['Process'] = '?' }
        if ($svcs) { $row['Service'] = (@($svcs | ForEach-Object { $_.Name }) | Sort-Object) -join ', ' } else { $row['Service'] = '' }
        if ($acct) { $row['Account'] = $acct } else { $row['Account'] = '?' }
        $rows += [pscustomobject]$row
    }
    $rows | Sort-Object Proto, Port, Address
}

# True when an account is a real user account rather than a built-in one.
function Test-RealAccount {
    param([string]$Account)
    if (-not $Account -or $Account -eq '?') { return $false }
    foreach ($a in ($Account -split ', ')) {
        if ($a -notmatch '^(LocalSystem|SYSTEM \(kernel\)|NT AUTHORITY\\.*|NT SERVICE\\.*|IIS APPPOOL\\.*|Window Manager\\.*|Font Driver Host\\.*)$') { return $true }
    }
    return $false
}

function Get-LocalAdmins {
    $m = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + ' | ' + $_.ObjectClass + ' | ' + $_.PrincipalSource })
    if ($m.Count -eq 0) {
        # domain controllers: read the built-in Administrators group with net.exe instead
        $m = @(net localgroup Administrators 2>$null | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' })
    }
    $m | Sort-Object
}

# ---------------------------------------------------------------------------
# snapshot: one text file per item, one line per thing, so a change is one line.
# hunt compares these with the last hunt and with the baseline.
# ---------------------------------------------------------------------------
function New-Snapshot {
    $script:stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:SnapDir = Join-Path $Vault $script:stamp
    New-Item -ItemType Directory -Force -Path $script:SnapDir | Out-Null
}

function Snap {
    param([string]$Name, [scriptblock]$Block)
    $file = Join-Path $script:SnapDir ($Name + '.txt')
    try {
        $out = @(& $Block 2>$null | ForEach-Object { [string]$_ })
        Set-Content -Path $file -Value $out -Encoding UTF8
    } catch {
        Set-Content -Path $file -Value ('ERROR collecting ' + $Name + ': ' + $_.Exception.Message) -Encoding UTF8
    }
}

function Get-Autoruns {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices')
    # every user who is logged in or has their registry loaded
    foreach ($sid in @(Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | Select-Object -ExpandProperty PSChildName)) {
        $keys += ('Registry::HKEY_USERS\' + $sid + '\Software\Microsoft\Windows\CurrentVersion\Run')
        $keys += ('Registry::HKEY_USERS\' + $sid + '\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    }
    foreach ($k in $keys) {
        $p = Get-ItemProperty $k
        if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' } | ForEach-Object { $k + ' | ' + $_.Name + ' | ' + $_.Value } }
    }
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    $folders += @(Resolve-Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' | ForEach-Object { $_.Path })
    foreach ($f in $folders) {
        Get-ChildItem -Path $f -File -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { 'Startup folder | ' + $_.FullName }
    }
}

function Get-PersistSpots {
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    'Winlogon Shell | ' + $wl.Shell
    'Winlogon Userinit | ' + $wl.Userinit
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $ai = Get-ItemProperty $k
        if ($ai) { 'AppInit_DLLs | ' + $k + ' | ' + $ai.AppInit_DLLs + ' | load=' + $ai.LoadAppInit_DLLs }
    }
    $ac = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if ($ac) { $ac.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { 'AppCertDlls | ' + $_.Name + ' | ' + $_.Value } }
    'BootExecute | ' + ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').BootExecute -join ';')
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    'LSA Security Packages | ' + ($lsa.'Security Packages' -join ';')
    'LSA OSConfig Security Packages | ' + ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig').'Security Packages' -join ';')
    'LSA Authentication Packages | ' + ($lsa.'Authentication Packages' -join ';')
    'LSA Notification Packages | ' + ($lsa.'Notification Packages' -join ';')
    'LSA RunAsPPL | ' + $lsa.RunAsPPL
    'LSA DsrmAdminLogonBehavior | ' + $lsa.DsrmAdminLogonBehavior
    'WDigest UseLogonCredential | ' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
    $ns = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh'
    if ($ns) { $ns.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { 'Netsh helper | ' + $_.Name + ' | ' + $_.Value } }
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object { 'Print monitor | ' + $_.PSChildName + ' | ' + (Get-ItemProperty $_.PSPath).Driver }
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' | ForEach-Object { 'Time provider | ' + $_.PSChildName + ' | ' + (Get-ItemProperty $_.PSPath).DllName }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        if ($p.Debugger) { 'IFEO Debugger | ' + $_.PSChildName + ' | ' + $p.Debugger }
        if ($p.GlobalFlag -and (([int]$p.GlobalFlag) -band 0x200)) { 'IFEO SilentProcessExit flag | ' + $_.PSChildName }
    }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        if ($p.MonitorProcess) { 'SilentProcessExit MonitorProcess | ' + $_.PSChildName + ' | ' + $p.MonitorProcess }
    }
    foreach ($f in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $fp = Join-Path "$env:windir\System32" $f
        if (Test-Path $fp) { 'Accessibility program | ' + $f + ' | ' + (Get-FileHash $fp -Algorithm SHA256).Hash.Substring(0, 16) }
    }
}

function Get-WmiPersist {
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | ForEach-Object { 'Filter | ' + $_.Name + ' | ' + $_.Query }
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ForEach-Object {
        $what = $_.CommandLineTemplate
        if (-not $what) { $what = $_.ScriptText }
        if (-not $what) { $what = $_.ScriptFileName }
        if (-not $what) { $what = $_.ExecutablePath }
        'Consumer | ' + $_.CimClass.CimClassName + ' | ' + $_.Name + ' | ' + (([string]$what) -replace "`r?`n", ' ')
    }
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | ForEach-Object { 'Binding | ' + [string]$_.Filter + ' | ' + [string]$_.Consumer }
}

function Collect-Common {
    Head 'saving a snapshot of this box'
    Set-Content -Path (Join-Path $script:SnapDir 'stamp.txt') -Value ('first30 snapshot of ' + $env:COMPUTERNAME + ' at ' + (UtcNow))

    Snap 'localusers' {
        $u = @(Get-LocalUser)
        if ($u.Count -gt 0) {
            $u | Sort-Object Name | ForEach-Object { $_.Name + ' | enabled=' + $_.Enabled + ' | password-required=' + $_.PasswordRequired + ' | password-set=' + $_.PasswordLastSet + ' | ' + $_.SID }
        } else {
            net user 2>$null | Select-Object -Skip 4 | Where-Object { $_ -and $_ -notmatch 'command completed' }
        }
    }
    Snap 'localadmins' { Get-LocalAdmins }
    Snap 'privgroups' {
        foreach ($g in 'Administrators', 'Remote Desktop Users', 'Remote Management Users', 'Backup Operators', 'Power Users', 'Event Log Readers', 'Hyper-V Administrators') {
            Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | ForEach-Object { $g + ' | ' + $_.Name }
        }
    }
    # Services: the state only for automatic ones (a stopped automatic service is
    # news; manual ones start and stop all day). Per-user copies like
    # CDPUserSvc_4f2a1 come and go with every logon, so they are left out.
    Snap 'services' {
        Get-CimInstance Win32_Service | Where-Object { $_.Name -notmatch '_[0-9a-f]{4,8}$' } | Sort-Object Name | ForEach-Object {
            $st = ''
            if ($_.StartMode -eq 'Auto') { $st = $_.State }
            $_.Name + ' | ' + $_.StartMode + ' ' + $st + ' | ' + $_.StartName + ' | ' + $_.PathName
        }
    }
    Snap 'drivers'     { Get-CimInstance Win32_SystemDriver | Sort-Object Name | ForEach-Object { $_.Name + ' | ' + $_.StartMode + ' | ' + $_.PathName } }
    Snap 'tasks' {
        Get-ScheduledTask | Sort-Object TaskPath, TaskName | ForEach-Object {
            $st = [string]$_.State
            if ($st -eq 'Running') { $st = 'Ready' }
            $act = ($_.Actions | ForEach-Object { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() }) -join '; '
            $_.TaskPath + $_.TaskName + ' | ' + $st + ' | ' + $act
        }
    }
    Snap 'listening'   { Get-ListenInfo -NoPid | ForEach-Object { $_.Proto + ' ' + $_.Port + ' ' + $_.Address + ' | ' + $_.Process + ' | ' + $_.Service + ' | ' + $_.Account } }
    Snap 'autoruns'    { Get-Autoruns }
    Snap 'persist'     { Get-PersistSpots }
    Snap 'wmi_persist' { Get-WmiPersist }
    Snap 'hostsfile'   { Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -and $_ -notmatch '^\s*#' } }
    Snap 'netcfg' {
        Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { 'DNS servers | ' + $_.InterfaceAlias + ' | ' + ($_.ServerAddresses -join ',') }
        'WinHTTP proxy | ' + (((netsh winhttp show proxy) -join ' ') -replace '\s+', ' ').Trim()
        'Machine proxy | ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
    }
    Snap 'fwrules'     { Get-NetFirewallRule | Sort-Object DisplayName, Direction | ForEach-Object { $_.DisplayName + ' | ' + $_.Direction + ' | ' + $_.Action + ' | enabled=' + $_.Enabled + ' | ' + $_.Profile } }
    Snap 'fwprofiles'  { Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { $_.Name + ' | enabled=' + $_.Enabled + ' | in=' + $_.DefaultInboundAction + ' | out=' + $_.DefaultOutboundAction + ' | local-rules=' + $_.AllowLocalFirewallRules } }
    # Defender settings red team changes to hide their tools (T1562.001)
    Snap 'defender' {
        $mp = Get-MpPreference
        'ExclusionPath | ' + ($mp.ExclusionPath -join '; ')
        'ExclusionProcess | ' + ($mp.ExclusionProcess -join '; ')
        'ExclusionExtension | ' + ($mp.ExclusionExtension -join '; ')
        'ExclusionIpAddress | ' + ($mp.ExclusionIpAddress -join '; ')
        'DisableRealtimeMonitoring | ' + $mp.DisableRealtimeMonitoring
        $st = Get-MpComputerStatus
        if ($st) {
            'RealTimeProtectionEnabled | ' + $st.RealTimeProtectionEnabled
            'AntivirusEnabled | ' + $st.AntivirusEnabled
            'BehaviorMonitorEnabled | ' + $st.BehaviorMonitorEnabled
            'IsTamperProtected | ' + $st.IsTamperProtected
        }
    }
    # shadow copies, so deleting them shows (T1490)
    Snap 'shadowcopies' { 'shadow copies: ' + @(Get-CimInstance Win32_ShadowCopy).Count }
    Snap 'shares'       { Get-SmbShare | Sort-Object Name | ForEach-Object { $_.Name + ' | ' + $_.Path } }
    Snap 'software' {
        $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        Get-ItemProperty $keys | Where-Object DisplayName | Sort-Object DisplayName | ForEach-Object { $_.DisplayName + ' | ' + $_.DisplayVersion }
    }
    Snap 'bits' { Get-BitsTransfer -AllUsers | ForEach-Object { $_.DisplayName + ' | ' + $_.OwnerAccount + ' | ' + (@($_.FileList) | Select-Object -First 1).RemoteName } }

    # kept for the record, never compared (they change all the time)
    Snap 'processes'   { Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine | Format-List | Out-String -Width 4096 }
    Snap 'connections' { Get-NetTCPConnection -State Established | Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table -AutoSize | Out-String -Width 4096 }
    Snap 'hotfixes'    { Get-HotFix | Select-Object HotFixID, InstalledOn | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String -Width 4096 }
    Snap 'posture' {
        'SMBv1 enabled : ' + (Get-SmbServerConfiguration).EnableSMB1Protocol
        'LSA RunAsPPL  : ' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').RunAsPPL + '    (1 = LSASS protected against credential theft)'
        'RDP NLA       : ' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
        '--- audit policy (must be ON or Windows writes no events to hunt) ---'
        auditpol /get /category:* 2>$null
    }
    Say ('  saved in ' + $script:SnapDir)
}

function Collect-DC {
    Head 'saving the domain snapshot (domain controller)'
    $haveAD = $null -ne (Get-Module -ListAvailable ActiveDirectory)
    if ($haveAD) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue }
    if (-not $haveAD) {
        Warn 'ActiveDirectory module not present; using net.exe instead'
        Snap 'ad_privgroups' { foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins') { net group $g /domain 2>$null | Select-Object -Skip 8 | Where-Object { $_ -and $_ -notmatch 'command completed' } | ForEach-Object { $g + ' | ' + $_.Trim() } } }
        Snap 'ad_users' { net user /domain 2>$null }
        return
    }
    Snap 'ad_privgroups' {
        foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators',
                       'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Protected Users', 'Remote Desktop Users') {
            Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue | ForEach-Object { $g + ' | ' + $_.SamAccountName + ' | ' + $_.objectClass }
        }
    }
    Snap 'ad_users'  { Get-ADUser -Filter * -Properties whenCreated | Sort-Object SamAccountName | ForEach-Object { $_.SamAccountName + ' | enabled=' + $_.Enabled + ' | created=' + $_.whenCreated } }
    Snap 'ad_spn'    { Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes' | ForEach-Object { $_.SamAccountName + ' | ' + ($_.ServicePrincipalName -join ';') + ' | enc=' + $_.'msDS-SupportedEncryptionTypes' } }
    Snap 'ad_asrep'  { Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | ForEach-Object { $_.SamAccountName } }
    Snap 'ad_delegation' {
        Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | ForEach-Object { 'unconstrained | ' + $_.Name }
        Get-ADObject -Filter 'msDS-AllowedToDelegateTo -like "*"' -Properties 'msDS-AllowedToDelegateTo' | ForEach-Object { 'constrained | ' + $_.Name + ' | ' + ($_.'msDS-AllowedToDelegateTo' -join ';') }
        Get-ADObject -Filter 'msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"' | ForEach-Object { 'resource-based | ' + $_.Name }
    }
    Snap 'ad_adminsdholder' {
        $d = (Get-ADDomain).DistinguishedName
        (Get-Acl ('AD:\CN=AdminSDHolder,CN=System,' + $d)).Access | ForEach-Object { [string]$_.IdentityReference + ' | ' + $_.ActiveDirectoryRights + ' | ' + $_.AccessControlType }
    }
    Snap 'ad_replrights' {
        $d = (Get-ADDomain).DistinguishedName
        (Get-Acl ('AD:\' + $d)).Access | Where-Object { $_.ObjectType -match '1131f6a' } | ForEach-Object { [string]$_.IdentityReference + ' | ' + $_.ActiveDirectoryRights + ' | ' + $_.ObjectType }
    }
    Snap 'ad_gpos'   { Get-GPO -All | Sort-Object DisplayName | ForEach-Object { $_.DisplayName + ' | ' + $_.Id + ' | changed ' + $_.ModificationTime } }
    Snap 'ad_krbtgt' { $k = Get-ADUser krbtgt -Properties pwdLastSet; 'krbtgt password set | ' + [datetime]::FromFileTime($k.pwdLastSet) }
    Snap 'ad_risky' {
        Get-ADUser -Filter 'PasswordNotRequired -eq $true' | ForEach-Object { 'password not required | ' + $_.SamAccountName }
        Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true' | ForEach-Object { 'reversible password | ' + $_.SamAccountName }
        Get-ADUser -LDAPFilter '(sIDHistory=*)' | ForEach-Object { 'has SID history | ' + $_.SamAccountName }
    }
    Snap 'ad_trusts' { Get-ADTrust -Filter * | ForEach-Object { $_.Name + ' | ' + $_.Direction + ' | ' + $_.TrustType } }
    # kept for the record
    Snap 'ad_dclist' { Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem, IsGlobalCatalog | Format-Table -AutoSize | Out-String -Width 4096 }
    Snap 'ad_recentobjects' { $cut = (Get-Date).AddDays(-2); Get-ADObject -Filter 'whenCreated -gt $cut' -Properties whenCreated | Select-Object Name, ObjectClass, whenCreated | Sort-Object whenCreated | Format-Table -AutoSize | Out-String -Width 4096 }
}

# the items hunt compares, with plain names
$DiffItems = [ordered]@{
    'localusers' = 'Local users'; 'localadmins' = 'Local Administrators'; 'privgroups' = 'Privileged local groups'
    'services' = 'Services'; 'drivers' = 'Drivers'; 'tasks' = 'Scheduled tasks'; 'listening' = 'Listening ports'
    'autoruns' = 'Run keys and Startup folders'; 'persist' = 'Other auto-start spots (LSA, Winlogon, IFEO, netsh...)'
    'wmi_persist' = 'WMI subscriptions'; 'hostsfile' = 'hosts file'; 'netcfg' = 'DNS servers and proxy'
    'fwrules' = 'Firewall rules'; 'fwprofiles' = 'Firewall on/off'; 'defender' = 'Defender settings'
    'shadowcopies' = 'Shadow copies'; 'shares' = 'Shares'; 'software' = 'Installed programs'; 'bits' = 'BITS jobs'
}
$DcDiffItems = [ordered]@{
    'ad_privgroups' = 'Privileged domain groups'; 'ad_users' = 'Domain users'; 'ad_spn' = 'SPN accounts (Kerberoast targets)'
    'ad_asrep' = 'AS-REP accounts (no pre-auth)'; 'ad_delegation' = 'Delegation'; 'ad_adminsdholder' = 'AdminSDHolder permissions'
    'ad_replrights' = 'Replication rights (DCSync)'; 'ad_gpos' = 'Group Policy objects'; 'ad_krbtgt' = 'krbtgt password'
    'ad_risky' = 'Risky account settings'; 'ad_trusts' = 'Domain trusts'
}

function Read-Lines {
    param([string]$File)
    if (-not (Test-Path $File)) { return $null }
    $l = @(Get-Content $File | Where-Object { $_ -ne '' })
    return ,$l     # the comma keeps an empty file as an empty list instead of nothing
}

function Compare-Lines {
    param($Old, $New)
    $o = @{}; foreach ($l in $Old) { $o[$l] = 1 }
    $n = @{}; foreach ($l in $New) { $n[$l] = 1 }
    return @{
        New  = @($New | Where-Object { -not $o.ContainsKey($_) } | Select-Object -Unique)
        Gone = @($Old | Where-Object { -not $n.ContainsKey($_) } | Select-Object -Unique)
    }
}

function Get-PrevDir {
    $d = @(Get-ChildItem -Path $Vault -Directory | Where-Object { $_.Name -match '^\d{8}-\d{6}$' -and $_.Name -ne $script:stamp } | Sort-Object Name -Descending | Select-Object -First 1)
    if ($d.Count -gt 0) { return $d[0].FullName }
    return $null
}

function Get-DirTime {
    param([string]$Dir)
    $n = Split-Path $Dir -Leaf
    if ($n -match '^\d{8}-\d{6}$') { return [datetime]::ParseExact($n, 'yyyyMMdd-HHmmss', $null) }
    return (Get-Item $Dir).CreationTime
}

# ---------------------------------------------------------------------------
# team notes
# ---------------------------------------------------------------------------
function Add-Note {
    param([string]$T, [string]$Who)
    if (-not $Who) { $Who = $env:USERNAME }
    $line = (UtcNow) + '  ' + $env:COMPUTERNAME + '  ' + $Who + ': ' + $T
    Add-Content -Path $NotesFile -Value $line
    return $line
}
function Auto-Note { param([string]$T) [void](Add-Note $T 'first30') }

# ---------------------------------------------------------------------------
# the checks. Each one prints its own section. They run at every hunt and in
# recon, and do not rely on the baseline: something planted BEFORE the baseline
# is part of it, and a baseline diff would never flag it. All read only.
# ---------------------------------------------------------------------------
function Check-Self {
    Sec 'self' 'Self-check: can this box fool this script? (T1546.013, T1574)'
    $bad = $false
    $hj = @(Test-Hijack)
    if ($hj.Count -gt 0) {
        Warn 'These commands are NOT the real Windows ones in this PowerShell window:'
        $hj | ForEach-Object { Say ('    ' + $_) }
        Say  ('  Results can be faked. Close this window and start again with: powershell -NoProfile -ExecutionPolicy Bypass -File .\first30.ps1')
        $bad = $true
    }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Warn 'This is 32-bit PowerShell: Windows shows it a different System32, so results are wrong.'
        Say  '  Use C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe instead.'
        $bad = $true
    }
    $vi = Get-Item -LiteralPath $Vault -Force
    if ($vi -and ($vi.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Warn ($Vault + ' is a link to somewhere else. Someone set a trap: use -Vault with another folder.')
        $bad = $true
    }
    $other = @((Get-Acl $Vault).Access | Where-Object { [string]$_.IdentityReference -notmatch '(Administrators|SYSTEM)$' })
    if ($other.Count -gt 0) {
        Warn ('Someone else has rights on the vault: ' + (($other | ForEach-Object { [string]$_.IdentityReference }) -join ', '))
        $bad = $true
    }
    if ($bad) { Flag; Nxt 'tell your lead. What this script shows below may be faked.' }
    else { Good 'the commands this script uses are the real Windows ones, and only Administrators and SYSTEM can open the vault' }
}

$RatNames = 'meshagent', 'meshcentral', 'mesh agent', 'anydesk', 'teamviewer', 'rustdesk', 'screenconnect', 'connectwise', 'atera', 'splashtop',
            'logmein', 'gotomypc', 'ammyy', 'remoteutilities', 'dwagent', 'supremo', 'netsupport', 'tightvnc', 'ultravnc', 'realvnc',
            'winvnc', 'tvnserver', 'ngrok', 'chisel', 'frpc', 'plink', 'psexesvc', 'imix', 'sliver', 'ligolo'
$RatPorts = 16990, 16991, 7070, 5938, 6568, 8041, 5900, 4899, 8040

function Check-RAT {
    Sec 'rat' 'Remote-access tools (T1219: the MeshCentral agent was the way in at the invitational)'
    $svc  = @(Get-CimInstance Win32_Service)
    $proc = @(Get-CimInstance Win32_Process)
    $sw   = @((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*').DisplayName)
    $tsk  = @(Get-ScheduledTask | ForEach-Object { $_.TaskName + ' ' + (($_.Actions | ForEach-Object { [string]$_.Execute + ' ' + [string]$_.Arguments }) -join ' ') })
    $hits = @()
    foreach ($n in $RatNames) {
        $rx = '(?i)(^|[^a-z])' + [regex]::Escape($n)
        foreach ($x in @($svc | Where-Object { $_.Name -match $rx -or $_.DisplayName -match $rx -or $_.PathName -match $rx })) { $hits += ('service: ' + $x.Name + '  ->  ' + $x.PathName) }
        foreach ($x in @($proc | Where-Object { $_.Name -match $rx -or $_.ExecutablePath -match $rx })) { $hits += ('process: ' + $x.Name + ' (pid ' + $x.ProcessId + ')  ' + $x.ExecutablePath) }
        foreach ($x in @($sw | Where-Object { $_ -match $rx })) { $hits += ('installed: ' + $x) }
        foreach ($x in @($tsk | Where-Object { $_ -match $rx })) { $hits += ('scheduled task: ' + $x) }
    }
    foreach ($x in @(Get-NetTCPConnection -State Listen | Where-Object { $RatPorts -contains $_.LocalPort })) { $hits += ('listening on a known remote-access port ' + $x.LocalPort + ' (pid ' + $x.OwningProcess + ')') }
    if ($hits.Count -gt 0) {
        Warn ('possible remote-access tools (' + $hits.Count + '):')
        $hits | Sort-Object -Unique | ForEach-Object { Say ('    * ' + $_) }
        Flag
        Nxt 'ask your team if anyone installed it. If not: save evidence (menu 5), then with your lead stop and disable it.'
        Say '        Red team installed MeshCentral the day BEFORE the invitational.'
    } else {
        Good 'none found by name, service, task or port'
    }
}

# connections this box opened to somewhere else
function Get-OutboundConn {
    param([string[]]$States = @('Established', 'SynSent'))
    $listen = @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique)
    foreach ($c in @(Get-NetTCPConnection -State $States)) {
        $ra = ([string]$c.RemoteAddress) -replace '^::ffff:', ''
        if ($ra -match '^(127\.|0\.0\.0\.0$|::1$|::$)') { continue }
        if ($listen -contains $c.LocalPort) { continue }      # an answer from one of our own services
        [pscustomobject]@{ Remote = $ra; Port = $c.RemotePort; LPort = $c.LocalPort; State = [string]$c.State; Owner = [int]$c.OwningProcess }
    }
}

function Get-C2Rows {
    $blocked = @(Get-BlockList)
    $procs = @{}
    foreach ($p in @(Get-CimInstance Win32_Process)) { $procs[[int]$p.ProcessId] = $p }
    foreach ($g in @(Get-OutboundConn | Group-Object Remote, Port, Owner, State)) {
        $c = $g.Group[0]
        $p = $procs[$c.Owner]
        $exe = ''
        if ($p) { $exe = [string]$p.ExecutablePath }
        $why = @()
        if ($blocked | Where-Object { Test-InNet $c.Remote $_ }) { $why += 'blocked-address' }
        if (Test-Outside $c.Remote) { $why += 'outside-our-networks' }
        if ($c.State -eq 'SynSent') { $why += 'still-trying-to-connect' }
        if ($exe -and (Test-UserWritable $exe)) { $why += 'user-or-temp-folder' }
        if ($exe -and (Get-SigStatus $exe) -ne 'Valid') { $why += 'not-signed' }
        $name = '?'
        if ($p) { $name = $p.Name }
        $to = $c.Remote + ':' + $c.Port
        if ($g.Count -gt 1) { $to = $to + ' (x' + $g.Count + ')' }
        [pscustomobject]@{ Program = $name; PID = $c.Owner; To = $to; Marked = ($why -join ' '); Path = $exe }
    }
}

function Check-C2 {
    Sec 'c2' 'Connections out of this box right now (T1071; for a 30-second watch use menu 3 or: first30.ps1 c2)'
    $rows = @(Get-C2Rows)
    if ($rows.Count -eq 0) { Good 'no connections out of this box right now'; return }
    Show ($rows | Sort-Object Marked -Descending)
    if ($rows | Where-Object { $_.Marked -match 'outside|blocked|user-or-temp|not-signed' }) {
        Flag
        Nxt 'write down the program, address and time. Save the program (evidence), then block the address (menu 8).'
    }
}

function Check-Programs {
    Sec 'progs' 'Running programs that are not signed, or run from a user or temp folder (T1036, T1204)'
    $rows = @()
    foreach ($g in @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | Group-Object ExecutablePath)) {
        $exe = $g.Name
        $why = @()
        if (Test-UserWritable $exe) { $why += 'user-or-temp-folder' }
        if ($why.Count -gt 0 -or -not ($exe.ToLower().StartsWith(($env:windir).ToLower() + '\'))) {
            $s = Get-SigStatus $exe
            if ($s -ne 'Valid') { $why += ('signature:' + $s) }
        }
        if ($why.Count -gt 0) {
            $rows += [pscustomobject]@{ Program = $exe; Running = $g.Count; PIDs = (($g.Group | Select-Object -First 3 | ForEach-Object { $_.ProcessId }) -join ','); Why = ($why -join ' ') }
        }
    }
    if ($rows.Count -gt 0) {
        Show $rows
        Say '  Some are real programs a person installed. Check each one: what is it, and who put it there?'
        Flag
        Nxt 'for one nobody knows: save evidence (menu 5), then ask your lead before stopping it.'
    } else {
        Good 'every running program outside C:\Windows is signed, and none runs from a user or temp folder'
    }
}

function Check-CmdLines {
    Sec 'cmdline' 'Suspicious command lines, and shells started by servers (T1059.001, T1218, T1505.003)'
    $lol = '(?i)(\s-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|invoke-webrequest|\biwr\s|net\.webclient|start-bitstransfer|certutil(\.exe)?\s.*-urlcache|bitsadmin(\.exe)?\s.*/transfer|mshta(\.exe)?\s+(http|javascript|vbscript)|regsvr32(\.exe)?\s.*/i:\s*http|rundll32(\.exe)?\s.*(javascript:|http)|wmic(\.exe)?\s.*process\s+call\s+create|-w(indowstyle)?\s+h(idden)?\b)'
    $shells  = 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe', 'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe', 'bash.exe'
    $servers = 'w3wp.exe', 'sqlservr.exe', 'httpd.exe', 'nginx.exe', 'php-cgi.exe', 'tomcat.exe', 'tomcat9.exe', 'java.exe', 'wmiprvse.exe', 'winrshost.exe', 'services.exe', 'spoolsv.exe', 'mshta.exe'
    $procs = @(Get-CimInstance Win32_Process)
    $byId = @{}
    foreach ($p in $procs) { $byId[[int]$p.ProcessId] = $p }
    $out = @()
    foreach ($p in $procs) {
        if ([int]$p.ProcessId -eq $PID) { continue }
        $cl = [string]$p.CommandLine
        if ($cl -match $lol) { $out += ('  pid ' + $p.ProcessId + ' ' + $p.Name + ': ' + $cl) }
        $par = $byId[[int]$p.ParentProcessId]
        if ($par -and ($shells -contains $p.Name.ToLower()) -and ($servers -contains $par.Name.ToLower())) {
            $out += ('  pid ' + $p.ProcessId + ' ' + $p.Name + ' was started by ' + $par.Name + ' (pid ' + $par.ProcessId + '): ' + $cl)
        }
    }
    if ($out.Count -gt 0) {
        Warn 'check these:'
        $out | Select-Object -Unique | ForEach-Object { Say $_ }
        Say '  A shell started by the web server, SQL server, WMI or services.exe is how remote commands run (webshell, wmiexec, psexec).'
        Flag
        Nxt 'note the pid, its parent and the time. Save the program (evidence), then stop it with your lead.'
    } else {
        Good 'no encoded or download-style command lines, and no server starting a shell right now'
    }
}

function Check-Services {
    Sec 'svc' 'Services from odd places, unsigned, or hidden from the services list (T1543.003, T1564)'
    $out = @()
    foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { $_.PathName })) {
        $exe = Get-ExeFromCmd $s.PathName
        $why = @()
        if (Test-UserWritable $exe) { $why += 'user-or-temp-folder' }
        if ($exe -and -not $exe.ToLower().StartsWith(($env:windir).ToLower() + '\')) {
            $sg = Get-SigStatus $exe
            if ($sg -ne 'Valid') { $why += ('signature:' + $sg) }
        }
        # svchost services load a DLL; a DLL outside System32 is a planted one
        if ($exe -match '(?i)\\svchost\.exe$') {
            $dll = (Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $s.Name + '\Parameters')).ServiceDll
            if ($dll) {
                $dll = [Environment]::ExpandEnvironmentVariables($dll)
                if ($dll -notmatch '(?i)^[a-z]:\\windows\\(system32|syswow64)\\') { $why += ('ServiceDll:' + $dll) }
            }
        }
        if ($why.Count -gt 0) { $out += ('  ' + $s.Name + ' (' + $s.State + ', ' + $s.StartMode + ') -> ' + $s.PathName + '   [' + ($why -join ' ') + ']') }
    }
    # hidden services: in the registry, but missing from the services list. A
    # service whose permissions deny reading hides from services.msc and Get-Service.
    $scm = @{}
    foreach ($s in @(Get-Service)) { $scm[$s.Name.ToLower()] = 1 }
    foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services')) {
        $p = Get-ItemProperty $k.PSPath
        if (($p.Type -eq 16 -or $p.Type -eq 32) -and $p.ImagePath -and -not $scm.ContainsKey($k.PSChildName.ToLower())) {
            $out += ('  HIDDEN service: ' + $k.PSChildName + ' -> ' + $p.ImagePath + '   (in the registry, not in the services list)')
        }
    }
    if ($out.Count -gt 0) {
        Warn 'check these services:'
        $out | ForEach-Object { Say $_ }
        Flag
        Nxt 'sc.exe qc <name> shows it. sc.exe sdshow <name> shows its permissions. Save the program (evidence) before you stop it.'
    } else {
        Good 'every service runs a signed program from a normal folder, and none is hidden'
    }
}

function Check-Drivers {
    Sec 'drivers' 'Kernel drivers that are not signed or not in the drivers folder (T1014, T1543.003)'
    $out = @()
    foreach ($d in @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' })) {
        $f = Get-ExeFromCmd $d.PathName
        if (-not $f) { continue }
        $why = @()
        if ($f -notmatch '(?i)^[a-z]:\\windows\\system32\\') { $why += 'outside System32' }
        $sg = Get-SigStatus $f
        if ($sg -ne 'Valid') { $why += ('signature:' + $sg) }
        if ($why.Count -gt 0) { $out += ('  ' + $d.Name + ' -> ' + $f + '   [' + ($why -join ', ') + ']') }
    }
    if ($out.Count -gt 0) {
        Warn 'check these drivers:'
        $out | ForEach-Object { Say $_ }
        Say '  (VirtualBox, VMware or Hyper-V guest drivers are signed; an unsigned driver is the warning sign.)'
        Flag
        Nxt 'tell your lead. A bad driver means the box cannot be trusted: plan to restore it.'
    } else {
        Good 'every running driver is signed and lives in System32'
    }
}

function Check-Tasks {
    Sec 'tasks' 'Scheduled tasks that download, decode, or run from user or temp folders (T1053.005)'
    $out = @()
    foreach ($t in @(Get-ScheduledTask)) {
        foreach ($a in @($t.Actions)) {
            $line = ([string]$a.Execute + ' ' + [string]$a.Arguments).Trim()
            if (-not $line) { continue }
            $why = @()
            if ($line -match '(?i)-enc|-EncodedCommand|FromBase64|DownloadString|DownloadFile|\bIEX\b|Invoke-Expression|Invoke-WebRequest|certutil|bitsadmin|mshta|regsvr32\s+/s\s+/i|http[s]?://') { $why += 'download-or-encoded' }
            $exe = Get-ExeFromCmd ([string]$a.Execute)
            if ($exe -and (Test-UserWritable $exe)) { $why += 'user-or-temp-folder' }
            if ($why.Count -gt 0) { $out += ('  ' + $t.TaskPath + $t.TaskName + ' (' + $t.State + '): ' + $line + '   [' + ($why -join ' ') + ']') }
        }
    }
    if ($out.Count -gt 0) {
        Warn 'check these tasks:'
        $out | ForEach-Object { Say $_ }
        Flag
        Nxt 'Task Scheduler > find the task > Actions tab. If nobody on your team made it: export it for evidence, then disable it.'
    } else {
        Good 'no task downloads, decodes, or runs from a user or temp folder'
    }
}

function Check-Persist {
    Sec 'persist' 'Logon-screen backdoors, password stealers and other auto-start spots (T1546, T1547, T1556.002)'
    $out = @()
    # accessibility programs swapped for cmd or anything else: the file's own name inside must match
    $cmdHash = (Get-FileHash "$env:windir\System32\cmd.exe" -Algorithm SHA256).Hash
    $psHash  = (Get-FileHash "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Algorithm SHA256).Hash
    foreach ($f in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $fp = Join-Path "$env:windir\System32" $f
        if (-not (Test-Path $fp)) { continue }
        $h = (Get-FileHash $fp -Algorithm SHA256).Hash
        $orig = ([string](Get-Item $fp).VersionInfo.OriginalFilename) -replace '(?i)\.mui$', ''
        if ($h -eq $cmdHash -or $h -eq $psHash) { $out += ('  ' + $f + ' is a copy of cmd.exe or powershell.exe (logon-screen backdoor, T1546.008)') }
        elseif ($orig -and $orig -ne $f) { $out += ('  ' + $f + ' is really "' + $orig + '" inside (a swapped program, T1546.008)') }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem $ifeo | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        if ($p.Debugger) { $out += ('  IFEO debugger on ' + $_.PSChildName + ' -> ' + $p.Debugger + '   (T1546.012)') }
    }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        if ($p.MonitorProcess) { $out += ('  when ' + $_.PSChildName + ' exits, Windows runs ' + $p.MonitorProcess + '   (T1546.012)') }
    }
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') { $out += ('  Winlogon Shell is "' + $wl.Shell + '" (normal: explorer.exe; Server Core can differ)') }
    if ($wl.Userinit -and ($wl.Userinit.Trim().TrimEnd(',') -notmatch '^(?i)(C:\\Windows\\system32\\)?userinit\.exe$')) { $out += ('  Winlogon Userinit is "' + $wl.Userinit + '" (normal: C:\Windows\system32\userinit.exe,)') }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $ai = Get-ItemProperty $k
        if ($ai.AppInit_DLLs) { $out += ('  AppInit_DLLs: ' + $ai.AppInit_DLLs + ' (loads into almost every program, T1546.010)') }
    }
    $ac = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if ($ac) { $ac.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $out += ('  AppCertDlls: ' + $_.Value + ' (T1546.009)') } }
    $be = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').BootExecute
    foreach ($b in @($be)) { if ($b -and $b -notmatch '^(?i)autocheck autochk \*$') { $out += ('  BootExecute runs: ' + $b + ' (before Windows starts)') } }
    # LSA: password filters see every new password, security packages see logons
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $okSec = '', 'kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'livessp', 'negoexts', '"', '""'
    $sp = @($lsa.'Security Packages') + @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig').'Security Packages')
    foreach ($v in $sp) { if ($v -and ($okSec -notcontains $v.ToLower())) { $out += ('  LSA security package "' + $v + '" is not a Windows one (mimilib-style logon stealer, T1547.005)') } }
    foreach ($v in @($lsa.'Authentication Packages')) { if ($v -and $v.ToLower() -ne 'msv1_0') { $out += ('  LSA authentication package "' + $v + '" (normal: msv1_0, T1547.002)') } }
    foreach ($v in @($lsa.'Notification Packages')) { if ($v -and ('scecli', 'rassfm', 'fpnwclnt', 'kdcsvc', 'passfilt' -notcontains $v.ToLower())) { $out += ('  password filter "' + $v + '": it sees every new password you set (T1556.002)') } }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential -eq 1) { $out += '  WDigest UseLogonCredential = 1: Windows keeps plain-text passwords in memory (T1112)' }
    if ($MyRole -eq 'dc' -and $lsa.DsrmAdminLogonBehavior -eq 2) { $out += '  DsrmAdminLogonBehavior = 2: the DSRM password logs in over the network (the backdoor from your AD session)' }
    # netsh helpers, print monitors and time providers load DLLs into system processes
    $ns = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh'
    if ($ns) { $ns.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        $v = [string]$_.Value
        if ($v -match '\\' -or -not (Test-Path (Join-Path "$env:windir\System32" $v))) { $out += ('  netsh helper ' + $_.Name + ' = ' + $v + ' (T1546.007)') } } }
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object {
        $d = [string](Get-ItemProperty $_.PSPath).Driver
        if ($d -and ($d -match '\\' -or -not (Test-Path (Join-Path "$env:windir\System32" $d)))) { $out += ('  print monitor ' + $_.PSChildName + ' = ' + $d + ' (T1547.010)') } }
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' | ForEach-Object {
        $d = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty $_.PSPath).DllName)
        if ($d -and $d -notmatch '(?i)\\system32\\(w32time|vmictimeprovider)\.dll$') { $out += ('  time provider ' + $_.PSChildName + ' = ' + $d + ' (T1547.003)') } }
    if ($out.Count -gt 0) {
        Warn 'check these:'
        $out | ForEach-Object { Say $_ }
        Flag
        Nxt 'export the registry key for evidence (reg export), then remove the value with your lead. Some need a reboot to unload.'
    } else {
        Good 'accessibility programs, IFEO, Winlogon, AppInit, LSA, WDigest, netsh, print monitors and time providers all look normal'
    }
    $sf = @(Get-Autoruns | Where-Object { $_ -like 'Startup folder | *' })
    if ($sf.Count -gt 0) { Say '  Files in Startup folders (they run at logon):'; $sf | ForEach-Object { Say ('    ' + ($_ -replace '^Startup folder \| ', '')) } }
}

function Check-Wmi {
    Sec 'wmi' 'WMI subscriptions that run commands (T1546.003)'
    $c = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Where-Object {
        $_.CimClass.CimClassName -match 'CommandLineEventConsumer|ActiveScriptEventConsumer' -and $_.Name -ne 'BVTConsumer' })
    if ($c.Count -gt 0) {
        Warn 'WMI consumers that run a command or a script:'
        foreach ($x in $c) {
            $what = $x.CommandLineTemplate
            if (-not $what) { $what = $x.ScriptText }
            if (-not $what) { $what = $x.ScriptFileName }
            Say ('    ' + $x.Name + ' (' + $x.CimClass.CimClassName + '): ' + $what)
        }
        Flag
        Nxt 'Windows has none of these by default. Save the output for evidence, then remove the consumer, its filter and binding with your lead.'
    } else {
        Good 'no WMI subscription runs a command or a script'
    }
}

function Check-Profiles {
    Sec 'profiles' 'PowerShell profiles (T1546.013: code that runs every time PowerShell starts)'
    $prof = @("$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1",
              "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
              "$env:windir\SysWOW64\WindowsPowerShell\v1.0\profile.ps1",
              "$env:windir\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
              "$env:ProgramFiles\PowerShell\7\profile.ps1")
    $prof += @(Get-ChildItem 'C:\Users\*\Documents\WindowsPowerShell\*profile.ps1', 'C:\Users\*\Documents\PowerShell\*profile.ps1' -Force | Select-Object -ExpandProperty FullName)
    $found = @($prof | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)
    if ($found.Count -gt 0) {
        Warn 'PowerShell profile files exist. Read each one: a planted profile can run code or fake commands.'
        $found | ForEach-Object { Say ('    * ' + $_ + '   (changed ' + (Get-Item $_ -Force).LastWriteTime + ')') }
        Flag
        Nxt 'open each in Notepad. If your team did not write it: copy it for evidence, then delete it.'
    } else {
        Good 'no PowerShell profile files'
    }
}

function Check-Defender {
    param([datetime]$Since)
    Sec 'defender' 'Defender: on, no exclusions, and what it caught (T1562.001)'
    $bad = $false
    $st = Get-MpComputerStatus
    if ($st) {
        if ($st.RealTimeProtectionEnabled) { Good 'real-time protection is on' } else { Warn 'real-time protection is OFF'; $bad = $true }
        if (-not $st.AntivirusEnabled) { Warn 'the antivirus engine is OFF'; $bad = $true }
    } else {
        Say '  Defender status is not available on this box'
    }
    $mp = Get-MpPreference
    $ex = @(@($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) + @($mp.ExclusionIpAddress) | Where-Object { $_ })
    if ($ex.Count -gt 0) {
        Warn 'Defender exclusions (Defender never scans these):'
        $ex | ForEach-Object { Say ('    * ' + $_) }
        $bad = $true
    }
    $det = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt $Since })
    if ($det.Count -gt 0) {
        $names = @{}
        foreach ($t in @(Get-MpThreat)) { $names[[string]$t.ThreatID] = $t.ThreatName }
        Warn ('Defender caught something since ' + $Since.ToString('HH:mm') + ':')
        foreach ($d in $det) { Say ('    ' + $d.InitialDetectionTime.ToString('HH:mm') + '  ' + $names[[string]$d.ThreatID] + '  ' + (@($d.Resources) -join '; ')) }
        $bad = $true
    }
    if ($bad) { Flag; Nxt 'turn protection back on, remove exclusions your team did not add, and look at every file Defender named.' }
}

function Check-Firewall {
    Sec 'firewall' 'Firewall (T1562.004: at the invitational the Windows firewall was turned off, and block rules broke scored services)'
    $bad = $false
    $off = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' } | Select-Object -ExpandProperty Name)
    if ($off.Count -gt 0) { Warn ('the firewall is OFF for: ' + ($off -join ', ')); $bad = $true } else { Good 'the firewall is on for every profile' }
    $gpo = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { [string]$_.AllowLocalFirewallRules -eq 'False' } | Select-Object -ExpandProperty Name)
    if ($gpo.Count -gt 0) {
        Warn ('a Group Policy ignores rules made on this box for: ' + ($gpo -join ', ') + '. Block rules from this script will NOT work there.')
        $bad = $true
    }
    foreach ($s in 'mpssvc', 'BFE') {
        $x = Get-Service $s
        if ($x -and $x.Status -ne 'Running') { Warn ('the ' + $x.DisplayName + ' service is ' + $x.Status + ': the firewall cannot work'); $bad = $true }
    }
    $blk = @(Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True | Where-Object { $_.DisplayName -notlike 'first30 block *' })
    if ($blk.Count -gt 0) {
        Warn 'inbound BLOCK rules (one of these can take a scored service down; check each one):'
        $blk | ForEach-Object { Say ('    * ' + $_.DisplayName) }
        $bad = $true
    }
    if ($bad) { Flag; Nxt 'tell your lead before turning the firewall on: it can also block scored services.' }
}

# Two ways of listing the same thing should agree. A rootkit usually fools one.
function Check-Rootkit {
    Sec 'rootkit' 'Rootkit checks: things hidden from normal tools (T1014, T1564)'
    $out = @()
    $a = @(Get-Process | ForEach-Object { [int]$_.Id })
    $b = @(Get-CimInstance Win32_Process | ForEach-Object { [int]$_.ProcessId })
    $cand = @($a | Where-Object { $b -notcontains $_ }) + @($b | Where-Object { $a -notcontains $_ })
    if ($cand.Count -gt 0) {
        Start-Sleep -Seconds 1
        foreach ($x in ($cand | Select-Object -Unique)) {
            $inA = [bool](Get-Process -Id $x -ErrorAction SilentlyContinue)
            $inB = [bool](Get-CimInstance Win32_Process -Filter ('ProcessId=' + $x))
            if ($inA -ne $inB) { $out += ('  process ' + $x + ' shows in only one of Get-Process and WMI') }
        }
    }
    $p1 = @(Get-NetTCPConnection -State Listen | ForEach-Object { [int]$_.LocalPort } | Sort-Object -Unique)
    $p2 = @(netstat -ano -p TCP | Select-String 'LISTENING' | ForEach-Object { [int](((($_.Line.Trim()) -split '\s+')[1]) -replace '.*:', '') })
    $p2 += @(netstat -ano -p TCPv6 | Select-String 'LISTENING' | ForEach-Object { [int](((($_.Line.Trim()) -split '\s+')[1]) -replace '.*:', '') })
    $p2 = @($p2 | Sort-Object -Unique)
    $d1 = @($p1 | Where-Object { $p2 -notcontains $_ })
    $d2 = @($p2 | Where-Object { $p1 -notcontains $_ })
    if ($d1.Count -gt 0 -or $d2.Count -gt 0) {
        Start-Sleep -Seconds 1
        $q1 = @(Get-NetTCPConnection -State Listen | ForEach-Object { [int]$_.LocalPort })
        $q2 = @(netstat -ano | Select-String 'LISTENING' | ForEach-Object { [int](((($_.Line.Trim()) -split '\s+')[1]) -replace '.*:', '') })
        foreach ($x in $d1) { if ($q2 -notcontains $x -and $q1 -contains $x) { $out += ('  port ' + $x + ' is listening, but netstat does not show it') } }
        foreach ($x in $d2) { if ($q1 -notcontains $x -and $q2 -contains $x) { $out += ('  port ' + $x + ' shows in netstat, but not in Get-NetTCPConnection') } }
    }
    if ($out.Count -gt 0) {
        Warn 'the two views disagree:'
        $out | ForEach-Object { Say $_ }
        Flag
        Nxt 'tell your lead NOW. Something is hiding: the box cannot be trusted. Plan to restore it.'
    } else {
        Good 'processes and listening ports look the same both ways (hidden services are checked under Services)'
    }
}

function Check-Accounts {
    Sec 'accounts' 'Accounts: Guest, no password needed, the built-in Administrator (T1078.001, T1098)'
    $out = @()
    foreach ($u in @(Get-LocalUser)) {
        if ($u.SID.Value -like '*-501' -and $u.Enabled) { $out += ('  the Guest account (' + $u.Name + ') is ENABLED') }
        if ($u.SID.Value -like '*-503' -and $u.Enabled) { $out += ('  DefaultAccount (' + $u.Name + ') is ENABLED') }
        if ($u.Enabled -and -not $u.PasswordRequired) { $out += ('  ' + $u.Name + ' can have an EMPTY password (PasswordRequired = False)') }
    }
    if ($out.Count -gt 0) {
        Warn 'check these accounts:'
        $out | ForEach-Object { Say $_ }
        Flag
        Nxt 'ask your lead. Disable an account nobody needs (lusrmgr.msc > right-click > Properties > Account is disabled).'
    } else {
        Good 'Guest and DefaultAccount are off, and every enabled account needs a password'
    }
    Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | ForEach-Object { Say ('  built-in Administrator (RID 500): ' + $_.Name + '   enabled=' + $_.Enabled) }
    $la = @(Get-LocalAdmins)
    if ($la.Count -gt 0) { Say ('  Administrators group: ' + (($la | ForEach-Object { ($_ -split ' \| ')[0] }) -join ', ')) }
}

function Check-Logins {
    Sec 'logins' 'Who is logged in now, and from where (T1078, T1021.001, T1021.002)'
    $bad = $false
    $q = @(quser 2>$null)
    if ($q.Count -gt 0) { Say '  sessions on this box (quser):'; $q | ForEach-Object { Say ('    ' + $_) } }
    $rdp = @(Get-NetTCPConnection -LocalPort 3389 -State Established | ForEach-Object { ([string]$_.RemoteAddress) -replace '^::ffff:', '' } | Sort-Object -Unique)
    foreach ($r in $rdp) {
        $m = ''
        if (Test-Outside $r) { $m = '   <- from outside your networks'; $bad = $true }
        Say ('  RDP connection from ' + $r + $m)
    }
    $smb = @(Get-SmbSession)
    foreach ($s in $smb) {
        $m = ''
        if (Test-Outside $s.ClientComputerName) { $m = '   <- from outside your networks'; $bad = $true }
        Say ('  share session: ' + $s.ClientUserName + ' from ' + $s.ClientComputerName + ' (' + $s.NumOpens + ' files open)' + $m)
    }
    if ($q.Count -eq 0 -and $rdp.Count -eq 0 -and $smb.Count -eq 0) { Say '  nobody else is connected right now' }
    if ($script:Nets.Count -eq 0) { Say '  Tip: save your networks so outside addresses get marked (menu N, or: first30.ps1 nets -OurNets 10.100.130.0/24)' }
    if ($bad) { Flag; Nxt 'a session you cannot explain: write down the account, address and time, then log it off (Task Manager > Users) and block the address.' }
}

# Pop-up spam and screen watching. msg.exe sends a pop-up to every session; from
# another machine it needs AllowRemoteRPC = 1. RDP shadowing lets someone watch (or
# drive) your RDP session; Shadow = 2 or 4 means without asking you first.
$TsKey     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$TsPolicy  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
function Check-Spam {
    param([datetime]$Since)
    Sec 'spam' 'Pop-up spam and screen watching (msg.exe, RDP shadowing; T1021.001, T1563.002, T1113)'
    $out = @()
    if ((Get-ItemProperty $TsKey).AllowRemoteRPC -eq 1) { $out += '  AllowRemoteRPC = 1: other machines can send pop-ups here (msg /server), and list or kick sessions' }
    # the policy wins; without it, RDP uses the setting on the RDP-Tcp listener
    $sh = (Get-ItemProperty $TsPolicy).Shadow
    $shw = 'policy'
    if ($null -eq $sh) { $sh = (Get-ItemProperty ($TsKey + '\WinStations\RDP-Tcp')).Shadow; $shw = 'RDP-Tcp listener' }
    if ($sh -eq 2) { $out += ('  RDP Shadow = 2 (' + $shw + '): someone can WATCH AND CONTROL your RDP sessions without asking you') }
    if ($sh -eq 4) { $out += ('  RDP Shadow = 4 (' + $shw + '): someone can WATCH your RDP sessions without asking you') }
    # RdpSa*.exe run on the box whose session is being shadowed; mstsc /shadow runs on the watcher's box
    foreach ($x in @(Get-CimInstance Win32_Process)) {
        $n = [string]$x.Name
        if ($n -ieq 'msg.exe') { $out += ('  msg.exe is running right now (pid ' + $x.ProcessId + '): ' + $x.CommandLine) }
        elseif ($n -match '^(?i)RdpSa(Proxy|UacHelper)?\.exe$') { $out += ('  ' + $n + ' is running (pid ' + $x.ProcessId + '): an RDP session on this box is being shadowed right now') }
        elseif ($n -ieq 'mstsc.exe' -and [string]$x.CommandLine -match '(?i)/shadow') { $out += ('  someone on this box is shadowing another session (pid ' + $x.ProcessId + '): ' + $x.CommandLine) }
    }
    foreach ($e in @(Get-Evt 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' (XSince @(20503, 20506) $Since) 20)) {
        $out += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  someone started shadowing an RDP session: watching it, maybe controlling it (event ' + $e.Id + ')')
    }
    $undo = Join-Path $Vault 'quiet_undo.txt'
    if ((Test-Path $undo) -and ((Get-ItemProperty $TsKey).AllowRemoteRPC -ne 0 -or (Get-ItemProperty $TsPolicy).Shadow -ne 0)) {
        $out += '  your spam protection was turned back off (AllowRemoteRPC or Shadow is no longer 0)'
    }
    if ($out.Count -gt 0) {
        Warn 'check these:'
        $out | ForEach-Object { Say $_ }
        Flag
        Nxt 'run quiet (menu 11). Pop-ups that keep coming are from an admin on this box: find the session with quser, log it off, change that password.'
    } else {
        Good 'no pop-up spam from other machines, and nobody can watch your RDP sessions without asking'
        if (-not (Test-Path $undo)) { Say '  Spam protection is not on. Turn it on: menu 11, or first30.ps1 quiet' }
    }
}

function Check-Bits {
    Sec 'bits' 'BITS jobs: background downloads (T1197)'
    $j = @(Get-BitsTransfer -AllUsers)
    $odd = @($j | Where-Object { (@($_.FileList) | Where-Object { $_.RemoteName -and $_.RemoteName -notmatch '(?i)(windowsupdate|microsoft|msftconnecttest|office)\.com' }).Count -gt 0 })
    if ($odd.Count -gt 0) {
        Warn 'BITS jobs downloading from somewhere other than Microsoft:'
        foreach ($x in $odd) { Say ('    ' + $x.DisplayName + ' (' + $x.OwnerAccount + ', ' + $x.JobState + '): ' + ((@($x.FileList) | ForEach-Object { $_.RemoteName + ' -> ' + $_.LocalName }) -join '; ')) }
        Flag
        Nxt 'save the list for evidence, then remove the job with your lead: Get-BitsTransfer -AllUsers | Where-Object DisplayName -eq <name> | Remove-BitsTransfer'
    } else {
        Good ('no BITS job downloads from outside Microsoft (' + $j.Count + ' jobs in total)')
    }
}

function Check-Ads {
    Sec 'ads' 'Files hidden inside other files (alternate data streams, T1564.004)'
    $okStreams = ':$DATA', 'Zone.Identifier', 'SmartScreen', 'Afp_AfpInfo', 'com.dropbox.attributes', 'encryptable', 'favicon', 'OECustomProperty'
    $spots = @('C:\Users\Public', "$env:windir\Temp", 'C:\inetpub\wwwroot', 'C:\PerfLogs')
    $spots += @(Resolve-Path 'C:\Users\*\AppData\Local\Temp' | ForEach-Object { $_.Path })
    $out = @()
    foreach ($s in $spots) {
        if (-not (Test-Path $s)) { continue }
        foreach ($f in @(Get-FilesDepth -Path $s -Depth 2 | Select-Object -First 400)) {
            foreach ($st in @(Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction SilentlyContinue)) {
                if ($okStreams -notcontains $st.Stream) { $out += ('  ' + $f.FullName + ' : ' + $st.Stream + ' (' + $st.Length + ' bytes)') }
            }
        }
    }
    if ($out.Count -gt 0) {
        Warn 'hidden streams:'
        $out | Select-Object -First 30 | ForEach-Object { Say $_ }
        Flag
        Nxt 'read one with: Get-Content <file> -Stream <name>. Save the file for evidence before you remove it.'
    } else {
        Good 'no hidden streams in Public, Temp, inetpub or PerfLogs'
    }
}

function Check-Web {
    Sec 'web' 'Web shells (T1505.003: a page that runs commands)'
    $roots = @('C:\inetpub\wwwroot')
    $cfg = "$env:windir\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $cfg) {
        $roots += @(Select-String -Path $cfg -Pattern 'physicalPath="([^"]+)"' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Groups[1].Value) })
    }
    $roots = @($roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)
    if ($roots.Count -eq 0) { Good 'no web root on this box'; return }
    $rx = '(?i)((eval|execute|executeglobal)\s*\(\s*request|process\.start|processstartinfo|wscript\.shell|shell\.application|cmd\.exe\s*/c|fromBase64String\s*\(\s*request|(eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\(\s*@?\$_(get|post|request|cookie)|runtime\.getruntime\(\)\.exec)'
    $files = @(Get-ChildItem -Path $roots -File -Recurse -Force -Include *.aspx, *.asp, *.ashx, *.asmx, *.cshtml, *.php, *.jsp, *.jspx, *.config | Where-Object { $_.FullName -ne $script:BaitPath })
    $hits = @($files | Select-String -Pattern $rx -List | Select-Object -ExpandProperty Path -Unique)
    if ($hits.Count -gt 0) {
        Warn 'files with web-shell code (REVIEW, do not delete yet):'
        $hits | Select-Object -First 30 | ForEach-Object { Say ('    ' + $_ + '   (changed ' + (Get-Item $_).LastWriteTime + ')') }
        Flag
        Nxt 'open each in Notepad. If it is a shell: save evidence, remove it, and find how it got there (IIS logs).'
    } else {
        Good ('nothing that looks like a web shell in: ' + ($roots -join ', '))
    }
}

function Check-Ransom {
    Sec 'ransom' 'Ransomware signs (T1486) and shadow copies (T1490)'
    $rans = @(Get-FilesDepth -Path (@('C:\Users', 'C:\inetpub', 'C:\Shares', 'C:\Data') | Where-Object { Test-Path $_ }) -Depth 3 -Include '*.locked', '*.encrypted', '*ransom*', '*decrypt*', '*how_to_recover*' | Select-Object -First 15 -ExpandProperty FullName)
    if ($rans.Count -gt 0) {
        Warn 'files that look like ransomware:'
        $rans | ForEach-Object { Say ('    * ' + $_) }
        Flag
        Nxt 'tell your lead NOW and restore from backup.'
    } else {
        Good 'no locked files or ransom notes found'
    }
    Say ('  shadow copies on this box: ' + @(Get-CimInstance Win32_ShadowCopy).Count + '   (hunt shows it if this number drops)')
}

function Check-DC {
    if (-not (Get-Command Search-ADAccount -ErrorAction SilentlyContinue)) { return }
    Sec 'dc' 'Domain accounts locked out or turned off (T1110, T1531)'
    $bad = $false
    $locked = @(Search-ADAccount -LockedOut -UsersOnly | Select-Object -ExpandProperty SamAccountName)
    if ($locked.Count -gt 0) {
        Warn ('locked out right now (' + $locked.Count + '): ' + ($locked -join ', '))
        Say  '    Many at once means password guessing, or red team locking scored users on purpose.'
        $bad = $true
    } else { Good 'no locked-out users' }
    $adm = Get-ADUser -Identity ((Get-ADDomain).DomainSID.Value + '-500')
    if ($adm -and -not $adm.Enabled) {
        Warn ('the built-in domain Administrator (' + $adm.SamAccountName + ') is DISABLED. Red team did this at the invitational (T1531).')
        $bad = $true
    }
    $dis = @(Search-ADAccount -AccountDisabled -UsersOnly | Where-Object { $_.SamAccountName -notmatch '^(krbtgt|Guest|DefaultAccount)$' } | Select-Object -ExpandProperty SamAccountName)
    if ($dis.Count -gt 0) { Say ('  turned off (' + $dis.Count + '): ' + (($dis | Select-Object -First 25) -join ', ')) }
    $risky = @(Read-Lines (Join-Path $script:SnapDir 'ad_risky.txt') | Where-Object { $_ })
    if ($risky.Count -gt 0) { Warn 'risky account settings:'; $risky | ForEach-Object { Say ('    ' + $_) }; $bad = $true }
    $k = Get-ADUser krbtgt -Properties pwdLastSet
    if ($k) { Say ('  krbtgt password last set: ' + [datetime]::FromFileTime($k.pwdLastSet) + '   (Golden Ticket defense: reset it twice, 10+ hours apart)') }
    if ($bad) { Flag; Nxt 'unlock scored users (Unlock-ADAccount <name>), re-enable Administrator, and find the source of the guessing (events below).' }
}

function Check-Bait {
    param([datetime]$Since)
    if (-not $script:BaitPath) { return }
    Sec 'bait' 'Your bait file and bait login (T1552.001: someone went looking for passwords)'
    Say ('  bait file: ' + $script:BaitPath + '   bait login name: ' + $script:BaitUser)
    $out = @()
    if (-not (Test-Path -LiteralPath $script:BaitPath)) { $out += '  the bait file is GONE: someone deleted or moved it' }
    $ignore = '(?i)\\(MsMpEng|MpDefenderCoreService|NisSrv|SearchProtocolHost|SearchIndexer|SearchFilterHost)\.exe$'
    foreach ($e in @(Get-Evt 'Security' (XSince @(4663) $script:BaitTime) 300)) {
        if ((EvData $e 'ObjectName') -ne $script:BaitPath) { continue }
        $pn = EvData $e 'ProcessName'
        if ($pn -match $ignore) { continue }
        $out += ('  ' + $e.TimeCreated.ToString('MM-dd HH:mm') + '  opened by ' + (EvData $e 'SubjectDomainName') + '\' + (EvData $e 'SubjectUserName') + ' using ' + $pn)
    }
    if ($script:BaitUser) {
        $xp = XSince @(4625, 4771, 4768) $script:BaitTime ("Data[@Name='TargetUserName']='" + $script:BaitUser + "'")
        foreach ($e in @(Get-Evt 'Security' $xp 50)) {
            $out += ('  ' + $e.TimeCreated.ToString('MM-dd HH:mm') + '  someone tried the bait login from ' + (EvData $e 'IpAddress') + ' (event ' + $e.Id + ')')
        }
    }
    if ($out.Count -gt 0) {
        Warn 'the bait was touched:'
        $out | ForEach-Object { Say $_ }
        Flag
        Nxt 'this is red team. Note the time, account, program and address. Block the address, and hunt for how they got in.'
    } else {
        Good 'nobody has touched the bait'
    }
}

function Check-Audit {
    Sec 'audit' 'Windows auditing (T1562.002: with auditing off, there is nothing to hunt)'
    $want = [ordered]@{
        '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'
        '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation'
        '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management'
        '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management'
        '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'Audit Policy Change'
    }
    if ($MyRole -eq 'dc') {
        $want['{0CCE9240-69AE-11D9-BED3-505054503030}'] = 'Kerberos Service Ticket Operations'
        $want['{0CCE9242-69AE-11D9-BED3-505054503030}'] = 'Kerberos Authentication Service'
    }
    $rows = @(auditpol /get /category:* /r 2>$null | ConvertFrom-Csv)
    if ($rows.Count -eq 0) { Say '  could not read the audit policy'; return }
    $off = @()
    foreach ($g in $want.Keys) {
        $r = $rows | Where-Object { $_.'Subcategory GUID' -eq $g } | Select-Object -First 1
        if ($r -and $r.'Inclusion Setting' -match '(?i)no auditing') { $off += $want[$g] }
    }
    if ($off.Count -gt 0) {
        Warn ('auditing is OFF for: ' + ($off -join ', '))
        Flag
        Nxt 'with your lead, turn them on, for example: auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
    } else {
        Good 'logons, new processes, account and group changes, and audit policy changes are all audited'
    }
    $sec = Get-WinEvent -ListLog Security
    if ($sec) { Say ('  Security log: ' + $sec.RecordCount + ' events, up to ' + [math]::Round($sec.MaximumSizeInBytes / 1MB) + ' MB') }
}

# "What happened since the last hunt", straight from the Windows event logs.
function Show-Events {
    param([datetime]$Since)
    $hit = $false
    $lines = @()
    foreach ($e in @(Get-Evt 'Security' (XSince @(1102) $Since) 20)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  the Security log was CLEARED by ' + (EvData $e 'SubjectUserName') + ' (1102, T1070.001)'); $hit = $true }
    foreach ($e in @(Get-Evt 'System' (XSince @(104) $Since) 20)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  the ' + (EvData $e 'Channel') + ' log was CLEARED by ' + (EvData $e 'SubjectUserName') + ' (104, T1070.001)'); $hit = $true }
    $acct = @{ 4720 = 'account CREATED'; 4722 = 'account enabled'; 4725 = 'account disabled'; 4726 = 'account DELETED'; 4724 = 'password RESET'; 4723 = 'password changed' }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4720, 4722, 4725, 4726, 4724, 4723) $Since) 100)) {
        $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  ' + $acct[[int]$e.Id] + ': ' + (EvData $e 'TargetUserName') + ', by ' + (EvData $e 'SubjectUserName') + ' (' + $e.Id + ')')
        if ($e.Id -eq 4720 -or $e.Id -eq 4726) { $hit = $true }
    }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4728, 4732, 4756) $Since) 100)) {
        $m = EvData $e 'MemberName'
        if (-not $m -or $m -eq '-') { $m = EvData $e 'MemberSid' }
        $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  ADDED to group ' + (EvData $e 'TargetUserName') + ': ' + $m + ', by ' + (EvData $e 'SubjectUserName') + ' (' + $e.Id + ', T1098)')
        $hit = $true
    }
    foreach ($e in @(Get-Evt 'System' (XSince @(7045) $Since) 50)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  NEW service ' + (EvData $e 'ServiceName') + ': ' + (EvData $e 'ImagePath') + ' (7045, T1543.003)'); $hit = $true }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4698) $Since) 50)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  NEW scheduled task ' + (EvData $e 'TaskName') + ', by ' + (EvData $e 'SubjectUserName') + ' (4698, T1053.005)'); $hit = $true }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4719) $Since) 20)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  audit policy CHANGED by ' + (EvData $e 'SubjectUserName') + ' (4719, T1562.002)'); $hit = $true }
    foreach ($e in @(Get-Evt 'Microsoft-Windows-Windows Defender/Operational' (XSince @(5001, 5007) $Since) 20)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  Defender: ' + ((([string]$e.Message) -split "`n")[0]).Trim() + ' (' + $e.Id + ')'); $hit = $true }
    $ps = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3; StartTime = $Since } -MaxEvents 20 -ErrorAction SilentlyContinue)
    foreach ($e in $ps) {
        $sb = (EvData $e 'ScriptBlockText') -replace '\s+', ' '
        if ($sb.Length -gt 140) { $sb = $sb.Substring(0, 140) + '...' }
        $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  PowerShell ran code Windows calls suspicious: ' + $sb + ' (4104, T1059.001)')
        $hit = $true
    }
    # failed logons, by source address
    $f = @(Get-Evt 'Security' (XSince @(4625) $Since) 2000 | ForEach-Object { EvMap $_ })
    if ($f.Count -gt 0) {
        $lines += ('  failed logons since then: ' + $f.Count + ' (4625). Top sources:')
        $f | Group-Object { $_['IpAddress'] } | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
            $acc = (($_.Group | ForEach-Object { $_['TargetUserName'] } | Sort-Object -Unique | Select-Object -First 5) -join ', ')
            $lines += ('    ' + $_.Count + ' from ' + $_.Name + '  (accounts: ' + $acc + ')')
            if ($_.Count -ge 20) { $hit = $true }
        }
    }
    # logons over the network and RDP, by account and address
    $xp = XSince @(4624) $Since "Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3'"
    $ok = @(Get-Evt 'Security' $xp 3000 | ForEach-Object { EvMap $_ } | Where-Object {
        $u = $_['TargetUserName']; $a = $_['IpAddress']
        $u -and $u -notlike '*$' -and $u -ne 'ANONYMOUS LOGON' -and $a -and $a -notin '-', '::1', '127.0.0.1' })
    if ($ok.Count -gt 0) {
        $lines += '  logons over the network (type 3) and RDP (type 10) since then:'
        $ok | Group-Object { $_['TargetUserName'] + '|' + $_['IpAddress'] + '|' + $_['LogonType'] } | Sort-Object Count -Descending | Select-Object -First 12 | ForEach-Object {
            $p = $_.Name -split '\|'
            $m = ''
            if (Test-Outside $p[1]) { $m = '   <- from outside your networks'; $hit = $true }
            $lines += ('    ' + $p[0] + ' from ' + $p[1] + ' (type ' + $p[2] + ') x' + $_.Count + $m)
        }
    }
    if ($MyRole -eq 'dc') {
        $xk = XSince @(4769) $Since "Data[@Name='TicketEncryptionType']='0x17'"
        $rc4 = @(Get-Evt 'Security' $xk 2000 | ForEach-Object { EvMap $_ } | Where-Object { $s = $_['ServiceName']; $s -and $s -notlike '*$' -and $s -ne 'krbtgt' })
        if ($rc4.Count -gt 0) {
            if ($script:LearnOn) { Show-Learn 'kerberos' }
            $lines += ('  RC4 service tickets (4769, 0x17) since then: ' + $rc4.Count + '. Many for different accounts from one address is Kerberoasting (T1558.003):')
            $rc4 | Group-Object { $_['TargetUserName'] + ' from ' + $_['IpAddress'] } | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                $svcs = @($_.Group | ForEach-Object { $_['ServiceName'] } | Sort-Object -Unique)
                $lines += ('    ' + $_.Name + ': ' + $_.Count + ' tickets for ' + (($svcs | Select-Object -First 6) -join ', '))
                if ($svcs.Count -ge 3) { $hit = $true }
            }
        }
        $xa = XSince @(4768) $Since "Data[@Name='PreAuthType']='0'"
        $asr = @(Get-Evt 'Security' $xa 200)
        if ($asr.Count -gt 0) {
            $lines += ('  logons without Kerberos pre-auth (4768, AS-REP roasting, T1558.004): ' + $asr.Count)
            $asr | Group-Object { (EvData $_ 'TargetUserName') + ' from ' + (EvData $_ 'IpAddress') } | Select-Object -First 5 | ForEach-Object { $lines += ('    ' + $_.Name + ' x' + $_.Count) }
            $hit = $true
        }
        foreach ($e in @(Get-Evt 'Security' (XSince @(4740) $Since) 50)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm') + '  account LOCKED OUT: ' + (EvData $e 'TargetUserName') + ' (caller ' + (EvData $e 'TargetDomainName') + ')') }
    }
    return @{ Lines = $lines; Hit = $hit }
}

function Get-NewFiles {
    param([datetime]$Since)
    $exts = '.exe', '.dll', '.sys', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.scr', '.msi', '.lnk', '.jar', '.aspx', '.asp', '.ashx', '.asmx', '.php', '.jsp', '.war', '.py'
    $spots = @(
        @{ P = "$env:windir\System32"; D = 0 }, @{ P = "$env:windir\SysWOW64"; D = 0 }, @{ P = "$env:windir\System32\drivers"; D = 0 },
        @{ P = "$env:windir\Temp"; D = 2 }, @{ P = "$env:windir\Tasks"; D = 0 }, @{ P = 'C:\ProgramData'; D = 2 }, @{ P = 'C:\Users\Public'; D = 3 },
        @{ P = 'C:\PerfLogs'; D = 2 }, @{ P = 'C:\'; D = 0 }, @{ P = 'C:\inetpub'; D = 4 }, @{ P = $env:ProgramFiles; D = 2 }, @{ P = ${env:ProgramFiles(x86)}; D = 2 }
    )
    foreach ($u in @(Get-ChildItem 'C:\Users' -Directory -Force)) {
        foreach ($sub in 'AppData\Local\Temp', 'AppData\Roaming', 'Desktop', 'Downloads', 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') {
            $spots += @{ P = (Join-Path $u.FullName $sub); D = 1 }
        }
    }
    foreach ($s in $spots) {
        if (-not $s.P -or -not (Test-Path $s.P)) { continue }
        Get-FilesDepth -Path $s.P -Depth $s.D | Where-Object {
            ($exts -contains $_.Extension.ToLower()) -and ($_.CreationTime -gt $Since -or $_.LastWriteTime -gt $Since) -and
            ($_.Name -notmatch '^(?i)(pagefile|swapfile|hiberfil)\.sys$')
        }
    }
}

function Every-Check {
    param([datetime]$Since)
    Check-Clock
    Check-Tamper
    Check-Decoy
    Check-RAT
    Check-C2
    Check-Udp
    Check-Programs
    Check-Masq
    Check-CmdLines
    Check-Services
    Check-Drivers
    Check-Tasks
    Check-Persist
    Check-Wmi
    Check-Profiles
    Check-Defender $Since
    Check-Firewall
    Check-Rootkit
    Check-Accounts
    Check-Logins
    Check-Domain
    Check-Trip $Since
    Check-Spam $Since
    Check-Bits
    Check-Ads
    Check-Web
    Check-IisModules
    Check-Db
    Check-Ransom
    if ($MyRole -eq 'dc') { Check-DC; Check-ADVuln; Check-ADEvents $Since; Check-GpoFiles }
    Check-Bait $Since
    Check-Bugs
    Check-Audit
}

function Show-Summary {
    Save-Findings
    Say ''
    Say '======================================================================'
    if ($script:Found.Count -eq 0) {
        Good 'SUMMARY: nothing to look at.'
    } else {
        Warn ('SUMMARY: ' + $script:Found.Count + ' things to look at (top first):')
        $script:Found | ForEach-Object { Say ('  - ' + $_) }
        Say 'For each one: write down the time and what you see (menu 6, or: first30.ps1 note -Text "..."), tell your lead,'
        Say 'and save evidence before you delete anything (menu 5, or: first30.ps1 evidence -Path <file>).'
    }
}

# ---------------------------------------------------------------------------
# hunt
# ---------------------------------------------------------------------------
function Run-Hunt {
    $script:Found.Clear()
    if (-not (Test-Path $BaseDir)) { Warn 'No baseline yet. Run the start of game first (menu 1, or: first30.ps1 all).'; return }
    New-Snapshot
    Say ('Hunt on ' + $env:COMPUTERNAME + ' at ' + (Get-Date).ToString('HH:mm') + ' (' + (UtcNow) + ')')
    Say ('Baseline seal: ' + (Get-Seal $BaseDir) + '   <- must match your paper. If not, someone edited the baseline: tell your lead.')
    $prev = Get-PrevDir
    if (-not $prev) { $prev = $BaseDir }
    $prevTime = Get-DirTime $prev
    if (-not (Test-Path $LastHuntFile)) {
        $label = 'the start of the game (' + $prevTime.ToString('HH:mm') + ')'
        Say 'First hunt: comparing with the start-of-game snapshot.'
    } else {
        $label = 'your last hunt (' + $prevTime.ToString('HH:mm') + ')'
        Say ('Last hunt: ' + $prevTime.ToString('HH:mm') + ', its seal ' + (Get-Seal $prev) + ' (should match what you posted)')
    }
    Check-Self
    Collect-Common
    if ($MyRole -eq 'dc') { Collect-DC }
    $items = [ordered]@{}
    foreach ($k in $DiffItems.Keys) { $items[$k] = $DiffItems[$k] }
    if ($MyRole -eq 'dc') { foreach ($k in $DcDiffItems.Keys) { $items[$k] = $DcDiffItems[$k] } }
    $details = @()

    # ---- part 1: the last 30 minutes
    Sec 'last' ('1. What changed since ' + $label)
    $changed = $false
    foreach ($k in $items.Keys) {
        $cur = Read-Lines (Join-Path $script:SnapDir ($k + '.txt'))
        $old = Read-Lines (Join-Path $prev ($k + '.txt'))
        if ($null -eq $cur -or $null -eq $old) { continue }
        $d = Compare-Lines $old $cur
        if ($d.New.Count -eq 0 -and $d.Gone.Count -eq 0) { continue }
        $changed = $true
        Warn ($items[$k] + ': ' + $d.New.Count + ' new, ' + $d.Gone.Count + ' gone')
        $d.New  | Select-Object -First 15 | ForEach-Object { Say ('    NEW   ' + $_) }
        $d.Gone | Select-Object -First 15 | ForEach-Object { Say ('    GONE  ' + $_) }
        if ($d.New.Count -gt 15 -or $d.Gone.Count -gt 15) { Say '    ... the rest is in the details file' }
        $details += ('== ' + $items[$k] + ' since ' + $label)
        $details += ($d.New | ForEach-Object { 'NEW   ' + $_ })
        $details += ($d.Gone | ForEach-Object { 'GONE  ' + $_ })
    }
    if (-not $changed) { Good 'nothing in the inventory changed' } else { Flag }
    if ($script:LearnOn) { Show-Learn 'files' }
    $nf = @(Get-NewFiles $prevTime | Sort-Object LastWriteTime)
    if ($nf.Count -gt 0) {
        Say ('  New or changed programs and scripts since then (' + $nf.Count + '):')
        $nf | Select-Object -Last 30 | ForEach-Object {
            $sg = ''
            if ($_.Extension -match '(?i)^\.(exe|dll|sys|msi|ps1)$') { $sg = '  [' + (Get-SigStatus $_.FullName) + ']' }
            Say ('    ' + $_.LastWriteTime.ToString('HH:mm') + '  ' + $_.FullName + '  (' + $_.Length + ' bytes)' + $sg)
        }
        $details += '== new or changed programs and scripts'
        $details += ($nf | ForEach-Object { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + '  ' + $_.FullName })
        if ($nf | Where-Object { Test-UserWritable $_.FullName }) { Flag }
    } else {
        Say '  No new programs or scripts in the system, temp, user and web folders since then.'
    }
    if ($script:LearnOn) { Show-Learn 'events' }
    $ev = Show-Events $prevTime
    if ($ev.Lines.Count -gt 0) {
        Say '  From the Windows event logs since then:'
        $ev.Lines | ForEach-Object { Say $_ }
        if ($ev.Hit) { Flag }
    } else {
        Say '  Nothing new in the event logs that matters (no new accounts, services, tasks, cleared logs or guessing).'
    }
    $seen = 0
    if (Test-Path $NotesSeenFile) { [int]::TryParse((Get-Content $NotesSeenFile | Select-Object -First 1), [ref]$seen) | Out-Null }
    $all = @()
    if (Test-Path $NotesFile) { $all = @(Get-Content $NotesFile) }
    if ($all.Count -gt $seen) {
        Say '  Team notes since then (the changes your team made):'
        $all | Select-Object -Skip $seen | ForEach-Object { Say ('    ' + $_) }
    } else {
        Say '  No team notes since then. Changed something? Write it down (menu 6, or: first30.ps1 note -Text "what you did").'
    }
    Set-Content -Path $NotesSeenFile -Value $all.Count
    Nxt 'anything above that is NOT in your team notes was done by someone else. Start there.'

    # ---- part 2: since the baseline, as counts
    Sec 'base' ('2. Changed since the baseline (' + (Get-DirTime $BaseDir).ToString('HH:mm') + ')')
    $sum = @()
    foreach ($k in $items.Keys) {
        $cur = Read-Lines (Join-Path $script:SnapDir ($k + '.txt'))
        $old = Read-Lines (Join-Path $BaseDir ($k + '.txt'))
        if ($null -eq $cur -or $null -eq $old) { continue }
        $d = Compare-Lines $old $cur
        if ($d.New.Count -or $d.Gone.Count) {
            $sum += ('  ' + $items[$k] + ': ' + $d.New.Count + ' new, ' + $d.Gone.Count + ' gone')
            $details += ('== ' + $items[$k] + ' since the baseline')
            $details += ($d.New | ForEach-Object { 'NEW   ' + $_ })
            $details += ($d.Gone | ForEach-Object { 'GONE  ' + $_ })
        }
    }
    $detailFile = Join-Path $ReportDir ('hunt_' + $script:stamp + '_details.txt')
    Set-Content -Path $detailFile -Value $details
    if ($sum.Count -eq 0) { Good 'the box matches the baseline' } else { $sum | ForEach-Object { Say $_ }; Say ('  The full list is in ' + $detailFile + '. Part 1 shows the newest of these.') }

    # ---- part 3: checks that run every time
    Head '3. Checks that run every time (they do not trust the baseline)'
    Every-Check $prevTime
    Show-Summary
    Say ('This hunt''s seal: ' + (Get-Seal $script:SnapDir) + '   <- post it in your team channel with the time.')
    Set-Content -Path $LastHuntFile -Value $script:stamp
    Say ('Next hunt: about ' + (Get-Date).AddMinutes(30).ToString('HH:mm') + '.')
}

# ---------------------------------------------------------------------------
# backup (config copies you can restore or compare later)
# ---------------------------------------------------------------------------
function Run-Backup {
    Head 'backup: config copies'
    $cfg = Join-Path $script:SnapDir 'config'
    New-Item -ItemType Directory -Force -Path $cfg | Out-Null
    netsh advfirewall export (Join-Path $cfg 'firewall.wfw') | Out-Null
    Say '  saved config\firewall.wfw'
    Copy-Item "$env:windir\System32\drivers\etc\hosts" (Join-Path $cfg 'hosts') -Force
    Say '  saved config\hosts'
    reg export 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' (Join-Path $cfg 'run_hklm.reg') /y | Out-Null
    reg export 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' (Join-Path $cfg 'run_hkcu.reg') /y | Out-Null
    reg export 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' (Join-Path $cfg 'lsa.reg') /y | Out-Null
    reg export 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' (Join-Path $cfg 'winlogon.reg') /y | Out-Null
    Say '  saved config\run_hklm.reg, run_hkcu.reg, lsa.reg, winlogon.reg'
    schtasks /query /xml ONE 2>$null | Out-File -FilePath (Join-Path $cfg 'tasks.xml') -Encoding UTF8
    Say '  saved config\tasks.xml'
    if ($MyRole -eq 'dc' -and (Get-Command Backup-GPO -ErrorAction SilentlyContinue)) {
        $gp = Join-Path $cfg 'gpo'
        New-Item -ItemType Directory -Force -Path $gp | Out-Null
        Backup-GPO -All -Path $gp | Out-Null
        Say '  saved config\gpo (every Group Policy object)'
    }
    Backup-Extra $cfg
    Good ('backup written to ' + $script:SnapDir)
}

function Make-Baseline {
    if (-not (Test-Path $BaseDir)) {
        Copy-Item $script:SnapDir $BaseDir -Recurse -Force
        Good ('baseline created at ' + $BaseDir)
        Good ('baseline seal: ' + (Get-Seal $BaseDir) + '   <- WRITE THIS ON PAPER, with the box name')
        Auto-Note ('made the baseline (seal ' + (Get-Seal $BaseDir) + ')')
    } else {
        Say ('baseline already exists at ' + $BaseDir + ' (left as it is)')
        Say ('baseline seal: ' + (Get-Seal $BaseDir) + '   (it must match your paper)')
    }
}

# ---------------------------------------------------------------------------
# recon (a fast picture on the screen, then every check)
# ---------------------------------------------------------------------------
function Run-Recon {
    $script:Found.Clear()
    Head ('recon: ' + $env:COMPUTERNAME + '  role=' + $MyRole)
    Say ('OS: ' + (Get-CimInstance Win32_OperatingSystem).Caption)
    Say ''
    Say 'Local administrators:'
    Get-LocalAdmins | ForEach-Object { Say ('  ' + $_) }
    Say ''
    Say 'Enabled local users:'
    Get-LocalUser | Where-Object Enabled | Select-Object -ExpandProperty Name | ForEach-Object { Say ('  ' + $_) }
    Say ''
    Say 'Listening ports, the program, and the account it runs as (scored ones stay open):'
    $li = @(Get-ListenInfo)
    Show $li
    $real = @($li | Where-Object { Test-RealAccount $_.Account })
    if ($real.Count -gt 0) {
        Warn 'These ports run as a real user account, not a built-in one. Real accounts that run services are Kerberoasting targets:'
        $real | ForEach-Object { Say ('  ' + $_.Proto + ' ' + $_.Port + '  ' + $_.Process + '  ->  ' + $_.Account) }
        Say '  Check each one: does it have an SPN, a long random password, and AES only?'
    }
    if ($MyRole -eq 'dc') {
        Say ''
        Say 'Domain Admins:'
        try { (Get-ADGroupMember 'Domain Admins' -Recursive).name | ForEach-Object { Say ('  ' + $_) } } catch { net group "Domain Admins" /domain }
    }
    Check-Self
    Check-Plumbing
    Every-Check ((Get-Date).AddHours(-2))
    Show-Summary
}

function Run-All {
    New-Snapshot
    Collect-Common
    if ($MyRole -eq 'dc') { Collect-DC }
    Run-Backup
    Make-Baseline
    Run-Recon
    Say ''
    Head 'your first 30 minutes'
    Say '  1. Write the baseline seal above on paper, with the box name.'
    Say '  2. Change passwords (your lead has the plan), then write a note (menu 6).'
    Say '  3. Go through every finding above with your lead.'
    Say '  4. Stop pop-up spam and RDP screen watching (menu 11).'
    Say '  5. Optional: plant a bait file (menu 10).'
    Say '  6. Look for C2 (menu 3).'
    Say '  7. Hunt every 30 minutes (menu 2).'
    Say '  Also: protect the scoring engine and Black Team box (menu P), turn on logging (menu 12), read the'
    Say '  shared plumbing before any password change (menu 23), and look at the known bugs (menu 15).'
    Say '  On a DC: menu 24 lists every AD weak spot with its fix. Something wrong at any point: menu S.'
}

# ---------------------------------------------------------------------------
# c2: programs talking OUT of this box, and a 30-second watch
# ---------------------------------------------------------------------------
# At the invitational, a dropper pulled the imix agent onto a Linux box, and it
# called its C2 server at 10.197.114.55:8001 over HTTP. A Windows agent looks the
# same from here: a program, often unsigned and in a user folder, that keeps
# connecting to one address.
function Run-C2 {
    $script:Found.Clear()
    Check-C2
    Head 'c2: who keeps calling out? watching for 30 seconds...'
    $first = @{}
    $seen = @{}
    for ($i = 0; $i -lt 6; $i++) {
        foreach ($c in @(Get-OutboundConn -States 'Established', 'SynSent', 'TimeWait')) {
            $key = $c.Remote + ':' + $c.Port + '|' + $c.Owner
            $one = $key + '|' + $c.LPort
            if ($i -eq 0) { $first[$one] = 1; continue }
            if ($first.ContainsKey($one)) { continue }
            if (-not $seen.ContainsKey($key)) { $seen[$key] = @{} }
            $seen[$key][[string]$c.LPort] = $true
        }
        if ($i -lt 5) { Start-Sleep -Seconds 5 }
    }
    $procs = @{}
    foreach ($p in @(Get-CimInstance Win32_Process)) { $procs[[int]$p.ProcessId] = $p }
    # count only connections that were not there in the first look: a program
    # that keeps a few connections open all the time is not calling out again and again
    $hits = foreach ($k in @($seen.Keys)) {
        if ($seen[$k].Count -ge 3) {
            $parts = $k -split '\|'
            $owner = [int]$parts[1]
            $nm = '?'
            if ($owner -eq 0) { $nm = '(connection already closed)' } elseif ($procs[$owner]) { $nm = $procs[$owner].Name }
            [pscustomobject]@{ Count = $seen[$k].Count; To = $parts[0]; Program = $nm; Owner = $owner }
        }
    }
    if ($hits) {
        Warn 'these opened 3 or more new connections to the same place in 30 seconds.'
        Say  '  A C2 agent checking in looks like this (so do some normal programs). Check each one:'
        $hits | Sort-Object Count -Descending | ForEach-Object { Say ('    ' + $_.Count + ' new connections to ' + $_.To + ' from ' + $_.Program + ' (pid ' + $_.Owner + ')') }
    } else {
        Good 'nothing kept opening new connections to the same place'
    }
    Say ''
    Say 'Write down the time, the program and the address first: that is your incident report.'
    Say 'Save the program (menu 5), then cut the address off, in and out (menu 8, or: first30.ps1 block -Ip <address>)'
}

# ---------------------------------------------------------------------------
# block / unblock: cut an address off in both directions
# ---------------------------------------------------------------------------
# Safety: it will not block this box, your own RDP session, the default gateway
# or a DNS server. Never block the scoring engine: check the packet for it.
function Run-Block {
    Head 'block: cut addresses off, in and out'
    $list = @($Ip | Where-Object { $_ })
    $again = $false
    if ($list.Count -eq 0) {
        # no address given: put back every saved block
        $list = @(Get-BlockList)
        if ($list.Count -eq 0) { Warn 'Usage: first30.ps1 block -Ip <address>'; return }
        Say ('putting back the saved blocks: ' + ($list -join ', '))
        $again = $true
    }
    $keep = @()
    $keep += @(Get-NetTCPConnection -LocalPort 3389 -State Established | Select-Object -ExpandProperty RemoteAddress)
    $keep += @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop)
    $keep += @(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
    $keep += @(Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress)
    $keep = @($keep | Where-Object { $_ -and $_ -ne '0.0.0.0' } | ForEach-Object { ([string]$_) -replace '^::ffff:', '' } | Sort-Object -Unique)
    $off = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' } | Select-Object -ExpandProperty Name)
    if ($off.Count -gt 0) {
        Warn ('The firewall is OFF for: ' + ($off -join ', ') + '. Block rules do nothing there until it is on.')
        Warn 'Tell the lead before turning it on: it can also block scored services.'
    }
    $gpo = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { [string]$_.AllowLocalFirewallRules -eq 'False' } | Select-Object -ExpandProperty Name)
    if ($gpo.Count -gt 0) { Warn ('A Group Policy ignores rules made on this box for: ' + ($gpo -join ', ') + '. Block it in that Group Policy instead (on the DC).') }
    foreach ($a in $list) {
        if (-not (Test-IPv4 $a)) { Warn ('skipped ' + $a + ': not an IPv4 address'); continue }
        if ($a -match '^(127|0)\.') { Warn ('skipped ' + $a + ': that is this computer'); continue }
        if (Test-Protected $a) { Warn ('skipped ' + $a + ': it is a PROTECTED address (scoring engine or Black Team box; see menu P)'); continue }
        $hit = @($keep | Where-Object { Test-InNet $_ $a }) | Select-Object -First 1
        if ($hit) { Warn ('skipped ' + $a + ': it covers ' + $hit + ' (this box, your RDP session, the gateway, or DNS)'); continue }
        foreach ($d in 'Outbound', 'Inbound') {
            $name = 'first30 block ' + $a + ' ' + $d
            if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $name -Direction $d -RemoteAddress $a -Action Block -Profile Any | Out-Null
            }
        }
        $now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
        if (-not $again) {
            Add-Content -Path $BlockFile -Value ($a + ' ' + $now + ' UTC ' + $env:COMPUTERNAME)
            Auto-Note ('blocked ' + $a + ' in and out')
        }
        Good ('blocked ' + $a + ' in and out, at ' + $now + ' UTC on ' + $env:COMPUTERNAME)
    }
    Say ''
    Say 'For the incident report: the time, this host, the address, and what it was doing'
    Say '(C2 traffic is T1071, password guessing is T1110). Where else it shows up: first30.ps1 trace -Ip <address>'
    Say ('The list is in ' + $BlockFile + '. To undo one: first30.ps1 unblock -Ip <address>')
}

function Run-Unblock {
    Head 'unblock'
    $list = @($Ip | Where-Object { $_ })
    if ($list.Count -eq 0) { Warn 'Usage: first30.ps1 unblock -Ip <address>'; return }
    foreach ($a in $list) {
        Get-NetFirewallRule -DisplayName ('first30 block ' + $a + ' *') | Remove-NetFirewallRule
        if (Test-Path $BlockFile) {
            $rest = @(Get-Content $BlockFile | Where-Object { ($_ -split '\s+')[0] -ne $a })
            Set-Content -Path $BlockFile -Value $rest
        }
        Auto-Note ('unblocked ' + $a)
        Good ('unblocked ' + $a)
    }
}

# ---------------------------------------------------------------------------
# notes, networks
# ---------------------------------------------------------------------------
function Run-Note {
    if (-not $Text) { Warn 'Usage: first30.ps1 note -Text "what you did, and why"'; return }
    $l = Add-Note $Text
    Good ('saved in ' + $NotesFile + ':')
    Say ('  ' + $l)
    Say 'The next hunt shows it next to the changes, so everyone knows this one was yours.'
}

function Run-Notes {
    if (Test-Path $NotesFile) { Get-Content $NotesFile | ForEach-Object { Say ('  ' + $_) } } else { Say 'No notes yet. Write one: first30.ps1 note -Text "what you did"' }
}

function Run-Nets {
    $n = @($OurNets | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($n.Count -eq 0) {
        if (Test-Path $NetsFile) { Say ('Your networks: ' + ((Get-Content $NetsFile) -join ', ')) } else { Say 'No networks saved. Example: first30.ps1 nets -OurNets 10.100.130.0/24,192.168.220.0/24' }
        return
    }
    foreach ($x in $n) { if (-not (Test-IPv4 $x)) { Warn ('Not an IPv4 network: ' + $x + ' (example: 10.100.130.0/24)'); return } }
    Set-Content -Path $NetsFile -Value $n
    $script:Nets = $n
    Good ('saved. Addresses outside ' + ($n -join ', ') + ' are now marked in hunt, c2 and the login checks.')
}

# ---------------------------------------------------------------------------
# evidence: copy a suspicious file into the vault with its fingerprint and what
# uses it. The original is not touched. That is what the incident report needs.
# ---------------------------------------------------------------------------
function Run-Evidence {
    if (-not $Path) { Warn 'Usage: first30.ps1 evidence -Path C:\full\path\to\file'; return }
    if (-not (Test-Path -LiteralPath $Path)) { Warn ('Not found: ' + $Path); return }
    $full = (Resolve-Path -LiteralPath $Path).Path
    $qd = Join-Path $Vault 'quarantine'
    New-Item -ItemType Directory -Force -Path $qd | Out-Null
    $st = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $dest = Join-Path $qd ($st + '_' + $env:COMPUTERNAME + '_' + (Split-Path $full -Leaf) + '.evidence')
    $it = Get-Item -LiteralPath $full -Force
    if ($it.PSIsContainer) {
        $dest = $dest + '.zip'
        Compress-Archive -Path $full -DestinationPath $dest -Force
    } else {
        Copy-Item -LiteralPath $full -Destination $dest -Force
    }
    $h = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
    if (-not $it.PSIsContainer) { $h = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash }
    $r = @()
    $r += ('== Evidence saved ' + (UtcNow) + ' on ' + $env:COMPUTERNAME)
    $r += ('original : ' + $full)
    $r += ('copy     : ' + $dest + '   (renamed so it cannot run; the original was not touched)')
    $r += ('sha256   : ' + $h)
    $r += ('size     : ' + $it.Length + ' bytes; created ' + $it.CreationTime + '; changed ' + $it.LastWriteTime)
    $r += ('owner    : ' + (Get-Acl -LiteralPath $full).Owner)
    if (-not $it.PSIsContainer) {
        $sig = Get-AuthenticodeSignature -LiteralPath $full
        $r += ('signed   : ' + $sig.Status + ' ' + $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }))
        $vi = $it.VersionInfo
        if ($vi) { $r += ('version  : ' + $vi.CompanyName + ' / ' + $vi.ProductName + ' / original name ' + $vi.OriginalFilename) }
        $ads = @(Get-Item -LiteralPath $full -Stream * | Where-Object { $_.Stream -ne ':$DATA' } | ForEach-Object { $_.Stream + ' (' + $_.Length + ' bytes)' })
        if ($ads.Count -gt 0) { $r += ('streams  : ' + ($ads -join ', ')) }
    }
    $r += 'running  :'
    $r += @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $full } | ForEach-Object { '    pid ' + $_.ProcessId + ' ' + $_.CommandLine })
    $r += 'used by (services, tasks, Run keys):'
    $r += @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -like ('*' + $full + '*') } | ForEach-Object { '    service ' + $_.Name + ' (' + $_.State + ')' })
    $r += @(Get-ScheduledTask | Where-Object { ($_.Actions | ForEach-Object { [string]$_.Execute + ' ' + [string]$_.Arguments }) -like ('*' + $full + '*') } | ForEach-Object { '    task ' + $_.TaskPath + $_.TaskName })
    $r += @(Get-Autoruns | Where-Object { $_ -like ('*' + $full + '*') } | ForEach-Object { '    ' + $_ })
    $r += ''
    $r | ForEach-Object { Say $_ }
    Add-Content -Path (Join-Path $qd 'evidence_log.txt') -Value $r
    Auto-Note ('saved evidence: ' + $full + ' (sha256 ' + $h.Substring(0, 16) + '...)')
    Say 'Defender may remove the copy if it knows the file; the fingerprint above is already saved.'
    Say 'Next, with your lead:'
    Say ('  1. Write it down: the time, ' + $env:COMPUTERNAME + ', the path, the sha256 above, and what it did (MITRE number).')
    Say '  2. Stop what runs it (Task Manager > End task, or stop and disable the service).'
    Say '  3. Remove what starts it again (the service, task or Run key named above).'
    Say '  4. Only then delete or move the original.'
    Say ('The log of everything saved: ' + (Join-Path $qd 'evidence_log.txt'))
}

# ---------------------------------------------------------------------------
# trace: where has an address shown up on this box? First and last time seen,
# which the incident report needs (like find_malicious_ip in the hunting guide).
# ---------------------------------------------------------------------------
function Run-Trace {
    $a = @($Ip | Where-Object { $_ }) | Select-Object -First 1
    if (-not $a -or -not (Test-IPv4 $a)) { Warn 'Usage: first30.ps1 trace -Ip <IPv4 address>'; return }
    Head ('where has ' + $a + ' shown up on ' + $env:COMPUTERNAME + '?')
    $xp = "*[EventData[Data[@Name='IpAddress']='" + $a + "' or Data[@Name='IpAddress']='::ffff:" + $a + "']]"
    $ev = @(Get-Evt 'Security' $xp 5000)
    if ($ev.Count -gt 0) {
        $names = @{ 4624 = 'logon worked'; 4625 = 'logon FAILED'; 4648 = 'logon with typed credentials'; 4768 = 'Kerberos logon ticket'; 4769 = 'Kerberos service ticket'; 4771 = 'Kerberos pre-auth FAILED'; 4776 = 'NTLM check' }
        Say ('  Security log: ' + $ev.Count + ' events. First ' + ($ev | Select-Object -Last 1).TimeCreated + ', last ' + ($ev | Select-Object -First 1).TimeCreated)
        $ev | Group-Object Id | ForEach-Object {
            $accts = (($_.Group | ForEach-Object { EvData $_ 'TargetUserName' } | Sort-Object -Unique | Select-Object -First 6) -join ', ')
            Say ('    ' + $_.Count + ' x ' + $_.Name + ' ' + $names[[int]$_.Name] + '  (accounts: ' + $accts + ')')
        }
    } else {
        Say '  not in the Security log'
    }
    $fw = "$env:windir\System32\LogFiles\Firewall\pfirewall.log"
    if (Test-Path $fw) {
        $m = @(Select-String -Path $fw -SimpleMatch $a)
        if ($m.Count -gt 0) { Say ('  firewall log: ' + $m.Count + ' lines. First: ' + $m[0].Line); Say ('                 last:  ' + $m[-1].Line) }
    }
    $iis = @(Get-ChildItem 'C:\inetpub\logs\LogFiles' -Recurse -File -Filter *.log)
    if ($iis.Count -gt 0) {
        $m = @($iis | Select-String -SimpleMatch $a)
        if ($m.Count -gt 0) { Say ('  web server logs: ' + $m.Count + ' requests. First: ' + $m[0].Line); Say ('                    last:  ' + $m[-1].Line) }
    }
    $now = @(Get-NetTCPConnection | Where-Object { (([string]$_.RemoteAddress) -replace '^::ffff:', '') -eq $a })
    if ($now.Count -gt 0) { Say '  connected right now:'; $now | ForEach-Object { Say ('    ' + $_.State + ' local port ' + $_.LocalPort + ' -> ' + $_.RemotePort + ' (pid ' + $_.OwningProcess + ')') } } else { Say '  no open connection with it right now' }
    if ((Get-BlockList) -contains $a) { Say '  blocked: yes' } else { Say ('  blocked: no. To block it: first30.ps1 block -Ip ' + $a) }
    Say ('Write it down: first30.ps1 note -Text "' + $a + ': first seen ..., last seen ..., did ..."')
}

# ---------------------------------------------------------------------------
# bait: a file that looks like it holds an old password. Nobody on your team
# opens it, so anyone who does is red team. Windows logs who opened it (event
# 4663), and the made-up login name inside shows in failed logons if they try it.
# ---------------------------------------------------------------------------
function Run-Bait {
    if (-not $Path) {
        if ($script:BaitPath) { Say ('Bait planted: ' + $script:BaitPath + ' (login name ' + $script:BaitUser + ')') }
        else { Warn 'Usage: first30.ps1 bait -Path C:\Users\Public\Documents\<a believable name only your team knows>' }
        return
    }
    if ($script:BaitPath) { Warn ('A bait is already planted: ' + $script:BaitPath + '. One per box.'); return }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -match '(?i)^[a-z]:\\(inetpub|windows)\\' -or $full.StartsWith($Vault, [StringComparison]::OrdinalIgnoreCase)) {
        Warn 'Not under C:\inetpub, C:\Windows or the vault (this script reads web files itself). Try C:\Users\Public\Documents.'
        return
    }
    if (Test-Path -LiteralPath $full) { Warn ($full + ' already exists. Pick a new file name.'); return }
    if (-not (Test-Path -LiteralPath (Split-Path $full -Parent))) { Warn ('The folder ' + (Split-Path $full -Parent) + ' does not exist.'); return }
    $n = Get-Random -Minimum 10 -Maximum 99
    $user = ''
    foreach ($w in 'backup', 'deploy', 'report', 'monitor', 'sync') {
        $user = 'svc_' + $w + $n
        if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) -and -not ((net user $user /domain 2>$null) -match 'User name')) { break }
    }
    $pw = -join ((48..57) + (97..122) | Get-Random -Count 14 | ForEach-Object { [char]$_ })
    Set-Content -Path $full -Value @('# old service login - moved to the vault, do not use', ('server=' + $env:COMPUTERNAME), ('user=' + $user), ('password=' + $pw))
    # log every read of this one file: a SACL on it, and file-system auditing on
    $acl = Get-Acl -LiteralPath $full -Audit
    $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData, Delete, WriteData', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $full -AclObject $acl
    auditpol /set "/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
    Set-Content -Path $BaitFile -Value @($full, $user, (Get-Date).ToString('o'))
    $script:BaitPath = $full
    $script:BaitUser = $user
    Auto-Note ('planted the bait (details in ' + $BaitFile + ')')
    Good ('bait planted: ' + $full + '   (made-up login name inside: ' + $user + ')')
    Say  '  Windows now logs anyone who opens it (event 4663). File-system auditing was turned on for it.'
    Say  '  Never open the bait yourself. Do not tell anyone where it is outside your team.'
}

# ---------------------------------------------------------------------------
# quiet: stop pop-up spam from other machines and RDP screen watching. Two
# registry settings, saved first so undo-quiet can put them back. An admin on
# this box can still run msg.exe locally: then find that session and log it off.
# ---------------------------------------------------------------------------
function Run-Quiet {
    Head 'quiet: stop pop-up spam and screen watching'
    $undo = Join-Path $Vault 'quiet_undo.txt'
    if (-not (Test-Path $undo)) {
        Set-Content -Path $undo -Value @(('AllowRemoteRPC|' + [string](Get-ItemProperty $TsKey).AllowRemoteRPC), ('Shadow|' + [string](Get-ItemProperty $TsPolicy).Shadow))
    }
    New-ItemProperty -Path $TsKey -Name AllowRemoteRPC -Value 0 -PropertyType DWord -Force | Out-Null
    Good 'AllowRemoteRPC = 0: other machines can no longer send pop-ups (msg /server) or list and kick sessions'
    if (-not (Test-Path $TsPolicy)) { New-Item -Path $TsPolicy -Force | Out-Null }
    New-ItemProperty -Path $TsPolicy -Name Shadow -Value 0 -PropertyType DWord -Force | Out-Null
    Good 'RDP Shadow = 0: nobody can shadow (watch or control) your RDP sessions'
    $m = @(Get-Process -Name msg -ErrorAction SilentlyContinue)
    if ($m.Count -gt 0) { $m | Stop-Process -Force; Good ('stopped ' + $m.Count + ' running msg.exe') }
    Auto-Note 'turned on spam protection: AllowRemoteRPC 0, RDP Shadow 0 (undo: first30.ps1 undo-quiet)'
    Say ''
    Say 'An admin on this box can still send pop-ups locally. If they keep coming: quser shows the sessions;'
    Say 'log off the one you do not know (Task Manager > Users > Sign off), then change that account''s password.'
    Say 'A domain Group Policy can set Shadow again at the next refresh: hunt shows it if that happens.'
}

function Run-UndoQuiet {
    $undo = Join-Path $Vault 'quiet_undo.txt'
    if (-not (Test-Path $undo)) { Warn 'Nothing to undo: spam protection was not turned on with this script.'; return }
    foreach ($l in (Get-Content $undo)) {
        $p = $l -split '\|', 2
        $key = $TsKey
        if ($p[0] -eq 'Shadow') { $key = $TsPolicy }
        if ($p[1] -eq '') { Remove-ItemProperty -Path $key -Name $p[0] -ErrorAction SilentlyContinue; Good ($p[0] + ': removed (it was not set before)') }
        else { New-ItemProperty -Path $key -Name $p[0] -Value ([int]$p[1]) -PropertyType DWord -Force | Out-Null; Good ($p[0] + ': back to ' + $p[1]) }
    }
    Remove-Item $undo -Force
    Auto-Note 'turned spam protection off (undo-quiet)'
}

# ---------------------------------------------------------------------------
# menu
# ---------------------------------------------------------------------------
function Invoke-Action {
    param([string]$Name, [scriptblock]$Do)
    $log = Join-Path $ReportDir ($Name + '_' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    try { Start-Transcript -Path $log -Force | Out-Null } catch {}
    try { & $Do } catch { Warn ('error: ' + $_.Exception.Message) }
    try { Stop-Transcript | Out-Null } catch {}
}

function Show-MenuHeader {
    Write-Host ''
    Say '======================================================================'
    Say ('first30 on ' + $env:COMPUTERNAME + ' (' + (Get-CimInstance Win32_OperatingSystem).Caption + ', role ' + $MyRole + ')   ' + (Get-Date).ToString('HH:mm'))
    if (Test-Path $BaseDir) {
        Say ('Baseline: made ' + (Get-DirTime $BaseDir).ToString('HH:mm') + ', seal ' + (Get-Seal $BaseDir) + ' (must match your paper)')
        if (Test-Path $LastHuntFile) {
            $ago = [int]((Get-Date) - (Get-Item $LastHuntFile).LastWriteTime).TotalMinutes
            if ($ago -ge 30) { Warn ('Last hunt: ' + $ago + ' minutes ago  <- time to hunt (choice 2)') } else { Say ('Last hunt: ' + $ago + ' minutes ago') }
        } else { Say 'No hunt yet. Hunt every 30 minutes (choice 2).' }
    } else {
        Warn 'No baseline yet: start with choice 1.'
    }
    if ($script:Nets.Count -gt 0) { Say ('Your networks: ' + ($script:Nets -join ', ')) } else { Say 'Your networks: not set (choice N)' }
    if ($script:LearnOn) { Say 'Learn mode: ON (each check shows where to click and the command behind it)' } else { Say 'Learn mode: off' }
    if ((Get-RemindCount) -gt 0) { Say ('Reminders: ' + (Get-RemindCount) + ' open (R)') }
    if (Test-Path (Join-Path $Vault 'ontrack.txt')) { Say ('Back on track: before the SOS you were doing: ' + (Get-Content (Join-Path $Vault 'ontrack.txt') | Select-Object -First 1)) }
    if (@(Get-Protected).Count -eq 0) { Say 'Protected addresses: none yet. Add the scoring engine and Black Team box (P).' }
    if (Test-ServerCore) { Say 'This is Server Core (no desktop): the "click" lines in learn mode do not apply here. Use the "type" lines.' }
    Say '----------------------------------------------------------------------'
    Say '  1  Start of game: snapshot, baseline, config copies, every check  (read only; saves copies)'
    Say '  2  Hunt: what changed? Run every 30 minutes                       (read only)'
    Say '  3  Find C2: programs calling out (takes 30 seconds)               (read only)'
    Say '  4  Trace an address: where has it shown up?                      (read only)'
    Say '  5  Save evidence: copy a suspicious file safely                   (the original is not touched)'
    Say '  6  Write a team note: what you changed and why'
    Say '  7  Show the team notes'
    Say '  8  Block an address, in and out                                  CHANGES the firewall'
    Say '  9  Unblock an address                                            CHANGES the firewall'
    Say ' 10  Plant a bait file                                             CHANGES: adds one file + its auditing'
    Say ' 11  Stop pop-up spam and RDP screen watching                      CHANGES 2 registry settings'
    Say ' 12  Turn on the logging the hunt needs, and the Game Day view     CHANGES audit settings only'
    Say ' 14  Harden this box, one step at a time (each step asks first)    CHANGES (undo-harden puts it back)'
    Say ' 15  Known bugs: missing updates and loose settings                (read only)'
    Say ' 16  Domain check: is AD / the DC the real problem?                (read only)'
    Say ' 17  AD rescue: restore, enable, unlock users, krbtgt (on a DC)    CHANGES AD (each step asks)'
    Say ' 18  Kick someone off: end their session and block them           CHANGES'
    Say ' 19  Restore settings or web files from the start-of-game copies   CHANGES (the bad copy is saved)'
    Say ' 20  Find where a password is written down                       (read only)'
    Say ' 21  Incident facts for a report (your team writes the report)    (read only; saves a facts file)'
    Say ' 22  Log port scanners (tripwire)                                 CHANGES firewall logging only'
    Say ' 23  Shared plumbing: what breaks if you change a password        (read only; do this FIRST)'
    Say ' 24  AD weak spots, each with its fix (on a DC)                    (read only)'
    Say ' 25  Plant a decoy file (more bait; several allowed)              CHANGES: adds one file + its auditing'
    Say ' 26  Fence in a service your team installed (lock-svc)            CHANGES that service (auto-undo if it fails)'
    Say ' 27  Scrub a leaked password out of PowerShell history            CHANGES history files'
    Say ' 28  Report: every address, evidence, blocks, findings with MITRE IDs  (read only; saves a file)'
    Say '  S  SOS: something is wrong RIGHT NOW (start here when unsure)'
    Say '  E  Explain an error message'
    Say '  R  Reminders: PCRs to file, reports to write, what you were doing'
    Say '  P  Protect addresses that must never be blocked (scoring engine, Black Team box)'
    Say '  U  Undo the hardening steps'
    Say '  N  Set your team''s networks (from the packet)'
    Say '  L  Learn mode on/off'
    Say '  Q  Quit'
}

function Run-Menu {
    if (-not $script:LearnSet) { $script:LearnOn = $true }
    while ($true) {
        Show-MenuHeader
        $c = Read-Host 'Type a choice and press Enter'
        switch -Regex ($c) {
            '^1$'  { Invoke-Action 'all' { Run-All }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^2$'  { Invoke-Action 'hunt' { Run-Hunt }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^3$'  { Invoke-Action 'c2' { Run-C2 }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^4$'  { $script:Ip = @(Read-Host 'Address to trace (like 10.194.194.85)'); Invoke-Action 'trace' { Run-Trace }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^5$'  { $script:Path = Read-Host 'Full path of the file (like C:\Users\Public\x.exe)'; Invoke-Action 'evidence' { Run-Evidence }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^6$'  { $script:Text = Read-Host 'Type the note (example: changed the Administrator password; removed task Updater)'; if ($script:Text) { Run-Note }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^7$'  { Run-Notes; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^8$'  {
                $a = Read-Host 'Address to block (like 10.197.114.55). Never the scoring engine'
                if ((Read-Host ('Block ' + $a + ' in and out of ' + $env:COMPUTERNAME + '? Type yes to go ahead')) -eq 'yes') { $script:Ip = @($a); Invoke-Action 'block' { Run-Block } }
                Read-Host 'Press Enter to go back to the menu' | Out-Null
            }
            '^9$'  {
                $a = Read-Host 'Address to unblock'
                if ((Read-Host ('Unblock ' + $a + '? Type yes to go ahead')) -eq 'yes') { $script:Ip = @($a); Run-Unblock }
                Read-Host 'Press Enter to go back to the menu' | Out-Null
            }
            '^10$' { $script:Path = Read-Host 'Where should the bait go? A believable name only your team knows, like C:\Users\Public\Documents\old_sql_login.txt'; if ($script:Path) { Run-Bait }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^11$' {
                Say 'This sets AllowRemoteRPC = 0 and RDP Shadow = 0, and stops running msg.exe.'
                if ((Read-Host 'Type yes to go ahead') -eq 'yes') { Run-Quiet }
                Read-Host 'Press Enter to go back to the menu' | Out-Null
            }
            '^12$' { Invoke-Action 'audit' { Run-Audit }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^14$' { Invoke-Action 'harden' { Run-Harden }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^15$' { Invoke-Action 'bugs' { Run-Bugs }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^16$' { Invoke-Action 'domain' { $script:Found.Clear(); Check-Domain }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^17$' { Run-AD; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^18$' { $script:Ip = @(); $script:Text = ''; Run-Kick; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^19$' { Run-Restore; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^20$' { Run-FindPass; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^21$' { $script:Ip = @(); $script:Text = ''; $script:Path = ''; Run-Facts; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^22$' { $script:Text = Read-Host 'Type on to start logging scanners, off to stop, or Enter to see who scanned'; Run-Trip; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^23$' { Invoke-Action 'plumbing' { Check-Plumbing }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^24$' { Invoke-Action 'advuln' { if ($MyRole -eq 'dc') { Check-ADVuln } else { Say 'Run this on a domain controller.' } }; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^25$' { $script:Path = Read-Host 'Full path for the decoy (like C:\Users\Public\Documents\old_backup_login.txt), or Enter to list them'; $script:Text = ''; if ($script:Path) { if ((Read-Host 'Kind: type login or admin') -eq 'admin') { $script:Text = 'admin' } }; Run-Decoy; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^26$' { $script:Text = Read-Host 'Service name to fence in (Enter for help)'; Run-LockSvc; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^27$' { Run-Scrub; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^28$' { Run-Report; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^[sS]$' { Run-SOS; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^[eE]$' { $script:Text = ''; Run-Why; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^[rR]$' { Run-Reminders; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^[pP]$' { $script:Ip = @((Read-Host 'Addresses to protect, separated by commas (Enter to list)') -split '[ ,]+' | Where-Object { $_ }); Run-Protect; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^[uU]$' { Run-UndoHarden; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^[nN]$' { $script:OurNets = @(Read-Host 'Your team''s networks from the packet, separated by commas (like 10.100.130.0/24,192.168.220.0/24)'); Run-Nets; Read-Host 'Press Enter to go back to the menu' | Out-Null }
            '^[lL]$' { $script:LearnOn = -not $script:LearnOn }
            '^[qQ]$' { return }
            default  { if ($c) { Say 'Pick one of the choices in the list.' } }
        }
    }
}


# ===========================================================================
# ADDED IN V4 (November 2026). Everything from here to "end of v4" is new:
# SOS (the "something is wrong right now" button), an error explainer, domain
# checks, AD rescue, known bugs, hardening with undo, kick, restore, a password
# finder, incident facts, reminders, protected addresses, tripwire logging and a
# honey account. Nothing here changes the box unless you type yes.
# ===========================================================================

# ---- compatibility: Windows Server 2012 and 2012 R2 (PowerShell 3 and 4) ----
# Last year's domain controller was Server 2012 R2. These commands do not exist
# there, so the checks that used them came back empty (no accounts, no files).
# These stand-ins are only defined when the real command is missing.
if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
    function Get-LocalUser {
        [CmdletBinding()]
        param([string]$Name)
        $f = 'LocalAccount=True'
        if ($Name) { $f += " AND Name='" + $Name.Replace("'", "''") + "'" }
        foreach ($u in @(Get-CimInstance Win32_UserAccount -Filter $f)) {
            New-Object PSObject -Property @{
                Name = $u.Name; Enabled = (-not $u.Disabled); PasswordRequired = $u.PasswordRequired
                SID = (New-Object System.Security.Principal.SecurityIdentifier($u.SID)); Description = $u.Description; FullName = $u.FullName
            }
        }
    }
}
if (-not (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
    function Get-LocalGroupMember {
        [CmdletBinding()]
        param([string]$Group)
        $on = $false
        foreach ($l in @(net localgroup "$Group" 2>$null)) {
            if ($l -match '^-{10,}') { $on = $true; continue }
            if (-not $on -or -not $l.Trim() -or $l -match '^The command completed') { continue }
            $n = $l.Trim(); $src = 'ActiveDirectory'
            if ($n -notmatch '\\') { $n = $env:COMPUTERNAME + '\' + $n; $src = 'Local' }
            elseif ($n -like ($env:COMPUTERNAME + '\*')) { $src = 'Local' }
            New-Object PSObject -Property @{ Name = $n; ObjectClass = 'User'; PrincipalSource = $src }
        }
    }
}
if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
    function Get-FileHash {
        [CmdletBinding()]
        param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath, [string]$Algorithm = 'SHA256')
        $p = $LiteralPath
        if (-not $p) { $p = $Path }
        try {
            $fs = [System.IO.File]::OpenRead($p)
            try { $h = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm).ComputeHash($fs) } finally { $fs.Close() }
            return (New-Object PSObject -Property @{ Algorithm = $Algorithm; Hash = ([BitConverter]::ToString($h) -replace '-', ''); Path = $p })
        } catch { return $null }
    }
}
if (-not (Get-Command Compress-Archive -ErrorAction SilentlyContinue)) {
    function Compress-Archive {
        [CmdletBinding()]
        param([string]$Path, [string]$DestinationPath, [switch]$Force)
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            if ($Force -and (Test-Path $DestinationPath)) { Remove-Item $DestinationPath -Force }
            [System.IO.Compression.ZipFile]::CreateFromDirectory($Path, $DestinationPath)
        } catch {}
    }
}
# Get-ChildItem -Recurse -Depth N, also on PowerShell 3 and 4 (where -Depth does not exist)
function Get-FilesDepth {
    param([string[]]$Path, [int]$Depth, [string[]]$Include = @())
    $Path = @($Path | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($Path.Count -eq 0) { return @() }
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        if ($Include.Count -gt 0) { return @(Get-ChildItem -Path $Path -Recurse -Depth $Depth -File -Force -Include $Include) }
        return @(Get-ChildItem -Path $Path -Recurse -Depth $Depth -File -Force)
    }
    $out = @()
    $level = @(foreach ($p in $Path) { Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue })
    for ($d = 0; $d -le $Depth -and $level.Count -gt 0; $d++) {
        $next = @()
        foreach ($dir in $level) {
            foreach ($c in @(Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue)) {
                if ($c.PSIsContainer) { $next += $c; continue }
                if ($Include.Count -eq 0) { $out += $c; continue }
                foreach ($pat in $Include) { if ($c.Name -like $pat) { $out += $c; break } }
            }
        }
        $level = $next
    }
    return $out
}

# ---- v4 helpers ----
function Why    { param($m) Write-Host ('  Why: ' + (Clean $m)) -ForegroundColor DarkCyan }
function ByHand { param($m) Write-Host ('  By hand: ' + (Clean $m)) -ForegroundColor DarkCyan }
function Ask-Yes {
    param([string]$Q)
    $a = Read-Host ($Q + ' Type yes to go ahead (anything else skips)')
    return ($a -eq 'yes')
}
function SecureToPlain {
    param($S)
    if (-not $S) { return '' }
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($S)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
function Get-RegValue {
    param([string]$Key, [string]$Name)
    $v = Get-ItemProperty -Path $Key -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $v) { return $null }
    return $v.$Name
}
function Test-ServerCore {
    return ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'InstallationType') -eq 'Server Core')
}

# ---- reminders: PCRs to file, reports to write; the menu shows them until done ----
function Add-Remind {
    param([string]$T)
    $f = Join-Path $Vault 'reminders.txt'
    $have = @(Get-Content $f -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 8 -and $_.Substring(8) -eq $T })
    if ($have.Count -eq 0) { Add-Content -Path $f -Value ((Get-Date).ToString('HH:mm') + ' | ' + $T) }
}
function Get-RemindCount { return @(Get-Content (Join-Path $Vault 'reminders.txt') -ErrorAction SilentlyContinue | Where-Object { $_ }).Count }
function Run-Reminders {
    Head 'reminders: things not done yet'
    $f = Join-Path $Vault 'reminders.txt'
    $ot = Join-Path $Vault 'ontrack.txt'
    if (Test-Path $ot) { Say ('  Before your last SOS you were: ' + (Get-Content $ot | Select-Object -First 1)) }
    $r = @(Get-Content $f -ErrorAction SilentlyContinue | Where-Object { $_ })
    if ($r.Count -eq 0) { Say '  None. The script adds one when you change a password (PCR), kick someone, or find an incident.'; return }
    for ($i = 0; $i -lt $r.Count; $i++) { Say ('  ' + ($i + 1) + '. ' + $r[$i]) }
    $a = Read-Host 'Type the numbers that are done (like 1 3), C to clear the SOS note, or press Enter to keep everything'
    if (-not $a) { return }
    if ($a -match '^[cC]$') { Remove-Item $ot -Force -ErrorAction SilentlyContinue; Say '  Cleared.'; return }
    $done = @($a -split '[ ,]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
    $keep = @(); $gone = @()
    for ($i = 0; $i -lt $r.Count; $i++) { if ($done -contains ($i + 1)) { $gone += $r[$i] } else { $keep += $r[$i] } }
    Set-Content -Path $f -Value $keep
    if ($gone.Count -gt 0) { Add-Content -Path (Join-Path $Vault 'reminders_done.txt') -Value $gone }
    Good ('marked done; ' + $keep.Count + ' left')
}

# ---- protected addresses: block and kick never touch these ----
function Get-Protected { return @(Get-Content (Join-Path $Vault 'protect.txt') -ErrorAction SilentlyContinue | ForEach-Object { ($_ -split ' ')[0] } | Where-Object { $_ }) }
function Test-Protected {
    param([string]$A)
    foreach ($p in (Get-Protected)) {
        if ((Test-InNet (($p -split '/')[0]) $A) -or (Test-InNet (($A -split '/')[0]) $p)) { return $true }
    }
    return $false
}
function Run-Protect {
    Head 'protected addresses (block and kick never touch these)'
    $f = Join-Path $Vault 'protect.txt'
    $list = @($Ip | Where-Object { $_ })
    if ($list.Count -eq 0) {
        $have = @(Get-Content $f -ErrorAction SilentlyContinue)
        if ($have.Count -gt 0) { $have | ForEach-Object { Say ('  ' + $_) } }
        else { Say '  None yet. Add the scoring engine and the Black Team box from the packet: first30.ps1 protect -Ip <address>,<address>' }
        Why 'a block that hits the scoring engine fails every check (rule 4.11). Last year touching the .3 Black Team box locked teams out.'
        return
    }
    foreach ($a in $list) {
        if (-not (Test-IPv4 $a)) { Warn ('skipped ' + $a + ': not an IPv4 address or network'); continue }
        if (@(Get-Protected) -contains $a) { Say ('  ' + $a + ' is already protected'); continue }
        Add-Content -Path $f -Value ($a + ' added ' + (UtcNow))
        Good ('protected: ' + $a)
    }
    Auto-Note ('protected from blocks: ' + ($list -join ', '))
}
function Run-Unprotect {
    $f = Join-Path $Vault 'protect.txt'
    foreach ($a in @($Ip | Where-Object { $_ })) {
        $rest = @(Get-Content $f -ErrorAction SilentlyContinue | Where-Object { ($_ -split ' ')[0] -ne $a })
        Set-Content -Path $f -Value $rest
        Good ('no longer protected: ' + $a)
    }
}

# ---- incident facts: the facts a report needs (rule 9.4). Your team writes the report. ----
$script:FactsFile = ''
function Start-Facts {
    param([string]$About)
    $d = Join-Path $Vault 'incidents'
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    $script:FactsFile = Join-Path $d ('facts_' + $env:COMPUTERNAME + '_' + (Get-Date -Format 'MMdd-HHmmss') + '.txt')
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^127\.' } | Select-Object -ExpandProperty IPAddress) -join ' '
    Set-Content -Path $script:FactsFile -Value @(
        'INCIDENT FACTS (not a report: your team writes the report in its own words)',
        ('box        : ' + $env:COMPUTERNAME + '   ' + $ips),
        ('OS         : ' + (Get-CimInstance Win32_OperatingSystem).Caption),
        ('about      : ' + $About),
        ('started    : ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '  (' + (UtcNow) + ')'),
        '----- what happened, in order (times are this box''s clock) -----')
}
function Fact {
    param([string]$T)
    if ($script:FactsFile) { Add-Content -Path $script:FactsFile -Value ((Get-Date).ToString('HH:mm:ss') + '  ' + $T) }
}
function Stop-Facts {
    if ($script:FactsFile -and (Test-Path $script:FactsFile) -and @(Get-Content $script:FactsFile).Count -le 6) {
        Remove-Item $script:FactsFile -Force
        $script:FactsFile = ''
    }
}

# ---------------------------------------------------------------------------
# error explainer: paste the exact error; it says what it means and the next step.
# Each line: words to look for @@ what it means @@ what to do. Add your own lines.
# ---------------------------------------------------------------------------
$script:ErrTable = @'
timed out|timeout|0x80072ee2|did not properly respond after a period of time@@Nothing answered. A firewall is dropping it (here, on the target, or the router), or the box is down.@@ping it, then Test-NetConnection <ip> -Port <port> from another box. Check Windows Firewall (wf.msc) and the router. It is not a password problem.
actively refused|connection refused|10061@@The box answered, but nothing listens on that port: the service is stopped or crashed.@@Get-Service <name>, then Start-Service <name>. netstat -ano | findstr LISTENING shows what listens.
access is denied|0x80070005|error 5\b|system error 5@@Access denied: the account lacks the right, or you are not elevated (not Run as administrator).@@open PowerShell with Run as administrator. On a DC, use a Domain Admin account.
user name or password is incorrect|logon failure|0x8007052e|0xc000006d|error 1326|data 52e@@Wrong password (the account exists).@@check it. Stop after 2 tries so the account does not lock. An app may still use the OLD password.
account is locked|locked out|0xc0000234|error 1909|data 775@@The account is locked out (wrong passwords, or red team locking it on purpose).@@on the DC: Unlock-ADAccount <name> (menu 17), then find who was guessing (events 4740, 4625, 4771).
account is disabled|account has been disabled|0xc0000072|error 1331|data 533@@The account is disabled.@@on the DC: Enable-ADAccount <name> (menu 17). Local: Enable-LocalUser <name>.
password has expired|0xc0000071|error 1330|data 532@@The password expired.@@set a new one (and file a PCR if the scorer uses it).
must change password|0xc0000224|data 773@@The user must change the password before logging on.@@set a password for them on the DC (menu 17, choice 7).
user does not exist|no such user|data 525|0xc0000064@@That account does not exist (deleted or renamed).@@restore it on the DC (menu 17: deleted users), then file a PCR.
trust relationship between this workstation and the primary domain failed|error 1789@@This computer's account in AD was changed or reset: the domain no longer trusts it.@@Test-ComputerSecureChannel -Repair -Credential (Get-Credential)   (a Domain Admin login). Menu 16 checks it.
no logon servers available|error 1311|0xc000005e@@This computer cannot reach a domain controller: DC down, DNS wrong, or a firewall.@@menu 16 (domain check): DNS must point at the DC; ports 88 and 389 must be open.
domain either does not exist or could not be contacted|error 1355@@DNS cannot find the domain. Domain members must use the DC for DNS.@@Get-DnsClientServerAddress, then set the DC as DNS. nltest /dsgetdc:<domain> tests it.
security database on the server does not have a computer account@@The computer account was deleted or reset in AD.@@rejoin the domain, or restore the computer object (menu 17 lists deleted objects).
time difference|clock skew|krb_ap_err_skew|0xc0000133@@The clock is more than 5 minutes off the DC. Kerberos refuses.@@w32tm /resync /force (on the DC: w32tm /config /syncfromflags:manual ... then /resync).
rpc server is unavailable|0x800706ba|error 1722@@RPC is blocked or the service is down (firewall, or AllowRemoteRPC = 0).@@check the firewall between the boxes, and that the target is up.
network path was not found|system error 53|error 53\b@@SMB (port 445) cannot be reached: wrong name, server down, or a firewall.@@Test-NetConnection <server> -Port 445
network name cannot be found|system error 67@@The share name does not exist (deleted or renamed).@@Get-SmbShare on the server. Restore the share if it was removed.
unable to contact the server.*active directory web services|active directory web services@@The AD PowerShell commands need the AD Web Services service (port 9389). Red team stops it to blind you.@@Start-Service ADWS (on the DC), then try again.
cannot find drive.*'ad'|a drive with the name 'ad' does not exist@@The ActiveDirectory module is not loaded.@@Import-Module ActiveDirectory
is not recognized as the name of a cmdlet@@That command does not exist here: a module is missing, or PowerShell is too old (2012 has 3.0/4.0).@@Get-Command <name>. For AD commands: Import-Module ActiveDirectory (on a DC).
running scripts is disabled|execution policy@@Windows blocks running .ps1 files here.@@powershell -NoProfile -ExecutionPolicy Bypass -File .\first30.ps1   (or double-click first30.cmd)
insufficient access rights@@Not allowed in AD: the account is not a Domain Admin, or AdminSDHolder protects that account.@@use a Domain Admin account. If a normal admin was blocked, check AdminSDHolder changes (menu 2 shows them).
unwilling to perform|does not meet the password policy|password does not meet|error 2245@@AD refused the new password: too short, too simple, or used before.@@use a longer password with upper and lower case, a number and a symbol.
503\b.*service unavailable|service unavailable|http error 503@@IIS: the application pool is stopped (crashed, or its account password changed).@@Start-WebAppPool <pool>  (inetmgr: Application Pools). If its account password changed, update it there.
500\.19@@IIS: web.config is broken or unreadable.@@restore web.config from the backup (menu 19), or fix the line the error names.
401\.1|401 - unauthorized|\b401\b@@HTTP 401: the login was rejected (a changed password, or the app's own login to AD or SQL broke).@@test the login by hand; read the app's log for the real error.
403\b|forbidden@@HTTP 403: permissions, or directory browsing is off and there is no default page.@@check the folder permissions and the default document (inetmgr).
\b404\b|page not found|404 - file@@HTTP 404: the page or file is gone (deleted or moved), or the site points at the wrong folder.@@compare the web root with the backup (menu 19).
login failed for user|error: 18456@@SQL Server rejected the login (wrong password, or SQL logins are turned off).@@check the app's connection string password. SQL logins need Mixed Mode.
winrm cannot complete the operation|winrm.*cannot@@WinRM (remote PowerShell) cannot reach the box: service stopped, firewall, or not trusted.@@Test-WSMan <box>; on the target: Enable-PSRemoting (with your lead).
there is a time and/or date difference@@Kerberos clock problem between client and server.@@w32tm /resync /force on both, from the DC.
'@
function Decode-Error {
    param([string]$T)
    $t = ([string]$T).ToLower()
    $n = 0
    foreach ($line in ($script:ErrTable -split "`r?`n")) {
        $p = $line -split '@@'
        if ($p.Count -lt 3) { continue }
        if ($t -match $p[0]) { $n++; Say ('  ' + $n + '. ' + $p[1]); Say ('     Do this: ' + $p[2]) }
    }
    if ($n -eq 0) {
        Say '  No match in the list. Read it slowly: the LAST words usually name the cause.'
        Say '     Do this: search the exact words plus the program name, or ask your lead. Add the answer to this list.'
    }
}
function Run-Why {
    Head 'what this error means'
    $t = $Text
    if (-not $t) { $t = Read-Host 'Paste or type the exact error message, then press Enter' }
    if (-not $t) { return }
    Say ('  You saw: ' + $t.Substring(0, [math]::Min(200, $t.Length)))
    Decode-Error $t
    Say '  Tip: the exact words matter. "timed out" and "refused" point to different fixes.'
}

# ---------------------------------------------------------------------------
# small network helper: is a TCP port open? (works on PowerShell 3, no ping first)
# ---------------------------------------------------------------------------
function Test-Port {
    param([string]$H, [int]$P, [int]$Ms = 2000)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($H, $P, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne($Ms) -and $c.Connected) { $c.EndConnect($ar); return $true }
        return $false
    } catch { return $false } finally { $c.Close() }
}

# ---------------------------------------------------------------------------
# domain health. At Invitational 2 most red services came from AD on the DC
# (deleted, locked, disabled users), and last year the DC fell and took the
# Linux boxes with it. Members: does the domain still trust this computer, can it
# find a DC, is the clock close? DCs: are the services and shares AD needs up,
# and were users deleted?
# ---------------------------------------------------------------------------
function Check-Domain {
    $cs = Get-CimInstance Win32_ComputerSystem
    if (-not $cs.PartOfDomain) { return }
    Sec 'domain' 'Domain: is AD working for this box? (T1531, T1098, T1078.002)'
    $dom = $cs.Domain
    $bad = $false
    if ($MyRole -eq 'dc') {
        foreach ($s in 'NTDS', 'ADWS', 'DNS', 'Kdc', 'Netlogon', 'DFSR', 'W32Time') {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($svc -and [string]$svc.Status -ne 'Running') { Warn ($s + ' (' + $svc.DisplayName + ') is ' + $svc.Status); $bad = $true }
        }
        $shares = @(net share 2>$null | ForEach-Object { ($_ -split '\s+')[0] })
        foreach ($n in 'SYSVOL', 'NETLOGON') {
            if ($shares -notcontains $n) { Warn ($n + ' share is MISSING: logons and Group Policy break'); $bad = $true }
        }
        if (Get-Command Get-ADObject -ErrorAction SilentlyContinue) {
            $since = (Get-Date).AddHours(-12)
            if (Test-Path $BaseDir) { $since = Get-DirTime $BaseDir }
            $del = @(Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties whenChanged, samAccountName |
                Where-Object { $_.whenChanged -gt $since })
            if ($del.Count -gt 0) {
                Warn ('domain users DELETED since ' + $since.ToString('HH:mm') + ': ' + (($del | ForEach-Object { $_.samAccountName }) -join ', '))
                Say  '    Scored users? Restore them: menu 17 (AD rescue), then file PCRs.'
                $bad = $true
            }
            $dcs = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
            if ($dcs.Count -gt 1) {
                $rf = @(repadmin /replsummary 2>$null | Select-String -Pattern '\s[1-9]\d*\s+/\s+\d+\s')
                if ($rf.Count -gt 0) { Warn 'replication between domain controllers is FAILING (repadmin /replsummary)'; $bad = $true }
            }
        }
        if (-not $bad) { Good 'AD services and the SYSVOL and NETLOGON shares are up, and no users were deleted' }
    } else {
        $sc = $null
        try { $sc = Test-ComputerSecureChannel -ErrorAction Stop } catch { $sc = $null }
        if ($sc -eq $false) { Warn 'the domain does NOT trust this computer anymore (its computer account was changed or deleted in AD)'; $bad = $true }
        elseif ($sc) { Good 'the domain trusts this computer (secure channel OK)' }
        $dcl = @(nltest ('/dsgetdc:' + $dom) 2>&1)
        $dcip = (($dcl | Select-String -Pattern 'Address: \\\\([0-9.]+)') | Select-Object -First 1)
        if ($dcip) {
            $ip = $dcip.Matches[0].Groups[1].Value
            Say ('  domain controller found: ' + $ip)
            foreach ($p in 88, 389) {
                if (-not (Test-Port $ip $p)) { Warn ('  port ' + $p + ' on the DC is CLOSED or filtered'); $bad = $true }
            }
            $w = @(w32tm /stripchart ('/computer:' + $ip) /samples:1 /dataonly 2>$null) | Select-Object -Last 1
            if ($w -match '([+-]\d+\.\d+)s') {
                $off = [math]::Abs([double]$Matches[1])
                if ($off -gt 240) { Warn ('  clock is ' + [int]$off + ' seconds off the DC: Kerberos fails past 300'); $bad = $true }
                else { Say ('  clock: ' + [math]::Round($off, 1) + ' seconds off the DC (fine)') }
            }
        } else {
            Warn ('cannot find a domain controller for ' + $dom + ': ' + (($dcl | Select-Object -Last 1) -join ''))
            $bad = $true
        }
    }
    if ($bad) {
        Flag
        Nxt 'trust broken: Test-ComputerSecureChannel -Repair -Credential (Get-Credential). Users deleted or locked: menu 17. Service stopped: Start-Service <name>.'
        Why 'when many services go red at once, find the ONE thing they share (AD, DNS, the firewall) before fixing them one by one.'
    }
}

# ---------------------------------------------------------------------------
# known bugs: missing updates and loose settings red team breaks in with
# ---------------------------------------------------------------------------
$script:BugN = 0
function Bug {
    param([string]$What, [string]$Why, [string]$Fix)
    $script:BugN++
    Say ('  ' + $script:BugN + '. ' + $What)
    Say ('     Why: ' + $Why)
    Say ('     Fix: ' + $Fix)
}
function Get-LastUpdate {
    $h = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn)
    if ($h.Count -eq 0) { return $null }
    return $h[-1].InstalledOn
}
# settings that are NOT the Windows default and hand red team a way in
function Bugs-Settings {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated') -eq 1 -and
        (Get-RegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated') -eq 1) {
        Bug 'AlwaysInstallElevated is on' 'any account can install an .msi file that runs as SYSTEM.' 'delete the AlwaysInstallElevated value in HKLM and HKCU ...\Policies\Microsoft\Windows\Installer'
    }
    $dp = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'
    if ($dp) { Bug ('auto-logon password stored in the registry (account ' + (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName') + ')') 'the password sits in plain text in Winlogon (DefaultPassword).' 'remove DefaultPassword (and AutoAdminLogon) from HKLM\...\Winlogon, then change that password (PCR if scored).' }
    foreach ($u in "$env:windir\Panther\Unattend.xml", "$env:windir\Panther\Unattend\Unattend.xml", "$env:windir\System32\Sysprep\unattend.xml", "$env:windir\System32\Sysprep\Panther\unattend.xml", 'C:\unattend.xml', "$env:windir\System32\sysprep.inf") {
        if ((Test-Path $u) -and (Select-String -Path $u -Pattern '<Password>|AdminPassword' -Quiet)) { Bug ('setup file with a password: ' + $u) 'setup answer files keep the admin password (often only base64).' 'delete the file after saving a copy as evidence; change the password it holds.' }
    }
    if ((Get-RegValue $lsa 'LmCompatibilityLevel') -ne $null -and (Get-RegValue $lsa 'LmCompatibilityLevel') -lt 3) { Bug ('LmCompatibilityLevel is ' + (Get-RegValue $lsa 'LmCompatibilityLevel') + ' (LM and NTLMv1 allowed)') 'NTLMv1 answers crack in minutes, and relaying is easy.' 'set LmCompatibilityLevel to 5 (menu 14), after checking no old system needs NTLMv1.' }
    if ((Get-RegValue $lsa 'NoLMHash') -eq 0) { Bug 'LM password hashes are stored (NoLMHash = 0)' 'LM hashes crack in seconds.' 'set NoLMHash to 1, then change passwords (old LM hashes stay until then).' }
    if ((Get-RegValue $lsa 'RestrictAnonymousSAM') -eq 0) { Bug 'anonymous users may list accounts (RestrictAnonymousSAM = 0)' 'red team gets every user name without a password.' 'set RestrictAnonymousSAM to 1 (menu 14).' }
    if ((Get-RegValue $lsa 'EveryoneIncludesAnonymous') -eq 1) { Bug 'EveryoneIncludesAnonymous = 1' 'anything "Everyone" can open, an anonymous visitor can open too.' 'set it to 0 (menu 14).' }
    $pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    if ((Get-RegValue $pp 'NoWarningNoElevationOnInstall') -eq 1 -or (Get-RegValue $pp 'UpdatePromptSettings') -eq 1) {
        Bug 'Point and Print installs drivers with no prompt' 'this undoes the PrintNightmare fix: any account becomes SYSTEM.' ('set NoWarningNoElevationOnInstall and UpdatePromptSettings to 0 in ' + $pp)
    }
    $acl = Get-Acl "$env:windir\System32\config\SAM" -ErrorAction SilentlyContinue
    if ($acl -and @($acl.Access | Where-Object { [string]$_.IdentityReference -match 'BUILTIN\\Users' -and [string]$_.FileSystemRights -match 'Read' }).Count -gt 0) {
        Bug 'normal users can read the SAM file (HiveNightmare, CVE-2021-34527/36934)' 'with a shadow copy, any account reads every local password hash.' 'icacls %windir%\system32\config\*.* /inheritance:e  then update Windows. Ask your lead about old shadow copies.'
    }
    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smb -and $smb.EnableSMB1Protocol) { Bug 'SMBv1 is ON' 'EternalBlue/WannaCry use SMBv1, and it has no protection against relaying.' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force (menu 14). Check nothing scored needs SMBv1.' }
    if ($MyRole -eq 'dc' -and $smb -and -not $smb.RequireSecuritySignature) { Bug 'SMB signing is NOT required on this domain controller' 'DCs require it by default: someone turned it off so they can relay logins to the DC.' 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force' }
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ((Get-RegValue $ts 'fDenyTSConnections') -eq 0 -and (Get-RegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication') -eq 0) {
        Bug 'RDP is on WITHOUT Network Level Authentication' 'anyone can reach the logon screen and pre-login bugs without a password.' 'turn NLA on (menu 14): System Properties > Remote > "Allow connections only from computers running Remote Desktop with NLA".'
    }
    $g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
    if ($g -and $g.Enabled) { Bug 'the Guest account is ENABLED' 'Guest needs no password.' 'Disable-LocalUser Guest   (or: net user guest /active:no)' }
    foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { $_.PathName })) {
        $pn = [string]$s.PathName
        if ($pn -notmatch '^"' -and $pn -match '^[a-zA-Z]:\\[^"]* [^"]*\.exe' -and $pn -notmatch '(?i)^[a-z]:\\windows\\') {
            Bug ('unquoted service path: ' + $s.Name + ' -> ' + $pn) 'Windows tries C:\Program.exe first for C:\Program Files\...: a planted file there runs as SYSTEM.' ('add quotes: sc.exe config ' + $s.Name + ' binPath= "\"<full path>\" <arguments>"')
        }
        $exe = Get-ExeFromCmd $pn
        if ($exe -and (Test-Path -LiteralPath $exe)) {
            $wa = @((Get-Acl -LiteralPath $exe -ErrorAction SilentlyContinue).Access | Where-Object {
                [string]$_.IdentityReference -match '(Everyone|BUILTIN\\Users|Authenticated Users|INTERACTIVE)$' -and
                [string]$_.FileSystemRights -match 'Write|Modify|FullControl' -and [string]$_.AccessControlType -eq 'Allow' })
            if ($wa.Count -gt 0) { Bug ('service program anyone can change: ' + $s.Name + ' -> ' + $exe) 'a normal account swaps the file and it runs as the service (often SYSTEM) at the next start.' ('icacls "' + $exe + '" /remove:g Users Everyone "Authenticated Users"   (save evidence first)') }
        }
    }
    if ($MyRole -eq 'dc' -and (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        $asr = @(Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Select-Object -ExpandProperty SamAccountName)
        if ($asr.Count -gt 0) { Bug ('accounts with Kerberos pre-auth OFF (AS-REP roasting): ' + ($asr -join ', ')) 'anyone can ask the DC for a hash of their password and crack it offline.' 'Set-ADAccountControl <name> -DoesNotRequirePreAuth $false (menu 14)' }
        $sysvol = "$env:windir\SYSVOL\domain\Policies"
        if (Test-Path $sysvol) {
            $gpp = @(Get-ChildItem -Path $sysvol -Recurse -Include *.xml -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword="[^"]+' -List | Select-Object -ExpandProperty Path)
            if ($gpp.Count -gt 0) { Bug ('Group Policy Preferences passwords in SYSVOL (MS14-025): ' + ($gpp -join '; ')) 'every domain user can read SYSVOL, and the cpassword key is public: it is the password in plain text.' 'delete those preference items (gpmc.msc), then change those passwords.' }
        }
        $ud = @(Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties PrimaryGroupID | Where-Object { $_.PrimaryGroupID -ne 516 } | Select-Object -ExpandProperty Name)
        if ($ud.Count -gt 0) { Bug ('computers with UNCONSTRAINED delegation (not DCs): ' + ($ud -join ', ')) 'whoever owns that computer can steal the tickets of anyone who logs in to it, including Domain Admins.' 'Set-ADComputer <name> -TrustedForDelegation $false (check the app does not need it).' }
    }
}
# missing updates: the newest update installed, against the dates famous holes were fixed
function Bugs-Updates {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$cv.CurrentBuildNumber
    $last = Get-LastUpdate
    $ls = 'unknown'
    if ($last) { $ls = $last.ToString('yyyy-MM-dd') }
    Say ('  Windows build ' + $build + '.' + $cv.UBR + ', newest update installed: ' + $ls)
    if (-not $last) { return }
    $smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
    if ($build -lt 16299 -and $last -lt [datetime]'2017-03-14' -and $smb1) { Bug 'no update since before March 2017, and SMBv1 is on: EternalBlue (MS17-010)' 'a remote SYSTEM exploit that needs no password (WannaCry).' 'install the updates, or turn SMBv1 off now (menu 14).' }
    if ($build -le 7601 -and $last -lt [datetime]'2019-05-14' -and (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0) { Bug 'no update since before May 2019 on an old Windows with RDP on: BlueKeep (CVE-2019-0708)' 'a remote SYSTEM exploit through RDP, no password needed.' 'update, or turn on NLA (menu 14) which blocks the unauthenticated part.' }
    if ($MyRole -eq 'dc' -and $build -lt 20348 -and $last -lt [datetime]'2020-08-11') { Bug 'domain controller without the August 2020 update: Zerologon (CVE-2020-1472)' 'anyone on the network becomes Domain Admin in seconds.' 'install the updates on this DC first.' }
    $sp = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($sp -and [string]$sp.Status -eq 'Running' -and $build -lt 20348 -and $last -lt [datetime]'2021-07-06') { Bug 'Print Spooler runs without the July 2021 update: PrintNightmare (CVE-2021-34527)' 'any domain account becomes SYSTEM (on a DC: Domain Admin).' 'update, or stop and disable the Spooler if printing is not scored (menu 14).' }
    if ($MyRole -eq 'dc' -and $build -lt 20348 -and $last -lt [datetime]'2021-11-09') { Bug 'domain controller without the November 2021 update: noPac (CVE-2021-42278/42287)' 'any domain account becomes Domain Admin (easier when MachineAccountQuota is above 0).' 'install the updates; set MachineAccountQuota to 0 (menu 14).' }
    if ((Get-Service CertSvc -ErrorAction SilentlyContinue) -and $last -lt [datetime]'2022-05-10') { Bug 'AD Certificate Services without the May 2022 update: Certifried (CVE-2022-26923)' 'any domain account can get a certificate that logs in as a DC.' 'install the updates.' }
    if ($last -lt (Get-Date).AddYears(-1)) { Say '  The newest update is more than a year old: expect public exploits for this box. Patch if your lead agrees.' }
}
# Windows defaults that are worth hardening (shown in the full check, not every hunt)
function Bugs-Defaults {
    Say ''
    Say '  Default settings worth hardening (menu 14 does these with an undo):'
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -ne 0) { Say '    - LLMNR is on: tools like Responder answer for any mistyped name and catch password hashes.' }
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 1) { Say '    - WDigest keeps passwords in memory in plain text (mimikatz reads them).' }
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -ne 1) { Say '    - LSA protection is off: tools can read LSASS memory (passwords and hashes).' }
    if ($MyRole -eq 'dc' -and [string](Get-Service Spooler -ErrorAction SilentlyContinue).Status -eq 'Running') { Say '    - Print Spooler runs on a DC: Microsoft says to turn it off there (printer-bug attacks on the DC).' }
    if ($MyRole -eq 'dc' -and (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        $maq = (Get-ADObject ((Get-ADDomain).DistinguishedName) -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
        if ($maq -gt 0) { Say ('    - MachineAccountQuota is ' + $maq + ': any domain user can add computers to the domain (used in noPac and RBCD attacks).') }
    }
    $sb = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    if ($sb -ne 1) { Say '    - PowerShell script block logging is off: red team''s PowerShell leaves no trace.' }
}
function Check-Bugs {
    Sec 'bugs' 'Known bugs: missing updates and loose settings red team uses (T1190, T1068, T1210)'
    $script:BugN = 0
    Bugs-Settings
    Bugs-Updates
    if ($script:BugN -gt 0) {
        Flag
        Nxt 'fix the settings now (most have a menu 14 step). Missing updates: write them down and ask your lead before patching.'
        Why 'red team scans for exactly these first. Each one fixed is one less way in, and it belongs in your report.'
    } else { Good 'no loose settings or famous missing updates found (the full check: menu 15)' }
}
function Run-Bugs {
    Head 'known bugs: the full check (read only)'
    $script:BugN = 0
    Bugs-Settings
    Bugs-Updates
    Bugs-Defaults
    if ($script:BugN -eq 0) { Good 'no bugs found in the list' }
    Add-Remind ('known bugs on ' + $env:COMPUTERNAME + ': ' + $script:BugN + ' found at ' + (Get-Date).ToString('HH:mm') + '. Fix or write up the open ones.')
}

# ---------------------------------------------------------------------------
# tripwire: Windows Firewall can log every packet it drops. A scanner hits many
# closed ports in seconds, so one address with many dropped ports is a scan. It
# only LOGS: nothing extra is blocked.
# ---------------------------------------------------------------------------
function Get-ScanHits {
    param([datetime]$Since)
    $f = [Environment]::ExpandEnvironmentVariables((Get-NetFirewallProfile -Name Domain).LogFileName)
    if (-not $f -or -not (Test-Path $f)) { $f = "$env:windir\System32\LogFiles\Firewall\pfirewall.log" }
    if (-not (Test-Path $f)) { return @() }
    $ports = @{}; $count = @{}; $first = @{}; $lastt = @{}
    foreach ($l in @(Get-Content $f -Tail 20000 -ErrorAction SilentlyContinue)) {
        $p = $l -split ' '
        if ($p.Count -lt 8 -or $p[2] -ne 'DROP') { continue }
        $t = [datetime]::MinValue
        if (-not [datetime]::TryParse(($p[0] + ' ' + $p[1]), [ref]$t) -or $t -lt $Since) { continue }
        $src = $p[4]
        if (-not $ports.ContainsKey($src)) { $ports[$src] = @{}; $count[$src] = 0; $first[$src] = $t }
        $ports[$src][$p[7]] = 1; $count[$src]++; $lastt[$src] = $t
    }
    $rows = @()
    foreach ($s in $ports.Keys) {
        if ($ports[$s].Count -ge 5) {
            $rows += (New-Object PSObject -Property @{ Address = $s; Ports = $ports[$s].Count; Packets = $count[$s]; First = $first[$s].ToString('HH:mm:ss'); Last = $lastt[$s].ToString('HH:mm:ss') })
        }
    }
    return @($rows | Sort-Object Ports -Descending)
}
function Check-Trip {
    param([datetime]$Since)
    if (-not (Test-Path (Join-Path $Vault 'trip.txt'))) { return }
    Sec 'trip' 'Tripwire: who scanned this box (dropped packets in the firewall log; T1046)'
    $h = @(Get-ScanHits $Since)
    if ($h.Count -gt 0) {
        Warn ('addresses that hit 5 or more closed ports since ' + $Since.ToString('HH:mm') + ':')
        Show ($h | Select-Object Address, Ports, Packets, First, Last)
        Flag
        Nxt 'is it the scoring engine, the Black Team box, or a teammate''s scan? If not: first30.ps1 block -Ip <address>'
    } else { Good 'no scanning in the firewall log' }
}
function Run-Trip {
    Head 'tripwire: log every packet the firewall drops'
    $tf = Join-Path $Vault 'trip.txt'
    switch -Regex ($Text) {
        '^on$' {
            if (Test-Path $tf) { Say 'already on'; return }
            $old = @(Get-NetFirewallProfile | ForEach-Object { $_.Name + '|' + $_.LogBlocked + '|' + $_.LogMaxSizeKilobytes })
            Set-Content -Path $tf -Value $old
            Set-NetFirewallProfile -Profile Domain, Private, Public -LogBlocked True -LogMaxSizeKilobytes 32767
            Good 'the firewall now logs dropped packets (pfirewall.log). Nothing extra is blocked.'
            $off = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' } | Select-Object -ExpandProperty Name)
            if ($off.Count -gt 0) { Warn ('the firewall is OFF for ' + ($off -join ', ') + ': nothing is dropped there, so nothing is logged.') }
            Why 'a red team scan hits many closed ports in seconds. The hunt lists those addresses, with times, for blocks and reports.'
            Auto-Note 'tripwire on: firewall logs dropped packets'
        }
        '^off$' {
            if (-not (Test-Path $tf)) { Say 'not on'; return }
            foreach ($l in (Get-Content $tf)) {
                $p = $l -split '\|'
                if ($p.Count -ge 3) { Set-NetFirewallProfile -Profile $p[0] -LogBlocked $p[1] -LogMaxSizeKilobytes ([int]$p[2]) }
            }
            Remove-Item $tf -Force
            Good 'tripwire off (logging back to how it was)'
            Auto-Note 'tripwire off'
        }
        default {
            if (Test-Path $tf) { Say 'tripwire: on' } else { Say 'tripwire: off. Turn it on: first30.ps1 trip -Text on' }
            $h = @(Get-ScanHits ((Get-Date).AddHours(-24)))
            if ($h.Count -gt 0) { Show ($h | Select-Object Address, Ports, Packets, First, Last) } else { Say '  no scans in the last 24 hours' }
        }
    }
}

# ---------------------------------------------------------------------------
# hardening, one step at a time. Every step says what it does and why, asks
# first, and writes an undo line. undo-harden puts every step back, newest first.
# ---------------------------------------------------------------------------
function Add-Undo { param([string]$L) Add-Content -Path (Join-Path $Vault 'harden_undo.txt') -Value $L }
function Set-HReg {
    param([string]$Key, [string]$Name, $Value, [string]$Type = 'DWord')
    $old = Get-RegValue $Key $Name
    if ([string]$old -eq [string]$Value) { Say ('    already set: ' + $Name + ' = ' + $Value); return $false }
    if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
    $o = '<none>'
    if ($null -ne $old) { $o = [string]$old }
    try {
        Set-ItemProperty -Path $Key -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        Add-Undo ('REG|' + $Key + '|' + $Name + '|' + $o + '|' + $Type)
        Say ('    set ' + $Name + ' = ' + $Value + '   (was ' + $o + ')')
        return $true
    } catch { Warn ('could not set ' + $Name + ': ' + $_.Exception.Message); return $false }
}
function H-Step {
    param([string]$Title, [string]$WhyText, [string]$Risk, [scriptblock]$Do)
    Say ''
    Say ('-- ' + $Title)
    Why $WhyText
    if ($Risk) { Say ('  Careful: ' + $Risk) }
    if (-not (Ask-Yes '  Do this step?')) { Say '    skipped'; return }
    try { & $Do } catch { Warn ('this step failed and was left as it was: ' + $_.Exception.Message) }
}
function Run-Harden {
    Head 'harden this box, one step at a time'
    Say '  Each step asks first. Nothing here needs the internet. To put everything back: first30.ps1 undo-harden'
    Say '  Check the scoreboard after each step. If a service goes red, undo right away.'
    H-Step 'Turn off SMB version 1' 'SMBv1 is the 1990s file-sharing protocol behind EternalBlue (WannaCry). Nothing modern needs it.' 'a very old client (Windows XP, an old copier or NAS) would lose its file shares.' {
        $c = Get-SmbServerConfiguration
        if ($c -and $c.EnableSMB1Protocol) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Add-Undo 'SMB1|True'; Say '    SMBv1 server is off'; Auto-Note 'harden: SMBv1 off' }
        else { Say '    already off (or not readable on this Windows version)' }
    }
    H-Step 'Turn off LLMNR and NetBIOS name lookups' 'when DNS has no answer, Windows shouts the name to the whole network. Red team answers "that is me" and collects password hashes (Responder).' 'a very old app that finds servers by NetBIOS name only would stop finding them.' {
        [void](Set-HReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0)
        foreach ($i in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces')) { [void](Set-HReg $i.PSPath 'NetbiosOptions' 2) }
        Auto-Note 'harden: LLMNR and NetBIOS name lookups off'
    }
    H-Step 'Stop Windows keeping plain-text passwords in memory (WDigest)' 'with WDigest on, Mimikatz reads the real password of everyone logged on. Off is the default since Windows 8.1, so "on" means someone set it.' '' {
        [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0)
    }
    H-Step 'Protect the LSASS process (takes effect at the next reboot)' 'LSASS holds the password hashes of everyone logged on. LSA protection stops other programs from reading its memory.' 'an old smart-card or antivirus plug-in that loads into LSASS may stop loading. It only starts after a reboot, so it cannot break anything today.' {
        [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1)
    }
    H-Step 'Log every command line and every PowerShell script block' 'event 4688 then shows the full command red team ran, and event 4104 shows their PowerShell even when it was hidden or encoded.' '' {
        [void](Set-HReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1)
        [void](Set-HReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1)
        auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
        Auto-Note 'harden: command-line and PowerShell script block logging on'
    }
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        H-Step 'Turn Microsoft Defender real-time protection back on' 'red team turns it off first so their tools are not caught.' '' {
            $m = Get-MpPreference
            if ($m -and $m.DisableRealtimeMonitoring) { Set-MpPreference -DisableRealtimeMonitoring $false; Add-Undo 'DEFENDER|rtoff'; Say '    real-time protection is on'; Auto-Note 'harden: Defender real-time on' }
            else { Say '    already on' }
        }
    }
    H-Step 'Turn the Windows Firewall on, and keep every port that is listening now' 'a firewall that is off lets red team reach every port. This first adds an allow rule for each port that is listening right now, so scored services keep answering, then turns the firewall on and logs dropped packets.' 'a service that is stopped right now gets no allow rule. Start your scored services first.' {
        $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
        if ($off.Count -eq 0) { Say '    all three profiles are already on' }
        else {
            $tcp = @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
            $udp = @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 } | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
            if ($tcp.Count -gt 0) { New-NetFirewallRule -DisplayName 'first30 keep TCP' -Group 'first30 keep' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $tcp | Out-Null }
            if ($udp.Count -gt 0) { New-NetFirewallRule -DisplayName 'first30 keep UDP' -Group 'first30 keep' -Direction Inbound -Action Allow -Protocol UDP -LocalPort $udp | Out-Null }
            Add-Undo 'FWRULES|first30 keep'
            foreach ($p in $off) { Set-NetFirewallProfile -Name $p.Name -Enabled True -LogBlocked True; Add-Undo ('FWPROFILE|' + $p.Name) }
            Say ('    firewall on for: ' + (($off | ForEach-Object { $_.Name }) -join ', ') + '. Kept open: TCP ' + ($tcp -join ',') + '  UDP ' + ($udp -join ','))
            Auto-Note 'harden: Windows Firewall turned on (listening ports kept open)'
        }
    }
    H-Step 'Stop Windows trying to download certificate lists (for a game network with no internet)' 'with no internet, every signature check waits many seconds for a download that never comes. That makes this script, and logons, slow.' 'on a box that HAS internet, new trusted root certificates would stop arriving. Undo puts it back.' {
        [void](Set-HReg 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' 'DisableRootAutoUpdate' 1)
    }
    H-Step 'Turn off the Guest account' 'Guest needs no password. It should never be on.' '' {
        $g = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
        if ($g -and $g.Enabled) { net user $g.Name /active:no | Out-Null; Add-Undo ('GUEST|' + $g.Name); Say '    Guest is off' } else { Say '    already off' }
    }
    H-Step 'Require Network Level Authentication for Remote Desktop' 'without NLA, anyone can reach the logon screen (and bugs like BlueKeep) before proving who they are.' 'a very old RDP client (before Windows 7) could no longer connect.' {
        [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1)
    }
    H-Step 'Refuse the old LM and NTLMv1 logins, and stop anonymous account listing' 'LM and NTLMv1 answers are cracked in minutes. Anonymous listing lets red team read every account name with no login.' 'an old Linux Samba client or an old app that only speaks NTLMv1 would fail to log in. Check the scoreboard after this one.' {
        [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5)
        [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1)
        [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1)
        [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1)
        Auto-Note 'harden: NTLMv2 only, anonymous listing off'
    }
    H-Step 'Require SMB signing on this server' 'without signing, a login that red team catches can be relayed to this box (NTLM relay).' 'an old client that cannot sign would lose its file shares.' {
        [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1)
    }
    if ($MyRole -eq 'dc') {
        H-Step 'Domain controller: turn off the Print Spooler' 'attackers use it to force the DC to log in to a machine they own (PrinterBug), and PrintNightmare runs code through it.' 'do not do this if printing from this DC is a scored service.' {
            $s = Get-CimInstance Win32_Service -Filter "Name='Spooler'"
            if ($s -and ($s.State -eq 'Running' -or $s.StartMode -ne 'Disabled')) {
                Add-Undo ('SVC|Spooler|' + $s.StartMode + '|' + $s.State)
                Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled; Say '    Print Spooler stopped and disabled'; Auto-Note 'harden: Print Spooler off on the DC'
            } else { Say '    already off' }
        }
        if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
            H-Step 'Domain: stop normal users from adding computers (MachineAccountQuota 0)' 'by default any user can join 10 computers. Red team makes a fake computer account and uses it to become an admin (RBCD, noPac).' 'if your team joins computers with a non-admin account, use a Domain Admin for that instead.' {
                $dn = (Get-ADDomain).DistinguishedName
                $q = (Get-ADObject $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
                if ($q -ne 0) { Set-ADObject $dn -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }; Add-Undo ('ADMAQ|' + $q); Say ('    was ' + $q + ', now 0'); Auto-Note 'harden: MachineAccountQuota 0' } else { Say '    already 0' }
            }
            H-Step 'Domain: turn Kerberos pre-authentication back on for every account' 'an account without pre-authentication hands out a crackable login reply to anyone, with no password (AS-REP roasting).' 'a very old app that needs it off would fail to log in. That is rare.' {
                $a = @(Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true')
                if ($a.Count -eq 0) { Say '    no such accounts' }
                foreach ($u in $a) { Set-ADAccountControl $u -DoesNotRequirePreAuth $false; Add-Undo ('ASREP|' + $u.SamAccountName); Say ('    fixed ' + $u.SamAccountName) }
                if ($a.Count -gt 0) { Auto-Note ('harden: pre-authentication back on for ' + (($a | ForEach-Object { $_.SamAccountName }) -join ', ')) }
            }
        }
    }
    Say ''
    Good 'hardening pass finished. Check the scoreboard now. Undo everything: first30.ps1 undo-harden'
}
function Run-UndoHarden {
    Head 'undo the hardening steps (newest first)'
    $f = Join-Path $Vault 'harden_undo.txt'
    $l = @(Get-Content $f -ErrorAction SilentlyContinue | Where-Object { $_ })
    if ($l.Count -eq 0) { Say '  Nothing to undo.'; return }
    [array]::Reverse($l)
    foreach ($x in $l) {
        $p = $x -split '\|'
        try {
            switch ($p[0]) {
                'REG' {
                    if ($p[3] -eq '<none>') { Remove-ItemProperty -Path $p[1] -Name $p[2] -ErrorAction SilentlyContinue }
                    else { Set-ItemProperty -Path $p[1] -Name $p[2] -Value $p[3] -Type $p[4] }
                    Say ('  put back ' + $p[2] + ' = ' + $p[3])
                }
                'SMB1'      { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force; Say '  SMBv1 back on' }
                'DEFENDER'  { Say '  Defender real-time protection was off before. It is left ON (turning it off again helps nobody).' }
                'FWRULES'   { Get-NetFirewallRule -Group $p[1] -ErrorAction SilentlyContinue | Remove-NetFirewallRule; Say '  removed the "first30 keep" rules' }
                'FWPROFILE' { Set-NetFirewallProfile -Name $p[1] -Enabled False; Say ('  firewall profile ' + $p[1] + ' off again') }
                'GUEST'     { Say '  Guest was on before. It is left OFF.' }
                'SVC'       { $m = $p[2]; if ($m -eq 'Auto') { $m = 'Automatic' }; Set-Service $p[1] -StartupType $m; if ($p[3] -eq 'Running') { Start-Service $p[1] }; Say ('  service ' + $p[1] + ' back to ' + $m) }
                'ADMAQ'     { Set-ADObject (Get-ADDomain).DistinguishedName -Replace @{ 'ms-DS-MachineAccountQuota' = [int]$p[1] }; Say ('  MachineAccountQuota back to ' + $p[1]) }
                'ASREP'     { Say ('  ' + $p[1] + ' had pre-authentication off. It is left ON. If an app needs it off: Set-ADAccountControl ' + $p[1] + ' -DoesNotRequirePreAuth $true') }
            }
        } catch { Warn ('could not undo: ' + $x + ' (' + $_.Exception.Message + ')') }
    }
    Move-Item $f (Join-Path $Vault ('harden_undo_done_' + (Get-Date -Format 'HHmmss') + '.txt')) -Force
    Auto-Note 'undid the hardening steps'
    Good 'done. Some registry settings need a restart of the service or a reboot to change back.'
}

# ---------------------------------------------------------------------------
# AD rescue (on a domain controller): the Alex case. Users deleted, disabled or
# locked out: put them back, then PCR, then the incident report, then back on track.
# ---------------------------------------------------------------------------
function Get-DeletedUsers {
    @(Get-ADObject -IncludeDeletedObjects -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -Properties samAccountName, lastKnownParent, whenChanged |
        Where-Object { $_.samAccountName -and $_.samAccountName -notmatch '\$$' })
}
function Read-NewPassword {
    param([string]$For)
    $a = Read-Host ('New password for ' + $For + ' (hidden; 14+ characters, upper, lower, number, symbol)') -AsSecureString
    $b = Read-Host 'Type it again' -AsSecureString
    if ((SecureToPlain $a) -ne (SecureToPlain $b)) { Warn 'The two did not match. Nothing changed.'; return $null }
    if ((SecureToPlain $a).Length -lt 8) { Warn 'Too short. Nothing changed.'; return $null }
    return $a
}
function Run-AD {
    Head 'AD rescue: restore, enable and unlock domain users'
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Warn 'The AD commands are not on this box. Run this on a domain controller.'
        Say '  If they are missing on a DC: Import-Module ActiveDirectory. If that fails: Start-Service ADWS'
        return
    }
    $dom = Get-ADDomain
    if (-not $dom) { Warn 'Cannot talk to AD. Start-Service ADWS, then try again. (Error help: menu E)'; return }
    Start-Facts 'AD accounts deleted, disabled or locked'
    while ($true) {
        $del = @(Get-DeletedUsers)
        $dis = @(Search-ADAccount -AccountDisabled -UsersOnly | Where-Object { $_.SamAccountName -notmatch '^(krbtgt|Guest|DefaultAccount)$' })
        $lock = @(Search-ADAccount -LockedOut -UsersOnly)
        $pol = Get-ADDefaultDomainPasswordPolicy
        $rb = @(Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' | Where-Object { $_.EnabledScopes.Count -gt 0 }).Count -gt 0
        Say ''
        Say ('  Domain ' + $dom.DNSRoot + ':  deleted users ' + $del.Count + '   disabled ' + $dis.Count + '   locked out ' + $lock.Count + '   lockout after ' + $pol.LockoutThreshold + ' bad tries (0 = never)   Recycle Bin ' + $(if ($rb) { 'ON' } else { 'off' }))
        Say '   1  Show them (deleted, disabled, locked)'
        Say '   2  Restore deleted users              CHANGES AD'
        Say '   3  Enable disabled users              CHANGES AD'
        Say '   4  Unlock every locked-out user       CHANGES AD'
        Say '   5  Set a new password for one user    CHANGES AD (then a PCR if it is scored)'
        Say '   6  Stop lockouts (threshold 0)        CHANGES the domain password policy'
        Say '   7  Reset krbtgt twice (Golden Ticket) CHANGES AD (your lead decides)'
        Say '   8  Turn on the AD Recycle Bin         CHANGES AD, cannot be turned off again'
        Say '   Q  Done: reminders and back on track'
        $c = Read-Host '  Choice'
        switch -Regex ($c) {
            '^1$' {
                if ($del.Count) { Say '  DELETED:'; $del | ForEach-Object { Say ('    ' + $_.samAccountName + '   deleted ' + $_.whenChanged + '   was in ' + $_.lastKnownParent) } }
                if ($dis.Count) { Say ('  DISABLED: ' + (($dis | ForEach-Object { $_.SamAccountName }) -join ', ')) }
                if ($lock.Count) { Say ('  LOCKED OUT: ' + (($lock | ForEach-Object { $_.SamAccountName }) -join ', ')) }
                Why 'many at once is not an accident. Red team deletes or locks scored users so service checks fail. Event 4726 (deleted), 4725 (disabled) and 4740 (locked) on this DC say who did it and when.'
            }
            '^2$' {
                if ($del.Count -eq 0) { Say '  No deleted users.'; break }
                if (-not $rb) { Say '  The Recycle Bin is off, so a restored user comes back WITHOUT its password and group memberships.'; Say '  After restoring: set a password (5) and add the groups back (your baseline has them: ad_privgroups.txt).' }
                $who = Read-Host '  Type a user name to restore, or ALL'
                $todo = @($del | Where-Object { $who -eq 'ALL' -or $_.samAccountName -eq $who })
                foreach ($d in $todo) {
                    try { Restore-ADObject -Identity $d.ObjectGUID -ErrorAction Stop; Say ('    restored ' + $d.samAccountName); Fact ('restored deleted user ' + $d.samAccountName + ' (deleted ' + $d.whenChanged + ')') }
                    catch { Warn ('could not restore ' + $d.samAccountName + ': ' + $_.Exception.Message); Decode-Error $_.Exception.Message }
                }
                if ($todo.Count) { Auto-Note ('AD: restored deleted users: ' + (($todo | ForEach-Object { $_.samAccountName }) -join ', ')); Add-Remind 'Incident report: AD users were deleted (facts file in the vault, incidents folder)'; Say '  A restored user is often disabled and has no password: use 3 and 5 next.' }
            }
            '^3$' {
                if ($dis.Count -eq 0) { Say '  No disabled users.'; break }
                Say ('  Disabled: ' + (($dis | ForEach-Object { $_.SamAccountName }) -join ', '))
                Say '  Some may be disabled on purpose (old accounts). Your baseline shows which were enabled at the start: ad_users.txt'
                $who = Read-Host '  Type a user name to enable, or ALL'
                foreach ($d in @($dis | Where-Object { $who -eq 'ALL' -or $_.SamAccountName -eq $who })) {
                    try { Enable-ADAccount -Identity $d -ErrorAction Stop; Say ('    enabled ' + $d.SamAccountName); Fact ('enabled ' + $d.SamAccountName) } catch { Warn ($d.SamAccountName + ': ' + $_.Exception.Message) }
                }
                Auto-Note ('AD: enabled users (' + $who + ')')
            }
            '^4$' {
                foreach ($d in $lock) { try { Unlock-ADAccount -Identity $d -ErrorAction Stop; Say ('    unlocked ' + $d.SamAccountName); Fact ('unlocked ' + $d.SamAccountName) } catch { Warn ($d.SamAccountName + ': ' + $_.Exception.Message) } }
                if ($lock.Count -eq 0) { Say '  Nobody is locked out.' } else { Auto-Note ('AD: unlocked ' + $lock.Count + ' users'); Say '  They will lock again if the guessing continues. Find the source (hunt shows 4740 and 4625), or use 6.' }
            }
            '^5$' {
                $who = Read-Host '  User name'
                if (-not $who) { break }
                Say '  STOP if the scoring engine logs in as this user: file a PCR FIRST, or the service check fails.'
                $pw = Read-NewPassword $who
                if ($pw) {
                    try { Set-ADAccountPassword -Identity $who -Reset -NewPassword $pw -ErrorAction Stop; Say ('    password set for ' + $who); Fact ('set a new password for ' + $who); Auto-Note ('AD: new password for ' + $who); Add-Remind ('PCR: password changed for ' + $who + ' (if the scoring engine uses it)') }
                    catch { Warn $_.Exception.Message; Decode-Error $_.Exception.Message }
                }
            }
            '^6$' {
                Why 'with a lockout threshold, red team locks every scored user with a few bad guesses, and locked users fail their service checks. Threshold 0 means accounts never lock.'
                Say '  Real world instead: keep a lockout (about 5 tries) together with MFA and monitoring.'
                if (Ask-Yes '  Set the lockout threshold to 0?') {
                    Add-Content -Path (Join-Path $Vault 'harden_undo.txt') -Value ('NOTE|lockout threshold was ' + $pol.LockoutThreshold)
                    try { Set-ADDefaultDomainPasswordPolicy -Identity $dom.DNSRoot -LockoutThreshold 0 -ErrorAction Stop; Say ('    was ' + $pol.LockoutThreshold + ', now 0. Put back: Set-ADDefaultDomainPasswordPolicy -Identity ' + $dom.DNSRoot + ' -LockoutThreshold ' + $pol.LockoutThreshold); Auto-Note 'AD: lockout threshold set to 0' }
                    catch { Warn $_.Exception.Message }
                }
            }
            '^7$' {
                Why 'if red team copied the krbtgt key (DCSync, or a copy of ntds.dit), they can forge a login ticket for anyone (Golden Ticket). Only two krbtgt resets kill those tickets, because AD keeps the current and the previous key.'
                Say '  Careful: right after the second reset, some logins and services can fail for a few minutes. Watch the scoreboard.'
                Say '  Real world instead: wait 10 hours between the two resets.'
                if (Ask-Yes '  Did your lead say yes to both resets now?') {
                    foreach ($n in 1, 2) {
                        $r = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($r)
                        $sp = ConvertTo-SecureString ([Convert]::ToBase64String($r) + 'aA1!') -AsPlainText -Force
                        try { Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword $sp -ErrorAction Stop; Say ('    krbtgt reset ' + $n + ' of 2 done') } catch { Warn $_.Exception.Message; break }
                        if ($n -eq 1) { Say '    copying the change to every DC (repadmin /syncall) ...'; repadmin /syncall /AdeP 2>$null | Out-Null; Start-Sleep -Seconds 10 }
                    }
                    Fact 'reset krbtgt twice'; Auto-Note 'AD: krbtgt reset twice'
                    Add-Remind 'Incident report: krbtgt was reset twice (say why you believed the key was stolen)'
                    Say '  If DCSync happened, red team has EVERY password hash: change the admin and service passwords too (PCR for scored ones).'
                }
            }
            '^8$' {
                if ($rb) { Say '  Already on.'; break }
                Why 'with the Recycle Bin on, a deleted user comes back WITH its password and groups. Without it, you rebuild each one by hand.'
                if ($del.Count -gt 0) { Warn ('There are ' + $del.Count + ' deleted users right now. Turning the Recycle Bin on makes them unrecoverable. Restore them FIRST (choice 2).'); break }
                Say '  Careful: this cannot be turned off again. That is normal; most companies have it on.'
                if (Ask-Yes '  Turn on the AD Recycle Bin for the whole forest?') {
                    try { Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -Confirm:$false -ErrorAction Stop; Say '    Recycle Bin is on'; Auto-Note 'AD: Recycle Bin turned on' }
                    catch { Warn $_.Exception.Message }
                }
            }
            '^[qQ]$' {
                Say ''
                Say '  Before you go back to what you were doing:'
                Say '   1. PCR for every scored account whose password changed (the reminders list has them: menu R).'
                Say '   2. Incident report: your team writes it. The facts are saved here:'
                if ($script:FactsFile -and (Test-Path $script:FactsFile)) { Say ('      ' + $script:FactsFile) }
                Say '      It needs: source and target addresses, the timeline, what was affected, what you did, and how you stop it happening again.'
                Say '   3. Find who did it: menu 2 (hunt) shows events 4726, 4725, 4740 with the account and time.'
                Stop-Facts
                return
            }
        }
    }
}

# ---------------------------------------------------------------------------
# kick: end someone's session on this box, then block their address
# ---------------------------------------------------------------------------
$script:NeverKill = 'System', 'Idle', 'lsass', 'csrss', 'wininit', 'winlogon', 'services', 'smss', 'svchost', 'dwm', 'sqlservr', 'w3wp', 'dns', 'ntds', 'dfsrs', 'MsMpEng'
function Run-Kick {
    Head 'kick someone off this box'
    $t = @($Ip | Where-Object { $_ })[0]
    if (-not $t) { $t = $Text }
    Say '  Logged on right now:'
    $q = @(quser 2>$null)
    $q | ForEach-Object { Say ('    ' + $_) }
    $smb = @(Get-SmbSession -ErrorAction SilentlyContinue)
    if ($smb.Count) { Say '  File-share sessions:'; $smb | ForEach-Object { Say ('    ' + $_.ClientComputerName + '  as ' + $_.ClientUserName) } }
    if (-not $t) { $t = Read-Host '  Type an address (like 10.1.2.3) or a user name to kick, or Enter to stop' }
    if (-not $t) { return }
    Start-Facts ('kicked ' + $t)
    if (Test-IPv4 $t) {
        if (Test-Protected $t) { Warn ($t + ' is a protected address (scoring engine or Black Team). Not touched.'); Stop-Facts; return }
        $mine = @(Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RemoteAddress)
        if ($mine -contains $t) { Warn ($t + ' has a Remote Desktop session open, and that may be YOU. Check your own address first (ipconfig on your own machine).'); if (-not (Ask-Yes '  Kick it anyway?')) { Stop-Facts; return } }
        $cons = @(Get-NetTCPConnection -RemoteAddress $t -ErrorAction SilentlyContinue)
        foreach ($c in $cons) { Fact ('connection ' + $t + ':' + $c.RemotePort + ' -> local port ' + $c.LocalPort + ' (pid ' + $c.OwningProcess + ', ' + $c.State + ')') }
        foreach ($s in @($smb | Where-Object { $_.ClientComputerName -match [regex]::Escape($t) })) { Close-SmbSession -SessionId $s.SessionId -Force; Say ('    closed the file-share session of ' + $s.ClientUserName); Fact ('closed SMB session of ' + $s.ClientUserName) }
        $listen = @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique)
        foreach ($c in @($cons | Where-Object { $listen -notcontains $_.LocalPort } | Sort-Object OwningProcess -Unique)) {
            $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            if (-not $p -or $script:NeverKill -contains $p.ProcessName) { continue }
            Say ('    ' + $p.ProcessName + ' (pid ' + $p.Id + ', ' + $p.Path + ') is talking OUT to ' + $t)
            if (Ask-Yes '    Save it as evidence and stop it?') { if ($p.Path) { $script:Path = $p.Path; Run-Evidence }; Stop-Process -Id $p.Id -Force; Fact ('stopped ' + $p.ProcessName + ' pid ' + $p.Id + ' (' + $p.Path + ')') }
        }
        Why 'a session that comes IN to one of your services (web, SQL, file share) is cut by the block below. The service itself is never stopped.'
        $script:Ip = @($t); Run-Block
        Fact ('blocked ' + $t)
    } else {
        $ids = @($q | Where-Object { $_ -match ('^[ >]' + [regex]::Escape($t) + '\s') } | ForEach-Object { if ($_ -match '\s(\d+)\s+(Active|Disc)') { $Matches[1] } })
        if ($ids.Count -eq 0) { Say ('  ' + $t + ' has no desktop session here.') }
        foreach ($i in $ids) { logoff $i; Say ('    logged off session ' + $i + ' (' + $t + ')'); Fact ('logged off ' + $t + ' session ' + $i) }
        foreach ($s in @($smb | Where-Object { $_.ClientUserName -match ('\\' + [regex]::Escape($t) + '$') })) { Close-SmbSession -SessionId $s.SessionId -Force; Say '    closed their file-share session' }
        Say '  They can log straight back in until the password changes or the account is disabled:'
        Say ('    local account:  net user ' + $t + ' /active:no        domain account (on the DC):  Disable-ADAccount ' + $t)
        Say '  Do NOT disable an account the scoring engine uses. Change its password with a PCR instead.'
    }
    Auto-Note ('kicked ' + $t)
    Add-Remind ('Incident report: kicked ' + $t + ' from ' + $env:COMPUTERNAME)
    if ($script:FactsFile) { Say ('  Facts for your report: ' + $script:FactsFile) }
    Stop-Facts
}

# ---------------------------------------------------------------------------
# restore: put settings and files back from the start-of-game copies
# ---------------------------------------------------------------------------
function Run-Restore {
    Head 'restore from the start-of-game copies'
    $cfg = Join-Path $BaseDir 'config'
    if (-not (Test-Path $cfg)) { Warn 'No baseline copies yet. They are made by menu 1 at the start of the game.'; return }
    Say ('  Copies from ' + (Get-DirTime $BaseDir).ToString('HH:mm') + ' are in ' + $cfg)
    Say '   1  Windows Firewall rules      (all rules go back to the start-of-game set)'
    Say '   2  The hosts file'
    Say '   3  Startup programs (the Run keys) and the Winlogon settings'
    Say '   4  Every Group Policy object   (domain controller)'
    Say '   5  One file or folder of the web site'
    Say '   6  IIS settings (applicationHost.config)'
    $c = Read-Host '  Choice (Enter to stop)'
    $st = Get-Date -Format 'HHmmss'
    switch ($c) {
        '1' { if (Ask-Yes '  Replace ALL current firewall rules? Blocks you added since are lost (menu 8 with no address puts them back).') { netsh advfirewall export (Join-Path $Vault ('firewall_before_restore_' + $st + '.wfw')) | Out-Null; netsh advfirewall import (Join-Path $cfg 'firewall.wfw'); Auto-Note 'restored the firewall rules from the baseline'; $script:Ip = @(); Run-Block } }
        '2' { $h = "$env:windir\System32\drivers\etc\hosts"; Copy-Item $h (Join-Path $Vault ('hosts_bad_' + $st)) -Force; Copy-Item (Join-Path $cfg 'hosts') $h -Force; Say '    hosts file put back (the changed one is saved in the vault as evidence)'; Auto-Note 'restored the hosts file' }
        '3' { if (Ask-Yes '  Put the Run keys and Winlogon settings back?') { foreach ($r in 'run_hklm.reg', 'run_hkcu.reg', 'winlogon.reg') { reg import (Join-Path $cfg $r) 2>$null | Out-Null }; Say '    put back. Entries red team ADDED are still there: remove those by hand (the hunt lists them).'; Auto-Note 'restored Run keys and Winlogon from the baseline' } }
        '4' { if (-not (Get-Command Restore-GPO -ErrorAction SilentlyContinue)) { Warn 'Only on a domain controller with the Group Policy tools.' } elseif (Ask-Yes '  Put every Group Policy object back to its start-of-game content?') { Restore-GPO -All -Path (Join-Path $cfg 'gpo') | Out-Null; Say '    done. GPOs red team CREATED are still there: Get-GPO -All | Sort-Object CreationTime'; Auto-Note 'restored all GPOs from the baseline' } }
        '5' {
            $w = Join-Path $cfg 'wwwroot'
            if (-not (Test-Path $w)) { Warn 'The web site was not in this baseline (it is copied when it is under 200 MB).'; break }
            $rel = Read-Host '  Path inside the web site, like index.html or images\logo.png (Enter = the whole site)'
            $src = Join-Path $w $rel; $dst = Join-Path 'C:\inetpub\wwwroot' $rel
            if (-not (Test-Path $src)) { Warn ('Not in the backup: ' + $rel); break }
            if (Test-Path $dst) { $bad = Join-Path $Vault ('web_bad_' + $st); New-Item -ItemType Directory -Force -Path $bad | Out-Null; Copy-Item $dst $bad -Recurse -Force; Say ('    the changed copy is saved as evidence: ' + $bad) }
            Copy-Item $src $dst -Recurse -Force; Say ('    put back: ' + $dst); Auto-Note ('restored web content: ' + $rel)
            Add-Remind 'Incident report: web content was changed and restored'
        }
        '6' { $a = Join-Path $cfg 'applicationHost.config'; if (Test-Path $a) { if (Ask-Yes '  Replace the IIS settings and restart IIS (a few seconds of downtime)?') { Copy-Item "$env:windir\System32\inetsrv\config\applicationHost.config" (Join-Path $Vault ('applicationHost_bad_' + $st + '.config')) -Force; Copy-Item $a "$env:windir\System32\inetsrv\config\applicationHost.config" -Force; iisreset | Out-Null; Say '    IIS settings put back'; Auto-Note 'restored applicationHost.config' } } else { Warn 'No IIS settings in this baseline.' } }
    }
}
function Backup-Extra {
    param([string]$Cfg)
    $w = 'C:\inetpub\wwwroot'
    if (Test-Path $w) {
        $sz = (Get-ChildItem $w -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        if ($sz -lt 200MB) { Copy-Item $w (Join-Path $Cfg 'wwwroot') -Recurse -Force; Say '  saved config\wwwroot (the web site)' } else { Say '  the web site is over 200 MB: not copied' }
    }
    $ah = "$env:windir\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $ah) { Copy-Item $ah (Join-Path $Cfg 'applicationHost.config') -Force; Say '  saved config\applicationHost.config (IIS settings)' }
    if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
        $z = @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })
        $out = foreach ($x in $z) { foreach ($r in @(Get-DnsServerResourceRecord -ZoneName $x.ZoneName)) { $x.ZoneName + ' | ' + $r.HostName + ' | ' + $r.RecordType + ' | ' + (($r.RecordData | Out-String).Trim() -replace '\s+', ' ') } }
        Set-Content -Path (Join-Path $Cfg 'dns_records.txt') -Value $out -Encoding UTF8
        Say ('  saved config\dns_records.txt (' + $z.Count + ' DNS zones, every record)')
    }
}

# ---------------------------------------------------------------------------
# findpass: where is this password written down?
# ---------------------------------------------------------------------------
function Run-FindPass {
    Head 'find where a password is written down'
    Why 'before you change a password, find every script, config file and task that still holds the old one. Those are what break after the change, and what red team reads.'
    $s = Read-Host '  Type the password to look for (hidden; it is not saved or shown)' -AsSecureString
    $p = SecureToPlain $s
    if ($p.Length -lt 4) { Warn 'Too short to search for.'; return }
    $roots = @('C:\inetpub', 'C:\ProgramData', 'C:\Users', 'C:\scripts', 'C:\Windows\SYSVOL', 'C:\Windows\Panther', 'C:\xampp', 'C:\Program Files\Microsoft SQL Server') | Where-Object { Test-Path $_ }
    $n = 0
    foreach ($r in $roots) {
        $files = @(Get-ChildItem -Path $r -Recurse -File -Force -ErrorAction SilentlyContinue -Include *.config, *.xml, *.ini, *.txt, *.ps1, *.bat, *.cmd, *.vbs, *.json, *.yml, *.yaml, *.php, *.env, *.inf, *.conf, *.properties, *.sql |
            Where-Object { $_.Length -lt 2MB -and $_.FullName -notlike ($Vault + '*') -and $_.FullName -ne $script:BaitPath })
        foreach ($f in $files) {
            if (Select-String -LiteralPath $f.FullName -SimpleMatch -Pattern $p -Quiet -ErrorAction SilentlyContinue) { Say ('    ' + $f.FullName); $n++ }
        }
    }
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) { foreach ($a in @($t.Actions)) { if (([string]$a.Arguments).Contains($p)) { Say ('    scheduled task: ' + $t.TaskPath + $t.TaskName); $n++ } } }
    foreach ($sv in @(Get-CimInstance Win32_Service)) { if (([string]$sv.PathName).Contains($p)) { Say ('    service command line: ' + $sv.Name); $n++ } }
    $p = $null
    if ($n -eq 0) { Good 'not found in the usual places' } else { Say ('  ' + $n + ' places hold it. Update each one when you change the password, or remove the password from it.') }
    Say '  Not searched: the registry, databases, and services that store the password inside Windows (Services > Log On tab).'
}

# ---------------------------------------------------------------------------
# facts: what an incident report needs (rule 9.4). Your team writes the report.
# ---------------------------------------------------------------------------
function Run-Facts {
    Head 'incident facts (your team writes the report in its own words)'
    $t = @($Ip | Where-Object { $_ })[0]
    if (-not $t) { $t = $Text }
    if (-not $t) { $t = $Path }
    if (-not $t) { $t = Read-Host '  An address, an account name, or a full file path' }
    if (-not $t) { return }
    Start-Facts $t
    $since = (Get-Date).AddHours(-12)
    if (Test-Path -LiteralPath $t) {
        $fi = Get-Item -LiteralPath $t -Force
        Fact ('file: ' + $fi.FullName + '   size ' + $fi.Length + '   created ' + $fi.CreationTime + '   changed ' + $fi.LastWriteTime)
        Fact ('SHA256: ' + (Get-FileHash -LiteralPath $t -Algorithm SHA256).Hash + '   signature: ' + (Get-SigStatus $t) + '   owner: ' + (Get-Acl -LiteralPath $t).Owner)
    } else {
        $pat = [regex]::Escape($t)
        foreach ($e in @(Get-Evt 'Security' (XSince @(4624, 4625, 4648, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4740, 4756) $since) 4000 | Where-Object { $_.Message -match $pat } | Sort-Object TimeCreated | Select-Object -First 60)) {
            Fact ($e.TimeCreated.ToString('MM-dd HH:mm:ss') + '  event ' + $e.Id + '  account ' + (EvData $e 'TargetUserName') + '  from ' + (EvData $e 'IpAddress') + '  by ' + (EvData $e 'SubjectUserName') + '  logon type ' + (EvData $e 'LogonType'))
        }
        $fw = "$env:windir\System32\LogFiles\Firewall\pfirewall.log"
        if ((Test-IPv4 $t) -and (Test-Path $fw)) { $l = @(Select-String -LiteralPath $fw -SimpleMatch -Pattern $t | Select-Object -First 1 -Last 1); foreach ($x in $l) { Fact ('firewall log: ' + $x.Line) } }
    }
    foreach ($n in @(Get-Content $NotesFile -ErrorAction SilentlyContinue | Where-Object { $_ -match [regex]::Escape($t) })) { Fact ('team note: ' + $n) }
    Add-Content -Path $script:FactsFile -Value @('', '----- your team fills these in (rule 9.4) -----', 'Source address(es):', 'Target address(es) and box:', 'Timeline (first seen, what they did, when it was stopped):', 'How they got in (access gained, passwords cracked or stolen):', 'What was affected or damaged:', 'What we did (contain, remove, recover):', 'How we stop it happening again:', 'Proof: files in the vault quarantine folder, with their SHA256 fingerprints')
    Get-Content $script:FactsFile | ForEach-Object { Say ('  ' + $_) }
    Say ''
    Good ('saved: ' + $script:FactsFile)
    Say '  An AI must not write any part of the report. This file is only the facts and the proof.'
    Add-Remind ('Incident report to write: ' + $t)
    $script:FactsFile = ''
}

# ---------------------------------------------------------------------------
# SOS: something is wrong right now
# ---------------------------------------------------------------------------
function Sos-Service {
    $n = Read-Host '  Service name or port number (like W3SVC, MSSQLSERVER, DNS, or 80)'
    if (-not $n) { return }
    $svc = $null
    if ($n -match '^\d+$') {
        $l = @(Get-NetTCPConnection -State Listen -LocalPort ([int]$n) -ErrorAction SilentlyContinue)
        if ($l.Count -eq 0) { Warn ('Nothing is listening on port ' + $n + '. The service behind it is stopped or crashed.'); $map = @{ '80' = 'W3SVC'; '443' = 'W3SVC'; '1433' = 'MSSQLSERVER'; '53' = 'DNS'; '389' = 'NTDS'; '88' = 'Kdc'; '445' = 'LanmanServer'; '3389' = 'TermService'; '25' = 'SMTPSVC'; '21' = 'FTPSVC'; '5985' = 'WinRM' }; if ($map[$n]) { $svc = Get-Service $map[$n] -ErrorAction SilentlyContinue } }
        else { $p = Get-Process -Id $l[0].OwningProcess; Good ('port ' + $n + ' is listening: ' + $p.ProcessName + ' (pid ' + $p.Id + ')'); Say '  So the service is up on this box. If the check still fails, look at: the firewall (below), the password the check uses, or the content.' }
    } else { $svc = Get-Service $n -ErrorAction SilentlyContinue; if (-not $svc) { $svc = Get-Service -DisplayName ('*' + $n + '*') -ErrorAction SilentlyContinue | Select-Object -First 1 } }
    if ($svc) {
        $w = Get-CimInstance Win32_Service -Filter ("Name='" + $svc.Name + "'")
        Say ('  ' + $svc.Name + ' (' + $svc.DisplayName + '): ' + $svc.Status + ', start type ' + $w.StartMode + ', runs as ' + $w.StartName)
        if ($w.StartMode -eq 'Disabled') { Warn 'It is DISABLED. Red team does this so a restart does not bring it back.'; if (Ask-Yes '  Set it to Automatic?') { Set-Service $svc.Name -StartupType Automatic; Auto-Note ('SOS: ' + $svc.Name + ' set to Automatic') } }
        if ($svc.Status -ne 'Running') {
            foreach ($e in @(Get-Evt 'System' (XSince @(7000, 7001, 7009, 7023, 7024, 7031, 7034, 7038, 7041) ((Get-Date).AddHours(-2))) 50 | Where-Object { $_.Message -match [regex]::Escape($svc.DisplayName) } | Select-Object -First 3)) { Say ('  ' + $e.TimeCreated.ToString('HH:mm') + ' event ' + $e.Id + ': ' + (($e.Message -split "`n")[0])); Decode-Error $e.Message }
            if (Ask-Yes '  Try to start it now?') {
                try { Start-Service $svc.Name -ErrorAction Stop; Start-Sleep 2; Good ($svc.Name + ' is ' + (Get-Service $svc.Name).Status); Auto-Note ('SOS: started ' + $svc.Name) }
                catch { Warn $_.Exception.Message; Decode-Error $_.Exception.Message; Say '  Event 7038 or "logon failure" means the password of the account it runs as was changed: fix it in Services > the service > Log On tab.' }
            }
        } else { Good 'it is running' }
    }
    $off = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -and $_.DefaultInboundAction -eq 'Block' })
    if ($off.Count -gt 0 -and $n -match '^\d+$') {
        $ok = @(Get-NetFirewallPortFilter -Protocol TCP | Where-Object { $_.LocalPort -contains $n -or $_.LocalPort -eq 'Any' } | Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' })
        $bl = @(Get-NetFirewallPortFilter -Protocol TCP | Where-Object { $_.LocalPort -contains $n } | Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' })
        if ($bl.Count -gt 0) { Warn ('A firewall rule BLOCKS port ' + $n + ': ' + (($bl | ForEach-Object { $_.DisplayName }) -join ', ') + '. A block rule always wins. Remove it: Remove-NetFirewallRule -DisplayName "<name>"') }
        elseif ($ok.Count -eq 0) { Warn ('The firewall is on and no rule allows port ' + $n + ' in. Add one: New-NetFirewallRule -DisplayName "allow ' + $n + '" -Direction Inbound -Protocol TCP -LocalPort ' + $n + ' -Action Allow') }
    }
}
function Sos-Many {
    Say '  When several services fail together, look for the ONE shared cause first.'
    $os = Get-CimInstance Win32_OperatingSystem
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    if ($d -and $d.FreeSpace -lt 500MB) { Warn ('Drive C: has only ' + [math]::Round($d.FreeSpace / 1MB) + ' MB free. A full disk stops databases, logs and logins.') } else { Good 'disk space is fine' }
    $blk = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Block -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -notlike 'first30*' })
    if ($blk.Count -gt 0) { Warn ('Inbound BLOCK rules that this script did not make: ' + (($blk | Select-Object -First 6 | ForEach-Object { $_.DisplayName }) -join '; ')) }
    $stopped = @()
    $bs = Join-Path $BaseDir 'services.txt'
    if (Test-Path $bs) {
        $now = @{}; foreach ($s in @(Get-CimInstance Win32_Service)) { $now[$s.Name] = $s }
        foreach ($l in @(Get-Content $bs | Where-Object { $_ -match '\| Auto Running \|' })) { $nm = ($l -split ' \| ')[0]; if ($now[$nm] -and $now[$nm].State -ne 'Running') { $stopped += ($nm + ' (now ' + $now[$nm].State + ', ' + $now[$nm].StartMode + ')') } }
        if ($stopped.Count -gt 0) { Warn 'Services that were running at the start of the game and are not now:'; $stopped | ForEach-Object { Say ('    ' + $_) } } else { Good 'every service from the baseline is still running' }
    }
    Check-Domain
    Say ('  Up since ' + $os.LastBootUpTime + '. A reboot you did not do is an incident.')
}
function Sos-Process {
    $x = Read-Host '  Process id (PID) or name'
    if (-not $x) { return }
    $ps = @(Get-CimInstance Win32_Process | Where-Object { [string]$_.ProcessId -eq $x -or $_.Name -like ($x + '*') })
    foreach ($p in $ps | Select-Object -First 5) {
        $par = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $p.ParentProcessId)
        $own = ''; try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner; $own = $o.Domain + '\' + $o.User } catch {}
        Say ('  ' + $p.Name + '  pid ' + $p.ProcessId + '  account ' + $own + '  started ' + $p.CreationDate)
        Say ('    program: ' + $p.ExecutablePath + '   signature: ' + (Get-SigStatus $p.ExecutablePath))
        Say ('    command: ' + $p.CommandLine)
        Say ('    started by: ' + $par.Name + ' (pid ' + $p.ParentProcessId + ')')
        foreach ($c in @(Get-NetTCPConnection -OwningProcess $p.ProcessId -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(0\.0\.0\.0|::|127\.)' })) { Say ('    talking to ' + $c.RemoteAddress + ':' + $c.RemotePort) }
        if ($script:NeverKill -contains ($p.Name -replace '\.exe$', '')) { Say '    This is a core Windows or service process. Do not stop it. If it looks wrong, look at what it LOADED and what started it.'; continue }
        if (Ask-Yes '    Save the program as evidence, then stop it?') {
            if ($p.ExecutablePath) { $script:Path = $p.ExecutablePath; Run-Evidence }
            Stop-Process -Id $p.ProcessId -Force; Auto-Note ('SOS: stopped ' + $p.Name + ' pid ' + $p.ProcessId + ' (' + $p.ExecutablePath + ')')
            Say '    Stopped. Something started it, and will start it again: hunt (menu 2) shows new services, tasks and Run keys.'
            Add-Remind ('Incident report: stopped ' + $p.Name + ' (' + $p.ExecutablePath + ')')
        }
    }
    if ($ps.Count -eq 0) { Say '  No such process now. It may have ended already: event 4688 in the Security log shows what ran.' }
}
function Run-SOS {
    Head 'SOS: something is wrong right now'
    $ot = Join-Path $Vault 'ontrack.txt'
    if (-not (Test-Path $ot)) {
        $w = Read-Host '  One line first: what were you doing before this? (so you can get back to it)'
        if ($w) { Set-Content -Path $ot -Value ((Get-Date).ToString('HH:mm') + ' | ' + $w) }
    }
    Say '  Breathe. Pick the line that is closest. Nothing changes until you type yes.'
    while ($true) {
        Say ''
        Say '   1  One scored service is down (red on the scoreboard)'
        Say '   2  Many services went down together'
        Say '   3  Someone is on this box who should not be'
        Say '   4  A strange program is running'
        Say '   5  Users are locked out, disabled or deleted'
        Say '   6  Files or the web site were changed, or settings were wrecked'
        Say '   7  I am locked out or cannot log in'
        Say '   8  I do not know: run the fast check'
        Say '   E  Explain an error message'
        Say '   Q  Done: reminders, then back on track'
        $c = Read-Host '  Choice'
        switch -Regex ($c) {
            '^1$' { Sos-Service }
            '^2$' { Sos-Many }
            '^3$' { Run-Kick }
            '^4$' { Sos-Process }
            '^5$' { if ($MyRole -eq 'dc') { Run-AD } else { Say '  Local accounts:'; Get-LocalUser | ForEach-Object { Say ('    ' + $_.Name + '  enabled=' + $_.Enabled) }; Say '  Enable one: net user <name> /active:yes     New password: net user <name> *'; Say '  Domain accounts are fixed on the domain controller: run this menu there (choice 5).'; Check-Domain } }
            '^6$' { Run-Restore }
            '^7$' {
                Say '  - "The trust relationship ... failed": log in with a LOCAL account (.\Administrator), then: Test-ComputerSecureChannel -Repair -Credential (Get-Credential)'
                Say '  - "No logon servers available": the DC or DNS is unreachable. Log in with a local account and run menu 16.'
                Say '  - Remote Desktop refuses you, the console works: check the firewall (port 3389) and the Remote Desktop Users group.'
                Say '  - The domain Administrator is disabled: on the DC, as another Domain Admin: Enable-ADAccount Administrator'
                Say '  - Nothing works: your lead decides about a box reset. It costs points (60 last year), so it is the last resort.'
            }
            '^8$' { Sos-Many; Check-C2; Check-Accounts }
            '^[eE]$' { $script:Text = ''; Run-Why }
            '^[qQ]$' {
                Say ''
                Say '  Before you go back:'
                Say '   1. Write a note of what happened and what you did (menu 6). Your teammates read it.'
                Say '   2. PCR for every scored password that changed.'
                Say '   3. Was it red team? Then it is an incident: menu 21 saves the facts, your team writes the report.'
                Say '      A report that shows how you removed them wins back up to half the penalty.'
                Say '   4. Tell your lead in the team channel: box, time, what, done or not done.'
                if (Test-Path $ot) { Say ('  Back on track. Before this you were: ' + (Get-Content $ot | Select-Object -First 1)); Remove-Item $ot -Force }
                if ((Get-RemindCount) -gt 0) { Say ('  Open reminders: ' + (Get-RemindCount) + '  (menu R)') }
                return
            }
        }
    }
}

# ===========================================================================
# ADDED IN V5 (November 2026). Red team reads this script three months before
# the game, so these checks look at BEHAVIOR and at the places the older checks
# named out loud: traps set for this script, logging that was quietly switched
# off, UDP and port forwards, renamed tools, and every well-known AD weakness.
# New modes: audit, advuln, plumbing, decoy, lock-svc, undo-lock-svc, scrub.
# ===========================================================================

# ---- traps for this script: a vault that is really a link to somewhere else ----
function Test-VaultTrap {
    $bad = @()
    $v = Get-Item -LiteralPath $Vault -Force -ErrorAction SilentlyContinue
    if ($v -and ($v.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $bad += ($Vault + ' itself') }
    foreach ($c in @(Get-ChildItem -LiteralPath $Vault -Force -ErrorAction SilentlyContinue)) {
        if ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) { $bad += $c.FullName }
    }
    if ($bad.Count -gt 0) {
        Warn 'STOP: the vault, or something inside it, is a LINK to another place (a junction or symbolic link):'
        $bad | ForEach-Object { Say ('    ' + $_) }
        Say '  Writing through it would overwrite files somewhere else. This is red team: note it as an incident.'
        Say '  Remove each link (cmd: rmdir "<link>" for a folder link, del "<link>" for a file link), or use another vault: -Vault C:\ProgramData\bk2'
        return $true
    }
    return $false
}

# ---- logging and script defenses that were quietly switched off ----
function Check-Tamper {
    Sec 'tamper' 'Defenses switched off under this script: AMSI, event tracing, module paths (T1562.001, T1562.006, T1574)'
    $out = @()
    # AMSI lets Defender see PowerShell code before it runs. These are the quiet ways to turn it off.
    if ((Get-RegValue 'HKCU:\Software\Microsoft\Windows Script\Settings' 'AmsiEnable') -eq 0) { $out += 'AMSI is turned off for this account (registry: HKCU Windows Script\Settings AmsiEnable = 0)' }
    $prov = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue)
    if ((Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) -and $prov.Count -eq 0) { $out += 'no AMSI provider is registered, so Defender cannot scan scripts (HKLM\SOFTWARE\Microsoft\AMSI\Providers is empty)' }
    foreach ($d in @($PSHOME, (Get-Location).Path, $PSScriptRoot) | Where-Object { $_ } | Select-Object -Unique) {
        if ($d -notlike "$env:windir\System32" -and (Test-Path (Join-Path $d 'amsi.dll'))) { $out += ('a file named amsi.dll sits in ' + $d + ': PowerShell loads it instead of the real one (DLL hijack)') }
    }
    # .NET and Windows event tracing
    foreach ($scope in 'Machine', 'User', 'Process') {
        if ([Environment]::GetEnvironmentVariable('COMPlus_ETWEnabled', $scope) -eq '0') { $out += ('the variable COMPlus_ETWEnabled=0 is set (' + $scope + '): .NET programs stop reporting what they load') }
    }
    if ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\.NETFramework' 'ETWEnabled') -eq 0) { $out += '.NET event tracing is turned off in the registry (ETWEnabled = 0)' }
    foreach ($ch in 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-Windows Defender/Operational') {
        $l = Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue
        if ($l -and -not $l.IsEnabled) { $out += ('the event log "' + $ch + '" is turned OFF') }
    }
    foreach ($a in 'EventLog-Security', 'EventLog-System', 'EventLog-Application') {
        if ((Get-RegValue ('HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\' + $a) 'Start') -eq 0) { $out += ('the ' + $a + ' logger is set not to start at the next boot') }
    }
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 0) { $out += 'PowerShell script block logging is forced OFF by policy' }
    $el = Get-Service EventLog -ErrorAction SilentlyContinue
    if ($el -and $el.Status -ne 'Running') { $out += 'the Windows Event Log service is NOT running: nothing is being logged' }
    # module folders that PowerShell searches before the real ones
    $core = 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Security', 'NetTCPIP', 'NetSecurity', 'ActiveDirectory', 'CimCmdlets', 'ScheduledTasks', 'Defender', 'SmbShare'
    foreach ($m in @($env:PSModulePath -split ';' | Where-Object { $_ })) {
        $ok = ($m -like "$env:windir\*") -or ($m -like "$env:ProgramFiles\*") -or ($m -like "${env:ProgramFiles(x86)}\*") -or ($m -like "$env:USERPROFILE\Documents\*")
        if (-not $ok) { $out += ('PowerShell also loads modules from ' + $m + ' (not a normal place)') }
        if ($m -notlike "$env:windir\System32\*" -and (Test-Path $m)) {
            foreach ($c in $core) { if (Test-Path (Join-Path $m $c)) { if ($c -eq 'ActiveDirectory' -or $c -eq 'Defender') { continue }; $out += ('a copy of the built-in module ' + $c + ' sits in ' + $m + ': it can replace the real commands') } }
        }
    }
    if ($out.Count -gt 0) {
        $out | ForEach-Object { Warn $_ }
        Flag
        Nxt 'these do not happen by accident. Note each one (it is an incident), put it back, and then run the hunt again, because results before the fix may have been blinded.'
    } else { Good 'AMSI, event tracing, the key event logs and the module folders look normal' }
}

# ---- UDP, port forwards, tunnels and named pipes ----
$script:PipeRx = '(?i)^(msagent_|MSSE-\d+-server|postex_|status_[0-9a-f]{2}$|mypipe-[fh]|win_svc|gruntsvc|psexesvc|paexec|remcom|csexecsvc|DserNamePipe|jaccdpqnvbrrxlaf|halfduplex_|SearchTextHarvester|ntsvcs_[0-9a-f]+|scerpc_[0-9a-f]+|winsock|rpc_[0-9a-f]{2,}$|demoagent_|sliver|merlin|interprocess_\d+|nc\.pipe)'
function Check-Udp {
    Sec 'udp' 'UDP programs, port forwards, tunnels and named pipes (T1572, T1090, T1095, T1570)'
    $hit = $false
    $procs = @{}
    foreach ($p in @(Get-CimInstance Win32_Process)) { $procs[[int]$p.ProcessId] = $p }
    $rows = @()
    foreach ($g in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Group-Object OwningProcess)) {
        $p = $procs[[int]$g.Name]
        if (-not $p -or -not $p.ExecutablePath) { continue }
        $why = @()
        if (Test-UserWritable $p.ExecutablePath) { $why += 'user-or-temp-folder' }
        if ((Get-SigStatus $p.ExecutablePath) -ne 'Valid') { $why += 'not-signed' }
        if ($why.Count -gt 0) { $rows += [pscustomobject]@{ Program = $p.Name; PID = $p.ProcessId; UdpPorts = (($g.Group | Select-Object -ExpandProperty LocalPort -Unique | Select-Object -First 6) -join ','); Marked = ($why -join ' '); Path = $p.ExecutablePath } }
    }
    if ($rows.Count -gt 0) { Warn 'programs using UDP that are unsigned or run from a user folder (C2 does not need TCP):'; Show $rows; $hit = $true }
    $pp = @(netsh interface portproxy show all 2>$null | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+|\*' -and $_ -match '\s\d+\s' })
    if ($pp.Count -gt 0) { Warn 'this box FORWARDS ports to another machine (netsh portproxy). Red team uses it to pass through you:'; $pp | ForEach-Object { Say ('    ' + $_.Trim()) }; Say '    Remove all of them: netsh interface portproxy reset'; $hit = $true }
    $tun = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match '(?i)wireguard|wintun|TAP-Windows|OpenVPN|ZeroTier|Tailscale|ligolo' -and $_.Status -eq 'Up' })
    if ($tun.Count -gt 0) { Warn ('tunnel network adapters that are up: ' + (($tun | ForEach-Object { $_.Name + ' (' + $_.InterfaceDescription + ')' }) -join '; ')); $hit = $true }
    foreach ($p in $procs.Values) {
        $cl = [string]$p.CommandLine
        if (-not $cl) { continue }
        if (($p.Name -match '(?i)^(ssh|plink)\.exe$' -and $cl -match '\s-(R|L|D)\s*\S') -or $cl -match '(?i)\b(client|server)\b.*\bR:(socks|\d)' -or $cl -match '(?i)\s-connect\s+\S+:\d+.*-ignore-cert|\bsocks5?\b.*\b\d{2,5}\b.*(tunnel|proxy)') {
            Warn ('a program is carrying a tunnel or port forward: ' + $p.Name + ' (pid ' + $p.ProcessId + '): ' + $cl.Substring(0, [math]::Min(160, $cl.Length))); $hit = $true
        }
    }
    $pipes = @()
    try { $pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_.Substring(9) } | Where-Object { $_ -match $script:PipeRx }) } catch {}
    if ($pipes.Count -gt 0) {
        Warn ('named pipes used by remote-control tools (PsExec, Cobalt Strike, Sliver and others): ' + (($pipes | Select-Object -First 8) -join ', '))
        Say '    psexesvc alone can be a teammate using PsExec: ask first. The others are C2 defaults.'
        $hit = $true
    }
    if ($hit) { Flag; Nxt 'note the program and the time. Save the program (menu 5), then stop it (menu S, choice 4) and block the address it talks to (menu 8).' }
    else { Good 'no odd UDP programs, no port forwards, no tunnel adapters, no C2 pipes' }
}

# ---- a well-known tool running under another name ----
function Check-Masq {
    Sec 'masq' 'Well-known tools running under a different file name (T1036.003)'
    $tools = '(?i)^(powershell|pwsh|cmd|rundll32|regsvr32|mshta|cscript|wscript|certutil|bitsadmin|wmic|msbuild|installutil|regasm|regsvcs|psexec|psexesvc|procdump|procdump64|nc|ncat|netcat|plink|ssh|mimikatz|rclone|ngrok|meshagent|anydesk|chisel|rubeus|sharphound|net|net1|schtasks|sc|reg|curl|tar|esentutl|ntdsutil|vssadmin|diskshadow|wevtutil)(\.exe|\.c)?$'
    $seen = @{}
    $rows = @()
    foreach ($p in @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath })) {
        $exe = $p.ExecutablePath
        if ($seen.ContainsKey($exe)) { continue }
        $seen[$exe] = 1
        $vi = $null
        try { $vi = (Get-Item -LiteralPath $exe -Force -ErrorAction Stop).VersionInfo } catch { continue }
        $on = ([string]$vi.OriginalFilename) -replace '\.mui$', ''
        if (-not $on) { continue }
        $fn = Split-Path $exe -Leaf
        if ($on -match $tools -and ($on -replace '\.(exe|c)$', '') -ne ($fn -replace '\.exe$', '')) {
            $rows += [pscustomobject]@{ RunningAs = $fn; ReallyIs = $on; PID = $p.ProcessId; Path = $exe }
        }
    }
    if ($rows.Count -gt 0) {
        Show $rows
        Why 'the name inside a program file does not change when the file is renamed. A copy of PowerShell or PsExec under another name is hiding from name-based checks.'
        Flag
        Nxt 'save it (menu 5), look at what started it (menu S, choice 4), then stop it.'
    } else { Good 'no renamed admin or attack tools are running' }
}

# ---- every well-known AD weakness, with the fix (run on a domain controller) ----
function Check-ADVuln {
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) { return }
    $dom = Get-ADDomain
    if (-not $dom) { return }
    Sec 'advuln' 'AD weak spots red team uses to take the domain, with the fix for each'
    $n = 0
    $dn = $dom.DistinguishedName
    # Kerberoasting
    foreach ($u in @(Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes', PasswordLastSet, adminCount | Where-Object { $_.SamAccountName -ne 'krbtgt' -and $_.Enabled })) {
        $et = [int]$u.'msDS-SupportedEncryptionTypes'
        $w = @()
        if ($et -eq 0 -or ($et -band 4)) { $w += 'allows RC4 tickets' }
        if ($u.PasswordLastSet -and $u.PasswordLastSet -lt (Get-Date).AddDays(-180)) { $w += ('password not changed since ' + $u.PasswordLastSet.ToString('yyyy-MM-dd')) }
        if ($u.adminCount -eq 1) { $w += 'is an ADMIN account' }
        Warn ('Kerberoasting target (T1558.003): ' + $u.SamAccountName + '  [' + ($u.ServicePrincipalName | Select-Object -First 1) + ']  ' + ($w -join ', '))
        Say  ('    Fix: Set-ADUser ' + $u.SamAccountName + ' -KerberosEncryptionType AES128,AES256   then a 30+ character password: net user ' + $u.SamAccountName + ' * /domain')
        Say  '         then update the password on the service that runs as it (Services > Log On tab). PCR if it is scored.'
        $n++
    }
    # AS-REP roasting
    foreach ($u in @(Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Where-Object Enabled)) {
        Warn ('AS-REP roasting target (T1558.004): ' + $u.SamAccountName + ' does not need pre-authentication')
        Say  ('    Fix: Set-ADAccountControl ' + $u.SamAccountName + ' -DoesNotRequirePreAuth $false')
        $n++
    }
    # passwords in descriptions
    foreach ($u in @(Get-ADUser -Filter * -Properties Description, info, comment | Where-Object { ([string]$_.Description + ' ' + [string]$_.info + ' ' + [string]$_.comment) -match '(?i)(pass(word|wd)?|pwd|pw|cred|login)\s*[:=]|temp(orary)?\s+pass|initial\s+pass' })) {
        Warn ('a password seems to be written in the description of ' + $u.SamAccountName + ' (T1552). Every domain user can read it.')
        Say  ('    Fix: Set-ADUser ' + $u.SamAccountName + ' -Clear Description   AND change that password (assume it was read).')
        $n++
    }
    # old Group Policy passwords
    $sv = '\\' + $dom.DNSRoot + '\SYSVOL\' + $dom.DNSRoot + '\Policies'
    $gpp = @(Get-ChildItem -Path $sv -Recurse -Include *.xml -File -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword="[^"]' -List | Select-Object -ExpandProperty Path)
    foreach ($g in $gpp) { Warn ('a Group Policy file holds a password anyone can decrypt (T1552.006): ' + $g); Say '    Fix: delete that setting in Group Policy Management, then change the password it held.'; $n++ }
    # machine account quota
    $maq = (Get-ADObject $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
    if ($maq -gt 0) { Warn ('any user can add ' + $maq + ' computers to the domain (ms-DS-MachineAccountQuota). Used for RBCD and noPac attacks.'); Say ('    Fix: Set-ADObject "' + $dn + '" -Replace @{"ms-DS-MachineAccountQuota"=0}'); $n++ }
    # delegation
    foreach ($o in @(Get-ADObject -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))' -Properties samAccountName)) {
        Warn ('unconstrained delegation on ' + $o.samAccountName + ' (not a DC): it keeps the login ticket of everyone who connects (T1558)'); Say ('    Fix: Set-ADAccountControl "' + $o.samAccountName + '" -TrustedForDelegation $false'); $n++
    }
    foreach ($o in @(Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties samAccountName)) {
        Warn ('resource-based delegation (RBCD) is set on ' + $o.samAccountName + ': another account may log in to it as anyone'); Say ('    If your team did not set it: Set-ADObject "' + $o.DistinguishedName + '" -Clear msDS-AllowedToActOnBehalfOfOtherIdentity'); $n++
    }
    foreach ($o in @(Get-ADObject -LDAPFilter '(&(msDS-KeyCredentialLink=*)(|(objectClass=user)(objectClass=computer)))' -Properties samAccountName, adminCount, primaryGroupID | Where-Object { $_.adminCount -eq 1 -or $_.primaryGroupID -eq 516 })) {
        Warn ('a login key ("shadow credential") is attached to ' + $o.samAccountName + '. Whoever holds the other half can log in as it without the password (T1556)'); Say ('    If nobody set up Windows Hello for it: Set-ADObject "' + $o.DistinguishedName + '" -Clear msDS-KeyCredentialLink'); $n++
    }
    # this DC's own settings
    $sp = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($sp -and $sp.Status -eq 'Running') { Warn 'the Print Spooler runs on this DC: it can be used to force the DC to log in to an attacker (PrinterBug, PrintNightmare)'; Say '    Fix: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled   (not if printing here is scored)'; $n++ }
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -ne 0) { Warn 'LLMNR is on (T1557.001): logins can be caught with Responder'; Say '    Fix for the whole domain: a GPO with Computer Configuration > Policies > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled'; $n++ }
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature') -ne 1) { Warn 'SMB signing is NOT required on this DC: logins can be relayed to it (T1557)'; Say '    Fix: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'; $n++ }
    if ([int](Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity') -lt 2) { Say '  note: LDAP signing is not required (LDAPServerIntegrity < 2). Requiring it can break Linux boxes and apps that bind with plain LDAP: test before you change it.' }
    # DCSync rights and AdminSDHolder
    try {
        $rx = '(?i)Domain Controllers|Administrators|ENTERPRISE DOMAIN CONTROLLERS|Read-only Domain Controllers|\\SYSTEM$|^S-1-5-(9|18)$'
        $repl = @((Get-Acl ('AD:\' + $dn)).Access | Where-Object { $_.ObjectType -match '^(1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c)$' -and ([string]$_.IdentityReference) -notmatch $rx } | ForEach-Object { [string]$_.IdentityReference } | Select-Object -Unique)
        foreach ($r in $repl) { Warn ($r + ' can copy every password hash from the domain (DCSync rights, T1003.006). Only DCs and Administrators should have them.'); Say '    Fix: ADUC > right-click the domain > Properties > Security > Advanced > remove its "Replicating Directory Changes" rows. Then reset krbtgt twice.'; $n++ }
        $ok = '(?i)\\(Domain Admins|Enterprise Admins|Administrators|Cert Publishers|Pre-Windows 2000 Compatible Access|Windows Authorization Access Group|Terminal Server License Servers)$|^(Everyone|NT AUTHORITY\\(SYSTEM|SELF|Authenticated Users))$|^BUILTIN\\'
        $ash = @((Get-Acl ('AD:\CN=AdminSDHolder,CN=System,' + $dn)).Access | Where-Object { ([string]$_.IdentityReference) -notmatch $ok } | ForEach-Object { [string]$_.IdentityReference } | Select-Object -Unique)
        foreach ($r in $ash) { Warn ($r + ' has rights on AdminSDHolder: its rights are copied onto every admin account every 60 minutes, even after you remove them (T1098)'); Say '    Fix: ADUC (Advanced Features on) > System > AdminSDHolder > Properties > Security > remove it.'; $n++ }
    } catch { Say '  could not read the domain permissions (the AD: drive needs the ActiveDirectory module)' }
    # certificate services
    try {
        $cfg = (Get-ADRootDSE).configurationNamingContext
        $cas = @(Get-ADObject -SearchBase ('CN=Enrollment Services,CN=Public Key Services,CN=Services,' + $cfg) -Filter 'objectClass -eq "pKIEnrollmentService"' -Properties certificateTemplates, dNSHostName)
        if ($cas.Count -gt 0) {
            $pub = @($cas | ForEach-Object { $_.certificateTemplates })
            foreach ($t in @(Get-ADObject -SearchBase ('CN=Certificate Templates,CN=Public Key Services,CN=Services,' + $cfg) -Filter * -Properties 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', pKIExtendedKeyUsage, 'msPKI-RA-Signature')) {
                if ($pub -notcontains $t.Name) { continue }
                $eku = @($t.pKIExtendedKeyUsage)
                $auth = ($eku.Count -eq 0) -or ($eku | Where-Object { $_ -match '^(1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|1\.3\.6\.1\.5\.2\.3\.4|2\.5\.29\.37\.0)$' })
                if (([int]$t.'msPKI-Certificate-Name-Flag' -band 1) -and $auth -and -not ([int]$t.'msPKI-Enrollment-Flag' -band 2) -and [int]$t.'msPKI-RA-Signature' -eq 0) {
                    Warn ('certificate template "' + $t.Name + '" lets the requester type any name and can be used to log in (ESC1, T1649). If normal users may enroll, any user becomes Domain Admin.')
                    Say  '    Fix on the CA: certtmpl.msc > the template > Subject Name tab > "Build from this Active Directory information", or Issuance Requirements > CA certificate manager approval.'
                    $n++
                }
            }
            Say ('  certificate authority: ' + (($cas | ForEach-Object { $_.Name + ' on ' + $_.dNSHostName }) -join '; ') + '. If http://<that server>/certsrv answers, turn web enrollment off or require HTTPS with Extended Protection (ESC8).')
        }
    } catch {}
    # recovery readiness
    $rb = @(Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' | Where-Object { $_.EnabledScopes.Count -gt 0 }).Count -gt 0
    if (-not $rb) { Say '  note: the AD Recycle Bin is OFF. If red team deletes users, they come back without passwords or groups. Turn it on BEFORE that happens: menu 17, choice 8.' }
    $lt = (Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
    if ($lt -gt 0) { Say ('  note: accounts lock after ' + $lt + ' bad passwords. Red team can lock scored users on purpose. Your lead decides: menu 17, choice 6 sets it to 0.') }
    if ($n -gt 0) { Flag; Nxt ($n.ToString() + ' weak spots. Fix the ADMIN and scored-service ones first. Every fix above is safe to run except where it says "scored" or "test first".') }
    else { Good 'none of the well-known AD weak spots are open' }
}

# ---- AD attack events since the last hunt (domain controller) ----
function Check-ADEvents {
    param([datetime]$Since)
    Sec 'adevents' 'AD attack events: DCSync, roasting, forged tickets, database theft (T1003.006, T1558, T1003.003)'
    $lines = @()
    foreach ($e in @(Get-Evt 'Security' (XSince @(4662) $Since) 400)) {
        $who = EvData $e 'SubjectUserName'
        if ($who -match '\$$') { continue }
        if ((EvData $e 'Properties') -match '(?i)1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c') { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  DCSync: ' + $who + ' asked for password data like a DC would (4662). If that is not a DC or a sync tool, every hash is stolen.') }
    }
    foreach ($e in @(Get-Evt 'Security' (XSince @(5136) $Since) 200)) {
        $o = EvData $e 'ObjectDN'
        if ($o -match '(?i)CN=AdminSDHolder|CN=Policies,CN=System') { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  ' + (EvData $e 'SubjectUserName') + ' changed ' + $o.Substring(0, [math]::Min(80, $o.Length)) + ' (5136)') }
    }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4741) $Since) 50)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  computer account ' + (EvData $e 'TargetUserName') + ' CREATED by ' + (EvData $e 'SubjectUserName') + ' (4741)') }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4768) $Since) 2000)) {
        $pa = EvData $e 'PreAuthType'
        if ($pa -eq '0' -and (EvData $e 'Status') -eq '0x0') { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  AS-REP roasting: a login ticket for ' + (EvData $e 'TargetUserName') + ' was handed out with NO password proof, to ' + (EvData $e 'IpAddress') + ' (4768)') }
        elseif ($pa -eq '16' -or $pa -eq '17') { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  ' + (EvData $e 'TargetUserName') + ' logged in with a CERTIFICATE from ' + (EvData $e 'IpAddress') + ' (4768). Normal only if you use smart cards.') }
    }
    $rc4 = @(Get-Evt 'Security' (XSince @(4769) $Since "Data[@Name='TicketEncryptionType']='0x17'") 500 | Where-Object { (EvData $_ 'ServiceName') -notmatch '\$$|^krbtgt$' })
    foreach ($g in @($rc4 | Group-Object { (EvData $_ 'TargetUserName') + ' from ' + (EvData $_ 'IpAddress') })) {
        $sv = @($g.Group | ForEach-Object { EvData $_ 'ServiceName' } | Select-Object -Unique)
        $lines += ('  ' + $g.Group[-1].TimeCreated.ToString('HH:mm:ss') + '  Kerberoasting: ' + $g.Name + ' asked for ' + $g.Count + ' RC4 service tickets (' + (($sv | Select-Object -First 5) -join ', ') + ') (4769)')
    }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4688) $Since) 3000)) {
        $cl = EvData $e 'CommandLine'; if (-not $cl) { $cl = EvData $e 'NewProcessName' }
        if ($cl -match '(?i)ntdsutil|vssadmin(\.exe)?"?\s+create|diskshadow|esentutl.*ntds|ntds\.dit|comsvcs.*MiniDump|procdump.*lsass|reg(\.exe)?"?\s+save\s+hk(lm)?\\(sam|system|security)') { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  password-database theft tool: ' + (EvData $e 'SubjectUserName') + ' ran: ' + $cl.Substring(0, [math]::Min(110, $cl.Length)) + ' (4688)') }
    }
    foreach ($e in @(Get-Evt 'System' (XSince @(8222) $Since) 20)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  a shadow copy of the disk was made (8222): the usual way to copy ntds.dit') }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4887) $Since) 50)) { $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  a certificate was issued to ' + (EvData $e 'Requester') + ' for ' + (EvData $e 'Subject') + ' (4887)') }
    # a service ticket with no login ticket before it: CISA's Golden Ticket sign. Only judged when the log reaches back 10 hours.
    $old = @(Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue)
    if ($old.Count -gt 0 -and $old[0].TimeCreated -lt (Get-Date).AddHours(-10)) {
        $tgt = @{}
        foreach ($e in @(Get-Evt 'Security' (XSince @(4768) ((Get-Date).AddHours(-10))) 6000)) { $tgt[((EvData $e 'TargetUserName') -replace '@.*$', '').ToLower() + '|' + ((EvData $e 'IpAddress') -replace '^::ffff:', '')] = 1 }
        $seen = @{}
        foreach ($e in @(Get-Evt 'Security' (XSince @(4769) $Since) 1500)) {
            $u = ((EvData $e 'TargetUserName') -replace '@.*$', '').ToLower(); $ip = (EvData $e 'IpAddress') -replace '^::ffff:', ''
            if ($u -match '\$$' -or $ip -match '^(::1|127\.)' -or -not $u) { continue }
            $k = $u + '|' + $ip
            if (-not $tgt.ContainsKey($k) -and -not $seen.ContainsKey($k)) { $seen[$k] = 1; $lines += ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + '  possible FORGED ticket: ' + $u + ' from ' + $ip + ' used a service ticket, but never got a login ticket from this DC in the last 10 hours. (Another DC may have issued it: check there.)') }
        }
    }
    if ($lines.Count -gt 0) {
        $lines | Select-Object -First 40 | ForEach-Object { Say $_ }
        Flag
        Nxt 'each line is an incident: note the time, account and address (menu 21 saves the facts). DCSync or database theft means: reset krbtgt twice (menu 17) and change every admin and service password.'
    } else { Good 'no DCSync, roasting, forged-ticket or database-theft events since the last hunt' }
}

# ---- audit: turn on the logging the hunt needs ----
function Run-Audit {
    Head 'turn on the logging the hunt needs (changes audit settings only)'
    Why 'a default Windows box does not log most attacks. These settings only add logging. They cannot break a service.'
    $subs = 'Logon', 'Logoff', 'Account Lockout', 'Special Logon', 'Process Creation', 'User Account Management', 'Security Group Management', 'Computer Account Management', 'Audit Policy Change', 'Authentication Policy Change', 'Other Object Access Events', 'Security System Extension', 'Sensitive Privilege Use'
    if ($MyRole -eq 'dc') { $subs += 'Kerberos Service Ticket Operations', 'Kerberos Authentication Service', 'Directory Service Access', 'Directory Service Changes', 'Credential Validation' }
    if (-not (Ask-Yes ('  Turn on ' + $subs.Count + ' audit categories, command-line and PowerShell logging, a bigger Security log, and the Game Day view?'))) { Say '  Nothing changed.'; return }
    foreach ($s in $subs) { $r = auditpol /set /subcategory:"$s" /success:enable /failure:enable 2>&1; if ($LASTEXITCODE -ne 0) { Warn ('could not set "' + $s + '": ' + $r) } }
    Say ('  audit categories on: ' + ($subs -join ', '))
    [void](Set-HReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1)
    [void](Set-HReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1)
    # a Group Policy that uses the old audit settings would wipe these out at the next refresh
    [void](Set-HReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1)
    $sec = Get-WinEvent -ListLog Security
    if ($sec -and $sec.MaximumSizeInBytes -lt 256MB) { wevtutil sl Security /ms:268435456; Say ('  Security log size: ' + [math]::Round($sec.MaximumSizeInBytes / 1MB) + ' MB -> 256 MB (so red team cannot push the evidence out by flooding it)') }
    $ps = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational'
    if ($ps -and $ps.MaximumSizeInBytes -lt 64MB) { wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:67108864 }
    $vd = Join-Path $env:ProgramData 'Microsoft\Event Viewer\Views'
    New-Item -ItemType Directory -Force -Path $vd | Out-Null
    $ids = '4720,4726,4728,4732,4756,4740,4625,4771,4698,1102,7045'
    $q = ($ids -split ',' | Where-Object { $_ -ne '7045' } | ForEach-Object { 'EventID=' + $_ }) -join ' or '
    $xml = '<ViewerConfig><QueryConfig><QueryParams><Simple><Channel>Security,System</Channel><EventId>' + $ids + '</EventId><RelativeTimeInfo>86400000</RelativeTimeInfo><BySource>False</BySource></Simple></QueryParams><QueryNode><Name>Game Day</Name><Description>first30: the events to read every 30 minutes</Description><QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(' + $q + ') and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]</Select><Select Path="System">*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]</Select></Query></QueryList></QueryNode></QueryConfig></ViewerConfig>'
    Set-Content -Path (Join-Path $vd 'First30_GameDay.xml') -Value $xml -Encoding UTF8
    Say '  Event Viewer > Custom Views now has "Game Day" (close and reopen Event Viewer to see it).'
    Auto-Note 'turned on auditing: audit categories, command-line and script block logging, 256 MB Security log, Game Day view'
    Good 'logging is on. The hunt (menu 2) and the Game Day view now have something to read.'
    Say '  Real world: companies set this with Group Policy and send the logs to a central system.'
}

# ---- plumbing: what breaks if you change a password ----
function Check-Plumbing {
    Sec 'plumbing' 'Shared plumbing: read this BEFORE you change any password'
    $n = 0
    $sv = @(Get-CimInstance Win32_Service | Where-Object { $_.StartName -and $_.StartName -notmatch '(?i)^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|.*\$$)' })
    if ($sv.Count -gt 0) {
        Say '  Services that log in with a normal account. If that account''s password changes, also change it in Services > the service > Log On tab, or the service fails at its next start:'
        $sv | ForEach-Object { Say ('    ' + $_.Name + '  runs as  ' + $_.StartName + '  (' + $_.State + ')') }
        $n++
    }
    $tk = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Principal.LogonType -eq 'Password' -and $_.State -ne 'Disabled' })
    if ($tk.Count -gt 0) { Say '  Scheduled tasks with a saved password (they fail quietly after a password change):'; $tk | Select-Object -First 12 | ForEach-Object { Say ('    ' + $_.TaskPath + $_.TaskName + '  as  ' + $_.Principal.UserId) }; $n++ }
    $ah = "$env:windir\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $ah) {
        $ap = @(Select-String -LiteralPath $ah -Pattern 'userName="([^"]+)"' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ } | Select-Object -Unique)
        if ($ap.Count -gt 0) { Say ('  IIS logs in as: ' + ($ap -join ', ') + '. After a password change, update it in IIS Manager (Application Pools > Advanced Settings > Identity), or the site answers 503.'); $n++ }
        $cs = @(Get-ChildItem 'C:\inetpub' -Recurse -Include web.config -File -ErrorAction SilentlyContinue | Select-String -Pattern '(?i)(password|pwd)\s*=' -List | Select-Object -ExpandProperty Path)
        if ($cs.Count -gt 0) { Say '  Web sites with a database password in web.config (change it there too when the SQL password changes):'; $cs | Select-Object -First 8 | ForEach-Object { Say ('    ' + $_) }; $n++ }
    }
    if (Get-Process -Name 'vault', 'vault-agent' -ErrorAction SilentlyContinue) { Say '  HashiCorp Vault is running here. If Vault hands out database passwords, do NOT reset those by hand: restart the Vault agent instead.'; $n++ }
    if (Get-CimInstance Win32_Process -Filter "Name='java.exe'" | Where-Object { $_.CommandLine -match '(?i)keycloak' }) { Say '  Keycloak (single sign-on) is running here. It logs in to AD with a bind account: if that password changes, every login through Keycloak fails (LDAP error 52e) until you update it in Keycloak.'; $n++ }
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain -and $MyRole -ne 'dc') { Say ('  This box is in the domain ' + $cs.Domain + '. If logins fail everywhere, check the DC, DNS and the clock first (menu 16).'); $n++ }
    if ($MyRole -eq 'dc') { Say '  This is a DC: Linux boxes, web apps and SSO log in to it with bind accounts. Before you change or disable an account, search for where it is used (menu 20), and never change a scored account without a PCR.'; $n++ }
    Say '  Rule from Invitational 2: when many services fail at once, look for the ONE shared cause before fixing each.'
    if ($n -eq 0) { Good 'nothing here depends on a normal account''s password' }
}
function Run-Plumbing { Check-Plumbing }

# ---- decoys: more bait files, each one audited ----
function Run-Decoy {
    $df = Join-Path $Vault 'decoys.txt'
    if (-not $Path) {
        Head 'decoys (extra bait files; you can plant several)'
        $l = @(Get-Content $df -ErrorAction SilentlyContinue | Where-Object { $_ })
        if ($l.Count) { $l | ForEach-Object { Say ('  ' + ($_ -split '\|')[0] + '   (made-up login: ' + ($_ -split '\|')[1] + ')') } } else { Say '  None planted.' }
        Say '  Plant one: first30.ps1 decoy -Path C:\Users\Public\Documents\<a believable name> [-Text admin]'
        Say '  -Text admin writes a fake remote-admin tool config instead of an old service login.'
        Why 'red team''s scripts search for files with passwords in them. Reading a decoy costs them time and tells you they are here, with the account and program they used.'
        return
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -match '(?i)^[a-z]:\\(inetpub|windows)\\' -or $full.StartsWith($Vault, [StringComparison]::OrdinalIgnoreCase)) { Warn 'Not under C:\inetpub, C:\Windows or the vault (this script reads those itself).'; return }
    if (Test-Path -LiteralPath $full) { Warn ($full + ' already exists. Pick a new file name.'); return }
    if (-not (Test-Path -LiteralPath (Split-Path $full -Parent))) { Warn ('The folder ' + (Split-Path $full -Parent) + ' does not exist.'); return }
    if (@(Get-Content $df -ErrorAction SilentlyContinue).Count -ge 12) { Warn '12 decoys are planted already. That is plenty.'; return }
    $user = 'svc_' + ('archive', 'mirror', 'relay', 'batch', 'ingest' | Get-Random) + (Get-Random -Minimum 10 -Maximum 99)
    $pw = -join ((48..57) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
    if ($Text -eq 'admin') { $body = @('# remote admin agent - legacy config, kept for rollback', '[server]', 'listen = 127.0.0.1:8443', ('operator = ' + $user), ('auth_token = ' + $pw), '# callback disabled by ops') }
    else { $body = @('# service login for the nightly job - rotated, old value kept until cutover', ('server=' + $env:COMPUTERNAME), ('user=' + $user), ('password=' + $pw)) }
    Set-Content -Path $full -Value $body
    $acl = Get-Acl -LiteralPath $full -Audit
    $acl.AddAuditRule((New-Object System.Security.AccessControl.FileSystemAuditRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')), 'ReadData, Delete, WriteData', 'Success')))
    Set-Acl -LiteralPath $full -AclObject $acl
    auditpol /set "/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
    Add-Content -Path $df -Value ($full + '|' + $user + '|' + (Get-Date).ToString('o'))
    Auto-Note ('planted a decoy (list in ' + $df + ')')
    Good ('decoy planted: ' + $full + '   (made-up login name inside: ' + $user + ')')
    Say '  Windows logs anyone who opens it (event 4663). Never open it yourself.'
}
function Check-Decoy {
    $df = Join-Path $Vault 'decoys.txt'
    $l = @(Get-Content $df -ErrorAction SilentlyContinue | Where-Object { $_ })
    if ($l.Count -eq 0) { return }
    Sec 'decoy' 'Your decoy files (T1552.001, T1083: someone is searching this box for passwords)'
    $paths = @{}; $first = Get-Date
    foreach ($x in $l) { $p = $x -split '\|'; $paths[$p[0]] = $p[1]; try { $t = [datetime]::Parse($p[2]); if ($t -lt $first) { $first = $t } } catch {} }
    $out = @()
    foreach ($k in $paths.Keys) { if (-not (Test-Path -LiteralPath $k)) { $out += ('  ' + $k + ' is GONE: someone deleted or moved it') } }
    $ignore = '(?i)\\(MsMpEng|MpDefenderCoreService|NisSrv|SearchProtocolHost|SearchIndexer|SearchFilterHost)\.exe$'
    foreach ($e in @(Get-Evt 'Security' (XSince @(4663) $first) 600)) {
        $o = EvData $e 'ObjectName'
        if (-not $paths.ContainsKey($o)) { continue }
        $pn = EvData $e 'ProcessName'
        if ($pn -match $ignore) { continue }
        $out += ('  ' + $e.TimeCreated.ToString('MM-dd HH:mm:ss') + '  ' + $o + ' opened by ' + (EvData $e 'SubjectDomainName') + '\' + (EvData $e 'SubjectUserName') + ' using ' + $pn + ' (pid ' + (EvData $e 'ProcessId') + ', logon ' + (EvData $e 'SubjectLogonId') + ')')
    }
    foreach ($u in ($paths.Values | Select-Object -Unique)) {
        foreach ($e in @(Get-Evt 'Security' (XSince @(4625, 4771, 4768) $first ("Data[@Name='TargetUserName']='" + $u + "'")) 20)) { $out += ('  ' + $e.TimeCreated.ToString('MM-dd HH:mm:ss') + '  someone tried the made-up login ' + $u + ' from ' + (EvData $e 'IpAddress') + ' (event ' + $e.Id + ')') }
    }
    if ($out.Count -gt 0) {
        Warn 'a decoy was touched:'
        $out | Select-Object -Unique | Select-Object -First 25 | ForEach-Object { Say $_ }
        Say '  The logon number ties it to a login: find event 4624 with the same Logon ID to get the address it came from.'
        Flag
        Nxt 'this is red team (or a teammate: ask first). Save the facts (menu 21), block the address (menu 8), then hunt for how they got in.'
    } else { Good ('nobody has opened a decoy (' + $l.Count + ' planted)') }
}

# ---- lock-svc: fence in a service your team installed ----
$script:LockNever = '(?i)^(lsass|samss|netlogon|ntds|kdc|dns|dnscache|rpcss|rpceptmapper|dcomlaunch|eventlog|winmgmt|schedule|lanmanserver|lanmanworkstation|termservice|w32time|bfe|mpssvc|windefend|wuauserv|trustedinstaller|dfsr|adws|ismserv|cryptsvc|gpsvc|profsvc|plugplay|power|w3svc|was|mssqlserver|sqlserveragent|spooler|winrm)$'
function Run-LockSvc {
    Head 'fence in a service your team installed'
    $n = $Text
    if (-not $n) { Say '  Usage: first30.ps1 lock-svc -Text <service name>      undo: first30.ps1 undo-lock-svc -Text <service name>'; Say '  For a service YOUR TEAM added (a runner, an exporter, your own app). If red team breaks into it, they must not become SYSTEM.'; return }
    if ($n -match $script:LockNever) { Warn ($n + ' is a core Windows service. Changing its account would break the box. Nothing changed.'); return }
    $w = Get-CimInstance Win32_Service -Filter ("Name='" + $n.Replace("'", "''") + "'")
    if (-not $w) { Warn ('No service called ' + $n + '. See them: Get-Service'); return }
    if ($w.StartName -notmatch '(?i)^(LocalSystem|NT AUTHORITY\\(LocalService|NetworkService|Local Service|Network Service))$') { Warn ($n + ' runs as ' + $w.StartName + ', an account with a password. This script cannot put that back afterwards, so it is left alone.'); Say '  Check by hand that the account is not an admin: net user <name>   and   net localgroup Administrators'; return }
    $exe = Get-ExeFromCmd $w.PathName
    Say ('  ' + $n + ' runs as ' + $w.StartName + '   program: ' + $exe + '   now: ' + $w.State)
    Why 'a service that runs as LocalSystem owns the whole box. As its own small account (NT SERVICE\<name>) with the dangerous rights removed, a break-in stays inside that service: no token stealing (the "Potato" attacks), no reading other programs'' memory.'
    Say '  Careful: the service restarts once. If it cannot start as the new account, everything is put back automatically.'
    if (-not (Ask-Yes '  Do it?')) { Say '  Nothing changed.'; return }
    $undo = Join-Path $Vault ('locksvc_' + $n + '.txt')
    $privs = (sc.exe qprivs $n 2>$null | Out-String)
    Set-Content -Path $undo -Value @($w.StartName, $w.State, $privs)
    $acct = 'NT SERVICE\' + $n
    sc.exe sidtype $n unrestricted | Out-Null
    if ($exe -and (Test-Path $exe)) { icacls (Split-Path $exe -Parent) /grant ($acct + ':(OI)(CI)RX') /T /C /Q | Out-Null }
    $data = Read-Host '  Folder the service WRITES to (its data or log folder), or Enter if none'
    if ($data -and (Test-Path $data)) { icacls $data /grant ($acct + ':(OI)(CI)M') /T /C /Q | Out-Null }
    sc.exe config $n obj= $acct password= '""' | Out-Null
    sc.exe privs $n SeChangeNotifyPrivilege/SeCreateGlobalPrivilege | Out-Null
    $ok = $true
    if ($w.State -eq 'Running') {
        Stop-Service $n -Force -ErrorAction SilentlyContinue; Start-Sleep 1
        try { Start-Service $n -ErrorAction Stop; Start-Sleep 3; $ok = ((Get-Service $n).Status -eq 'Running') } catch { $ok = $false; Warn $_.Exception.Message }
    }
    if (-not $ok) { Warn 'It did not start as the new account, so everything is being put back.'; $script:Text = $n; Run-UnlockSvc; Say '  Usual cause: it needs to write to a folder the new account cannot reach, or it needs a right that was removed.'; return }
    Auto-Note ('fenced in the service ' + $n + ' (now ' + $acct + ', dangerous rights removed)')
    Good ($n + ' now runs as ' + $acct + ' without impersonation or debug rights. Check that it still does its job, and the scoreboard.')
    Say ('  Undo: first30.ps1 undo-lock-svc -Text ' + $n)
}
function Run-UnlockSvc {
    $n = $Text
    $undo = Join-Path $Vault ('locksvc_' + $n + '.txt')
    if (-not $n -or -not (Test-Path $undo)) { Warn 'Usage: first30.ps1 undo-lock-svc -Text <service name>   (only for a service this script fenced in)'; return }
    $u = @(Get-Content $undo)
    $old = $u[0]; if ($old -eq 'LocalSystem') { $o = 'LocalSystem' } else { $o = $old }
    if ($o -eq 'LocalSystem') { sc.exe config $n obj= LocalSystem | Out-Null } else { sc.exe config $n obj= $o password= '""' | Out-Null }
    $pl = @($u | Where-Object { $_ -match '^\s+Se\w+Privilege' } | ForEach-Object { $_.Trim() })
    if ($pl.Count -gt 0) { sc.exe privs $n ($pl -join '/') | Out-Null } else { reg delete ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) /v RequiredPrivileges /f 2>$null | Out-Null }
    if ($u[1] -eq 'Running') { Stop-Service $n -Force -ErrorAction SilentlyContinue; Start-Service $n -ErrorAction SilentlyContinue }
    Remove-Item $undo -Force
    Auto-Note ('removed the fence from the service ' + $n)
    Good ($n + ' is back to ' + $old + ' (' + (Get-Service $n).Status + ')')
}

# ---- scrub: a password typed in plain sight ----
function Run-Scrub {
    Head 'scrub a password out of the PowerShell history files'
    Say '  FIRST change that password. Someone may have read it already. Scrubbing only stops the NEXT reader.'
    Why 'this removes only the lines that contain the password. The rest of the history stays, because history is also evidence of what red team typed.'
    if (-not (Ask-Yes '  Have you already changed the leaked password?')) { Say '  Change it first, then run this again. Nothing changed.'; return }
    $p = SecureToPlain (Read-Host '  Type the LEAKED (old) password (hidden; not saved anywhere)' -AsSecureString)
    if ($p.Length -lt 4) { Warn 'Too short to search for safely. Nothing changed.'; return }
    $n = 0
    foreach ($f in @(Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt' -Force -ErrorAction SilentlyContinue)) {
        $all = @(Get-Content -LiteralPath $f.FullName)
        $keep = @($all | Where-Object { -not $_.Contains($p) })
        if ($keep.Count -ne $all.Count) { Set-Content -LiteralPath $f.FullName -Value $keep; Say ('    removed ' + ($all.Count - $keep.Count) + ' line(s) from ' + $f.FullName); $n += ($all.Count - $keep.Count) }
    }
    $p = $null
    if ($n -eq 0) { Say '  Not found in any PowerShell history file.' } else { Auto-Note ('scrubbed a leaked password from PowerShell history (' + $n + ' lines)') }
    Say '  Still to do by hand, in each PowerShell window that is open right now (type both lines there):'
    Say '      [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()'
    Say '      Clear-History'
    Say '  The Security log (4688) and the PowerShell log (4104) may also hold the command. They are evidence, so they are left alone.'
    Add-Remind 'PCR or team note: a password was exposed in command history and was changed'
}

# ===========================================================================
# ADDED IN V6 (November 2026): the clock, every address on the box, Group
# Policy tasks and scripts in SYSVOL, IIS modules and WMI providers, database
# backdoors, and "report": the facts for the packet and for incident reports.
# ===========================================================================
function Get-AllIPs {
    foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Sort-Object InterfaceIndex, SkipAsSource)) {
        $kind = 'primary'
        if ($a.SkipAsSource) { $kind = 'SECONDARY' }
        if ($a.InterfaceAlias -match '(?i)vEthernet|Loopback|WSL|Docker|nat|TAP|WireGuard|Tailscale') { $kind += ' (virtual switch, container or tunnel)' }
        [pscustomobject]@{ Address = ($a.IPAddress + '/' + $a.PrefixLength); Adapter = $a.InterfaceAlias; Kind = $kind; Origin = [string]$a.PrefixOrigin }
    }
}
function Check-Clock {
    Sec 'clock' 'The clock and every address on this box (Kerberos breaks at 5 minutes off; T1070.006)'
    Say ('  UTC now:   ' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + '    <- compare with your phone. It must match within 1 minute.')
    Say ('  local now: ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '    time zone: ' + [TimeZoneInfo]::Local.Id)
    $bad = $false
    $w = Get-Service W32Time -ErrorAction SilentlyContinue
    if ($w -and $w.Status -ne 'Running') { Warn 'the Windows Time service is NOT running: this clock drifts, and on a DC every domain computer follows it'; $bad = $true }
    $src = (w32tm /query /source 2>$null | Select-Object -First 1)
    if ($src) { Say ('  time comes from: ' + ([string]$src).Trim()) }
    if ($MyRole -ne 'dc') {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.PartOfDomain) {
            $o = (w32tm /stripchart /computer:$($cs.Domain) /samples:1 /dataonly 2>$null | Select-String -Pattern '([+-]\d+\.\d+)s' | Select-Object -Last 1)
            if ($o) { $sec = [math]::Abs([double]$o.Matches[0].Groups[1].Value); Say ('  difference from the domain controller: ' + [math]::Round($sec, 1) + ' seconds'); if ($sec -gt 240) { Warn 'more than 4 minutes off the DC. At 5 minutes every Kerberos login fails (KRB_AP_ERR_SKEW).'; $bad = $true } }
        }
    }
    foreach ($e in @(Get-Evt 'Security' (XSince @(4616) ((Get-Date).AddHours(-2))) 20 | Where-Object { (EvData $_ 'SubjectUserName') -notmatch '\$$|LOCAL SERVICE' -and (EvData $_ 'ProcessName') -notmatch '(?i)svchost|vmtoolsd|VBoxService' })) {
        Warn ('the clock was CHANGED at ' + $e.TimeCreated.ToString('HH:mm:ss') + ' by ' + (EvData $e 'SubjectUserName') + ' using ' + (EvData $e 'ProcessName') + ' (event 4616)'); $bad = $true
    }
    $ips = @(Get-AllIPs)
    Say '  Addresses on this box (write ALL of them in the packet documentation):'
    $ips | ForEach-Object { Say ('    ' + $_.Address.PadRight(20) + $_.Adapter + '   ' + $_.Kind) }
    $f = Join-Path $Vault 'v6_ips.txt'
    $now = @($ips | ForEach-Object { $_.Address + ' ' + $_.Adapter })
    if (-not (Test-Path $f)) { Set-Content -Path $f -Value $now }
    else {
        $d = Compare-Lines @(Get-Content $f) $now
        if ($d.New.Count -gt 0) { Warn ('addresses added since this script''s first run here: ' + ($d.New -join '; ') + '. A new address can catch traffic meant for another box.'); $bad = $true }
        if ($d.Gone.Count -gt 0) { Warn ('addresses that are gone: ' + ($d.Gone -join '; ')); $bad = $true }
    }
    if ($bad) { Flag; Nxt 'fix the clock: w32tm /resync /force (a member), or on the DC: w32tm /config /syncfromflags:domhier /update then net stop w32time and net start w32time. Remove an address: Remove-NetIPAddress -IPAddress <address>' }
    else { Good 'the time service is running, nobody changed the clock, and the addresses are the same' }
}

# ---- Group Policy files in SYSVOL: tasks, services, scripts and local-admin changes pushed to every computer ----
function Check-GpoFiles {
    if ($MyRole -ne 'dc') { return }
    $root = Join-Path $env:windir 'SYSVOL\sysvol'
    if (-not (Test-Path $root)) { return }
    Sec 'gpofiles' 'Group Policy files that run things on every computer: tasks, services, scripts (T1484.001, T1053.005, T1037.003)'
    $names = 'ScheduledTasks.xml', 'Services.xml', 'Groups.xml', 'Registry.xml', 'Files.xml', 'scripts.ini', 'psscripts.ini', 'GptTmpl.inf'
    $files = @(Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.Name -or $_.Extension -match '^\.(ps1|bat|cmd|vbs|js|exe|dll|msi|aas|hta|wsf)$' })
    $now = @($files | ForEach-Object { $_.FullName.Substring($root.Length) + ' | ' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.Substring(0, 16) })
    $out = @()
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($root.Length)
        if ($f.Name -eq 'ScheduledTasks.xml') {
            foreach ($m in @(Select-String -LiteralPath $f.FullName -Pattern '<(ImmediateTaskV2|TaskV2|ImmediateTask|Task)\s[^>]*name="([^"]+)"' -AllMatches | ForEach-Object { $_.Matches })) { $out += ('  task pushed by Group Policy: "' + $m.Groups[2].Value + '" (' + $m.Groups[1].Value + ') in ' + $rel) }
            foreach ($m in @(Select-String -LiteralPath $f.FullName -Pattern '<Command>([^<]+)</Command>(\s*<Arguments>([^<]*)</Arguments>)?' -AllMatches | ForEach-Object { $_.Matches })) { $out += ('      runs: ' + $m.Groups[1].Value + ' ' + $m.Groups[3].Value) }
        }
        elseif ($f.Name -eq 'Groups.xml') { foreach ($m in @(Select-String -LiteralPath $f.FullName -Pattern '<Member\s[^>]*name="([^"]+)"[^>]*action="ADD"' -AllMatches | ForEach-Object { $_.Matches })) { $out += ('  Group Policy ADDS ' + $m.Groups[1].Value + ' to a local group on every computer: ' + $rel) } }
        elseif ($f.Name -eq 'Services.xml') { $out += ('  Group Policy changes services on every computer: ' + $rel) }
        elseif ($f.Name -match '^(ps)?scripts\.ini$') { foreach ($l in @(Get-Content -LiteralPath $f.FullName | Where-Object { $_ -match '^\d+CmdLine=(.+)$' })) { $out += ('  startup, shutdown, logon or logoff script: ' + ($l -replace '^\d+CmdLine=', '') + '   (' + $rel + ')') } }
        elseif ($f.Name -eq 'GptTmpl.inf') { foreach ($l in @(Get-Content -LiteralPath $f.FullName | Where-Object { $_ -match '^(SeDebugPrivilege|SeEnableDelegationPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege|SeImpersonatePrivilege)\s*=\s*(.+)$' })) { if ($l -notmatch '=\s*(\*S-1-5-32-544|\*S-1-5-19|\*S-1-5-20|\*S-1-5-6|\*S-1-5-32-551|\*S-1-5-32-549|\*S-1-5-32-550|,|\s)*$') { $out += ('  Group Policy hands out a powerful right: ' + $l.Trim() + '   (' + $rel + ')') } } }
    }
    $bf = Join-Path $Vault 'v6_gpofiles.txt'
    $hit = $false
    if (-not (Test-Path $bf)) {
        Set-Content -Path $bf -Value $now
        Say ('  saved a fingerprint of ' + $now.Count + ' Group Policy files. Later hunts show what is new or changed. Right now:')
        if ($out.Count -gt 0) { $out | Select-Object -First 30 | ForEach-Object { Say $_ }; Say '  Read each line above once, now. Anything your packet does not explain is a finding.'; $hit = $true }
    } else {
        $d = Compare-Lines @(Get-Content $bf) $now
        if ($d.New.Count -gt 0 -or $d.Gone.Count -gt 0) {
            Warn 'Group Policy files that are NEW or CHANGED since the first run (they reach every computer in the domain within 90 minutes):'
            $d.New | Select-Object -First 20 | ForEach-Object { Say ('    new or changed: ' + $_) }
            $d.Gone | Select-Object -First 10 | ForEach-Object { Say ('    gone or changed: ' + $_) }
            $out | Select-Object -First 20 | ForEach-Object { Say $_ }
            $hit = $true
        }
    }
    Why 'Get-ScheduledTask on the DC only shows the DC''s own tasks. A task or script in a Group Policy file never shows there, but runs as SYSTEM on every computer that reads the policy.'
    if ($hit) { Flag; Nxt 'find the policy: the {GUID} folder name in the path is the GPO id: Get-GPO -Guid <GUID>. If your team did not make the change: back it up (it is evidence), then remove the setting in Group Policy Management, or restore all GPOs (menu 19, choice 4).' }
    else { Good 'no Group Policy file is new or changed' }
}

# ---- IIS modules and WMI providers: code that loads into a trusted process ----
function Check-IisModules {
    $ah = "$env:windir\System32\inetsrv\config\applicationHost.config"
    $hasIis = Test-Path $ah
    Sec 'iismod' 'IIS modules and WMI providers: backdoors that load inside a trusted program (T1505.004, T1546.003)'
    $out = @()
    if ($hasIis) {
        $txt = Get-Content -LiteralPath $ah -Raw
        foreach ($m in [regex]::Matches($txt, '<add\s+name="([^"]+)"\s+image="([^"]+)"')) {
            $img = [Environment]::ExpandEnvironmentVariables(($m.Groups[2].Value -replace '%windir%', $env:windir))
            $why = @()
            if ($img -notmatch '(?i)^[a-z]:\\Windows\\(System32|SysWOW64)\\inetsrv\\|\\Microsoft\.NET\\Framework|\\IIS\\|\\Windows\\System32\\(webengine|rpcproxy|authz)') { $why += 'not in the IIS folder' }
            if (-not (Test-Path -LiteralPath $img)) { $why += 'file missing' } elseif ((Get-SigStatus $img) -ne 'Valid') { $why += 'not signed' }
            if ($why.Count -gt 0) { $out += ('  IIS native module "' + $m.Groups[1].Value + '" loads ' + $img + '   (' + ($why -join ', ') + ')') }
        }
        $cfgs = @($ah) + @(Get-ChildItem 'C:\inetpub' -Recurse -Include web.config -File -ErrorAction SilentlyContinue | Select-Object -First 200 -ExpandProperty FullName)
        foreach ($c in $cfgs) {
            $t = Get-Content -LiteralPath $c -Raw -ErrorAction SilentlyContinue
            if (-not $t) { continue }
            $mods = [regex]::Match($t, '(?s)<modules[^>]*>(.*?)</modules>').Groups[1].Value
            foreach ($m in [regex]::Matches($mods, '<add\s+name="([^"]+)"[^>]*\stype="([^"]+)"')) {
                if ($m.Groups[2].Value -notmatch '^(System\.|Microsoft\.)') { $out += ('  IIS managed module "' + $m.Groups[1].Value + '" type ' + $m.Groups[2].Value + '   in ' + $c) }
            }
            foreach ($m in [regex]::Matches($t, '<filter\s+name="([^"]+)"\s+path="([^"]+)"')) {
                $p = [Environment]::ExpandEnvironmentVariables($m.Groups[2].Value)
                if ($p -notmatch '(?i)\\Microsoft\.NET\\Framework|\\inetsrv\\' ) { $out += ('  ISAPI filter "' + $m.Groups[1].Value + '" loads ' + $p + '   in ' + $c) }
            }
        }
        foreach ($d in @(Get-ChildItem 'C:\inetpub' -Recurse -Include *.dll -File -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -match '(?i)\\bin$' -and $_.LastWriteTime -gt (Get-Date).AddDays(-2) } | Select-Object -First 10)) { $out += ('  a DLL in a web site''s bin folder changed in the last 2 days (it loads into the site): ' + $d.FullName + '  ' + $d.LastWriteTime) }
    }
    foreach ($p in @(Get-CimInstance -Namespace root\cimv2 -ClassName __Win32Provider -ErrorAction SilentlyContinue)) {
        if (-not $p.CLSID) { continue }
        $dll = Get-RegValue ('HKLM:\SOFTWARE\Classes\CLSID\' + $p.CLSID + '\InprocServer32') '(default)'
        if (-not $dll) { continue }
        $dll = [Environment]::ExpandEnvironmentVariables(([string]$dll).Trim('"'))
        if ($dll -notmatch '^[A-Za-z]:\\') { continue }
        if ($dll -notmatch '(?i)^[a-z]:\\(Windows|Program Files|Program Files \(x86\))\\' -or ((Test-Path -LiteralPath $dll) -and (Test-UserWritable $dll))) { $out += ('  WMI provider "' + $p.Name + '" loads ' + $dll + ' (outside the Windows and Program Files folders): it runs as SYSTEM inside WMI') }
    }
    $bf = Join-Path $Vault 'v6_iismods.txt'
    if ($hasIis) {
        $now = @([regex]::Matches((Get-Content -LiteralPath $ah -Raw), '<add\s+name="([^"]+)"\s+image="([^"]+)"') | ForEach-Object { $_.Groups[1].Value + ' | ' + $_.Groups[2].Value })
        if (-not (Test-Path $bf)) { Set-Content -Path $bf -Value $now } else { $d = Compare-Lines @(Get-Content $bf) $now; foreach ($n in $d.New) { $out += ('  IIS module added since the first run: ' + $n) } }
    }
    if ($out.Count -gt 0) {
        $out | Select-Object -Unique | Select-Object -First 30 | ForEach-Object { Say $_ }
        Why 'an IIS module sees every web request, so it can hide a command channel inside normal web traffic. The web site still loads, so the scoring check stays green.'
        Flag
        Nxt 'your own app''s modules are normal: check the list against the app. Unknown: save the DLL (menu 5), then remove its <add> line (inetmgr > Modules, or appcmd uninstall module "<name>") and restart IIS.'
    } else { Good 'every IIS module is a signed Microsoft one, and no WMI provider loads from an odd folder' }
}

# ---- database backdoors (SQL Server through Windows login; MySQL if its client is here) ----
function Invoke-Sql {
    param([string]$Q)
    $exe = Get-Command sqlcmd.exe -ErrorAction SilentlyContinue
    if (-not $exe) { return $null }
    return @(sqlcmd.exe -E -S . -h -1 -W -l 5 -t 15 -Q ('SET NOCOUNT ON; ' + $Q) 2>$null | Where-Object { $_ -and $_ -notmatch '^(Msg \d+|Sqlcmd:|\(\d+ rows)' })
}
function Check-Db {
    $sql = @(Get-Service -Name 'MSSQLSERVER', 'MSSQL$*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
    if ($sql.Count -eq 0) { return }
    Sec 'db' 'Database accounts and backdoors (T1505.001, T1136, T1059)'
    if (-not (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue)) { Say '  SQL Server is running, but sqlcmd.exe is not on this box, so it was not checked.'; ByHand 'SQL Server Management Studio > Security > Logins, and Server Objects > Linked Servers'; return }
    $t = Invoke-Sql 'select 1'
    if (-not $t -or ([string]$t[0]).Trim() -ne '1') { Say '  SQL Server is running, but this Windows account cannot log in to it, so it was not checked. Run as an account that is a SQL admin.'; return }
    $out = @()
    $adm = @(Invoke-Sql "select p.name from sys.server_role_members m join sys.server_principals r on r.principal_id=m.role_principal_id join sys.server_principals p on p.principal_id=m.member_principal_id where r.name='sysadmin'" | ForEach-Object { ([string]$_).Trim() })
    Say ('  SQL Server admins (sysadmin): ' + ($adm -join ', '))
    $bf = Join-Path $Vault 'v6_sqladmins.txt'
    if (-not (Test-Path $bf)) { Set-Content -Path $bf -Value $adm } else { $d = Compare-Lines @(Get-Content $bf) $adm; if ($d.New.Count) { $out += ('  NEW SQL admins since the first run: ' + ($d.New -join ', ')) } }
    foreach ($o in 'xp_cmdshell', 'Ole Automation Procedures', 'clr enabled', 'Ad Hoc Distributed Queries') {
        $v = Invoke-Sql ("select cast(value_in_use as int) from sys.configurations where name='" + $o + "'")
        if ($v -and ([string]$v[0]).Trim() -eq '1') { $out += ('  "' + $o + '" is ON: SQL can run operating-system commands or outside code. Off unless your app needs it: EXEC sp_configure ''' + $o + ''', 0; RECONFIGURE;') }
    }
    $ls = @(Invoke-Sql 'select name + '' -> '' + isnull(data_source, '''') from sys.servers where is_linked = 1')
    if ($ls.Count) { $out += ('  linked servers (a path from this SQL Server to another): ' + ($ls -join '; ')) }
    $sp = @(Invoke-Sql "select name from master.sys.procedures where is_auto_executed = 1")
    if ($sp.Count) { $out += ('  procedures that run by themselves every time SQL Server starts: ' + ($sp -join ', ')) }
    $np = @(Invoke-Sql "select name from sys.sql_logins where pwdcompare('', password_hash) = 1 or pwdcompare(name, password_hash) = 1")
    if ($np.Count) { $out += ('  SQL logins with an EMPTY password, or the password equal to the name: ' + ($np -join ', ')) }
    $tw = @(Invoke-Sql "select name from sys.databases where is_trustworthy_on = 1 and name <> 'msdb'")
    if ($tw.Count) { $out += ('  databases marked TRUSTWORTHY (their owner can become a SQL admin): ' + ($tw -join ', ')) }
    $as = @(Invoke-Sql "select name from sys.assemblies where is_user_defined = 1")
    if ($as.Count) { $out += ('  user-made code libraries loaded into master (CLR assemblies): ' + ($as -join ', ')) }
    $tr = @(Invoke-Sql "select name from sys.server_triggers")
    if ($tr.Count) { $out += ('  server-wide triggers (they run at every logon or change): ' + ($tr -join ', ')) }
    if ($out.Count -gt 0) {
        $out | ForEach-Object { Say $_ }
        Flag
        Nxt 'check each against your app before you remove it: the scored check may log in with one of these. Tell your lead, then: DROP LOGIN [name]; or the sp_configure line shown.'
    } else { Good 'no new SQL admins, no command execution switched on, no empty passwords' }
}

# ---- report: the facts for the packet and for incident reports ----
$script:Mitre = 'T1003=OS Credential Dumping|T1003.001=LSASS Memory|T1003.003=NTDS|T1003.006=DCSync|T1014=Rootkit|T1021.001=Remote Desktop Protocol|T1036.003=Rename Legitimate Utilities|T1036.005=Match Legitimate Resource Name or Location|T1037.003=Network Logon Script|T1053.005=Scheduled Task|T1055=Process Injection|T1056=Input Capture|T1059=Command and Scripting Interpreter|T1059.001=PowerShell|T1068=Exploitation for Privilege Escalation|T1070.006=Timestomp|T1071=Application Layer Protocol|T1071.001=Web Protocols|T1078=Valid Accounts|T1083=File and Directory Discovery|T1090=Proxy|T1095=Non-Application Layer Protocol|T1098=Account Manipulation|T1105=Ingress Tool Transfer|T1110=Brute Force|T1110.003=Password Spraying|T1113=Screen Capture|T1136=Create Account|T1190=Exploit Public-Facing Application|T1197=BITS Jobs|T1219=Remote Access Tools|T1484.001=Group Policy Modification|T1486=Data Encrypted for Impact|T1505.001=SQL Stored Procedures|T1505.003=Web Shell|T1505.004=IIS Components|T1531=Account Access Removal|T1543.003=Windows Service|T1546=Event Triggered Execution|T1546.003=Windows Management Instrumentation Event Subscription|T1546.013=PowerShell Profile|T1547.001=Registry Run Keys / Startup Folder|T1552=Unsecured Credentials|T1552.001=Credentials In Files|T1552.006=Group Policy Preferences|T1556=Modify Authentication Process|T1557=Adversary-in-the-Middle|T1557.001=LLMNR/NBT-NS Poisoning and SMB Relay|T1558=Steal or Forge Kerberos Tickets|T1558.001=Golden Ticket|T1558.003=Kerberoasting|T1558.004=AS-REP Roasting|T1562.001=Disable or Modify Tools|T1562.002=Disable Windows Event Logging|T1562.004=Disable or Modify System Firewall|T1562.006=Indicator Blocking|T1564.004=NTFS File Attributes|T1570=Lateral Tool Transfer|T1572=Protocol Tunneling|T1574=Hijack Execution Flow|T1649=Steal or Forge Authentication Certificates'
function Run-Report {
    $map = @{}; foreach ($kv in ($script:Mitre -split '\|')) { $p = $kv -split '=', 2; $map[$p[0]] = $p[1] }
    $o = @()
    $os = Get-CimInstance Win32_OperatingSystem
    $o += ('===== FACTS for ' + $env:COMPUTERNAME + '  (copy what you need; your team writes the words) =====')
    $o += ('Box:        ' + $env:COMPUTERNAME + '     OS: ' + $os.Caption + ' ' + $os.Version + '     role: ' + $MyRole + '     domain: ' + (Get-CimInstance Win32_ComputerSystem).Domain)
    $o += ('Time:       ' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC     local: ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' ' + [TimeZoneInfo]::Local.Id)
    if (Test-Path $BaseDir) { $o += ('Baseline:   seal ' + (Get-Seal $BaseDir) + '   (must match the seal on your paper)') } else { $o += 'Baseline:   none yet (menu 1)' }
    $o += ''; $o += '--- Every address on this box (packet documentation) ---'
    foreach ($i in @(Get-AllIPs)) { $o += ('  ' + $i.Address.PadRight(20) + $i.Adapter + '   ' + $i.Kind) }
    $o += ('  default gateway: ' + ((Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop -Unique) -join ', ') + '     DNS: ' + ((Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses -Unique) -join ', '))
    $o += ''; $o += '--- Listening services (port, program, account) ---'
    foreach ($l in @(Get-ListenInfo | Select-Object -First 40)) { $o += ('  ' + $l.Proto + ' ' + ([string]$l.Port).PadRight(7) + ([string]$l.Process).PadRight(22) + $l.Account) }
    $o += ''; $o += '--- Evidence saved in the vault (proof for an incident report) ---'
    $ev = Join-Path $Vault 'quarantine\evidence_log.txt'
    if (Test-Path $ev) { Get-Content $ev | Select-Object -Last 60 | ForEach-Object { $o += ('  ' + $_) } } else { $o += '  none saved yet (menu 5)' }
    $o += ''; $o += '--- Addresses your team blocked, with first and last time each one appears in the logs ---'
    $bl = @(Get-Content $BlockFile -ErrorAction SilentlyContinue | Where-Object { $_ })
    if ($bl.Count -eq 0) { $o += '  none' }
    foreach ($b in $bl) {
        $ip = ($b -split '\s+')[0]
        $o += ('  ' + $b)
        $hits = @(Get-Evt 'Security' (XSince @(4624, 4625) ((Get-Date).AddHours(-24)) ("Data[@Name='IpAddress']='" + ($ip -replace '/.*$', '') + "'")) 2000 | Sort-Object TimeCreated)
        if ($hits.Count -gt 0) { $o += ('      first seen: ' + $hits[0].TimeCreated.ToString('MM-dd HH:mm:ss') + ' event ' + $hits[0].Id + ' as ' + (EvData $hits[0] 'TargetUserName') + '      last seen: ' + $hits[-1].TimeCreated.ToString('MM-dd HH:mm:ss') + ' (' + $hits.Count + ' logon events)') }
    }
    $o += ''; $o += '--- Findings from the latest hunt, with their MITRE ATT&CK technique ---'
    $lf = Join-Path $Vault 'lastfindings.txt'
    if (Test-Path $lf) {
        $o += ('  (hunt of ' + (Get-Item $lf).LastWriteTime.ToString('MM-dd HH:mm') + ')')
        foreach ($f in @(Get-Content $lf | Where-Object { $_ })) {
            $o += ('  * ' + $f)
            foreach ($m in @([regex]::Matches($f, 'T\d{4}(\.\d{3})?') | ForEach-Object { $_.Value } | Sort-Object -Unique)) { $n = $map[$m]; if (-not $n) { $n = '(look the name up on attack.mitre.org)' }; $o += ('      ' + $m + '  ' + $n) }
        }
    } else { $o += '  no hunt has been run yet (menu 2)' }
    $o += ''; $o += '--- Your team''s notes (what you changed, and when) ---'
    Get-Content $NotesFile -ErrorAction SilentlyContinue | Select-Object -Last 25 | ForEach-Object { $o += ('  ' + $_) }
    $o += ''; $o += 'An incident report also needs, in your own words: how they got in, what was affected, what you did,'
    $o += 'and how you stop it happening again. An AI must not write any part of it.'
    $rp = Join-Path $ReportDir ('report_' + $env:COMPUTERNAME + '_' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    Set-Content -Path $rp -Value $o -Encoding UTF8
    $o | ForEach-Object { Say $_ }
    Say ''
    Good ('saved: ' + $rp + '   (open it in Notepad to copy from it)')
}
function Save-Findings { Set-Content -Path (Join-Path $Vault 'lastfindings.txt') -Value @($script:Found) }

# ===== end of the v4 and v5 additions =====

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
$IsAdmin = Test-Admin
if (-not $IsAdmin) {
    if ($Mode -eq 'menu' -and $PSCommandPath -and [Environment]::UserInteractive) {
        Warn 'This needs to run as Administrator.'
        if ((Read-Host 'Open it again as Administrator now? (y/n)') -match '^(?i)y') {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"')
            return
        }
    }
    Warn 'Not elevated. Right-click PowerShell and Run as Administrator, then run this again.'
    Warn 'Continuing anyway, but many checks will be blank.'
}

$MyRole        = Get-Role
$script:stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:SnapDir = Join-Path $Vault $script:stamp
$BaseDir       = Join-Path $Vault 'baseline'
$ReportDir     = Join-Path $Vault 'reports'
$BlockFile     = Join-Path $Vault 'blocked.txt'
$NotesFile     = Join-Path $Vault 'notes.txt'
$NotesSeenFile = Join-Path $Vault '.notes_seen'
$LastHuntFile  = Join-Path $Vault '.lasthunt'
$NetsFile      = Join-Path $Vault 'ournets.txt'
$BaitFile      = Join-Path $Vault 'bait.txt'
New-Item -ItemType Directory -Force -Path $Vault | Out-Null
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
if ($IsAdmin) { Lock-Vault }
if (Test-VaultTrap) { return }
$script:LearnSet = $PSBoundParameters.ContainsKey('Learn')

# game-day settings saved in the vault: your networks and the bait
$script:Nets = @($OurNets | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($script:Nets.Count -eq 0 -and (Test-Path $NetsFile)) { $script:Nets = @(Get-Content $NetsFile | Where-Object { $_ }) }
$script:BaitPath = ''; $script:BaitUser = ''; $script:BaitTime = (Get-Date).AddDays(-1)
if (Test-Path $BaitFile) {
    $b = @(Get-Content $BaitFile)
    $script:BaitPath = $b[0]
    $script:BaitUser = $b[1]
    try { $script:BaitTime = [datetime]::Parse($b[2]) } catch {}
}

Say ('first30.ps1  host=' + $env:COMPUTERNAME + '  role=' + $MyRole + '  mode=' + $Mode + '  vault=' + $Vault)

switch ($Mode) {
    'menu'     { Run-Menu }
    'recon'    { Invoke-Action 'recon' { Run-Recon } }
    'backup'   { Invoke-Action 'backup' { New-Snapshot; Collect-Common; if ($MyRole -eq 'dc') { Collect-DC }; Run-Backup; Make-Baseline } }
    'all'      { Invoke-Action 'all' { Run-All } }
    'hunt'     { Invoke-Action 'hunt' { Run-Hunt } }
    'c2'       { Invoke-Action 'c2' { Run-C2 } }
    'trace'    { Invoke-Action 'trace' { Run-Trace } }
    'evidence' { Invoke-Action 'evidence' { Run-Evidence } }
    'note'     { Run-Note }
    'notes'    { Run-Notes }
    'nets'     { Run-Nets }
    'block'    { Invoke-Action 'block' { Run-Block } }
    'unblock'  { Run-Unblock }
    'bait'     { Run-Bait }
    'quiet'      { Run-Quiet }
    'undo-quiet' { Run-UndoQuiet }
    'sos'        { Run-SOS }
    'why'        { Run-Why }
    'harden'     { Invoke-Action 'harden' { Run-Harden } }
    'undo-harden' { Run-UndoHarden }
    'bugs'       { Invoke-Action 'bugs' { Run-Bugs } }
    'domain'     { Invoke-Action 'domain' { Check-Domain } }
    'ad'         { Run-AD }
    'kick'       { Run-Kick }
    'restore'    { Run-Restore }
    'findpass'   { Run-FindPass }
    'facts'      { Run-Facts }
    'trip'       { Run-Trip }
    'protect'    { Run-Protect }
    'unprotect'  { Run-Unprotect }
    'reminders'  { Run-Reminders }
    'audit'      { Invoke-Action 'audit' { Run-Audit } }
    'advuln'     { Invoke-Action 'advuln' { if ($MyRole -eq 'dc') { Check-ADVuln; Check-ADEvents ((Get-Date).AddHours(-12)) } else { Say 'Run this on a domain controller.' } } }
    'plumbing'   { Invoke-Action 'plumbing' { Check-Plumbing } }
    'decoy'      { Run-Decoy }
    'lock-svc'   { Run-LockSvc }
    'undo-lock-svc' { Run-UnlockSvc }
    'scrub'      { Run-Scrub }
    'report'     { Run-Report }
}
