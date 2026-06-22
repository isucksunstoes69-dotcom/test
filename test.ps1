<#
.SYNOPSIS
    Javaw Scanner - RAM + DNS cache cheat-client detector for SS investigations.

.DESCRIPTION
    Phase 1: Enumerates java.exe/javaw.exe processes.
    Phase 2: Walks committed/readable memory regions (skips PAGE_GUARD, >MaxRegionMB).
    Phase 3: Aho-Corasick multi-pattern scan against Client + Generic signature DBs.
    Phase 4: DNS cache scan (ipconfig /displaydns) against known C2/update domains.
    Phase 5: Verdict classification + JSON output, optional POST to SSDashApi.

.NOTES
    Read-only. Never writes to target process memory. Requires admin (PROCESS_VM_READ
    + DNS cache access work better elevated; will warn and continue with reduced scope
    if not elevated).

.PARAMETER PostUrl
    Optional SSDashApi endpoint to POST the resulting JSON verdict to.

.PARAMETER MaxRegionMB
    Skip committed regions larger than this (default 100MB), mirrors the Phase 2 filter.

.PARAMETER OutFile
    Where to write the JSON result. Default: .\javaw-scan-result.json
#>

[CmdletBinding()]
param(
    [string]$PostUrl,
    [int]$MaxRegionMB = 100,
    [string]$OutFile = ".\javaw-scan-result.json"
)

# ---------------------------------------------------------------------------
# Elevation check
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running elevated. Process memory access and full DNS cache enumeration may fail. Re-run as Administrator for best results."
}

# ---------------------------------------------------------------------------
# Native interop + Aho-Corasick (C#) — compiled once via Add-Type
# ---------------------------------------------------------------------------
$cs = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace JavawScan
{
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public static class Native
    {
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;

        public const uint MEM_COMMIT = 0x1000;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_NOACCESS = 0x01;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
    }

    // Simple Aho-Corasick automaton for case-insensitive ASCII substring matching
    // across many patterns in a single pass per memory chunk.
    public class AhoCorasick
    {
        private class Node
        {
            public Dictionary<byte, Node> Children = new Dictionary<byte, Node>();
            public Node Fail;
            public List<int> Outputs = new List<int>(); // indices into pattern list
        }

        private Node _root = new Node();
        private List<string> _patterns = new List<string>();
        private bool _built = false;

        public int AddPattern(string pattern)
        {
            int id = _patterns.Count;
            _patterns.Add(pattern);
            var bytes = Encoding.ASCII.GetBytes(pattern.ToLowerInvariant());
            var node = _root;
            foreach (var b in bytes)
            {
                if (!node.Children.TryGetValue(b, out var next))
                {
                    next = new Node();
                    node.Children[b] = next;
                }
                node = next;
            }
            node.Outputs.Add(id);
            _built = false;
            return id;
        }

        public void Build()
        {
            var queue = new Queue<Node>();
            foreach (var kv in _root.Children)
            {
                kv.Value.Fail = _root;
                queue.Enqueue(kv.Value);
            }
            while (queue.Count > 0)
            {
                var cur = queue.Dequeue();
                foreach (var kv in cur.Children)
                {
                    byte c = kv.Key;
                    var child = kv.Value;
                    var f = cur.Fail;
                    while (f != null && !f.Children.ContainsKey(c)) f = f.Fail;
                    child.Fail = (f == null) ? _root : f.Children[c];
                    if (child.Fail.Outputs.Count > 0) child.Outputs.AddRange(child.Fail.Outputs);
                    queue.Enqueue(child);
                }
            }
            _built = true;
        }

        // Returns set of matched pattern indices found anywhere in buffer.
        public HashSet<int> Search(byte[] buffer, int length)
        {
            if (!_built) Build();
            var found = new HashSet<int>();
            var node = _root;
            for (int i = 0; i < length; i++)
            {
                byte c = buffer[i];
                if (c >= 65 && c <= 90) c = (byte)(c + 32); // lowercase ASCII
                while (node != _root && !node.Children.ContainsKey(c)) node = node.Fail;
                if (node.Children.TryGetValue(c, out var next)) node = next;
                else node = _root;
                if (node.Outputs.Count > 0)
                    foreach (var id in node.Outputs) found.Add(id);
            }
            return found;
        }

        public string GetPattern(int id) { return _patterns[id]; }
    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp

# ---------------------------------------------------------------------------
# Signature database
# Extend these freely — keys are client/module names, values are substrings
# that, if found in process memory, indicate that client/module.
# (Sample set — wire this up to your existing IOC list / ss-tool-ig repo.)
# ---------------------------------------------------------------------------
$ClientSignatures = @{
    "Vape Client"        = @("vapeclient", "vape.client", "dev/vape")
    "Meteor Client"      = @("meteorclient", "meteordevelopment")
    "LiquidBounce"       = @("liquidbounce", "net/ccbluex/liquidbounce")
    "Wurst"              = @("wurstclient", "net/wurstclient")
    "Sigma Client"       = @("sigmaclient", "sigma.client")
    "Novoware"           = @("novoware")
    "GameSense"          = @("gamesense.")
    "Osiris Client"      = @("osirisclient")
    "Cosmos Client"      = @("cosmosclient")
    "Sorus Client"       = @("sorusclient")
    "Azura Client"       = @("azuraclient")
    "Doomsday Client"    = @("doomsdayclient")
    "Argon Client"       = @("argonclient")
    "Krypton Client"     = @("kryptonclient")
    "Prestige Client"    = @("prestigeclient")
    "198Macros"          = @("198macros", "macros198")
    "ZenithMacros"       = @("zenithmacros", "zenith.macros")
    "Delta Client"       = @("deltaclient")
    "Elysian Client"     = @("elysianclient")
    "Onyx Client"        = @("onyxclient")
    "Lumina Client"      = @("luminaclient")
    "Momentum Client"    = @("momentumclient")
    "Raven B++"          = @("ravenb++", "ravenclient")
    "UZI Client"         = @("uziclient")
    "SkidBounce"         = @("skidbounce")
    "Skidcraft"          = @("skidcraft")
}

$GenericFlags = @{
    # Combat
    "Kill Aura"          = @("killaura")
    "Crystal Aura"       = @("crystalaura")
    "Silent Aim"         = @("silentaim")
    "TriggerBot"         = @("triggerbot")
    "Static HitBoxes"    = @("statichitbox")
    # Crystal / Anchor PvP
    "Auto Crystal"       = @("autocrystal")
    "Crystal Optimizer"  = @("crystaloptimizer")
    "Double Anchor"      = @("doubleanchor")
    "Anchor Exploder"    = @("anchorexploder")
    # Totem
    "Auto Totem"         = @("autototem")
    "Hover Totem"        = @("hovertotem")
    # Movement
    "Fast Bridge"        = @("fastbridge")
    "No Break Delay"     = @("nobreakdelay")
    "Elytra Swap"        = @("elytraswap")
    # Utility / automation
    "Auto Clicker"       = @("autoclicker")
    "Chest Stealer"      = @("cheststealer")
    "Shulker Dropper"    = @("shulkerdropper")
    # ESP / Vision
    "Player ESP"         = @("playeresp")
    "X-Ray"              = @("xray.")
    # Evasion / anti-forensic
    "Anti SS Tool"       = @("antisstool", "anti-ss")
    "String Cleaner"     = @("stringcleaner")
    "Self Destruct"      = @("selfdestruct")
    "USN Journal Cleaner"= @("usnjournalcleaner", "deleteusnjournal")
}

# Domains known to be used by cheat clients for auth/update check-ins.
# (Sample placeholders — populate from your own IOC tracking.)
$KnownDomains = @{
    "Vape Client"   = @("vapeclient.dev")
    "Sigma Client"  = @("sigmaclient.org")
    "ZenithMacros"  = @("zenithmacros.net")
}

# ---------------------------------------------------------------------------
# Build a single Aho-Corasick engine across BOTH client + generic patterns,
# keeping a lookup back to (category, label) for each pattern id.
# ---------------------------------------------------------------------------
$ac = New-Object JavawScan.AhoCorasick
$patternMap = @{}  # id -> @{Category=...; Label=...; Pattern=...}

foreach ($client in $ClientSignatures.Keys) {
    foreach ($pat in $ClientSignatures[$client]) {
        $id = $ac.AddPattern($pat)
        $patternMap[$id] = @{ Category = "Client"; Label = $client; Pattern = $pat }
    }
}
foreach ($flag in $GenericFlags.Keys) {
    foreach ($pat in $GenericFlags[$flag]) {
        $id = $ac.AddPattern($pat)
        $patternMap[$id] = @{ Category = "Generic"; Label = $flag; Pattern = $pat }
    }
}
$ac.Build()

# ---------------------------------------------------------------------------
# Phase 1 — Process discovery
# ---------------------------------------------------------------------------
Write-Host "[Phase 1] Enumerating java/javaw processes..." -ForegroundColor Cyan
$targets = Get-Process -Name "java", "javaw" -ErrorAction SilentlyContinue

if (-not $targets) {
    Write-Host "No java.exe / javaw.exe processes found." -ForegroundColor Yellow
}

$results = [System.Collections.Generic.List[object]]::new()
$clientHits  = [System.Collections.Generic.HashSet[string]]::new()
$genericHits = [System.Collections.Generic.HashSet[string]]::new()

foreach ($proc in $targets) {
    Write-Host "  -> PID $($proc.Id) | Start: $($proc.StartTime) | Uptime: $((Get-Date) - $proc.StartTime)"

    $hProcess = [JavawScan.Native]::OpenProcess(
        [JavawScan.Native]::PROCESS_VM_READ -bor [JavawScan.Native]::PROCESS_QUERY_INFORMATION,
        $false, $proc.Id)

    if ($hProcess -eq [IntPtr]::Zero) {
        Write-Warning "    Could not open PID $($proc.Id) (insufficient privileges?)"
        continue
    }

    # ---------------------------------------------------------------------
    # Phase 2 — Memory mapping
    # ---------------------------------------------------------------------
    Write-Host "  [Phase 2] Walking memory regions for PID $($proc.Id)..." -ForegroundColor DarkCyan
    $address = [IntPtr]::Zero
    $regionCount = 0
    $scannedBytes = 0L
    $maxBytes = $MaxRegionMB * 1MB

    while ($true) {
        $mbi = New-Object JavawScan.MEMORY_BASIC_INFORMATION
        $mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)
        $ret = [JavawScan.Native]::VirtualQueryEx($hProcess, $address, [ref]$mbi, $mbiSize)
        if ($ret -eq 0) { break }

        $regionSize = [int64]$mbi.RegionSize
        $isCommitted = ($mbi.State -eq [JavawScan.Native]::MEM_COMMIT)
        $isGuarded   = (($mbi.Protect -band [JavawScan.Native]::PAGE_GUARD) -ne 0)
        $isNoAccess  = ($mbi.Protect -eq [JavawScan.Native]::PAGE_NOACCESS)
        $tooBig      = ($regionSize -gt $maxBytes)

        if ($isCommitted -and -not $isGuarded -and -not $isNoAccess -and -not $tooBig -and $regionSize -gt 0) {
            $buffer = New-Object byte[] $regionSize
            $bytesRead = [IntPtr]::Zero
            $okRead = [JavawScan.Native]::ReadProcessMemory($hProcess, $mbi.BaseAddress, $buffer, $regionSize, [ref]$bytesRead)

            if ($okRead -and $bytesRead.ToInt64() -gt 0) {
                $regionCount++
                $scannedBytes += $bytesRead.ToInt64()

                # -------------------------------------------------------
                # Phase 3 — Pattern matching (Aho-Corasick, single pass)
                # -------------------------------------------------------
                $matches = $ac.Search($buffer, [int]$bytesRead)
                foreach ($id in $matches) {
                    $info = $patternMap[$id]
                    if ($info.Category -eq "Client") {
                        if ($clientHits.Add($info.Label)) {
                            Write-Host "    [CLIENT MATCH] $($info.Label) (pattern: $($info.Pattern))" -ForegroundColor Red
                        }
                    } else {
                        if ($genericHits.Add($info.Label)) {
                            Write-Host "    [GENERIC MATCH] $($info.Label) (pattern: $($info.Pattern))" -ForegroundColor Yellow
                        }
                    }
                }
            }
        }

        # advance to next region
        $next = [int64]$mbi.BaseAddress + $regionSize
        if ($next -le [int64]$address) { break } # safety against infinite loop
        $address = [IntPtr]$next
    }

    Write-Host "    Regions scanned: $regionCount | Bytes scanned: $([math]::Round($scannedBytes/1MB,1)) MB"
    [JavawScan.Native]::CloseHandle($hProcess) | Out-Null

    $results.Add([pscustomobject]@{
        Pid           = $proc.Id
        StartTime     = $proc.StartTime
        RegionsScanned= $regionCount
        BytesScanned  = $scannedBytes
    })
}

# ---------------------------------------------------------------------------
# Phase 4 — DNS cache scan
# ---------------------------------------------------------------------------
Write-Host "`n[Phase 4] Scanning DNS cache..." -ForegroundColor Cyan
$dnsHits = [System.Collections.Generic.List[object]]::new()
try {
    $dnsRaw = ipconfig /displaydns 2>$null
    $cachedNames = $dnsRaw | Select-String -Pattern "Record Name" | ForEach-Object {
        ($_ -split ":\s*", 2)[1].Trim().ToLowerInvariant()
    } | Select-Object -Unique

    foreach ($client in $KnownDomains.Keys) {
        foreach ($domain in $KnownDomains[$client]) {
            $hit = $cachedNames | Where-Object { $_ -like "*$domain*" }
            if ($hit) {
                $clientHits.Add($client) | Out-Null
                $dnsHits.Add([pscustomobject]@{ Client = $client; Domain = $domain; CachedName = $hit })
                Write-Host "  [DNS MATCH] $client -> $hit" -ForegroundColor Red
            }
        }
    }
    if ($dnsHits.Count -eq 0) { Write-Host "  No known cheat-client domains found in DNS cache." }
} catch {
    Write-Warning "  DNS cache scan failed: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Phase 5 — Verdict classification
# ---------------------------------------------------------------------------
$verdict = "CLEAN"
if ($clientHits.Count -gt 0) {
    $verdict = "CONFIRMED"
} elseif ($genericHits.Count -gt 0) {
    $verdict = "SUSPICIOUS"
}

$verdictColor = switch ($verdict) {
    "CONFIRMED"   { "Red" }
    "SUSPICIOUS"  { "Yellow" }
    default       { "Green" }
}

Write-Host "`n=== VERDICT: $verdict ===" -ForegroundColor $verdictColor

$reportObj = [pscustomobject]@{
    Tool          = "Javaw Scanner (PS1)"
    Timestamp     = (Get-Date).ToString("o")
    Host          = $env:COMPUTERNAME
    Verdict       = $verdict
    ClientFlags   = @($clientHits)
    GenericFlags  = @($genericHits)
    DnsHits       = $dnsHits
    Processes     = $results
}

$json = $reportObj | ConvertTo-Json -Depth 6
$json | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "`nReport written to $OutFile"

if ($PostUrl) {
    try {
        Write-Host "Posting result to $PostUrl ..."
        Invoke-RestMethod -Uri $PostUrl -Method Post -Body $json -ContentType "application/json" | Out-Null
        Write-Host "Posted OK." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to POST to dashboard API: $($_.Exception.Message)"
    }
}
