# Canonical Windows-share generator seed lineage:
#   ejm2bj4s.foxclaw-test -> foxclaw-seed.default
param(
  [int]$Count = 10,
  [string]$ProfilesRoot = "$env:APPDATA\Mozilla\Firefox\Profiles",
  [string]$SeedName = "foxclaw-seed.default",
  [ValidateSet(
    "mixed",
    "balanced",
    "adware_like",
    "credential_reuse",
    "privacy_weak",
    "dev_power_user",
    "cve_sandbox_escape",
    "cve_extension_abuse",
    "cve_session_hijack",
    "cve_cert_injection",
    "cve_handler_hijack",
    "cve_hsts_downgrade",
    "cve_search_hijack"
  )]
  [string]$Scenario = "mixed",
  [int]$Seed = 424242,
  [switch]$Overwrite,
  [switch]$FailFast,
  [string]$SummaryOut = "",
  [string]$LogPath = "",
  [switch]$Resume,
  [int]$StartIndex = 1,
  [int]$EndIndex = 0,
  [int]$Workers = 0,
  [switch]$Fast
)

# ── Preflight checks ─────────────────────────────────────────────────
if ($PSVersionTable.PSVersion.Major -lt 5) {
  throw "PowerShell 5.1 or later is required. Current version: $($PSVersionTable.PSVersion)"
}

$isPSCore = $PSVersionTable.PSVersion.Major -ge 7
if ($Workers -gt 1 -and -not $isPSCore) {
  Write-Host "WARNING: Parallel execution requires PowerShell 7+. Falling back to sequential."
  $Workers = 1
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js is not installed or not in PATH."
}

$nodeVersion = "unknown"
try { $nodeVersion = (node -v 2>$null).Trim() } catch { }
$nodeMajor = 0
if ($nodeVersion -match '^v?(\d+)') { $nodeMajor = [int]$Matches[1] }
if ($nodeMajor -lt 16) {
  throw "Node.js >= 16 is required. Detected: $nodeVersion"
}

try {
  node -e "require('better-sqlite3')" 2>$null
}
catch {
  throw "better-sqlite3 is not installed. Run 'npm install' in the foxclaw-gen directory first."
}
if ($LASTEXITCODE -ne 0) {
  throw "better-sqlite3 is not installed. Run 'npm install' in the foxclaw-gen directory first."
}

$SeedDir = Join-Path $ProfilesRoot $SeedName
if (!(Test-Path $SeedDir)) { throw "Seed profile not found: $SeedDir" }

foreach ($lockName in @("parent.lock", ".parentlock", "lock")) {
  if (Test-Path (Join-Path $SeedDir $lockName)) {
    throw "Seed profile is locked ($lockName). Close Firefox before generating."
  }
}

# ── Seed profile completeness validation ─────────────────────────────
$requiredSeedFiles = @("places.sqlite", "cookies.sqlite", "key4.db", "cert9.db", "prefs.js")
$missingSeedFiles = @()
foreach ($seedFile in $requiredSeedFiles) {
  $seedFilePath = Join-Path $SeedDir $seedFile
  if (!(Test-Path $seedFilePath)) { $missingSeedFiles += $seedFile }
}
if ($missingSeedFiles.Count -gt 0) {
  $missing = $missingSeedFiles -join ", "
  throw "Seed profile is incomplete — missing: $missing. Launch Firefox ESR with this profile at least once to initialize it."
}
Write-Host "[OK] Seed profile validated: $($requiredSeedFiles.Count) critical files present."

$Mutator = Join-Path $PSScriptRoot "mutate_profile.mjs"
if (!(Test-Path $Mutator)) { throw "Mutator script not found: $Mutator" }

if (!(Test-Path $ProfilesRoot)) {
  throw "Profiles root does not exist: $ProfilesRoot"
}
try {
  $testFile = Join-Path $ProfilesRoot ".foxclaw-write-test"
  [IO.File]::WriteAllText($testFile, "test")
  Remove-Item $testFile -Force -ErrorAction SilentlyContinue
}
catch {
  throw "Profiles root is not writable: $ProfilesRoot"
}

$freeGB = [math]::Round((Get-PSDrive -Name (Get-Item $ProfilesRoot).PSDrive.Name).Free / 1GB, 2)
if ($freeGB -lt 1) {
  Write-Host "WARNING: Only ${freeGB}GB free. Large runs may fail."
}

# ── Defaults ──────────────────────────────────────────────────────────
if ($EndIndex -le 0) { $EndIndex = $Count }
if ($StartIndex -lt 1) { $StartIndex = 1 }
if ($EndIndex -gt $Count) { $EndIndex = $Count }
if ($Workers -le 0) {
  $cpuCount = [Environment]::ProcessorCount
  $Workers = [math]::Max(1, [math]::Min([math]::Floor($cpuCount / 2), 10))
}

if ([string]::IsNullOrWhiteSpace($SummaryOut)) {
  $SummaryOut = Join-Path $ProfilesRoot "windows-auth-gen-summary.json"
}
if ([string]::IsNullOrWhiteSpace($LogPath)) {
  $LogPath = Join-Path $ProfilesRoot "windows-auth-gen.log"
}

Start-Transcript -Path $LogPath -Append -Force | Out-Null

$totalInRange = $EndIndex - $StartIndex + 1

# ── Build work items ──────────────────────────────────────────────────
$rng = [System.Random]::new($Seed)

function Get-ScenarioName {
  param([string]$ScenarioMode, [System.Random]$Random)
  if ($ScenarioMode -ne "mixed") { return $ScenarioMode }
  $roll = $Random.NextDouble()
  if ($roll -lt 0.30) { return "balanced" }
  if ($roll -lt 0.55) { return "credential_reuse" }
  if ($roll -lt 0.75) { return "privacy_weak" }
  if ($roll -lt 0.90) { return "adware_like" }
  return "dev_power_user"
}

$workItems = @()
for ($i = $StartIndex; $i -le $EndIndex; $i++) {
  $name = ("foxclaw-gen-{0:D3}.default" -f $i)
  $dest = Join-Path $ProfilesRoot $name
  $profileSeed = $Seed + $i
  $scenarioName = Get-ScenarioName -ScenarioMode $Scenario -Random $rng
  $workItems += [pscustomobject]@{
    Index        = $i
    Name         = $name
    Dest         = $dest
    ProfileSeed  = $profileSeed
    ScenarioName = $scenarioName
  }
}

# ── Phase 1: Parallel seed cloning ────────────────────────────────────
Write-Host ""
Write-Host "=== FoxClaw Profile Generator ==="
Write-Host "  Range: $StartIndex..$EndIndex ($totalInRange profiles)"
Write-Host "  Workers: $Workers  Scenario: $Scenario  Seed: $Seed"
Write-Host "  Node: $nodeVersion  Profiles: $ProfilesRoot"
Write-Host "  Resume: $Resume  Overwrite: $Overwrite  FailFast: $FailFast"
Write-Host ""
Write-Host "--- Phase 1: Cloning seed to $totalInRange profiles ---"

$cloneStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$cloneSkipped = 0
$cloneResumed = 0
$cloneFailed = 0

# Items that need mutation after cloning.
$mutateItems = [System.Collections.ArrayList]::new()

foreach ($work in $workItems) {
  $dest = $work.Dest
  $name = $work.Name

  # Resume check.
  if ($Resume) {
    $existingManifest = Join-Path $dest "foxclaw-sim-metadata.json"
    if (Test-Path $existingManifest) {
      try {
        $mc = Get-Content $existingManifest -Raw | ConvertFrom-Json
        if ($mc.status -eq "ok") {
          $cloneResumed++
          continue
        }
      }
      catch { }
    }
  }

  # Handle existing directory.
  if (Test-Path $dest) {
    if ($Overwrite) {
      if ($name -notmatch '^foxclaw-gen-\d{3}\.default$') {
        $cloneSkipped++
        continue
      }
      $isLocked = $false
      foreach ($lockName in @("parent.lock", ".parentlock", "lock")) {
        if (Test-Path (Join-Path $dest $lockName)) { $isLocked = $true; break }
      }
      if ($isLocked) {
        $cloneSkipped++
        continue
      }
      Remove-Item -Recurse -Force -Path $dest
    }
    else {
      $cloneSkipped++
      continue
    }
  }

  # Clone seed.
  New-Item -ItemType Directory -Path $dest -Force | Out-Null
  robocopy "$SeedDir" "$dest" /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
  $robocopyExit = $LASTEXITCODE
  if ($robocopyExit -ge 8) {
    Write-Host "ERROR: Robocopy failed for $name (exit=$robocopyExit)"
    $cloneFailed++
    if ($FailFast) { throw "Robocopy failed for $name" }
    continue
  }

  # Remove lock files from cloned profile.
  foreach ($lockName in @("parent.lock", ".parentlock", "lock")) {
    $lock = Join-Path $dest $lockName
    if (Test-Path $lock) { Remove-Item $lock -Force -ErrorAction SilentlyContinue }
  }

  # Remove session restore files — these cause Playwright to try restoring
  # the seed's open tabs, triggering "Unexpected number of tabs" errors
  # when multiple workers launch in parallel.
  foreach ($sessionFile in @(
      "sessionstore.jsonlz4",
      "sessionstore.js",
      "sessionstore.bak",
      "sessionstore-backups"
    )) {
    $sf = Join-Path $dest $sessionFile
    if (Test-Path $sf) { Remove-Item $sf -Recurse -Force -ErrorAction SilentlyContinue }
  }

  # Remove startup cache and shader cache to avoid stale state conflicts.
  foreach ($cacheDir in @("startupCache", "shader-cache", "cache2")) {
    $cd = Join-Path $dest $cacheDir
    if (Test-Path $cd) { Remove-Item $cd -Recurse -Force -ErrorAction SilentlyContinue }
  }

  [void]$mutateItems.Add($work)
}

$cloneStopwatch.Stop()
Write-Host "  Cloned: $($mutateItems.Count)  Skipped: $cloneSkipped  Resumed: $cloneResumed  Failed: $cloneFailed  ($(([math]::Round($cloneStopwatch.Elapsed.TotalSeconds, 1)))s)"

# ── Phase 2: Parallel mutation ────────────────────────────────────────
Write-Host ""
Write-Host "--- Phase 2: Mutating $($mutateItems.Count) profiles ($Workers workers) ---"

$mutateStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$extCachePath = ""
if ($Fast) {
  $extCachePath = Join-Path $env:TEMP "foxclaw-ext-cache-$([Guid]::NewGuid().ToString().Substring(0,8))"
  Write-Host "  Building extension cache at $extCachePath..."
  New-Item -ItemType Directory -Path $extCachePath -Force | Out-Null
  node $Mutator $extCachePath --build-cache | Out-Null
}

# Thread-safe result collection.
$results = [System.Collections.Concurrent.ConcurrentBag[pscustomobject]]::new()

if ($isPSCore -and $Workers -gt 1 -and $mutateItems.Count -gt 1) {
  # ── Parallel execution (PowerShell 7+) ─────────────────────────
  $mutateItems | ForEach-Object -ThrottleLimit $Workers -Parallel {
    $work = $_
    $mutatorPath = $using:Mutator
    
    $dest = $work.Dest
    $name = $work.Name
    $manifestOut = Join-Path $dest "foxclaw-sim-metadata.json"
    $mutatorLogPath = Join-Path $dest "foxclaw-mutate.log"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $args = @("$mutatorPath", "$dest", "--scenario", $work.ScenarioName, "--seed", $work.ProfileSeed, "--profile-name", $name, "--manifest-out", "$manifestOut")
    $jsonlPath = Join-Path $dest "foxclaw-mutate.jsonl"
    $args += "--jsonl-log"
    $args += "$jsonlPath"

    if ($using:Fast) {
      $args += "--fast"
      $args += "--extensions-cache"
      $args += $using:extCachePath
    }

    $output = & node @args 2>&1
    $exitCode = $LASTEXITCODE
    $sw.Stop()

    # Write per-profile log.
    $output | Out-File -FilePath $mutatorLogPath -Encoding utf8 -Force

    $status = "created"
    $msg = "ok"
    if ($exitCode -ne 0) {
      $status = "mutate_failed"
      $msg = "exit=$exitCode"
    }
    elseif (!(Test-Path $manifestOut)) {
      $status = "missing_manifest"
      $msg = "no manifest"
    }

    ($using:results).Add([pscustomobject]@{
        profile         = $name
        path            = $dest
        scenario        = $work.ScenarioName
        seed            = $work.ProfileSeed
        status          = $status
        exit_code       = $exitCode
        elapsed_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        mutator_log     = $mutatorLogPath
        message         = $msg
      })

    $posLabel = "W$([System.Threading.Thread]::CurrentThread.ManagedThreadId)"
    Write-Host "  [$posLabel] $status $name ($(([math]::Round($sw.Elapsed.TotalSeconds, 1)))s) scenario=$($work.ScenarioName)"
  }
}
else {
  # ── Sequential fallback ────────────────────────────────────────
  $completedCount = 0
  $elapsedTimes = @()

  foreach ($work in $mutateItems) {
    $completedCount++
    $dest = $work.Dest
    $name = $work.Name
    $manifestOut = Join-Path $dest "foxclaw-sim-metadata.json"
    $mutatorLogPath = Join-Path $dest "foxclaw-mutate.log"

    Write-Host "  [$completedCount/$($mutateItems.Count)] Mutating: $name (scenario=$($work.ScenarioName))"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $nodeArgs = @("$Mutator", "$dest", "--scenario", $work.ScenarioName, "--seed", $work.ProfileSeed, "--profile-name", $name, "--manifest-out", "$manifestOut")
    $jsonlPath = Join-Path $dest "foxclaw-mutate.jsonl"
    $nodeArgs += "--jsonl-log"
    $nodeArgs += "$jsonlPath"

    if ($Fast) {
      $nodeArgs += "--fast"
      $nodeArgs += "--extensions-cache"
      $nodeArgs += $extCachePath
    }

    node @nodeArgs 2>&1 | Tee-Object -FilePath $mutatorLogPath
    $exitCode = $LASTEXITCODE
    $sw.Stop()
    $elapsedSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $elapsedTimes += $elapsedSec

    $status = "created"
    $msg = "ok"
    if ($exitCode -ne 0) {
      $status = "mutate_failed"
      $msg = "exit=$exitCode"
      if ($FailFast) { throw "Mutator failed for $name" }
    }
    elseif (!(Test-Path $manifestOut)) {
      $status = "missing_manifest"
      $msg = "no manifest"
      if ($FailFast) { throw "Missing manifest for $name" }
    }

    $results.Add([pscustomobject]@{
        profile         = $name
        path            = $dest
        scenario        = $work.ScenarioName
        seed            = $work.ProfileSeed
        status          = $status
        exit_code       = $exitCode
        elapsed_seconds = $elapsedSec
        mutator_log     = $mutatorLogPath
        message         = $msg
      })

    # ETA.
    $avgSec = ($elapsedTimes | Measure-Object -Average).Average
    $remaining = $mutateItems.Count - $completedCount
    $etaSec = [math]::Round($avgSec * $remaining)
    $etaSpan = [TimeSpan]::FromSeconds($etaSec)
    Write-Host "  [$completedCount/$($mutateItems.Count)] $status $name (${elapsedSec}s) ETA=$($etaSpan.ToString('hh\:mm\:ss'))"
  }
}

$mutateStopwatch.Stop()

# ── Build summary ─────────────────────────────────────────────────────
$allResults = $results.ToArray()
$created = ($allResults | Where-Object { $_.status -eq "created" }).Count
$failed = ($allResults | Where-Object { $_.status -ne "created" }).Count

$summary = [ordered]@{
  schema_version             = "1.0.0"
  generated_at_utc           = (Get-Date).ToUniversalTime().ToString("o")
  completed_at_utc           = (Get-Date).ToUniversalTime().ToString("o")
  profiles_root              = $ProfilesRoot
  seed_profile               = $SeedName
  seed_profile_previous_name = "ejm2bj4s.foxclaw-test"
  requested_count            = $Count
  effective_range            = "${StartIndex}..${EndIndex}"
  scenario_mode              = $Scenario
  seed                       = $Seed
  node_version               = $nodeVersion
  mutator_path               = $Mutator
  fast                       = [bool]$Fast
  overwrite                  = [bool]$Overwrite
  fail_fast                  = [bool]$FailFast
  resume                     = [bool]$Resume
  workers                    = $Workers
  attempted                  = $totalInRange
  cloned                     = $mutateItems.Count
  created                    = $created
  skipped_existing           = $cloneSkipped
  skipped_complete           = $cloneResumed
  clone_failed               = $cloneFailed
  mutate_failed              = $failed
  failures                   = $cloneFailed + $failed
  clone_seconds              = [math]::Round($cloneStopwatch.Elapsed.TotalSeconds, 1)
  mutate_seconds             = [math]::Round($mutateStopwatch.Elapsed.TotalSeconds, 1)
  total_elapsed_seconds      = [math]::Round($cloneStopwatch.Elapsed.TotalSeconds + $mutateStopwatch.Elapsed.TotalSeconds, 1)
  profiles                   = $allResults | Sort-Object profile
}

$summary | ConvertTo-Json -Depth 8 | Out-File -FilePath $SummaryOut -Encoding utf8 -Force

Stop-Transcript | Out-Null

Write-Host ""
Write-Host "=== Complete ==="
Write-Host "  Summary:  $SummaryOut"
Write-Host "  Log:      $LogPath"
Write-Host "  Created:  $created / $totalInRange"
Write-Host "  Skipped:  $cloneSkipped existing, $cloneResumed resumed"
Write-Host "  Failures: $($cloneFailed + $failed)"
Write-Host "  Clone:    $($summary.clone_seconds)s  Mutate: $($summary.mutate_seconds)s  Total: $($summary.total_elapsed_seconds)s"
if ($Fast) { Write-Host "  Fast:     ON (Cache: $extCachePath)" }
if ($Workers -gt 1) {
  Write-Host "  Workers:  $Workers parallel"
}
Write-Host ""

if ($summary.failures -gt 0) {
  exit 1
}
