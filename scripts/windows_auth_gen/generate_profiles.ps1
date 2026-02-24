# Canonical Windows-share generator seed lineage:
#   ejm2bj4s.foxclaw-test -> foxclaw-seed.default
param(
  [int]$Count = 10,
  [string]$ProfilesRoot = "$env:APPDATA\Mozilla\Firefox\Profiles",
  [string]$SeedName = "foxclaw-seed.default",
  [ValidateSet("mixed", "balanced", "adware_like", "credential_reuse", "privacy_weak", "dev_power_user")]
  [string]$Scenario = "mixed",
  [int]$Seed = 424242,
  [switch]$Overwrite,
  [switch]$FailFast,
  [string]$SummaryOut = ""
)

if (Get-Process firefox -ErrorAction SilentlyContinue) { throw "Firefox is running. Close it before generating profiles." }

$SeedDir = Join-Path $ProfilesRoot $SeedName
if (!(Test-Path $SeedDir)) { throw "Seed profile not found: $SeedDir" }
$Mutator = Join-Path $PSScriptRoot "mutate_profile.mjs"
if (!(Test-Path $Mutator)) { throw "Mutator script not found: $Mutator" }

if ([string]::IsNullOrWhiteSpace($SummaryOut)) {
  $SummaryOut = Join-Path $ProfilesRoot "windows-auth-gen-summary.json"
}

$rng = [System.Random]::new($Seed)
$summary = [ordered]@{
  schema_version = "1.0.0"
  generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  profiles_root = $ProfilesRoot
  seed_profile = $SeedName
  seed_profile_previous_name = "ejm2bj4s.foxclaw-test"
  requested_count = $Count
  scenario_mode = $Scenario
  seed = $Seed
  overwrite = [bool]$Overwrite
  fail_fast = [bool]$FailFast
  attempted = 0
  created = 0
  skipped_existing = 0
  failures = 0
  profiles = @()
}

function Get-ScenarioName {
  param(
    [string]$ScenarioMode,
    [System.Random]$Random
  )

  if ($ScenarioMode -ne "mixed") {
    return $ScenarioMode
  }

  $roll = $Random.NextDouble()
  if ($roll -lt 0.30) { return "balanced" }
  if ($roll -lt 0.55) { return "credential_reuse" }
  if ($roll -lt 0.75) { return "privacy_weak" }
  if ($roll -lt 0.90) { return "adware_like" }
  return "dev_power_user"
}

for ($i = 1; $i -le $Count; $i++) {
  $name = ("foxclaw-gen-{0:D3}.default" -f $i)
  $dest = Join-Path $ProfilesRoot $name
  $profileSeed = $Seed + $i
  $scenarioName = Get-ScenarioName -ScenarioMode $Scenario -Random $rng
  $profileMeta = [ordered]@{
    profile = $name
    path = $dest
    scenario = $scenarioName
    seed = $profileSeed
    status = "pending"
    exit_code = $null
    message = ""
  }

  $summary.attempted++

  if (Test-Path $dest) {
    if ($Overwrite) {
      Write-Host "Removing existing profile for overwrite: $dest"
      Remove-Item -Recurse -Force -Path $dest
    }
    else {
      Write-Host "Skipping existing: $dest"
      $summary.skipped_existing++
      $profileMeta.status = "skipped_existing"
      $summary.profiles += [pscustomobject]$profileMeta
      continue
    }
  }

  Write-Host "Cloning seed to: $dest"
  New-Item -ItemType Directory -Path $dest | Out-Null
  robocopy $SeedDir $dest /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
  $robocopyExit = $LASTEXITCODE
  if ($robocopyExit -ge 8) {
    $msg = "Robocopy failed with exit code $robocopyExit for $name"
    Write-Host "ERROR: $msg"
    $summary.failures++
    $profileMeta.status = "copy_failed"
    $profileMeta.exit_code = $robocopyExit
    $profileMeta.message = $msg
    $summary.profiles += [pscustomobject]$profileMeta
    if ($FailFast) { throw $msg }
    continue
  }

  foreach ($lockName in @("parent.lock", ".parentlock", "lock")) {
    $lock = Join-Path $dest $lockName
    if (Test-Path $lock) { Remove-Item $lock -Force -ErrorAction SilentlyContinue }
  }

  $manifestOut = Join-Path $dest "foxclaw-sim-metadata.json"
  Write-Host "Mutating: $name (scenario=$scenarioName seed=$profileSeed)"
  node $Mutator $dest --scenario $scenarioName --seed $profileSeed --profile-name $name --manifest-out $manifestOut
  $mutateExit = $LASTEXITCODE

  if ($mutateExit -ne 0) {
    $msg = "Mutator failed with exit code $mutateExit for $name"
    Write-Host "ERROR: $msg"
    $summary.failures++
    $profileMeta.status = "mutate_failed"
    $profileMeta.exit_code = $mutateExit
    $profileMeta.message = $msg
    $summary.profiles += [pscustomobject]$profileMeta
    if ($FailFast) { throw $msg }
    continue
  }

  $summary.created++
  $profileMeta.status = "created"
  $profileMeta.exit_code = 0
  $profileMeta.message = "ok"
  $summary.profiles += [pscustomobject]$profileMeta
}

$summary.completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
$summary | ConvertTo-Json -Depth 8 | Out-File -FilePath $SummaryOut -Encoding utf8

Write-Host "Summary: $SummaryOut"
if ($summary.failures -gt 0) {
  Write-Host "Done with failures. created=$($summary.created) skipped=$($summary.skipped_existing) failures=$($summary.failures)"
  exit 1
}

Write-Host "Done. created=$($summary.created) skipped=$($summary.skipped_existing) failures=$($summary.failures)"
