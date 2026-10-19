$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
function Hash([string]$value) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}
function HostIdentity {
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $machine = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
  $parts = @($machine, $cv.CurrentBuildNumber, $cv.EditionID, $cv.InstallationType, [Environment]::Is64BitOperatingSystem)
  # Pin update source policy as well as installation identity. UBR intentionally
  # changes during servicing and is not part of this stable installation identity.
  foreach ($path in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU')) {
    if (Test-Path $path) {
      $key = Get-Item $path
      foreach ($name in @($key.GetValueNames() | Sort-Object)) { $parts += $path + ':' + $name + '=' + [string]$key.GetValue($name) }
    }
  }
  $services = (New-Object -ComObject 'Microsoft.Update.ServiceManager').Services
  $defaults = @()
  for ($i = 0; $i -lt $services.Count; $i++) {
    $service = $services.Item($i)
    if ($service.IsDefaultAUService) { $defaults += ([string]$service.ServiceID + ':' + [string]$service.IsManaged) }
  }
  $parts += @($defaults | Sort-Object)
  return Hash ($parts -join "`n")
}
function Deadline {
  if ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge [long]$request.deadline) { throw 'deadline_expired' }
}
function Metadata($u) {
  $reason = ''
  $kb = @($u.KBArticleIDs | ForEach-Object { [string]$_ } | Sort-Object -Unique)
  $classes = @($u.Categories | ForEach-Object { ([string]$_.CategoryID).ToLowerInvariant() })
  if ($u.Type -ne 1 -or $u.IsBeta -or $u.IsHidden -or $kb.Count -eq 0) { $reason = 'unsupported_update' }
  elseif ($classes -notcontains '0fa1201d-4330-4fa8-8ae9-b877473b6441' -and $classes -notcontains 'e6cf1350-c01b-414d-a61f-263d14d133b4') { $reason = 'not_security_or_critical' }
  elseif (-not $u.EulaAccepted) { $reason = 'eula_not_accepted' }
  elseif ($u.InstallationBehavior.CanRequestUserInput -or $u.CanRequireSource) { $reason = 'interactive_or_source_required' }
  elseif ([long]$u.MaxDownloadSize -gt 4294967296 -or [long]$u.MaxDownloadSize -lt 0) { $reason = 'download_size_limit' }
  $title = [string]$u.Title
  if ($title.Length -gt 512) { $title = $title.Substring(0, 512) }
  return @{ update_id = ([string]$u.Identity.UpdateID).ToLowerInvariant(); revision = [int]$u.Identity.RevisionNumber; title = $title; kb = $kb; size = [long]$u.MaxDownloadSize; eula_digest = (Hash ([string]$u.EulaText)); eligible = ($reason -eq ''); reason = $reason }
}
function Exact($installed) {
  $id = [string]$request.update.update_id
  $rev = [int]$request.update.revision
  if ($id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $rev -lt 1) { throw 'invalid_identity' }
  $found = $searcher.Search("IsInstalled=$installed and Type='Software' and UpdateID='$id' and RevisionNumber=$rev")
  if ($found.ResultCode -ne 2 -or $found.Warnings.Count -ne 0) { throw 'incomplete_search' }
  if ($found.Updates.Count -eq 0) { return $null }
  if ($found.Updates.Count -ne 1) { throw 'ambiguous_update' }
  $u = $found.Updates.Item(0)
  if (([string]$u.Identity.UpdateID).ToLowerInvariant() -cne $id -or [int]$u.Identity.RevisionNumber -ne $rev) { throw 'changed_identity' }
  return $u
}
function AssertTarget($u) {
  $m = Metadata $u
  $p = $request.update
  if (-not $m.eligible -or $m.title -cne [string]$p.title -or $m.size -ne [long]$p.size -or $m.eula_digest -cne [string]$p.eula_digest -or ($m.kb -join ',') -cne (@($p.kb) -join ',')) { throw 'target_changed_or_ineligible' }
}
function Result([string]$phase, [bool]$installed, [bool]$reboot, [int]$code, [long]$hresult) {
  return @{ contract = 1; boot_id = $boot; update_id = [string]$request.update.update_id; revision = [int]$request.update.revision; host_identity = $identity; phase = $phase; installed = $installed; reboot_required = $reboot; result_code = $code; hresult = $hresult; error = '' }
}
try {
  Deadline
  $identity = HostIdentity
  $boot = [string](Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks
  if ($request.operation -ne 'scan' -and $request.operation -ne 'probe' -and $identity -cne [string]$request.host_identity) { throw 'host_or_source_changed' }
  $session = New-Object -ComObject 'Microsoft.Update.Session'
  $session.ClientApplicationID = 'AlinkSec approved update'
  $searcher = $session.CreateUpdateSearcher()
  $searcher.ServerSelection = 0
  $searcher.CanAutomaticallyUpgradeService = $false
  $searcher.Online = ($request.operation -ne 'verify' -and $request.operation -ne 'probe')
  $systemInfo = New-Object -ComObject 'Microsoft.Update.SystemInfo'
  if ($request.operation -eq 'probe') {
    # Nonmutating native acceptance probe: instantiate the real interfaces and
    # exercise quiet-mode properties without selecting or installing an update.
    $installer = $session.CreateUpdateInstaller()
    $installer.AllowSourcePrompts = $false
    $installer.ForceQuiet = $true
    $installer.IsForced = $false
    $answer = @{ contract = 1; status = 'complete'; error = ''; host_identity = $identity; reboot_required = [bool]$systemInfo.RebootRequired; updates = @() }
  } elseif ($request.operation -eq 'scan') {
    $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    if ($found.ResultCode -ne 2 -or $found.Warnings.Count -ne 0 -or $found.Updates.Count -gt 256) { throw 'incomplete_or_oversize_scan' }
    $updates = @()
    for ($i = 0; $i -lt $found.Updates.Count; $i++) { $updates += (Metadata $found.Updates.Item($i)) }
    $answer = @{ contract = 1; status = 'complete'; error = ''; host_identity = $identity; reboot_required = [bool]$systemInfo.RebootRequired; updates = $updates }
  } elseif ($request.operation -eq 'verify') {
    $u = Exact 1
    $answer = Result 'verified' ($null -ne $u) ([bool]$systemInfo.RebootRequired) 0 0
  } elseif ($request.operation -eq 'download' -or $request.operation -eq 'install') {
    if ($systemInfo.RebootRequired) { throw 'reboot_required_before_installation' }
    $u = Exact 0
    if ($null -eq $u) {
      # An external installer may have completed exactly this revision already.
      if ($null -eq (Exact 1)) { throw 'not_applicable_or_superseded' }
      $answer = Result $(if ($request.operation -eq 'download') { 'downloaded' } else { 'installed' }) $true $false 2 0
    } else {
      AssertTarget $u
      $collection = New-Object -ComObject 'Microsoft.Update.UpdateColl'
      [void]$collection.Add($u)
      Deadline
      if ($identity -cne (HostIdentity)) { throw 'host_or_source_changed' }
      if ($request.operation -eq 'download') {
        $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($env:SystemRoot))
        if ($drive.AvailableFreeSpace -lt ([long]$u.MaxDownloadSize + 1073741824)) { throw 'insufficient_disk_space' }
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $collection
        $download = $downloader.Download()
        $one = $download.GetUpdateResult(0)
        if ($download.ResultCode -ne 2 -or $one.ResultCode -ne 2 -or $one.HResult -ne 0 -or -not $u.IsDownloaded) { throw 'download_failed' }
        $answer = Result 'downloaded' $false $false 2 0
      } else {
        if (-not $u.IsDownloaded) { throw 'content_not_downloaded' }
        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $collection
        $installer.AllowSourcePrompts = $false
        $installer.ForceQuiet = $true
        $installer.IsForced = $false
        if ($installer.IsBusy -or $installer.RebootRequiredBeforeInstallation) { throw 'installer_busy_or_reboot_required' }
        Deadline
        $installed = $installer.Install()
        $one = $installed.GetUpdateResult(0)
        $code = [int]$one.ResultCode
        if ($installed.ResultCode -ne 2) { $code = [int]$installed.ResultCode }
        $answer = Result 'installed' ($code -eq 2 -and $one.HResult -eq 0) ([bool]$installed.RebootRequired -or [bool]$one.RebootRequired) $code ([long]$one.HResult)
      }
    }
  } else { throw 'unknown_operation' }
  $answer | ConvertTo-Json -Depth 8 -Compress
} catch {
  # Do not return native command output, URLs, license text, or registry values.
  [Console]::Error.WriteLine('Windows Update operation failed')
  exit 1
}
