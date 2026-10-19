# Test-only WUA objects. The production worker has no provider override switch.
function New-Object {
  param([Parameter(Position=0)][string]$TypeName, [Parameter(Position=1)][object[]]$ArgumentList, [string]$ComObject)
  if (-not $ComObject) { return Microsoft.PowerShell.Utility\New-Object @PSBoundParameters }
  switch ($ComObject) {
    'Microsoft.Update.ServiceManager' { return Microsoft.PowerShell.Utility\New-Object -ComObject $ComObject }
    'Microsoft.Update.SystemInfo' { return [pscustomobject]@{RebootRequired=($script:Mode -eq 'pre_reboot')} }
    'Microsoft.Update.UpdateColl' {
      $c=[pscustomobject]@{Count=0}
      $c | Add-Member ScriptMethod Add {param($u);$this.Count++;return 0};return $c
    }
    'Microsoft.Update.Session' {
      $s=[pscustomobject]@{ClientApplicationID=''}
      $s | Add-Member ScriptMethod CreateUpdateSearcher {
        $search=[pscustomobject]@{ServerSelection=-1;CanAutomaticallyUpgradeService=$true;Online=$true}
        $search | Add-Member ScriptMethod Search {
          param($criteria)
          if($this.ServerSelection -ne 0 -or $this.CanAutomaticallyUpgradeService){throw 'source overridden'}
          $u=[pscustomobject]@{Identity=[pscustomobject]@{UpdateID='12345678-1234-1234-1234-123456789abc';RevisionNumber=7};Title='Native worker 安全更新';KBArticleIDs=@('1234567');MaxDownloadSize=1024;EulaText='Native fixture license';EulaAccepted=($script:Mode -ne 'eula');Type=1;IsBeta=$false;IsHidden=$false;CanRequireSource=$false;IsDownloaded=$true;InstallationBehavior=[pscustomobject]@{CanRequestUserInput=($script:Mode -eq 'interactive')};Categories=@([pscustomobject]@{CategoryID='0fa1201d-4330-4fa8-8ae9-b877473b6441'})}
          if($script:Mode -eq 'changed'){$u.Identity.RevisionNumber=8}
          $script:Update=$u
          $count=1
          if($criteria -match 'IsInstalled=0' -and $script:Mode -eq 'absent'){$count=0}
          if($criteria -match 'IsInstalled=1' -and $script:Mode -eq 'absent'){$count=0}
          $updates=[pscustomobject]@{Count=$count}
          $updates | Add-Member ScriptMethod Item {param($i);return $script:Update}
          return [pscustomobject]@{ResultCode=2;Warnings=@();Updates=$updates}
        };return $search
      }
      $s | Add-Member ScriptMethod CreateUpdateDownloader {
        $d=[pscustomobject]@{Updates=$null}
        $d | Add-Member ScriptMethod Download {
          $r=[pscustomobject]@{ResultCode=$(if($script:Mode -eq 'download_partial'){3}else{2})}
          $r | Add-Member ScriptMethod GetUpdateResult {param($i);return [pscustomobject]@{ResultCode=2;HResult=0}};return $r
        };return $d
      }
      $s | Add-Member ScriptMethod CreateUpdateInstaller {
        $i=[pscustomobject]@{Updates=$null;AllowSourcePrompts=$true;ForceQuiet=$false;IsForced=$true;IsBusy=$false;RebootRequiredBeforeInstallation=$false}
        $i | Add-Member ScriptMethod Install {
          if($this.AllowSourcePrompts -or -not $this.ForceQuiet -or $this.IsForced -or $this.Updates.Count -ne 1){throw 'unsafe installation'}
          $r=[pscustomobject]@{ResultCode=$(if($script:Mode -eq 'install_partial'){3}else{2});RebootRequired=($script:Mode -eq 'install_reboot')}
          $r | Add-Member ScriptMethod GetUpdateResult {param($i);return [pscustomobject]@{ResultCode=2;HResult=0;RebootRequired=($script:Mode -eq 'install_reboot')}};return $r
        };return $i
      };return $s
    }
    default {throw 'unexpected COM interface'}
  }
}
