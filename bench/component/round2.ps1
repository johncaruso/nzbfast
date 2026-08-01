# PAR2 bench round, Windows rig. Same protocol as round2.sh on the Macs:
#   fresh copy of the corpus -> PRE-WARM (read every byte once) -> time.
# Adds the two columns the previous round left out: classic par2cmdline and
# MultiPar's par2j.
param([string]$Leg = "verify", [int]$Rounds = 3, [string]$Tools = "ours,turboT,turboD,rarpar,classic,par2j",
      [string]$Ours = "")

$B       = "$env:USERPROFILE\parshoot"
# Default kept for older invocations; pass -Ours to race a freshly built
# driver without overwriting a binary another session may be timing.
$OURS    = if ($Ours) { $Ours } else { "$B\bin\ourpar2.exe" }
$TURBO   = "C:\tools\bin\par2.exe"
$RARPAR  = "$env:USERPROFILE\rarshoot\bin\rarpar.exe"
$CLASSIC = "$env:USERPROFILE\p2classic\x64\Release\par2.exe"
$PAR2J   = "C:\Program Files (x86)\MultiPar\par2j64.exe"
$WORK    = "$B\work-round2"

switch ($Leg) {
  "verify" { $src = "site-pristine";    $pris = "site-pristine";    $par2 = "corpus.par2"; $repair = $false }
  "rep101" { $src = "rep101-damaged";   $pris = "site-pristine";    $par2 = "corpus.par2"; $repair = $true }
  "rep3"   { $src = "rep3-damaged";     $pris = "site-pristine";    $par2 = "corpus.par2"; $repair = $true }
  "heavy"  { $src = "heavy-damaged21";  $pris = "heavy-pristine21"; $par2 = "corpus.par2"; $repair = $true }
}

function PreWarm($dir) {
  $buf = New-Object byte[] (4MB)
  foreach ($f in Get-ChildItem "$dir\*") {
    $fs = [System.IO.File]::OpenRead($f.FullName)
    while ($fs.Read($buf, 0, $buf.Length) -gt 0) { }
    $fs.Close()
  }
}

# Every tool runs at High priority. Windows demotes sustained "background"
# work onto E-cores a few seconds in, which took the heavy leg from 16.6 s to
# 58 s for our own binary and from ~250 s to 849 s for par2cmdline - i.e. the
# unmodified numbers measure the scheduler, not the tool. Our daemon opts out
# of that in-product; the others cannot, so the harness lifts all of them
# equally rather than publishing a throttled competitor.
function RunTimed($exe, $argv) {
  $p = Start-Process -FilePath $exe -ArgumentList $argv -WorkingDirectory $WORK `
       -NoNewWindow -PassThru -RedirectStandardOutput "$B\out.txt" -RedirectStandardError "$B\err.txt"
  try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High } catch { }
  $p.WaitForExit()
  return $p.ExitCode
}

function RunOne($tool) {
  Remove-Item -Recurse -Force $WORK -ErrorAction SilentlyContinue
  Copy-Item -Recurse "$B\$src" $WORK
  PreWarm $WORK
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  switch ($tool) {
    # The product default since e206ede6: the driver mirrors the daemon's
    # "fast par mode", so this row is what a user gets today.
    "ours"    { $code = RunTimed $OURS @($WORK) }
    # Explicit-NTT row, for older drivers and for A/B against the fold; on
    # a current driver it matches `ours`.
    "oursntt" { $env:NZBFAST_NTT = "1"; try { $code = RunTimed $OURS @($WORK) } finally { Remove-Item Env:NZBFAST_NTT } }
    # The streaming fold, i.e. fast par mode off: comparison, not shipping.
    "oursfold" { $env:NZBFAST_NTT = "0"; try { $code = RunTimed $OURS @($WORK) } finally { Remove-Item Env:NZBFAST_NTT } }
    "turboT"  { $code = if ($repair) { RunTimed $TURBO @("r","-q","-T16",$par2) } else { RunTimed $TURBO @("v","-q","-T16",$par2) } }
    "turboD"  { $code = if ($repair) { RunTimed $TURBO @("r","-q",$par2) }        else { RunTimed $TURBO @("v","-q",$par2) } }
    "rarpar"  { $code = if ($repair) { RunTimed $RARPAR @("par","repair","-C",$WORK,$WORK) } else { RunTimed $RARPAR @("par","verify",$WORK) } }
    "classic" { $code = if ($repair) { RunTimed $CLASSIC @("r","-q",$par2) }      else { RunTimed $CLASSIC @("v","-q",$par2) } }
    # par2j takes the command letter first and wants the index file by name.
    # It returns 16 after a SUCCESSFUL repair, so the exit code is recorded and
    # the output gate below is what decides whether the run counted.
    "par2j"   { $code = if ($repair) { RunTimed $PAR2J @("r",$par2) }             else { RunTimed $PAR2J @("v",$par2) } }
  }
  $sw.Stop()
  $bad = 0
  if ($repair) {
    foreach ($v in Get-ChildItem "$B\$pris\*.rar") {
      if ((Get-FileHash -Algorithm SHA256 $v.FullName).Hash -ne
          (Get-FileHash -Algorithm SHA256 "$WORK\$($v.Name)").Hash) { $bad++ }
    }
  }
  $flag = if ($bad -eq 0) { "" } else { "  !! MISMATCH $bad" }
  Write-Host ("  {0,-8} {1,8:N3}s  exit={2}{3}" -f $tool, $sw.Elapsed.TotalSeconds, $code, $flag)
}

Write-Host "=== $Leg (warm protocol, $Rounds rounds, $Tools) ==="
$list = $Tools -split ","
for ($i = 1; $i -le $Rounds; $i++) { foreach ($t in $list) { RunOne $t } }
Remove-Item -Recurse -Force $WORK -ErrorAction SilentlyContinue
