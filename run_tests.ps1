<#
  RuleForge test suite (Step 9).

  Run from the ruleforge folder:
      powershell -ExecutionPolicy Bypass -File .\run_tests.ps1

  What it does:
    1. Builds ruleforge.exe from src\*.c with gcc.
    2. Part A - compiler output: runs every tests\*.rf file and compares
       the exit code, normal output and error output with the saved
       expected result in tests\expected\<name>.txt.
    3. Part B - compiled code (Step 8): for every test that compiles,
       turns the generated .ll into an object file with clang, links it
       with tests\test_access.c using gcc, runs it, and checks that the
       compiled checkAccess gives the right answer for every combination.
       Part B is skipped (not failed) if clang is not installed.

  After an intended change to the output, re-record the expected files:
      powershell -ExecutionPolicy Bypass -File .\run_tests.ps1 -Update
#>
param([switch]$Update)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$IsWin    = ($env:OS -eq 'Windows_NT')
$ExeName  = if ($IsWin) { 'ruleforge.exe' } else { 'ruleforge' }
$Exe      = Join-Path $PSScriptRoot $ExeName
$OutDir   = Join-Path $PSScriptRoot 'tests/out'
$ExpDir   = Join-Path $PSScriptRoot 'tests/expected'
New-Item -ItemType Directory -Force -Path $OutDir, $ExpDir | Out-Null

# Run a program, wait for it, and return its exit code and output lines.
function Invoke-Tool([string]$File, [string[]]$Arguments) {
    $outFile = Join-Path $OutDir '_stdout.txt'
    $errFile = Join-Path $OutDir '_stderr.txt'
    $opts = @{
        FilePath               = $File
        NoNewWindow            = $true
        PassThru               = $true
        RedirectStandardOutput = $outFile
        RedirectStandardError  = $errFile
    }
    # Windows PowerShell 5.1 rejects an empty -ArgumentList, so only pass it when needed.
    if ($Arguments -and $Arguments.Count -gt 0) { $opts.ArgumentList = $Arguments }
    $p = Start-Process @opts
    $null = $p.Handle          # makes ExitCode reliable in Windows PowerShell 5.1
    $p.WaitForExit()
    [pscustomobject]@{
        Code = $p.ExitCode
        Out  = @(Read-Lines $outFile)
        Err  = @(Read-Lines $errFile)
    }
}

# Read a text file as lines: backslashes -> '/', no trailing spaces, and
# blank lines removed (they are only spacing, and PowerShell on Linux drops
# them from redirected output while Windows keeps them). Makes Windows and
# Linux output comparable.
function Read-Lines([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @(Get-Content -LiteralPath $Path |
             ForEach-Object { ($_ -replace '\\', '/').TrimEnd() } |
             Where-Object { $_ -ne '' })
}

function Write-Result([bool]$Ok, [string]$Text) {
    if ($Ok) { Write-Host "  PASS  $Text" -ForegroundColor Green }
    else     { Write-Host "  FAIL  $Text" -ForegroundColor Red }
}

# ---------------------------------------------------------------- build
$gcc = (Get-Command gcc -ErrorAction SilentlyContinue)
if ($null -eq $gcc) { Write-Host 'gcc not found on PATH' -ForegroundColor Red; exit 1 }

Write-Host 'Building ruleforge with gcc...'
$sources = @(Get-ChildItem -Path src -Filter *.c | Sort-Object Name | ForEach-Object { 'src/' + $_.Name })
if (Test-Path -LiteralPath $Exe) { Remove-Item -LiteralPath $Exe }
$build = Invoke-Tool $gcc.Source (@('-std=c11', '-Wall', '-o', $ExeName) + $sources)
if ($build.Code -ne 0 -or -not (Test-Path -LiteralPath $Exe)) {
    Write-Host 'Build FAILED:' -ForegroundColor Red
    $build.Err | ForEach-Object { Write-Host "  $_" }
    exit 1
}
Write-Host "Build OK ($($sources.Count) source files)`n"

# ---------------------------------------------------------------- Part A
$tests = @(Get-ChildItem -Path tests -Filter *.rf | Sort-Object Name)
Write-Host "Part A - compiler output ($($tests.Count) test files)"

$passA = 0
$compiled = @()
foreach ($t in $tests) {
    $name = $t.BaseName
    $ll = "tests/out/$name.ll"
    $h  = "tests/out/$name.h"
    $r = Invoke-Tool $Exe @('--tokens', "tests/$name.rf", '-o', $ll, '--header', $h)

    $actual = @("exit code: $($r.Code)", '--- stdout ---') + $r.Out + @('--- stderr ---') + $r.Err
    $actualFile = Join-Path $OutDir "$name.actual.txt"
    $expFile    = Join-Path $ExpDir "$name.txt"
    [System.IO.File]::WriteAllText($actualFile, (($actual -join "`n") + "`n"))

    if ($r.Code -eq 0) { $compiled += $name }

    if ($Update) {
        [System.IO.File]::WriteAllText($expFile, (($actual -join "`n") + "`n"))
        Write-Host "  SAVED $name" -ForegroundColor Yellow
        $passA++
        continue
    }

    if (-not (Test-Path -LiteralPath $expFile)) {
        Write-Result $false "$name  (no expected file - run with -Update first)"
        continue
    }
    $expected = @(Read-Lines $expFile)

    $firstDiff = -1
    $max = [Math]::Max($expected.Count, $actual.Count)
    for ($i = 0; $i -lt $max; $i++) {
        $e = if ($i -lt $expected.Count) { $expected[$i] } else { '<missing line>' }
        $a = if ($i -lt $actual.Count)   { $actual[$i] }   else { '<missing line>' }
        if ($e -cne $a) { $firstDiff = $i; break }
    }

    $what = if ($r.Code -eq 0) { 'compiles' } else { "rejected as expected (exit $($r.Code))" }
    if ($firstDiff -lt 0) {
        Write-Result $true "$name  ($what)"
        $passA++
    } else {
        Write-Result $false "$name  - first difference at line $($firstDiff + 1):"
        Write-Host "          expected: $($expected[$firstDiff])"
        Write-Host "          actual:   $($actual[$firstDiff])"
        Write-Host "          full output: tests/out/$name.actual.txt"
    }
}

# ---------------------------------------------------------------- Part B
$clang = (Get-Command clang -ErrorAction SilentlyContinue)
$passB = 0
$runB = 0
Write-Host "`nPart B - run the compiled checkAccess from C ($($compiled.Count) compiled policies)"
if ($null -eq $clang) {
    Write-Host '  SKIPPED: clang not found. Install LLVM (winget install LLVM.LLVM) to run Part B.' -ForegroundColor Yellow
} else {
    # Make clang produce objects in the same format as this gcc.
    $machine = (Invoke-Tool $gcc.Source @('-dumpmachine')).Out[0]
    $target = $machine
    if ($machine -match '^x86_64-.*mingw')      { $target = 'x86_64-w64-windows-gnu' }
    elseif ($machine -match '^i[3-6]86-.*mingw') { $target = 'i686-w64-windows-gnu' }
    elseif ($machine -eq 'mingw32')              { $target = 'i686-pc-windows-gnu' }
    Write-Host "  gcc target: $machine  ->  clang --target=$target"

    foreach ($name in $compiled) {
        $runB++
        $obj = "tests/out/$name.o"
        $chk = if ($IsWin) { "tests/out/${name}_check.exe" } else { "tests/out/${name}_check" }

        $c = Invoke-Tool $clang.Source @('-c', '-Wno-override-module', "--target=$target", "tests/out/$name.ll", '-o', $obj)
        if ($c.Code -ne 0) { Write-Result $false "$name  (clang could not compile the .ll)"; $c.Err | ForEach-Object { Write-Host "          $_" }; continue }

        $l = Invoke-Tool $gcc.Source @('-std=c11', '-include', "tests/out/$name.h", 'tests/test_access.c', $obj, '-o', $chk)
        if ($l.Code -ne 0) { Write-Result $false "$name  (gcc could not link the test program)"; $l.Err | ForEach-Object { Write-Host "          $_" }; continue }

        $run = Invoke-Tool (Join-Path $PSScriptRoot $chk) @()
        $summary = ($run.Out | Where-Object { $_ -like 'RESULT:*' } | Select-Object -Last 1)
        $ok = ($run.Code -eq 0)
        Write-Result $ok "$name  ($summary)"
        if ($ok) { $passB++ }
    }
}

# ---------------------------------------------------------------- summary
Write-Host ''
Write-Host "Part A (compiler output):    $passA / $($tests.Count) passed"
if ($null -eq $clang) { Write-Host 'Part B (compiled checkAccess): skipped (no clang)' }
else                  { Write-Host "Part B (compiled checkAccess): $passB / $runB passed" }

$allOk = ($passA -eq $tests.Count) -and (($null -eq $clang) -or ($passB -eq $runB))
if ($allOk) { Write-Host "`nALL TESTS PASSED" -ForegroundColor Green; exit 0 }
else        { Write-Host "`nSOME TESTS FAILED" -ForegroundColor Red; exit 1 }