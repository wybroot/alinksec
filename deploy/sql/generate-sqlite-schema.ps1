param(
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$sourcePath = Join-Path $repoRoot 'deploy\sql\001_init.sql'
$targetPath = Join-Path $repoRoot 'server\alinksec-bootstrap\src\main\resources\db\sqlite\V001__initial.sql'

$sql = [IO.File]::ReadAllText($sourcePath, [Text.Encoding]::UTF8)
$sql = $sql -replace "`r`n?", "`n"
$sql = $sql -replace '^-- ALinkSec unified bootstrap schema\..*$', '-- Generated SQLite bootstrap schema. Do not edit; run deploy/sql/generate-sqlite-schema.ps1.'
$sql = $sql -replace '::jsonb\b', ''
$sql = $sql -replace '\bBIGSERIAL\s+PRIMARY\s+KEY\b', 'INTEGER PRIMARY KEY AUTOINCREMENT'
$sql = $sql -replace '\bBIGSERIAL\b', 'INTEGER'
$sql = $sql -replace '\bTIMESTAMPTZ\b', 'TEXT'
$sql = $sql -replace '\bJSONB\b', 'TEXT'
$sql = $sql -replace '\bBIGINT\[\]', 'TEXT'
$sql = $sql -replace '\bBYTEA\b', 'BLOB'
$sql = $sql -replace '\bDOUBLE\s+PRECISION\b', 'REAL'
$sql = $sql -replace '\bnow\(\)', 'CURRENT_TIMESTAMP'
$sql = [regex]::Replace($sql, '(?m)^(\s*)check(\s+TEXT\s+NOT NULL,)', '$1"check"$2')
$sql = $sql -replace '(t_baseline_item \(template_id, code, name, category, severity, )check(, remediation, fix_spec\))', '$1"check"$2'
$sql = [regex]::Replace($sql, '(?m)^CREATE INDEX[^\n]*\bUSING GIN\b[^\n]*\n', '')
$sql = [regex]::Replace($sql, '(?m)^COMMENT ON[^\n]*\n', '')

if (-not $sql.EndsWith("`n")) {
    $sql += "`n"
}

if ($Check) {
    if (-not (Test-Path -LiteralPath $targetPath)) {
        throw "SQLite schema is missing: $targetPath"
    }
    $actual = [IO.File]::ReadAllText($targetPath, [Text.Encoding]::UTF8) -replace "`r`n?", "`n"
    if ($actual -cne $sql) {
        throw 'SQLite schema is stale. Run deploy/sql/generate-sqlite-schema.ps1 and commit the result.'
    }
    Write-Host 'SQLite schema is up to date.'
    exit 0
}

$targetDir = Split-Path -Parent $targetPath
[IO.Directory]::CreateDirectory($targetDir) | Out-Null
[IO.File]::WriteAllText($targetPath, $sql, [Text.UTF8Encoding]::new($false))
Write-Host "Generated $targetPath"
