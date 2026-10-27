Set-StrictMode -Version Latest

$sourceModule = Join-Path $PSScriptRoot 'DmaForensics.Core.Source.psm1'
if (-not (Test-Path -LiteralPath $sourceModule)) { throw "Core-Modul fehlt: $sourceModule" }
. $sourceModule
