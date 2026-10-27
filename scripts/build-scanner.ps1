[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$templatePath = Join-Path $projectRoot 'package\DmaForensicsAnalyzer.sed'
$targetPath = Join-Path $projectRoot 'DmaForensicsScanner.exe'
$iexpressPath = Join-Path $env:windir 'System32\iexpress.exe'

foreach ($requiredPath in @($templatePath, (Join-Path $projectRoot 'package\Run-DmaForensics.cmd'), (Join-Path $projectRoot 'package\Invoke-DmaForensics.Gui.ps1'), (Join-Path $projectRoot 'package\DmaForensics.Core.Source.psm1'))) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required build input is missing: $requiredPath"
    }
}
if (-not (Test-Path -LiteralPath $iexpressPath -PathType Leaf)) {
    throw 'IExpress is not available on this Windows installation.'
}

$template = Get-Content -LiteralPath $templatePath -Raw
$rendered = $template.Replace('__PROJECT_ROOT__', $projectRoot)
$tempSedPath = Join-Path $env:TEMP ('dma-forensics-{0}.sed' -f [guid]::NewGuid().ToString('N'))
try {
    [System.IO.File]::WriteAllText($tempSedPath, $rendered, [System.Text.Encoding]::ASCII)
    $process = Start-Process -FilePath $iexpressPath -ArgumentList @('/N', '/Q', $tempSedPath) -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "IExpress failed with exit code $($process.ExitCode)."
    }
    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        throw 'IExpress completed without creating DmaForensicsScanner.exe.'
    }
    $hash = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash
    Write-Output "Built: $targetPath"
    Write-Output "SHA-256: $hash"
    Write-Output "Signature: $((Get-AuthenticodeSignature -LiteralPath $targetPath).Status)"
} finally {
    Remove-Item -LiteralPath $tempSedPath -Force -ErrorAction SilentlyContinue
}
