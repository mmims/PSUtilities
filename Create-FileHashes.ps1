[CmdletBinding()]
param(
    [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160')]
    [string]$Algorithm = 'SHA256',
    [int]$Depth = -1,
    [switch]$NoCompress,
    [switch]$NoOut,
    [string]$OutFile,
    [Parameter(Position=0)]
    [string]$Path = (Get-Location).Path,
    [switch]$Recurse
)

if ($MyInvocation.InvocationName -ne '.') {
  Create-FileHashes @PSBoundParameters
}

function Create-FileHashes {
    [CmdletBinding()]
    param (
        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160')]
        [string]$Algorithm = 'SHA256',
        [int]$Depth = -1,
        [switch]$NoCompress,
        [switch]$NoOut,
        [string]$OutFile,
        [Parameter(Position=0)]
        [string]$Path = (Get-Location).Path,
        [switch]$Recurse
    )

    $Path = Resolve-Path $Path

    if (!$NoOut -and ($OutFile -eq "")) {
        $OutFile = Join-Path $Path "$((Get-Item $Path).BaseName).$($Algorithm.ToLower())"
    }

    Write-Progress -Activity 'Processing files'
    $fileInfo = @()
    if ($Recurse) {
        if ($Depth -ge 0) {
            $files = Get-ChildItem -Path:$Path -File -Recurse -Depth:$Depth
        } else {
            $files = Get-ChildItem -Path:$Path -File -Recurse
        }
    } else {
        $files = Get-ChildItem -Path:$Path -File
    }

    Push-Location $Path
    Write-Progress -Activity 'Processing files'
    $completed = 0
    try {
        foreach ($file in $files) {
            Write-Progress -Activity 'Processing files' -Status "$completed of $($files.Length)" -PercentComplete ($completed/$files.Length*100) -CurrentOperation $file.Name
            $info = @{
                Path = Resolve-Path $file.FullName -Relative
                Hash = $(Get-FileHash $file.FullName -Algorithm $Algorithm).Hash.ToLower()
                Date = [string]$file.LastWriteTime.GetDateTimeFormats('o')
                Size = $file.Length
            }
            $fileInfo += $info
            $completed++
        }
    }
    catch {
        Write-Error $_
        return
    } finally {
        Write-Progress -Activity 'Processing files' -Completed
        Pop-Location
    }

    $hashes = @{
        Algorithm = $Algorithm
        Date = Get-Date -Format o
        Files = $fileInfo
        TotalFiles = $fileInfo.Length
        OriginalLocation = $Path
    }

    $hashesJson = $hashes | ConvertTo-Json -Compress:$(!$NoCompress)

    if ($NoOut) {
        $hashesJson
    } else {
        $hashesJson | Out-File -LiteralPath $OutFile -Encoding utf8
        Write-Host "Verification file written [$(Resolve-Path $OutFile -Relative)]"
    }
}