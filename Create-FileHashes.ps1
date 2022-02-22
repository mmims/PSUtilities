<#
    .SYNOPSIS
    Creates a checksum file for all the files in the specified path.

    .PARAMETER Path
    Specifies the path of a directory to the files that need to be hashed.

    .PARAMETER Algorithm
    Specifies the algorithm to use for hash values. "SHA256" is the default.

    .PARAMETER OutFile
    Specifies the name of the checksum file to create. "<DirectoryName>.<Algorithm>"
    is the default.

    .PARAMETER Recurse
    Specifies whether subdirectories in the Path should be included.

    .PARAMETER Depth
    Specifies how many levels of subdirectories in the Path should be included.
    Implies -Recurse.

    .PARAMETER NoCompress
    Do not remove whitespace from the JSON output.

    .PARAMETER NoOut
    Do not create an output file. Output results as a string.

    .PARAMETER Force
    Allows hidden or system files to be included in the checksums file.

    .PARAMETER Include
    Specifies an array of one or more string patterns to be matched as the cmdlet
    gets child items. Any matching item is included in the output. Enter a path
    element or pattern, such as "*.txt". Wildcard characters are permitted.

    .PARAMETER Exclude
    Specifies an array of one or more string patterns to be matched as the cmdlet
    gets child items. Any matching item is excluded from the output. Enter a path
    element or pattern, such as *.txt or A*. Wildcard characters are accepted.

    .INPUTS
    None. You cannot pipe objects to Create-FileHashes.

    .OUTPUTS
    String. Only if -NoOut is specified.

    .LINK
    Verify-FileHashes
#>
[CmdletBinding()]
param(
    [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160')]
    [string]$Algorithm = 'SHA256',
    [int]$Depth = -1,
    [string[]]$Exclude,
    [switch]$Force,
    [string[]]$Include,
    [switch]$NoCompress,
    [switch]$NoOut,
    [string]$OutFile,
    [Parameter(Position=0)]
    [string]$Path = (Get-Location).Path,
    [switch]$Recurse
)

function Create-FileHashes {
    <#
      .SYNOPSIS
      Creates a checksum file for all the files in the specified path.

      .PARAMETER Path
      Specifies the path of a directory to the files that need to be hashed.

      .PARAMETER Algorithm
      Specifies the algorithm to use for hash values. "SHA256" is the default.

      .PARAMETER OutFile
      Specifies the name of the checksum file to create. "<DirectoryName>.<Algorithm>"
      is the default.

      .PARAMETER Recurse
      Specifies whether subdirectories in the Path should be included.

      .PARAMETER Depth
      Specifies how many levels of subdirectories in the Path should be included.
      Implies -Recurse.

      .PARAMETER NoCompress
      Do not remove whitespace from the JSON output.

      .PARAMETER NoOut
      Do not create an output file. Output results as a string.

      .PARAMETER Force
      Allows hidden or system files to be included in the checksums file.

      .PARAMETER Include
      Specifies an array of one or more string patterns to be matched as the cmdlet
      gets child items. Any matching item is included in the output. Enter a path
      element or pattern, such as "*.txt". Wildcard characters are permitted.

      .PARAMETER Exclude
      Specifies an array of one or more string patterns to be matched as the cmdlet
      gets child items. Any matching item is excluded from the output. Enter a path
      element or pattern, such as *.txt or A*. Wildcard characters are accepted.

      .INPUTS
      None. You cannot pipe objects to Create-FileHashes.

      .OUTPUTS
      String. Only if -NoOut is specified.

      .LINK
      Verify-FileHashes
    #>
    [CmdletBinding()]
    param (
        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160')]
        [string]$Algorithm = 'SHA256',
        [int]$Depth = -1,
        [string[]]$Exclude,
        [switch]$Force,
        [string[]]$Include,
        [switch]$NoCompress,
        [switch]$NoOut,
        [string]$OutFile,
        [Parameter(Position=0)]
        [string]$Path = (Get-Location).Path,
        [switch]$Recurse
    )

    $Path = Resolve-Path $Path

    if ($OutFile -eq "") {
        $OutFile = Join-Path $Path "$((Get-Item $Path).BaseName).$($Algorithm.ToLower())"
    }

    Write-Progress -Activity 'Processing files'
    if ($Depth -ge 0) {
      $files = Get-ChildItem -Path:$Path -File -Force:$Force -Depth:$Depth
    } else {
      $files = Get-ChildItem -Path:$Path -File -Force:$Force -Recurse:$Recurse
    }

    Push-Location $Path
    Write-Progress -Activity 'Processing files'
    $completed = 0
    try {
        $fileInfo = @(foreach ($file in $files) {
            Write-Progress -Activity 'Processing files' -Status "$completed of $($files.Length)" -PercentComplete ($completed/$files.Length*100) -CurrentOperation $file.Name

            if ($file.FullName -eq $OutFile) {
                $completed++
                continue
            }

            if ($null -ne $Include) {
                $match = $false
                foreach($filter in $Include) {
                    if($file.Name -like $filter) {
                        $match = $true
                        break
                    }
                }
                if(!$match) {
                    $completed++
                    continue
                }
            }

            if ($null -ne $Exclude) {
                $match = $false
                foreach($filter in $Exclude) {
                    if($file.Name -like $filter) {
                        $match = $true
                        break
                    }
                }
                if($match) {
                    $completed++
                    continue
                }
            }

            $info = @{
                Path = Resolve-Path $file.FullName -Relative
                Hash = $(Get-FileHash $file.FullName -Algorithm $Algorithm).Hash.ToLower()
                Date = [string]$file.LastWriteTime.GetDateTimeFormats('o')
                Size = $file.Length
            }
            $completed++
            $info
        })
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
        HiddenFiles = $Force.IsPresent
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

if ($MyInvocation.InvocationName -ne '.') {
  Create-FileHashes @PSBoundParameters
}
