<#
    .SYNOPSIS
    Verifies a checksum file for all the files in the specified path.

    .PARAMETER All
    Include all files in the path in the results not just those defined in the
    checksum file.

    .PARAMETER Force
    Allow hidden or system files to be included in the verification. Defaults to
    HiddenFiles value of checksum file.

    .PARAMETER Path
    Specifies the path of a directory to the files that need to be verified.

    .PARAMETER VerifyFile
    Specifies the name of the checksum file to verify. "<DirectoryName>.<Algorithm>"
    is the default.

    .PARAMETER IgnoreMissing
    Specifies whether missing files should be ignored during verification.

    .INPUTS
    None. You cannot pipe objects to Verify-FileHashes.

    .OUTPUTS
    Integer. Returns exit code for verification.

    .LINK
    Create-FileHashes
#>
[CmdletBinding()]
param(
    [switch]$All,
    [switch]$Force,
    [Parameter(Position=0)]
    [string]$Path = (Get-Location).Path,
    [string]$VerifyFile,
    [switch]$IgnoreMissing
)

$isDotsourced = $true
if ($MyInvocation.InvocationName -ne '.') {
    $isDotsourced = $false
}

function Verify-FileHashes {
    <#
      .SYNOPSIS
      Verifies a checksum file for all the files in the specified path.

      .PARAMETER All
      Include all files in the path in the results not just those defined in the
      checksum file.

      .PARAMETER Force
      Allow hidden or system files to be included in the verification. Defaults to
      HiddenFiles value of checksum file.

      .PARAMETER Path
      Specifies the path of a directory to the files that need to be verified.

      .PARAMETER VerifyFile
      Specifies the name of the checksum file to verify. "<DirectoryName>.<Algorithm>"
      is the default.

      .PARAMETER IgnoreMissing
      Specifies whether missing files should be ignored during verification.

      .INPUTS
      None. You cannot pipe objects to Verify-FileHashes.

      .OUTPUTS
      None.

      .LINK
      Create-FileHashes
    #>
    [CmdletBinding()]
    param(
        [switch]$All,
        [switch]$Force,
        [Parameter(Position=0)]
        [string]$Path = (Get-Location).Path,
        [string]$VerifyFile,
        [switch]$IgnoreMissing
    )

    function ReturnOrExit {
        param (
            [int]$ExitCode
        )
        if (!$isDotsourced) {
            exit $ExitCode
        }
        return
    }
    $Path = Resolve-Path $Path

    if ([string]::IsNullOrEmpty($VerifyFile)) {
        $algs = @('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160')
        foreach ($alg in $algs) {
            $testFile = Join-Path $Path "$((Get-Item $Path).BaseName).$($alg.ToLower())"
            if (Test-Path $testFile) {
                $VerifyFile = $testFile
                break
            }
        }
        if ([string]::IsNullOrEmpty($VerifyFile)) {
            Write-Warning "No verification file detected [$Path]"
            Invoke-Expression (ReturnOrExit 1)
        }
    } else {
        $VerifyFile = Resolve-Path $VerifyFile
    }

    try {
        $verifyObject = Get-Content $VerifyFile | ConvertFrom-Json
        $props = @('Date', 'OriginalLocation', 'Files', 'Algorithm', 'TotalFiles', 'HiddenFiles')
        foreach ($prop in $props) {
            if (![bool]($verifyObject.PSObject.Properties | Where-Object { $_.Name -eq $prop })) {
                Write-Warning "Invalid verification file; unable to find '$prop' property [$VerifyFile]"
            }
        }
        if (-not $Force.IsPresent) {
            $Force = $verifyObject.HiddenFiles
        }
    }
    catch {
        Write-Error "Invalid verification file [$VerifyFile]"
        Invoke-Expression (ReturnOrExit -1)
    }

    Push-Location $Path

    $verified = [System.Collections.Generic.List[Object]]@()
    $invalid = [System.Collections.Generic.List[Object]]@()
    $missing = [System.Collections.Generic.List[Object]]@()
    $completed = 0

    if ($All) {
        Write-Progress -Activity 'Processing files' -Status 'Initializing...'
        $untracked = [System.Collections.Generic.List[string]](Get-ChildItem -Path:$Path -File -Force:$Force -Recurse -Name)
    }

    try {
        foreach ($file in $verifyObject.Files) {
            Write-Progress -Activity 'Processing files' -Status "$completed of $($verifyObject.Files.Count)" -PercentComplete ($completed/$verifyObject.Files.Count*100) -CurrentOperation $file.Path

            if ($file.Path -eq (Resolve-Path $VerifyFile -Relative)) {
                $completed++
                continue
            }

            $fileInfo = @{
                Date = $file.Date
                Hash = $file.Hash
                Path = $file.Path
                Size = $file.Size
            }

            if (Test-Path $file.Path -PathType Leaf) {
                $compFile = Get-ChildItem $file.Path -File -Force
                $fileInfo.VerifyDate = [string]$compFile.LastWriteTime.GetDateTimeFormats('o')
                $fileInfo.VerifySize = $compFile.Length
                $fileInfo.VerifyHash = (Get-FileHash $compFile.FullName -Algorithm $verifyObject.Algorithm).Hash.toLower()
                if ($file.Hash -eq $fileInfo.VerifyHash) {
                    $verified.Add($fileInfo)
                } else {
                    $invalid.Add($fileInfo)
                }
            } else {
                $missing.Add($fileInfo)
            }

            if ($All) {
               $null = $untracked.Remove($file.Path.Replace('.\',''))
            }

            $completed++
        }
    }
    catch {
        Write-Error $_
        Invoke-Expression (ReturnOrExit -1)
    } finally {
        Write-Progress -Activity 'Processing files' -Completed
    }

    Pop-Location

    Function Format-Bytes {
      Param
      (
          [Parameter(
              ValueFromPipeline = $true
          )]
          [ValidateNotNullOrEmpty()]
          [float]$number
      )
      Begin{
          $sizes = 'KB','MB','GB','TB','PB'
      }
      Process {
          for($x = 0;$x -lt $sizes.count; $x++){
              if ($number -lt "1$($sizes[$x])"){
                  if ($x -eq 0){
                      return "$number B"
                  } else {
                      $num = $number / "1$($sizes[$x-1])"
                      $num = "{0:N2}" -f $num
                      return "$num $($sizes[$x-1])"
                  }
              }
          }
      }
      End{}
    }

    $RESET = $RED = $GREEN = $YELLOW = $GRAY = ""
    if ($Host.UI.SupportsVirtualTerminal) {
      $ESC = [char]0x1b
      $RESET = "$ESC[0m"
      $RED = "$ESC[91m"
      $GREEN = "$ESC[92m"
      $YELLOW = "$ESC[93m"
      $GRAY = "$ESC[90m"
    }

    if (($verified.Count -gt 0) -and $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent) {
        foreach ($item in $verified) {
            Write-Host "${GREEN}Verified file [$($item.Path)]${RESET}"
        }
    }

    if ($invalid.Count -gt 0) {
        foreach ($item in $invalid) {
            Write-Host "${RED}Invalid file [$($item.Path)]${RESET}"
            if ($PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent) {
                Write-Host "  Original"
                Write-Host "    Hash: $($item.Hash)`n    Date: $($item.Date)`n    Size: $(Format-Bytes $item.Size)"
                Write-Host "  Computed"
                Write-Host "    Hash: ${RED}$($item.VerifyHash)${RESET}"
                if ($item.Date -ne $item.VerifyDate) {
                    $span = [datetime]::Parse($item.VerifyDate) - [datetime]::Parse($item.Date)
                    $sb = "    Date: $($item.VerifyDate) (${YELLOW}"
                    if ($span.Ticks -gt 0) {
                        $sb += "+"
                    }
                    if ($span.Days -gt 0) {
                        $sb += "$($span.Days) days${RESET})"
                    } else {
                        $sb += "$($span.ToString())${RESET})"
                    }
                    Write-Host $sb
                } else {
                    Write-Host "    Date: ${GREEN}$($item.VerifyDate)${RESET}"
                }
                $size = $item.VerifySize - $item.Size
                if ($size -ne 0) {
                    $sb = "    Size: $(Format-Bytes $item.VerifySize) (${YELLOW}"
                    if ($size -gt 0) {
                        $sb += "+"
                    }
                    $sb += "$(Format-Bytes $size)${RESET})"
                    Write-Host $sb
                } else {
                    Write-Host "    Size: $(Format-Bytes $item.VerifySize)"
                }
            }
        }
    }

    if ($missing.Count -gt 0) {
        foreach ($item in $missing) {
            Write-Host "${YELLOW}Missing file [$($item.Path)]${RESET}"
            if ($PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent) {
                Write-Host "  Hash: $($item.Hash)"
                Write-Host "  Date: $($item.Date)"
                Write-Host "  Size: $(Format-Bytes $item.Size)"
            }
        }
    }

    if ($All -and ($untracked.Count -gt 0) -and $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent) {
        foreach ($item in $untracked) {
            Write-Host "${GRAY}Untracked file [$item]${RESET}"
        }
    }

    $results = "`nVerified: ${GREEN}$($verified.Count)${RESET}  Invalid: ${RED}$($invalid.Count)${RESET}  Missing: ${YELLOW}$($missing.Count)${RESET}"
    if ($All) {
        $results += "  Untracked: $ESC[90m$($untracked.Count)${RESET}"
    }
    Write-Host $results

    if (($invalid.Count -gt 0) -or (!$IgnoreMissing -and ($missing.Count -gt 0))) {
      Write-Host "Verification ${RED}FAILED${RESET} [$(Resolve-Path $VerifyFile -Relative)]"
      return ReturnOrExit -1
    }
    Write-Host "Verification ${GREEN}PASSED${RESET} [$(Resolve-Path $VerifyFile -Relative)]"
    return ReturnOrExit 0
}

if ($MyInvocation.InvocationName -ne '.') {
  Verify-FileHashes @PSBoundParameters
}
