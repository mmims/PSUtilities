[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Path = (Get-Location).Path,
    [string]$VerifyFile,
    [switch]$IgnoreMissing
)

$isDotsourced = $true
if ($MyInvocation.InvocationName -ne '.') {
    $isDotsourced = $false
    Verify-FileHashes @PSBoundParameters
}

function Verify-FileHashes {
    [CmdletBinding()]
    param(
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
        $props = @('Date', 'OriginalLocation', 'Files', 'Algorithm', 'TotalFiles')
        foreach ($prop in $props) {
            if (![bool]($verifyObject.PSObject.Properties | Where-Object { $_.Name -eq $prop })) {
                Write-Warning "Invalid verification file; unable to find '$prop' property [$VerifyFile]"
            }
        }
        $hashes = @{}
        foreach ($prop in $verifyObject.PSObject.Properties.Name) {
            if ($prop -eq 'Files') {
                $hashes[$prop] = @()
                foreach ($file in $verifyObject.$prop) {
                    $info = @{}
                    foreach ($fprop in $file.PSObject.Properties.Name) {
                        $info[$fprop] = $file.$fprop
                    }
                    $info['Status'] = 'Missing'
                    $hashes[$prop] += $info
                }
            } else {
                $hashes[$prop] = $verifyObject.$prop
            }
        }
    }
    catch {
        Write-Error "Invalid verification file [$VerifyFile]"
        Invoke-Expression (ReturnOrExit -1)
    }

    Push-Location $Path
    $files = Get-ChildItem -Path:$Path -File -Recurse

    Write-Progress -Activity 'Processing files'
    $completed = 0
    try {
        foreach ($file in $files) {
            Write-Progress -Activity 'Processing files' -Status "$completed of $($files.Length)" -PercentComplete ($completed/$files.Length*100) -CurrentOperation $file.Name

            $relativePath = Resolve-Path $file.FullName -Relative
            if ($relativePath -eq (Resolve-Path $VerifyFile -Relative)) {
                # Write-Warning "Verification file skipped [$relativePath]"
                $completed++
                continue
            }

            # Write-Host "relativePath: $relativePath"
            $fileIndex = ([Collections.Generic.List[Object]]($hashes.Files)).FindIndex({ $args[0].Path -eq $relativePath })
            if ($fileIndex -ge 0) {
                # Write-Host "Matched file [$($hashes.Files[$fileIndex].Path)]"
                $hashes.Files[$fileIndex].Status = 'Found'
                $hashes.Files[$fileIndex].Verified = $false
                $hashes.Files[$fileIndex].VerifyDate = [string]$file.LastWriteTime.GetDateTimeFormats('o')
                $hashes.Files[$fileIndex].VerifySize = $file.Length
                $hashes.Files[$fileIndex].VerifyHash = (Get-FileHash $file.FullName -Algorithm $hashes.Algorithm).Hash.toLower()
                if ($hashes.Files[$fileIndex].Hash -eq $hashes.Files[$fileIndex].VerifyHash) {
                    $hashes.Files[$fileIndex].Verified = $true
                }
            } else {
                # Write-Warning "Unmatched file [$relativePath]"
                $fileInfo = @{}
                $fileInfo.Status = 'Untracked'
                $fileInfo.Path = $relativePath
                $fileInfo.VerifyDate = [string]$file.LastWriteTime.GetDateTimeFormats('o')
                $fileInfo.VerifySize = $file.Length
                $hashes.Files += $fileInfo
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

    $verified = @($hashes.Files | Where-Object { ($_.Status -eq 'Found') -and $_.Verified })
    $invalid = @($hashes.Files | Where-Object { ($_.Status -eq 'Found') -and !$_.Verified })
    $missing = @($hashes.Files | Where-Object { $_.Status -eq 'Missing' })
    $untracked = @($hashes.Files | Where-Object { $_.Status -eq 'Untracked' })

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
          # New for loop
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

    if ($untracked.Count -gt 0 -and $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent) {
        foreach ($item in $untracked) {
            Write-Host "${GRAY}Untracked file [$($item.Path)]${RESET}"
        }
    }

    Write-Host "`nVerified: ${GREEN}$($verified.Count)${RESET}  Invalid: ${RED}$($invalid.Count)${RESET}  Missing: ${YELLOW}$($missing.Count)${RESET}  Untracked: $ESC[90m$($untracked.Count)${RESET}"

    if (($invalid.Count -gt 0) -or (!$IgnoreMissing -and ($missing.Count -gt 0))) {
      Write-Host "Verification ${RED}FAILED${RESET} [$(Resolve-Path $VerifyFile -Relative)]"
      return ReturnOrExit -1
    }
    Write-Host "Verification ${GREEN}PASSED${RESET} [$(Resolve-Path $VerifyFile -Relative)]"
    return ReturnOrExit 0
}