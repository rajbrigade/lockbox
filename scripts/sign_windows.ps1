<#
.SYNOPSIS
    Sign the Lockbox executables with Authenticode.

.DESCRIPTION
    Three modes, matching the three realistic situations:

      -Mode Token       a certificate on a USB token or HSM from a CA
                        (DigiCert, Sectigo, SSL.com ...). Since 1 June 2023 the
                        CA/Browser Forum requires the private key to live on
                        hardware, so there is no .pfx file to point at.

      -Mode Azure       Azure Artifact Signing (formerly Trusted Signing).
                        Cloud HSM, no token. Needs the `dotnet sign` tool and a
                        metadata JSON describing your signing account.

      -Mode SelfSigned  a certificate you create yourself. Useless to the
                        public -- other machines will not trust it -- but fine
                        for your own machines and for testing the pipeline.

    Every mode timestamps the signature. Without a timestamp the signature dies
    the day the certificate expires; with one it stays valid afterwards.

.EXAMPLE
    .\scripts\sign_windows.ps1 -Mode Token -Thumbprint A1B2C3...
    .\scripts\sign_windows.ps1 -Mode Azure -MetadataPath .\signing.json
    .\scripts\sign_windows.ps1 -Mode SelfSigned -CreateCert
#>

[CmdletBinding()]
param(
    [ValidateSet("Token", "Azure", "SelfSigned")]
    [string]$Mode = "Token",

    # Certificate thumbprint (Token / SelfSigned). Find it with:
    #   Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
    [string]$Thumbprint,

    # Azure Artifact Signing metadata JSON (Azure mode).
    [string]$MetadataPath = ".\signing.json",

    # RFC 3161 timestamp authority.
    [string]$TimestampUrl = "http://timestamp.digicert.com",

    # Files to sign. Defaults to whatever build.py produced.
    [string[]]$Files = @(".\dist\lockbox.exe", ".\dist\lockbox-gui.exe"),

    # SelfSigned mode: create the certificate first.
    [switch]$CreateCert,

    [string]$SubjectName = "CN=Lockbox Local Build"
)

$ErrorActionPreference = "Stop"

function Find-SignTool {
    $existing = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($existing) { return $existing.Source }

    # signtool ships with the Windows SDK, which is not on PATH by default.
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    ) | Where-Object { Test-Path $_ }

    $found = $roots |
        ForEach-Object { Get-ChildItem $_ -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue } |
        Where-Object { $_.FullName -match "x64" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if (-not $found) {
        throw "signtool.exe not found. Install the Windows SDK (the 'Signing Tools' component is enough): https://developer.microsoft.com/windows/downloads/windows-sdk/"
    }
    return $found.FullName
}

function Assert-FilesExist {
    param([string[]]$Paths)
    $missing = $Paths | Where-Object { -not (Test-Path $_) }
    if ($missing) {
        throw "Nothing to sign -- these do not exist:`n  $($missing -join "`n  ")`nRun: python build.py"
    }
}

$present = $Files | Where-Object { Test-Path $_ }
if (-not $present) { Assert-FilesExist -Paths $Files }
Write-Host "Signing $($present.Count) file(s) in $Mode mode`n"

switch ($Mode) {

    "SelfSigned" {
        if ($CreateCert) {
            Write-Host "Creating a self-signed code-signing certificate..."
            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $SubjectName `
                -CertStoreLocation Cert:\CurrentUser\My `
                -KeyUsage DigitalSignature `
                -KeyLength 3072 `
                -NotAfter (Get-Date).AddYears(3)
            $Thumbprint = $cert.Thumbprint
            Write-Host "  thumbprint: $Thumbprint"
            Write-Host ""
            Write-Host "This certificate is trusted by nobody, including you, until it is"
            Write-Host "imported into Trusted Root. To trust it on THIS machine only"
            Write-Host "(needs an elevated shell):"
            Write-Host "  Export-Certificate -Cert Cert:\CurrentUser\My\$Thumbprint -FilePath lockbox-local.cer"
            Write-Host "  Import-Certificate -FilePath lockbox-local.cer -CertStoreLocation Cert:\LocalMachine\Root"
            Write-Host ""
            Write-Host "Do NOT ship this certificate. Other people's machines will still warn."
            Write-Host ""
        }
        if (-not $Thumbprint) { throw "Pass -Thumbprint, or add -CreateCert to make one." }
    }

    "Token" {
        if (-not $Thumbprint) {
            Write-Host "Code-signing certificates available to you:"
            Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
                Format-Table Thumbprint, Subject, NotAfter -AutoSize
            throw "Pass -Thumbprint <one of the above>. Insert the USB token first if the list is empty."
        }
    }

    "Azure" {
        if (-not (Test-Path $MetadataPath)) {
            @'
{
  "Endpoint": "https://eus.codesigning.azure.net/",
  "CodeSigningAccountName": "your-signing-account",
  "CertificateProfileName": "your-public-trust-profile"
}
'@ | Set-Content -Path $MetadataPath -Encoding UTF8
            Write-Host "Wrote a template to $MetadataPath -- fill it in and run again."
            Write-Host "The endpoint region must match your signing account's region,"
            Write-Host "or signing fails with 403 Forbidden."
            exit 1
        }
        $sign = Get-Command sign -ErrorAction SilentlyContinue
        if (-not $sign) {
            throw "The `dotnet sign` tool is missing. Install it with:`n  dotnet tool install --global sign --prerelease"
        }
    }
}

if ($Mode -eq "Azure") {
    foreach ($file in $present) {
        Write-Host "  signing $file"
        & sign code trusted-signing $file `
            --trusted-signing-endpoint (Get-Content $MetadataPath | ConvertFrom-Json).Endpoint `
            --trusted-signing-account (Get-Content $MetadataPath | ConvertFrom-Json).CodeSigningAccountName `
            --trusted-signing-certificate-profile (Get-Content $MetadataPath | ConvertFrom-Json).CertificateProfileName
        if ($LASTEXITCODE -ne 0) { throw "signing failed for $file" }
    }
} else {
    $signtool = Find-SignTool
    Write-Host "using $signtool`n"
    foreach ($file in $present) {
        Write-Host "  signing $file"
        & $signtool sign `
            /sha1 $Thumbprint `
            /fd SHA256 `
            /tr $TimestampUrl `
            /td SHA256 `
            /d "Lockbox offline password manager" `
            $file
        if ($LASTEXITCODE -ne 0) { throw "signing failed for $file" }
    }
}

Write-Host "`nVerifying signatures..."
$signtool = Find-SignTool
foreach ($file in $present) {
    & $signtool verify /pa /v $file
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$file did not verify against the machine's trust store."
        Write-Warning "For a self-signed certificate this is expected until it is imported into Trusted Root."
    }
}

Write-Host "`nDone."
Write-Host "Signing does not switch SmartScreen off. A newly signed file still"
Write-Host "warns until it accumulates download reputation -- signing is what lets"
Write-Host "that reputation attach to your identity instead of restarting with"
Write-Host "every build."
