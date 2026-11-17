#requires -Version 7.4
# Tiago Carvalho | https://www.tiagoscarvalho.com | MIT
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigurationPath,
    [Parameter(Mandatory)][string]$OutputRoot,
    [string]$PreviousSnapshot
)
$ErrorActionPreference='Stop'
$code=1
$stage='Configuration';$graphConnected=$false;$azureStarted=$false
$statusPath=$null
$runStatus=[ordered]@{StartedUtc=[DateTimeOffset]::UtcNow.ToString('o');FinishedUtc=$null;Stage=$stage;CertificateSignInSucceeded=$false;DefenderTokenIssued=$false;GraphCertificateConnected=$false;CollectionStarted=$false;ExitCode=1;FailureType=$null;TenantConfigurationChanged=$false}
try {
    Import-Module (Join-Path $PSScriptRoot 'EndpointSecurityReport.psm1') -Force
    $config=Read-EndpointRunConfiguration $ConfigurationPath
    $tenant=$config.TenantId;$client=$config.ClientId;$ids=$config.ManagedDeviceIds
    $stage='CertificatePreflight'
    if (-not $IsWindows) {throw 'The certificate-store runner requires Windows.'}
    $certificate=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$config.CertificateThumbprint) -ErrorAction Stop
    $now=[DateTime]::UtcNow
    if (-not $certificate.HasPrivateKey -or $certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now.AddMinutes(5)) {throw 'A valid certificate and accessible private key are required.'}
    $stage='LoadAuthenticationModules'
    Import-Module Az.Accounts -MinimumVersion 5.0.0
    Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.37.0
    if(-not (Test-Path -LiteralPath $OutputRoot)){New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null}
    $statusPath=Join-Path $OutputRoot ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-run-status.json')
    Disable-AzContextAutosave -Scope Process|Out-Null
    $azureStarted=$true;$stage='CertificateSignIn'
    $profile=Connect-AzAccount -ServicePrincipal -Tenant $tenant -ApplicationId $client -CertificateThumbprint $config.CertificateThumbprint -SkipContextPopulation -Scope Process
    $runStatus.CertificateSignInSucceeded=$true
    $stage='DefenderToken'
    $defenderToken=Get-AzAccessToken -ResourceUrl 'https://api.securitycenter.microsoft.com' -TenantId $tenant -DefaultProfile $profile
    if ($defenderToken.Token -isnot [Security.SecureString]) {throw 'Azure PowerShell must return a SecureString token.'}
    $runStatus.DefenderTokenIssued=$true
    $stage='GraphConnection'
    Connect-MgGraph -TenantId $tenant -ClientId $client -Certificate $certificate -ContextScope Process -NoWelcome
    $graphConnected=$true
    $context=Get-MgContext
    if($context.AuthType -ne 'AppOnly' -or $context.TenantId -ne $tenant.ToString() -or $context.ClientId -ne $client.ToString() -or $context.Environment -ne 'Global'){throw 'Unexpected Graph certificate identity.'}
    $runStatus.GraphCertificateConnected=$true;$stage='ReadOnlyCollection';$runStatus.CollectionStarted=$true
    $output=Join-Path $OutputRoot ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
    $params=@{ExpectedTenantId=$tenant;ManagedDeviceId=$ids;DefenderAccessToken=$defenderToken.Token;OutputPath=$output;MaxDataAgeHours=[int]$config.MaxDataAgeHours}
    if ($PreviousSnapshot) {$params.PreviousSnapshot=$PreviousSnapshot}
    $result=& (Join-Path $PSScriptRoot 'Get-EndpointSecurityReport.ps1') @params
    $result|Format-List
    $code=if ($result.Status.StartsWith('COMPLETE')) {0} else {2}
} catch {
    $runStatus.FailureType=$_.Exception.GetType().FullName
    Write-Warning "Report run failed at $stage. Check the matching prerequisite in docs/OPERATIONS.md. No raw authentication error or token is printed."
} finally {
    if ($graphConnected) {Disconnect-MgGraph -ErrorAction SilentlyContinue|Out-Null}
    if ($azureStarted -and (Get-Command Clear-AzContext -ErrorAction SilentlyContinue)) {Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue|Out-Null}
    $runStatus.Stage=$stage;$runStatus.ExitCode=$code;$runStatus.FinishedUtc=[DateTimeOffset]::UtcNow.ToString('o')
    if($statusPath){$runStatus|ConvertTo-Json|Set-Content -LiteralPath $statusPath}
    $defenderToken=$null;$certificate=$null;$profile=$null;$context=$null
}
exit $code
