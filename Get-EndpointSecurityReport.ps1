#requires -Version 7.4
# Tiago Carvalho | https://www.tiagoscarvalho.com | MIT
<#
.SYNOPSIS
Read selected Intune devices and their Defender vulnerability findings into local reports.
.EXAMPLE
./Get-EndpointSecurityReport.ps1 -ExpectedTenantId '<tenant-guid>' -ManagedDeviceId '<intune-device-guid>' -DefenderAccessToken $token -OutputPath './Weekly-Report'
#>
[CmdletBinding(DefaultParameterSetName='Token')]
param(
    [Parameter(Mandatory)][guid]$ExpectedTenantId,
    [Parameter(Mandatory)][ValidateCount(1,500)][guid[]]$ManagedDeviceId,
    [Parameter(Mandatory,ParameterSetName='Token')][securestring]$DefenderAccessToken,
    [Parameter(Mandatory,ParameterSetName='IntuneOnly')][switch]$IntuneOnly,
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$PreviousSnapshot,
    [ValidateRange(1,720)][int]$MaxDataAgeHours=48
)
$ErrorActionPreference='Stop'
Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.37.0 -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'EndpointSecurityReport.psm1') -Force
Invoke-EndpointSecurityReport @PSBoundParameters
