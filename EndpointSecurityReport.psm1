#requires -Version 7.4
# Tiago Carvalho | https://www.tiagoscarvalho.com | MIT
Set-StrictMode -Version Latest
$script:Version='0.1.0-rc.4'

function Read-EndpointRunConfiguration([string]$Path) {
    $config=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop|ConvertFrom-Json -AsHashtable -ErrorAction Stop
    $tenant=[guid]$config.TenantId;$client=[guid]$config.ClientId
    if ($tenant -eq [guid]::Empty -or $client -eq [guid]::Empty) {throw 'Replace placeholder tenant and application IDs.'}
    if ($config.ManagedDeviceIds -isnot [array]) {throw 'ManagedDeviceIds must be an array.'}
    $ids=[guid[]]$config.ManagedDeviceIds
    if (-not $ids.Count -or $ids.Count -gt 500 -or $ids -contains [guid]::Empty -or @($ids|Select-Object -Unique).Count -ne $ids.Count) {throw 'Select 1 to 500 distinct managed-device IDs.'}
    $thumbprint=[string]$config.CertificateThumbprint
    if ($thumbprint -notmatch '^[a-fA-F0-9]{40}$' -or $thumbprint -eq ('0'*40)) {throw 'Replace the placeholder certificate thumbprint.'}
    $age=$config.MaxDataAgeHours
    if ($age -isnot [long] -and $age -isnot [int]) {throw 'MaxDataAgeHours must be an integer.'}
    if ($age -lt 1 -or $age -gt 720) {throw 'MaxDataAgeHours must be between 1 and 720.'}
    [pscustomobject]@{TenantId=$tenant;ClientId=$client;ManagedDeviceIds=$ids;CertificateThumbprint=$thumbprint;MaxDataAgeHours=[int]$age}
}

function Field($Object,[string]$Name) {
    if ($null -eq $Object) {return $null}
    if ($Object -is [Collections.IDictionary]) {return ,$Object[$Name]}
    $p=$Object.PSObject.Properties[$Name]
    if ($null -ne $p) {return ,$p.Value}
    return $null
}
function Get-HttpStatus($ErrorRecord) {
    $queue=[Collections.Generic.Queue[Exception]]::new();$queue.Enqueue($ErrorRecord.Exception)
    $seen=[Collections.Generic.HashSet[Exception]]::new()
    while ($queue.Count -and $seen.Count -lt 32) {
        $e=$queue.Dequeue();if (-not $seen.Add($e)) {continue}
        foreach ($v in @((Field $e 'StatusCode'),(Field $e 'ResponseStatusCode'),(Field (Field $e 'Response') 'StatusCode'))) {
            if ($null -ne $v) {try {$n=[int]$v;if ($n -ge 400 -and $n -le 599) {return $n}} catch {}}
        }
        if ($e.InnerException) {$queue.Enqueue($e.InnerException)}
        if ($e -is [AggregateException]) {foreach ($inner in $e.InnerExceptions) {$queue.Enqueue($inner)}}
    }
    return 0
}
function Test-ReadUri([string]$Uri,[string]$InitialUri,[string]$Source) {
    $u=$null;$initial=$null
    if (-not [uri]::TryCreate($Uri,[UriKind]::Absolute,[ref]$u) -or -not [uri]::TryCreate($InitialUri,[UriKind]::Absolute,[ref]$initial)) {return $false}
    $hostName=if ($Source -eq 'Intune') {'graph.microsoft.com'} else {'api.security.microsoft.com'}
    if ($u.Scheme -ne 'https' -or $u.Host -ne $hostName -or $u.Port -ne 443 -or $u.UserInfo -or $u.Fragment -or $u.AbsolutePath -ne $initial.AbsolutePath) {return $false}
    if ($Source -eq 'Intune') {return $u.AbsolutePath -match '^/v1\.0/deviceManagement/managedDevices/[0-9a-f-]{36}(/deviceCompliancePolicyStates)?$'}
    return $u.AbsolutePath -match '^/api/(machines|machines/[a-f0-9]{40,64}/vulnerabilities|vulnerabilities/machinesVulnerabilities)$'
}
function Request-Read([string]$Uri,[string]$Source,$Token) {
    if ($Source -eq 'Intune') {return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop}
    Invoke-RestMethod -Method Get -Uri $Uri -Authentication Bearer -Token $Token -MaximumRedirection 0 -TimeoutSec 90 -ErrorAction Stop
}
function Read-Endpoint([string]$Uri,[string]$Source,[bool]$Collection,[hashtable]$Session) {
    $items=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new();$itemIds=[Collections.Generic.HashSet[string]]::new()
    $initial=$Uri;$complete=$true;$reason='';$status=0;$pages=0
    while ($Uri) {
        if ($Session.Stopped[$Source]) {$complete=$false;$reason='StoppedAfterServiceFailure';break}
        if ($pages -ge 100 -or -not (Test-ReadUri $Uri $initial $Source) -or -not $seen.Add($Uri)) {$complete=$false;$reason='InvalidOrExcessivePagination';break}
        try {
            $page=Request-Read $Uri $Source $Session.Token
            if ($Collection) {
                $values=Field $page 'value'
                if ($values -isnot [Collections.IList]) {throw 'Invalid response shape'}
                foreach ($item in $values) {
                    if (-not (Field $item 'id')) {throw 'Missing item identifier'}
                    $newId=$itemIds.Add([string](Field $item 'id'))
                    if (-not $newId -and -not ($Source -eq 'Intune' -and ([uri]$initial).AbsolutePath.EndsWith('/deviceCompliancePolicyStates'))) {throw 'Duplicate item identifier'}
                    $items.Add($item)
                }
                $Uri=[string](Field $page '@odata.nextLink')
                if (-not $Uri -and $Source -eq 'Defender' -and $values.Count -eq 10000 -and ([uri]$initial).AbsolutePath -in @('/api/machines','/api/vulnerabilities/machinesVulnerabilities')) {
                    $Uri=$initial+'&$skip='+(($pages+1)*10000)
                }
            } else {if (-not (Field $page 'id')) {throw 'Missing identifier'};$items.Add($page);$Uri=''}
            $pages++
        } catch {
            $status=Get-HttpStatus $_;$complete=$false
            $reason=switch ($status) {401 {'AuthenticationRequired'} 403 {'AccessDenied'} 404 {'NotFound'} 429 {'Throttled'} {$_ -ge 500} {'ServiceUnavailable'} default {'InvalidResponseOrRequestFailed'}}
            if ($status -eq 401 -or $status -eq 429 -or $status -ge 500) {$Session.Stopped[$Source]=$true}
            break
        }
    }
    [pscustomobject]@{Items=$items.ToArray();Complete=$complete;Reason=$reason;HttpStatus=$status;Pages=$pages}
}
function Assert-DefenderToken([securestring]$Token,[string]$Tenant) {
    $plain=[Net.NetworkCredential]::new('', $Token).Password
    try {
        $parts=$plain.Split('.');if ($parts.Count -ne 3) {throw 'Invalid token'}
        $payload=$parts[1].Replace('-','+').Replace('_','/');$payload=$payload.PadRight([int]([Math]::Ceiling($payload.Length/4.0)*4),'=')
        $claims=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        $aud=[string](Field $claims 'aud')
        if ((Field $claims 'tid') -ne $Tenant -or $aud.TrimEnd('/') -notin @('https://api.securitycenter.microsoft.com','https://api.security.microsoft.com','fc780465-2017-40d4-a0c5-307022471b92')) {throw 'Wrong token context'}
        if ([long](Field $claims 'exp') -lt [DateTimeOffset]::UtcNow.AddMinutes(2).ToUnixTimeSeconds()) {throw 'Expired token'}
    } catch {throw 'Defender token is malformed, expires soon, or does not match the expected tenant and Defender audience.'}
    finally {$plain=$null;$claims=$null;$payload=$null}
}
function Get-Freshness($Value,[DateTimeOffset]$AsOf,[int]$Hours) {
    $date=[DateTimeOffset]::MinValue
    if($Value -is [DateTime] -and $Value.Kind -eq [DateTimeKind]::Unspecified){return 'Unknown'}
    $text=DateText $Value
    if($text -notmatch '^\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2})$'){return 'Unknown'}
    if (-not [DateTimeOffset]::TryParse($text,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$date) -or $date.Year -lt 2000 -or $date -gt $AsOf.AddMinutes(5)) {return 'Unknown'}
    if (($AsOf-$date).TotalHours -gt $Hours) {return 'Stale'}
    return 'Recent'
}
function DateText($Value) {
    if ($Value -is [DateTimeOffset]) {return $Value.ToUniversalTime().ToString('o')}
    if ($Value -is [DateTime]) {return $Value.ToUniversalTime().ToString('o')}
    return [string]$Value
}
function CsvCell($Value) {
    $s=[string]$Value;if ($s -match '^[\s\p{Cf}]*[=+@-]') {$s="'"+$s}
    '"'+$s.Replace('"','""')+'"'
}
function Write-Csv([string]$Path,[object[]]$Rows,[string[]]$Columns) {
    $lines=[Collections.Generic.List[string]]::new();$lines.Add(($Columns | ForEach-Object {CsvCell $_}) -join ',')
    foreach ($row in $Rows) {$lines.Add(($Columns | ForEach-Object {CsvCell (Field $row $_)}) -join ',')}
    [IO.File]::WriteAllLines($Path,$lines,[Text.UTF8Encoding]::new($true))
}
function Html($Value) {[Net.WebUtility]::HtmlEncode([string]$Value)}
function Table([object[]]$Rows,[string[]]$Columns,[string]$Label) {
    if ($null -eq $Rows -or $Rows.Count -eq 0) {return '<p>No rows. Check collection coverage before interpreting this result.</p>'}
    $head=($Columns|ForEach-Object {'<th scope="col">'+(Html $_)+'</th>'}) -join ''
    $body=foreach ($r in $Rows) {'<tr>'+ (($Columns|ForEach-Object {'<td>'+(Html (Field $r $_))+'</td>'}) -join '') +'</tr>'}
    '<div class="table" role="region" tabindex="0" aria-label="'+(Html $Label)+'"><table><thead><tr>'+$head+'</tr></thead><tbody>'+($body -join '')+'</tbody></table></div>'
}
function Add-Coverage($List,[string]$DeviceId,[string]$Source,[string]$Section,$Read) {
    $List.Add([pscustomobject]@{DeviceId=$DeviceId;Source=$Source;Section=$Section;Complete=$Read.Complete;Rows=$Read.Items.Count;HttpStatus=$Read.HttpStatus;Reason=$Read.Reason})
}
function Add-Action($List,[string]$DeviceId,[string]$Name,[string]$Priority,[string]$Code,[string]$Detail,[string]$NextStep) {
    $List.Add([pscustomobject]@{DeviceId=$DeviceId;Device=$Name;Priority=$Priority;Code=$Code;Detail=$Detail;NextStep=$NextStep;Team='Unassigned'})
}
function Merge-ComplianceDisplayRows([object[]]$Rows) {
    foreach ($group in @($Rows|Group-Object DeviceId,PolicyId,Policy,PolicyState,Setting,State)) {
        $r=$group.Group[0]
        [pscustomobject]@{Device=$r.Device;DeviceId=$r.DeviceId;PolicyId=$r.PolicyId;Policy=$r.Policy;PolicyState=$r.PolicyState;Setting=$r.Setting;State=$r.State;ReportedInstances=$group.Count}
    }
}
function Build-DeviceResult([string]$Id,$Device,$MachineRead,$VulnRead,$ContextRead,[DateTimeOffset]$AsOf,[int]$Hours) {
    $row=[ordered]@{DeviceId=$Id;Device=[string](Field $Device 'deviceName');EntraDeviceId=[string](Field $Device 'azureADDeviceId');OS=[string](Field $Device 'operatingSystem');OSVersion=[string](Field $Device 'osVersion');Compliance=[string](Field $Device 'complianceState');Encrypted='Unknown';IntuneLastSync=[string](Field $Device 'lastSyncDateTime');IntuneFreshness='Unknown';DefenderMatch='Unknown';DefenderId='';DefenderLastSeen='';DefenderFreshness='Unknown';SensorHealth='Unknown';Onboarding='Unknown';Risk='Unknown';Exposure='Unknown';VulnerabilityRows=$null;UniqueCves=$null;VulnerabilityAssessment='NotAssessed'}
    $encrypted=Field $Device 'isEncrypted';if ($encrypted -is [bool]) {$row.Encrypted=if ($encrypted) {'Yes'} else {'No'}}
    $row.IntuneLastSync=DateText (Field $Device 'lastSyncDateTime')
    if (-not $row.Device) {$row.Device=$Id};if (-not $row.Compliance) {$row.Compliance='Unknown'}
    $row.IntuneFreshness=Get-Freshness $row.IntuneLastSync $AsOf $Hours
    $actions=[Collections.Generic.List[object]]::new();$vulnerabilities=[Collections.Generic.List[object]]::new()
    if (-not $Device) {Add-Action $actions $Id $row.Device 'Review' 'IntuneUnavailable' 'Device metadata could not be verified.' 'Check scope, permissions and device identifier.'}
    if ($row.IntuneFreshness -ne 'Recent') {Add-Action $actions $Id $row.Device 'Review' 'IntuneDataAge' $row.IntuneFreshness 'Check connectivity and last Intune check-in before trusting this status.'}
    if ($row.Compliance -ne 'compliant') {Add-Action $actions $Id $row.Device 'Review' 'ComplianceReview' $row.Compliance 'Review compliance policies and grace periods in Intune.'}
    if ($row.Encrypted -eq 'No') {Add-Action $actions $Id $row.Device 'High' 'EncryptionNotReported' 'Intune reports isEncrypted=false.' 'Confirm local encryption and the applicable policy; do not infer protector or recovery-key status.'}
    $matches=@($MachineRead.Items | Where-Object {([string](Field $_ 'aadDeviceId')).Equals($row.EntraDeviceId,[StringComparison]::OrdinalIgnoreCase) -and $row.EntraDeviceId -and $row.EntraDeviceId -ne [guid]::Empty.ToString()})
    if (-not $MachineRead.Complete) {$row.DefenderMatch='NotVerified'}
    elseif ($matches.Count -eq 0) {$row.DefenderMatch='NoVisibleMatch'}
    elseif ($matches.Count -gt 1) {$row.DefenderMatch='Ambiguous'}
    else {
        $m=$matches[0];$row.DefenderMatch='ExactEntraId';$row.DefenderId=[string](Field $m 'id')
        foreach ($pair in @(@('DefenderLastSeen','lastSeen'),@('SensorHealth','healthStatus'),@('Onboarding','onboardingStatus'),@('Risk','riskScore'),@('Exposure','exposureLevel'))) {$value=Field $m $pair[1];if ($null -ne $value) {$row[$pair[0]]=[string]$value}}
        $row.DefenderLastSeen=DateText (Field $m 'lastSeen')
        $row.DefenderFreshness=Get-Freshness $row.DefenderLastSeen $AsOf $Hours
        if ($row.DefenderFreshness -ne 'Recent' -or $row.SensorHealth -ne 'Active' -or $row.Onboarding -ne 'Onboarded') {Add-Action $actions $Id $row.Device 'Review' 'DefenderTelemetry' 'Sensor, onboarding or data freshness needs review.' 'Verify device onboarding, sensor health and last seen in Defender.'}
        $context=@{};foreach ($c in $ContextRead.Items) {$context[[string](Field $c 'id')]=$c}
        foreach ($v in $VulnRead.Items) {
            if ((Field $v 'machineId') -ne $row.DefenderId) {throw 'Defender returned a row outside the selected device scope.'}
            $cve=[string](Field $v 'cveId');if ($cve -notmatch '^CVE-\d{4}-\d{4,}$') {throw 'Invalid CVE identifier.'}
            $severity=[string](Field $v 'severity');$exploit='Unknown';$cvss=$null
            if ($context.ContainsKey($cve)) {
                $c=$context[$cve];$cvss=Field $c 'cvssV3';$flags=@((Field $c 'publicExploit'),(Field $c 'exploitVerified'),(Field $c 'exploitInKit'))
                if (@($flags | Where-Object {$_ -is [bool] -and $_}).Count) {$exploit='Reported'}
                elseif (@($flags | Where-Object {$_ -is [bool]}).Count -eq 3) {$exploit='NotReported'}
            }
            $priority=if ($severity -eq 'Critical' -or ($severity -eq 'High' -and $exploit -eq 'Reported')) {'UrgentReview'} elseif ($severity -eq 'High') {'High'} elseif ($severity -in @('Medium','Low')) {'RoutineReview'} else {'ReviewUnknownSeverity'}
            $key=@($Id,$cve,(Field $v 'productVendor'),(Field $v 'productName'),(Field $v 'productVersion')) | ConvertTo-Json -Compress
            $vulnerabilities.Add([pscustomobject]@{Key=$key;DeviceId=$Id;Device=$row.Device;Cve=$cve;Vendor=[string](Field $v 'productVendor');Product=[string](Field $v 'productName');Version=[string](Field $v 'productVersion');Severity=$severity;Cvss=$cvss;ExploitIndicator=$exploit;FixingKb=[string](Field $v 'fixingKbId');Priority=$priority})
        }
        if ($VulnRead.Complete) {
            $row.VulnerabilityRows=$vulnerabilities.Count;$row.UniqueCves=@($vulnerabilities | ForEach-Object {$_.Cve} | Sort-Object -Unique).Count
            $row.VulnerabilityAssessment=if ($row.DefenderFreshness -ne 'Recent' -or $row.SensorHealth -ne 'Active' -or $row.Onboarding -ne 'Onboarded') {'CollectedWithTelemetryGap'} elseif ($row.Exposure -notin @('Low','Medium','High')) {'CollectedWithExposureGap'} elseif ($vulnerabilities.Count -eq 0) {'CollectedEmptyNeedsReview'} else {'Collected'}
            if ($row.Exposure -notin @('Low','Medium','High')) {
                if ($vulnerabilities.Count -eq 0) {$row.VulnerabilityRows=$null;$row.UniqueCves=$null}
                Add-Action $actions $Id $row.Device 'Review' 'ExposureAssessmentUnavailable' ('Defender exposure value: '+$row.Exposure) 'Confirm exposure and vulnerability data in Defender, especially after onboarding. Successful empty API reads do not establish a completed assessment; keep the device online and collect again.'
            }
            if ($vulnerabilities.Count -eq 0) {
                $row.VulnerabilityRows=$null;$row.UniqueCves=$null
                if ($row.Exposure -in @('Low','Medium','High')) {Add-Action $actions $Id $row.Device 'Review' 'EmptyAssessmentNeedsReview' ('No CVE/software rows returned; exposure: '+$row.Exposure+'; CVE context rows: '+$ContextRead.Items.Count) 'Review software inventory, discovered vulnerabilities and assessment availability in Defender. Empty responses can be legitimate, but these reads alone cannot distinguish zero findings from an unpopulated feed. Do not close previous findings from this result alone.'}
            }
        } else {$row.VulnerabilityAssessment='Incomplete'}
        if ($row.Risk -eq 'High') {Add-Action $actions $Id $row.Device 'UrgentReview' 'HighDeviceRisk' 'Defender reports High risk.' 'Review incidents and device timeline; vulnerability count is not an incident verdict.'}
    }
    if ($row.DefenderMatch -ne 'ExactEntraId' -or $row.VulnerabilityAssessment -eq 'Incomplete') {Add-Action $actions $Id $row.Device 'Review' 'VulnerabilityCoverageGap' $row.DefenderMatch 'Verify API permissions, device-group visibility, exact Entra ID and onboarding. Missing data is not zero vulnerabilities.'}
    [pscustomobject]@{Device=[pscustomobject]$row;Vulnerabilities=$vulnerabilities.ToArray();Actions=$actions.ToArray()}
}
function Compare-EndpointSnapshot($Current,$Previous) {
    $changes=[Collections.Generic.List[object]]::new()
    if (-not $Previous) {foreach ($v in $Current.Vulnerabilities) {$changes.Add([pscustomobject]@{Device=$v.Device;Cve=$v.Cve;Product=$v.Product;Version=$v.Version;Change='Baseline'})};return ,$changes.ToArray()}
    if ($Previous.SchemaVersion -ne 1 -or $Previous.TenantId -ne $Current.TenantId -or (($Previous.Scope|Sort-Object) -join ',') -ne (($Current.Scope|Sort-Object) -join ',') -or [DateTimeOffset]$Previous.CollectedAt -ge [DateTimeOffset]$Current.CollectedAt) {throw 'Previous snapshot is incompatible: tenant, schema, device scope or time differs.'}
    $old=@{};$new=@{};$oldDevices=@{};$newDevices=@{}
    foreach ($d in $Previous.Devices) {$oldDevices[$d.DeviceId]=$d};foreach ($d in $Current.Devices) {$newDevices[$d.DeviceId]=$d}
    foreach ($v in $Previous.Vulnerabilities) {$old[$v.Key]=$v};foreach ($v in $Current.Vulnerabilities) {$new[$v.Key]=$v}
    foreach ($key in @(@($old.Keys)+@($new.Keys)|Sort-Object -Unique)) {
        $v=if ($new.ContainsKey($key)) {$new[$key]} else {$old[$key]}
        $before=Field $oldDevices[$v.DeviceId] 'VulnerabilityAssessment';$after=Field $newDevices[$v.DeviceId] 'VulnerabilityAssessment'
        if ((Field $oldDevices[$v.DeviceId] 'VulnerabilityRows') -le 0) {$before='EmptyNeedsReview'}
        if ((Field $newDevices[$v.DeviceId] 'VulnerabilityRows') -le 0) {$after='EmptyNeedsReview'}
        $change=if ($old.ContainsKey($key) -and $new.ContainsKey($key)) {'StillObserved'} elseif ($new.ContainsKey($key)) {if ($before -eq 'Collected') {'NewlyObserved'} else {'FirstObservedAfterGap'}} else {if ($after -eq 'Collected') {'NoLongerObserved'} else {'PendingVerification'}}
        $changes.Add([pscustomobject]@{Device=$v.Device;Cve=$v.Cve;Product=$v.Product;Version=$v.Version;Change=$change})
    }
    return ,$changes.ToArray()
}
function Write-EndpointReport($Snapshot,[string]$OutputPath,$Previous) {
    $changes=Compare-EndpointSnapshot $Snapshot $Previous
    $incomplete=@($Snapshot.Coverage|Where-Object {-not $_.Complete}).Count
    $assessed=@($Snapshot.Devices|Where-Object VulnerabilityAssessment -eq 'Collected').Count
    $status=if ($incomplete -or $assessed -ne $Snapshot.Scope.Count) {'PARTIAL — coverage needs review'} else {'COMPLETE for the stated reads — not a security certification'}
    $summary=[ordered]@{Version=$script:Version;Status=$status;CollectedAt=$Snapshot.CollectedAt;RequestedDevices=$Snapshot.Scope.Count;DevicesWithCurrentVulnerabilityData=$assessed;DevicesNeedingAssessmentReview=($Snapshot.Scope.Count-$assessed);VulnerabilityRows=$Snapshot.Vulnerabilities.Count;UniqueCves=@($Snapshot.Vulnerabilities|ForEach-Object {$_.Cve}|Sort-Object -Unique).Count;IncompleteSections=$incomplete;Baseline=($null -eq $Previous);ReportPath=(Join-Path $OutputPath 'report.html')}
    $tables=[ordered]@{
        devices=@('Device','DeviceId','EntraDeviceId','OS','OSVersion','Compliance','Encrypted','IntuneLastSync','IntuneFreshness','DefenderMatch','DefenderId','DefenderLastSeen','DefenderFreshness','SensorHealth','Onboarding','Risk','Exposure','VulnerabilityRows','UniqueCves','VulnerabilityAssessment')
        vulnerabilities=@('Device','DeviceId','Cve','Vendor','Product','Version','Severity','Cvss','ExploitIndicator','FixingKb','Priority')
        compliance=@('Device','DeviceId','PolicyId','Policy','PolicyState','Setting','State','ReportedInstances')
        actions=@('Device','DeviceId','Priority','Code','Detail','NextStep','Team')
        coverage=@('DeviceId','Source','Section','Complete','Rows','HttpStatus','Reason')
        changes=@('Device','Cve','Product','Version','Change')
    }
    $sections=[Collections.Generic.List[string]]::new()
    foreach ($name in $tables.Keys) {
        $rows=Field $Snapshot $name
        if ($name -eq 'changes') {$rows=$changes}
        if ($null -eq $rows) {$rows=@()}
        Write-Csv (Join-Path $OutputPath "$name.csv") $rows $tables[$name]
        $sections.Add('<section id="'+$name+'"><h2>'+($name.Substring(0,1).ToUpper()+$name.Substring(1))+'</h2><p><a href="'+$name+'.csv">Download CSV</a></p>'+(Table $rows $tables[$name] $name)+'</section>')
    }
    $style=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'report.css') -Raw
    $historyText=if ($null -eq $Previous) {'First run: baseline only. No weekly improvement or remediation claim is made.'} else {'Compared with '+(Html $Previous.CollectedAt)+'. NoLongerObserved means absent from a complete current device assessment; it does not prove which remediation fixed it.'}
    $sampleNotice=switch (Field $Snapshot 'DataNature') {
        'Synthetic' {'<div class="notice"><strong>SYNTHETIC EXAMPLE — NOT TENANT EVIDENCE</strong><p>Device names, CVEs and results in this demonstration are fabricated test fixtures. Use the real pilot evidence in the guide to assess validation status.</p></div>'}
        'TenantCaptureReplay' {'<div class="notice"><strong>REBUILT FROM SAVED TENANT READS</strong><p>This report verifies the corrected transformation against previously collected tenant evidence. It is not a new API collection. Defender remains unassessed.</p></div>'}
        default {''}
    }
    $body=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Weekly endpoint security report</title><style>$style</style></head><body>
<header><p>INTUNE + MICROSOFT DEFENDER · READ ONLY</p><h1>Weekly endpoint security report</h1><p>Collected $(Html $Snapshot.CollectedAt) · Version $(Html $script:Version)</p></header><main>
$sampleNotice<div class="notice"><strong>$(Html $status)</strong><p>$(Html $assessed) / $($Snapshot.Scope.Count) selected devices have current vulnerability data. Compliance, device risk and vulnerability exposure answer different questions.</p></div>
<div class="cards"><div><strong>$($Snapshot.Scope.Count)</strong> devices in scope</div><div><strong>$assessed</strong> current vulnerability coverage</div><div><strong>$($Snapshot.Scope.Count-$assessed)</strong> devices needing assessment review</div><div><strong>$($Snapshot.Vulnerabilities.Count)</strong> returned CVE/software rows</div><div><strong>$incomplete</strong> incomplete collection sections</div></div>
<p>$historyText</p><p>Freshness review threshold: $($Snapshot.MaxDataAgeHours) hours, configured locally. Recent telemetry does not guarantee an immediate vulnerability scan. A blank count means no verified device assessment count. Missing exposure data keeps coverage partial even when every API read succeeds; any returned findings remain visible. Empty vulnerability responses also require review even when an exposure level is available: this version cannot distinguish zero findings from an unpopulated feed using those responses alone. Priorities are local triage suggestions, not Microsoft severity changes or proof of exploitation.</p>
<nav aria-label="Report sections"><a href="#actions">Actions</a> <a href="#devices">Devices</a> <a href="#vulnerabilities">Vulnerabilities</a> <a href="#compliance">Compliance</a> <a href="#coverage">Coverage</a> <a href="#changes">Changes</a></nav>
<label for="filter">Filter table rows</label><input id="filter" type="search" placeholder="Device, CVE, product or state"><p id="filter-status" role="status"></p>
$($sections -join "`n")
<footer>Tiago Carvalho · Local report. Protect device inventory and vulnerability details. No email was sent and no device or tenant setting was changed.</footer></main>
<script>document.getElementById('filter').addEventListener('input',function(){const q=this.value.toLowerCase();let shown=0;document.querySelectorAll('tbody tr').forEach(r=>{r.hidden=!r.textContent.toLowerCase().includes(q);if(!r.hidden)shown++;});document.getElementById('filter-status').textContent=shown+' matching rows across all tables';});</script></body></html>
"@
    [IO.File]::WriteAllText((Join-Path $OutputPath 'report.html'),$body,[Text.UTF8Encoding]::new($false))
    $Snapshot|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $OutputPath 'snapshot.json') -Encoding utf8
    $summary|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputPath 'summary.json') -Encoding utf8
    @("Endpoint security review — $($Snapshot.CollectedAt)",$status,"Selected devices: $($Snapshot.Scope.Count); current vulnerability coverage: $assessed; returned vulnerability rows: $($Snapshot.Vulnerabilities.Count).",'Review coverage and actions before sharing. The report was generated locally; no message was sent.')|Set-Content -LiteralPath (Join-Path $OutputPath 'weekly-summary.txt') -Encoding utf8
    [pscustomobject]$summary
}
function Invoke-EndpointSecurityReport {
    [CmdletBinding()]param([guid]$ExpectedTenantId,[guid[]]$ManagedDeviceId,[securestring]$DefenderAccessToken,[switch]$IntuneOnly,[string]$OutputPath,[string]$PreviousSnapshot,[int]$MaxDataAgeHours=48)
    $ErrorActionPreference='Stop';$ctx=Get-MgContext
    if (-not $ctx -or [string]$ctx.TenantId -ne $ExpectedTenantId.ToString() -or (Field $ctx 'Environment') -ne 'Global') {throw 'Connect Microsoft Graph to the expected tenant in the Global cloud first.'}
    if (-not $IntuneOnly) {if (-not $DefenderAccessToken) {throw 'A Defender access token is required unless IntuneOnly is explicit.'};Assert-DefenderToken $DefenderAccessToken $ExpectedTenantId.ToString()}
    if (Test-Path -LiteralPath $OutputPath) {throw 'Choose a new output directory. Existing reports are never overwritten.'}
    $previous=$null;if ($PreviousSnapshot) {$previous=Get-Content -LiteralPath $PreviousSnapshot -Raw|ConvertFrom-Json}
    $scope=@($ManagedDeviceId|ForEach-Object {$_.ToString()}|Sort-Object -Unique);$now=[DateTimeOffset]::UtcNow
    $session=@{Token=$DefenderAccessToken;Stopped=@{Intune=$false;Defender=$false}}
    $devices=[Collections.Generic.List[object]]::new();$vulns=[Collections.Generic.List[object]]::new();$coverage=[Collections.Generic.List[object]]::new();$actions=[Collections.Generic.List[object]]::new();$compliance=[Collections.Generic.List[object]]::new()
    foreach ($id in $scope) {
        $read=Read-Endpoint ('https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/'+$id+'?$select=id,deviceName,azureADDeviceId,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime') 'Intune' $false $session
        $device=if ($read.Complete -and $read.Items.Count -eq 1 -and (Field $read.Items[0] 'id') -eq $id) {$read.Items[0]} else {$null}
        if ($read.Complete -and -not $device) {throw 'Intune returned an unexpected device identifier.'}
        if ($device) {
            foreach ($fieldName in @('deviceName','azureADDeviceId','operatingSystem','osVersion','complianceState','lastSyncDateTime')) {
                if (-not (Field $device $fieldName)) {$read.Complete=$false;$read.Reason='RequiredMetadataMissing'}
            }
            if ((Field $device 'isEncrypted') -isnot [bool]) {$read.Complete=$false;$read.Reason='RequiredMetadataMissing'}
        }
        Add-Coverage $coverage $id 'Intune' 'Device' $read
        $empty=[pscustomobject]@{Items=@();Complete=$false;Reason='NotAttempted';HttpStatus=0;Pages=0}
        $machineRead=$empty;$vulnRead=$empty;$contextRead=$empty
        if ($device) {
            $policies=Read-Endpoint ('https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/'+$id+'/deviceCompliancePolicyStates') 'Intune' $true $session
            Add-Coverage $coverage $id 'Intune' 'CompliancePolicies' $policies
            foreach ($p in $policies.Items) {
                $settings=Field $p 'settingStates'
                if ($null -eq $settings -or $settings.Count -eq 0) {$settings=@(@{settingName='Policy summary; setting detail not returned';state=Field $p 'state'})}
                foreach ($s in $settings) {$compliance.Add([pscustomobject]@{Device=[string](Field $device 'deviceName');DeviceId=$id;PolicyId=[string](Field $p 'id');Policy=[string](Field $p 'displayName');PolicyState=[string](Field $p 'state');Setting=[string](Field $s 'settingName');State=[string](Field $s 'state')})}
                if ((Field $p 'state') -notin @('compliant','remediated','notApplicable','notAssigned')) {Add-Action $actions $id ([string](Field $device 'deviceName')) 'Review' 'CompliancePolicyReview' ([string](Field $p 'displayName')+': '+[string](Field $p 'state')) 'Review the failing or unknown settings and applicable grace period in Intune.'}
            }
            $aad=[string](Field $device 'azureADDeviceId');$parsed=[guid]::Empty
            if ($IntuneOnly) {$machineRead=[pscustomobject]@{Items=@();Complete=$false;Reason='IntuneOnlyRequested';HttpStatus=0;Pages=0}}
            elseif ([guid]::TryParse($aad,[ref]$parsed) -and $parsed -ne [guid]::Empty) {
                $machineRead=Read-Endpoint ('https://api.security.microsoft.com/api/machines?$top=10000&$filter='+[uri]::EscapeDataString("aadDeviceId eq $($parsed.ToString('D'))")) 'Defender' $true $session
                $matches=@($machineRead.Items|Where-Object {(Field $_ 'aadDeviceId') -eq $aad})
                if ($machineRead.Complete -and $matches.Count -eq 1) {
                    $mid=[string](Field $matches[0] 'id');if ($mid -notmatch '^[a-f0-9]{40,64}$') {throw 'Unexpected Defender machine identifier.'}
                    $vulnRead=Read-Endpoint ('https://api.security.microsoft.com/api/vulnerabilities/machinesVulnerabilities?$top=10000&$filter='+[uri]::EscapeDataString("machineId eq '$mid'")) 'Defender' $true $session
                    $contextRead=Read-Endpoint ("https://api.security.microsoft.com/api/machines/$mid/vulnerabilities") 'Defender' $true $session
                }
            }
        }
        Add-Coverage $coverage $id 'Defender' 'DeviceMatch' $machineRead
        Add-Coverage $coverage $id 'Defender' 'SoftwareVulnerabilities' $vulnRead
        Add-Coverage $coverage $id 'Defender' 'CveContext' $contextRead
        $result=Build-DeviceResult $id $device $machineRead $vulnRead $contextRead $now $MaxDataAgeHours
        $devices.Add($result.Device);foreach ($v in $result.Vulnerabilities) {$vulns.Add($v)};foreach ($a in $result.Actions) {$actions.Add($a)}
    }
    foreach ($g in @($vulns|Group-Object DeviceId,Vendor,Product,Version)) {
        $v=$g.Group[0]
        $unknownCount=@($g.Group|Where-Object Priority -eq 'ReviewUnknownSeverity').Count
        $priority=if (@($g.Group|Where-Object Priority -eq 'UrgentReview').Count) {'UrgentReview'} elseif (@($g.Group|Where-Object Priority -eq 'High').Count) {'High'} elseif ($unknownCount) {'ReviewUnknownSeverity'} else {'RoutineReview'}
        $nextStep='Review vendor updates, applicability and deployment plan. Reassess after deployment; do not close from the installation result alone.'
        if ($unknownCount) {$nextStep+=" Confirm severity for $unknownCount finding(s) with missing or unrecognized severity before downgrading this group."}
        Add-Action $actions $v.DeviceId $v.Device $priority 'SoftwareRemediationReview' "$($v.Product) $($v.Version): $($g.Count) CVE/software rows" $nextStep
    }
    $snapshot=[pscustomobject]@{SchemaVersion=1;Version=$script:Version;TenantId=$ExpectedTenantId.ToString();CollectedAt=$now.ToString('o');MaxDataAgeHours=$MaxDataAgeHours;Scope=$scope;Devices=$devices.ToArray();Vulnerabilities=$vulns.ToArray();Compliance=@(Merge-ComplianceDisplayRows $compliance.ToArray());Coverage=$coverage.ToArray();Actions=$actions.ToArray()}
    $null=Compare-EndpointSnapshot $snapshot $previous
    $null=New-Item -ItemType Directory -Path $OutputPath
    Write-EndpointReport $snapshot ([IO.Path]::GetFullPath($OutputPath)) $previous
}
Export-ModuleMember -Function Invoke-EndpointSecurityReport,Read-EndpointRunConfiguration
