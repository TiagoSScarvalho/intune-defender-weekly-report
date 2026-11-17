#requires -Version 7.4
$ErrorActionPreference='Stop'
$module=Import-Module (Join-Path $PSScriptRoot '../EndpointSecurityReport.psm1') -Force -PassThru
& $module {
    $script:Checks=0
    function Assert($Condition,[string]$Message) {if (-not $Condition) {throw "FAIL: $Message"};$script:Checks++;Write-Host "PASS: $Message"}
    function Throws([scriptblock]$Action,[string]$Message) {$thrown=$false;try {& $Action|Out-Null} catch {$thrown=$true};Assert $thrown $Message}
    function ReadResult($Items=@(),$Complete=$true) {[pscustomobject]@{Items=@($Items);Complete=$Complete;Reason='';HttpStatus=0;Pages=1}}
    $id='11111111-1111-4111-8111-111111111111';$aad='22222222-2222-4222-8222-222222222222';$tenant='33333333-3333-4333-8333-333333333333';$mid='a'*40;$now=[DateTimeOffset]::UtcNow
    $device=@{id=$id;deviceName='SYNTHETIC-LAB';azureADDeviceId=$aad;operatingSystem='Windows';osVersion='10.0.test';complianceState='compliant';isEncrypted=$true;lastSyncDateTime=$now.AddHours(-1).ToString('o')}
    $machine=@{id=$mid;aadDeviceId=$aad;computerDnsName='different-name';lastSeen=$now.AddHours(-1).ToString('o');healthStatus='Active';onboardingStatus='Onboarded';riskScore='Low';exposureLevel='High'}
    $v=@{id='row1';machineId=$mid;cveId='CVE-2026-99999';productName='SYNTHETIC-PRODUCT';productVendor='SYNTHETIC';productVersion='1.0';severity='High';fixingKbId=''}
    $context=@{id=$v.cveId;cvssV3=8.1;publicExploit=$true;exploitVerified=$false;exploitInKit=$false}
    $empty=ReadResult;$unavailable=ReadResult @() $false;$mr=ReadResult @($machine);$vr=ReadResult @($v);$cr=ReadResult @($context)
    $result=Build-DeviceResult $id $device $mr $vr $cr $now 48
    Assert ($result.Device.DefenderMatch -eq 'ExactEntraId') 'Match uses Entra ID despite different hostname'
    Assert ($result.Device.Compliance -eq 'compliant' -and $result.Device.UniqueCves -eq 1) 'Compliant can still have a vulnerability'
    Assert ($result.Device.Risk -eq 'Low' -and $result.Device.Exposure -eq 'High') 'Risk and exposure remain separate'
    Assert ($result.Vulnerabilities[0].Priority -eq 'UrgentReview') 'High severity plus exploit indicator requires urgent review'
    Assert ($result.Vulnerabilities[0].FixingKb -eq '') 'Missing KB is not a claim that no fix exists'
    $zero=Build-DeviceResult $id $device $mr $empty $empty $now 48
    Assert ($null -eq $zero.Device.VulnerabilityRows -and $zero.Device.VulnerabilityAssessment -eq 'CollectedEmptyNeedsReview') 'Empty API responses require review even with available exposure'
    foreach ($knownExposure in @('Low','Medium','High')) {
        $emptyMachine=$machine.Clone();$emptyMachine.exposureLevel=$knownExposure
        $emptyAssessment=Build-DeviceResult $id $device (ReadResult @($emptyMachine)) $empty $empty $now 48
        Assert ($emptyAssessment.Device.VulnerabilityAssessment -eq 'CollectedEmptyNeedsReview' -and $null -eq $emptyAssessment.Device.UniqueCves -and @($emptyAssessment.Actions|Where-Object Code -eq 'EmptyAssessmentNeedsReview').Count -eq 1) "Exposure $knownExposure cannot verify an empty vulnerability feed"
    }
    $contextOnly=Build-DeviceResult $id $device $mr $empty $cr $now 48
    Assert ($contextOnly.Device.VulnerabilityAssessment -eq 'CollectedEmptyNeedsReview') 'CVE context without software rows cannot become a verified zero'
    foreach ($exposure in @('None','Unknown','')) {
        $initial=$machine.Clone();$initial.exposureLevel=$exposure
        $initialResult=Build-DeviceResult $id $device (ReadResult @($initial)) $empty $empty $now 48
        Assert ($null -eq $initialResult.Device.UniqueCves -and $initialResult.Device.VulnerabilityAssessment -ne 'Collected') "Unavailable exposure '$exposure' cannot turn empty responses into a zero-CVE assessment"
    }
    Assert (@($initialResult.Actions|Where-Object Code -eq 'ExposureAssessmentUnavailable').Count -eq 1) 'Unavailable exposure produces an administrator follow-up action'
    $initialFinding=Build-DeviceResult $id $device (ReadResult @($initial)) $vr $cr $now 48
    Assert ($initialFinding.Vulnerabilities.Count -eq 1 -and $initialFinding.Device.UniqueCves -eq 1 -and $initialFinding.Device.VulnerabilityAssessment -ne 'Collected') 'Observed findings remain visible when exposure data is unavailable'
    $gap=Build-DeviceResult $id $device $empty $empty $empty $now 48
    Assert ($null -eq $gap.Device.VulnerabilityRows -and $gap.Device.DefenderMatch -eq 'NoVisibleMatch') 'Missing Defender device remains unassessed'
    $gap=Build-DeviceResult $id $device $unavailable $empty $empty $now 48
    Assert ($gap.Device.DefenderMatch -eq 'NotVerified') 'Denied or failed inventory is not no match'
    $dup=Build-DeviceResult $id $device (ReadResult @($machine,$machine)) $vr $cr $now 48
    Assert ($dup.Device.DefenderMatch -eq 'Ambiguous' -and $null -eq $dup.Device.UniqueCves) 'Ambiguous device identifiers cannot be selected silently'
    $stale=$machine.Clone();$stale.lastSeen=$now.AddDays(-7).ToString('o')
    $staleResult=Build-DeviceResult $id $device (ReadResult @($stale)) $empty $empty $now 48
    Assert ($staleResult.Device.VulnerabilityAssessment -eq 'CollectedWithTelemetryGap') 'Stale zero rows are not current coverage'
    $unknown=$device.Clone();$unknown.Remove('isEncrypted');$unknown.lastSyncDateTime='invalid'
    $r=Build-DeviceResult $id $unknown $mr $empty $empty $now 48
    Assert ($r.Device.Encrypted -eq 'Unknown' -and $r.Device.IntuneFreshness -eq 'Unknown') 'Missing fields stay unknown'
    Assert ((Get-Freshness $now.AddHours(1).ToString('o') $now 48) -eq 'Unknown') 'Future telemetry timestamps are not recent'
    $cultureBefore=[Threading.Thread]::CurrentThread.CurrentCulture
    try {
        foreach($culture in @('pt-PT','en-US')) {
            [Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo($culture)
            $recentTime=$now.AddHours(-1)
            $jsonTime=('{"time":"'+$recentTime.ToString('o')+'"}'|ConvertFrom-Json).time
            Assert ((Get-Freshness $recentTime.UtcDateTime $now 48) -eq 'Recent') "Typed UTC timestamps preserve freshness in $culture"
            Assert ((Get-Freshness $recentTime $now 48) -eq 'Recent') "DateTimeOffset preserves freshness in $culture"
            Assert ((Get-Freshness $jsonTime $now 48) -eq 'Recent') "JSON dates preserve freshness in $culture"
            Assert ((Get-Freshness '11/16/2026 12:00:00' $now 48) -eq 'Unknown') "Ambiguous date strings remain unknown in $culture"
        }
    }finally{[Threading.Thread]::CurrentThread.CurrentCulture=$cultureBefore}
    $r=Build-DeviceResult $id $device $mr $vr $unavailable $now 48
    Assert ($r.Vulnerabilities[0].ExploitIndicator -eq 'Unknown') 'Missing exploit context is not no exploit'
    $bad=$v.Clone();$bad.machineId='b'*40
    Throws {Build-DeviceResult $id $device $mr (ReadResult @($bad)) $cr $now 48} 'Cross-device vulnerability response rejected'
    $base=[pscustomobject]@{SchemaVersion=1;TenantId=$tenant;Scope=@($id);CollectedAt=$now.AddDays(-7).ToString('o');Devices=@($result.Device);Vulnerabilities=@($result.Vulnerabilities)}
    $current=[pscustomobject]@{SchemaVersion=1;TenantId=$tenant;Scope=@($id);CollectedAt=$now.ToString('o');Devices=@($zero.Device);Vulnerabilities=@()}
    $delta=Compare-EndpointSnapshot $current $base
    Assert ($delta[0].Change -eq 'PendingVerification') 'An entirely empty current feed cannot close a previous vulnerability'
    $remaining=$v.Clone();$remaining.cveId='CVE-2026-99998'
    $remainingResult=Build-DeviceResult $id $device $mr (ReadResult @($remaining)) $cr $now 48
    $current.Devices=@($remainingResult.Device);$current.Vulnerabilities=@($remainingResult.Vulnerabilities)
    $delta=Compare-EndpointSnapshot $current $base
    Assert (($delta|Where-Object Cve -eq $v.cveId).Change -eq 'NoLongerObserved') 'An absent row in a current nonempty feed remains no longer observed, not a patch verdict'
    $legacyEmpty=$zero.Device.PSObject.Copy();$legacyEmpty.VulnerabilityAssessment='Collected';$legacyEmpty.VulnerabilityRows=0;$legacyEmpty.UniqueCves=0
    $legacyPrevious=$base.PSObject.Copy();$legacyPrevious.Devices=@($legacyEmpty);$legacyPrevious.Vulnerabilities=@()
    $legacyDelta=Compare-EndpointSnapshot $current $legacyPrevious
    Assert ($legacyDelta[0].Change -eq 'FirstObservedAfterGap') 'Legacy empty snapshots cannot establish prior verified coverage'
    $legacyCurrent=$current.PSObject.Copy();$legacyCurrent.Devices=@($legacyEmpty);$legacyCurrent.Vulnerabilities=@()
    $legacyDelta=Compare-EndpointSnapshot $legacyCurrent $base
    Assert ($legacyDelta[0].Change -eq 'PendingVerification') 'Legacy empty snapshots cannot close previously observed findings'
    $current.Vulnerabilities=@()
    $current.Devices=@($initialResult.Device);$delta=Compare-EndpointSnapshot $current $base
    Assert ($delta[0].Change -eq 'PendingVerification') 'Unavailable exposure cannot close a previously observed vulnerability'
    $current.Devices=@($staleResult.Device);$delta=Compare-EndpointSnapshot $current $base
    Assert ($delta[0].Change -eq 'PendingVerification') 'Stale data cannot close a previous vulnerability'
    $current.Devices=@($gap.Device);$delta=Compare-EndpointSnapshot $current $base
    Assert ($delta[0].Change -eq 'PendingVerification') 'Missing source cannot close a previous vulnerability'
    $current.Vulnerabilities=@($result.Vulnerabilities);$delta=Compare-EndpointSnapshot $current $base
    Assert ($delta[0].Change -eq 'StillObserved') 'Finding present in both snapshots remains observed'
    $base.Vulnerabilities=@();$base.Devices=@($gap.Device);$delta=Compare-EndpointSnapshot $current $base
    Assert ($delta[0].Change -eq 'FirstObservedAfterGap') 'Absent prior coverage is not a newly introduced vulnerability'
    $base.TenantId=[guid]::NewGuid().ToString();Throws {Compare-EndpointSnapshot $current $base} 'Cross-tenant snapshot rejected'
    $base.TenantId=$tenant;$base.Scope=@([guid]::NewGuid().ToString());Throws {Compare-EndpointSnapshot $current $base} 'Different snapshot scope rejected'
    $url="https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$id/deviceCompliancePolicyStates"
    Assert (Test-ReadUri ($url+'?$skiptoken=abc') $url 'Intune') 'Same-path Graph pagination accepted'
    foreach ($badUrl in @($url.Replace('https:','http:'),$url.Replace('graph.microsoft.com','evil.example'),$url.Replace('graph.microsoft.com','graph.microsoft.com:444'),$url.Replace('deviceCompliancePolicyStates','wipe'),($url+'#x'))) {Assert (-not (Test-ReadUri $badUrl $url 'Intune')) 'Unsafe pagination rejected'}
    $script:Requests=0
    function Request-Read {param($Uri,$Source,$Token);$script:Requests++;[pscustomobject]@{value=@(@{id='p1'});'@odata.nextLink'=$Uri}}
    $session=@{Token=$null;Stopped=@{Intune=$false;Defender=$false}}
    $r=Read-Endpoint $url 'Intune' $true $session
    Assert (-not $r.Complete -and $r.Reason -eq 'InvalidOrExcessivePagination' -and $script:Requests -eq 1) 'Pagination cycle stops after one request'
    function Request-Read {param($Uri,$Source,$Token);[pscustomobject]@{value=@(@{id='policy1';state='compliant'},@{id='policy1';state='nonCompliant'})}}
    $r=Read-Endpoint $url 'Intune' $true $session
    Assert ($r.Complete -and $r.Items.Count -eq 2) 'Repeated compliance policy IDs preserve distinct returned states'
    $rows=@(@{Device='Demo';DeviceId=$id;PolicyId='p';Policy='Policy';PolicyState='compliant';Setting='Summary';State='compliant'},@{Device='Demo';DeviceId=$id;PolicyId='p';Policy='Policy';PolicyState='compliant';Setting='Summary';State='compliant'},@{Device='Demo';DeviceId=$id;PolicyId='p';Policy='Policy';PolicyState='nonCompliant';Setting='Summary';State='nonCompliant'})
    $merged=@(Merge-ComplianceDisplayRows $rows)
    Assert ($merged.Count -eq 2 -and ($merged|Where-Object State -eq 'compliant').ReportedInstances -eq 2) 'Only identical displayed compliance rows are folded with instance count'
    function Request-Read {throw [Net.Http.HttpRequestException]::new('secret error payload',$null,[Net.HttpStatusCode]::TooManyRequests)}
    $r=Read-Endpoint $url 'Intune' $true $session
    Assert ($r.HttpStatus -eq 429 -and $r.Reason -eq 'Throttled') '429 safely categorised without raw error'
    $r=Read-Endpoint $url 'Intune' $true $session
    Assert ($r.Reason -eq 'StoppedAfterServiceFailure') 'No blind polling after throttling'
    Assert ((CsvCell '=HYPERLINK("bad")').StartsWith('"''=')) 'CSV formula injection neutralised'
    Assert ((Html '<script>alert(1)</script>') -eq '&lt;script&gt;alert(1)&lt;/script&gt;') 'HTML values encoded'
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('endpoint-report-test-'+[guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp|Out-Null
    $configDirectory=New-Item -ItemType Directory -Path (Join-Path $tmp 'config')
    $configPath=Join-Path $configDirectory.FullName 'runner-config.json'
    $validConfig=@{TenantId=$tenant;ClientId=$aad;ManagedDeviceIds=@($id);CertificateThumbprint=('a'*40);MaxDataAgeHours=48}
    $validConfig|ConvertTo-Json|Set-Content -LiteralPath $configPath
    $parsed=Read-EndpointRunConfiguration $configPath
    Assert ($parsed.ManagedDeviceIds.Count -eq 1 -and $parsed.MaxDataAgeHours -eq 48) 'Certificate runner accepts explicit valid read scope'
    foreach ($test in @(
        @{Field='TenantId';Value=([guid]::Empty.ToString());Reason='Placeholder tenant rejected before authentication'},
        @{Field='ClientId';Value=([guid]::Empty.ToString());Reason='Placeholder application rejected before authentication'},
        @{Field='ManagedDeviceIds';Value=@($id,$id);Reason='Duplicate managed-device IDs rejected'},
        @{Field='ManagedDeviceIds';Value=@([guid]::Empty.ToString());Reason='Placeholder device rejected'},
        @{Field='ManagedDeviceIds';Value=$id;Reason='Scalar device scope rejected'},
        @{Field='CertificateThumbprint';Value=('0'*40);Reason='Placeholder certificate rejected'},
        @{Field='MaxDataAgeHours';Value=48.5;Reason='Fractional data age rejected'},
        @{Field='MaxDataAgeHours';Value=721;Reason='Excessive data age rejected'}
    )) {
        $invalid=$validConfig.Clone();$invalid[$test.Field]=$test.Value
        $invalid|ConvertTo-Json|Set-Content -LiteralPath $configPath
        Throws {Read-EndpointRunConfiguration $configPath} $test.Reason
    }
    $snap=[pscustomobject]@{SchemaVersion=1;Version=$script:Version;TenantId=$tenant;CollectedAt=$now.ToString('o');MaxDataAgeHours=48;Scope=@($id);Devices=@($gap.Device);Vulnerabilities=@();Compliance=@();Actions=@($gap.Actions);Coverage=@(@{DeviceId=$id;Source='Defender';Section='SoftwareVulnerabilities';Complete=$false;Rows=0;HttpStatus=403;Reason='AccessDenied'})}
    $summary=Write-EndpointReport $snap $tmp $null
    Assert ($summary.Status.StartsWith('PARTIAL') -and $summary.DevicesWithCurrentVulnerabilityData -eq 0) 'No coverage produces partial report'
    Assert (@(Get-Content (Join-Path $tmp 'vulnerabilities.csv')).Count -eq 1) 'Empty CSV still contains columns'
    Assert ((Get-Content (Join-Path $tmp 'report.html') -Raw).Contains('First run: baseline only')) 'Baseline clearly labelled'
    Assert ((Get-ChildItem $tmp -File).Count -eq 10) 'HTML, six CSVs, snapshot, summary and weekly text generated'
    $initialSnapshot=$snap.PSObject.Copy();$initialSnapshot.Devices=@($initialResult.Device);$initialSnapshot.Actions=@($initialResult.Actions);$initialSnapshot.Coverage=@(@{DeviceId=$id;Source='Defender';Section='SoftwareVulnerabilities';Complete=$true;Rows=0;HttpStatus=0;Reason=''})
    $initialOutput=Join-Path $tmp 'initial-assessment';New-Item -Path $initialOutput -ItemType Directory|Out-Null
    $initialSummary=Write-EndpointReport $initialSnapshot $initialOutput $null
    Assert ($initialSummary.Status.StartsWith('PARTIAL') -and $initialSummary.IncompleteSections -eq 0 -and $initialSummary.DevicesNeedingAssessmentReview -eq 1) 'Successful reads still produce partial coverage when assessment data is unavailable'
    Assert ((Import-Csv (Join-Path $initialOutput 'devices.csv')).UniqueCves -eq '' -and (Get-Content (Join-Path $initialOutput 'report.html') -Raw).Contains('Missing exposure data keeps coverage partial')) 'CSV and HTML preserve the initial assessment gap'
    $emptySnapshot=$initialSnapshot.PSObject.Copy();$emptySnapshot.Devices=@($zero.Device);$emptySnapshot.Actions=@($zero.Actions)
    $emptyOutput=Join-Path $tmp 'empty-assessment';New-Item -Path $emptyOutput -ItemType Directory|Out-Null
    $emptySummary=Write-EndpointReport $emptySnapshot $emptyOutput $null
    Assert ($emptySummary.Status.StartsWith('PARTIAL') -and $emptySummary.IncompleteSections -eq 0 -and $emptySummary.DevicesNeedingAssessmentReview -eq 1) 'Empty findings stay partial independently of API completion'
    Assert ((Import-Csv (Join-Path $emptyOutput 'devices.csv')).UniqueCves -eq '' -and (Get-Content (Join-Path $emptyOutput 'report.html') -Raw).Contains('Empty vulnerability responses also require review')) 'HTML and CSV explain empty-result review without fabricating a zero'
    function Get-MgContext {[pscustomobject]@{TenantId=$tenant;Environment='Global'}}
    function Request-Read {
        param($Uri,$Source,$Token)
        if ($Source -ne 'Intune') {throw 'Unexpected network source'}
        if ($Uri -match '/deviceCompliancePolicyStates') {return [pscustomobject]@{value=@(@{id='policy1';displayName='Synthetic policy';state='compliant';settingStates=@(@{settingName='Synthetic setting';state='compliant'})})}}
        return $device
    }
    $out=Join-Path $tmp 'collector'
    $r=Invoke-EndpointSecurityReport -ExpectedTenantId $tenant -ManagedDeviceId @($id) -IntuneOnly -OutputPath $out
    $rows=@(Import-Csv (Join-Path $out 'compliance.csv'))
    Assert ($rows.Count -eq 1 -and $rows[0].Setting -eq 'Synthetic setting') 'End-to-end collector preserves individual compliance setting rows'
    $rows=@(Import-Csv (Join-Path $out 'devices.csv'))
    Assert ($rows.Count -eq 1 -and $rows[0].Device -eq 'SYNTHETIC-LAB') 'End-to-end collector writes one selected device'
    Assert ($r.Status.StartsWith('PARTIAL') -and $r.IncompleteSections -eq 3) 'Intune-only mode explicitly leaves all Defender reads incomplete'
    Assert ($rows[0].Device -eq 'SYNTHETIC-LAB') 'Selected device identity remains stable'
    Throws {Invoke-EndpointSecurityReport -ExpectedTenantId ([guid]::NewGuid()) -ManagedDeviceId @($id) -IntuneOnly -OutputPath (Join-Path $tmp 'wrong')} 'Wrong Graph tenant stops collection'
    Throws {Invoke-EndpointSecurityReport -ExpectedTenantId $tenant -ManagedDeviceId @($id) -IntuneOnly -OutputPath $out} 'Existing output cannot be overwritten'
    function Assert-DefenderToken {param($Token,$Tenant)}
    $script:DefenderRequests=[Collections.Generic.List[string]]::new()
    function Request-Read {
        param($Uri,$Source,$Token)
        if ($Source -eq 'Intune') {
            if ($Uri -match '/deviceCompliancePolicyStates') {return [pscustomobject]@{value=@()}}
            return $device
        }
        $script:DefenderRequests.Add($Uri)
        $decoded=[uri]::UnescapeDataString(([uri]$Uri).Query)
        if (([uri]$Uri).AbsolutePath -ne '/api/machines' -or $decoded -ne ('?$top=10000&$filter=aadDeviceId eq '+$aad)) {
            throw [Net.Http.HttpRequestException]::new('Expected an exact GUID filter, not a quoted string',$null,[Net.HttpStatusCode]::BadRequest)
        }
        [pscustomobject]@{value=@()}
    }
    $emptyDefender=Join-Path $tmp 'empty-defender'
    $r=Invoke-EndpointSecurityReport -ExpectedTenantId $tenant -ManagedDeviceId @($id) -DefenderAccessToken (ConvertTo-SecureString 'synthetic-not-a-token' -AsPlainText -Force) -OutputPath $emptyDefender
    $rows=@(Import-Csv (Join-Path $emptyDefender 'devices.csv'))
    $coverage=@(Import-Csv (Join-Path $emptyDefender 'coverage.csv'))
    Assert (($coverage|Where-Object Section -eq 'DeviceMatch').Complete -eq 'True') 'Defender inventory uses an unquoted canonical GUID filter'
    Assert ($rows[0].DefenderMatch -eq 'NoVisibleMatch' -and $rows[0].VulnerabilityRows -eq '') 'Successful empty inventory remains unassessed, with no zero-CVE claim'
    Assert ($script:DefenderRequests.Count -eq 1) 'No vulnerability request is sent without a matched Defender device'
    Assert ($r.Status.StartsWith('PARTIAL') -and $r.IncompleteSections -eq 2) 'Completed empty inventory leaves only vulnerability sections incomplete'
    $priorityCases=@(
        @{Name='missing';Severities=@($null);Expected='ReviewUnknownSeverity'},
        @{Name='unrecognized';Severities=@('Unexpected');Expected='ReviewUnknownSeverity'},
        @{Name='mixed-low';Severities=@($null,'Low');Expected='ReviewUnknownSeverity'},
        @{Name='mixed-high';Severities=@($null,'High');Expected='High'},
        @{Name='mixed-critical';Severities=@($null,'Critical');Expected='UrgentReview'}
    )
    function Request-Read {
        param($Uri,$Source,$Token)
        $path=([uri]$Uri).AbsolutePath
        if ($Source -eq 'Intune') {
            if ($path.EndsWith('/deviceCompliancePolicyStates')) {return @{value=@()}}
            return $device
        }
        if ($path -eq '/api/machines') {return @{value=@($machine)}}
        if ($path -eq '/api/vulnerabilities/machinesVulnerabilities') {return @{value=@($script:PriorityRows)}}
        if ($path -eq "/api/machines/$mid/vulnerabilities") {return @{value=@()}}
        throw 'Unexpected request; offline fixtures only.'
    }
    foreach ($case in $priorityCases) {
        $script:PriorityRows=@(for ($n=0;$n -lt $case.Severities.Count;$n++) {
            @{id="priority-$n";machineId=$mid;cveId=('CVE-2099-'+(90000+$n));productName='SYNTHETIC-PRODUCT';productVendor='SYNTHETIC';productVersion='1.0';severity=$case.Severities[$n]}
        })
        $priorityOutput=Join-Path $tmp ('priority-'+$case.Name)
        $null=Invoke-EndpointSecurityReport -ExpectedTenantId $tenant -ManagedDeviceId @($id) -DefenderAccessToken (ConvertTo-SecureString 'synthetic-not-a-token' -AsPlainText -Force) -OutputPath $priorityOutput
        $findings=@(Import-Csv (Join-Path $priorityOutput 'vulnerabilities.csv'))
        $queue=@(Import-Csv (Join-Path $priorityOutput 'actions.csv')|Where-Object Code -eq 'SoftwareRemediationReview')
        Assert ($findings[0].Priority -eq 'ReviewUnknownSeverity' -and $queue.Count -eq 1 -and $queue[0].Priority -eq $case.Expected) "Unknown severity remains explicit in grouped action: $($case.Name)"
        Assert ($queue[0].NextStep.Contains('Confirm severity for 1 finding(s)')) "Mixed priorities retain the severity follow-up: $($case.Name)"
        Assert ((Get-Content (Join-Path $priorityOutput 'report.html') -Raw).Contains('Confirm severity for 1 finding(s)')) "HTML retains the severity follow-up: $($case.Name)"
    }
    Write-Host "Passed $script:Checks checks. Synthetic test artifacts: $tmp"
}
