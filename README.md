# Intune and Defender weekly endpoint report

Read-only PowerShell reporting for a selected set of Intune devices, their compliance policy states, and matching Microsoft Defender vulnerability findings. Written by [Tiago Carvalho](https://www.tiagoscarvalho.com).

**Public preview: 0.1.0-rc.4. Not a production release.** A live one-device certificate collection returned 715 CVE/software rows and 640 distinct CVEs, matching the portal total. The corrected candidate passed 97 local regression checks and a fresh tenant run. The tests use synthetic fixtures; the separate pilot evidence and deployment limitations are recorded in [validation](docs/VALIDATION.md).

[Administrator guide and real screenshots](https://www.tiagoscarvalho.com/microsoft-intune/intune-defender-weekly-security-report) · [Download the versioned package](https://github.com/TiagoSScarvalho/intune-defender-weekly-report/releases/tag/v0.1.0-rc.4)

## What you get

- A self-contained, searchable HTML report with mobile-friendly tables.
- `devices.csv`: identity matching, compliance, encryption metadata, freshness, Defender health, risk and exposure.
- `vulnerabilities.csv`: device/CVE/software/version rows, severity, exploit indicators and fixing KB when returned.
- `compliance.csv`: returned policy and setting states. This is not a universal security baseline.
- `actions.csv`: triage suggestions, with an initially unassigned team column.
- `coverage.csv`: query completion, missing access, failures and unattempted sections.
- `changes.csv`: comparison with an explicitly supplied previous snapshot.
- `snapshot.json`, `summary.json`, and a short `weekly-summary.txt` for human review.

No policies, devices, permissions, assignments or remediation tasks are changed. No email is sent. No scheduled task is installed. The collector calls only GET endpoints. Authentication establishes sessions but does not grant permissions.

## Requirements and boundaries

PowerShell 7.4+ and `Microsoft.Graph.Authentication` 2.37.0+. Global Microsoft cloud only. The optional certificate runner also requires `Az.Accounts` 5.0.0+ and a Windows certificate store accessible to its run identity.

The device must be enrolled in Intune, visible to the caller, and separately onboarded to the licensed Defender service to return vulnerability data. An Intune Compliant state does not imply Defender coverage or absence of vulnerabilities. Defender for Business includes core vulnerability-management capabilities, but verify the specific API access and feature entitlement in your own tenant. No advanced hunting is used.

The current implementation takes 1–500 explicit **Intune managed-device IDs**. It is a bounded pilot/team collector, not a full-tenant high-volume export. It matches Defender records using the **Entra device ID**. It never picks a duplicate by hostname or silently chooses the newest matching object.

| Source | Delegated pilot permission | Application permission for an approved scheduled identity |
|---|---|---|
| Microsoft Graph | `DeviceManagementManagedDevices.Read.All` | `DeviceManagementManagedDevices.Read.All` |
| Microsoft Graph | `DeviceManagementConfiguration.Read.All` | `DeviceManagementConfiguration.Read.All` |
| WindowsDefenderATP | `Machine.Read` | `Machine.Read.All` |
| WindowsDefenderATP | `Vulnerability.Read` | `Vulnerability.Read.All` |

Permissions need appropriate admin consent and licensing. Delegated access also depends on user/device-group visibility. **Application permissions can expose tenant-wide endpoint/security data even when this script selects one device. The selected ID list is a collection limit, not an authorization boundary.** Do not grant write, isolation, remediation, mail or directory-write permissions for this report.

## Start with Intune only

Extract the release ZIP and open PowerShell 7 in the extracted folder containing `Get-EndpointSecurityReport.ps1`. The `./` paths below refer to that folder. For example, use `Set-Location -LiteralPath 'C:\Tools\intune-defender-weekly-report'`, replacing the path with your actual extraction folder. Install the Microsoft module from the PowerShell Gallery if it is not already available. Review the module and the scripts before running. Local administrator rights are not needed for the collector.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -MinimumVersion 2.37.0
Connect-MgGraph -TenantId '<tenant-guid>' -ContextScope Process -NoWelcome `
    -Scopes 'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All'

./Get-EndpointSecurityReport.ps1 `
    -ExpectedTenantId '<tenant-guid>' `
    -ManagedDeviceId '<intune-managed-device-guid>' `
    -IntuneOnly `
    -OutputPath './Reports/Pilot-01'

Disconnect-MgGraph
```

Use an account/role approved for the required reads. Check any new consent prompt before accepting it. Find the managed-device ID in Intune device details or its portal URL; do not substitute the Entra device ID.

`-IntuneOnly` deliberately produces **PARTIAL** coverage. It never infers Defender results from the portal, the operating system version or Intune's compliance status. Existing report directories are rejected to protect earlier snapshots.

## Include Defender

Use a Defender access token obtained by your organization's approved authentication process. Keep it in memory as a `SecureString`; never paste it into a file, transcript, issue or command history. A Graph access token cannot be used for the Defender API.

```powershell
# $defenderToken is an in-memory SecureString for the expected tenant and Defender resource.
./Get-EndpointSecurityReport.ps1 `
    -ExpectedTenantId '<tenant-guid>' `
    -ManagedDeviceId '<intune-managed-device-guid>' `
    -DefenderAccessToken $defenderToken `
    -OutputPath './Reports/Week-01'
```

For unattended reporting, the supplied `Invoke-WeeklyEndpointReport.ps1` uses an **already approved app and certificate**. Microsoft Graph authenticates directly with the certificate for the current process; Azure PowerShell obtains the separate Defender token. A dated run-status JSON records the authentication milestones without tokens or raw errors. The runner does not create the app, certificate or consent. See [scheduled operation](docs/OPERATIONS.md). The real rc.4 run at 14:41 UTC on 17 November 2026 matched an Active, Onboarded Defender device and completed all five collection sections. Its 715 CVE/software rows represented 640 distinct CVEs; the portal total and three selected findings were compared. Earlier empty results remain useful gap evidence, but no longer describe the latest pilot. Weekly scheduling, distribution and a genuine weekly trend still need operational validation.

The token context check is a local routing guard (tenant, audience, expiration), not cryptographic verification. Microsoft validates tokens at the API. Token content is not written to reports. Requests use `https://api.security.microsoft.com`; Microsoft documents the legacy resource `https://api.securitycenter.microsoft.com` for token acquisition.

## Compare two runs

```powershell
./Get-EndpointSecurityReport.ps1 `
    -ExpectedTenantId '<tenant-guid>' `
    -ManagedDeviceId '<intune-managed-device-guid>' `
    -DefenderAccessToken $defenderToken `
    -PreviousSnapshot './Reports/Week-01/snapshot.json' `
    -OutputPath './Reports/Week-02'
```

The tenant, device scope, schema and chronological order must match. First run means **Baseline**, not a weekly trend. A finding is keyed by managed-device ID, CVE, vendor, product and version.

| Change | Meaning |
|---|---|
| StillObserved | Present in both snapshots |
| NewlyObserved | Not in the earlier complete assessment; present now |
| FirstObservedAfterGap | Present now, but earlier coverage was insufficient |
| NoLongerObserved | Absent from a new, nonempty assessment that passes the source, exposure and recent Active/Onboarded telemetry checks |
| PendingVerification | Previously present, now absent while collection or telemetry is insufficient |

NoLongerObserved is not proof of a particular patch or a validated incident resolution. A version change can produce an old row that disappears and a new row that appears. Compare runs collected roughly seven days apart for a weekly view; the script does not fabricate a seven-day window from arbitrary snapshots.

## Read the results correctly

1. Review **coverage** and data age before counting findings. An empty or inaccessible source is never interpreted as safe.
2. Investigate identity mismatches, duplicate Entra IDs and stale telemetry.
3. Review urgent/high actions and assign an owner in your team's workflow.
4. Confirm software update applicability with the vendor. A missing KB is not evidence that no fix exists.
5. Rerun after remediation and compare with the retained snapshot.

The default 48-hour freshness threshold is a local review rule, configurable from 1–720 hours. It is not a Microsoft compliance or vulnerability scanning SLA. Intune last sync and Defender last seen describe different activities; neither guarantees an immediate vulnerability assessment refresh.

An Active, Onboarded sensor can still have no exposure assessment. The report conservatively treats exposure values other than Low, Medium or High as an assessment gap. With successful reads, this is labelled `CollectedWithExposureGap` (or `CollectedWithTelemetryGap` if telemetry also fails the checks). Empty device-level counts stay blank, returned findings remain visible, and previously observed findings stay PendingVerification. `IncompleteSections = 0` means all API reads completed; check `DevicesNeedingAssessmentReview` and the overall status separately. This reporting guard is not a Microsoft guarantee that every CVE assessment is complete when an exposure level exists.

Successful reads with no CVE/software rows also need review **when exposure is Low, Medium or High**. With otherwise healthy telemetry this is `CollectedEmptyNeedsReview`, with an `EmptyAssessmentNeedsReview` action and blank device counts. The live pilot exposed this case: Medium exposure, but no rows and no populated software or vulnerability list in the portal. These responses alone cannot distinguish genuine zero findings from an unpopulated feed. Consequently, even a genuinely zero-result device remains partial in this candidate until separately reviewed; there is no automatic override. An all-empty assessment cannot close earlier findings, including when an older snapshot incorrectly labelled an empty result Collected.

The collector does not read the full installed-software inventory. Microsoft's separate installed-software API requires `Software.Read.All`, which is outside this package's four-permission design. Portal inventory was consulted separately during validation; it is not exported by this script.

UrgentReview means Critical severity, High severity with a reported exploit indicator, or High device risk. High means High severity or Intune reporting encryption as false. Known Medium and Low findings receive RoutineReview. Missing or unrecognized severity receives ReviewUnknownSeverity in both the finding and its software action. If the same software group also contains High or UrgentReview findings, that higher urgency is retained and the action still explicitly requests confirmation of the unknown severity. These are prioritization rules, not claims of active exploitation or Microsoft-assigned response deadlines. A public/verified exploit indicator does not prove compromise on your device.

The report covers reported software vulnerabilities and returned compliance settings. It does not inventory every security configuration, prove patch applicability, scan the endpoint, assess all CVE exceptions, read recovery secrets, or certify regulatory compliance.

## Failure handling and privacy

Pagination is bounded, restricted to the same approved host/path, and rejects loops. Defender duplicate identifiers are rejected. Intune can return repeated policy-state identifiers: identical displayed compliance rows are folded with `ReportedInstances`, while different states remain separate. That count is a count of returned records, not a count of users or assignments. 401, 429 and service failures stop further requests to that source; the other source can continue. The Microsoft SDK may apply its own retries before a failure reaches the script. Rerun later after checking service throttling guidance; do not schedule rapid retry loops.

Reports contain device/security inventory. Restrict their directory and retention, and distribute only to authorized recipients. CSV formula prefixes and HTML values are escaped. No public samples contain tenant data, tokens, private keys, user profiles or raw exception payloads. The author credit is **not an Authenticode signature**. SHA-256 checksums detect changes; they do not establish publisher identity.

## Validate locally

```powershell
pwsh -NoProfile -File ./tests/Run-Tests.ps1
```

The test suite has no network access or authentication requirement. Synthetic device/CVE fixtures are not tenant evidence. See [Microsoft source mapping](docs/MICROSOFT-SOURCES.md) and [security policy](SECURITY.md).
