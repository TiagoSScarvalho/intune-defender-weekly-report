# Scheduled operation — public preview

The runner prepares one local report per invocation. Scheduling and message delivery are separate operational steps and have not been enabled by this project.

## Identity and certificate

Use a dedicated single-tenant application with only the four application read permissions listed in the README. An administrator must approve the app and consent. Do not reuse a broadly privileged app merely to avoid that review.

Before the first certificate run, complete this setup checklist separately from the collector:

1. In Entra **App registrations**, register a dedicated application for accounts in your directory only. This background report does not need a redirect URI.
2. Add the two Microsoft Graph and two WindowsDefenderATP **Application permissions** listed in the README. Remove an unused default delegated User.Read entry if present; the report's application configuration needs only those four read permissions.
3. Have an authorized administrator grant consent and confirm all four application permissions show **Granted**. Creating the app alone does not grant data access.
4. Obtain an authentication certificate through your organization's process. Upload only the public `.cer` file under **Certificates & secrets → Certificates**. The corresponding private key must remain accessible in `CurrentUser\My` for the Windows identity that will execute the report. Do not create a client secret for this runner.
5. Copy the **Directory (tenant) ID**, **Application (client) ID** and certificate thumbprint into a private copy of `config.example.json`. Add the **Intune managed-device IDs**, keeping the JSON array, and confirm the certificate has not expired.

Microsoft documents [application registration and API permissions](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp) and [certificate creation and public-certificate upload for a test](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-self-signed-certificate). Follow your organization's certificate lifecycle for ongoing operation. The report does not perform any of these setup changes.

Provisioning is a separate administrator task. If using Microsoft Graph to attach the certificate or remove the temporary application, Microsoft's [application update](https://learn.microsoft.com/en-us/graph/api/application-update?view=graph-rest-1.0) and [application deletion](https://learn.microsoft.com/en-us/graph/api/application-delete?view=graph-rest-1.0) documentation requires an appropriate management permission and Entra role. The least-privileged documented delegated permission is Application.ReadWrite.All. Do not treat Directory.ReadWrite.All as a substitute, or add management permissions to the reporting application. The report runner needs only the four application read permissions.

Provision a certificate using your organization's process, upload only its public certificate to the application and protect its private key. This is an **application authentication certificate**, not a script-signing certificate. The runner expects it in **CurrentUser\My under the Windows identity that runs the job**, with an accessible private key. The preflight rejects certificates that are not yet valid or expire within five minutes; the authentication attempt establishes whether the key is actually usable. Keep certificates, credentials, actual configuration, snapshots and reports outside the repository. Plan expiry monitoring and rotation before scheduling.

## Configuration and manual run

Install Microsoft.Graph.Authentication and Az.Accounts from the PowerShell Gallery. Copy `config.example.json` to a private working directory and replace every zero GUID/thumbprint. Enter the explicit Intune managed-device IDs in scope and the review threshold. Do not place tokens or private keys in JSON.

Run the certificate runner in a dedicated PowerShell process, under the intended scheduled identity:

Open that process in the extracted package directory first. Replace this example with the folder that contains `Invoke-WeeklyEndpointReport.ps1`:

```powershell
Set-Location -LiteralPath 'C:\Tools\intune-defender-weekly-report'
```

```powershell
pwsh -NoProfile -File ./Invoke-WeeklyEndpointReport.ps1 `
    -ConfigurationPath 'C:\PrivateReports\endpoint-config.json' `
    -OutputRoot 'C:\PrivateReports\Runs'
```

For the following run, explicitly pass `-PreviousSnapshot` pointing to the earlier report's snapshot. The runner deliberately does not guess which file is the baseline. Retain the last run even when it is partial: gaps matter when interpreting the following week's changes.

Exit code 0 means complete stated reads; 2 means a report was produced with incomplete coverage; 1 means the run failed. Monitor all three outcomes. A successful process exit is not a clean security verdict.

Exit code 2 can occur with `IncompleteSections = 0`: every API request succeeded, but the device assessment still needs review. Since rc.3, an empty CVE/software response never establishes a zero-finding assessment by itself, even with a Low, Medium or High exposure level. Review the device's software inventory, vulnerability view and assessment availability separately. A genuinely zero-result device also remains partial under this conservative rule; the current version has no manual-completion override. Do not treat an all-empty new response as evidence that earlier findings were remediated.

The runner disables Azure context autosave for its process and clears process contexts at the end. Graph uses its certificate authentication parameter set with Process context; Azure PowerShell obtains the separate Defender token. It changes no tenant permissions. Do not run it inside a PowerShell session containing unrelated administrative work.

After local preflight, the runner saves a dated run-status JSON file under OutputRoot. It distinguishes certificate sign-in, Defender token issuance, the verified Graph app-only context and collection startup. It contains no token or raw authentication error. A token or successful connection does not establish that a data API returned usable results; check report coverage separately.

## Diagnose a failed certificate run

The warning identifies a stage without printing raw authentication errors or tokens:

| Stage | Check |
|---|---|
| Configuration | Replace zero placeholders, use distinct managed-device IDs in an array, and set an integer age from 1 to 720 hours. |
| CertificatePreflight | Run on Windows as the intended identity; confirm the matching certificate, private key and validity in CurrentUser\My. |
| LoadAuthenticationModules | Confirm the required Graph and Az.Accounts versions are installed for that identity. |
| CertificateSignIn | Confirm the client/tenant match, uploaded public certificate and approved app access. Review service-principal sign-in logs privately if needed. |
| DefenderToken | Confirm access to the intended resource and certificate authentication. Defender uses the documented legacy token resource. |
| GraphConnection / ReadOnlyCollection | Review the report's coverage, HTTP status and safe reason codes. A 403 can reflect permissions or service access; no matching machine does not prove zero vulnerabilities. |

A token being issued is not proof that an endpoint is onboarded or that the vulnerability API is licensed and accessible. Preserve these outcomes separately in the validation record.

## Production readiness gate

Before scheduling, validate the certificate flow in the target tenant, a known onboarded device with a genuine current finding, a zero-result device that follows the manual-review rule above, a denied source, and two comparable real snapshots. Match the report to Intune and Defender while accounting for independent data refresh times. This pilot now validates certificate access, live findings and recovery from an earlier assessment gap. It does not yet demonstrate a seven-day trend, scheduled execution or distribution.

The 14:41 UTC rc.4 pilot on 17 November returned 715 CVE/software rows representing 640 distinct CVEs and zero incomplete sections. An earlier empty-to-populated comparison produced FirstObservedAfterGap, not a claim of newly introduced vulnerabilities. See the dated validation record before interpreting readiness for your own environment.

Start with a small approved device list. The per-device collector is limited to 500 IDs and may hit API limits before that in some tenants. An expired Defender token produces partial results; this candidate does not refresh a supplied token during collection. For larger estates, design separate batching and token renewal rather than claiming fleet-wide completeness.

Use a weekly schedule only after reviewing runtime, retention and access control. Keep a notification when the report is partial or fails. If email delivery is added later, prefer an access-controlled report link and a concise coverage summary. That delivery component needs its own approved sender, recipients and mail permissions; it is not included here.
