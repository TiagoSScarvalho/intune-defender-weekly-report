# Validation status

Version 0.1.0-rc.4 is a review candidate. It has not been published as a final release. The latest live run is 14:41 UTC on 17 November: 715 CVE/software rows, 640 distinct CVEs, all five sections complete and exit code 0. Portal totals and three selected findings matched. All 97 offline checks passed. Earlier observations below preserve the development chronology; statements about pending findings describe their dated stage, not the current result.

## Observed in the pilot portals — 16 November 2026

- The selected Windows pilot appeared Compliant in Intune.
- Its device overview showed last check-in on 11 November 2026 at 17:27 (Lisbon).
- Three compliance policies appeared Compliant. The security baseline showed BitLocker, Code Integrity, Secure Boot and storage encryption as Compliant.
- Defender device inventory showed 0 devices in the selected 30-day range after removing the transient-device and exclusion-state filters.

These are earlier portal observations. The separate certificate test below establishes a successful inventory API query, but neither observation proves that the endpoint has no vulnerabilities.

### Follow-up: missing Defender coverage

The Intune connector page showed the Defender connection Enabled, with a successful synchronization at 03:39:47 on 16 November. The EDR Summary contained no EDR policies. After generating the EDR Onboarding Status report at 10:14 (Lisbon), the pilot row showed **Not Onboarded** and **Defender sensor state: No**, with a last reported check-in of 11 November at 17:29:52. This distinguishes an active tenant connector from endpoint onboarding. The empty inventory alone did not establish that cause; the refreshed onboarding report provides the additional evidence.

Because the per-device state is older than the report generation time, a local read of Sense service status and OnboardingState was requested. The first console image suppressed registry errors. A follow-up image explicitly shows Sense Stopped and a registry key-or-value-not-found error. The owner then executed hostname in the same window and confirmed the selected pilot's name. This supports the onboarding gap; it is not a measured OnboardingState of 0. The 17 November follow-up below confirms a newly saved policy, but not device receipt. Connector risk signals not being included in compliance policies are a separate issue, not evidence that the connector is disabled.

## Real Intune API pilot

The corrected collector completed a read-only run at 10:01 UTC on 16 November 2026. It read one selected managed device and six policy-state records. The device identity, Windows version, Compliant state and last-sync timestamp matched the portal. Intune reported encryption as true.

The API returned two records for each of three policy-state identifiers. The initial strict duplicate check incorrectly marked that section incomplete. The fix retains returned policy states and folds only identical displayed rows, preserving a ReportedInstances count. The final CSV contains three compliant policy summaries with two instances each. A regression test also checks that different states remain separate.

The API returned empty settingStates arrays. The CSV therefore labels these as policy summaries; the four setting-level results are portal observations, not returned API detail. This limitation must remain visible in the guide.

That Intune-only report has three incomplete sections, all intentionally unattempted Defender reads. It remains PARTIAL and records no assessed vulnerability count for the device. It is a first-run baseline, not a weekly trend. No tenant, device or permission setting was changed by the collector. The later certificate run below supersedes this run for authentication and inventory coverage.

65 local regression checks passed on PowerShell 7, including certificate-runner configuration guards, date handling under pt-PT and en-US, the Defender GUID filter and successful empty-inventory handling. These offline checks do not use a real authentication certificate. The GitHub Windows/Ubuntu workflow is prepared but has not run remotely. On 17 November the article was opened through a local HTTP preview: all nine images loaded when their sections were visited, the navigation and full-image link worked, and the page had no horizontal overflow at the observed 1265-pixel viewport. The portrait assignment capture is limited to its original 552-pixel width. A phone-width interaction check remains pending. Static links, images and package checks are recorded separately.

Two separate local process checks confirmed exit code 1 at Configuration for placeholders and at CertificatePreflight for an absent certificate. Neither created a report or attempted authentication. Four PowerShell files passed parsing. These local checks are distinct from the live certificate test below.

The owner approved a disposable application with exactly the four application read permissions documented in the README. The application and consent were observed in Entra; a local non-exportable certificate valid for 24 hours was created. At 15:28 UTC, a separate private administration helper verified those four permissions, but public-certificate upload failed with HTTP 403. The report runner was never invoked. Attempts to delete the application and its service principal also returned 403. The local certificate was removed with DeleteKey and its absence was verified. The owner then deleted the application through Entra. At 15:54 UTC, a read-only Graph check verified that both active tenant objects were absent, the local certificate was absent, and the earlier DeleteKey operation was recorded. The failed attempt's cleanup is complete.

The administration helper incorrectly relied on Directory.ReadWrite.All. Microsoft's current application update/delete APIs document Application.ReadWrite.All for delegated management. The helper now refuses management operations without an existing session containing that permission and does not request new consent. Seventeen offline guards passed, including rejection of the earlier scope. This private helper is not included in the public package; its provisioning failure does not demonstrate a failure or success of certificate authentication, the read-only collector or Defender API access.

A replacement non-exportable 24-hour certificate was prepared after cleanup. The owner registered a replacement single-tenant application in Entra and completed its setup. An independent Application.Read.All query at 16:32 UTC verified the uploaded public certificate, exactly four configured and granted application read permissions, single-tenant scope and no client secret. No additional management consent was granted.

## Real certificate run — 16:41 UTC, 16 November 2026

The runner completed certificate authentication without an interactive user login. Its status record confirms Azure certificate sign-in, a Defender token, the expected Graph app-only certificate context, and collection startup. The selected-device report shows:

| Read | Observed result |
|---|---|
| Intune device | Complete; one selected device, Compliant, encryption true |
| Intune freshness | Last sync 16 November 10:37:20 UTC; Recent under the 48-hour rule, newer than the morning screenshot |
| Compliance policy states | Complete; six records folded into three compliant policy summaries, two instances each |
| Defender inventory by exact Entra device ID | Complete; zero matching records; NoVisibleMatch |
| Vulnerability rows and CVE context | Not attempted because no matching Defender device was available |
| Report outcome | PARTIAL, two incomplete sections, exit code 2, no assessed vulnerability count |

The inventory query initially returned HTTP 400 because the GUID was quoted as a string. It now uses a canonical unquoted GUID, consistent with Microsoft's machine resource type, and the real corrected query completed successfully. The Graph runner also now uses the supported certificate parameter set; AccessToken with ContextScope was an incompatible combination. Date handling accepts typed JSON timestamps without relying on the process culture. These fixes are included in the review package.

Successful inventory access does not establish that either vulnerability endpoint can return real findings in this tenant. The absence is consistent with the older Not Onboarded portal row and the subsequent owner-confirmed local check. No endpoint, onboarding policy, schedule or email was changed by this certificate run. No weekly remediation improvement has been measured.

At 16:42 UTC, the retry certificate and its local private key were removed with DeleteKey; certificate absence was verified. The owner subsequently instructed us to retain the replacement application. Its application, service principal and four read grants therefore remain intentionally registered. The uploaded public certificate remains until removed or expired; its local private key is no longer available. A new approved authentication certificate is required for another run. This is an intentionally retained app, not a claim that all lab objects were deleted.

## Onboarding follow-up — in progress

The owner explicitly authorized Defender onboarding limited to the selected pilot. A read-only Graph baseline at 16:58 UTC verified the existing static pilot group contains exactly that one directory device. The read session has no Intune configuration-write permission. The approved portal procedure uses a Windows EDR policy with Auto from connector and assigns only that group; the report application receives no additional permissions.

A new non-exportable 24-hour local certificate was prepared for the retained application. At 17:06 UTC the four configured and granted read permissions were independently reverified, but the new public certificate had not yet been uploaded. At 17:07 UTC the named onboarding policy was not found. No successful deployment, sensor recovery or vulnerability result is claimed. These follow-up provisioning and verification helpers remain private and outside the GET-only public package.

### Saved pilot policy — 17 November 2026

At 10:53 UTC the authorized Windows EDR policy was created in Intune, using Auto from connector. Sample Sharing and the deprecated telemetry reporting frequency remained Not configured. The portal confirmed that the policy and group assignment were saved. Only the existing static pilot group was assigned, with one device and zero users. No group membership, compliance policy or Conditional Access setting was changed.

At 10:54 UTC, an independent GET-only verification confirmed the policy name and EDR template, exactly one group assignment without a filter, and the exact pilot device as the group's only member. The choice setting was Auto from connector. A screenshot of the saved assignment was captured. This proves configuration and scope, not that the endpoint has received the policy or started its sensor. Device synchronization and a subsequent Defender assessment are still pending. The new public-certificate upload also remains pending; all four existing application read grants were reverified earlier the same morning.

## Pending evidence

- Certificate authentication, populated CVE/software reads and recovery from an earlier assessment gap are now validated, as recorded in the latest section below.
- A genuine weekly comparison and any remediation outcome remain to be demonstrated.
- Scheduling, distribution and a phone-width interaction check remain separate deployment checks; the GitHub workflow has not run remotely.

The offline tests cover identity ambiguity, stale telemetry, partial results, missing fields, safe pagination, HTTP failures, snapshot comparison and output escaping. Their synthetic CVEs and devices must never be presented as tenant findings. A partial pilot report is useful to inspect the design but does not complete these publication gates.

## Onboarding and assessment follow-up — 17 November

After the owner confirmed synchronization and public-certificate upload, a GET-only check at 11:08 UTC verified the matching certificate, no client secret, single-tenant scope and exactly the four configured and granted application read permissions. The certificate is used only for authentication; the report remains GET-only.

At 11:09 UTC, rc.1 matched the pilot by its exact Entra device ID. Defender reported Active and Onboarded, with lastSeen 10:55:50 UTC; Intune reported Compliant and a last sync of 10:56:41 UTC. The Defender portal showed first seen at 10:55:37 UTC. Both vulnerability API requests succeeded but returned no rows, while exposureLevel was None and the portal showed No data available for exposure and discovered vulnerabilities. The raw empty responses are not proof of zero device vulnerabilities.

This uncovered an rc.1 coverage defect: successful empty responses with no exposure data were marked complete. The historical report is retained privately as evidence; it is not the corrected result. In rc.2, missing exposure preserves an assessment gap, leaves empty device counts blank and prevents false closure of previous findings. Returned positive findings are retained even if coverage is incomplete. All 73 local regression checks passed, including eight tests covering this behavior.

The real rc.2 certificate run at 11:17 UTC completed all five collection sections, returned the same Active/Onboarded match, and correctly produced PARTIAL, zero incomplete API sections, one device needing assessment review and CollectedWithExposureGap. Device-level vulnerability counts were blank. The successful API reads validate access and empty-response handling, not positive live CVE/software parsing or an actual weekly change.

The refreshed Intune policy page subsequently showed Succeeded: 1, with zero errors, conflicts, not-applicable or in-progress results. Its screenshot is included in the guide. The one-device onboarding scope is unchanged.

A final read-only certificate run at 11:25 UTC returned the same partial assessment state, with all five queries completed. At 11:25:54 UTC, the temporary local certificate and its private key were removed with DeleteKey and certificate absence was verified. The application and four read grants are intentionally retained, as requested; the public certificate remains in Entra until removed or expired. A further authenticated collection needs a valid certificate whose private key is available to the runner. No schedule, email delivery, remediation or further tenant permission was enabled.

The real HTML report's action filter and CSV download were tested in the browser; the downloaded CSV matched the source hash. The article's review-package download also matched the generated ZIP hash. New portal and report images loaded, and the full-size report image link worked. The observed desktop page had no horizontal overflow. A phone-width interaction check and remote GitHub workflow execution have not been performed.

Live CVE/software findings and two comparable real assessment snapshots remain publication gates for a fully validated integrated report. The first expected follow-up is to review Defender's assessment availability while the pilot stays online; no additional endpoint or tenant change is justified solely by these initial empty responses.

## Assessment follow-up — 14:01 UTC, 17 November

The owner approved and uploaded a new non-exportable 24-hour certificate to the retained application. A read-only setup check at 13:57 UTC independently verified the public certificate, the single-tenant app with no client secret, and exactly the same four configured and granted application read permissions. The certificate expires on 18 November at 13:41 UTC and remains available for the ongoing assessment validation; removal of its local private key is pending completion. The application is intentionally retained.

The Defender overview at 13:38 UTC showed Medium exposure and an Active sensor. Its software inventory remained empty, and the Discovered vulnerabilities view at 14:00 UTC showed 0 items and No data available. Both API vulnerability reads also returned no rows. This exposed a second false-completeness case in rc.2: once an exposure level was present, it accepted the empty result as current coverage. The earlier private report is retained as defect evidence, not the current result.

Candidate rc.3 requires separate review for every empty CVE/software response. With otherwise healthy telemetry and known exposure, the device state is CollectedEmptyNeedsReview, its two counts remain blank, and the queue includes EmptyAssessmentNeedsReview. Even a genuinely zero-finding device remains partial under this conservative rule. Full installed-software inventory is not collected: its API requires Software.Read.All, outside the approved four-permission design. The portal inventory check was separate evidence.

The real rc.3 certificate run at 14:01 UTC completed all five collection sections and returned the exact pilot match, Active/Onboarded telemetry and Medium exposure. Its outcome was PARTIAL, exit code 2, zero incomplete API sections, one device needing assessment review and blank device-level vulnerability counts. Both vulnerability feeds returned zero rows. This validates authentication, read access and handling of this observed empty-feed case; it does not validate positive live CVE/software parsing or weekly remediation claims.

All 82 local regression checks passed, including Low/Medium/High exposure with empty responses, CVE context without software rows, HTML/CSV/summary output, and guards against older empty snapshots incorrectly labelled Collected. A current all-empty response cannot close previous findings. These fixture tests remain separate from tenant evidence. New genuine portal and report screenshots are included in the review draft. No permissions, devices, policies, schedule, email or remediation were changed by the report run.

## Populated findings and corrected triage — 14:41 UTC, 17 November

The refreshed Defender portal displayed 640 discovered vulnerabilities. The rc.3 certificate run at 14:35 UTC returned 715 CVE/software rows representing those same 640 distinct CVEs. The rows contained 15 Critical, 472 High, 194 Medium and 34 Low severity findings; the 15 Critical rows represented 13 distinct CVEs. The device was still Compliant in Intune and Active/Onboarded with risk None and exposure Medium in Defender.

Three sampled Windows findings matched the portal by CVE, product version, severity and CVSS: CVE-2026-88218 and CVE-2026-119958 were Critical, CVSS 9.8; CVE-2026-111497 was Critical, CVSS 9.2. All three referred to Windows version 10.0.26200.9911. This is a sampled field comparison, not a manual audit of every record. The API's fixing-KB value was retained as reported, not treated as a verified deployment instruction.

Comparing the saved 14:01 empty assessment with the populated 14:35 snapshot produced 715 FirstObservedAfterGap rows. It did not label them newly introduced vulnerabilities. This validates that real transition; it is not a seven-day trend or evidence of remediation.

An additional offline test exposed a triage defect: a finding with missing severity was ReviewUnknownSeverity, but its grouped action became RoutineReview. Candidate rc.4 preserves the unknown-severity priority and, for mixed High/Critical groups, keeps the higher urgency plus an explicit severity-confirmation instruction. Fifteen end-to-end fixture checks exercise missing, unrecognized and mixed severities through CSV and HTML. All 97 local regression checks passed. No unknown severities were present in the real pilot rows.

The corrected rc.4 certificate run at 14:41 UTC returned the same 715 rows and 640 distinct CVEs, six software action groups, zero incomplete sections and exit code 0. It used the same retained application, temporary certificate and four read grants. No device, policy, permission, schedule, email or remediation setting was changed. The application remains registered; the temporary certificate is available during final review and expires on 18 November at 13:41 UTC.
