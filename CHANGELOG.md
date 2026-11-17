# Changelog

## 0.1.0-rc.4 — 2026-11-17

First public preview. Added an explicit extraction-directory step, a separate application/certificate setup checklist and the administrator guide link. These documentation changes do not change collection behavior or permissions.

Fixed grouped software actions downgrading missing or unrecognized severity to RoutineReview. ReviewUnknownSeverity is now preserved when there is no higher known urgency. Mixed High/Critical groups retain their higher urgency and an explicit follow-up to confirm the unknown severity. Fifteen additional offline checks exercise the collector and its CSV/HTML output; all 97 checks pass.

Live vulnerability collection is now validated: the rc.3 run at 14:35 UTC and corrected rc.4 run at 14:41 UTC each returned 715 CVE/software rows representing 640 distinct CVEs. The portal total and three selected findings matched. The earlier empty-to-populated comparison correctly produced FirstObservedAfterGap. The guide now leads with the administrator workflow and current results. Scheduling, email delivery and a genuine weekly trend remain untested; no tenant permissions or remediation behavior were added.

## 0.1.0-rc.3 — 2026-11-17

Fixed a second empty-response coverage case found in the live pilot: Defender exposure changed to Medium while both vulnerability reads still returned no rows and the portal showed No data available. Empty CVE/software responses now require assessment review even when an exposure level exists. Device counts remain blank, and previous findings cannot be closed by an all-empty response. Snapshot comparison also protects against older empty snapshots incorrectly marked Collected. Genuine zero-result devices therefore require separate review in this candidate.

The 14:01 UTC certificate run completed all five reads and correctly produced PARTIAL, zero incomplete API sections and one CollectedEmptyNeedsReview device. All 82 local regression checks passed. The same four read permissions are used; the application is retained and the temporary certificate remains available during validation. No full software-inventory API, schedule, delivery or remediation operation was added. Positive live CVE/software findings and a real weekly comparison remain pending.

## 0.1.0-rc.2 — 2026-11-17

Fixed an empty-response coverage error found during real onboarding validation. A matched Active, Onboarded device with unavailable exposure data no longer becomes a complete zero-CVE assessment merely because its API requests succeed. Empty device counts stay blank, observed findings are retained, and snapshot comparison cannot close findings across this gap. HTML and JSON now show the number of devices needing assessment review separately from incomplete API sections.

The pilot now appears in Defender after a separately approved one-device EDR assignment. Certificate authentication and both vulnerability API reads succeeded, but the portal still showed No data available. Positive live CVE/software findings and a real weekly comparison remain pending. All 73 local regression checks passed. This remains a review candidate.

## 0.1.0-rc.1 — 2026-11-16

Initial review candidate: selected-device Intune/Defender collector, local HTML and six CSV reports, explicit coverage gaps, snapshot comparison, certificate runner, read-only tenant pilot helper kept outside the public package, and offline regression tests.

Certificate authentication, Intune reads and an exact-ID Defender inventory query were validated in the tenant. The inventory returned no matching device, so live vulnerability collection and weekly operation remain pending. No final release or production-readiness claim is made.

Added strict certificate-runner configuration validation, local certificate preflight and safe authentication milestone records. Fixed Graph certificate connection parameters, the Defender Entra device-ID filter's GUID type, and culture-independent handling of typed JSON dates. All 65 local regression checks passed. The real onboarding status report documents the pilot as Not Onboarded despite an enabled connector; a current local endpoint check remains pending.
