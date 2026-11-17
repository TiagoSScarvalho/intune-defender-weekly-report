# Microsoft documentation checked

Reviewed 16–17 November 2026. Documentation validation is separate from a successful tenant API test.

| Design decision | Microsoft source |
|---|---|
| Read minimal Intune device metadata; use the Entra device ID to correlate | [managedDevice](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice?view=graph-rest-1.0) |
| Read managed devices with the read-only Graph permission | [Get managedDevice](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-get?view=graph-rest-1.0) |
| Read per-device compliance policy states | [Graph PowerShell device compliance states](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.devicemanagement/get-mgdevicemanagementmanageddevicecompliancepolicystate?view=graph-powershell-1.0) |
| Match Defender machines through aadDeviceId; account for user/device-group visibility | [List machines](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines) |
| Treat aadDeviceId as a GUID; preserve risk, exposure, health and lastSeen separately | [Machine resource](https://learn.microsoft.com/en-us/defender-endpoint/api/machine) |
| Separate sensor health from exposure availability; conservatively retain a coverage gap when exposure is unavailable | [Device inventory field reference](https://learn.microsoft.com/en-us/defender-endpoint/device-inventory-field-reference) |
| Restrict software vulnerabilities by machineId | [List vulnerabilities by machine and software](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines) |
| Read device-specific CVE context and exploit indicators | [Get discovered vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-discovered-vulnerabilities) |
| Do not infer a full installed-software inventory from vulnerability rows; the separate inventory API requires Software.Read.All and is not called | [Get installed software](https://learn.microsoft.com/en-us/defender-endpoint/api/get-installed-software) |
| Separate Defender authentication audience from endpoint hostname | [App-only Defender API access](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp) |
| Use an existing certificate identity and in-memory secure tokens | [Connect-AzAccount](https://learn.microsoft.com/en-us/powershell/module/az.accounts/connect-azaccount) and [Get-AzAccessToken](https://learn.microsoft.com/en-us/powershell/module/az.accounts/get-azaccesstoken) |
| Connect Graph with the certificate parameter set and process context | [Connect-MgGraph](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0) |
| Distinguish vulnerability remediation from Intune compliance | [Remediate vulnerabilities](https://learn.microsoft.com/en-us/intune/device-security/microsoft-defender/remediate-vulnerabilities) |
| Check Business licensing without assuming every API feature is available | [Defender for Business overview](https://learn.microsoft.com/en-us/defender-business/mdb-overview) |

The script's 48-hour data-age threshold, change names, action priorities and conservative empty-response review rule are local design decisions. They are not Microsoft standards. A nonempty exposure level is not used as proof of a populated CVE/software feed. This version does not use beta Graph endpoints, advanced hunting, the full installed-software inventory API, the tenant-wide software-vulnerability export, or write/remediation APIs.
