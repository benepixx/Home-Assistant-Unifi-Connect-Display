Release v1.0.6

## Release Notes
This release includes all commits up to 2026-02-25.

### Changes
- **Fix**: Device discovery now correctly handles UniFi Connect controllers
  (e.g. Cloud Key) that return a JSON wrapper object
  `{"err": null, "type": "collection", "data": [...], ...}` from the devices
  endpoint, in addition to the bare-list format used by other controllers.
- **Improvement**: The devices list request now includes `?shadow=true` to
  match what the UniFi Connect web UI sends, improving compatibility.
- **Debug logging**: Added debug-level log messages indicating which response
  format was received from the devices endpoint (no sensitive values logged).

---

Release v1.0.5

## Release Notes
This release includes all commits up to 2026-02-25.

### Changes
- **Fix**: Authentication now works with newer UniFi OS / UniFi Connect
  controllers that return the `TOKEN` cookie with the `Partitioned` (CHIPS)
  attribute. The integration now parses `Set-Cookie` response headers
  directly to extract the token, falling back to the cookie jar for older
  controllers where the attribute is absent.

---

Release v1.0.4

## Release Notes
This release includes all commits up to 2026-02-25.

### Commit History
- Commit 0ee402f97627fb3e3e44b547184ed81270669671 (Latest)

... (Include additional relevant commits as needed)
