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
