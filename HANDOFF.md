# Burp MCP Pentest Fork — Engineering Handoff

Audience: a dev agent picking up this fork. This document explains what was built on top of upstream `PortSwigger/mcp-server`, how it is structured, known issues and risks ranked by priority, and concrete next steps.

## 1. Status at a glance

- Base: upstream `origin/main` at v1.3.0 (commit `5f76126`).
- All pentest work is LOCAL and UNCOMMITTED (modified + untracked). Nothing has been committed or pushed.
- Build: `./gradlew test embedProxyJar` is green. 153 tests pass. Output jar: `build/libs/burp-mcp-all.jar`.
- Tech: Kotlin Burp extension (Montoya API) + embedded SSE MCP server (Ktor), tools registered via `mcpTool`/`mcpPaginatedTool`.

### New source files (all under `src/main/kotlin/net/portswigger/mcp/tools/`)

| File | Role |
|---|---|
| `HistoryFilters.kt` | Filter options, endpoint normalization, static-asset detection |
| `RequestResolver.kt` | Unified request source: history index / raw content / active editor |
| `AuthTestEngine.kt` | Identity replay, enforcement detectors, bypass logic |
| `PentestTools.kt` | Registration hub + history/auth/repeater/scope/Pro tools |
| `ReconPatterns.kt` | Pure matchers: secrets, JS endpoints, error sigs, similarity, IDOR |
| `ReconTools.kt` | Recon tools (secrets, endpoints, fingerprint, params, JS bundles, attack surface, headers, forms) |
| `ReconAnalysis.kt` | Pure: security-header analysis, HTML form parsing, attack-surface hints |
| `ProbeTools.kt` | Active probing: probe_parameter, test_idor, fuzz_parameter, probe_injection, diff_responses, OOB |
| `ProbeSignatures.kt` | Pure: payload sets, reflection/SSTI/redirect/timing/LFI/CMDi detectors, verdict engine |
| `JsSecretPatterns.kt` | Pure: SecretFinder-style regex set, Shannon entropy, source-map extraction |
| `DiffResponses.kt` | Pure: `diffResponses` helper + `ResponseDiff` DTO |
| `ProtocolTools.kt` | WebSocket send + Comparer handoff |

Modified: `Tools.kt` (registers pentest tools; summary list tools), `McpConfig.kt` (auth identities), `schema/serialization.kt` (summary DTOs), `README.md`, `BappDescription.html`, `ToolsKtTest.kt`.

### Test files
`ReconPatternsTest`, `ProbeAnalysisTest`, `ProbeSignaturesTest`, `JsSecretPatternsTest`, `DiffResponsesTest`, `ReconAnalysisTest`, `HistoryFiltersTest`, `AuthTestEngineTest`, `McpConfigAuthIdentityTest`, `PentestToolsKtTest`.

## 2. Architecture conventions (follow these)

- Pure analysis lives in `*Patterns.kt` / `*Signatures.kt` / `*Analysis.kt` and is unit-tested without Burp. Tool wrappers (I/O + Montoya) live in `*Tools.kt`. Keep this split — it is why coverage is good.
- Tools are registered from `registerPentestTools` in `PentestTools.kt`, which is called at the end of `registerTools` in `Tools.kt`. Recon/probe/protocol clusters each have a `registerXTools(api, config)`.
- Passive reads gate on `checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, ...)`. Outbound sends gate on `checkHttpPermissionForRequest(...)` (wraps `HttpRequestSecurity`). Pro-only tools are gated by `BurpSuiteEdition.PROFESSIONAL` in the `registerProfessionalPentestTools` block.
- Request sourcing is always `resolveRequestFromSource(api, historyIndex, rawContent, useActiveEditor, targetHostname, targetPort, usesHttps)`.
- `@Serializable` DTOs are co-located in the tool file. New serializers that touch Burp model types go in `schema/serialization.kt`.

## 3. Known issues and risks (priority order)

### P1 — Correctness / reliability

1. Time-based injection is single-sample (`ProbeSignatures.kt` `detectTimingAnomaly`, used by `probe_injection` SQLI_TIME). One baseline request vs one probe request, threshold 4000ms (suspicious 2000ms). Network jitter or a slow endpoint will produce false positives; a fast server under load can mask true positives. Recommended fix: take N baseline samples (e.g. 3), use median, and require probe delay to exceed median + margin; optionally re-test a hit to confirm. This is the single most impactful accuracy improvement.

2. `responseSimilarity` uses full Levenshtein (`ReconPatterns.kt`), O(n*m) time and O(m) space. On large response bodies (`test_idor`, `diff_responses`) this is slow and can spike memory. Recommended fix: cap comparison length (e.g. first/last N KB) or switch to a token/shingle similarity (Jaccard over n-grams) for large bodies. Add a length guard before calling Levenshtein.

3. Length metric inconsistency: `analyzeProbeResponse` uses `body().length()` (byte length) for `lengthDelta`, while `diffResponses` uses `String.length`. Harmless today but confusing; pick one and document it.

### P2 — False positives in detection

4. `JsSecretPatterns.kt`:
   - `heroku_api` is a bare UUID regex — matches ANY UUID. Very high FP rate. Either remove, or only flag when near a `heroku`/`api_key` keyword.
   - `firebase` matches the literal domain `firebaseio.com` — informational at best.
   - `twilio_auth` and `twilio_api_key` are identical patterns (`SK[a-f0-9]{32}`) producing duplicate findings. Deduplicate or differentiate.
   - `email` and `internal_ip` in `ReconPatterns.SECRET_PATTERNS` are noisy in `scan_responses_for_secrets`. Consider a severity/confidence field so the agent can filter.

5. `detectOpenRedirect` (`ProbeSignatures.kt`) interpolates the canary host straight into a regex; the `.` in `burp-mcp-redirect-canary.example` is an unescaped regex metachar. Low risk but should use `Pattern.quote(canary)` for the body/meta-refresh check.

### P3 — Coverage and robustness

6. No tests exercise the `mcpTool` wrapper bodies (request resolution failure messages, permission-denied paths, JSON shape of results). All new tests are pure-function. Add MockK-based registration tests mirroring `ToolsKtTest` for at least `fuzz_parameter`, `probe_injection`, `diff_responses`, `scan_js_bundles`, `map_attack_surface`.

7. `fuzz_parameter` / `probe_injection` send sequentially with an optional `delayMs`. There is no global rate cap or total-time budget beyond `maxRequests` (capped at 100). For large sets against slow targets this can run long and blocks the calling coroutine via `Thread.sleep`. Consider a wall-clock budget and/or making delays non-blocking.

8. `send_websocket_message` (`ProtocolTools.kt`) uses `Thread.sleep(waitMs)` (coerced 100..30000) on the calling thread. Acceptable, but document the upper bound and that it blocks.

### P4 — Repo hygiene

9. Everything is uncommitted (6 modified, ~16 untracked source/test files). `.gitignore` already excludes `build/` (line 2), so build artifacts are not an issue. Recommend splitting into reviewable commits by cluster (history/auth, recon, probe, protocol, tier1, tier2) if PRs are wanted.

## 4. Build, test, verify

```
./gradlew test            # 153 tests, all green
./gradlew embedProxyJar   # builds build/libs/burp-mcp-all.jar
```

Load `build/libs/burp-mcp-all.jar` in Burp (Extensions > Add > Java) to manually exercise tools. Pro-only tools (`probe_parameter_oob`, scanner detail, audit/crawl, custom issues) require Burp Professional.

## 5. Suggested next steps (in order)

**Implemented (see git diff):**
- P1.1 — Multi-sample timing baseline (median of 3) + confirmation re-test for SQLI_TIME in `probe_injection`
- P1.2 — `truncateForSimilarity` (8KB cap) before Levenshtein in `responseSimilarity`
- P1.3 — `analyzeProbeResponse` uses UTF-16 string length consistently
- P2.4 — JS secret FP fixes (heroku context, removed duplicate twilio/firebase patterns), `confidence` on secret scan results
- P2.5 — `Pattern.quote` for redirect canary in meta-refresh check
- P3.6 — `PentestToolsKtTest` registration + error-path tests
- P3.7 — `maxWallClockMs` (default 120s) on `fuzz_parameter` and `probe_injection`
- P3.8 — WebSocket tool description documents blocking + 100–30000ms bounds

**Remaining:**
1. P4.9 — commit in logical chunks per cluster (manual git step).
2. Optional: richer MockK integration tests that exercise successful probe/fuzz flows with mocked HTTP responses.
3. Tier 3 auth/reporting cluster (see prior brainstorm).

## 6. Tool inventory (new in this fork)

- History/site map: `get_proxy_history_entry`, `get_organizer_item`, `get_site_map_entry`, `annotate_history_entry`, `get_site_map`
- Auth: `set_auth_identity`, `list_auth_identities`, `delete_auth_identity`, `test_authorization`, `test_authorization_batch`
- Workflow/scope: `send_and_open_repeater`, `resend_history_entry`, `extract_parameters`, `get_scope`, `add_to_scope`, `remove_from_scope`
- Recon: `scan_responses_for_secrets`, `extract_js_endpoints`, `fingerprint_technologies`, `aggregate_parameters`, `scan_js_bundles`, `map_attack_surface`, `analyze_security_headers`, `extract_forms_and_inputs`
- Probing: `probe_parameter`, `fuzz_parameter`, `probe_injection`, `test_idor`, `diff_responses`, `probe_parameter_oob` (Pro)
- Protocol: `send_websocket_message`, `send_to_comparer`
- Pro scanner: `get_scanner_issue`, `start_audit`, `start_crawl`, `add_audit_issue`
