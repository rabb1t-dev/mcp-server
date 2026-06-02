package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessType

fun Server.registerReconTools(api: MontoyaApi, config: McpConfig) {
    mcpPaginatedTool<ScanResponsesForSecrets>(
        "Scans proxy history response bodies for secrets (API keys, JWTs, tokens, emails, internal IPs). " +
            "Returns index, URL, pattern name, and redacted snippet."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val filter = historyFilterFromParams(
            inScopeOnly, host, method, statusCodeClass, excludeStaticAssets, urlRegex, uniqueEndpoints
        )

        filterProxyHistory(api.proxy().history(), filter, api).asSequence()
            .flatMap { (index, entry) ->
                val body = entry.response()?.bodyToString() ?: return@flatMap emptySequence()
                val url = runCatching { entry.finalRequest().url() }.getOrElse { "<unknown>" }

                scanTextForSecrets(body).asSequence().map { match ->
                    Json.encodeToString(
                        SecretScanResult(index, url, match.patternName, match.snippet, match.confidence)
                    )
                }
            }
    }

    mcpPaginatedTool<ExtractJsEndpoints>(
        "Extracts URLs and API paths from JavaScript/HTML responses in proxy history (LinkFinder-style)."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val filter = historyFilterFromParams(
            inScopeOnly, host, method, statusCodeClass, excludeStaticAssets, urlRegex, uniqueEndpoints
        )

        val seenEndpoints = linkedSetOf<String>()
        filterProxyHistory(api.proxy().history(), filter, api).asSequence()
            .flatMap { (index, entry) ->
                val body = entry.response()?.bodyToString() ?: return@flatMap emptySequence()
                val sourceUrl = runCatching { entry.finalRequest().url() }.getOrElse { "<unknown>" }

                extractEndpointsFromText(body).asSequence()
                    .filter { seenEndpoints.add(it) }
                    .map { endpoint ->
                        Json.encodeToString(JsEndpointResult(index, sourceUrl, endpoint))
                    }
            }
    }

    mcpTool<FingerprintTechnologies>(
        "Aggregates technology indicators (Server, X-Powered-By, framework cookies) per host from proxy history."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val filter = historyFilterFromParams(
            inScopeOnly, host, method, statusCodeClass, excludeStaticAssets, urlRegex, uniqueEndpoints
        )

        val hostIndicators = linkedMapOf<String, MutableSet<String>>()

        filterProxyHistory(api.proxy().history(), filter, api).forEach { (_, entry) ->
            val request = entry.finalRequest()
            val hostName = request.httpService()?.host() ?: return@forEach
            val indicators = hostIndicators.getOrPut(hostName) { mutableSetOf() }

            val response = entry.response() ?: return@forEach
            for (headerName in TECHNOLOGY_HEADERS) {
                response.headerValue(headerName)?.let { indicators.add("$headerName: $it") }
            }

            for ((cookieName, tech) in FRAMEWORK_COOKIE_INDICATORS) {
                if (request.hasHeader("Cookie") && request.headerValue("Cookie")?.contains(cookieName) == true) {
                    indicators.add("Cookie: $cookieName ($tech)")
                }
                response.headerValue("Set-Cookie")?.let { setCookie ->
                    if (setCookie.contains(cookieName)) {
                        indicators.add("Set-Cookie: $cookieName ($tech)")
                    }
                }
            }
        }

        if (hostIndicators.isEmpty()) {
            "No technology indicators found"
        } else {
            hostIndicators.entries.joinToString("\n\n") { (hostName, indicators) ->
                Json.encodeToString(TechnologyFingerprint(hostName, indicators.sorted()))
            }
        }
    }

    mcpTool<AggregateParameters>(
        "Collects parameter names, types, sample values, and source indices across filtered proxy history. " +
            "Highlights interesting parameter names."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val filter = historyFilterFromParams(
            inScopeOnly, host, method, statusCodeClass, excludeStaticAssets, urlRegex, uniqueEndpoints
        )

        val aggregated = linkedMapOf<String, MutableParameterAggregate>()

        filterProxyHistory(api.proxy().history(), filter, api).forEach { (index, entry) ->
            val request = entry.finalRequest()
            val url = runCatching { request.url() }.getOrElse { "<unknown>" }

            for (param in request.parameters()) {
                val key = "${param.type().name}:${param.name()}"
                val aggregate = aggregated.getOrPut(key) {
                    MutableParameterAggregate(
                        name = param.name(),
                        type = param.type().name,
                        sampleValues = linkedSetOf(),
                        sourceIndices = mutableListOf(),
                        sourceUrls = linkedSetOf(),
                        interesting = isInterestingParamName(param.name())
                    )
                }
                if (aggregate.sampleValues.size < 5) {
                    aggregate.sampleValues.add(redactSnippet(param.value()))
                }
                if (aggregate.sourceIndices.size < 10) {
                    aggregate.sourceIndices.add(index)
                }
                if (aggregate.sourceUrls.size < 5) {
                    aggregate.sourceUrls.add(url)
                }
            }
        }

        if (aggregated.isEmpty()) {
            "No parameters found in filtered history"
        } else {
            val results = aggregated.values
                .sortedWith(compareByDescending<MutableParameterAggregate> { it.interesting }.thenBy { it.name })
                .map {
                    ParameterAggregateResult(
                        name = it.name,
                        type = it.type,
                        sampleValues = it.sampleValues.toList(),
                        sourceIndices = it.sourceIndices,
                        sourceUrls = it.sourceUrls.toList(),
                        interesting = it.interesting
                    )
                }
            Json.encodeToString(results)
        }
    }

    mcpPaginatedTool<ScanJsBundles>(
        "Scans JavaScript bundle responses for secrets (SecretFinder/jsluice-style), endpoints, and source maps. " +
            "Uses entropy filtering to reduce false positives."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val filter = historyFilterFromParams(
            inScopeOnly, host, method, statusCodeClass, excludeStaticAssets, urlRegex, uniqueEndpoints
        )

        filterProxyHistory(api.proxy().history(), filter, api).asSequence()
            .flatMap { (index, entry) ->
                val response = entry.response() ?: return@flatMap emptySequence()
                val body = response.bodyToString()
                val url = runCatching { entry.finalRequest().url() }.getOrElse { "<unknown>" }
                val mime = runCatching { entry.mimeType()?.toString() }.getOrNull()

                if (!isJsBundleResponse(mime, url, body)) return@flatMap emptySequence()

                scanJsBundleText(body).asSequence().map { finding ->
                    Json.encodeToString(
                        JsBundleScanResult(
                            index = index,
                            url = url,
                            kind = finding.kind,
                            patternName = finding.patternName,
                            snippet = finding.snippet,
                            entropy = finding.entropy,
                            confidence = finding.confidence
                        )
                    )
                }
            }
    }

    mcpTool<MapAttackSurface>(
        "Builds a lightweight per-host attack surface summary: endpoints, parameters, tech indicators, counts, " +
            "and hints pointing to specialized recon/probe tools."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val filter = historyFilterFromParams(
            inScopeOnly, host, method, statusCodeClass, excludeStaticAssets, urlRegex, uniqueEndpoints
        )

        val surfaces = linkedMapOf<String, MutableHostSurface>()

        filterProxyHistory(api.proxy().history(), filter, api).forEach { (_, entry) ->
            val request = entry.finalRequest()
            val hostName = request.httpService()?.host() ?: return@forEach
            val url = runCatching { request.url() }.getOrElse { "<unknown>" }
            val surface = surfaces.getOrPut(hostName) { MutableHostSurface() }
            surface.requestCount++

            if (surface.endpoints.size < 50) {
                surface.endpoints.add(normalizeEndpointKey(request.method(), url))
            }

            for (param in request.parameters()) {
                if (surface.paramNames.size < 50) {
                    surface.paramNames.add(param.name())
                }
                if (isInterestingParamName(param.name())) {
                    surface.interestingParamNames.add(param.name())
                }
            }

            val response = entry.response() ?: return@forEach
            val mime = runCatching { entry.mimeType()?.toString() }.getOrNull()
            val body = response.bodyToString()

            if (isJsBundleResponse(mime, url, body)) surface.jsResponseCount++
            if (isHtmlResponse(mime, url)) surface.htmlResponseCount++

            for (headerName in TECHNOLOGY_HEADERS) {
                response.headerValue(headerName)?.let {
                    if (surface.techIndicators.size < 20) {
                        surface.techIndicators.add("$headerName: $it")
                    }
                }
            }
            for ((cookieName, tech) in FRAMEWORK_COOKIE_INDICATORS) {
                if (request.hasHeader("Cookie") && request.headerValue("Cookie")?.contains(cookieName) == true) {
                    surface.techIndicators.add("Cookie: $cookieName ($tech)")
                }
                response.headerValue("Set-Cookie")?.let { setCookie ->
                    if (setCookie.contains(cookieName)) {
                        surface.techIndicators.add("Set-Cookie: $cookieName ($tech)")
                    }
                }
            }
        }

        if (surfaces.isEmpty()) {
            "No attack surface data in filtered history"
        } else {
            val results = surfaces.entries
                .sortedByDescending { it.value.requestCount }
                .map { (hostName, surface) ->
                    HostSurfaceResult(
                        host = hostName,
                        requestCount = surface.requestCount,
                        jsResponseCount = surface.jsResponseCount,
                        htmlResponseCount = surface.htmlResponseCount,
                        endpoints = surface.endpoints.sorted().take(50),
                        parameters = surface.paramNames.sorted().take(50),
                        interestingParameters = surface.interestingParamNames.sorted(),
                        technologyIndicators = surface.techIndicators.sorted().take(20),
                        hints = buildAttackSurfaceHints(
                            surface.requestCount,
                            surface.jsResponseCount,
                            surface.htmlResponseCount,
                            surface.interestingParamNames.size
                        )
                    )
                }
            Json.encodeToString(results)
        }
    }

    mcpTool<AnalyzeSecurityHeaders>(
        "Analyzes security headers (CSP, HSTS, X-Frame-Options, CORS, etc.) per host from filtered proxy history."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val filter = historyFilterFromParams(
            inScopeOnly, host, method, statusCodeClass, excludeStaticAssets, urlRegex, uniqueEndpoints
        )

        val hostFindings = linkedMapOf<String, MutableSet<String>>()
        val hostReports = linkedMapOf<String, MutableList<SecurityHeaderFinding>>()

        filterProxyHistory(api.proxy().history(), filter, api).forEach { (_, entry) ->
            val request = entry.finalRequest()
            val hostName = request.httpService()?.host() ?: return@forEach
            val response = entry.response() ?: return@forEach
            val isHttps = request.httpService()?.secure() == true

            val headerMap = response.headers().associate { it.name() to it.value() }
            val findings = analyzeSecurityHeaders(headerMap, isHttps)

            val dedupe = hostFindings.getOrPut(hostName) { mutableSetOf() }
            val report = hostReports.getOrPut(hostName) { mutableListOf() }

            for (finding in findings) {
                val key = "${finding.header}:${finding.status}:${finding.detail}"
                if (dedupe.add(key)) {
                    report.add(
                        SecurityHeaderFinding(
                            header = finding.header,
                            status = finding.status.name,
                            detail = finding.detail
                        )
                    )
                }
            }
        }

        if (hostReports.isEmpty()) {
            "No security header data in filtered history"
        } else {
            hostReports.entries.joinToString("\n\n") { (hostName, findings) ->
                Json.encodeToString(SecurityHeaderReport(hostName, findings))
            }
        }
    }

    mcpPaginatedTool<ExtractFormsAndInputs>(
        "Extracts HTML forms and input fields from proxy history for fuzzing and CSRF analysis."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val filter = historyFilterFromParams(
            inScopeOnly, host, method, statusCodeClass, excludeStaticAssets, urlRegex, uniqueEndpoints
        )

        filterProxyHistory(api.proxy().history(), filter, api).asSequence()
            .flatMap { (index, entry) ->
                val response = entry.response() ?: return@flatMap emptySequence()
                val url = runCatching { entry.finalRequest().url() }.getOrElse { "<unknown>" }
                val mime = runCatching { entry.mimeType()?.toString() }.getOrNull()
                val body = response.bodyToString()

                if (!isHtmlResponse(mime, url)) return@flatMap emptySequence()

                extractFormsFromHtml(body).asSequence().map { form ->
                    Json.encodeToString(
                        FormResult(
                            index = index,
                            url = url,
                            action = form.action,
                            method = form.method,
                            inputs = form.inputs.map {
                                FormInput(name = it.name, type = it.type, hidden = it.hidden)
                            }
                        )
                    )
                }
            }
    }
}

@Serializable
data class SecretScanResult(
    val index: Int,
    val url: String,
    val patternName: String,
    val snippet: String,
    val confidence: String = "high"
)

@Serializable
data class JsEndpointResult(
    val index: Int,
    val sourceUrl: String,
    val endpoint: String
)

@Serializable
data class TechnologyFingerprint(
    val host: String,
    val indicators: List<String>
)

@Serializable
data class ParameterAggregateResult(
    val name: String,
    val type: String,
    val sampleValues: List<String>,
    val sourceIndices: List<Int>,
    val sourceUrls: List<String>,
    val interesting: Boolean
)

private data class MutableParameterAggregate(
    val name: String,
    val type: String,
    val sampleValues: LinkedHashSet<String>,
    val sourceIndices: MutableList<Int>,
    val sourceUrls: LinkedHashSet<String>,
    val interesting: Boolean
)

private data class MutableHostSurface(
    var requestCount: Int = 0,
    var jsResponseCount: Int = 0,
    var htmlResponseCount: Int = 0,
    val endpoints: LinkedHashSet<String> = linkedSetOf(),
    val paramNames: LinkedHashSet<String> = linkedSetOf(),
    val interestingParamNames: LinkedHashSet<String> = linkedSetOf(),
    val techIndicators: LinkedHashSet<String> = linkedSetOf()
)

@Serializable
data class ScanResponsesForSecrets(
    override val count: Int,
    override val offset: Int,
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false
) : Paginated

@Serializable
data class ExtractJsEndpoints(
    override val count: Int,
    override val offset: Int,
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false
) : Paginated

@Serializable
data class FingerprintTechnologies(
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false
)

@Serializable
data class AggregateParameters(
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false
)

@Serializable
data class JsBundleScanResult(
    val index: Int,
    val url: String,
    val kind: String,
    val patternName: String,
    val snippet: String,
    val entropy: Double?,
    val confidence: String = "high"
)

@Serializable
data class ScanJsBundles(
    override val count: Int,
    override val offset: Int,
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false
) : Paginated

@Serializable
data class HostSurfaceResult(
    val host: String,
    val requestCount: Int,
    val jsResponseCount: Int,
    val htmlResponseCount: Int,
    val endpoints: List<String>,
    val parameters: List<String>,
    val interestingParameters: List<String>,
    val technologyIndicators: List<String>,
    val hints: List<String>
)

@Serializable
data class SecurityHeaderFinding(
    val header: String,
    val status: String,
    val detail: String
)

@Serializable
data class SecurityHeaderReport(
    val host: String,
    val findings: List<SecurityHeaderFinding>
)

@Serializable
data class FormInput(
    val name: String,
    val type: String,
    val hidden: Boolean
)

@Serializable
data class FormResult(
    val index: Int,
    val url: String,
    val action: String?,
    val method: String,
    val inputs: List<FormInput>
)

@Serializable
data class MapAttackSurface(
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false
)

@Serializable
data class AnalyzeSecurityHeaders(
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false
)

@Serializable
data class ExtractFormsAndInputs(
    override val count: Int,
    override val offset: Int,
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false
) : Paginated
