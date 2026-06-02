package net.portswigger.mcp.tools

import java.util.regex.Pattern

enum class HeaderFindingStatus {
    PRESENT,
    MISSING,
    WEAK
}

data class HeaderFinding(
    val header: String,
    val status: HeaderFindingStatus,
    val detail: String
)

data class ParsedFormInput(
    val name: String,
    val type: String,
    val hidden: Boolean
)

data class ParsedForm(
    val action: String?,
    val method: String,
    val inputs: List<ParsedFormInput>
)

private val FORM_TAG_PATTERN = Pattern.compile(
    "(?is)<form\\b([^>]*)>(.*?)</form>"
)
private val FORM_ATTR_PATTERN = Pattern.compile(
    """(?i)(action|method)\s*=\s*["']([^"']*)["']"""
)
private val INPUT_TAG_PATTERN = Pattern.compile(
    """(?is)<(input|select|textarea)\b([^>/]*)(?:/>|>(?:[^<]*</\1>)?)"""
)
private val INPUT_ATTR_PATTERN = Pattern.compile(
    """(?i)(name|type)\s*=\s*["']([^"']*)["']"""
)

private const val MAX_FORMS_PER_PAGE = 20
private const val MAX_INPUTS_PER_FORM = 50

private val SECURITY_HEADERS_TO_CHECK = listOf(
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
)

fun analyzeSecurityHeaders(headers: Map<String, String>, isHttps: Boolean): List<HeaderFinding> {
    val normalized = headers.mapKeys { (key, _) -> key.lowercase() }
    val findings = mutableListOf<HeaderFinding>()

    for (headerName in SECURITY_HEADERS_TO_CHECK) {
        val key = headerName.lowercase()
        val value = normalized[key]

        when (headerName) {
            "Strict-Transport-Security" -> {
                if (!isHttps) {
                    findings.add(
                        HeaderFinding(headerName, HeaderFindingStatus.PRESENT, "Not applicable on plain HTTP")
                    )
                } else if (value.isNullOrBlank()) {
                    findings.add(
                        HeaderFinding(headerName, HeaderFindingStatus.MISSING, "HSTS not set on HTTPS response")
                    )
                } else {
                    val weak = !value.contains("max-age", ignoreCase = true) ||
                        value.contains("max-age=0", ignoreCase = true)
                    findings.add(
                        HeaderFinding(
                            headerName,
                            if (weak) HeaderFindingStatus.WEAK else HeaderFindingStatus.PRESENT,
                            value
                        )
                    )
                }
            }
            "Content-Security-Policy" -> {
                if (value.isNullOrBlank()) {
                    findings.add(
                        HeaderFinding(headerName, HeaderFindingStatus.MISSING, "No CSP header")
                    )
                } else if (value.contains("unsafe-inline", ignoreCase = true) ||
                    value.contains("unsafe-eval", ignoreCase = true)
                ) {
                    findings.add(HeaderFinding(headerName, HeaderFindingStatus.WEAK, value))
                } else {
                    findings.add(HeaderFinding(headerName, HeaderFindingStatus.PRESENT, value))
                }
            }
            "X-Frame-Options" -> {
                if (value.isNullOrBlank()) {
                    findings.add(
                        HeaderFinding(headerName, HeaderFindingStatus.MISSING, "Clickjacking protection absent")
                    )
                } else {
                    findings.add(HeaderFinding(headerName, HeaderFindingStatus.PRESENT, value))
                }
            }
            "X-Content-Type-Options" -> {
                if (value.isNullOrBlank()) {
                    findings.add(
                        HeaderFinding(headerName, HeaderFindingStatus.MISSING, "MIME sniffing protection absent")
                    )
                } else if (!value.equals("nosniff", ignoreCase = true)) {
                    findings.add(HeaderFinding(headerName, HeaderFindingStatus.WEAK, value))
                } else {
                    findings.add(HeaderFinding(headerName, HeaderFindingStatus.PRESENT, value))
                }
            }
            else -> {
                if (value.isNullOrBlank()) {
                    findings.add(HeaderFinding(headerName, HeaderFindingStatus.MISSING, "Header not present"))
                } else {
                    findings.add(HeaderFinding(headerName, HeaderFindingStatus.PRESENT, value))
                }
            }
        }
    }

    val corsOrigin = normalized["access-control-allow-origin"]
    val corsCredentials = normalized["access-control-allow-credentials"]
    if (!corsOrigin.isNullOrBlank()) {
        val permissiveWildcard = corsOrigin.trim() == "*"
        val credentialsTrue = corsCredentials?.equals("true", ignoreCase = true) == true
        when {
            permissiveWildcard && credentialsTrue ->
                findings.add(
                    HeaderFinding(
                        "CORS",
                        HeaderFindingStatus.WEAK,
                        "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
                    )
                )
            permissiveWildcard ->
                findings.add(
                    HeaderFinding("CORS", HeaderFindingStatus.WEAK, "Access-Control-Allow-Origin: *")
                )
            else ->
                findings.add(
                    HeaderFinding("CORS", HeaderFindingStatus.PRESENT, "Origin: $corsOrigin")
                )
        }
    }

    val cacheControl = normalized["cache-control"]
    if (cacheControl.isNullOrBlank()) {
        findings.add(
            HeaderFinding(
                "Cache-Control",
                HeaderFindingStatus.MISSING,
                "No cache-control header (review for sensitive responses)"
            )
        )
    }

    return findings
}

fun extractFormsFromHtml(html: String): List<ParsedForm> {
    val forms = mutableListOf<ParsedForm>()
    val formMatcher = FORM_TAG_PATTERN.matcher(html)

    while (formMatcher.find() && forms.size < MAX_FORMS_PER_PAGE) {
        val formAttrs = formMatcher.group(1) ?: ""
        val formBody = formMatcher.group(2) ?: ""

        var action: String? = null
        var method = "GET"
        val attrMatcher = FORM_ATTR_PATTERN.matcher(formAttrs)
        while (attrMatcher.find()) {
            when (attrMatcher.group(1)?.lowercase()) {
                "action" -> action = attrMatcher.group(2)?.trim()?.ifBlank { null }
                "method" -> method = attrMatcher.group(2)?.trim()?.uppercase() ?: "GET"
            }
        }

        val inputs = mutableListOf<ParsedFormInput>()
        val inputMatcher = INPUT_TAG_PATTERN.matcher(formBody)
        while (inputMatcher.find() && inputs.size < MAX_INPUTS_PER_FORM) {
            val tagName = inputMatcher.group(1)?.lowercase() ?: continue
            val inputAttrs = inputMatcher.group(2) ?: ""

            var name: String? = null
            var type = if (tagName == "textarea") "textarea" else if (tagName == "select") "select" else "text"
            val attrInputMatcher = INPUT_ATTR_PATTERN.matcher(inputAttrs)
            while (attrInputMatcher.find()) {
                when (attrInputMatcher.group(1)?.lowercase()) {
                    "name" -> name = attrInputMatcher.group(2)?.trim()
                    "type" -> type = attrInputMatcher.group(2)?.trim()?.lowercase() ?: type
                }
            }

            if (!name.isNullOrBlank()) {
                inputs.add(
                    ParsedFormInput(
                        name = name,
                        type = type,
                        hidden = type == "hidden"
                    )
                )
            }
        }

        forms.add(ParsedForm(action = action, method = method, inputs = inputs))
    }

    return forms
}

fun responseHeadersToMap(headers: List<Pair<String, String>>): Map<String, String> {
    return headers.associate { (name, value) -> name to value }
}

fun isHtmlResponse(mimeType: String?, url: String): Boolean {
    val mime = mimeType?.lowercase().orEmpty()
    if (mime.contains("html")) return true
    val path = url.substringBefore('?').lowercase()
    return path.endsWith(".html") || path.endsWith(".htm") || path.endsWith("/")
}

fun buildAttackSurfaceHints(
    requestCount: Int,
    jsResponseCount: Int,
    htmlResponseCount: Int,
    interestingParamCount: Int
): List<String> {
    val hints = mutableListOf<String>()
    if (requestCount == 0) return hints

    hints.add("Use aggregate_parameters for full parameter values and source indices")
    if (interestingParamCount > 0) {
        hints.add("Interesting parameters detected — consider probe_injection or fuzz_parameter on flagged params")
    }
    if (jsResponseCount > 0) {
        hints.add("JS responses present — run scan_js_bundles and extract_js_endpoints for secrets and routes")
    }
    if (htmlResponseCount > 0) {
        hints.add("HTML responses present — run extract_forms_and_inputs for form/CSRF analysis")
    }
    hints.add("Run analyze_security_headers for CSP/HSTS/CORS review per host")
    hints.add("Run scan_responses_for_secrets for credential leaks in response bodies")
    return hints
}
