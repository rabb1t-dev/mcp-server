package net.portswigger.mcp.tools

import java.util.regex.Pattern
import kotlin.math.log2

data class JsBundleFinding(
    val patternName: String,
    val snippet: String,
    val kind: String,
    val entropy: Double?,
    val confidence: String = "high"
)

data class JsSecretPattern(
    val name: String,
    val pattern: Pattern,
    val minEntropy: Double = 0.0,
    val requiresEntropyCheck: Boolean = false,
    val confidence: String = "high"
)

private val SOURCE_MAP_PATTERN = Pattern.compile(
    "(?m)(?://#|//@)\\s*sourceMappingURL\\s*=\\s*(\\S+)"
)

val JS_SECRET_PATTERNS: List<JsSecretPattern> = listOf(
    JsSecretPattern("aws_access_key", Pattern.compile("(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
    JsSecretPattern("aws_secret_key", Pattern.compile("(?i)aws[_\\-.]?secret[_\\-.]?access[_\\-.]?key\\s*[=:]\\s*['\"]?[A-Za-z0-9/+=]{40}")),
    JsSecretPattern("google_api_key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}")),
    JsSecretPattern("google_oauth", Pattern.compile("[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com")),
    JsSecretPattern("google_captcha", Pattern.compile("6L[0-9A-Za-z-_]{38}|6P[0-9A-Za-z-_]{38}")),
    JsSecretPattern("facebook_token", Pattern.compile("(?i)(?:EAACEdEose0cBA|EAAG)[0-9A-Za-z]{20,}")),
    JsSecretPattern("github_token", Pattern.compile("(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}")),
    JsSecretPattern("gitlab_token", Pattern.compile("glpat-[A-Za-z0-9\\-_]{20,}")),
    JsSecretPattern("npm_token", Pattern.compile("npm_[A-Za-z0-9]{36}")),
    JsSecretPattern("stripe_live", Pattern.compile("(?:sk|rk)_live_[0-9a-zA-Z]{24,}")),
    JsSecretPattern("stripe_test", Pattern.compile("(?:sk|rk)_test_[0-9a-zA-Z]{24,}")),
    JsSecretPattern("twilio_sid", Pattern.compile("AC[a-f0-9]{32}")),
    JsSecretPattern("twilio_auth", Pattern.compile("SK[a-f0-9]{32}")),
    JsSecretPattern("sendgrid", Pattern.compile("SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}")),
    JsSecretPattern("mailgun", Pattern.compile("key-[0-9a-zA-Z]{32}")),
    JsSecretPattern(
        "heroku_api",
        Pattern.compile("(?i)(?:heroku|HEROKU_API_KEY)[^\\n\"']{0,40}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    ),
    JsSecretPattern("slack_token", Pattern.compile("xox[baprs]-[0-9A-Za-z-]{10,}")),
    JsSecretPattern("slack_webhook", Pattern.compile("https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    JsSecretPattern("jwt", Pattern.compile("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}")),
    JsSecretPattern("private_key", Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    JsSecretPattern("square_token", Pattern.compile("sq0atp-[0-9A-Za-z\\-_]{22}|sq0csp-[0-9A-Za-z\\-_]{43}")),
    JsSecretPattern(
        "paypal_braintree",
        Pattern.compile("access_token${'$'}production${'$'}[0-9a-z]{16}${'$'}[0-9a-f]{32}")
    ),
    JsSecretPattern(
        "generic_secret_assignment",
        Pattern.compile("(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\\s*[=:]\\s*['\"]([A-Za-z0-9\\-._~+/=]{12,})['\"]"),
        minEntropy = 3.5,
        requiresEntropyCheck = true
    ),
    JsSecretPattern(
        "high_entropy_string",
        Pattern.compile("['\"]([A-Za-z0-9+/=]{32,})['\"]"),
        minEntropy = 4.5,
        requiresEntropyCheck = true
    )
)

private const val MIN_ENTROPY_FOR_GENERIC = 3.5

fun shannonEntropy(value: String): Double {
    if (value.isEmpty()) return 0.0
    val frequencies = value.groupingBy { it }.eachCount()
    val length = value.length.toDouble()
    return frequencies.values.sumOf { count ->
        val probability = count / length
        -probability * log2(probability)
    }
}

fun extractSourceMapUrls(text: String): List<String> {
    val urls = mutableListOf<String>()
    val matcher = SOURCE_MAP_PATTERN.matcher(text)
    while (matcher.find()) {
        matcher.group(1)?.let { urls.add(it.trim()) }
    }
    return urls
}

fun isJsBundleResponse(mimeType: String?, url: String, body: String): Boolean {
    val mime = mimeType?.lowercase().orEmpty()
    if (mime.contains("javascript") || mime.contains("ecmascript")) return true
    if (url.lowercase().contains(".js") || url.lowercase().contains(".mjs")) return true
    if (mime.contains("html") && body.contains("<script")) return true
    return false
}

fun scanJsBundleText(text: String): List<JsBundleFinding> {
    val findings = mutableListOf<JsBundleFinding>()
    val seen = mutableSetOf<String>()

    for (pattern in JS_SECRET_PATTERNS) {
        val matcher = pattern.pattern.matcher(text)
        while (matcher.find()) {
            val raw = if (matcher.groupCount() >= 1) {
                matcher.group(1) ?: matcher.group()
            } else {
                matcher.group()
            }
            if (pattern.requiresEntropyCheck) {
                val entropy = shannonEntropy(raw)
                if (entropy < pattern.minEntropy) continue
                val key = "${pattern.name}:$raw"
                if (seen.add(key)) {
                    findings.add(
                        JsBundleFinding(
                            patternName = pattern.name,
                            snippet = redactSnippet(raw),
                            kind = "secret",
                            entropy = entropy,
                            confidence = pattern.confidence
                        )
                    )
                }
            } else {
                val key = "${pattern.name}:$raw"
                if (seen.add(key)) {
                    findings.add(
                        JsBundleFinding(
                            patternName = pattern.name,
                            snippet = redactSnippet(raw),
                            kind = "secret",
                            entropy = shannonEntropy(raw).takeIf { it >= MIN_ENTROPY_FOR_GENERIC },
                            confidence = pattern.confidence
                        )
                    )
                }
            }
        }
    }

    for (endpoint in extractEndpointsFromText(text)) {
        val key = "endpoint:$endpoint"
        if (seen.add(key)) {
            findings.add(
                JsBundleFinding(
                    patternName = "endpoint",
                    snippet = endpoint,
                    kind = "endpoint",
                    entropy = null
                )
            )
        }
    }

    for (sourceMap in extractSourceMapUrls(text)) {
        val key = "sourcemap:$sourceMap"
        if (seen.add(key)) {
            findings.add(
                JsBundleFinding(
                    patternName = "sourcemap",
                    snippet = sourceMap,
                    kind = "sourcemap",
                    entropy = null
                )
            )
        }
    }

    return findings
}
