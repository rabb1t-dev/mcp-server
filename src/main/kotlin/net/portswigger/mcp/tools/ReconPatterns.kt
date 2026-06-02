package net.portswigger.mcp.tools

import java.util.regex.Pattern

data class SecretMatch(
    val patternName: String,
    val snippet: String,
    val confidence: String = "high"
)

data class SecretPattern(
    val name: String,
    val pattern: Pattern,
    val confidence: String = "high"
)

private const val MAX_SNIPPET_LENGTH = 120

val SECRET_PATTERNS: List<SecretPattern> = listOf(
    SecretPattern("aws_access_key", Pattern.compile("AKIA[0-9A-Z]{16}")),
    SecretPattern("jwt", Pattern.compile("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}")),
    SecretPattern("google_api_key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}")),
    SecretPattern("slack_token", Pattern.compile("xox[baprs]-[0-9A-Za-z-]{10,}")),
    SecretPattern("private_key_header", Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    SecretPattern("bearer_token", Pattern.compile("(?i)bearer\\s+[A-Za-z0-9\\-._~+/]+=*")),
    SecretPattern("api_key_assignment", Pattern.compile("(?i)(?:api[_-]?key|apikey|secret[_-]?key)\\s*[=:]\\s*['\"]?[A-Za-z0-9\\-._~+/]{8,}")),
    SecretPattern("email", Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"), confidence = "low"),
    SecretPattern("internal_ip", Pattern.compile("\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b"), confidence = "low")
)

private val JS_ENDPOINT_PATTERNS = listOf(
    Pattern.compile("""(?:"|')((?:https?://|/)[^"'\\s<>]+)(?:"|')"""),
    Pattern.compile("""(?:"|')(/(?:api|v[0-9]+|rest|graphql|auth|admin|internal)[^"'\\s<>]*)(?:"|')""", Pattern.CASE_INSENSITIVE),
    Pattern.compile("""fetch\s*\(\s*["']([^"']+)["']"""),
    Pattern.compile("""axios\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"""),
    Pattern.compile("""\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']"""),
    Pattern.compile("""url\s*:\s*["']([^"']+)["']""", Pattern.CASE_INSENSITIVE)
)

val ERROR_SIGNATURE_PATTERNS: List<Pair<String, Pattern>> = listOf(
    "sql_syntax" to Pattern.compile("(?i)(?:You have an error in your )?SQL syntax|syntax error at or near"),
    "oracle_error" to Pattern.compile("(?i)ORA-\\d{5}"),
    "sqlstate" to Pattern.compile("(?i)SQLSTATE\\[\\w+\\]"),
    "unclosed_quotation" to Pattern.compile("(?i)unclosed quotation mark|Unclosed quotation mark"),
    "stack_trace" to Pattern.compile("(?i)(?:Exception in thread|Traceback \\(most recent call last\\)|at \\w+\\.\\w+\\([^)]+\\.java:\\d+\\))"),
    "asp_net_error" to Pattern.compile("(?i)(?:Server Error in '/' Application|System\\.Web\\.HttpException)"),
    "php_error" to Pattern.compile("(?i)(?:Fatal error:|Parse error:|Warning:.*on line \\d+)"),
    "debug_disclosure" to Pattern.compile("(?i)(?:stack trace:|debug mode|Exception Details:)")
)

val INTERESTING_PARAM_NAMES = setOf(
    "redirect", "url", "uri", "file", "path", "id", "uid", "user", "user_id",
    "debug", "cmd", "command", "exec", "token", "key", "secret", "admin",
    "role", "next", "return", "callback", "dest", "destination", "page"
)

val FRAMEWORK_COOKIE_INDICATORS = mapOf(
    "PHPSESSID" to "PHP",
    "JSESSIONID" to "Java/JSP",
    "ASP.NET_SessionId" to "ASP.NET",
    "laravel_session" to "Laravel",
    "connect.sid" to "Express.js",
    "_session_id" to "Rails",
    "csrftoken" to "Django/CSRF"
)

val TECHNOLOGY_HEADERS = listOf("Server", "X-Powered-By", "Via", "X-AspNet-Version", "X-Generator")

fun scanTextForSecrets(text: String): List<SecretMatch> {
    val matches = mutableListOf<SecretMatch>()
    val seen = mutableSetOf<String>()

    for (secretPattern in SECRET_PATTERNS) {
        val matcher = secretPattern.pattern.matcher(text)
        while (matcher.find()) {
            val raw = matcher.group()
            val dedupeKey = "${secretPattern.name}:$raw"
            if (seen.add(dedupeKey)) {
                matches.add(SecretMatch(secretPattern.name, redactSnippet(raw), secretPattern.confidence))
            }
        }
    }

    return matches
}

fun extractEndpointsFromText(text: String): List<String> {
    val endpoints = linkedSetOf<String>()

    for (pattern in JS_ENDPOINT_PATTERNS) {
        val matcher = pattern.matcher(text)
        while (matcher.find()) {
            val endpoint = matcher.group(1)?.trim() ?: continue
            if (endpoint.length < 2 || endpoint.startsWith("#")) continue
            if (endpoint.matches(Regex("(?i)^(text|application|image)/.+"))) continue
            endpoints.add(endpoint)
        }
    }

    return endpoints.toList()
}

fun detectErrorSignatures(text: String): List<String> {
    return ERROR_SIGNATURE_PATTERNS
        .filter { (_, pattern) -> pattern.matcher(text).find() }
        .map { (name, _) -> name }
}

fun isInterestingParamName(name: String): Boolean {
    val lower = name.lowercase()
    return INTERESTING_PARAM_NAMES.any { lower.contains(it) }
}

fun redactSnippet(value: String): String {
    val trimmed = value.trim()
    if (trimmed.length <= MAX_SNIPPET_LENGTH) return trimmed

    return if (trimmed.length > 20) {
        "${trimmed.take(8)}...${trimmed.takeLast(4)}"
    } else {
        trimmed.take(MAX_SNIPPET_LENGTH) + "..."
    }
}

fun extractReflectionContext(payload: String, responseBody: String, contextRadius: Int = 40): String? {
    val index = responseBody.indexOf(payload)
    if (index < 0) return null

    val start = (index - contextRadius).coerceAtLeast(0)
    val end = (index + payload.length + contextRadius).coerceAtMost(responseBody.length)
    return responseBody.substring(start, end)
}

fun responseSimilarity(originalBody: String, modifiedBody: String): Double {
    if (originalBody == modifiedBody) return 1.0
    if (originalBody.isEmpty() || modifiedBody.isEmpty()) return 0.0

    val left = truncateForSimilarity(originalBody)
    val right = truncateForSimilarity(modifiedBody)
    val longer = maxOf(left.length, right.length)
    val distance = levenshteinDistance(left, right)
    return (1.0 - distance.toDouble() / longer).coerceIn(0.0, 1.0)
}

/** Caps bodies at 8KB (first+last half) before Levenshtein to avoid O(n*m) blowups on large responses. */
internal fun truncateForSimilarity(body: String, maxChars: Int = 8192): String {
    if (body.length <= maxChars) return body
    val half = maxChars / 2
    return body.take(half) + body.takeLast(half)
}

private fun levenshteinDistance(a: String, b: String): Int {
    if (a == b) return 0
    if (a.isEmpty()) return b.length
    if (b.isEmpty()) return a.length

    val costs = IntArray(b.length + 1) { it }
    for (i in 1..a.length) {
        var previousDiagonal = costs[0]
        costs[0] = i
        for (j in 1..b.length) {
            val previousColumn = costs[j]
            val substitute = previousDiagonal + if (a[i - 1] == b[j - 1]) 0 else 1
            val insert = costs[j] + 1
            val delete = costs[j - 1] + 1
            previousDiagonal = previousColumn
            costs[j] = minOf(substitute, insert, delete)
        }
    }
    return costs[b.length]
}
