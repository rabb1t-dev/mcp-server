package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import java.util.regex.Pattern

data class HistoryFilterOptions(
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false,
)

private val NUMERIC_PATH_SEGMENT = Regex("/\\d+")
private val NUMERIC_QUERY_VALUE = Regex("=\\d+")
private val UUID_QUERY_VALUE = Regex("=[a-fA-F0-9-]{36}")
private val STATIC_MIME_PREFIXES = listOf("image/", "text/css", "text/javascript", "application/javascript")

fun normalizeEndpointKey(method: String, url: String): String {
    val normalizedPath = url
        .replace(NUMERIC_PATH_SEGMENT, "/{id}")
        .replace(NUMERIC_QUERY_VALUE, "={val}")
        .replace(UUID_QUERY_VALUE, "={uuid}")
    return "${method.uppercase()} $normalizedPath"
}

fun matchesStatusCodeClass(statusCode: Int, statusCodeClass: String?): Boolean {
    if (statusCodeClass.isNullOrBlank()) return true

    val normalized = statusCodeClass.trim().lowercase()
    if (normalized.endsWith("xx") && normalized.length == 3) {
        val prefix = normalized.first().digitToIntOrNull() ?: return false
        return statusCode in (prefix * 100) until ((prefix + 1) * 100)
    }

    return statusCode == statusCodeClass.trim().toIntOrNull()
}

fun isStaticAssetMime(mimeType: MimeType?): Boolean {
    if (mimeType == null) return false
    val description = mimeType.toString().lowercase()
    return STATIC_MIME_PREFIXES.any { description.contains(it) }
}

fun matchesHistoryFilter(
    entry: ProxyHttpRequestResponse,
    filter: HistoryFilterOptions,
    api: MontoyaApi,
    seenEndpoints: MutableSet<String>? = null
): Boolean {
    if (!entry.hasResponse()) return false

    val request = try {
        entry.finalRequest()
    } catch (_: Exception) {
        return false
    }

    val url = try {
        request.url()
    } catch (_: Exception) {
        return false
    }

    if (filter.inScopeOnly && !api.scope().isInScope(url)) return false

    filter.host?.let { hostFilter ->
        val host = request.httpService()?.host() ?: return false
        if (!host.equals(hostFilter, ignoreCase = true) && !host.contains(hostFilter, ignoreCase = true)) {
            return false
        }
    }

    filter.method?.let { methodFilter ->
        if (!request.method().equals(methodFilter, ignoreCase = true)) return false
    }

    val response = entry.response()
    val statusCode = response?.statusCode()?.toInt() ?: -1
    if (!matchesStatusCodeClass(statusCode, filter.statusCodeClass)) return false

    if (filter.excludeStaticAssets && isStaticAssetMime(entry.mimeType())) return false

    filter.urlRegex?.let { pattern ->
        val compiled = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE)
        if (!compiled.matcher(url).find()) return false
    }

    if (filter.uniqueEndpoints) {
        val key = normalizeEndpointKey(request.method(), url)
        val endpoints = seenEndpoints ?: return false
        if (!endpoints.add(key)) return false
    }

    return true
}

fun filterProxyHistory(
    history: List<ProxyHttpRequestResponse>,
    filter: HistoryFilterOptions,
    api: MontoyaApi,
    fullTextRegex: Pattern? = null
): List<IndexedValue<ProxyHttpRequestResponse>> {
    val seenEndpoints = if (filter.uniqueEndpoints) mutableSetOf<String>() else null

    return history.asSequence()
        .withIndex()
        .filter { (_, entry) ->
            if (fullTextRegex != null && !entry.contains(fullTextRegex)) return@filter false
            matchesHistoryFilter(entry, filter, api, seenEndpoints)
        }
        .toList()
}
