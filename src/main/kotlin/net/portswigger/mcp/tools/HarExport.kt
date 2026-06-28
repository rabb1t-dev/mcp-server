package net.portswigger.mcp.tools

import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

private val harJson = Json { prettyPrint = false }

@Serializable
data class HarLog(
    val log: HarLogRoot
)

@Serializable
data class HarLogRoot(
    val version: String = "1.2",
    val creator: HarCreator = HarCreator(),
    val entries: List<HarEntry>
)

@Serializable
data class HarCreator(
    val name: String = "Burp MCP Server",
    val version: String = "1.0"
)

@Serializable
data class HarEntry(
    val startedDateTime: String,
    val time: Long,
    val request: HarRequest,
    val response: HarResponse,
    val cache: Map<String, String> = emptyMap(),
    val timings: HarTimings = HarTimings()
)

@Serializable
data class HarRequest(
    val method: String,
    val url: String,
    val httpVersion: String,
    val headers: List<HarNameValue>,
    val queryString: List<HarNameValue>,
    val cookies: List<HarNameValue>,
    val headersSize: Int,
    val bodySize: Int,
    val postData: HarPostData? = null
)

@Serializable
data class HarResponse(
    val status: Int,
    val statusText: String,
    val httpVersion: String,
    val headers: List<HarNameValue>,
    val cookies: List<HarNameValue>,
    val content: HarContent,
    val redirectURL: String = "",
    val headersSize: Int,
    val bodySize: Int
)

@Serializable
data class HarNameValue(val name: String, val value: String)

@Serializable
data class HarPostData(
    val mimeType: String,
    val text: String
)

@Serializable
data class HarContent(
    val size: Int,
    val mimeType: String,
    val text: String? = null,
    val encoding: String? = null
)

@Serializable
data class HarTimings(val send: Long = 0, val wait: Long = 0, val receive: Long = 0)

fun buildHarFromProxyEntries(entries: List<Pair<Int, ProxyHttpRequestResponse>>): String {
    val harEntries = entries.mapNotNull { (_, entry) -> entry.toHarEntry() }
    return harJson.encodeToString(HarLog(HarLogRoot(entries = harEntries)))
}

private fun ProxyHttpRequestResponse.toHarEntry(): HarEntry? {
    if (!hasResponse()) return null

    val request = try {
        finalRequest()
    } catch (_: Exception) {
        return null
    }
    val response = response() ?: return null

    val url = runCatching { request.url() }.getOrNull() ?: return null
    val started = time().toInstant()
        .atOffset(ZoneOffset.UTC)
        .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)

    return HarEntry(
        startedDateTime = started,
        time = 0,
        request = request.toHarRequest(url),
        response = response.toHarResponse()
    )
}

private fun HttpRequest.toHarRequest(url: String): HarRequest {
    val raw = toString()
    val body = bodyToString()
    val headers = headers().map { HarNameValue(it.name(), it.value()) }
    val queryParams = parameters(HttpParameterType.URL).map { HarNameValue(it.name(), it.value()) }

    return HarRequest(
        method = method(),
        url = url,
        httpVersion = httpVersion(),
        headers = headers,
        queryString = queryParams,
        cookies = emptyList(),
        headersSize = raw.length,
        bodySize = body.length,
        postData = body.takeIf { it.isNotEmpty() }?.let {
            HarPostData(
                mimeType = headerValue("Content-Type") ?: "application/octet-stream",
                text = it
            )
        }
    )
}

private fun HttpResponse.toHarResponse(): HarResponse {
    val raw = toString()
    val body = bodyToString()
    val headers = headers().map { HarNameValue(it.name(), it.value()) }
    val mime = headerValue("Content-Type") ?: mimeType()?.toString() ?: "application/octet-stream"

    return HarResponse(
        status = statusCode().toInt(),
        statusText = reasonPhrase(),
        httpVersion = httpVersion(),
        headers = headers,
        cookies = emptyList(),
        content = HarContent(
            size = body.length,
            mimeType = mime,
            text = if (bodyIsText(mime)) body else null,
            encoding = if (bodyIsText(mime)) null else "base64"
        ).let { content ->
            if (content.encoding == "base64") {
                content.copy(text = Base64.getEncoder().encodeToString(body.toByteArray(Charsets.ISO_8859_1)))
            } else {
                content
            }
        },
        headersSize = raw.length,
        bodySize = body.length
    )
}

private fun bodyIsText(mimeType: String): Boolean {
    val lower = mimeType.lowercase()
    return lower.startsWith("text/") ||
        lower.contains("json") ||
        lower.contains("xml") ||
        lower.contains("javascript") ||
        lower.contains("html")
}

fun resolveHarArchiveDirectory(engagementDirectory: String): java.nio.file.Path? {
    val trimmed = engagementDirectory.trim()
    if (trimmed.isEmpty()) return null
    return java.nio.file.Paths.get(trimmed, "proxy-archives")
}

fun harArchiveFileName(batchIndex: Int): String {
    val timestamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
        .format(Instant.now().atOffset(ZoneOffset.UTC))
    return "proxy-history-$timestamp-batch$batchIndex.har"
}
