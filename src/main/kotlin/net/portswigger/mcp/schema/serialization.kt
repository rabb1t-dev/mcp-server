package net.portswigger.mcp.schema

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable
import net.portswigger.mcp.tools.LoggerEntry

fun LoggerEntry.toSummaryForm(): LoggerHistorySummary {
    val request = request
    val response = response
    return LoggerHistorySummary(
        index = index,
        messageId = messageId,
        toolType = toolType,
        method = request.method(),
        url = runCatching { request.url() }.getOrNull() ?: "<unknown>",
        host = request.httpService()?.host() ?: "<unknown>",
        statusCode = response?.statusCode()?.toInt() ?: -1,
        mimeType = response?.let { runCatching { it.mimeType().toString() }.getOrNull() },
        responseLength = response?.body()?.length() ?: 0,
        hasParameters = request.hasParameters(),
        time = timestampMs.toString(),
    )
}

fun LoggerEntry.toLoggerEntryDetails(): LoggerEntryDetails {
    return LoggerEntryDetails(
        index = index,
        messageId = messageId,
        toolType = toolType,
        timestampMs = timestampMs,
        request = request.toString(),
        response = response?.toString(),
    )
}

fun AuditIssue.toSerializableForm(): IssueDetails {
    return IssueDetails(
        name = name(),
        detail = detail(),
        remediation = remediation(),
        httpService = HttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl(),
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().map { it.toSerializableForm() },
        collaboratorInteractions = collaboratorInteractions().map {
            Interaction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = AuditIssueDefinition(
            id = definition().name(),
            background = definition().background(),
            remediation = definition().remediation(),
            typeIndex = definition().typeIndex(),
        )
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyHttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyHttpRequestResponse.toSummaryForm(index: Int): ProxyHistorySummary {
    val request = try {
        finalRequest()
    } catch (_: Exception) {
        null
    }

    val response = response()
    val annotations = annotations()

    return ProxyHistorySummary(
        index = index,
        id = id(),
        method = request?.method() ?: "<unknown>",
        url = request?.let { runCatching { it.url() }.getOrNull() } ?: "<unknown>",
        host = request?.httpService()?.host() ?: "<unknown>",
        statusCode = response?.statusCode()?.toInt() ?: -1,
        mimeType = mimeType()?.toString(),
        responseLength = response?.body()?.length() ?: 0,
        hasParameters = request?.hasParameters() ?: false,
        highlight = if (annotations.hasHighlightColor()) annotations.highlightColor().displayName() else null,
        notes = annotations.notes().takeIf { it.isNotBlank() },
        time = time().toString()
    )
}

fun MontoyaHttpRequestResponse.toSummaryForm(index: Int): SiteMapEntrySummary {
    val request = request()
    val response = response()
    val annotations = annotations()

    return SiteMapEntrySummary(
        index = index,
        method = request.method(),
        url = runCatching { request.url() }.getOrNull() ?: "<unknown>",
        host = request.httpService().host(),
        statusCode = response?.statusCode()?.toInt() ?: -1,
        mimeType = response?.let { runCatching { it.mimeType().toString() }.getOrNull() },
        responseLength = response?.body()?.length() ?: 0,
        hasParameters = request.hasParameters(),
        highlight = if (annotations.hasHighlightColor()) annotations.highlightColor().displayName() else null,
        notes = annotations.notes().takeIf { it.isNotBlank() }
    )
}

fun AuditIssue.toSummaryForm(index: Int): ScannerIssueSummary {
    return ScannerIssueSummary(
        index = index,
        name = name(),
        severity = severity().name,
        confidence = confidence().name,
        url = baseUrl(),
        host = httpService()?.host()
    )
}

fun OrganizerItem.toSummaryForm(index: Int): OrganizerItemSummary {
    return OrganizerItemSummary(
        index = index,
        id = id(),
        status = status().displayName(),
        method = request()?.method(),
        url = request()?.let { runCatching { it.url() }.getOrNull() },
        host = request()?.httpService()?.host(),
        statusCode = response()?.statusCode()?.toInt() ?: -1,
        highlight = if (annotations().hasHighlightColor()) annotations().highlightColor().displayName() else null,
        notes = annotations().notes().takeIf { it.isNotBlank() }
    )
}

fun HttpRequest.extractParametersForm(): List<ExtractedParameter> {
    return parameters().map { param ->
        ExtractedParameter(
            name = param.name(),
            value = param.value(),
            type = param.type().name
        )
    }
}

fun OrganizerItem.toSerializableForm(): OrganizerItemDetails {
    return OrganizerItemDetails(
        id = id(),
        status = status().displayName(),
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyWebSocketMessage.toSerializableForm(): WebSocketMessage {
    return WebSocketMessage(
        payload = payload()?.toString() ?: "<no payload>",
        direction =
            if (direction() == Direction.CLIENT_TO_SERVER)
                WebSocketMessageDirection.CLIENT_TO_SERVER
            else
                WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes()
    )
}

@Serializable
data class IssueDetails(
    val name: String?,
    val detail: String?,
    val remediation: String?,
    val httpService: HttpService?,
    val baseUrl: String?,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val requestResponses: List<HttpRequestResponse>,
    val collaboratorInteractions: List<Interaction>,
    val definition: AuditIssueDefinition
)

@Serializable
data class HttpService(
    val host: String,
    val port: Int,
    val secure: Boolean
)

@Serializable
enum class AuditIssueSeverity {
    HIGH,
    MEDIUM,
    LOW,
    INFORMATION,
    FALSE_POSITIVE;
}

@Serializable
enum class AuditIssueConfidence {
    CERTAIN,
    FIRM,
    TENTATIVE
}

@Serializable
data class HttpRequestResponse(
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class ProxyHistorySummary(
    val index: Int,
    val id: Int,
    val method: String,
    val url: String,
    val host: String,
    val statusCode: Int,
    val mimeType: String?,
    val responseLength: Int,
    val hasParameters: Boolean,
    val highlight: String?,
    val notes: String?,
    val time: String?
)

@Serializable
data class LoggerHistorySummary(
    val index: Int,
    val messageId: Int,
    val toolType: String,
    val method: String,
    val url: String,
    val host: String,
    val statusCode: Int,
    val mimeType: String?,
    val responseLength: Int,
    val hasParameters: Boolean,
    val time: String,
)

@Serializable
data class LoggerEntryDetails(
    val index: Int,
    val messageId: Int,
    val toolType: String,
    val timestampMs: Long,
    val request: String,
    val response: String?,
)

@Serializable
data class SiteMapEntrySummary(
    val index: Int,
    val method: String,
    val url: String,
    val host: String,
    val statusCode: Int,
    val mimeType: String?,
    val responseLength: Int,
    val hasParameters: Boolean,
    val highlight: String?,
    val notes: String?
)

@Serializable
data class ScannerIssueSummary(
    val index: Int,
    val name: String?,
    val severity: String,
    val confidence: String,
    val url: String?,
    val host: String?
)

@Serializable
data class OrganizerItemSummary(
    val index: Int,
    val id: Int,
    val status: String,
    val method: String?,
    val url: String?,
    val host: String?,
    val statusCode: Int,
    val highlight: String?,
    val notes: String?
)

@Serializable
data class ExtractedParameter(
    val name: String,
    val value: String,
    val type: String
)

@Serializable
data class OrganizerItemDetails(
    val id: Int,
    val status: String,
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class Interaction(
    val interactionId: String,
    val timestamp: String
)

@Serializable
data class AuditIssueDefinition(
    val id: String,
    val background: String?,
    val remediation: String?,
    val typeIndex: Int
)


@Serializable
enum class WebSocketMessageDirection {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}

@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?
)

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null),
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = it.requestResponse()?.request()?.toString(),
                response = it.requestResponse()?.response()?.toString()
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = it.conversation()
            )
        }
    )
}

@Serializable
data class CollaboratorInteractionDetails(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String?,
    val dnsDetails: CollaboratorDnsDetails?,
    val httpDetails: CollaboratorHttpDetails?,
    val smtpDetails: CollaboratorSmtpDetails?
)

@Serializable
data class CollaboratorDnsDetails(
    val queryType: String
)

@Serializable
data class CollaboratorHttpDetails(
    val protocol: String,
    val request: String?,
    val response: String?
)

@Serializable
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String
)