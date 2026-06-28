package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import kotlinx.serialization.Serializable
import java.util.regex.Pattern

enum class AuthVerdict {
    ENFORCED,
    BYPASSED,
    NEEDS_REVIEW;

    fun displayName(): String = when (this) {
        ENFORCED -> "Enforced!"
        BYPASSED -> "Bypassed!"
        NEEDS_REVIEW -> "Is enforced??? (needs review)"
    }
}

enum class DetectorType {
    STATUS_CODE_EQUALS,
    HEADERS_CONTAINS,
    HEADERS_REGEX,
    BODY_CONTAINS,
    BODY_REGEX,
    FULL_RESPONSE_CONTAINS,
    FULL_RESPONSE_REGEX,
    FULL_RESPONSE_LENGTH,
}

enum class DetectorLogic {
    AND,
    OR;

    companion object {
        fun fromString(value: String): DetectorLogic =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: AND
    }
}

@Serializable
data class EnforcementDetectorSpec(
    val type: String,
    val value: String,
    val inverse: Boolean = false
)

data class EnforcementDetector(
    val type: DetectorType,
    val value: String,
    val inverse: Boolean = false
)

fun EnforcementDetectorSpec.toDetector(): EnforcementDetector? {
    val detectorType = runCatching { DetectorType.valueOf(type.uppercase()) }.getOrNull() ?: return null
    return EnforcementDetector(detectorType, value, inverse)
}

class AuthTestEngine(private val api: MontoyaApi) {

    fun buildIdentityRequest(original: HttpRequest, identityHeaders: List<String>): HttpRequest {
        var request = stripAuthenticationHeaders(original)

        for (headerLine in identityHeaders) {
            if (!headerLine.contains(":")) continue
            val name = headerLine.substringBefore(":").trim()
            val value = headerLine.substringAfter(":").trim()
            if (name.isEmpty()) continue
            request = request.withRemovedHeader(name).withAddedHeader(name, value)
        }

        return request
    }

    fun buildUnauthenticatedRequest(original: HttpRequest): HttpRequest {
        return stripAuthenticationHeaders(original)
    }

    private fun stripAuthenticationHeaders(request: HttpRequest): HttpRequest {
        var modified = request
        for (headerName in AUTHENTICATION_HEADER_NAMES) {
            if (modified.hasHeader(headerName)) {
                modified = modified.withRemovedHeader(headerName)
            }
        }
        return modified
    }

    fun replay(request: HttpRequest): HttpResponse? {
        return api.http().sendRequest(request)?.response()
    }

    fun checkBypass(
        originalResponse: HttpResponse?,
        modifiedResponse: HttpResponse?,
        detectors: List<EnforcementDetector>,
        logic: DetectorLogic
    ): AuthVerdict {
        if (originalResponse == null || modifiedResponse == null) {
            return AuthVerdict.NEEDS_REVIEW
        }

        return checkBypassFromValues(
            originalResponse.statusCode(),
            modifiedResponse.statusCode(),
            originalResponse.bodyToString(),
            modifiedResponse.bodyToString(),
            modifiedResponse,
            detectors,
            logic
        )
    }

    companion object {
        private val AUTHENTICATION_HEADER_NAMES = listOf(
            "Cookie",
            "Authorization",
            "X-Api-Key",
            "X-Auth-Token"
        )
    }
}

internal fun checkBypassFromValues(
    oldStatusCode: Short,
    newStatusCode: Short,
    oldBody: String,
    newBody: String,
    responseForDetectors: HttpResponse?,
    detectors: List<EnforcementDetector>,
    logic: DetectorLogic
): AuthVerdict {
    if (oldStatusCode != newStatusCode) {
        return AuthVerdict.ENFORCED
    }

    if (detectors.isNotEmpty() && responseForDetectors != null &&
        matchesEnforcementDetectors(responseForDetectors, detectors, logic)
    ) {
        return AuthVerdict.ENFORCED
    }

    if (oldBody == newBody) {
        return AuthVerdict.BYPASSED
    }

    if (responseSimilarity(oldBody, newBody) >= AUTORIZE_BYPASS_SIMILARITY) {
        return AuthVerdict.BYPASSED
    }

    return AuthVerdict.NEEDS_REVIEW
}

private const val AUTORIZE_BYPASS_SIMILARITY = 0.98

private fun matchesEnforcementDetectors(
    response: HttpResponse,
    detectors: List<EnforcementDetector>,
    logic: DetectorLogic
): Boolean {
    var authEnforced = logic == DetectorLogic.AND

    for (detector in detectors) {
        val matched = evaluateDetector(response, detector)
        authEnforced = when (logic) {
            DetectorLogic.AND -> authEnforced && matched
            DetectorLogic.OR -> authEnforced || matched
        }
    }

    return authEnforced
}

private fun evaluateDetector(response: HttpResponse, detector: EnforcementDetector): Boolean {
    val matched = when (detector.type) {
        DetectorType.STATUS_CODE_EQUALS ->
            response.statusCode().toString() == detector.value.trim()

        DetectorType.HEADERS_CONTAINS ->
            response.headers().joinToString("\n") { "${it.name()}: ${it.value()}" }
                .contains(detector.value)

        DetectorType.HEADERS_REGEX ->
            Pattern.compile(detector.value, Pattern.CASE_INSENSITIVE)
                .matcher(response.headers().joinToString("\n") { "${it.name()}: ${it.value()}" })
                .find()

        DetectorType.BODY_CONTAINS ->
            response.bodyToString().contains(detector.value)

        DetectorType.BODY_REGEX ->
            Pattern.compile(detector.value, Pattern.CASE_INSENSITIVE)
                .matcher(response.bodyToString())
                .find()

        DetectorType.FULL_RESPONSE_CONTAINS ->
            response.toString().contains(detector.value)

        DetectorType.FULL_RESPONSE_REGEX ->
            Pattern.compile(detector.value, Pattern.CASE_INSENSITIVE)
                .matcher(response.toString())
                .find()

        DetectorType.FULL_RESPONSE_LENGTH ->
            response.toString().length.toString() == detector.value.trim()
    }

    return if (detector.inverse) !matched else matched
}
