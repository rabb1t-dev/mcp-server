package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessType

enum class IdorVerdict {
    LIKELY_IDOR,
    OK,
    REVIEW
}

fun defaultProbePayloads(): List<String> = listOf(
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "../../../etc/passwd",
    "'; WAITFOR DELAY '0:0:3'--",
    "\${7*7}",
    "`id`"
)

fun analyzeProbeResponse(
    payload: String,
    originalResponse: HttpResponse?,
    probeResponse: HttpResponse?
): ProbeResult {
    if (probeResponse == null) {
        return ProbeResult(
            payload = payload,
            statusCode = -1,
            responseLength = 0,
            reflected = false,
            reflectionContext = null,
            errorSignatures = emptyList(),
            lengthDelta = 0,
            statusChanged = originalResponse?.statusCode()?.toInt() != -1
        )
    }

    val body = probeResponse.bodyToString()
    val originalBody = originalResponse?.bodyToString() ?: ""
    val originalLength = originalBody.length
    val probeLength = body.length

    return ProbeResult(
        payload = payload,
        statusCode = probeResponse.statusCode().toInt(),
        responseLength = probeLength,
        reflected = body.contains(payload),
        reflectionContext = extractReflectionContext(payload, body),
        errorSignatures = detectErrorSignatures(body),
        lengthDelta = probeLength - originalLength,
        statusChanged = originalResponse?.statusCode() != probeResponse.statusCode()
    )
}

fun evaluateIdorVerdict(
    originalStatus: Int,
    alternateStatus: Int,
    originalBody: String,
    alternateBody: String,
    alternateValue: String
): IdorVerdict {
    if (alternateStatus != 200) return IdorVerdict.OK

    val similarity = responseSimilarity(originalBody, alternateBody)
    val containsAlternateValue = alternateBody.contains(alternateValue)

    return when {
        similarity > 0.75 && alternateBody != originalBody && containsAlternateValue ->
            IdorVerdict.LIKELY_IDOR

        similarity > 0.5 && alternateBody != originalBody ->
            IdorVerdict.REVIEW

        else -> IdorVerdict.OK
    }
}

fun findTargetParameter(request: HttpRequest, paramName: String?, paramType: String?): ParsedHttpParameter? {
    if (paramName != null) {
        val type = paramType?.let { runCatching { HttpParameterType.valueOf(it.uppercase()) }.getOrNull() }
        return if (type != null) {
            request.parameter(paramName, type)
        } else {
            request.parameter(paramName)
        }
    }

    return request.parameters().firstOrNull()
}

fun applyParameterValue(request: HttpRequest, param: ParsedHttpParameter, value: String): HttpRequest {
    val updated = HttpParameter.parameter(param.name(), value, param.type())
    return request.withUpdatedParameters(updated)
}

private data class DiffContent(val body: String, val status: Int)

private fun resolveDiffContent(api: MontoyaApi, historyIndex: Int?, rawContent: String?): DiffContent? {
    if (historyIndex != null) {
        val entry = resolveHistoryEntry(api, historyIndex) ?: return null
        val response = entry.response() ?: return null
        return DiffContent(response.bodyToString(), response.statusCode().toInt())
    }
    if (!rawContent.isNullOrBlank()) {
        return DiffContent(rawContent, -1)
    }
    return null
}

private fun timedSend(api: MontoyaApi, request: HttpRequest): Pair<Long, HttpResponse?> {
    val start = System.currentTimeMillis()
    val response = api.http().sendRequest(request)?.response()
    return System.currentTimeMillis() - start to response
}

private fun collectBaselineWithResponse(
    api: MontoyaApi,
    request: HttpRequest,
    delayMs: Int
): Pair<List<Long>, HttpResponse?> {
    var lastResponse: HttpResponse? = null
    val samples = collectBaselineTimings(delayMs = delayMs) {
        val (ms, response) = timedSend(api, request)
        lastResponse = response
        ms
    }
    return samples to lastResponse
}

private fun resolveWallClockDeadline(maxWallClockMs: Int): Long {
    return System.currentTimeMillis() + maxWallClockMs.coerceIn(5_000, 300_000)
}

private fun resolveFuzzPayloads(payloadSet: String?, inlinePayloads: List<String>, maxRequests: Int): List<String> {
    val source = when {
        inlinePayloads.isNotEmpty() -> inlinePayloads
        !payloadSet.isNullOrBlank() -> payloadsForSetName(payloadSet) ?: emptyList()
        else -> defaultProbePayloads()
    }
    return source.take(maxRequests.coerceIn(1, 100))
}

fun Server.registerProbeTools(api: MontoyaApi, config: McpConfig) {
    mcpTool<ProbeParameter>(
        "Probes a request parameter with injection payloads. Detects reflection, error signatures, and response changes. " +
            "Provide historyIndex, rawContent (+ target), or useActiveEditor=true."
    ) {
        val request = resolveRequestFromSource(
            api, historyIndex, rawContent, useActiveEditor,
            targetHostname, targetPort, usesHttps
        ) ?: return@mcpTool "Could not resolve request source"

        val targetParam = findTargetParameter(request, parameterName, parameterType)
            ?: return@mcpTool "No matching parameter found"

        val allowed = runBlocking { checkHttpPermissionForRequest(request, config, api) }
        if (!allowed) return@mcpTool "Send HTTP request denied by Burp Suite"

        val originalResponse = api.http().sendRequest(request)?.response()
        val payloadsToTest = if (payloads.isEmpty()) defaultProbePayloads() else payloads

        val results = payloadsToTest.map { payload ->
            val modified = applyParameterValue(request, targetParam, payload)
            val probeResponse = api.http().sendRequest(modified)?.response()
            analyzeProbeResponse(payload, originalResponse, probeResponse)
        }

        Json.encodeToString(
            ProbeParameterResult(
                parameterName = targetParam.name(),
                parameterType = targetParam.type().name,
                originalStatus = originalResponse?.statusCode()?.toInt() ?: -1,
                results = results
            )
        )
    }

    mcpTool<TestIdor>(
        "Tests for IDOR by swapping an object ID parameter with alternate values and comparing responses."
    ) {
        val request = resolveRequestFromSource(
            api, historyIndex, rawContent, useActiveEditor,
            targetHostname, targetPort, usesHttps
        ) ?: return@mcpTool "Could not resolve request source"

        val targetParam = findTargetParameter(request, parameterName, parameterType)
            ?: return@mcpTool "No matching parameter found"

        val allowed = runBlocking { checkHttpPermissionForRequest(request, config, api) }
        if (!allowed) return@mcpTool "Send HTTP request denied by Burp Suite"

        val originalResponse = api.http().sendRequest(request)?.response()
            ?: return@mcpTool "No response received for original request"

        val originalBody = originalResponse.bodyToString()
        val originalStatus = originalResponse.statusCode().toInt()

        val results = alternateValues.map { alternateValue ->
            val modified = applyParameterValue(request, targetParam, alternateValue)
            val alternateResponse = api.http().sendRequest(modified)?.response()
            val alternateBody = alternateResponse?.bodyToString() ?: ""
            val alternateStatus = alternateResponse?.statusCode()?.toInt() ?: -1
            val similarity = responseSimilarity(originalBody, alternateBody)
            val verdict = evaluateIdorVerdict(
                originalStatus, alternateStatus, originalBody, alternateBody, alternateValue
            )

            IdorTestResult(
                alternateValue = alternateValue,
                statusCode = alternateStatus,
                similarity = similarity,
                verdict = verdict.name
            )
        }

        Json.encodeToString(
            IdorTestSummary(
                parameterName = targetParam.name(),
                parameterType = targetParam.type().name,
                originalValue = targetParam.value(),
                originalStatus = originalStatus,
                results = results
            )
        )
    }

    mcpTool<FuzzParameter>(
        "Fuzzes a request parameter with a named payload set or inline payloads. " +
            "Returns anomaly-sorted results with timing, reflection, and error signatures."
    ) {
        val request = resolveRequestFromSource(
            api, historyIndex, rawContent, useActiveEditor,
            targetHostname, targetPort, usesHttps
        ) ?: return@mcpTool "Could not resolve request source"

        val targetParam = findTargetParameter(request, parameterName, parameterType)
            ?: return@mcpTool "No matching parameter found"

        val allowed = runBlocking { checkHttpPermissionForRequest(request, config, api) }
        if (!allowed) return@mcpTool "Send HTTP request denied by Burp Suite"

        val payloadsToTest = resolveFuzzPayloads(payloadSet, payloads, maxRequests)
        if (payloadsToTest.isEmpty()) return@mcpTool "No payloads to test"

        val deadline = resolveWallClockDeadline(maxWallClockMs)
        val (baselineMs, originalResponse) = timedSend(api, request)
        val originalErrorSigs = originalResponse?.bodyToString()
            ?.let { detectErrorSignatures(it).toSet() } ?: emptySet()

        val rows = payloadsToTest.mapNotNull { payload ->
            if (System.currentTimeMillis() >= deadline) return@mapNotNull null
            if (delayMs > 0) Thread.sleep(delayMs.toLong())
            val modified = applyParameterValue(request, targetParam, payload)
            val (probeMs, probeResponse) = timedSend(api, modified)
            val probe = analyzeProbeResponse(payload, originalResponse, probeResponse)
            val score = fuzzAnomalyScore(probe, probeMs, baselineMs, originalErrorSigs)
            FuzzRow(
                payload = payload,
                statusCode = probe.statusCode,
                responseLength = probe.responseLength,
                lengthDelta = probe.lengthDelta,
                reflected = probe.reflected,
                errorSignatures = probe.errorSignatures,
                statusChanged = probe.statusChanged,
                timingMs = probeMs,
                anomalyScore = score
            )
        }.sortedByDescending { it.anomalyScore }

        Json.encodeToString(
            FuzzParameterResult(
                parameterName = targetParam.name(),
                parameterType = targetParam.type().name,
                baselineTimingMs = baselineMs,
                originalStatus = originalResponse?.statusCode()?.toInt() ?: -1,
                results = rows
            )
        )
    }

    mcpTool<ProbeInjection>(
        "Runs opinionated injection probes for a vulnerability class (xss, sqli, sqli_time, ssti, traversal, cmdi, redirect, crlf, nosqli). " +
            "Returns per-payload verdicts with evidence."
    ) {
        val vuln = VulnClass.fromString(vulnClass)
            ?: return@mcpTool "Unknown vulnClass '$vulnClass'. Use: xss, sqli, sqli_time, ssti, traversal, cmdi, redirect, crlf, nosqli"

        val request = resolveRequestFromSource(
            api, historyIndex, rawContent, useActiveEditor,
            targetHostname, targetPort, usesHttps
        ) ?: return@mcpTool "Could not resolve request source"

        val targetParam = findTargetParameter(request, parameterName, parameterType)
            ?: return@mcpTool "No matching parameter found"

        val allowed = runBlocking { checkHttpPermissionForRequest(request, config, api) }
        if (!allowed) return@mcpTool "Send HTTP request denied by Burp Suite"

        val payloadsToTest = payloadsForVulnClass(vuln)
        val deadline = resolveWallClockDeadline(maxWallClockMs)
        val (baselineSamples, originalResponse) = if (vuln == VulnClass.SQLI_TIME) {
            collectBaselineWithResponse(api, request, delayMs)
        } else {
            val (ms, response) = timedSend(api, request)
            listOf(ms) to response
        }
        val baselineMedian = medianTimingMs(baselineSamples)

        val results = payloadsToTest.mapNotNull { payload ->
            if (System.currentTimeMillis() >= deadline) return@mapNotNull null
            if (delayMs > 0) Thread.sleep(delayMs.toLong())
            val modified = applyParameterValue(request, targetParam, payload)
            val (probeMs, probeResponse) = timedSend(api, modified)
            var (verdict, evidence) = evaluateInjectionVerdict(
                vuln, payload, originalResponse, probeResponse, baselineMedian, probeMs, baselineSamples
            )

            if (vuln == VulnClass.SQLI_TIME && verdict == InjectionVerdict.VULNERABLE) {
                if (delayMs > 0) Thread.sleep(delayMs.toLong())
                val (confirmMs, _) = timedSend(api, modified)
                val (confirmVerdict, _) = evaluateInjectionVerdict(
                    vuln, payload, originalResponse, probeResponse, baselineMedian, confirmMs, baselineSamples
                )
                if (confirmVerdict != InjectionVerdict.VULNERABLE) {
                    verdict = InjectionVerdict.SUSPICIOUS
                    evidence = "Initial timing anomaly; confirmation probe did not repeat delay"
                }
            }

            InjectionProbeResult(
                payload = payload,
                verdict = verdict.name,
                evidence = evidence,
                statusCode = probeResponse?.statusCode()?.toInt() ?: -1,
                timingMs = probeMs
            )
        }

        Json.encodeToString(
            ProbeInjectionSummary(
                vulnClass = vuln.name.lowercase(),
                parameterName = targetParam.name(),
                parameterType = targetParam.type().name,
                baselineTimingMs = baselineMedian,
                results = results
            )
        )
    }

    mcpTool<DiffResponses>(
        "Returns a structured diff between two HTTP responses (history indices or raw content). " +
            "Includes status/length deltas, similarity, and line-level changes."
    ) {
        if (leftHistoryIndex != null || rightHistoryIndex != null) {
            val allowed = runBlocking {
                checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
            }
            if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val left = resolveDiffContent(api, leftHistoryIndex, leftContent)
            ?: return@mcpTool "Could not resolve left response content"
        val right = resolveDiffContent(api, rightHistoryIndex, rightContent)
            ?: return@mcpTool "Could not resolve right response content"

        Json.encodeToString(
            diffResponses(left.body, right.body, left.status, right.status)
        )
    }
}

fun Server.registerProbeOobTool(api: MontoyaApi, config: McpConfig, collaboratorClient: CollaboratorClient) {
    mcpTool<ProbeParameterOob>(
        "Injects a Burp Collaborator payload into a parameter and sends the request for out-of-band detection. " +
            "Poll get_collaborator_interactions with the returned payloadId."
    ) {
        val request = resolveRequestFromSource(
            api, historyIndex, rawContent, useActiveEditor,
            targetHostname, targetPort, usesHttps
        ) ?: return@mcpTool "Could not resolve request source"

        val targetParam = findTargetParameter(request, parameterName, parameterType)
            ?: return@mcpTool "No matching parameter found"

        val allowed = runBlocking { checkHttpPermissionForRequest(request, config, api) }
        if (!allowed) return@mcpTool "Send HTTP request denied by Burp Suite"

        val payload = collaboratorClient.generatePayload()
        val modified = applyParameterValue(request, targetParam, payload.toString())
        val response = api.http().sendRequest(modified)?.response()

        Json.encodeToString(
            ProbeOobResult(
                parameterName = targetParam.name(),
                parameterType = targetParam.type().name,
                collaboratorPayload = payload.toString(),
                payloadId = payload.id().toString(),
                statusCode = response?.statusCode()?.toInt() ?: -1
            )
        )
    }
}

@Serializable
data class ProbeResult(
    val payload: String,
    val statusCode: Int,
    val responseLength: Int,
    val reflected: Boolean,
    val reflectionContext: String?,
    val errorSignatures: List<String>,
    val lengthDelta: Int,
    val statusChanged: Boolean
)

@Serializable
data class ProbeParameterResult(
    val parameterName: String,
    val parameterType: String,
    val originalStatus: Int,
    val results: List<ProbeResult>
)

@Serializable
data class IdorTestResult(
    val alternateValue: String,
    val statusCode: Int,
    val similarity: Double,
    val verdict: String
)

@Serializable
data class IdorTestSummary(
    val parameterName: String,
    val parameterType: String,
    val originalValue: String,
    val originalStatus: Int,
    val results: List<IdorTestResult>
)

@Serializable
data class ProbeOobResult(
    val parameterName: String,
    val parameterType: String,
    val collaboratorPayload: String,
    val payloadId: String,
    val statusCode: Int
)

@Serializable
data class ProbeParameter(
    val historyIndex: Int? = null,
    val rawContent: String? = null,
    val useActiveEditor: Boolean = false,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
    val parameterName: String? = null,
    val parameterType: String? = null,
    val payloads: List<String> = emptyList()
)

@Serializable
data class TestIdor(
    val historyIndex: Int? = null,
    val rawContent: String? = null,
    val useActiveEditor: Boolean = false,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
    val parameterName: String,
    val parameterType: String? = null,
    val alternateValues: List<String>
)

@Serializable
data class ProbeParameterOob(
    val historyIndex: Int? = null,
    val rawContent: String? = null,
    val useActiveEditor: Boolean = false,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
    val parameterName: String? = null,
    val parameterType: String? = null
)

@Serializable
data class FuzzRow(
    val payload: String,
    val statusCode: Int,
    val responseLength: Int,
    val lengthDelta: Int,
    val reflected: Boolean,
    val errorSignatures: List<String>,
    val statusChanged: Boolean,
    val timingMs: Long,
    val anomalyScore: Int
)

@Serializable
data class FuzzParameterResult(
    val parameterName: String,
    val parameterType: String,
    val baselineTimingMs: Long,
    val originalStatus: Int,
    val results: List<FuzzRow>
)

@Serializable
data class InjectionProbeResult(
    val payload: String,
    val verdict: String,
    val evidence: String?,
    val statusCode: Int,
    val timingMs: Long
)

@Serializable
data class ProbeInjectionSummary(
    val vulnClass: String,
    val parameterName: String,
    val parameterType: String,
    val baselineTimingMs: Long,
    val results: List<InjectionProbeResult>
)

@Serializable
data class FuzzParameter(
    val historyIndex: Int? = null,
    val rawContent: String? = null,
    val useActiveEditor: Boolean = false,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
    val parameterName: String? = null,
    val parameterType: String? = null,
    val payloadSet: String? = null,
    val payloads: List<String> = emptyList(),
    val maxRequests: Int = 50,
    val delayMs: Int = 0,
    val maxWallClockMs: Int = 120_000
)

@Serializable
data class ProbeInjection(
    val historyIndex: Int? = null,
    val rawContent: String? = null,
    val useActiveEditor: Boolean = false,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
    val parameterName: String? = null,
    val parameterType: String? = null,
    val vulnClass: String,
    val delayMs: Int = 0,
    val maxWallClockMs: Int = 120_000
)

@Serializable
data class DiffResponses(
    val leftHistoryIndex: Int? = null,
    val leftContent: String? = null,
    val rightHistoryIndex: Int? = null,
    val rightContent: String? = null
)
