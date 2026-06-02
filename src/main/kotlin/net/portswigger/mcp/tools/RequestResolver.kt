package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyHttpRequestResponse

fun resolveHistoryEntry(api: MontoyaApi, index: Int): ProxyHttpRequestResponse? {
    val history = api.proxy().history()
    if (index < 0 || index >= history.size) return null
    return history[index]
}

fun resolveHistoryRequest(api: MontoyaApi, index: Int): HttpRequest? {
    return resolveHistoryEntry(api, index)?.finalRequest()
}

fun resolveRawRequest(
    content: String,
    targetHostname: String,
    targetPort: Int,
    usesHttps: Boolean
): HttpRequest {
    val service = HttpService.httpService(targetHostname, targetPort, usesHttps)
    return HttpRequest.httpRequest(service, normalizeHttpContent(content))
}

fun resolveActiveEditorRequest(api: MontoyaApi): HttpRequest? {
    val editorText = getActiveEditor(api)?.text ?: return null
    if (editorText.isBlank()) return null
    return HttpRequest.httpRequest(normalizeHttpContent(editorText))
}

fun resolveRequestFromSource(
    api: MontoyaApi,
    historyIndex: Int?,
    rawContent: String?,
    useActiveEditor: Boolean,
    targetHostname: String?,
    targetPort: Int?,
    usesHttps: Boolean?
): HttpRequest? {
    if (useActiveEditor) {
        return resolveActiveEditorRequest(api)
    }

    if (historyIndex != null) {
        return resolveHistoryRequest(api, historyIndex)
    }

    if (!rawContent.isNullOrBlank()) {
        requireNotNull(targetHostname) { "targetHostname is required when using rawContent" }
        requireNotNull(targetPort) { "targetPort is required when using rawContent" }
        requireNotNull(usesHttps) { "usesHttps is required when using rawContent" }
        return resolveRawRequest(rawContent, targetHostname, targetPort, usesHttps)
    }

    return null
}
