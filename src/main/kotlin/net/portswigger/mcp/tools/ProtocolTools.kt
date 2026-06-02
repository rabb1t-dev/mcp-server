package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity
import java.util.Collections

fun Server.registerProtocolTools(api: MontoyaApi, config: McpConfig) {
    mcpTool<SendWebsocketMessage>(
        "Creates a WebSocket connection, sends a message, collects replies for waitMs milliseconds (100-30000, blocks the calling thread), then closes."
    ) {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(
                targetHostname, targetPort, config,
                "WebSocket $path: $message", api
            )
        }
        if (!allowed) return@mcpTool "Send HTTP request denied by Burp Suite"

        val service = HttpService.httpService(targetHostname, targetPort, usesHttps)
        val creation = api.websockets().createWebSocket(service, path)

        if (creation.status() != ExtensionWebSocketCreationStatus.SUCCESS) {
            val upgradeStatus = creation.upgradeResponse().map { it.statusCode().toInt() }.orElse(-1)
            return@mcpTool Json.encodeToString(
                WebSocketResult(
                    success = false,
                    creationStatus = creation.status().name,
                    upgradeStatusCode = upgradeStatus,
                    messages = emptyList()
                )
            )
        }

        val webSocket = creation.webSocket().orElse(null)
            ?: return@mcpTool "WebSocket creation reported success but no socket was returned"

        val receivedMessages = Collections.synchronizedList(mutableListOf<String>())

        val registration = webSocket.registerMessageHandler(object : ExtensionWebSocketMessageHandler {
            override fun textMessageReceived(textMessage: burp.api.montoya.websocket.TextMessage) {
                receivedMessages.add("[TEXT] ${textMessage.payload()}")
            }

            override fun binaryMessageReceived(binaryMessage: burp.api.montoya.websocket.BinaryMessage) {
                receivedMessages.add("[BINARY] ${binaryMessage.payload().toString()}")
            }
        })

        try {
            if (binary) {
                webSocket.sendBinaryMessage(ByteArray.byteArray(message))
            } else {
                webSocket.sendTextMessage(message)
            }

            Thread.sleep(waitMs.toLong().coerceIn(100, 30_000))
        } finally {
            registration.deregister()
            webSocket.close()
        }

        Json.encodeToString(
            WebSocketResult(
                success = true,
                creationStatus = creation.status().name,
                upgradeStatusCode = creation.upgradeResponse().map { it.statusCode().toInt() }.orElse(200),
                messages = receivedMessages.toList()
            )
        )
    }

    mcpTool<SendToComparer>(
        "Sends two items to Burp Comparer for side-by-side diff. Provide history indices or raw content strings."
    ) {
        val leftBytes = resolveComparerContent(api, leftHistoryIndex, leftContent)
            ?: return@mcpTool "Could not resolve left comparer content"
        val rightBytes = resolveComparerContent(api, rightHistoryIndex, rightContent)
            ?: return@mcpTool "Could not resolve right comparer content"

        api.comparer().sendToComparer(leftBytes, rightBytes)
        "Sent two items to Burp Comparer"
    }
}

private fun resolveComparerContent(
    api: MontoyaApi,
    historyIndex: Int?,
    rawContent: String?
): ByteArray? {
    if (historyIndex != null) {
        val entry = resolveHistoryEntry(api, historyIndex) ?: return null
        val content = buildString {
            entry.request()?.let { append(it.toString()) }
            entry.response()?.let {
                if (isNotEmpty()) append("\n\n")
                append(it.toString())
            }
        }
        return ByteArray.byteArray(content)
    }

    if (!rawContent.isNullOrBlank()) {
        return ByteArray.byteArray(rawContent)
    }

    return null
}

@Serializable
data class WebSocketResult(
    val success: Boolean,
    val creationStatus: String,
    val upgradeStatusCode: Int,
    val messages: List<String>
)

@Serializable
data class SendWebsocketMessage(
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val path: String,
    val message: String,
    val binary: Boolean = false,
    val waitMs: Int = 2000
) : HttpServiceParams

@Serializable
data class SendToComparer(
    val leftHistoryIndex: Int? = null,
    val leftContent: String? = null,
    val rightHistoryIndex: Int? = null,
    val rightContent: String? = null
)
