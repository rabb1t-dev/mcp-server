package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toLoggerEntryDetails
import net.portswigger.mcp.schema.toSummaryForm
import net.portswigger.mcp.security.DataAccessType
import java.util.regex.Pattern

fun Server.registerLoggerTools(api: MontoyaApi, config: McpConfig, store: LoggerCaptureStore) {
    mcpPaginatedTool<GetLoggerHistory>(
        "Displays lightweight summaries of cross-tool HTTP traffic captured by the MCP Logger " +
            "(Scanner, Repeater, Intruder, Extensions, Proxy, etc.). Capture is forward-only from extension load. " +
            "Use get_logger_history_entry for full request/response details."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.LOGGER, config, api, "Logger capture")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Logger capture access denied by Burp Suite")
        }

        val filter = loggerFilterFromParams(
            inScopeOnly = inScopeOnly,
            host = host,
            method = method,
            statusCodeClass = statusCodeClass,
            excludeStaticAssets = excludeStaticAssets,
            urlRegex = urlRegex,
            uniqueEndpoints = uniqueEndpoints,
            toolType = toolType,
        )

        filterLoggerEntriesForBrowse(store.snapshot(), filter, api).asSequence()
            .map { Json.encodeToString(it.toSummaryForm()) }
    }

    mcpPaginatedTool<GetLoggerHistoryRegex>(
        "Displays lightweight summaries of captured cross-tool HTTP traffic matching a full-text regex. " +
            "Use get_logger_history_entry for full request/response details."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.LOGGER, config, api, "Logger capture")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Logger capture access denied by Burp Suite")
        }

        val filter = loggerFilterFromParams(
            inScopeOnly = inScopeOnly,
            host = host,
            method = method,
            statusCodeClass = statusCodeClass,
            excludeStaticAssets = excludeStaticAssets,
            urlRegex = urlRegex,
            uniqueEndpoints = uniqueEndpoints,
            toolType = toolType,
        )

        val compiledRegex = Pattern.compile(regex)
        filterLoggerEntriesForBrowse(store.snapshot(), filter, api, compiledRegex).asSequence()
            .map { Json.encodeToString(it.toSummaryForm()) }
    }

    mcpTool<GetLoggerHistoryEntry>(
        "Returns the full request and response for a single Logger capture entry by index. " +
            "Use get_logger_history first to discover indices."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.LOGGER, config, api, "Logger capture")
        }
        if (!allowed) return@mcpTool "Logger capture access denied by Burp Suite"

        val entry = store.getEntry(index)
            ?: return@mcpTool "No logger capture entry at index $index"

        truncateFullEntry(Json.encodeToString(entry.toLoggerEntryDetails()))
    }

    mcpTool<ClearLoggerCapture>(
        "Clears all captured Logger traffic from memory and persisted project storage (if enabled). " +
            "Requires confirm=true and Logger capture access approval."
    ) {
        if (!confirm) {
            return@mcpTool "Clear not confirmed; pass confirm=true to wipe Logger capture"
        }

        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.LOGGER, config, api, "Logger capture clear")
        }
        if (!allowed) return@mcpTool "Logger capture access denied by Burp Suite"

        store.clear()
        "Logger capture cleared"
    }
}

@Serializable
data class GetLoggerHistory(
    override val count: Int,
    override val offset: Int,
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false,
    val toolType: String? = null,
) : Paginated

@Serializable
data class GetLoggerHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false,
    val toolType: String? = null,
) : Paginated

@Serializable
data class GetLoggerHistoryEntry(val index: Int)

@Serializable
data class ClearLoggerCapture(val confirm: Boolean = true)
