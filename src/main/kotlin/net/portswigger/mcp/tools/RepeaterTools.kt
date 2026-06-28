package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toLoggerEntryDetails
import net.portswigger.mcp.schema.toSummaryForm
import net.portswigger.mcp.security.DataAccessType
import java.util.regex.Pattern

private fun repeaterFilterFromParams(
    inScopeOnly: Boolean = false,
    host: String? = null,
    method: String? = null,
    statusCodeClass: String? = null,
    excludeStaticAssets: Boolean = false,
    urlRegex: String? = null,
    uniqueEndpoints: Boolean = false,
): LoggerFilterOptions = loggerFilterFromParams(
    inScopeOnly = inScopeOnly,
    host = host,
    method = method,
    statusCodeClass = statusCodeClass,
    excludeStaticAssets = excludeStaticAssets,
    urlRegex = urlRegex,
    uniqueEndpoints = uniqueEndpoints,
    toolType = ToolType.REPEATER.name,
)

fun Server.registerRepeaterTools(api: MontoyaApi, config: McpConfig, store: LoggerCaptureStore) {
    mcpPaginatedTool<GetRepeaterHistory>(
        "Lists Repeater traffic captured since extension load (every send from a Repeater tab), newest first. " +
            "Montoya cannot read idle/unsent Repeater editor tabs — only sent requests appear here. " +
            "Use get_repeater_history_entry for full request/response."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.LOGGER, config, api, "Repeater capture")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Repeater capture access denied by Burp Suite")
        }

        val filter = repeaterFilterFromParams(
            inScopeOnly = inScopeOnly,
            host = host,
            method = method,
            statusCodeClass = statusCodeClass,
            excludeStaticAssets = excludeStaticAssets,
            urlRegex = urlRegex,
            uniqueEndpoints = uniqueEndpoints,
        )

        filterLoggerEntriesForBrowse(store.snapshot(), filter, api).asSequence()
            .map { Json.encodeToString(it.toSummaryForm()) }
    }

    mcpPaginatedTool<GetRepeaterHistoryRegex>(
        "Lists Repeater traffic matching a full-text regex. Use get_repeater_history_entry for details."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.LOGGER, config, api, "Repeater capture")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Repeater capture access denied by Burp Suite")
        }

        val filter = repeaterFilterFromParams(
            inScopeOnly = inScopeOnly,
            host = host,
            method = method,
            statusCodeClass = statusCodeClass,
            excludeStaticAssets = excludeStaticAssets,
            urlRegex = urlRegex,
            uniqueEndpoints = uniqueEndpoints,
        )

        val compiledRegex = Pattern.compile(regex)
        filterLoggerEntriesForBrowse(store.snapshot(), filter, api, compiledRegex).asSequence()
            .map { Json.encodeToString(it.toSummaryForm()) }
    }

    mcpTool<GetRepeaterHistoryEntry>(
        "Returns full request/response for a Repeater capture entry by index. Use get_repeater_history first."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.LOGGER, config, api, "Repeater capture")
        }
        if (!allowed) return@mcpTool "Repeater capture access denied by Burp Suite"

        val entry = store.getEntry(index)
            ?: return@mcpTool "No Repeater capture entry at index $index"

        if (!entry.toolType.equals(ToolType.REPEATER.name, ignoreCase = true)) {
            return@mcpTool "Entry $index is not Repeater traffic (toolType=${entry.toolType})"
        }

        truncateFullEntry(Json.encodeToString(entry.toLoggerEntryDetails()))
    }
}

fun Server.registerProxyHarTools(config: McpConfig, archiveStore: ProxyHarArchiveStore) {
    mcpTool<ExportProxyHistoryHar>(
        "Exports proxy HTTP history to a HAR file under {engagement directory}/proxy-archives/. " +
            "Use this before manually clearing Burp proxy history."
    ) {
        val (_, message) = when {
            startIndex != null && count != null -> archiveStore.exportRangeToHar(startIndex, count)
            else -> archiveStore.exportAllToHar()
        }
        message
    }

    mcpTool("get_proxy_har_archive_status", "Returns proxy HAR auto-export configuration and progress.") {
        archiveStore.statusSummary()
    }
}

@Serializable
data class GetRepeaterHistory(
    override val count: Int,
    override val offset: Int,
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false,
) : Paginated

@Serializable
data class GetRepeaterHistoryRegex(
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
) : Paginated

@Serializable
data class GetRepeaterHistoryEntry(val index: Int)

@Serializable
data class ExportProxyHistoryHar(
    val startIndex: Int? = null,
    val count: Int? = null,
)
