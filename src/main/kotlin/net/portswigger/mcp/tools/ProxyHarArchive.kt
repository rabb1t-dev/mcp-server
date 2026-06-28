package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import net.portswigger.mcp.config.McpConfig
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class ProxyHarArchiveStore(
    private val api: MontoyaApi,
    private val config: McpConfig,
) {
    private val lock = ReentrantLock()
    private var nextExportIndex = 0
    private val batchCounter = AtomicInteger(0)
    private var lastArchiveError: String? = null

    fun onProxyHistoryChanged() {
        if (!config.proxyHarAutoExportEnabled) return

        val archiveDir = resolveHarArchiveDirectory(config.engagementDirectory) ?: run {
            lastArchiveError = "Engagement directory not configured"
            return
        }

        lock.withLock {
            val history = api.proxy().history()
            val batchSize = config.proxyHarBatchSize.coerceIn(10, 500)

            while (history.size - nextExportIndex >= batchSize) {
                val slice = history.subList(nextExportIndex, nextExportIndex + batchSize)
                val indexed = slice.withIndex().map { (offset, entry) -> nextExportIndex + offset to entry }

                try {
                    Files.createDirectories(archiveDir)
                    val fileName = harArchiveFileName(batchCounter.incrementAndGet())
                    val target = archiveDir.resolve(fileName)
                    Files.writeString(target, buildHarFromProxyEntries(indexed))
                    api.logging().logToOutput("MCP proxy HAR archived: ${target.toAbsolutePath()} ($batchSize entries)")
                    lastArchiveError = null
                } catch (e: Exception) {
                    lastArchiveError = e.message
                    api.logging().logToError("MCP proxy HAR archive failed: ${e.message}")
                    return
                }

                nextExportIndex += batchSize
            }
        }
    }

    fun exportAllToHar(): Pair<Path?, String> {
        val archiveDir = resolveHarArchiveDirectory(config.engagementDirectory)
            ?: return null to "Engagement directory not configured. Set it in the MCP tab."

        val history = api.proxy().history()
        if (history.isEmpty()) {
            return null to "Proxy history is empty"
        }

        val indexed = history.withIndex().map { it.index to it.value }
        return lock.withLock {
            try {
                Files.createDirectories(archiveDir)
                val fileName = harArchiveFileName(batchCounter.incrementAndGet())
                val target = archiveDir.resolve(fileName)
                Files.writeString(target, buildHarFromProxyEntries(indexed))
                api.logging().logToOutput("MCP proxy HAR exported: ${target.toAbsolutePath()} (${history.size} entries)")
                lastArchiveError = null
                target to "Exported ${history.size} entries to ${target.toAbsolutePath()}"
            } catch (e: Exception) {
                lastArchiveError = e.message
                null to "Export failed: ${e.message}"
            }
        }
    }

    fun exportRangeToHar(startIndex: Int, count: Int): Pair<Path?, String> {
        val archiveDir = resolveHarArchiveDirectory(config.engagementDirectory)
            ?: return null to "Engagement directory not configured. Set it in the MCP tab."

        val history = api.proxy().history()
        if (startIndex < 0 || startIndex >= history.size) {
            return null to "Start index $startIndex out of range (history size ${history.size})"
        }

        val end = (startIndex + count).coerceAtMost(history.size)
        val indexed = history.subList(startIndex, end).withIndex().map { (offset, entry) ->
            startIndex + offset to entry
        }

        return lock.withLock {
            try {
                Files.createDirectories(archiveDir)
                val fileName = harArchiveFileName(batchCounter.incrementAndGet())
                val target = archiveDir.resolve(fileName)
                Files.writeString(target, buildHarFromProxyEntries(indexed))
                target to "Exported ${indexed.size} entries to ${target.toAbsolutePath()}"
            } catch (e: Exception) {
                null to "Export failed: ${e.message}"
            }
        }
    }

    fun statusSummary(): String {
        val archiveDir = resolveHarArchiveDirectory(config.engagementDirectory)
        return buildString {
            appendLine("Auto-export enabled: ${config.proxyHarAutoExportEnabled}")
            appendLine("Engagement directory: ${config.engagementDirectory.ifBlank { "<not set>" }}")
            appendLine("Archive directory: ${archiveDir?.toAbsolutePath() ?: "<not configured>"}")
            appendLine("Batch size: ${config.proxyHarBatchSize}")
            appendLine("Next export index: $nextExportIndex")
            appendLine("Proxy history size: ${api.proxy().history().size}")
            appendLine("Archives written: ${batchCounter.get()}")
            lastArchiveError?.let { appendLine("Last error: $it") }
        }.trimEnd()
    }

    fun resetExportCursor() {
        lock.withLock { nextExportIndex = 0 }
    }
}

class ProxyHarArchiveHandler(
    private val store: ProxyHarArchiveStore,
) : ProxyResponseHandler {
    override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction {
        store.onProxyHistoryChanged()
        return ProxyResponseReceivedAction.continueWith(interceptedResponse)
    }

    override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
    }
}
