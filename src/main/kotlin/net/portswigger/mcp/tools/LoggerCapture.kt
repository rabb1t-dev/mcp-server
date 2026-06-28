package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.persistence.PersistedList
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.http.message.HttpRequestResponse
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.regex.Pattern

private const val PERSISTENCE_PAGE_SIZE = 500
private const val PERSISTENCE_BODY_MAX_BYTES = 50_000
private const val METADATA_KEY = "logger.metadataJson"
private const val PAGE_KEY_PREFIX = "logger.page."
private const val MIN_MAX_ENTRIES = 100
private const val MAX_MAX_ENTRIES = 50_000

data class LoggerFilterOptions(
    val inScopeOnly: Boolean = false,
    val host: String? = null,
    val method: String? = null,
    val statusCodeClass: String? = null,
    val excludeStaticAssets: Boolean = false,
    val urlRegex: String? = null,
    val uniqueEndpoints: Boolean = false,
    val toolType: String? = null,
)

data class LoggerEntry(
    val index: Int,
    val messageId: Int,
    val toolType: String,
    val timestampMs: Long,
    var request: HttpRequest,
    var response: HttpResponse?,
    var pageIndex: Int? = null,
    var pageOffset: Int? = null,
)

@Serializable
internal data class LoggerEntryMetadata(
    val index: Int,
    val messageId: Int,
    val toolType: String,
    val timestampMs: Long,
    val pageIndex: Int,
    val pageOffset: Int,
)

private sealed interface CaptureEvent {
    data class RequestCaptured(
        val messageId: Int,
        val toolType: String,
        val timestampMs: Long,
        val request: HttpRequest,
    ) : CaptureEvent

    data class ResponseCaptured(
        val messageId: Int,
        val response: HttpResponse,
    ) : CaptureEvent
}

class LoggerCaptureStore(
    private val config: McpConfig,
    private val storage: PersistedObject,
) {
    private val lock = Any()
    private val entries = ArrayList<LoggerEntry>()
    private val messageIndex = HashMap<Int, Int>()
    private var nextIndex = 0
    private val queue = LinkedBlockingQueue<CaptureEvent>()
    private val workerRunning = AtomicBoolean(true)
    private val metadataJson = Json { ignoreUnknownKeys = true }

    private var currentPage: PersistedList<HttpRequestResponse>? = null
    private var currentPageIndex = 0
    private var currentPageOffset = 0
    private val persistedMetadata = ArrayList<LoggerEntryMetadata>()

    private val worker = Thread(
        {
            while (workerRunning.get() || queue.isNotEmpty()) {
                try {
                    val event = queue.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
                    processEvent(event)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
        },
        "burp-mcp-logger-capture"
    ).apply {
        isDaemon = true
        start()
    }

    init {
        if (config.loggerPersistenceEnabled) {
            restoreFromPersistence()
        }
    }

    fun shutdown() {
        workerRunning.set(false)
        worker.interrupt()
    }

    fun enqueueRequest(messageId: Int, toolType: String, request: HttpRequest) {
        if (!shouldCapture(toolType)) return
        queue.offer(
            CaptureEvent.RequestCaptured(messageId, toolType, System.currentTimeMillis(), request)
        )
    }

    fun enqueueResponse(messageId: Int, response: HttpResponse) {
        if (!config.loggerCaptureEnabled) return
        queue.offer(CaptureEvent.ResponseCaptured(messageId, response))
    }

    fun size(): Int = synchronized(lock) { entries.size }

    fun snapshot(): List<LoggerEntry> = synchronized(lock) { entries.toList() }

    fun getEntry(index: Int): LoggerEntry? = synchronized(lock) {
        entries.firstOrNull { it.index == index }?.let { resolveEntry(it) }
    }

    fun clear() {
        synchronized(lock) {
            entries.clear()
            messageIndex.clear()
            nextIndex = 0
            persistedMetadata.clear()
            currentPage = null
            currentPageIndex = 0
            currentPageOffset = 0
        }
        queue.clear()
        clearPersistedKeys()
    }

    private fun shouldCapture(toolType: String): Boolean {
        if (!config.loggerCaptureEnabled) return false
        if (toolType.equals(ToolType.EXTENSIONS.name, ignoreCase = true) && !config.loggerCaptureExtensions) {
            return false
        }
        return true
    }

    private fun processEvent(event: CaptureEvent) {
        when (event) {
            is CaptureEvent.RequestCaptured -> addRequest(event)
            is CaptureEvent.ResponseCaptured -> attachResponse(event)
        }
    }

    private fun addRequest(event: CaptureEvent.RequestCaptured) {
        synchronized(lock) {
            evictIfNeeded()
            val entry = LoggerEntry(
                index = nextIndex++,
                messageId = event.messageId,
                toolType = event.toolType,
                timestampMs = event.timestampMs,
                request = event.request.copyToTempFile(),
                response = null,
            )
            entries.add(entry)
            messageIndex[event.messageId] = entry.index
            if (config.loggerPersistenceEnabled) {
                persistEntry(entry)
                evictPersistedIfNeeded()
            }
        }
    }

    private fun attachResponse(event: CaptureEvent.ResponseCaptured) {
        synchronized(lock) {
            val entryIndex = messageIndex[event.messageId] ?: return
            val entry = entries.firstOrNull { it.index == entryIndex } ?: return
            val storedResponse = event.response.copyToTempFile()
            entry.response = storedResponse
            if (config.loggerPersistenceEnabled && entry.pageIndex != null && entry.pageOffset != null) {
                updatePersistedResponse(entry, storedResponse)
            }
        }
    }

    private fun evictIfNeeded() {
        val maxEntries = config.loggerMaxEntries.coerceIn(MIN_MAX_ENTRIES, MAX_MAX_ENTRIES)
        while (entries.size >= maxEntries) {
            val removed = entries.removeAt(0)
            messageIndex.remove(removed.messageId)
        }
    }

    private fun evictPersistedIfNeeded() {
        val maxEntries = config.loggerMaxEntries.coerceIn(MIN_MAX_ENTRIES, MAX_MAX_ENTRIES)
        while (persistedMetadata.size > maxEntries) {
            evictOldestPersistedPage()
        }
    }

    private fun resolveEntry(entry: LoggerEntry): LoggerEntry {
        if (entry.pageIndex == null || entry.pageOffset == null) return entry
        if (entry.response != null) return entry
        val page = storage.getHttpRequestResponseList(pageKey(entry.pageIndex!!)) ?: return entry
        if (entry.pageOffset!! >= page.size) return entry
        val stored = page[entry.pageOffset!!]
        return entry.copy(
            request = stored.request() ?: entry.request,
            response = stored.response(),
        )
    }

    private fun persistEntry(entry: LoggerEntry) {
        val page = ensureCurrentPage()
        val truncatedRequest = truncateRequest(entry.request)
        val pair = HttpRequestResponse.httpRequestResponse(truncatedRequest, null)
        page.add(pair)
        entry.pageIndex = currentPageIndex
        entry.pageOffset = currentPageOffset
        persistedMetadata.add(
            LoggerEntryMetadata(
                index = entry.index,
                messageId = entry.messageId,
                toolType = entry.toolType,
                timestampMs = entry.timestampMs,
                pageIndex = currentPageIndex,
                pageOffset = currentPageOffset,
            )
        )
        currentPageOffset++
        if (currentPageOffset >= PERSISTENCE_PAGE_SIZE) {
            currentPageIndex++
            currentPageOffset = 0
            currentPage = null
        }
        flushMetadata()
    }

    private fun updatePersistedResponse(entry: LoggerEntry, response: HttpResponse) {
        val pageIndex = entry.pageIndex ?: return
        val pageOffset = entry.pageOffset ?: return
        val page = storage.getHttpRequestResponseList(pageKey(pageIndex)) ?: return
        if (pageOffset >= page.size) return
        val existing = page[pageOffset]
        page[pageOffset] = HttpRequestResponse.httpRequestResponse(
            existing.request(),
            truncateResponse(response),
        )
    }

    private fun ensureCurrentPage(): PersistedList<HttpRequestResponse> {
        currentPage?.let { return it }
        val page = PersistedList.persistedHttpRequestResponseList()
        storage.setHttpRequestResponseList(pageKey(currentPageIndex), page)
        currentPage = page
        return page
    }

    private fun pageKey(index: Int) = "$PAGE_KEY_PREFIX$index"

    private fun flushMetadata() {
        storage.setString(METADATA_KEY, metadataJson.encodeToString(persistedMetadata))
    }

    private fun restoreFromPersistence() {
        val raw = storage.getString(METADATA_KEY) ?: return
        val restored = runCatching {
            metadataJson.decodeFromString<List<LoggerEntryMetadata>>(raw)
        }.getOrNull() ?: return
        synchronized(lock) {
            persistedMetadata.clear()
            persistedMetadata.addAll(restored)
            for (meta in restored) {
                val page = storage.getHttpRequestResponseList(pageKey(meta.pageIndex)) ?: continue
                if (meta.pageOffset >= page.size) continue
                val stored = page[meta.pageOffset]
                val entry = LoggerEntry(
                    index = meta.index,
                    messageId = meta.messageId,
                    toolType = meta.toolType,
                    timestampMs = meta.timestampMs,
                    request = stored.request() ?: continue,
                    response = stored.response(),
                    pageIndex = meta.pageIndex,
                    pageOffset = meta.pageOffset,
                )
                entries.add(entry)
                messageIndex[meta.messageId] = meta.index
                nextIndex = maxOf(nextIndex, meta.index + 1)
            }
            currentPageIndex = restored.maxOfOrNull { it.pageIndex } ?: 0
            val lastOnPage = restored.filter { it.pageIndex == currentPageIndex }.maxOfOrNull { it.pageOffset }
            currentPageOffset = (lastOnPage ?: -1) + 1
            if (currentPageOffset >= PERSISTENCE_PAGE_SIZE) {
                currentPageIndex++
                currentPageOffset = 0
            }
            currentPage = storage.getHttpRequestResponseList(pageKey(currentPageIndex))
        }
    }

    private fun evictOldestPersistedPage() {
        val oldestPage = persistedMetadata.minOfOrNull { it.pageIndex } ?: return
        storage.deleteHttpRequestResponseList(pageKey(oldestPage))
        persistedMetadata.removeAll { it.pageIndex == oldestPage }
        entries.forEach { entry ->
            if (entry.pageIndex == oldestPage) {
                entry.pageIndex = null
                entry.pageOffset = null
            }
        }
        flushMetadata()
    }

    private fun clearPersistedKeys() {
        storage.deleteString(METADATA_KEY)
        storage.httpRequestResponseListKeys()
            .filter { it.startsWith(PAGE_KEY_PREFIX) }
            .forEach { storage.deleteHttpRequestResponseList(it) }
    }

    private fun truncateRequest(request: HttpRequest): HttpRequest {
        val body = request.bodyToString()
        if (body.length <= PERSISTENCE_BODY_MAX_BYTES) return request
        return request.withBody(body.substring(0, PERSISTENCE_BODY_MAX_BYTES))
    }

    private fun truncateResponse(response: HttpResponse): HttpResponse {
        val body = response.bodyToString()
        if (body.length <= PERSISTENCE_BODY_MAX_BYTES) return response
        return response.withBody(body.substring(0, PERSISTENCE_BODY_MAX_BYTES))
    }
}

class LoggerHttpHandler(
    private val store: LoggerCaptureStore,
    private val config: McpConfig,
) : HttpHandler {

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        if (config.loggerCaptureEnabled) {
            val toolType = requestToBeSent.toolSource().toolType().name
            store.enqueueRequest(requestToBeSent.messageId(), toolType, requestToBeSent)
        }
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        if (config.loggerCaptureEnabled) {
            store.enqueueResponse(responseReceived.messageId(), responseReceived)
        }
        return ResponseReceivedAction.continueWith(responseReceived)
    }
}

fun matchesLoggerFilter(
    entry: LoggerEntry,
    filter: LoggerFilterOptions,
    api: MontoyaApi,
    seenEndpoints: MutableSet<String>? = null,
): Boolean {
    filter.toolType?.let { toolFilter ->
        if (!entry.toolType.equals(toolFilter, ignoreCase = true)) return false
    }

    val request = entry.request
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

    val statusCode = entry.response?.statusCode()?.toInt() ?: -1
    if (!matchesStatusCodeClass(statusCode, filter.statusCodeClass)) return false

    if (filter.excludeStaticAssets) {
        val mime = entry.response?.mimeType()?.toString()?.lowercase().orEmpty()
        if (STATIC_MIME_PREFIXES.any { mime.contains(it) }) return false
    }

    filter.urlRegex?.let { pattern ->
        if (!Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(url).find()) return false
    }

    if (filter.uniqueEndpoints) {
        val key = normalizeEndpointKey(request.method(), url)
        val endpoints = seenEndpoints ?: return false
        if (!endpoints.add(key)) return false
    }

    return true
}

fun filterLoggerEntries(
    entries: List<LoggerEntry>,
    filter: LoggerFilterOptions,
    api: MontoyaApi,
    fullTextRegex: Pattern? = null,
): List<LoggerEntry> {
    val seenEndpoints = if (filter.uniqueEndpoints) mutableSetOf<String>() else null
    return entries.asSequence()
        .filter { entry ->
            if (fullTextRegex != null) {
                val text = buildString {
                    append(entry.request.toString())
                    entry.response?.let { append(it.toString()) }
                }
                if (!fullTextRegex.matcher(text).find()) return@filter false
            }
            matchesLoggerFilter(entry, filter, api, seenEndpoints)
        }
        .toList()
}

fun filterLoggerEntriesForBrowse(
    entries: List<LoggerEntry>,
    filter: LoggerFilterOptions,
    api: MontoyaApi,
    fullTextRegex: Pattern? = null,
): List<LoggerEntry> {
    return filterLoggerEntries(entries, filter, api, fullTextRegex).asReversed()
}

private val STATIC_MIME_PREFIXES = listOf("image/", "text/css", "text/javascript", "application/javascript")

fun loggerFilterFromParams(
    inScopeOnly: Boolean = false,
    host: String? = null,
    method: String? = null,
    statusCodeClass: String? = null,
    excludeStaticAssets: Boolean = false,
    urlRegex: String? = null,
    uniqueEndpoints: Boolean = false,
    toolType: String? = null,
): LoggerFilterOptions = LoggerFilterOptions(
    inScopeOnly = inScopeOnly,
    host = host,
    method = method,
    statusCodeClass = statusCodeClass,
    excludeStaticAssets = excludeStaticAssets,
    urlRegex = urlRegex,
    uniqueEndpoints = uniqueEndpoints,
    toolType = toolType,
)
