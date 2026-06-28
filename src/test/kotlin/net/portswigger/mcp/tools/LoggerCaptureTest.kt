package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedList
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSummaryForm
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

class LoggerCaptureTest {

    private lateinit var config: McpConfig
    private lateinit var storage: PersistedObject
    private lateinit var store: LoggerCaptureStore
    private val storageMap = mutableMapOf<String, Any>()
    private val pageLists = mutableMapOf<String, PersistedList<burp.api.montoya.http.message.HttpRequestResponse>>()

    @BeforeEach
    fun setup() {
        storageMap.clear()
        pageLists.clear()

        storage = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers {
                val key = firstArg<String>()
                storageMap[key] as? Boolean ?: when (key) {
                    "loggerCaptureEnabled" -> true
                    "loggerCaptureExtensions" -> true
                    "loggerPersistenceEnabled" -> false
                    else -> false
                }
            }
            every { getString(any()) } answers {
                storageMap[firstArg()] as? String
            }
            every { getInteger(any()) } answers {
                when (val key = firstArg<String>()) {
                    "loggerMaxEntries" -> storageMap[key] as? Int ?: 100
                    else -> storageMap[key] as? Int
                }
            }
            every { setBoolean(any(), any()) } answers {
                storageMap[firstArg()] = secondArg()
            }
            every { setString(any(), any()) } answers {
                storageMap[firstArg()] = secondArg()
            }
            every { setInteger(any(), any()) } answers {
                storageMap[firstArg()] = secondArg<Int>()
            }
            every { deleteString(any()) } answers {
                storageMap.remove(firstArg())
            }
            every { setHttpRequestResponseList(any(), any()) } answers {
                pageLists[firstArg()] = secondArg()
            }
            every { getHttpRequestResponseList(any()) } answers {
                pageLists[firstArg()]
            }
            every { deleteHttpRequestResponseList(any()) } answers {
                pageLists.remove(firstArg())
            }
            every { httpRequestResponseListKeys() } answers {
                pageLists.keys.toSet()
            }
        }

        val logging = mockk<Logging>(relaxed = true)
        config = McpConfig(storage, logging).apply {
            loggerCaptureEnabled = true
            loggerCaptureExtensions = true
            loggerMaxEntries = 100
            loggerPersistenceEnabled = false
        }

        store = LoggerCaptureStore(config, storage)
    }

    @AfterEach
    fun tearDown() {
        store.shutdown()
    }

    @Test
    fun `correlates response to request by messageId`() {
        val request = mockRequest("GET", "https://example.com/a")
        val response = mockResponse(200, "ok")

        store.enqueueRequest(42, "REPEATER", request)
        store.enqueueResponse(42, response)
        waitUntil { store.getEntry(0)?.response != null }

        val entry = store.getEntry(0)
        assertNotNull(entry)
        assertEquals("REPEATER", entry!!.toolType)
        assertEquals(200, entry.response?.statusCode()?.toInt())
    }

    @Test
    fun `evicts oldest entries when max exceeded`() {
        config.loggerMaxEntries = 100
        repeat(101) { i ->
            store.enqueueRequest(i, "PROXY", mockRequest("GET", "https://example.com/$i"))
        }
        waitUntil { store.snapshot().any { it.index == 100 } }

        assertEquals(100, store.size())
        val indices = store.snapshot().map { it.index }
        assertEquals((1..100).toList(), indices)
    }

    @Test
    fun `skips extension traffic when disabled`() {
        config.loggerCaptureExtensions = false

        store.enqueueRequest(1, "EXTENSIONS", mockRequest("GET", "https://example.com/ext"))
        store.enqueueRequest(2, "REPEATER", mockRequest("GET", "https://example.com/rep"))
        drainQueue(1)

        assertEquals(1, store.size())
        assertEquals("REPEATER", store.snapshot().single().toolType)
    }

    @Test
    fun `toolType filter matches case insensitively`() {
        store.enqueueRequest(1, "REPEATER", mockRequest("GET", "https://example.com/a"))
        store.enqueueRequest(2, "SCANNER", mockRequest("GET", "https://example.com/b"))
        drainQueue(2)

        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.scope().isInScope(any<String>()) } returns true

        val filtered = filterLoggerEntries(
            store.snapshot(),
            loggerFilterFromParams(toolType = "repeater"),
            api,
        )

        assertEquals(1, filtered.size)
        assertEquals("REPEATER", filtered.single().toolType)
    }

    @Test
    fun `summary mapping includes toolType and index`() {
        store.enqueueRequest(7, "INTRUDER", mockRequest("POST", "https://example.com/login"))
        drainQueue(1)

        val summary = store.snapshot().single().toSummaryForm()
        assertEquals(0, summary.index)
        assertEquals(7, summary.messageId)
        assertEquals("INTRUDER", summary.toolType)
        assertEquals("POST", summary.method)
        assertTrue(summary.url.contains("example.com"))
    }

    @Test
    fun `clear removes all entries and persisted keys`() {
        store.enqueueRequest(1, "PROXY", mockRequest("GET", "https://example.com/a"))
        drainQueue(1)
        assertTrue(store.size() > 0)

        store.clear()
        assertEquals(0, store.size())
        verify { storage.deleteString("logger.metadataJson") }
    }

    @Test
    fun `persistence round trip restores entries on new store load`() {
        mockkStatic(PersistedList::class)
        mockkStatic(HttpRequestResponse::class)
        try {
            every { PersistedList.persistedHttpRequestResponseList() } answers {
                mockPersistedPage()
            }
            every {
                HttpRequestResponse.httpRequestResponse(any<HttpRequest>(), any())
            } answers {
                val req = firstArg<HttpRequest>()
                val resp = secondArg<HttpResponse?>()
                mockk<HttpRequestResponse> {
                    every { request() } returns req
                    every { response() } returns resp
                }
            }

            config.loggerPersistenceEnabled = true
            store.shutdown()
            store = LoggerCaptureStore(config, storage)

            val request = mockRequest("GET", "https://example.com/persisted")
            val response = mockResponse(201, "created")
            store.enqueueRequest(99, "SCANNER", request)
            store.enqueueResponse(99, response)
            waitUntil { store.getEntry(0)?.response != null }

            assertNotNull(storageMap["logger.metadataJson"])
            assertTrue(pageLists.containsKey("logger.page.0"))

            store.shutdown()
            val restored = LoggerCaptureStore(config, storage)

            assertEquals(1, restored.size())
            val entry = restored.getEntry(0)
            assertNotNull(entry)
            assertEquals("SCANNER", entry!!.toolType)
            assertEquals(99, entry.messageId)
            assertEquals(201, entry.response?.statusCode()?.toInt())
            assertTrue(entry.request.url().contains("persisted"))

            restored.shutdown()
        } finally {
            unmockkStatic(PersistedList::class)
            unmockkStatic(HttpRequestResponse::class)
        }
    }

    private fun waitUntil(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (condition()) return
            Thread.sleep(10)
        }
        org.junit.jupiter.api.fail("Timed out waiting for condition")
    }

    private fun drainQueue(expectedMin: Int) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (store.size() >= expectedMin) return
            Thread.sleep(10)
        }
        org.junit.jupiter.api.fail("Timed out waiting for queue drain, size=${store.size()}, expected>=$expectedMin")
    }

    private fun mockRequest(method: String, url: String): HttpRequest {
        val service = mockk<HttpService>()
        every { service.host() } returns "example.com"
        val request = mockk<HttpRequest>()
        every { request.method() } returns method
        every { request.url() } returns url
        every { request.httpService() } returns service
        every { request.hasParameters() } returns false
        every { request.toString() } returns "$method $url HTTP/1.1"
        every { request.bodyToString() } returns ""
        every { request.copyToTempFile() } returns request
        return request
    }

    private fun mockPersistedPage(): PersistedList<HttpRequestResponse> {
        val backing = mutableListOf<HttpRequestResponse>()
        return object : PersistedList<HttpRequestResponse>, MutableList<HttpRequestResponse> by backing {}
    }

    private fun mockResponse(status: Int, body: String): HttpResponse {
        val bodyBytes = mockk<burp.api.montoya.core.ByteArray>()
        every { bodyBytes.length() } returns body.length
        val response = mockk<HttpResponse>()
        every { response.statusCode() } returns status.toShort()
        every { response.body() } returns bodyBytes
        every { response.bodyToString() } returns body
        every { response.withBody(any<String>()) } returns response
        every { response.mimeType() } returns null
        every { response.toString() } returns "HTTP/1.1 $status OK\r\n\r\n$body"
        every { response.copyToTempFile() } returns response
        return response
    }
}
