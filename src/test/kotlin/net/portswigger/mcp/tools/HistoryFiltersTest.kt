package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scope.Scope
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HistoryFiltersTest {

    @Test
    fun `normalizeEndpointKey collapses numeric segments and query values`() {
        val key1 = normalizeEndpointKey("GET", "https://example.com/users/123/orders/456?id=789")
        val key2 = normalizeEndpointKey("GET", "https://example.com/users/999/orders/111?id=222")

        assertEquals(key1, key2)
        assertTrue(key1.contains("/{id}"))
    }

    @Test
    fun `matchesStatusCodeClass supports exact and class filters`() {
        assertTrue(matchesStatusCodeClass(200, "2xx"))
        assertTrue(matchesStatusCodeClass(404, "404"))
        assertFalse(matchesStatusCodeClass(404, "2xx"))
    }

    @Test
    fun `matchesHistoryFilter applies host method and scope filters`() {
        val api = mockk<MontoyaApi>()
        val scope = mockk<Scope>()
        every { api.scope() } returns scope
        every { scope.isInScope(any<String>()) } returns true

        val request = mockk<HttpRequest>()
        every { request.url() } returns "https://example.com/api/users"
        every { request.method() } returns "GET"
        every { request.httpService() } returns mockk {
            every { host() } returns "example.com"
        }

        val response = mockk<HttpResponse>()
        every { response.statusCode() } returns 200.toShort()

        val entry = mockk<ProxyHttpRequestResponse>()
        every { entry.hasResponse() } returns true
        every { entry.finalRequest() } returns request
        every { entry.response() } returns response
        every { entry.mimeType() } returns MimeType.JSON

        val filter = HistoryFilterOptions(host = "example.com", method = "GET")
        assertTrue(matchesHistoryFilter(entry, filter, api))

        val wrongMethod = filter.copy(method = "POST")
        assertFalse(matchesHistoryFilter(entry, wrongMethod, api))
    }

    @Test
    fun `uniqueEndpoints filter deduplicates normalized endpoints`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val entries = listOf(
            mockHistoryEntry("GET", "https://example.com/users/1"),
            mockHistoryEntry("GET", "https://example.com/users/2")
        )

        val filter = HistoryFilterOptions(uniqueEndpoints = true)
        val filtered = filterProxyHistory(entries, filter, api)

        assertEquals(1, filtered.size)
    }

    @Test
    fun `filterProxyHistoryForBrowse returns newest entries first`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val entries = listOf(
            mockHistoryEntry("GET", "https://example.com/old"),
            mockHistoryEntry("GET", "https://example.com/mid"),
            mockHistoryEntry("GET", "https://example.com/new"),
        )

        val filtered = filterProxyHistoryForBrowse(entries, HistoryFilterOptions(), api)

        assertEquals(3, filtered.size)
        assertEquals(2, filtered[0].index)
        assertEquals(1, filtered[1].index)
        assertEquals(0, filtered[2].index)
    }

    private fun mockHistoryEntry(method: String, url: String): ProxyHttpRequestResponse {
        val request = mockk<HttpRequest>()
        every { request.url() } returns url
        every { request.method() } returns method
        every { request.httpService() } returns mockk {
            every { host() } returns "example.com"
        }

        val response = mockk<HttpResponse>()
        every { response.statusCode() } returns 200.toShort()

        return mockk {
            every { hasResponse() } returns true
            every { finalRequest() } returns request
            every { response() } returns response
            every { mimeType() } returns MimeType.JSON
        }
    }
}
