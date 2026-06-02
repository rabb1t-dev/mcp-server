package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReconAnalysisTest {

    @Test
    fun `analyzeSecurityHeaders flags missing CSP and X-Frame-Options`() {
        val findings = analyzeSecurityHeaders(emptyMap(), isHttps = true)
        assertTrue(findings.any { it.header == "Content-Security-Policy" && it.status == HeaderFindingStatus.MISSING })
        assertTrue(findings.any { it.header == "X-Frame-Options" && it.status == HeaderFindingStatus.MISSING })
    }

    @Test
    fun `analyzeSecurityHeaders flags missing HSTS on HTTPS`() {
        val findings = analyzeSecurityHeaders(emptyMap(), isHttps = true)
        assertTrue(findings.any { it.header == "Strict-Transport-Security" && it.status == HeaderFindingStatus.MISSING })
    }

    @Test
    fun `analyzeSecurityHeaders marks HSTS not applicable on plain HTTP`() {
        val findings = analyzeSecurityHeaders(emptyMap(), isHttps = false)
        val hsts = findings.first { it.header == "Strict-Transport-Security" }
        assertEquals(HeaderFindingStatus.PRESENT, hsts.status)
        assertTrue(hsts.detail.contains("plain HTTP", ignoreCase = true))
    }

    @Test
    fun `analyzeSecurityHeaders detects permissive CORS with credentials`() {
        val headers = mapOf(
            "Access-Control-Allow-Origin" to "*",
            "Access-Control-Allow-Credentials" to "true"
        )
        val findings = analyzeSecurityHeaders(headers, isHttps = true)
        assertTrue(findings.any { it.header == "CORS" && it.status == HeaderFindingStatus.WEAK })
    }

    @Test
    fun `analyzeSecurityHeaders marks weak CSP with unsafe-inline`() {
        val headers = mapOf("Content-Security-Policy" to "default-src 'self' 'unsafe-inline'")
        val findings = analyzeSecurityHeaders(headers, isHttps = true)
        assertTrue(findings.any { it.header == "Content-Security-Policy" && it.status == HeaderFindingStatus.WEAK })
    }

    @Test
    fun `extractFormsFromHtml parses action method and inputs`() {
        val html = """
            <html><body>
            <form action="/login" method="post">
              <input type="text" name="username">
              <input type="password" name="password">
              <input type="hidden" name="csrf" value="abc">
            </form>
            </body></html>
        """.trimIndent()

        val forms = extractFormsFromHtml(html)
        assertEquals(1, forms.size)
        assertEquals("/login", forms[0].action)
        assertEquals("POST", forms[0].method)
        assertEquals(3, forms[0].inputs.size)
        assertTrue(forms[0].inputs.any { it.name == "csrf" && it.hidden })
    }

    @Test
    fun `extractFormsFromHtml defaults method to GET and action to null`() {
        val html = """<form><input name="q" type="search"></form>"""
        val forms = extractFormsFromHtml(html)
        assertEquals(1, forms.size)
        assertEquals(null, forms[0].action)
        assertEquals("GET", forms[0].method)
        assertEquals("q", forms[0].inputs[0].name)
    }

    @Test
    fun `buildAttackSurfaceHints includes probe hint when interesting params exist`() {
        val hints = buildAttackSurfaceHints(10, 0, 0, 2)
        assertTrue(hints.any { it.contains("probe_injection") || it.contains("fuzz_parameter") })
    }

    @Test
    fun `isHtmlResponse detects html mime and paths`() {
        assertTrue(isHtmlResponse("text/html", "https://x.com/page"))
        assertTrue(isHtmlResponse(null, "https://x.com/index.html"))
        assertFalse(isHtmlResponse("application/json", "https://x.com/api/users"))
    }
}
