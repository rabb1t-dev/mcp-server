package net.portswigger.mcp.tools

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ProbeSignaturesTest {

    @Test
    fun `PAYLOAD_SETS has non-empty entries for each class`() {
        listOf("xss", "sqli_error", "sqli_time", "ssti", "traversal_lfi", "cmdi", "redirect", "crlf", "nosqli")
            .forEach { key ->
                assertTrue(PAYLOAD_SETS[key]!!.isNotEmpty(), "Expected payloads for $key")
            }
    }

    @Test
    fun `classifyReflectionContext detects script context`() {
        val payload = "alert(1)"
        val body = "<html><script>var x='$payload';</script></html>"
        val (context, dangerous) = classifyReflectionContext(payload, body)
        assertEquals(ReflectionContext.SCRIPT, context)
        assertFalse(dangerous)
    }

    @Test
    fun `classifyReflectionContext returns none when not reflected`() {
        val (context, _) = classifyReflectionContext("notfound", "hello world")
        assertEquals(ReflectionContext.NONE, context)
    }

    @Test
    fun `detectSstiEvaluation finds evaluated expression`() {
        assertTrue(detectSstiEvaluation("{{7*7}}", "Result: 49"))
        assertFalse(detectSstiEvaluation("{{7*7}}", "Result: {{7*7}}"))
    }

    @Test
    fun `detectOpenRedirect finds location header canary`() {
        val response = mockk<burp.api.montoya.http.message.responses.HttpResponse> {
            every { headerValue("Location") } returns "https://burp-mcp-redirect-canary.example/path"
            every { bodyToString() } returns ""
        }
        assertTrue(detectOpenRedirect(response))
    }

    @Test
    fun `detectTimingAnomaly triggers above threshold`() {
        assertTrue(detectTimingAnomaly(100, 5000))
        assertFalse(detectTimingAnomaly(100, 500))
    }

    @Test
    fun `evaluateInjectionVerdict marks SQL error as vulnerable`() {
        val original = mockResponse(200, "ok")
        val probe = mockResponse(500, "You have an error in your SQL syntax near")
        val (verdict, _) = evaluateInjectionVerdict(
            VulnClass.SQLI, "' OR 1=1--", original, probe, 100, 150
        )
        assertEquals(InjectionVerdict.VULNERABLE, verdict)
    }

    @Test
    fun `evaluateInjectionVerdict marks time-based SQLi as vulnerable`() {
        val original = mockResponse(200, "ok")
        val probe = mockResponse(200, "ok")
        val baselineSamples = listOf(100L, 120L, 110L)
        val (verdict, evidence) = evaluateInjectionVerdict(
            VulnClass.SQLI_TIME, "' OR SLEEP(5)--", original, probe, 110, 5200, baselineSamples
        )
        assertEquals(InjectionVerdict.VULNERABLE, verdict)
        assertTrue(evidence!!.contains("5090"))
    }

    @Test
    fun `medianTimingMs returns middle sample`() {
        assertEquals(120L, medianTimingMs(listOf(100, 120, 500)))
    }

    @Test
    fun `detectTimingAnomalyAgainstBaseline uses median margin`() {
        val samples = listOf(100L, 110L, 105L)
        assertTrue(detectTimingAnomalyAgainstBaseline(samples, 3600))
        assertFalse(detectTimingAnomalyAgainstBaseline(samples, 2000))
    }

    @Test
    fun `payloadsForVulnClass maps sqli to error payloads`() {
        assertEquals(PAYLOAD_SETS["sqli_error"], payloadsForVulnClass(VulnClass.SQLI))
    }

    private fun mockResponse(status: Int, body: String) =
        mockk<burp.api.montoya.http.message.responses.HttpResponse>(relaxed = true) {
            every { statusCode() } returns status.toShort()
            every { bodyToString() } returns body
            every { body() } returns mockk {
                every { length() } returns body.length
            }
        }
}
