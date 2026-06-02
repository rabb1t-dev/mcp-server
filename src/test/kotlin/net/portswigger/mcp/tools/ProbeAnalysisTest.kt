package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ProbeAnalysisTest {

    @Test
    fun `responseSimilarity returns 1 for identical bodies`() {
        assertEquals(1.0, responseSimilarity("same body", "same body"))
    }

    @Test
    fun `responseSimilarity returns low score for very different bodies`() {
        val similarity = responseSimilarity("aaaaaaa", "zzzzzzz")
        assertTrue(similarity < 0.5)
    }

    @Test
    fun `analyzeProbeResponse detects reflection and SQL error`() {
        val payload = "' OR '1'='1"
        val body = "Query failed: You have an error in your SQL syntax; payload was '$payload'"

        val result = analyzeProbeResponse(payload, null, mockResponse(500, body))

        assertTrue(result.reflected)
        assertTrue(result.errorSignatures.contains("sql_syntax"))
        assertTrue(result.reflectionContext!!.contains(payload))
    }

    @Test
    fun `evaluateIdorVerdict returns likely idor for similar alternate response`() {
        val original = """{"id":"USER-1","role":"user","data":"same-content-block-here"}"""
        val alternate = """{"id":"USER-ALT-9999","role":"user","data":"same-content-block-here"}"""

        assertEquals(
            IdorVerdict.LIKELY_IDOR,
            evaluateIdorVerdict(200, 200, original, alternate, "USER-ALT-9999")
        )
    }

    @Test
    fun `evaluateIdorVerdict returns ok for forbidden alternate response`() {
        assertEquals(
            IdorVerdict.OK,
            evaluateIdorVerdict(200, 403, "secret", "denied", "2")
        )
    }

    private fun mockResponse(status: Int, body: String) =
        io.mockk.mockk<burp.api.montoya.http.message.responses.HttpResponse>(relaxed = true) {
            io.mockk.every { statusCode() } returns status.toShort()
            io.mockk.every { bodyToString() } returns body
            io.mockk.every { body() } returns io.mockk.mockk {
                io.mockk.every { length() } returns body.length
            }
        }
}
