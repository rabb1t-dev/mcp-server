package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReconPatternsTest {

    @Test
    fun `scanTextForSecrets finds AWS key and JWT`() {
        val text = """
            config = { aws: "AKIAIOSFODNN7EXAMPLE", token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" }
        """.trimIndent()

        val matches = scanTextForSecrets(text)
        assertTrue(matches.any { it.patternName == "aws_access_key" })
        assertTrue(matches.any { it.patternName == "jwt" })
    }

    @Test
    fun `scanTextForSecrets does not duplicate identical matches`() {
        val text = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE"
        val matches = scanTextForSecrets(text)
        assertEquals(1, matches.count { it.patternName == "aws_access_key" })
    }

    @Test
    fun `extractEndpointsFromText finds fetch and relative paths`() {
        val js = """
            fetch("/api/v1/users");
            axios.get('/admin/settings');
            var x = "https://example.com/internal/report";
        """.trimIndent()

        val endpoints = extractEndpointsFromText(js)
        assertTrue(endpoints.any { it.contains("/api/v1/users") })
        assertTrue(endpoints.any { it.contains("/admin/settings") })
    }

    @Test
    fun `detectErrorSignatures finds SQL and stack trace patterns`() {
        val body = "You have an error in your SQL syntax near 'SELECT'"
        assertTrue(detectErrorSignatures(body).contains("sql_syntax"))

        val stack = "Exception in thread \"main\" at com.example.App.run(App.java:42)"
        assertTrue(detectErrorSignatures(stack).contains("stack_trace"))
    }

    @Test
    fun `scanTextForSecrets assigns low confidence to email`() {
        val matches = scanTextForSecrets("contact: user@example.com")
        val email = matches.first { it.patternName == "email" }
        assertEquals("low", email.confidence)
    }

    @Test
    fun `truncateForSimilarity caps large bodies`() {
        val huge = "a".repeat(20_000)
        assertEquals(8192, truncateForSimilarity(huge).length)
    }

    @Test
    fun `responseSimilarity handles large bodies without timing out`() {
        val a = "x".repeat(50_000)
        val b = "x".repeat(49_999) + "y"
        val similarity = responseSimilarity(a, b)
        assertTrue(similarity > 0.9)
    }

    @Test
    fun `isInterestingParamName flags redirect and id params`() {
        assertTrue(isInterestingParamName("redirect_url"))
        assertTrue(isInterestingParamName("user_id"))
        assertFalse(isInterestingParamName("utm_source"))
    }

    @Test
    fun `extractReflectionContext returns surrounding text`() {
        val body = "Hello <script>alert(1)</script> world"
        val context = extractReflectionContext("<script>alert(1)</script>", body)
        assertTrue(context!!.contains("alert(1)"))
    }
}
