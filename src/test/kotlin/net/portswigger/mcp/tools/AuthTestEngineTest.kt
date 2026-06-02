package net.portswigger.mcp.tools

import burp.api.montoya.http.message.responses.HttpResponse
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class AuthTestEngineTest {

    @Test
    fun `checkBypass returns enforced when status codes differ`() {
        assertEquals(
            AuthVerdict.ENFORCED,
            checkBypassFromValues(200, 403, "secret", "denied", null, emptyList(), DetectorLogic.AND)
        )
    }

    @Test
    fun `checkBypass returns bypassed when status and body match`() {
        assertEquals(
            AuthVerdict.BYPASSED,
            checkBypassFromValues(200, 200, "same-data", "same-data", null, emptyList(), DetectorLogic.AND)
        )
    }

    @Test
    fun `checkBypass returns needs review when status matches but body differs`() {
        assertEquals(
            AuthVerdict.NEEDS_REVIEW,
            checkBypassFromValues(200, 200, "admin-data", "limited-data", null, emptyList(), DetectorLogic.AND)
        )
    }

    @Test
    fun `checkBypass uses enforcement detector for access denied text`() {
        val modified = mockk<HttpResponse>(relaxed = true)
        every { modified.bodyToString() } returns "You are not authorized"
        every { modified.toString() } returns "HTTP/1.1 200 OK\r\n\r\nYou are not authorized"
        every { modified.headers() } returns emptyList()

        val detectors = listOf(
            EnforcementDetector(DetectorType.BODY_CONTAINS, "not authorized")
        )

        assertEquals(
            AuthVerdict.ENFORCED,
            checkBypassFromValues(200, 200, "secret", "You are not authorized", modified, detectors, DetectorLogic.OR)
        )
    }
}
