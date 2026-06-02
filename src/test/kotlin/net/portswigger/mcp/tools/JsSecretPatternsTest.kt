package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class JsSecretPatternsTest {

    @Test
    fun `shannonEntropy rejects low entropy strings`() {
        assertTrue(shannonEntropy("aaaaaaaaaa") < 1.0)
        assertTrue(shannonEntropy("aB3${'$'}xZ9!mK2@pQ7#wR4") > 3.5)
    }

    @Test
    fun `scanJsBundleText detects github token`() {
        val js = """const token = "ghp_1234567890abcdefghij1234567890ab";"""
        val findings = scanJsBundleText(js)
        assertTrue(findings.any { it.patternName == "github_token" && it.kind == "secret" })
    }

    @Test
    fun `scanJsBundleText detects stripe test key pattern`() {
        val keySuffix = "fakekeyforunittests000000"
        val js = """apiKey: "${"sk_test_" + keySuffix}";"""
        val findings = scanJsBundleText(js)
        assertTrue(findings.any { it.patternName == "stripe_test" })
    }

    @Test
    fun `scanJsBundleText detects source map reference`() {
        val js = "//# sourceMappingURL=app.bundle.js.map"
        val findings = scanJsBundleText(js)
        assertTrue(findings.any { it.kind == "sourcemap" && it.snippet.contains(".map") })
    }

    @Test
    fun `scanJsBundleText extracts endpoints`() {
        val js = """fetch("/api/v1/users");"""
        val findings = scanJsBundleText(js)
        assertTrue(findings.any { it.kind == "endpoint" && it.snippet.contains("/api") })
    }

    @Test
    fun `scanJsBundleText deduplicates identical secrets`() {
        val token = "ghp_1234567890abcdefghij1234567890ab"
        val js = "$token $token"
        val findings = scanJsBundleText(js).filter { it.patternName == "github_token" }
        assertEquals(1, findings.size)
    }

    @Test
    fun `generic secret assignment rejects low entropy values`() {
        val js = """api_key: "aaaaaaaaaaaa";"""
        val findings = scanJsBundleText(js).filter { it.patternName == "generic_secret_assignment" }
        assertFalse(findings.isNotEmpty())
    }

    @Test
    fun `heroku_api does not match bare uuid`() {
        val js = """id: "550e8400-e29b-41d4-a716-446655440000";"""
        assertFalse(scanJsBundleText(js).any { it.patternName == "heroku_api" })
    }

    @Test
    fun `isJsBundleResponse matches js mime and url`() {
        assertTrue(isJsBundleResponse("application/javascript", "https://x.com/app.js", ""))
        assertTrue(isJsBundleResponse("text/html", "https://x.com/page", "<script>x</script>"))
        assertFalse(isJsBundleResponse("application/json", "https://x.com/api", "{}"))
    }

    @Test
    fun `extractSourceMapUrls finds multiple references`() {
        val urls = extractSourceMapUrls("//# sourceMappingURL=a.js.map\n//@ sourceMappingURL=b.js.map")
        assertEquals(2, urls.size)
    }
}
