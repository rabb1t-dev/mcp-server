package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DiffResponsesTest {

    @Test
    fun `diffResponses computes status and length deltas`() {
        val diff = diffResponses("body-a", "body-b-longer", 200, 500)
        assertEquals(200, diff.leftStatus)
        assertEquals(500, diff.rightStatus)
        assertEquals(300, diff.statusDelta)
        assertTrue(diff.lengthDelta > 0)
    }

    @Test
    fun `diffResponses finds added and removed lines`() {
        val left = "line1\nline2\nline3"
        val right = "line1\nline2-changed\nline4"
        val diff = diffResponses(left, right)

        assertTrue(diff.removedLines.any { it.contains("line3") })
        assertTrue(diff.addedLines.any { it.contains("line4") || it.contains("line2-changed") })
        assertTrue(diff.firstDiffSnippets.isNotEmpty())
    }

    @Test
    fun `diffResponses returns similarity 1 for identical content`() {
        val diff = diffResponses("same", "same", 200, 200)
        assertEquals(1.0, diff.similarity)
        assertEquals(0, diff.lengthDelta)
    }
}
