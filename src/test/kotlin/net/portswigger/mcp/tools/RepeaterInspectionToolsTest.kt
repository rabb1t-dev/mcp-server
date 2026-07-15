package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.UserInterface
import burp.api.montoya.ui.swing.SwingUtils
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.awt.Frame
import javax.swing.JPanel
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea

class RepeaterInspectionToolsTest {

    private fun buildFrame(): Frame {
        val frame = Frame()
        val tabs = JTabbedPane()

        val requestArea = JTextArea("GET / HTTP/1.1")
        val responseArea = JTextArea("HTTP/1.1 200 OK")
        val split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            JPanel().apply { add(requestArea) },
            JPanel().apply { add(responseArea) }
        )
        tabs.addTab("MyTab1", split)
        tabs.addTab("Unrelated", JPanel())

        frame.add(tabs)
        return frame
    }

    private fun mockApi(frame: Frame): MontoyaApi {
        val api = mockk<MontoyaApi>(relaxed = true)
        val ui = mockk<UserInterface>()
        val swingUtils = mockk<SwingUtils>()

        every { api.userInterface() } returns ui
        every { ui.swingUtils() } returns swingUtils
        every { swingUtils.suiteFrame() } returns frame

        return api
    }

    @Test
    fun `finds tab by exact name and extracts request and response text`() {
        val api = mockApi(buildFrame())

        val result = findRepeaterTabContent(api, "MyTab1")

        assertNotNull(result)
        assertEquals("MyTab1", result!!.tabTitle)
        assertEquals("GET / HTTP/1.1", result.request)
        assertEquals("HTTP/1.1 200 OK", result.response)
    }

    @Test
    fun `finds tab by case-insensitive name when no exact match exists`() {
        val api = mockApi(buildFrame())

        val result = findRepeaterTabContent(api, "mytab1")

        assertNotNull(result)
        assertEquals("MyTab1", result!!.tabTitle)
    }

    @Test
    fun `returns null when no tab matches`() {
        val api = mockApi(buildFrame())

        val result = findRepeaterTabContent(api, "DoesNotExist")

        assertNull(result)
    }

    @Test
    fun `finds a matching tab by name but cannot extract content when it lacks a request-response split`() {
        val api = mockApi(buildFrame())

        val result = findRepeaterTabContent(api, "Unrelated")

        assertNotNull(result)
        assertEquals("Unrelated", result!!.tabTitle)
        assertNull(result.request)
        assertNull(result.response)
    }

    @Test
    fun `lists only tabs that look like message editors`() {
        val api = mockApi(buildFrame())

        val titles = findRepeaterTabTitles(api)

        assertEquals(listOf("MyTab1"), titles)
    }
}
