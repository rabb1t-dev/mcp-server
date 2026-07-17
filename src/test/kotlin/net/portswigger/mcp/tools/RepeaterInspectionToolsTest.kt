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

    private fun mockApi(frame: Frame): MontoyaApi {
        val api = mockk<MontoyaApi>(relaxed = true)
        val ui = mockk<UserInterface>()
        val swingUtils = mockk<SwingUtils>()

        every { api.userInterface() } returns ui
        every { ui.swingUtils() } returns swingUtils
        every { swingUtils.suiteFrame() } returns frame

        return api
    }

    /** A minimal frame with a single JTabbedPane, no surrounding Burp suite chrome. */
    private fun buildSimpleFrame(): Frame {
        val frame = Frame()
        val tabs = JTabbedPane()

        val split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            JPanel().apply { add(JTextArea("GET / HTTP/1.1")) },
            JPanel().apply { add(JTextArea("HTTP/1.1 200 OK")) }
        )
        tabs.addTab("MyTab1", split)
        tabs.addTab("Unrelated", JPanel())

        frame.add(tabs)
        return frame
    }

    /**
     * A frame that mirrors real Burp UI structure closely enough to reproduce the reported bug: a main suite tool
     * switcher (Dashboard/Target/Proxy/.../Repeater/...) whose "Repeater" tab contains the real, user-named tab
     * strip. Only the tab at [initialSelectedIndex] starts out "realized" (a genuine request/response split);
     * every other tab starts as an unrealized stub, matching Burp only building a tab's editors when it's
     * selected. Selecting a tab (via the returned JTabbedPane, or indirectly through the code under test)
     * dynamically materializes it, simulating that lazy behavior.
     */
    private fun buildBurpLikeFrame(tabNames: List<String>, initialSelectedIndex: Int): Pair<Frame, JTabbedPane> {
        val repeaterStrip = JTabbedPane()
        tabNames.forEach { repeaterStrip.addTab(it, JPanel()) }

        repeaterStrip.addChangeListener {
            val index = repeaterStrip.selectedIndex
            if (index < 0) return@addChangeListener

            val name = tabNames[index]
            repeaterStrip.setComponentAt(
                index,
                JSplitPane(
                    JSplitPane.HORIZONTAL_SPLIT,
                    JPanel().apply { add(JTextArea("request $name")) },
                    JPanel().apply { add(JTextArea("response $name")) }
                )
            )
        }
        repeaterStrip.selectedIndex = initialSelectedIndex

        // A single-tab wrapper, purely for tab-styled borders around one editor - this is what leaked as phantom
        // "Request"/"Response" entries in the reported bug.
        val requestWrapper = JTabbedPane().apply { addTab("Request", JPanel().apply { add(JTextArea("req")) }) }
        val responseWrapper = JTabbedPane().apply { addTab("Response", JPanel().apply { add(JTextArea("resp")) }) }
        val wrapperSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestWrapper, responseWrapper)
        repeaterStrip.addTab("__wrapperHost", wrapperSplit)

        val repeaterToolPanel = JPanel().apply { add(repeaterStrip) }

        val suiteNav = JTabbedPane()
        suiteNav.addTab("Dashboard", JPanel())
        suiteNav.addTab("Target", JPanel())
        suiteNav.addTab("Proxy", JPanel())
        suiteNav.addTab("Repeater", repeaterToolPanel)
        suiteNav.addTab("Sequencer", JPanel())

        val frame = Frame()
        frame.add(suiteNav)
        return frame to repeaterStrip
    }

    @Test
    fun `finds tab by exact name and extracts request and response text`() {
        val api = mockApi(buildSimpleFrame())

        val result = findRepeaterTabContent(api, "MyTab1")

        assertNotNull(result)
        assertEquals("MyTab1", result!!.tabTitle)
        assertEquals("GET / HTTP/1.1", result.request)
        assertEquals("HTTP/1.1 200 OK", result.response)
    }

    @Test
    fun `finds tab by case-insensitive name when no exact match exists`() {
        val api = mockApi(buildSimpleFrame())

        val result = findRepeaterTabContent(api, "mytab1")

        assertNotNull(result)
        assertEquals("MyTab1", result!!.tabTitle)
    }

    @Test
    fun `returns null when no tab matches`() {
        val api = mockApi(buildSimpleFrame())

        val result = findRepeaterTabContent(api, "DoesNotExist")

        assertNull(result)
    }

    @Test
    fun `finds a matching tab by name but cannot extract content when it lacks a request-response split`() {
        val api = mockApi(buildSimpleFrame())

        val result = findRepeaterTabContent(api, "Unrelated")

        assertNotNull(result)
        assertEquals("Unrelated", result!!.tabTitle)
        assertNull(result.request)
        assertNull(result.response)
    }

    @Test
    fun `list repeater tabs returns every open tab, not just the focused one`() {
        val names = (1..10).map { "MyTab$it" }
        val (frame, _) = buildBurpLikeFrame(names, initialSelectedIndex = 6)
        val api = mockApi(frame)

        val titles = findRepeaterTabTitles(api)

        assertEquals(names + listOf("__wrapperHost"), titles)
    }

    @Test
    fun `list repeater tabs excludes the main suite tool switcher and nested request response wrappers`() {
        val names = (1..10).map { "MyTab$it" }
        val (frame, _) = buildBurpLikeFrame(names, initialSelectedIndex = 6)
        val api = mockApi(frame)

        val titles = findRepeaterTabTitles(api)

        assertEquals(false, titles.contains("Repeater"))
        assertEquals(false, titles.contains("Dashboard"))
        assertEquals(false, titles.contains("Request"))
        assertEquals(false, titles.contains("Response"))
    }

    @Test
    fun `list repeater tabs is correct even with fewer repeater tabs than main suite tool tabs`() {
        val names = listOf("OnlyTab")
        val (frame, _) = buildBurpLikeFrame(names, initialSelectedIndex = 0)
        val api = mockApi(frame)

        val titles = findRepeaterTabTitles(api)

        assertEquals(names + listOf("__wrapperHost"), titles)
    }

    @Test
    fun `get repeater tab can read a cold (unrealized) tab by activating it temporarily`() {
        val names = (1..10).map { "MyTab$it" }
        val (frame, _) = buildBurpLikeFrame(names, initialSelectedIndex = 6)
        val api = mockApi(frame)

        val result = findRepeaterTabContent(api, "MyTab3")

        assertNotNull(result)
        assertEquals("MyTab3", result!!.tabTitle)
        assertEquals("request MyTab3", result.request)
        assertEquals("response MyTab3", result.response)
    }

    @Test
    fun `get repeater tab restores the previously selected tab after reading a cold tab`() {
        val names = (1..5).map { "MyTab$it" }
        val (frame, strip) = buildBurpLikeFrame(names, initialSelectedIndex = 2)
        val api = mockApi(frame)

        findRepeaterTabContent(api, "MyTab5")

        assertEquals(2, strip.selectedIndex)
    }
}
