package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.Version
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.modelcontextprotocol.kotlin.sdk.CallToolResultBase
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket

class LoggerToolsKtTest {

    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val loggerStore = mockLoggerStore()
    private val serverManager = KtorServerManager(api, loggerStore)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private lateinit var originalApprovalHandler: DataAccessApprovalHandler

    init {
        val configStorage = mutableMapOf<String, Any>(
            "enabled" to true,
            "configEditingTooling" to true,
            "requireHttpRequestApproval" to false,
            "requireDataAccessApproval" to false,
            "_alwaysAllowHttpHistory" to true,
            "_alwaysAllowWebSocketHistory" to false,
            "_alwaysAllowOrganizer" to false,
            "_alwaysAllowSiteMap" to false,
            "_alwaysAllowLogger" to true,
            "loggerCaptureEnabled" to true,
            "loggerCaptureExtensions" to true,
            "loggerPersistenceEnabled" to false,
        )
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { configStorage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { configStorage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { configStorage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers { configStorage[firstArg()] = secondArg() }
            every { setString(any(), any()) } answers { configStorage[firstArg()] = secondArg() }
            every { setInteger(any(), any()) } answers { configStorage[firstArg()] = secondArg() }
        }
        persistedObject.apply {
            every { getString("host") } returns "127.0.0.1"
            every { getString("_autoApproveTargets") } returns ""
            every { getString("_authIdentitiesJson") } returns "[]"
            every { getInteger("port") } returns testPort
            every { getInteger("loggerMaxEntries") } returns 5000
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }
        config = McpConfig(persistedObject, mockLogging)

        val burpSuite = mockk<BurpSuite>()
        val version = mockk<Version>()
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
    }

    @BeforeEach
    fun setup() {
        originalApprovalHandler = DataAccessSecurity.approvalHandler
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }
        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
            client.connectToServer("http://127.0.0.1:$testPort")
        }
    }

    @AfterEach
    fun tearDown() {
        DataAccessSecurity.approvalHandler = originalApprovalHandler
        runBlocking {
            if (client.isConnected()) client.close()
        }
        serverManager.stop {}
        serverStarted = false
    }

    @Test
    fun `logger tools are registered`() = runBlocking {
        val toolNames = client.listTools().map { it.name }.toSet()
        val expected = setOf(
            "get_logger_history",
            "get_logger_history_regex",
            "get_logger_history_entry",
            "clear_logger_capture",
        )
        expected.forEach { name ->
            assertTrue(toolNames.contains(name), "Expected tool $name to be registered")
        }
    }

    @Test
    fun `get_logger_history returns empty message when capture empty`() = runBlocking {
        val result = client.callTool(
            "get_logger_history",
            mapOf("count" to 10, "offset" to 0),
        )
        result.expectTextContains("Reached end of items")
    }

    @Test
    fun `clear_logger_capture succeeds`() = runBlocking {
        val result = client.callTool("clear_logger_capture", mapOf("confirm" to true))
        result.expectTextContains("Logger capture cleared")
    }

    @Test
    fun `clear_logger_capture requires confirm`() = runBlocking {
        val result = client.callTool("clear_logger_capture", mapOf("confirm" to false))
        result.expectTextContains("Clear not confirmed")
    }

    @Test
    fun `clear_logger_capture denied without logger consent`() = runBlocking {
        config.requireDataAccessApproval = true
        config.alwaysAllowLogger = false
        DataAccessSecurity.approvalHandler = object : DataAccessApprovalHandler {
            override suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig) = false
        }

        val result = client.callTool("clear_logger_capture", mapOf("confirm" to true))
        result.expectTextContains("Logger capture access denied by Burp Suite")
    }

    private fun mockLoggerStore(): LoggerCaptureStore {
        val storage = mockk<PersistedObject>(relaxed = true)
        val logging = mockk<Logging>(relaxed = true)
        val cfg = McpConfig(storage, logging)
        return LoggerCaptureStore(cfg, storage)
    }

    private fun findAvailablePort(): Int = ServerSocket(0).use { it.localPort }

    private fun CallToolResultBase?.expectTextContains(expected: String) {
        assertNotNull(this)
        val textContent = this!!.content?.firstOrNull() as? TextContent
        assertNotNull(textContent)
        val text = textContent!!.text!!
        assertTrue(text.contains(expected), "Expected '$expected' in: $text")
    }
}
