package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class McpConfigAuthIdentityTest {

    private val storage = mutableMapOf<String, Any?>()
    private val persistedObject = mockk<PersistedObject>().apply {
        every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean }
        every { getString(any()) } answers { storage[firstArg()] as? String }
        every { getInteger(any()) } answers { storage[firstArg()] as? Int }
        every { setBoolean(any(), any()) } answers {
            storage[firstArg()] = secondArg()
            Unit
        }
        every { setString(any(), any()) } answers {
            storage[firstArg()] = secondArg()
            Unit
        }
        every { setInteger(any(), any()) } answers {
            storage[firstArg()] = secondArg()
            Unit
        }
    }

    private val logging = mockk<Logging>(relaxed = true)

    init {
        storage["enabled"] = true
        storage["configEditingTooling"] = false
        storage["host"] = "127.0.0.1"
        storage["port"] = 9876
        storage["requireHttpRequestApproval"] = true
        storage["requireDataAccessApproval"] = true
        storage["_alwaysAllowHttpHistory"] = false
        storage["_alwaysAllowWebSocketHistory"] = false
        storage["_alwaysAllowOrganizer"] = false
        storage["filterConfigCredentials"] = true
        storage["_autoApproveTargets"] = ""
        storage["_authIdentitiesJson"] = "[]"
    }

    @Test
    fun `auth identities can be set listed and deleted`() {
        val config = McpConfig(persistedObject, logging)

        assertTrue(config.setAuthIdentity("low_priv", listOf("Cookie: session=abc")))
        assertEquals(1, config.getAuthIdentities().size)
        assertEquals("low_priv", config.getAuthIdentity("low_priv")?.name)

        assertTrue(config.deleteAuthIdentity("low_priv"))
        assertFalse(config.deleteAuthIdentity("missing"))
        assertTrue(config.getAuthIdentities().isEmpty())
    }
}
