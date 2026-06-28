package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import net.portswigger.mcp.config.components.CollaboratorSuiteTab
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import net.portswigger.mcp.tools.CollaboratorManager
import net.portswigger.mcp.tools.LoggerCaptureStore
import net.portswigger.mcp.tools.LoggerHttpHandler
import net.portswigger.mcp.tools.ProxyHarArchiveHandler
import net.portswigger.mcp.tools.ProxyHarArchiveStore

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server")

        val config = McpConfig(api.persistence().extensionData(), api.logging())
        val loggerStore = LoggerCaptureStore(
            config,
            api.persistence().extensionData(),
        )
        api.http().registerHttpHandler(LoggerHttpHandler(loggerStore, config))

        val archiveStore = ProxyHarArchiveStore(api, config)
        api.proxy().registerResponseHandler(ProxyHarArchiveHandler(archiveStore))

        val isProfessional = api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL
        var collaboratorManager: CollaboratorManager? = null
        var collaboratorTab: CollaboratorSuiteTab? = null

        if (isProfessional) {
            collaboratorManager = CollaboratorManager(api)
            collaboratorTab = CollaboratorSuiteTab(collaboratorManager)
            api.userInterface().registerSuiteTab("MCP Collaborator", collaboratorTab)
        }

        val serverManager = KtorServerManager(api, loggerStore, archiveStore, collaboratorManager)

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            config = config,
            loggerStore = loggerStore,
            archiveStore = archiveStore,
            isProfessional = isProfessional,
            providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        api.userInterface().registerSuiteTab("MCP", configUi.component)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()
            loggerStore.shutdown()
            collaboratorManager?.shutdown()
            collaboratorTab?.shutdown()
            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }
}
