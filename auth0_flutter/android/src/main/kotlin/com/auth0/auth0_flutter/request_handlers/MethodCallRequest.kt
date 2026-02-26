package com.auth0.auth0_flutter.request_handlers

import android.os.Build
import com.auth0.android.Auth0
import com.auth0.android.request.DefaultClient
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import com.auth0.android.util.Auth0UserAgent
import com.auth0.auth0_flutter.utils.assertHasProperties
import io.flutter.plugin.common.MethodCall

class MethodCallRequest {
    var account: Auth0
    var data: HashMap<*, *>

    constructor(account: Auth0, data: HashMap<*, *>) {
        this.data = data
        this.account = account

    }

    companion object {
        fun fromCall(call: MethodCall): MethodCallRequest {
            val args = call.arguments as HashMap<*, *>

            assertHasProperties(
                listOf(
                    "_account",
                    "_account.domain",
                    "_account.clientId",
                    "_userAgent",
                    "_userAgent.name",
                    "_userAgent.version"
                ), args
            )

            val accountMap = args["_account"] as Map<String, String>
            val account = Auth0(
                accountMap["clientId"] as String,
                accountMap["domain"] as String
            )

            val userAgentMap = args["_userAgent"] as Map<String, String>
            account.auth0UserAgent = Auth0UserAgent(
                name = userAgentMap["name"] as String,
                version = userAgentMap["version"] as String,
            )

            // Fix: Wrap DefaultClient to force a proper mobile User-Agent.
            // DefaultClient merges headers as: defaultHeaders.plus(options.headers)
            // Since the SDK sets User-Agent in options.headers, defaultHeaders
            // can never override it. Instead, we mutate options.headers directly
            // before delegating to DefaultClient.
            val mobileUserAgent = buildMobileUserAgent(userAgentMap)
            account.networkingClient = MobileUserAgentClient(mobileUserAgent)

            return MethodCallRequest(account, args)
        }

        private fun buildMobileUserAgent(userAgentMap: Map<String, String>): String {
            val sdkName = userAgentMap["name"] ?: "auth0-flutter"
            val sdkVersion = userAgentMap["version"] ?: "unknown"
            return "Mozilla/5.0 (Linux; Android ${Build.VERSION.RELEASE}; " +
                "${Build.MODEL} Build/${Build.DISPLAY}) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) " +
                "Version/4.0 $sdkName/$sdkVersion Mobile"
        }
    }
}

/**
 * Wrapper around DefaultClient that forces a mobile User-Agent header.
 *
 * DefaultClient merges headers as: defaultHeaders.plus(options.headers),
 * meaning options.headers (set by the SDK) always takes precedence.
 * Since options.headers is a MutableMap, we replace the User-Agent
 * in-place before delegating, ensuring our value is the one sent.
 */
private class MobileUserAgentClient(
    private val userAgent: String,
    private val delegate: DefaultClient = DefaultClient()
) : NetworkingClient {

    override fun load(url: String, options: RequestOptions): ServerResponse {
        options.headers["User-Agent"] = userAgent
        return delegate.load(url, options)
    }
}
