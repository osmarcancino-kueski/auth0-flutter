package com.auth0.auth0_flutter.request_handlers

import android.content.Context
import android.os.Build
import com.auth0.android.Auth0
import com.auth0.android.request.HttpMethod
import com.auth0.android.request.NetworkingClient
import com.auth0.android.request.RequestOptions
import com.auth0.android.request.ServerResponse
import com.auth0.android.util.Auth0UserAgent
import com.auth0.auth0_flutter.utils.assertHasProperties
import com.google.gson.Gson
import io.flutter.plugin.common.MethodCall
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UploadDataProvider
import org.chromium.net.UploadDataSink
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

class MethodCallRequest {
    var account: Auth0
    var data: HashMap<*, *>

    constructor(account: Auth0, data: HashMap<*, *>) {
        this.data = data
        this.account = account
    }

    companion object {
        @Volatile
        private var cronetEngine: CronetEngine? = null

        private fun getOrCreateCronetEngine(context: Context): CronetEngine {
            return cronetEngine ?: synchronized(this) {
                cronetEngine ?: CronetEngine.Builder(context.applicationContext)
                    .enableHttp2(true)
                    .enableQuic(true)
                    .enableBrotli(true)
                    .build()
                    .also { cronetEngine = it }
            }
        }

        fun fromCall(call: MethodCall, context: Context): MethodCallRequest {
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

            // Use CroNet (Chromium's network stack) instead of OkHttp so the
            // TLS fingerprint (JA3/JA4) matches Chrome Mobile, preventing
            // Auth0 Bot Detection from flagging API requests as suspicious.
            val mobileUserAgent = buildMobileUserAgent(userAgentMap)
            val engine = getOrCreateCronetEngine(context)
            account.networkingClient = CronetNetworkingClient(engine, mobileUserAgent)

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
 * NetworkingClient backed by CroNet (Chromium's network stack).
 *
 * CroNet uses BoringSSL — the same TLS library as Chrome — so the
 * JA3/JA4 fingerprint matches a real Chrome Mobile browser. This
 * prevents Auth0 Bot Detection from classifying requests as non-mobile.
 *
 * CroNet is asynchronous, so we block with a CountDownLatch to satisfy
 * the synchronous NetworkingClient.load() contract.
 */
private class CronetNetworkingClient(
    private val engine: CronetEngine,
    private val userAgent: String
) : NetworkingClient {

    private val executor = Executors.newCachedThreadPool()
    private val gson = Gson()

    override fun load(url: String, options: RequestOptions): ServerResponse {
        val finalUrl = when (options.method) {
            is HttpMethod.GET -> buildUrlWithParams(url, options.parameters)
            else -> url
        }

        val latch = CountDownLatch(1)
        val callback = SynchronousCallback(latch)

        val requestBuilder = engine.newUrlRequestBuilder(
            finalUrl,
            callback,
            executor
        )

        requestBuilder.setHttpMethod(options.method.toString())

        // Force our mobile User-Agent
        options.headers["User-Agent"] = userAgent
        for ((key, value) in options.headers) {
            requestBuilder.addHeader(key, value)
        }

        // For non-GET requests, serialize parameters as JSON body
        if (options.method !is HttpMethod.GET && options.parameters.isNotEmpty()) {
            val jsonBody = gson.toJson(options.parameters)
            val bodyBytes = jsonBody.toByteArray(StandardCharsets.UTF_8)

            requestBuilder.addHeader("Content-Type", "application/json; charset=UTF-8")
            requestBuilder.setUploadDataProvider(
                ByteArrayUploadDataProvider(bodyBytes),
                executor
            )
        }

        val request = requestBuilder.build()
        request.start()

        latch.await()

        if (callback.exception != null) {
            throw IOException("CroNet request failed", callback.exception)
        }

        return ServerResponse(
            statusCode = callback.httpStatusCode,
            body = ByteArrayInputStream(callback.responseBody),
            headers = callback.responseHeaders
        )
    }

    private fun buildUrlWithParams(url: String, params: Map<String, Any>): String {
        if (params.isEmpty()) return url
        val separator = if (url.contains("?")) "&" else "?"
        val queryString = params.entries.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v.toString(), "UTF-8")}"
        }
        return "$url$separator$queryString"
    }
}

/**
 * UrlRequest.Callback that accumulates the response and signals
 * a CountDownLatch when complete.
 */
private class SynchronousCallback(
    private val latch: CountDownLatch
) : UrlRequest.Callback() {

    var httpStatusCode: Int = -1
    var responseHeaders: Map<String, List<String>> = emptyMap()
    var exception: Exception? = null

    private val bodyParts = mutableListOf<ByteArray>()
    val responseBody: ByteArray
        get() {
            val totalSize = bodyParts.sumOf { it.size }
            val result = ByteArray(totalSize)
            var offset = 0
            for (part in bodyParts) {
                System.arraycopy(part, 0, result, offset, part.size)
                offset += part.size
            }
            return result
        }

    override fun onRedirectReceived(
        request: UrlRequest?,
        info: UrlResponseInfo?,
        newLocationUrl: String?
    ) {
        request?.followRedirect()
    }

    override fun onResponseStarted(
        request: UrlRequest?,
        info: UrlResponseInfo?
    ) {
        httpStatusCode = info?.httpStatusCode ?: -1
        responseHeaders = info?.allHeaders ?: emptyMap()
        request?.read(ByteBuffer.allocateDirect(102400))
    }

    override fun onReadCompleted(
        request: UrlRequest?,
        info: UrlResponseInfo?,
        byteBuffer: ByteBuffer?
    ) {
        byteBuffer?.let {
            it.flip()
            val bytes = ByteArray(it.remaining())
            it.get(bytes)
            bodyParts.add(bytes)
            it.clear()
            request?.read(it)
        }
    }

    override fun onSucceeded(
        request: UrlRequest?,
        info: UrlResponseInfo?
    ) {
        latch.countDown()
    }

    override fun onFailed(
        request: UrlRequest?,
        info: UrlResponseInfo?,
        error: CronetException?
    ) {
        exception = error ?: IOException("Unknown CroNet error")
        latch.countDown()
    }

    override fun onCanceled(
        request: UrlRequest?,
        info: UrlResponseInfo?
    ) {
        exception = IOException("Request was canceled")
        latch.countDown()
    }
}

/**
 * UploadDataProvider that sends a byte array as the request body.
 */
private class ByteArrayUploadDataProvider(
    private val data: ByteArray
) : UploadDataProvider() {

    private var offset = 0

    override fun getLength(): Long = data.size.toLong()

    override fun read(uploadDataSink: UploadDataSink, byteBuffer: ByteBuffer) {
        val remaining = data.size - offset
        val toWrite = minOf(remaining, byteBuffer.remaining())
        byteBuffer.put(data, offset, toWrite)
        offset += toWrite
        uploadDataSink.onReadSucceeded(false)
    }

    override fun rewind(uploadDataSink: UploadDataSink) {
        offset = 0
        uploadDataSink.onRewindSucceeded()
    }
}
