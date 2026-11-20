package com.llmsecurityscanner.data.api

import android.util.Log
import com.google.gson.Gson
import com.llmsecurityscanner.data.model.ScanEventResponse
import com.llmsecurityscanner.data.security.SecureTokenStorage
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import okhttp3.*
import okhttp3.sse.EventSource
import okhttp3.sse.EventSourceListener
import okhttp3.sse.EventSources
import java.util.concurrent.TimeUnit

class SseClient(
    private val secureStorage: SecureTokenStorage,
    private val gson: Gson = Gson()
) {
    private val okHttpClient = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS) // infinite timeout for SSE stream
        .connectTimeout(15, TimeUnit.SECONDS)
        .build()

    fun observeScanStream(scanId: String, sinceSeq: Int = 0): Flow<ScanEventResponse> = callbackFlow {
        val baseUrl = secureStorage.getBaseUrl()
        val url = "${baseUrl}api/v1/scans/$scanId/live?since_seq=$sinceSeq"

        val requestBuilder = Request.Builder()
            .url(url)
            .header("Accept", "text/event-stream")

        val token = secureStorage.getToken()
        if (!token.isNullOrBlank()) {
            requestBuilder.header("Authorization", "Bearer $token")
        } else if (secureStorage.isDevMode()) {
            requestBuilder.header("X-User-ID", secureStorage.getUserId())
        }

        val request = requestBuilder.build()
        val factory = EventSources.createFactory(okHttpClient)

        val listener = object : EventSourceListener() {
            override fun onOpen(eventSource: EventSource, response: Response) {
                Log.d("SseClient", "SSE Stream opened for scan $scanId")
            }

            override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
                try {
                    val event = gson.fromJson(data, ScanEventResponse::class.java)
                    trySend(event)
                } catch (e: Exception) {
                    Log.e("SseClient", "Failed to parse SSE event: $data", e)
                }
            }

            override fun onClosed(eventSource: EventSource) {
                Log.d("SseClient", "SSE Stream closed for scan $scanId")
                close()
            }

            override fun onFailure(eventSource: EventSource, t: Throwable?, response: Response?) {
                Log.w("SseClient", "SSE Stream error for scan $scanId: ${t?.message}")
                close(t)
            }
        }

        val eventSource = factory.newEventSource(request, listener)

        awaitClose {
            eventSource.cancel()
        }
    }
}
