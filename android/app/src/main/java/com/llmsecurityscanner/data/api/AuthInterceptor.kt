package com.llmsecurityscanner.data.api

import com.llmsecurityscanner.data.security.SecureTokenStorage
import okhttp3.Interceptor
import okhttp3.Response

class AuthInterceptor(private val secureStorage: SecureTokenStorage) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val builder = original.newBuilder()

        val token = secureStorage.getToken()
        if (!token.isNullOrBlank()) {
            builder.header("Authorization", "Bearer $token")
        } else if (secureStorage.isDevMode()) {
            // Development identity mode for local testing
            builder.header("X-User-ID", secureStorage.getUserId())
        }

        builder.header("Accept", "application/json")
        return chain.proceed(builder.build())
    }
}
