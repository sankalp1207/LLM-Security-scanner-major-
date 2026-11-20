package com.llmsecurityscanner

import android.app.Application
import com.google.gson.Gson
import com.llmsecurityscanner.data.api.AuthInterceptor
import com.llmsecurityscanner.data.api.ScannerApiService
import com.llmsecurityscanner.data.api.SseClient
import com.llmsecurityscanner.data.local.AppDatabase
import com.llmsecurityscanner.data.repository.ScannerRepository
import com.llmsecurityscanner.data.security.SecureTokenStorage
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

class LLMSecurityApp : Application() {

    lateinit var secureStorage: SecureTokenStorage
        private set

    lateinit var database: AppDatabase
        private set

    lateinit var repository: ScannerRepository
        private set

    lateinit var sseClient: SseClient
        private set

    override fun onCreate() {
        super.onCreate()

        secureStorage = SecureTokenStorage(this)
        database = AppDatabase.getDatabase(this)
        sseClient = SseClient(secureStorage)

        rebuildRepository()
    }

    fun rebuildRepository() {
        val okHttpClient = OkHttpClient.Builder()
            .addInterceptor(AuthInterceptor(secureStorage))
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()

        val retrofit = Retrofit.Builder()
            .baseUrl(secureStorage.getBaseUrl())
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create(Gson()))
            .build()

        val apiService = retrofit.create(ScannerApiService::class.java)
        repository = ScannerRepository(apiService, database, sseClient, secureStorage)
    }
}
