package com.llmsecurityscanner.presentation.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.llmsecurityscanner.LLMSecurityApp
import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.repository.ScannerRepository
import com.llmsecurityscanner.data.security.SecureTokenStorage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class SettingsUiState(
    val baseUrl: String = SecureTokenStorage.DEFAULT_EMULATOR_URL,
    val authToken: String = "",
    val userId: String = "default_user",
    val isDevMode: Boolean = true,
    val isTestingConnection: Boolean = false,
    val connectionStatus: String? = null,
    val isConnected: Boolean? = null
)

class SettingsViewModel(
    private val repository: ScannerRepository,
    private val app: LLMSecurityApp
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SettingsUiState(
            baseUrl = repository.secureStorage.getBaseUrl(),
            authToken = repository.secureStorage.getToken() ?: "",
            userId = repository.secureStorage.getUserId(),
            isDevMode = repository.secureStorage.isDevMode()
        )
    )
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    fun updateBaseUrl(url: String) {
        _uiState.value = _uiState.value.copy(baseUrl = url)
        repository.secureStorage.saveBaseUrl(url)
        app.rebuildRepository()
    }

    fun updateAuthToken(token: String) {
        _uiState.value = _uiState.value.copy(authToken = token)
        repository.secureStorage.saveToken(token.ifBlank { null })
    }

    fun updateUserId(userId: String) {
        _uiState.value = _uiState.value.copy(userId = userId)
        repository.secureStorage.saveUserId(userId)
    }

    fun setDevMode(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(isDevMode = enabled)
        repository.secureStorage.setDevMode(enabled)
    }

    fun testConnection() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isTestingConnection = true, connectionStatus = null, isConnected = null)
            when (val res = repository.checkHealth()) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(
                        isTestingConnection = false,
                        isConnected = true,
                        connectionStatus = "Connected successfully: ${res.data["status"] ?: "OK"}"
                    )
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(
                        isTestingConnection = false,
                        isConnected = false,
                        connectionStatus = "Connection failed: ${res.message}"
                    )
                }
                else -> {}
            }
        }
    }

    fun clearAuth() {
        repository.secureStorage.clearAuth()
        _uiState.value = _uiState.value.copy(authToken = "")
    }

    class Factory(
        private val repository: ScannerRepository,
        private val app: LLMSecurityApp
    ) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            @Suppress("UNCHECKED_CAST")
            return SettingsViewModel(repository, app) as T
        }
    }
}
