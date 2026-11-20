package com.llmsecurityscanner.presentation.copilot

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.model.CopilotConversationResponse
import com.llmsecurityscanner.data.model.CopilotMessageResponse
import com.llmsecurityscanner.data.repository.ScannerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class CopilotUiState(
    val isLoading: Boolean = false,
    val isSending: Boolean = false,
    val activeConversation: CopilotConversationResponse? = null,
    val messages: List<CopilotMessageResponse> = emptyList(),
    val errorMessage: String? = null
)

class CopilotViewModel(private val repository: ScannerRepository) : ViewModel() {

    private val _uiState = MutableStateFlow(CopilotUiState())
    val uiState: StateFlow<CopilotUiState> = _uiState.asStateFlow()

    init {
        initOrLoadConversation()
    }

    fun initOrLoadConversation() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            when (val convRes = repository.getCopilotConversations()) {
                is NetworkResult.Success -> {
                    val first = convRes.data.firstOrNull()
                    if (first != null) {
                        _uiState.value = _uiState.value.copy(activeConversation = first)
                        loadMessages(first.id)
                    } else {
                        // Create default conversation
                        createConversation("Security Assistant Session")
                    }
                }
                is NetworkResult.Error -> {
                    // Try to create initial conversation if none exists
                    createConversation("Security Assistant Session")
                }
                else -> {}
            }
        }
    }

    private fun createConversation(title: String) {
        viewModelScope.launch {
            when (val res = repository.createCopilotConversation(title)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        activeConversation = res.data,
                        messages = emptyList()
                    )
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    private fun loadMessages(conversationId: String) {
        viewModelScope.launch {
            when (val res = repository.getCopilotMessages(conversationId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, messages = res.data)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun sendMessage(content: String) {
        if (content.isBlank()) return
        val convId = _uiState.value.activeConversation?.id ?: return

        // Optimistically add user message to list
        val optimisticUserMsg = CopilotMessageResponse(
            id = "temp_${System.currentTimeMillis()}",
            conversationId = convId,
            role = "user",
            content = content
        )

        _uiState.value = _uiState.value.copy(
            isSending = true,
            messages = _uiState.value.messages + optimisticUserMsg
        )

        viewModelScope.launch {
            when (val res = repository.sendCopilotMessage(convId, content)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(
                        isSending = false,
                        messages = _uiState.value.messages.filter { it.id != optimisticUserMsg.id } + listOf(optimisticUserMsg, res.data)
                    )
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(
                        isSending = false,
                        errorMessage = res.message
                    )
                }
                else -> {}
            }
        }
    }

    class Factory(private val repository: ScannerRepository) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            @Suppress("UNCHECKED_CAST")
            return CopilotViewModel(repository) as T
        }
    }
}
