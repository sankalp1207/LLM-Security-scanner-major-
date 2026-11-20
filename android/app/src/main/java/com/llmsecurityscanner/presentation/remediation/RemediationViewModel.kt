package com.llmsecurityscanner.presentation.remediation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.model.RemediationPatchResponse
import com.llmsecurityscanner.data.model.RemediationResponse
import com.llmsecurityscanner.data.model.VerificationResultResponse
import com.llmsecurityscanner.data.repository.ScannerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class RemediationUiState(
    val isLoading: Boolean = false,
    val isOperating: Boolean = false,
    val remediation: RemediationResponse? = null,
    val selectedPatch: RemediationPatchResponse? = null,
    val verificationResult: VerificationResultResponse? = null,
    val errorMessage: String? = null
)

class RemediationViewModel(private val repository: ScannerRepository) : ViewModel() {

    private val _uiState = MutableStateFlow(RemediationUiState())
    val uiState: StateFlow<RemediationUiState> = _uiState.asStateFlow()

    fun initForFinding(findingId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            when (val res = repository.initRemediation(findingId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        remediation = res.data,
                        selectedPatch = res.data.patches.firstOrNull()
                    )
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun generateFix(remediationId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isOperating = true, errorMessage = null)
            when (val res = repository.generateFix(remediationId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(
                        isOperating = false,
                        remediation = res.data,
                        selectedPatch = res.data.patches.firstOrNull()
                    )
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun approvePatch(patchId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isOperating = true)
            when (val res = repository.approvePatch(patchId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, selectedPatch = res.data)
                    refreshRemediation()
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun rejectPatch(patchId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isOperating = true)
            when (val res = repository.rejectPatch(patchId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, selectedPatch = res.data)
                    refreshRemediation()
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun applyPatch(patchId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isOperating = true)
            when (val res = repository.applyPatch(patchId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, selectedPatch = res.data)
                    refreshRemediation()
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun verifyRemediation(remediationId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isOperating = true, verificationResult = null)
            when (val res = repository.verifyRemediation(remediationId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, verificationResult = res.data)
                    refreshRemediation()
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun rollbackRemediation(remediationId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isOperating = true)
            when (val res = repository.rollbackRemediation(remediationId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, remediation = res.data)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isOperating = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    private fun refreshRemediation() {
        val remId = _uiState.value.remediation?.id ?: return
        viewModelScope.launch {
            when (val res = repository.getRemediation(remId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(remediation = res.data)
                }
                else -> {}
            }
        }
    }

    class Factory(private val repository: ScannerRepository) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            @Suppress("UNCHECKED_CAST")
            return RemediationViewModel(repository) as T
        }
    }
}
