package com.llmsecurityscanner.presentation.reports

import android.content.Context
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.model.ScanReportResponse
import com.llmsecurityscanner.data.repository.ScannerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class ReportsUiState(
    val isLoading: Boolean = false,
    val report: ScanReportResponse? = null,
    val isExporting: Boolean = false,
    val errorMessage: String? = null
)

class ReportsViewModel(private val repository: ScannerRepository) : ViewModel() {

    private val _uiState = MutableStateFlow(ReportsUiState())
    val uiState: StateFlow<ReportsUiState> = _uiState.asStateFlow()

    fun loadReport(scanId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            when (val res = repository.getScanReport(scanId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, report = res.data)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun shareReportCsv(context: Context, scanId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isExporting = true)
            when (val res = repository.downloadScanCsv(scanId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isExporting = false)
                    try {
                        val csvContent = res.data.string()
                        val sendIntent = Intent().apply {
                            action = Intent.ACTION_SEND
                            putExtra(Intent.EXTRA_TEXT, csvContent)
                            putExtra(Intent.EXTRA_SUBJECT, "LLM Security Scan Report - $scanId")
                            type = "text/csv"
                        }
                        val shareIntent = Intent.createChooser(sendIntent, "Share Security CSV Report")
                        shareIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        context.startActivity(shareIntent)
                    } catch (e: Exception) {
                        _uiState.value = _uiState.value.copy(errorMessage = "Export failed: ${e.localizedMessage}")
                    }
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isExporting = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    class Factory(private val repository: ScannerRepository) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            @Suppress("UNCHECKED_CAST")
            return ReportsViewModel(repository) as T
        }
    }
}
