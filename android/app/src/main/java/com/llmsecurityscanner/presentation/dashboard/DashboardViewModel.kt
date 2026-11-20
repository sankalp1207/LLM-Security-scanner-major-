package com.llmsecurityscanner.presentation.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.model.FindingResponse
import com.llmsecurityscanner.data.model.ScanResponse
import com.llmsecurityscanner.data.repository.ScannerRepository
import com.llmsecurityscanner.domain.model.Severity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class DashboardUiState(
    val isLoading: Boolean = false,
    val totalScans: Int = 0,
    val totalVulnerabilities: Int = 0,
    val criticalCount: Int = 0,
    val highCount: Int = 0,
    val mediumCount: Int = 0,
    val lowCount: Int = 0,
    val recentScans: List<ScanResponse> = emptyList(),
    val errorMessage: String? = null
)

class DashboardViewModel(private val repository: ScannerRepository) : ViewModel() {

    private val _uiState = MutableStateFlow(DashboardUiState())
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        loadDashboardData()
    }

    fun loadDashboardData() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)

            var scans = emptyList<ScanResponse>()
            var findings = emptyList<FindingResponse>()
            var err: String? = null

            repository.getScansFlow().collect { result ->
                when (result) {
                    is NetworkResult.Success -> scans = result.data
                    is NetworkResult.Error -> err = result.message
                    else -> {}
                }
            }

            repository.getFindingsFlow().collect { result ->
                when (result) {
                    is NetworkResult.Success -> findings = result.data
                    is NetworkResult.Error -> if (err == null) err = result.message
                    else -> {}
                }
            }

            val crit = findings.count { Severity.fromString(it.severity) == Severity.CRITICAL }
            val high = findings.count { Severity.fromString(it.severity) == Severity.HIGH }
            val med = findings.count { Severity.fromString(it.severity) == Severity.MEDIUM }
            val low = findings.count { Severity.fromString(it.severity) == Severity.LOW }

            _uiState.value = DashboardUiState(
                isLoading = false,
                totalScans = scans.size,
                totalVulnerabilities = findings.size,
                criticalCount = crit,
                highCount = high,
                mediumCount = med,
                lowCount = low,
                recentScans = scans.take(5),
                errorMessage = err
            )
        }
    }

    class Factory(private val repository: ScannerRepository) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            @Suppress("UNCHECKED_CAST")
            return DashboardViewModel(repository) as T
        }
    }
}
