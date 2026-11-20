package com.llmsecurityscanner.presentation.findings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.model.FindingResponse
import com.llmsecurityscanner.data.model.RetestResponse
import com.llmsecurityscanner.data.repository.ScannerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class FindingsUiState(
    val isLoading: Boolean = false,
    val findings: List<FindingResponse> = emptyList(),
    val filteredFindings: List<FindingResponse> = emptyList(),
    val selectedFinding: FindingResponse? = null,
    val selectedSeverityFilter: String? = null,
    val searchQuery: String = "",
    val isRetesting: Boolean = false,
    val retestResult: RetestResponse? = null,
    val errorMessage: String? = null
)

class FindingsViewModel(private val repository: ScannerRepository) : ViewModel() {

    private val _uiState = MutableStateFlow(FindingsUiState())
    val uiState: StateFlow<FindingsUiState> = _uiState.asStateFlow()

    init {
        loadFindings()
    }

    fun loadFindings() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            repository.getFindingsFlow().collect { res ->
                when (res) {
                    is NetworkResult.Success -> {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            findings = res.data,
                            filteredFindings = applyFilters(res.data, _uiState.value.selectedSeverityFilter, _uiState.value.searchQuery)
                        )
                    }
                    is NetworkResult.Error -> {
                        _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = res.message)
                    }
                    else -> {}
                }
            }
        }
    }

    fun setSeverityFilter(severity: String?) {
        val newFilter = if (_uiState.value.selectedSeverityFilter == severity) null else severity
        _uiState.value = _uiState.value.copy(
            selectedSeverityFilter = newFilter,
            filteredFindings = applyFilters(_uiState.value.findings, newFilter, _uiState.value.searchQuery)
        )
    }

    fun setSearchQuery(query: String) {
        _uiState.value = _uiState.value.copy(
            searchQuery = query,
            filteredFindings = applyFilters(_uiState.value.findings, _uiState.value.selectedSeverityFilter, query)
        )
    }

    fun selectFinding(findingId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, retestResult = null)
            when (val res = repository.getFinding(findingId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, selectedFinding = res.data)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun retestFinding(findingId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isRetesting = true, retestResult = null)
            when (val res = repository.retestFinding(findingId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isRetesting = false, retestResult = res.data)
                    // Refresh current finding record
                    selectFinding(findingId)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isRetesting = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    private fun applyFilters(list: List<FindingResponse>, severity: String?, query: String): List<FindingResponse> {
        return list.filter { f ->
            val matchSeverity = severity == null || f.severity.equals(severity, ignoreCase = true)
            val matchQuery = query.isBlank() || f.title.contains(query, ignoreCase = true) ||
                    (f.description?.contains(query, ignoreCase = true) == true) ||
                    f.category.contains(query, ignoreCase = true)
            matchSeverity && matchQuery
        }
    }

    class Factory(private val repository: ScannerRepository) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            @Suppress("UNCHECKED_CAST")
            return FindingsViewModel(repository) as T
        }
    }
}
