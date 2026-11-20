package com.llmsecurityscanner.presentation.scanner

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.model.*
import com.llmsecurityscanner.data.repository.ScannerRepository
import com.llmsecurityscanner.domain.model.PresetType
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class ScannerUiState(
    val isLoading: Boolean = false,
    val presets: List<PresetResponse> = emptyList(),
    val selectedPreset: PresetType = PresetType.QUICK_SCAN,
    val externalTargetAuthorized: Boolean = false,
    val selectedProjectId: String? = null,
    val projects: List<ProjectResponse> = emptyList(),
    val activeScan: ScanResponse? = null,
    val scanProgress: ScanProgressResponse? = null,
    val liveEvents: List<ScanEventResponse> = emptyList(),
    val isScanning: Boolean = false,
    val errorMessage: String? = null
)

class ScannerViewModel(private val repository: ScannerRepository) : ViewModel() {

    private val _uiState = MutableStateFlow(ScannerUiState())
    val uiState: StateFlow<ScannerUiState> = _uiState.asStateFlow()

    private var sseJob: Job? = null

    init {
        loadInitialData()
    }

    fun loadInitialData() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)

            // Fetch presets
            when (val presetsRes = repository.getPresets()) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(presets = presetsRes.data.presets)
                }
                else -> {}
            }

            // Fetch projects
            repository.getProjectsFlow().collect { projectsRes ->
                when (projectsRes) {
                    is NetworkResult.Success -> {
                        val firstId = projectsRes.data.firstOrNull()?.id
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            projects = projectsRes.data,
                            selectedProjectId = _uiState.value.selectedProjectId ?: firstId
                        )
                    }
                    is NetworkResult.Error -> {
                        _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = projectsRes.message)
                    }
                    else -> {}
                }
            }
        }
    }

    fun setPreset(preset: PresetType) {
        _uiState.value = _uiState.value.copy(selectedPreset = preset)
    }

    fun setProjectId(projectId: String) {
        _uiState.value = _uiState.value.copy(selectedProjectId = projectId)
    }

    fun setAuthorized(authorized: Boolean) {
        _uiState.value = _uiState.value.copy(externalTargetAuthorized = authorized)
    }

    fun startScan(onScanStarted: (String) -> Unit) {
        val projectId = _uiState.value.selectedProjectId ?: return
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isScanning = true, errorMessage = null)

            val req = ProjectScanCreateRequest(
                preset = _uiState.value.selectedPreset.id,
                externalTargetAuthorized = _uiState.value.externalTargetAuthorized,
                syncExecute = false
            )

            when (val res = repository.launchProjectScan(projectId, req)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(
                        isScanning = false,
                        activeScan = res.data,
                        liveEvents = emptyList()
                    )
                    onScanStarted(res.data.id)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(
                        isScanning = false,
                        errorMessage = res.message
                    )
                }
                else -> {}
            }
        }
    }

    fun attachToScan(scanId: String) {
        viewModelScope.launch {
            // Load current scan record
            when (val res = repository.getScan(scanId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(activeScan = res.data)
                }
                else -> {}
            }

            // Load progress
            when (val progRes = repository.getScanProgress(scanId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(scanProgress = progRes.data)
                }
                else -> {}
            }

            // Start SSE stream
            sseJob?.cancel()
            sseJob = launch {
                repository.observeScanStream(scanId).collect { event ->
                    val currentEvents = _uiState.value.liveEvents.toMutableList()
                    if (currentEvents.none { it.id == event.id }) {
                        currentEvents.add(event)
                    }

                    // Update progress if payload contains it
                    var updatedProg = _uiState.value.scanProgress
                    if (event.eventType == "SCAN_PROGRESS") {
                        val pct = (event.payload?.get("progress_percentage") as? Double) ?: updatedProg?.progressPercentage ?: 0.0
                        updatedProg = updatedProg?.copy(progressPercentage = pct)
                    }

                    _uiState.value = _uiState.value.copy(
                        liveEvents = currentEvents,
                        scanProgress = updatedProg
                    )

                    if (event.eventType == "SCAN_COMPLETED" || event.eventType == "SCAN_FAILED" || event.eventType == "SCAN_CANCELLED") {
                        // Refresh final scan record
                        repository.getScan(scanId).let { finalScan ->
                            if (finalScan is NetworkResult.Success) {
                                _uiState.value = _uiState.value.copy(activeScan = finalScan.data)
                            }
                        }
                    }
                }
            }
        }
    }

    fun cancelScan(scanId: String) {
        viewModelScope.launch {
            when (val res = repository.cancelScan(scanId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(activeScan = res.data)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        sseJob?.cancel()
    }

    class Factory(private val repository: ScannerRepository) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            @Suppress("UNCHECKED_CAST")
            return ScannerViewModel(repository) as T
        }
    }
}
