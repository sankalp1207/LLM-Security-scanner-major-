package com.llmsecurityscanner.presentation.projects

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.model.*
import com.llmsecurityscanner.data.repository.ScannerRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class ProjectsUiState(
    val isLoading: Boolean = false,
    val projects: List<ProjectResponse> = emptyList(),
    val selectedProject: ProjectResponse? = null,
    val capabilities: ScanCapabilitiesResponse? = null,
    val verificationResult: TargetVerificationResponse? = null,
    val isVerifying: Boolean = false,
    val errorMessage: String? = null
)

class ProjectsViewModel(private val repository: ScannerRepository) : ViewModel() {

    private val _uiState = MutableStateFlow(ProjectsUiState())
    val uiState: StateFlow<ProjectsUiState> = _uiState.asStateFlow()

    init {
        loadProjects()
    }

    fun loadProjects() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, errorMessage = null)
            repository.getProjectsFlow().collect { result ->
                when (result) {
                    is NetworkResult.Success -> {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            projects = result.data,
                            errorMessage = null
                        )
                    }
                    is NetworkResult.Error -> {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            errorMessage = result.message
                        )
                    }
                    else -> {}
                }
            }
        }
    }

    fun createProject(name: String, description: String?, targetType: String, targetUrl: String?, onComplete: () -> Unit) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)
            val req = ProjectCreateRequest(
                name = name,
                description = description,
                targetType = targetType,
                targetUrl = targetUrl
            )
            when (val res = repository.createProject(req)) {
                is NetworkResult.Success -> {
                    loadProjects()
                    onComplete()
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    fun selectProject(projectId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, verificationResult = null)
            when (val res = repository.getProject(projectId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, selectedProject = res.data)
                    loadProjectCapabilities(projectId)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(isLoading = false, errorMessage = res.message)
                }
                else -> {}
            }
        }
    }

    private fun loadProjectCapabilities(projectId: String) {
        viewModelScope.launch {
            when (val res = repository.getScanCapabilities(projectId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(capabilities = res.data)
                }
                else -> {}
            }
        }
    }

    fun verifyConnection(projectId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isVerifying = true, verificationResult = null)
            when (val res = repository.verifyProjectConnection(projectId)) {
                is NetworkResult.Success -> {
                    _uiState.value = _uiState.value.copy(isVerifying = false, verificationResult = res.data)
                }
                is NetworkResult.Error -> {
                    _uiState.value = _uiState.value.copy(
                        isVerifying = false,
                        verificationResult = TargetVerificationResponse(
                            status = "FAILED",
                            reachable = false,
                            message = res.message
                        )
                    )
                }
                else -> {}
            }
        }
    }

    class Factory(private val repository: ScannerRepository) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            @Suppress("UNCHECKED_CAST")
            return ProjectsViewModel(repository) as T
        }
    }
}
