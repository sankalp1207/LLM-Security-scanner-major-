package com.llmsecurityscanner.data.repository

import com.llmsecurityscanner.data.api.NetworkResult
import com.llmsecurityscanner.data.api.ScannerApiService
import com.llmsecurityscanner.data.api.SseClient
import com.llmsecurityscanner.data.local.AppDatabase
import com.llmsecurityscanner.data.local.entity.FindingEntity
import com.llmsecurityscanner.data.local.entity.ProjectEntity
import com.llmsecurityscanner.data.local.entity.ScanEntity
import com.llmsecurityscanner.data.model.*
import com.llmsecurityscanner.data.security.SecureTokenStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import okhttp3.ResponseBody
import retrofit2.Response

class ScannerRepository(
    private val api: ScannerApiService,
    private val db: AppDatabase,
    private val sseClient: SseClient,
    val secureStorage: SecureTokenStorage
) {
    // Helper to safely execute Retrofit calls into NetworkResult
    private suspend fun <T> safeApiCall(apiCall: suspend () -> Response<T>): NetworkResult<T> {
        return try {
            val response = apiCall()
            if (response.isSuccessful && response.body() != null) {
                NetworkResult.Success(response.body()!!)
            } else {
                val errorMsg = response.errorBody()?.string() ?: response.message()
                NetworkResult.Error("API Error ${response.code()}: $errorMsg", response.code())
            }
        } catch (e: Exception) {
            NetworkResult.Error("Network failure: ${e.localizedMessage ?: "Unknown error"}", cause = e)
        }
    }

    // Health
    suspend fun checkHealth(): NetworkResult<Map<String, Any>> = safeApiCall { api.getHealth() }

    // Presets
    suspend fun getPresets(): NetworkResult<ScanPresetsListResponse> = safeApiCall { api.getPresets() }

    // Projects
    fun getProjectsFlow(): Flow<NetworkResult<List<ProjectResponse>>> = flow {
        emit(NetworkResult.Loading)
        val result = safeApiCall { api.getProjects() }
        if (result is NetworkResult.Success) {
            // Cache to Room
            val entities = result.data.items.map {
                ProjectEntity(
                    id = it.id,
                    name = it.name,
                    description = it.description,
                    applicationType = it.applicationType,
                    environment = it.environment,
                    targetType = it.targetType,
                    targetUrl = it.targetUrl,
                    createdAt = it.createdAt
                )
            }
            db.projectDao().insertProjects(entities)
            emit(NetworkResult.Success(result.data.items))
        } else if (result is NetworkResult.Error) {
            emit(result)
        }
    }.flowOn(Dispatchers.IO)

    suspend fun createProject(request: ProjectCreateRequest): NetworkResult<ProjectResponse> =
        safeApiCall { api.createProject(request) }

    suspend fun getProject(id: String): NetworkResult<ProjectResponse> =
        safeApiCall { api.getProject(id) }

    suspend fun deleteProject(id: String): NetworkResult<Map<String, Any>> {
        val res = safeApiCall { api.deleteProject(id) }
        if (res is NetworkResult.Success) {
            db.projectDao().deleteProjectById(id)
        }
        return res
    }

    suspend fun verifyProjectConnection(id: String): NetworkResult<TargetVerificationResponse> =
        safeApiCall { api.verifyProjectConnection(id) }

    suspend fun getScanCapabilities(id: String): NetworkResult<ScanCapabilitiesResponse> =
        safeApiCall { api.getScanCapabilities(id) }

    // Scans
    suspend fun launchProjectScan(projectId: String, request: ProjectScanCreateRequest): NetworkResult<ScanResponse> =
        safeApiCall { api.launchProjectScan(projectId, request) }

    fun getScansFlow(): Flow<NetworkResult<List<ScanResponse>>> = flow {
        emit(NetworkResult.Loading)
        val result = safeApiCall { api.getScans() }
        if (result is NetworkResult.Success) {
            val entities = result.data.items.map {
                ScanEntity(
                    id = it.id,
                    projectId = it.projectId,
                    status = it.status,
                    preset = it.preset,
                    progressPct = it.progressPct,
                    startedAt = it.startedAt,
                    completedAt = it.completedAt,
                    vulnerabilitiesFound = it.summary?.vulnerabilitiesFound ?: 0,
                    criticalSeverity = it.summary?.criticalSeverity ?: 0,
                    highSeverity = it.summary?.highSeverity ?: 0
                )
            }
            db.scanDao().insertScans(entities)
            emit(NetworkResult.Success(result.data.items))
        } else if (result is NetworkResult.Error) {
            emit(result)
        }
    }.flowOn(Dispatchers.IO)

    suspend fun getScan(id: String): NetworkResult<ScanResponse> = safeApiCall { api.getScan(id) }

    suspend fun cancelScan(id: String): NetworkResult<ScanResponse> = safeApiCall { api.cancelScan(id) }

    suspend fun getScanProgress(id: String): NetworkResult<ScanProgressResponse> =
        safeApiCall { api.getScanProgress(id) }

    suspend fun getScanEvents(id: String, sinceSeq: Int = 0): NetworkResult<ScanEventsListResponse> =
        safeApiCall { api.getScanEvents(id, sinceSeq) }

    fun observeScanStream(scanId: String, sinceSeq: Int = 0): Flow<ScanEventResponse> =
        sseClient.observeScanStream(scanId, sinceSeq)

    // Findings
    fun getFindingsFlow(
        severity: String? = null,
        category: String? = null,
        retestStatus: String? = null
    ): Flow<NetworkResult<List<FindingResponse>>> = flow {
        emit(NetworkResult.Loading)
        val result = safeApiCall { api.getFindings(severity = severity, category = category, retestStatus = retestStatus) }
        if (result is NetworkResult.Success) {
            val entities = result.data.items.map {
                FindingEntity(
                    id = it.id,
                    scanId = it.scanId,
                    projectId = it.projectId,
                    title = it.title,
                    description = it.description,
                    severity = it.severity,
                    category = it.category,
                    affectedComponent = it.affectedComponent,
                    retestStatus = it.retestStatus,
                    createdAt = it.createdAt
                )
            }
            db.findingDao().insertFindings(entities)
            emit(NetworkResult.Success(result.data.items))
        } else if (result is NetworkResult.Error) {
            emit(result)
        }
    }.flowOn(Dispatchers.IO)

    suspend fun getFinding(id: String): NetworkResult<FindingResponse> = safeApiCall { api.getFinding(id) }

    suspend fun retestFinding(id: String): NetworkResult<RetestResponse> = safeApiCall { api.retestFinding(id) }

    // Copilot
    suspend fun getCopilotConversations(): NetworkResult<List<CopilotConversationResponse>> =
        safeApiCall { api.getCopilotConversations() }

    suspend fun createCopilotConversation(title: String, projectId: String? = null): NetworkResult<CopilotConversationResponse> {
        val map = mutableMapOf("title" to title)
        projectId?.let { map["project_id"] = it }
        return safeApiCall { api.createCopilotConversation(map) }
    }

    suspend fun getCopilotMessages(conversationId: String): NetworkResult<List<CopilotMessageResponse>> =
        safeApiCall { api.getCopilotMessages(conversationId) }

    suspend fun sendCopilotMessage(
        conversationId: String,
        content: String,
        projectId: String? = null,
        findingId: String? = null,
        scanId: String? = null
    ): NetworkResult<CopilotMessageResponse> {
        val req = CopilotMessageRequest(
            content = content,
            projectId = projectId,
            findingId = findingId,
            scanId = scanId
        )
        return safeApiCall { api.sendCopilotMessage(conversationId, req) }
    }

    suspend fun explainFinding(findingId: String): NetworkResult<CopilotFindingExplanationResponse> =
        safeApiCall { api.explainFinding(findingId) }

    // Remediation
    suspend fun initRemediation(findingId: String): NetworkResult<RemediationResponse> =
        safeApiCall { api.initRemediation(findingId) }

    suspend fun getRemediation(id: String): NetworkResult<RemediationResponse> =
        safeApiCall { api.getRemediation(id) }

    suspend fun generateFix(id: String): NetworkResult<RemediationResponse> =
        safeApiCall { api.generateFix(id) }

    suspend fun approvePatch(patchId: String, notes: String? = null): NetworkResult<RemediationPatchResponse> =
        safeApiCall { api.approvePatch(patchId, PatchApprovalRequest(decision = "APPROVED", notes = notes)) }

    suspend fun rejectPatch(patchId: String, reason: String? = null): NetworkResult<RemediationPatchResponse> =
        safeApiCall { api.rejectPatch(patchId, PatchApprovalRequest(decision = "REJECTED", notes = reason)) }

    suspend fun applyPatch(patchId: String): NetworkResult<RemediationPatchResponse> =
        safeApiCall { api.applyPatch(patchId) }

    suspend fun verifyRemediation(remediationId: String): NetworkResult<VerificationResultResponse> =
        safeApiCall { api.verifyRemediation(remediationId) }

    suspend fun rollbackRemediation(remediationId: String): NetworkResult<RemediationResponse> =
        safeApiCall { api.rollbackRemediation(remediationId) }

    // Reports
    suspend fun getScanReport(scanId: String): NetworkResult<ScanReportResponse> =
        safeApiCall { api.getScanReport(scanId) }

    suspend fun downloadScanCsv(scanId: String): NetworkResult<ResponseBody> =
        safeApiCall { api.downloadScanCsv(scanId) }
}
