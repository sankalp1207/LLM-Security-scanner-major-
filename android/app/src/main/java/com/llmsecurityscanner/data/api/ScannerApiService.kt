package com.llmsecurityscanner.data.api

import com.llmsecurityscanner.data.model.*
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.*

interface ScannerApiService {

    // Health
    @GET("api/v1/health")
    suspend fun getHealth(): Response<Map<String, Any>>

    // Presets
    @GET("api/v1/scans/presets")
    suspend fun getPresets(): Response<ScanPresetsListResponse>

    // Projects
    @GET("api/v1/projects")
    suspend fun getProjects(
        @Query("skip") skip: Int = 0,
        @Query("limit") limit: Int = 50
    ): Response<ProjectListResponse>

    @POST("api/v1/projects")
    suspend fun createProject(@Body request: ProjectCreateRequest): Response<ProjectResponse>

    @GET("api/v1/projects/{id}")
    suspend fun getProject(@Path("id") id: String): Response<ProjectResponse>

    @DELETE("api/v1/projects/{id}")
    suspend fun deleteProject(@Path("id") id: String): Response<Map<String, Any>>

    @POST("api/v1/projects/{id}/verify-connection")
    suspend fun verifyProjectConnection(@Path("id") id: String): Response<TargetVerificationResponse>

    @GET("api/v1/projects/{id}/scan-capabilities")
    suspend fun getScanCapabilities(@Path("id") id: String): Response<ScanCapabilitiesResponse>

    // Scans
    @POST("api/v1/projects/{id}/scans")
    suspend fun launchProjectScan(
        @Path("id") projectId: String,
        @Body request: ProjectScanCreateRequest
    ): Response<ScanResponse>

    @GET("api/v1/scans")
    suspend fun getScans(
        @Query("skip") skip: Int = 0,
        @Query("limit") limit: Int = 50
    ): Response<ScanListResponse>

    @GET("api/v1/scans/{id}")
    suspend fun getScan(@Path("id") scanId: String): Response<ScanResponse>

    @POST("api/v1/scans/{id}/cancel")
    suspend fun cancelScan(@Path("id") scanId: String): Response<ScanResponse>

    @GET("api/v1/scans/{id}/progress")
    suspend fun getScanProgress(@Path("id") scanId: String): Response<ScanProgressResponse>

    @GET("api/v1/scans/{id}/events")
    suspend fun getScanEvents(
        @Path("id") scanId: String,
        @Query("since_seq") sinceSeq: Int = 0,
        @Query("limit") limit: Int = 100
    ): Response<ScanEventsListResponse>

    // Findings
    @GET("api/v1/findings")
    suspend fun getFindings(
        @Query("skip") skip: Int = 0,
        @Query("limit") limit: Int = 100,
        @Query("severity") severity: String? = null,
        @Query("category") category: String? = null,
        @Query("retest_status") retestStatus: String? = null
    ): Response<FindingListResponse>

    @GET("api/v1/findings/{id}")
    suspend fun getFinding(@Path("id") id: String): Response<FindingResponse>

    @POST("api/v1/findings/{id}/retest")
    suspend fun retestFinding(@Path("id") id: String): Response<RetestResponse>

    // Copilot
    @POST("api/v1/copilot/conversations")
    suspend fun createCopilotConversation(@Body body: Map<String, String>): Response<CopilotConversationResponse>

    @GET("api/v1/copilot/conversations")
    suspend fun getCopilotConversations(): Response<List<CopilotConversationResponse>>

    @GET("api/v1/copilot/conversations/{id}/messages")
    suspend fun getCopilotMessages(@Path("id") conversationId: String): Response<List<CopilotMessageResponse>>

    @POST("api/v1/copilot/conversations/{id}/messages")
    suspend fun sendCopilotMessage(
        @Path("id") conversationId: String,
        @Body request: CopilotMessageRequest
    ): Response<CopilotMessageResponse>

    @POST("api/v1/copilot/explain-finding/{id}")
    suspend fun explainFinding(@Path("id") findingId: String): Response<CopilotFindingExplanationResponse>

    // Remediation
    @POST("api/v1/remediations/findings/{id}")
    suspend fun initRemediation(@Path("id") findingId: String): Response<RemediationResponse>

    @GET("api/v1/remediations/{id}")
    suspend fun getRemediation(@Path("id") remediationId: String): Response<RemediationResponse>

    @POST("api/v1/remediations/{id}/generate-fix")
    suspend fun generateFix(@Path("id") remediationId: String): Response<RemediationResponse>

    @POST("api/v1/remediations/patches/{id}/approve")
    suspend fun approvePatch(
        @Path("id") patchId: String,
        @Body request: PatchApprovalRequest = PatchApprovalRequest()
    ): Response<RemediationPatchResponse>

    @POST("api/v1/remediations/patches/{id}/reject")
    suspend fun rejectPatch(
        @Path("id") patchId: String,
        @Body request: PatchApprovalRequest = PatchApprovalRequest(decision = "REJECTED")
    ): Response<RemediationPatchResponse>

    @POST("api/v1/remediations/patches/{id}/apply")
    suspend fun applyPatch(@Path("id") patchId: String): Response<RemediationPatchResponse>

    @POST("api/v1/remediations/{id}/verify")
    suspend fun verifyRemediation(@Path("id") remediationId: String): Response<VerificationResultResponse>

    @POST("api/v1/remediations/{id}/rollback")
    suspend fun rollbackRemediation(@Path("id") remediationId: String): Response<RemediationResponse>

    // Reports
    @GET("api/v1/scans/{id}/report")
    suspend fun getScanReport(@Path("id") scanId: String): Response<ScanReportResponse>

    @GET("api/v1/scans/{id}/export.csv")
    @Streaming
    suspend fun downloadScanCsv(@Path("id") scanId: String): Response<ResponseBody>
}
