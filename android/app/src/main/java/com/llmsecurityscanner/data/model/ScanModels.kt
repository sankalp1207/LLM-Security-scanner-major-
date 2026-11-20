package com.llmsecurityscanner.data.model

import com.google.gson.annotations.SerializedName

data class PresetResponse(
    @SerializedName("preset_id") val presetId: String,
    @SerializedName("name") val name: String,
    @SerializedName("description") val description: String,
    @SerializedName("enabled_categories") val enabledCategories: List<String> = emptyList(),
    @SerializedName("requires_authorization_ack") val requiresAuthorizationAck: Boolean = false,
    @SerializedName("max_tests_limit") val maxTestsLimit: Int = 50
)

data class ScanPresetsListResponse(
    @SerializedName("presets") val presets: List<PresetResponse>
)

data class ProjectScanCreateRequest(
    @SerializedName("preset") val preset: String,
    @SerializedName("external_target_authorized") val externalTargetAuthorized: Boolean = false,
    @SerializedName("sync_execute") val syncExecute: Boolean = false
)

data class ScanSummary(
    @SerializedName("total_tests") val totalTests: Int = 0,
    @SerializedName("passed_tests") val passedTests: Int = 0,
    @SerializedName("failed_tests") val failedTests: Int = 0,
    @SerializedName("vulnerabilities_found") val vulnerabilitiesFound: Int = 0,
    @SerializedName("critical_severity") val criticalSeverity: Int = 0,
    @SerializedName("high_severity") val highSeverity: Int = 0,
    @SerializedName("medium_severity") val mediumSeverity: Int = 0,
    @SerializedName("low_severity") val lowSeverity: Int = 0
)

data class ScanResponse(
    @SerializedName("id") val id: String,
    @SerializedName("project_id") val projectId: String? = null,
    @SerializedName("status") val status: String,
    @SerializedName("preset") val preset: String? = null,
    @SerializedName("progress_pct") val progressPct: Double = 0.0,
    @SerializedName("started_at") val startedAt: String? = null,
    @SerializedName("completed_at") val completedAt: String? = null,
    @SerializedName("summary") val summary: ScanSummary? = null,
    @SerializedName("failure_reason") val failureReason: String? = null
)

data class ScanListResponse(
    @SerializedName("total") val total: Int,
    @SerializedName("items") val items: List<ScanResponse>
)

data class ScanProgressResponse(
    @SerializedName("scan_id") val scanId: String,
    @SerializedName("status") val status: String,
    @SerializedName("progress_percentage") val progressPercentage: Double = 0.0,
    @SerializedName("total_tests") val totalTests: Int = 0,
    @SerializedName("completed_tests") val completedTests: Int = 0,
    @SerializedName("current_category") val currentCategory: String? = null,
    @SerializedName("latest_sequence") val latestSequence: Int = 0,
    @SerializedName("findings_count") val findingsCount: Int = 0,
    @SerializedName("severity_breakdown") val severityBreakdown: Map<String, Int> = emptyMap()
)

data class ScanEventResponse(
    @SerializedName("id") val id: String,
    @SerializedName("scan_id") val scanId: String,
    @SerializedName("sequence") val sequence: Int,
    @SerializedName("event_type") val eventType: String,
    @SerializedName("message") val message: String,
    @SerializedName("timestamp") val timestamp: String? = null,
    @SerializedName("payload") val payload: Map<String, Any?>? = null
)

data class ScanEventsListResponse(
    @SerializedName("scan_id") val scanId: String,
    @SerializedName("events") val events: List<ScanEventResponse>,
    @SerializedName("latest_seq") val latestSeq: Int = 0
)
