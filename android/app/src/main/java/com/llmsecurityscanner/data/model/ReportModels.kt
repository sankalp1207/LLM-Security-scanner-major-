package com.llmsecurityscanner.data.model

import com.google.gson.annotations.SerializedName

data class ScanReportResponse(
    @SerializedName("scan_id") val scanId: String,
    @SerializedName("project_name") val projectName: String? = null,
    @SerializedName("scan_preset") val scanPreset: String? = null,
    @SerializedName("status") val status: String,
    @SerializedName("generated_at") val generatedAt: String? = null,
    @SerializedName("summary") val summary: ScanSummary? = null,
    @SerializedName("findings") val findings: List<FindingResponse> = emptyList(),
    @SerializedName("recommendations") val recommendations: List<String> = emptyList()
)
