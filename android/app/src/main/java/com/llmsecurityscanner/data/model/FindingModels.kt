package com.llmsecurityscanner.data.model

import com.google.gson.annotations.SerializedName

data class FindingResponse(
    @SerializedName("id") val id: String,
    @SerializedName("scan_id") val scanId: String? = null,
    @SerializedName("project_id") val projectId: String? = null,
    @SerializedName("title") val title: String,
    @SerializedName("description") val description: String? = null,
    @SerializedName("severity") val severity: String,
    @SerializedName("category") val category: String,
    @SerializedName("affected_component") val affectedComponent: String? = null,
    @SerializedName("evidence") val evidence: Map<String, Any?>? = null,
    @SerializedName("recommendation") val recommendation: String? = null,
    @SerializedName("retest_status") val retestStatus: String? = "UNTESTED",
    @SerializedName("retested_at") val retestedAt: String? = null,
    @SerializedName("created_at") val createdAt: String? = null
)

data class FindingListResponse(
    @SerializedName("total") val total: Int,
    @SerializedName("items") val items: List<FindingResponse>
)

data class RetestResponse(
    @SerializedName("finding_id") val findingId: String,
    @SerializedName("retest_status") val retestStatus: String,
    @SerializedName("passed") val passed: Boolean,
    @SerializedName("details") val details: String? = null,
    @SerializedName("timestamp") val timestamp: String? = null
)
