package com.llmsecurityscanner.data.model

import com.google.gson.annotations.SerializedName

data class ProjectResponse(
    @SerializedName("id") val id: String,
    @SerializedName("name") val name: String,
    @SerializedName("description") val description: String? = null,
    @SerializedName("application_type") val applicationType: String? = "custom_llm",
    @SerializedName("environment") val environment: String? = "development",
    @SerializedName("target_type") val targetType: String? = "custom_http",
    @SerializedName("target_url") val targetUrl: String? = null,
    @SerializedName("created_at") val createdAt: String? = null,
    @SerializedName("updated_at") val updatedAt: String? = null
)

data class ProjectListResponse(
    @SerializedName("total") val total: Int,
    @SerializedName("items") val items: List<ProjectResponse>
)

data class ProjectCreateRequest(
    @SerializedName("name") val name: String,
    @SerializedName("description") val description: String? = null,
    @SerializedName("application_type") val applicationType: String = "custom_llm",
    @SerializedName("environment") val environment: String = "development",
    @SerializedName("target_type") val targetType: String = "custom_http",
    @SerializedName("target_url") val targetUrl: String? = null
)

data class TargetVerificationResponse(
    @SerializedName("status") val status: String,
    @SerializedName("reachable") val reachable: Boolean,
    @SerializedName("latency_ms") val latencyMs: Double? = null,
    @SerializedName("message") val message: String? = null
)

data class ScanCapabilitiesResponse(
    @SerializedName("project_id") val projectId: String,
    @SerializedName("target_type") val targetType: String,
    @SerializedName("supported_categories") val supportedCategories: List<String> = emptyList(),
    @SerializedName("capabilities") val capabilities: Map<String, Boolean> = emptyMap()
)
