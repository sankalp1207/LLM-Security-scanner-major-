package com.llmsecurityscanner.data.model

import com.google.gson.annotations.SerializedName

data class CopilotConversationResponse(
    @SerializedName("id") val id: String,
    @SerializedName("project_id") val projectId: String? = null,
    @SerializedName("title") val title: String,
    @SerializedName("created_at") val createdAt: String? = null,
    @SerializedName("updated_at") val updatedAt: String? = null
)

data class CopilotMessageResponse(
    @SerializedName("id") val id: String,
    @SerializedName("conversation_id") val conversationId: String,
    @SerializedName("role") val role: String,
    @SerializedName("content") val content: String,
    @SerializedName("created_at") val createdAt: String? = null,
    @SerializedName("context_data") val contextData: Map<String, Any?>? = null
)

data class CopilotMessageRequest(
    @SerializedName("content") val content: String,
    @SerializedName("project_id") val projectId: String? = null,
    @SerializedName("finding_id") val findingId: String? = null,
    @SerializedName("scan_id") val scanId: String? = null
)

data class CopilotFindingExplanationResponse(
    @SerializedName("finding_id") val findingId: String,
    @SerializedName("explanation") val explanation: String,
    @SerializedName("remediation_advice") val remediationAdvice: String? = null
)
