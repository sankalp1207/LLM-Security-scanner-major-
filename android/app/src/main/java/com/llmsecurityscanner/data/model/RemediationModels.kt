package com.llmsecurityscanner.data.model

import com.google.gson.annotations.SerializedName

data class RemediationPatchResponse(
    @SerializedName("id") val id: String,
    @SerializedName("remediation_id") val remediationId: String,
    @SerializedName("file_path") val filePath: String,
    @SerializedName("diff") val diff: String,
    @SerializedName("explanation") val explanation: String? = null,
    @SerializedName("status") val status: String? = "PROPOSED",
    @SerializedName("applied_at") val appliedAt: String? = null
)

data class RemediationResponse(
    @SerializedName("id") val id: String,
    @SerializedName("finding_id") val findingId: String,
    @SerializedName("status") val status: String,
    @SerializedName("suggested_fix") val suggestedFix: String? = null,
    @SerializedName("patches") val patches: List<RemediationPatchResponse> = emptyList(),
    @SerializedName("created_at") val createdAt: String? = null
)

data class PatchApprovalRequest(
    @SerializedName("decision") val decision: String = "APPROVED",
    @SerializedName("notes") val notes: String? = null
)

data class VerificationResultResponse(
    @SerializedName("remediation_id") val remediationId: String,
    @SerializedName("vulnerability_retested") val vulnerabilityRetested: Boolean,
    @SerializedName("vulnerability_fixed") val vulnerabilityFixed: Boolean,
    @SerializedName("unit_tests_passed") val unitTestsPassed: Boolean,
    @SerializedName("details") val details: String? = null
)
