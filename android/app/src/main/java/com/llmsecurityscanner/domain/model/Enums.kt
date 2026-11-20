package com.llmsecurityscanner.domain.model

enum class Severity(val label: String, val level: Int) {
    CRITICAL("CRITICAL", 4),
    HIGH("HIGH", 3),
    MEDIUM("MEDIUM", 2),
    LOW("LOW", 1),
    INFORMATIONAL("INFORMATIONAL", 0);

    companion object {
        fun fromString(value: String?): Severity {
            return when (value?.uppercase()?.trim()) {
                "CRITICAL" -> CRITICAL
                "HIGH" -> HIGH
                "MEDIUM" -> MEDIUM
                "LOW" -> LOW
                else -> INFORMATIONAL
            }
        }
    }
}

enum class ScanStatus(val label: String) {
    PENDING("PENDING"),
    RUNNING("RUNNING"),
    COMPLETED("COMPLETED"),
    FAILED("FAILED"),
    CANCELLED("CANCELLED");

    companion object {
        fun fromString(value: String?): ScanStatus {
            return when (value?.uppercase()?.trim()) {
                "PENDING" -> PENDING
                "RUNNING" -> RUNNING
                "COMPLETED" -> COMPLETED
                "FAILED" -> FAILED
                "CANCELLED" -> CANCELLED
                else -> PENDING
            }
        }
    }
}

enum class PresetType(val id: String, val displayName: String) {
    QUICK_SCAN("quick_scan", "Quick Scan"),
    FULL_SCAN("full_scan", "Full Scan"),
    DEEP_RED_TEAM("deep_red_team", "Deep Red Team");

    companion object {
        fun fromId(id: String?): PresetType {
            return when (id?.lowercase()?.trim()) {
                "quick_scan" -> QUICK_SCAN
                "full_scan" -> FULL_SCAN
                "deep_red_team" -> DEEP_RED_TEAM
                else -> QUICK_SCAN
            }
        }
    }
}
