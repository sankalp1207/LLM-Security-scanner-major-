package com.llmsecurityscanner.presentation.navigation

sealed class Screen(val route: String, val title: String) {
    object Dashboard : Screen("dashboard", "Dashboard")
    object Projects : Screen("projects", "Projects")
    object ProjectDetail : Screen("project_detail/{projectId}", "Project Detail") {
        fun createRoute(projectId: String) = "project_detail/$projectId"
    }
    object Scanner : Screen("scanner", "Security Scanner")
    object LiveMonitor : Screen("live_monitor/{scanId}", "Live Monitor") {
        fun createRoute(scanId: String) = "live_monitor/$scanId"
    }
    object Findings : Screen("findings", "Findings")
    object FindingDetail : Screen("finding_detail/{findingId}", "Finding Detail") {
        fun createRoute(findingId: String) = "finding_detail/$findingId"
    }
    object Copilot : Screen("copilot", "AI Copilot")
    object Remediation : Screen("remediation/{findingId}", "Remediation") {
        fun createRoute(findingId: String) = "remediation/$findingId"
    }
    object Reports : Screen("reports/{scanId}", "Audit Report") {
        fun createRoute(scanId: String) = "reports/$scanId"
    }
    object Settings : Screen("settings", "Settings")
}
