package com.llmsecurityscanner.presentation.navigation

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.llmsecurityscanner.LLMSecurityApp
import com.llmsecurityscanner.presentation.copilot.CopilotScreen
import com.llmsecurityscanner.presentation.copilot.CopilotViewModel
import com.llmsecurityscanner.presentation.dashboard.DashboardScreen
import com.llmsecurityscanner.presentation.dashboard.DashboardViewModel
import com.llmsecurityscanner.presentation.findings.FindingDetailScreen
import com.llmsecurityscanner.presentation.findings.FindingsScreen
import com.llmsecurityscanner.presentation.findings.FindingsViewModel
import com.llmsecurityscanner.presentation.projects.ProjectDetailScreen
import com.llmsecurityscanner.presentation.projects.ProjectsScreen
import com.llmsecurityscanner.presentation.projects.ProjectsViewModel
import com.llmsecurityscanner.presentation.remediation.RemediationScreen
import com.llmsecurityscanner.presentation.remediation.RemediationViewModel
import com.llmsecurityscanner.presentation.reports.ReportsScreen
import com.llmsecurityscanner.presentation.reports.ReportsViewModel
import com.llmsecurityscanner.presentation.scanner.LiveMonitorScreen
import com.llmsecurityscanner.presentation.scanner.ScannerScreen
import com.llmsecurityscanner.presentation.scanner.ScannerViewModel
import com.llmsecurityscanner.presentation.settings.SettingsScreen
import com.llmsecurityscanner.presentation.settings.SettingsViewModel

@Composable
fun NavGraph(
    navController: NavHostController,
    app: LLMSecurityApp,
    paddingValues: PaddingValues
) {
    NavHost(
        navController = navController,
        startDestination = Screen.Dashboard.route,
        modifier = Modifier.padding(paddingValues)
    ) {
        // Dashboard
        composable(Screen.Dashboard.route) {
            val vm: DashboardViewModel = viewModel(factory = DashboardViewModel.Factory(app.repository))
            DashboardScreen(
                viewModel = vm,
                onNavigateToScan = { navController.navigate(Screen.Scanner.route) },
                onNavigateToLiveScan = { scanId -> navController.navigate(Screen.LiveMonitor.createRoute(scanId)) },
                onNavigateToSettings = { navController.navigate(Screen.Settings.route) }
            )
        }

        // Projects
        composable(Screen.Projects.route) {
            val vm: ProjectsViewModel = viewModel(factory = ProjectsViewModel.Factory(app.repository))
            ProjectsScreen(
                viewModel = vm,
                onProjectSelected = { projectId -> navController.navigate(Screen.ProjectDetail.createRoute(projectId)) }
            )
        }

        composable(
            route = Screen.ProjectDetail.route,
            arguments = listOf(navArgument("projectId") { type = NavType.StringType })
        ) { backStackEntry ->
            val projectId = backStackEntry.arguments?.getString("projectId") ?: ""
            val vm: ProjectsViewModel = viewModel(factory = ProjectsViewModel.Factory(app.repository))
            ProjectDetailScreen(
                projectId = projectId,
                viewModel = vm,
                onBack = { navController.popBackStack() },
                onStartScan = { _ -> navController.navigate(Screen.Scanner.route) }
            )
        }

        // Scanner
        composable(Screen.Scanner.route) {
            val vm: ScannerViewModel = viewModel(factory = ScannerViewModel.Factory(app.repository))
            ScannerScreen(
                viewModel = vm,
                onNavigateToLiveScan = { scanId -> navController.navigate(Screen.LiveMonitor.createRoute(scanId)) }
            )
        }

        composable(
            route = Screen.LiveMonitor.route,
            arguments = listOf(navArgument("scanId") { type = NavType.StringType })
        ) { backStackEntry ->
            val scanId = backStackEntry.arguments?.getString("scanId") ?: ""
            val vm: ScannerViewModel = viewModel(factory = ScannerViewModel.Factory(app.repository))
            LiveMonitorScreen(
                scanId = scanId,
                viewModel = vm,
                onBack = { navController.popBackStack() },
                onViewReport = { id -> navController.navigate(Screen.Reports.createRoute(id)) }
            )
        }

        // Findings
        composable(Screen.Findings.route) {
            val vm: FindingsViewModel = viewModel(factory = FindingsViewModel.Factory(app.repository))
            FindingsScreen(
                viewModel = vm,
                onFindingSelected = { findingId -> navController.navigate(Screen.FindingDetail.createRoute(findingId)) }
            )
        }

        composable(
            route = Screen.FindingDetail.route,
            arguments = listOf(navArgument("findingId") { type = NavType.StringType })
        ) { backStackEntry ->
            val findingId = backStackEntry.arguments?.getString("findingId") ?: ""
            val vm: FindingsViewModel = viewModel(factory = FindingsViewModel.Factory(app.repository))
            FindingDetailScreen(
                findingId = findingId,
                viewModel = vm,
                onBack = { navController.popBackStack() },
                onStartRemediation = { id -> navController.navigate(Screen.Remediation.createRoute(id)) }
            )
        }

        // Copilot
        composable(Screen.Copilot.route) {
            val vm: CopilotViewModel = viewModel(factory = CopilotViewModel.Factory(app.repository))
            CopilotScreen(viewModel = vm)
        }

        // Remediation
        composable(
            route = Screen.Remediation.route,
            arguments = listOf(navArgument("findingId") { type = NavType.StringType })
        ) { backStackEntry ->
            val findingId = backStackEntry.arguments?.getString("findingId") ?: ""
            val vm: RemediationViewModel = viewModel(factory = RemediationViewModel.Factory(app.repository))
            RemediationScreen(
                findingId = findingId,
                viewModel = vm,
                onBack = { navController.popBackStack() }
            )
        }

        // Reports
        composable(
            route = Screen.Reports.route,
            arguments = listOf(navArgument("scanId") { type = NavType.StringType })
        ) { backStackEntry ->
            val scanId = backStackEntry.arguments?.getString("scanId") ?: ""
            val vm: ReportsViewModel = viewModel(factory = ReportsViewModel.Factory(app.repository))
            ReportsScreen(
                scanId = scanId,
                viewModel = vm,
                onBack = { navController.popBackStack() }
            )
        }

        // Settings
        composable(Screen.Settings.route) {
            val vm: SettingsViewModel = viewModel(factory = SettingsViewModel.Factory(app.repository, app))
            SettingsScreen(
                viewModel = vm,
                onBack = { navController.popBackStack() }
            )
        }
    }
}
