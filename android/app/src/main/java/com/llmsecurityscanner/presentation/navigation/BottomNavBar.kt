package com.llmsecurityscanner.presentation.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavController
import androidx.navigation.compose.currentBackStackEntryAsState
import com.llmsecurityscanner.presentation.theme.*

data class BottomNavItem(
    val screen: Screen,
    val icon: ImageVector,
    val label: String
)

@Composable
fun BottomNavBar(navController: NavController) {
    val items = listOf(
        BottomNavItem(Screen.Dashboard, Icons.Default.Dashboard, "Dashboard"),
        BottomNavItem(Screen.Projects, Icons.Default.Folder, "Projects"),
        BottomNavItem(Screen.Scanner, Icons.Default.Security, "Scan"),
        BottomNavItem(Screen.Findings, Icons.Default.Warning, "Findings"),
        BottomNavItem(Screen.Copilot, Icons.Default.SmartToy, "Copilot")
    )

    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    NavigationBar(
        containerColor = CyberSurface,
        contentColor = TextPrimary
    ) {
        items.forEach { item ->
            val isSelected = currentRoute == item.screen.route
            NavigationBarItem(
                icon = { Icon(item.icon, contentDescription = item.label) },
                label = { Text(item.label) },
                selected = isSelected,
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = CyberCyan,
                    selectedTextColor = CyberCyan,
                    indicatorColor = CyberSurfaceCard,
                    unselectedIconColor = TextMuted,
                    unselectedTextColor = TextMuted
                ),
                onClick = {
                    if (currentRoute != item.screen.route) {
                        navController.navigate(item.screen.route) {
                            popUpTo(Screen.Dashboard.route) { saveState = true }
                            launchSingleTop = true
                            restoreState = true
                        }
                    }
                }
            )
        }
    }
}
