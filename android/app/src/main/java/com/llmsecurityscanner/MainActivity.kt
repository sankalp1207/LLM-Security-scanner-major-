package com.llmsecurityscanner

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Scaffold
import androidx.navigation.compose.rememberNavController
import com.llmsecurityscanner.presentation.navigation.BottomNavBar
import com.llmsecurityscanner.presentation.navigation.NavGraph
import com.llmsecurityscanner.presentation.theme.CyberBg
import com.llmsecurityscanner.presentation.theme.LLMSecurityTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = application as LLMSecurityApp

        setContent {
            LLMSecurityTheme {
                val navController = rememberNavController()

                Scaffold(
                    containerColor = CyberBg,
                    bottomBar = {
                        BottomNavBar(navController = navController)
                    }
                ) { paddingValues ->
                    NavGraph(
                        navController = navController,
                        app = app,
                        paddingValues = paddingValues
                    )
                }
            }
        }
    }
}
