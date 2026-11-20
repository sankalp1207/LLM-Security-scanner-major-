package com.llmsecurityscanner.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "projects")
data class ProjectEntity(
    @PrimaryKey val id: String,
    val name: String,
    val description: String?,
    val applicationType: String?,
    val environment: String?,
    val targetType: String?,
    val targetUrl: String?,
    val createdAt: String?
)

@Entity(tableName = "scans")
data class ScanEntity(
    @PrimaryKey val id: String,
    val projectId: String?,
    val status: String,
    val preset: String?,
    val progressPct: Double,
    val startedAt: String?,
    val completedAt: String?,
    val vulnerabilitiesFound: Int,
    val criticalSeverity: Int,
    val highSeverity: Int
)

@Entity(tableName = "findings")
data class FindingEntity(
    @PrimaryKey val id: String,
    val scanId: String?,
    val projectId: String?,
    val title: String,
    val description: String?,
    val severity: String,
    val category: String,
    val affectedComponent: String?,
    val retestStatus: String?,
    val createdAt: String?
)
