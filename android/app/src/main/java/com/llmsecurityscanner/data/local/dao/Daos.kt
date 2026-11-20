package com.llmsecurityscanner.data.local.dao

import androidx.room.*
import com.llmsecurityscanner.data.local.entity.FindingEntity
import com.llmsecurityscanner.data.local.entity.ProjectEntity
import com.llmsecurityscanner.data.local.entity.ScanEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ProjectDao {
    @Query("SELECT * FROM projects ORDER BY createdAt DESC")
    fun getAllProjects(): Flow<List<ProjectEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertProjects(projects: List<ProjectEntity>)

    @Query("DELETE FROM projects WHERE id = :id")
    suspend fun deleteProjectById(id: String)
}

@Dao
interface ScanDao {
    @Query("SELECT * FROM scans ORDER BY startedAt DESC")
    fun getAllScans(): Flow<List<ScanEntity>>

    @Query("SELECT * FROM scans WHERE id = :id LIMIT 1")
    suspend fun getScanById(id: String): ScanEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScans(scans: List<ScanEntity>)
}

@Dao
interface FindingDao {
    @Query("SELECT * FROM findings ORDER BY createdAt DESC")
    fun getAllFindings(): Flow<List<FindingEntity>>

    @Query("SELECT * FROM findings WHERE severity = :severity")
    fun getFindingsBySeverity(severity: String): Flow<List<FindingEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFindings(findings: List<FindingEntity>)
}
