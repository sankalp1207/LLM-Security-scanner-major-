package com.llmsecurityscanner.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.llmsecurityscanner.data.local.dao.FindingDao
import com.llmsecurityscanner.data.local.dao.ProjectDao
import com.llmsecurityscanner.data.local.dao.ScanDao
import com.llmsecurityscanner.data.local.entity.FindingEntity
import com.llmsecurityscanner.data.local.entity.ProjectEntity
import com.llmsecurityscanner.data.local.entity.ScanEntity

@Database(
    entities = [ProjectEntity::class, ScanEntity::class, FindingEntity::class],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun projectDao(): ProjectDao
    abstract fun scanDao(): ScanDao
    abstract fun findingDao(): FindingDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "llm_security_database"
                ).fallbackToDestructiveMigration().build()
                INSTANCE = instance
                instance
            }
        }
    }
}
