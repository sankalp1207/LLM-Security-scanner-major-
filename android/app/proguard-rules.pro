-keepattributes *Annotation*
-dontwarn javax.annotation.**
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keep class com.llmsecurityscanner.data.model.** { *; }
-keep class androidx.room.** { *; }
