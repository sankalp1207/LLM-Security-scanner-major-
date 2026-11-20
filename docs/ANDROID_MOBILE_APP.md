# LLM Security Scanner — Android Mobile Application Guide

## 1. Overview & Architecture

The **LLM Security Scanner Android Client** is a commercial-grade, cybersecurity-themed mobile application built specifically for Android phones and tablets. It communicates directly with the existing FastAPI backend (`/api/v1`) to deliver full security operations, live scan monitoring, AI Copilot analysis, and verified vulnerability remediation on mobile devices.

### Architecture Highlights
- **Tech Stack**: Kotlin, Jetpack Compose, Material 3, MVVM Architecture, StateFlow.
- **Networking**: Centralized Retrofit client, OkHttp, Gson converters, and Server-Sent Events (SSE) `EventSource` for real-time live telemetry streaming (`/api/v1/scans/{id}/live`).
- **Persistence & Caching**: Offline-first Room Database (`projects`, `scans`, `findings`).
- **Security & Keystore**: Android Keystore backed `EncryptedSharedPreferences` (AES-256-GCM) storing enterprise JWT Bearer tokens and developer credentials safely without plaintext leaks.
- **Theme**: Dark cybersecurity SaaS design (Obsidian `#0B0F17`, Navy `#111827`, Neon Cyan `#06B6D4`, Copilot Purple `#8B5CF6`, with bright severity indicators for Critical `#EF4444`, High `#F97316`, Medium `#F59E0B`, Low `#10B981`).

---

## 2. Directory Structure

```
android/
├── build.gradle.kts                          # Root build script with Kotlin 2.0.21 & AGP 8.7.3
├── settings.gradle.kts                       # Repository management and module include
├── gradle.properties                         # JVM memory and AndroidX flags
├── gradlew, gradlew.bat                      # Gradle wrapper execution scripts
├── gradle/wrapper/gradle-wrapper.properties  # Gradle 8.11.1 distribution
└── app/
    ├── build.gradle.kts                      # Compose, Retrofit, Room, Keystore dependencies
    ├── proguard-rules.pro                    # Obfuscation and keep rules for DTOs and Room
    └── src/main/
        ├── AndroidManifest.xml               # INTERNET, ACCESS_NETWORK_STATE permissions
        ├── res/
        │   ├── values/ (colors.xml, strings.xml, themes.xml)
        │   └── xml/network_security_config.xml # Cleartext traffic enabled for local dev (10.0.2.2 & LAN)
        └── java/com/llmsecurityscanner/
            ├── LLMSecurityApp.kt             # Application class initializing Room and Retrofit
            ├── MainActivity.kt               # Root ComponentActivity with BottomNavBar & NavGraph
            ├── data/
            │   ├── api/ (ScannerApiService, AuthInterceptor, NetworkResult, SseClient)
            │   ├── local/ (AppDatabase, DAOs, Room Entities)
            │   ├── model/ (Project, Scan, Finding, Copilot, Remediation, Report DTOs)
            │   ├── repository/ (ScannerRepository)
            │   └── security/ (SecureTokenStorage via EncryptedSharedPreferences)
            ├── domain/model/ (Enums: Severity, ScanStatus, PresetType)
            └── presentation/
                ├── components/ (CyberCard, SeverityBadge, StatusBadge, MetricCard, UnifiedDiffViewer, LiveTerminalLog)
                ├── copilot/ (CopilotViewModel, CopilotScreen)
                ├── dashboard/ (DashboardViewModel, DashboardScreen)
                ├── findings/ (FindingsViewModel, FindingsScreen, FindingDetailScreen)
                ├── navigation/ (Screen, NavGraph, BottomNavBar)
                ├── projects/ (ProjectsViewModel, ProjectsScreen, ProjectDetailScreen)
                ├── remediation/ (RemediationViewModel, RemediationScreen)
                ├── reports/ (ReportsViewModel, ReportsScreen)
                ├── scanner/ (ScannerViewModel, ScannerScreen, LiveMonitorScreen)
                ├── settings/ (SettingsViewModel, SettingsScreen)
                └── theme/ (Color, Theme, Type)
```

---

## 3. Building the APK

### Prerequisites
1. **JDK 17 or 21**: Make sure `JAVA_HOME` points to your JDK installation (e.g. `set JAVA_HOME=C:\Program Files\Microsoft\jdk-17.0.x`).
2. **Android SDK Platform 35**: Available via Android Studio or command-line tools (`sdkmanager "platforms;android-35" "build-tools;35.0.0"`).

### Debug APK Build Command
From the project root:
```cmd
cd android
.\gradlew.bat assembleDebug
```

On Linux or macOS:
```bash
cd android
./gradlew assembleDebug
```

### Generated APK Output Path
The debug APK is generated at:
```
android/app/build/outputs/apk/debug/app-debug.apk
```

### Release Build Configuration
To build an optimized release APK:
```cmd
.\gradlew.bat assembleRelease
```
*Note: Release builds have R8 shrinking and code obfuscation enabled (`isMinifyEnabled = true`). Production signing requires configuring your keystore credentials via environment variables or `gradle.properties`.*

---

## 4. Connecting the Android App to the FastAPI Backend

### A. Android Emulator Setup (Localhost)
Android emulators access the host machine's `localhost` via the special loopback IP `10.0.2.2`.
1. Start the FastAPI backend on the host:
   ```powershell
   .venv\Scripts\uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
2. The mobile app defaults to `http://10.0.2.2:8000/`.
3. In the app, navigate to **Settings** (top-right cog) and tap **Ping Health** to verify connectivity.

### B. Physical Android Device Setup (Same Wi-Fi Network)
To run on a real smartphone without cables:
1. Ensure both your computer and Android phone are connected to the same Wi-Fi network.
2. Find your computer's local IP address:
   ```cmd
   ipconfig
   ```
   *(Look for `IPv4 Address`, e.g., `192.168.1.100`)*
3. Ensure FastAPI listens on all interfaces:
   ```powershell
   .venv\Scripts\uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
4. On your Android phone, open the **LLM Security Scanner** app.
5. Tap **Settings** (gear icon on the top right of the Dashboard).
6. Under **Backend Server Configuration**, replace the URL with:
   ```
   http://192.168.1.100:8000/
   ```
7. Tap **Ping Health**. When the badge shows green ("Connected successfully"), your phone is communicating directly with your local LLM Security Scanner server.

### C. Installing the APK via ADB
Connect your phone with USB debugging enabled, then execute:
```cmd
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

---

## 5. Mobile Capabilities & Screen Guide

1. **Operations Dashboard**:
   - Executive cybersecurity KPIs: Total Scans, Total Findings, Critical, High, Medium, Low severity breakdown.
   - Recent scans feed with status indicators.
   - One-tap quick launch for security assessments.
2. **Project & Target Management**:
   - Register target AI applications (Custom HTTP endpoints, Ollama, LangChain, RAG systems).
   - "Ping Target" connection diagnostic tool to measure latency.
   - Capability inspector showing enabled attack modules.
3. **Security Scanner & Presets**:
   - Three canonical presets: **Quick Scan** (15 tests), **Full Scan** (60 tests), and **Deep Red Team** (adaptive fuzzing).
   - Authorization switch gate before initiating deep red-team attacks.
4. **Real-Time Live Scan Monitor**:
   - Streams live scan telemetry over OkHttp Server-Sent Events (SSE).
   - Live percentage progress bar and real-time terminal log viewer.
   - Finding counter and remote scan cancellation.
5. **Vulnerability Findings & Triage**:
   - Filter findings by severity (Critical, High, Medium, Low) and instant search.
   - View exploit payloads, target responses, and evidence.
   - One-click live retest button to verify if vulnerabilities have been patched.
6. **AI Security Copilot**:
   - Multi-turn conversational AI security assistant grounded in scan telemetry.
   - One-tap suggestion chips for instant analysis.
7. **Automated Remediation Assistant**:
   - Review proposed code fixes with a syntax-highlighted **Unified Diff Viewer** (`+` green additions, `-` red deletions).
   - Human approval gate: Explicit **Approve** and **Reject** controls.
   - Apply patch directly to authorized workspace, execute verification tests, and trigger instant rollback.
8. **Audit Reports & Android Sharing**:
   - Structured audit summary with executive recommendations.
   - One-tap CSV export integrated with the native Android Share Sheet (`Intent.ACTION_SEND`).
9. **Settings & Keystore Security**:
   - Seamlessly switch between Emulator (`10.0.2.2`), Local LAN IP, or Production HTTPS.
   - Secure Bearer JWT token storage using Android Keystore AES-256-GCM.
   - Developer identity toggle (`X-User-ID`).
