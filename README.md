# TRAE Guardian

**Advanced Endpoint Detection & Response (EDR) + Antivirus (AV) Security Platform**

A comprehensive terminal security protection platform built on Qt framework, integrating EDR+AV capabilities with AI-powered risk analysis.

## 🌟 Features

### Core Security Capabilities
- **Process Management**: View, terminate (tree kill), and repeated kill of malicious processes
- **Malicious Behavior Detection**: Physical disk access interception, MBR protection, registry monitoring
- **Network Audit**: TCP/UDP connection logging, DNS resolution auditing
- **File Static Analysis**: PE header analysis, entropy detection, signature verification

### AI-Powered Analysis
- **Multi-dimensional Risk Scoring**: Dynamic scoring system with time decay
- **Rule Engine**: Configurable rules for threat detection
- **State Machine**: 6-state process management (Untrusted → Observed → Suspicious → Restricted → Quarantined → Removed)
- **AI Risk Evaluation**: DeepSeek-R1-0528-Qwen3-8B model integration via SiliconFlow API

### Protection Mechanisms
- **Self-Protection**: GUI/Daemon mutual protection, file protection
- **MBR/GPT Protection**: Automatic backup and restoration of boot sectors
- **Registry Protection**: Monitor and block critical registry modifications
- **Watchdog Group Termination**: Simultaneous termination of mutually-protected malware processes

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Qt Visualization GUI                     │
│  trae_guardian_qt.exe                                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Core Modules Layer                            │
│  Configuration | Log Center(SQLite) | AI Score Center      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Detection Engine Layer                         │
│  ETW Monitoring | Handle Scanning | MBR Protection         │
│  Registry Protection | File Scanning | Network Audit       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Response & Rule Engine                         │
│  Graded Response(8 levels) | State Machine(6 states)       │
│  Configurable Rule Engine | AI Risk Evaluation             │
└─────────────────────────────────────────────────────────────┘
```

## 🤖 AI Integration

TRAE Guardian integrates AI capabilities through the **SiliconFlow API**:

### AI Components
- **ai_client.dll**: WinHTTP-based API client for OpenAI-compatible endpoints
- **ai_action.dll**: AI action execution module
- **ai_web_search.dll**: AI-powered web search for threat intelligence

### AI Model
- **Model**: DeepSeek-R1-0528-Qwen3-8B
- **Endpoint**: SiliconFlow Cloud API
- **Key Management**: XOR-encrypted API key storage

### AI Functions
1. **Risk Evaluation**: `AiEvaluateSingleProcess()` - Analyze process behavior and assign risk scores
2. **Behavior Analysis**: Long-term monitoring of suspicious process patterns
3. **Threat Intelligence**: Enhanced detection through AI-powered pattern recognition

### AI Constraints
- AI provides **indirect influence** only - it adds AI scores to the risk assessment
- AI does not directly execute termination commands
- AI only monitors ETW logs and provides analysis
- Virus detection and termination are handled autonomously by the algorithmic engine

## 🛡️ Threat Detection

### Key Detection Rules
| Rule | Description | Score |
|------|-------------|-------|
| **R001** | Physical disk access (PhysicalDrive/Harddisk) | 35 |
| **R006** | SYSTEM registry modifications | 10 |
| **R007a** | Run key write | 35 |
| **R010** | Process spawn monitoring | 0 (observation) |

### Response Thresholds
- **Observation**: 0 points
- **Suspicious**: 30 points
- **Restricted**: 50 points
- **Rogue Software**: 60 points (display in UI)
- **Quarantine/Terminate**: 70 points

## 📁 Project Structure

```
Process Guardian/
├── bin/                    # Release binaries
│   ├── trae_guardian_daemon.exe     # Core daemon (SYSTEM privileges)
│   ├── trae_guardian_qt.exe         # Qt GUI
│   ├── trae_guardian_service_wrapper.exe  # Service wrapper
│   ├── popup_notifier.exe           # Alert popup
│   └── observer.exe                 # Observer module
├── daemon_core.c/h         # Daemon core logic
├── etw_monitor.c/h         # ETW kernel event monitoring
├── thread_modules.c/h      # Background thread modules
├── state_machine.c/h       # Process state machine
├── rule_engine.c/h         # Configurable rule engine
├── score_center.c/h        # Risk scoring system
├── response_center.c/h     # Response management
├── pe_analysis.c/h         # PE file analysis
├── ai_client.c/h           # AI API client
└── qt_gui/                 # Qt6 GUI components
```

## 🚀 Quick Start

### Requirements
- Windows 10 1809 or later
- Administrator privileges
- Qt6 runtime libraries
- MinGW runtime libraries

### Installation
1. Download and extract the release package
2. Run `install_service.exe` to install the daemon as a Windows service
3. Run `trae_guardian_qt.exe` for the GUI interface

### Manual Start
```cmd
# Start daemon (requires admin)
trae_guardian_daemon.exe

# Start GUI
trae_guardian_qt.exe
```

## 🔧 Technical Details

### Security Architecture
- **Daemon**: Runs with SYSTEM privileges as Windows Service
- **GUI**: Runs with user privileges, communicates with daemon
- **Protection**: Critical system processes are hardcoded and unconditionally protected
- **Signature Verification**: Signed processes are handled by rogue software detection, not terminated

### Monitoring Technologies
- **ETW (Event Tracing for Windows)**: Kernel-level event monitoring
- **NtQuerySystemInformation**: Handle scanning for sensitive operations
- **Toolhelp32**: Process enumeration as fallback

### Response Actions
1. Alert only
2. Add to observation list
3. Restrict process activities
4. Quarantine process
5. Terminate process
6. Repeated termination (watchdog defense)
7. File deletion
8. Group termination (mutually-protected processes)

## 📊 Test Results

### Rainbow Cat (MEMZ) Detection
- ✅ **Detection**: Process terminated immediately upon execution
- ✅ **MBR Protection**: Boot sector restored automatically
- ✅ **Watchdog Defense**: No process restart detected
- ✅ **No False Positives**: VMware Tools and system processes correctly skipped

### Watchdog Mutual Protection
- ✅ **Group Termination**: All 4 processes terminated simultaneously
- ✅ **No Race Condition**: No watchdog restart during termination
- ✅ **Complete Removal**: Process executable files deleted

## 📝 License

This project is for educational and research purposes only.

## 🔗 Links

- [Project Website](https://github.com/BaikerrNO1/TRAE-Guardian)
- [Download Latest Release](https://github.com/BaikerrNO1/TRAE-Guardian/releases)
