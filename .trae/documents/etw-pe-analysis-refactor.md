# ETW驱动 + PE静态分析架构调整

## Context

当前守护进程有三条重叠的新进程检测路径：ETW事件驱动（`OnEtwProcStart`）、50ms轮询（`HandleScanThreadProc`）、硬编码测试程序检测（`QuickDetectThreadProc`）。其中低频扫描调用的 `ScanProcessHandles` 每次遍历全系统25万+句柄、分配4MB+缓冲区，内存占用大、延迟高。同时 `virus_signature.c` 已实现完整的Hash/字符串/导入表匹配功能和7种内置病毒特征，但 `VirusSignatureMatchImports` 从未被调用——`CheckPEForMaliciousImports` 仅检查固定的两个ntdll函数名，且RVA→文件偏移转换有bug（直接把VirtualAddress当文件偏移用）。

**目标**：去掉全局句柄扫描，改用ETW事件驱动检测新进程；新增PE静态分析模块让80%的已知病毒在进程启动瞬间就被删除；保留轻量级单进程句柄监控（5秒观察期）作为运行时行为后备。

## 实施步骤

### 步骤1：新建 pe_analysis.c / pe_analysis.h

**文件**：`pe_analysis.c`、`pe_analysis.h`（新建）

从 `thread_modules.c` 迁移并增强PE分析函数：

| 函数 | 来源 | 改动 |
|------|------|------|
| `PEComputeSHA256` | 迁移自 `ComputeSHA256Hash` (thread_modules.c:500) | 改为非static |
| `PERvaToFileOffset` | 新建 | 修复RVA→文件偏移bug，遍历节区表转换 |
| `PEExtractImports` | 新建 | 提取全部导入函数名为 `char[][128]` 数组，供 `VirusSignatureMatchImports` 使用 |
| `PEAnalyzeSections` | 新建 | 检测RWX可执行可写节区 |
| `PEAnalyzeFile` | 新建 | 统一入口：读文件到内存一次，完成Hash+节区+导入+字符串分析 |
| `PEQuickAnalyze` | 新建 | 便捷函数，返回 `PEThreatLevel` |

关键结构体 `PEAnalysisResult` 包含：`sha256[32]`、`importNames[256][128]`、`importCount`、`hasExecutableWritableSection`、`hasPhysicalDriveString`、`hasSuspiciousImports`、`fileData`指针（缓存文件数据避免多次IO）。

### 步骤2：改造 CoreModulesOnNewProcess

**文件**：`thread_modules.c:1384-1506`

改造现有 `CoreModulesOnNewProcess` 函数：

1. **替换** `CheckPEForMaliciousImports` + `CheckPEForPhysicalDriveString` + `ComputeSHA256Hash` 三个调用为统一的 `PEQuickAnalyze(imagePath, &result)`
2. **新增** Import匹配调用：`VirusSignatureMatchImports(&cm->vsdb, importPtrs, result.importCount)` —— 这是之前从未调用的关键功能
3. **提取** `ExecuteVirusResponse` 公共函数消除Hash匹配和String匹配中重复的终止/删除/恢复代码
4. 字符串匹配复用 `PEAnalyzeFile` 已缓存的 `fileData`，避免二次读文件

改造后的匹配顺序：Hash精确匹配 → Import表匹配（新增） → String特征匹配 → PE结构特征（RWX等）

### 步骤3：删除全局句柄扫描

**文件**：`thread_modules.c`

| 删除内容 | 行号 | 原因 |
|---------|------|------|
| `ScanProcessHandles` | 311-431 | 25万+全局句柄扫描，4MB+缓冲区 |
| `ScanSingleProcessHandles` | 433-498 | 仍查询全系统句柄再过滤PID |
| `GetCurrentProcessList` | 721-748 | 仅被轮询逻辑使用 |
| `HighSpeedScanThreadProc` | 876-891 | 内部只调用已删除的 `ScanProcessHandles` |
| `QuickDetectThreadProc` | 893-1027 | 硬编码test_threat名称，全量句柄查询 |

同时删除 `thread_modules.h` 中的 `hHighSpeedScanThread`、`hQuickDetectThread` 字段，以及 `CoreModulesStartThreads`/`CoreModulesStopThreads` 中创建/等待这些线程的代码。

### 步骤4：改造 HandleScanThreadProc 为轻量级监控

**文件**：`thread_modules.c:750-874`

改造为仅扫描PE分析标记为可疑进程的句柄：

1. **删除** 进程列表轮询逻辑（765-852行，`CreateToolhelp32Snapshot` diff）
2. **删除** 低频 `ScanProcessHandles` 调用（854-863行）
3. **保留** 遍历状态机 `inHighFreqMonitor` 进程的逻辑
4. **替换** `ScanSingleProcessHandles` 调用为新增的 `CheckProcessForDiskHandle`
5. **保留** 缓存清理逻辑

新增 `CheckProcessForDiskHandle` 函数：对单个PID，用 `DuplicateHandle` 逐个探测前256个句柄值（步长4），用 `NtQueryObject` 查名称，发现PhysicalDrive/Harddisk句柄即终止。单进程几十个句柄，耗时约5-50ms。

### 步骤5：更新构建脚本

**文件**：`build_pro_mingw1310.ps1`

添加 `pe_analysis.c` 的编译步骤和链接时的 `pe_analysis.o`。

## 关键流程

```
ETW ProcStart事件 → OnEtwProcStart → CoreModulesOnNewProcess
  ├─ PEQuickAnalyze (Hash + Import + String + 结构特征)
  │   ├─ Hash/Import/String匹配 → 立即终止+删除+恢复 (CRITICAL)
  │   ├─ RWX节区/可疑导入 → 终止+删除 (HIGH)
  │   └─ 无威胁 → 标记inHighFreqMonitor (5秒观察)
  └─ HandleScanThreadProc (轻量级)
      └─ CheckProcessForDiskHandle (仅扫描可疑进程句柄)
          ├─ 发现磁盘句柄 → 终止+恢复
          └─ 5秒无异常 → 信任
```

## 复用的现有代码

- `OnEtwProcStart` (daemon_core.c:6565) — ETW进程启动回调，已包含LOLBin检测和行为分析
- `VirusSignatureMatchHash/Strings/Imports` (virus_signature.c) — 特征匹配函数，Import匹配首次启用
- `RecoverFromEtwLogs` (daemon_core.c:3500) — 注册表/文件恢复
- `RestoreMBR` / `RestoreRegistryKeys` (thread_modules.c) — MBR/注册表恢复
- `ForceDeleteFile` / `DeleteVirusCopies` / `TerminateAllThreads` / `TerminateProcessTree` — 终止删除工具函数
- `IsProcessSigned` (thread_modules.c:295) — WinVerifyTrust签名验证
- 7种内置病毒特征 (virus_signature.c:30-178) — MEMZ/Petya/BlackLotus/熊猫烧香/WannaCry/Conficker/SilverFox

## 验证方法

1. 编译 `pe_analysis.c` 并链接到守护进程
2. 启动守护进程，用 `test_threat.exe` 测试：
   - 验证PE静态分析在进程启动瞬间触发
   - 验证Import匹配检测到 `NtRaiseHardError` 等导入
   - 验证进程被终止、文件被删除
   - 验证恢复逻辑（`RecoverFromEtwLogs`）执行
3. 检查日志无 `ScanProcessHandles` 的25万+句柄扫描记录
4. 检查内存占用下降（无4MB+缓冲区分配）
5. 验证ETW事件驱动检测延迟（从进程启动到PE分析完成应<50ms）
