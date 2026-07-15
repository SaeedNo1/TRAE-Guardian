# SystemGuard 全域AI终端安全防护平台

> **轻量化用户态EDR+AV一体化系统 · 用户态天花板定位**

---

## 一、创意名称 + 创意介绍

### 创意名称

**SystemGuard 全域AI终端安全防护平台**（轻量化用户态EDR+AV一体化系统）

### 想解决什么问题

市面传统杀毒软件仅聚焦基础文件查杀，属于单一AV产品，缺少终端检测与响应EDR完整能力，架构耦合严重、模块高度绑定；普遍依赖ETW异步日志存在致命时间延迟，面对MBR篡改、引导型勒索、多进程互保流氓软件只能事后补救，极易造成系统崩溃、数据加密丢失；同时现有工具规则硬编码、功能拓展困难，新增病毒识别逻辑、AI模型、检测手段均需重构主程序，可维护性极差，无标准化状态流转、可配置风险评分、插件拓展体系。

### 为什么会想到做这个

在长期测试彩虹猫、Petya骷髅勒索、银狐远控、熊猫烧香、引导型黑莲花木马等高危样本，以及长期对抗各类多进程互保流氓软件的过程中，发现传统安全工具单层架构存在不可弥补的底层短板：一是检测与处置逻辑耦合，分层拦截能力缺失，极速底层破坏病毒无法前置阻断；二是无标准化数据流转、统一风险判定中心，各检测模块独立运行、数据割裂，误报与漏报率居高不下；三是全部逻辑写死在代码内，迭代、新增功能、更换AI算法、接入云端威胁库都需要大规模修改源码。参考企业级商用EDR标准化分层设计思路，结合本项目73MB轻量化、纯用户态SYSTEM权限、无内核驱动的核心特点，重构一套解耦、模块化、可无限横向拓展的终端安全平台架构，打破"轻量化工具做不了企业级EDR完整能力"的行业局限。

### 大概是什么产品

SystemGuard 是一套**纯用户态天花板级轻量化EDR+AV一体化终端安全平台**，基于Qt构建可视化管理界面，采用分层解耦多线程架构，搭载统一AI风险评分中心、可配置规则引擎、进程状态机管控、标准化插件拓展接口，集成静态病毒扫描、全维度行为监控、底层磁盘/引导防护、分级自动响应、自保护防篡改、本地日志数据库六大核心体系，仅73MB体积实现个人终端、小型办公终端全场景安全防护，支持后续无侵入迭代各类检测、AI、云查毒功能。

---

## 二、目标用户及痛点

### 面向哪些用户

1. **个人深度电脑使用者**：重视底层磁盘、引导分区数据安全，长期受弹窗捆绑、主页劫持类流氓软件困扰，厌恶臃肿高占用传统杀毒软件；
2. **网络安全技术爱好者**：需要完整终端行为溯源、底层MBR/分区监控、病毒行为分析工具，用于样本测试、安全学习；
3. **中小企业桌面运维人员**：预算有限无法采购商业付费EDR产品，需要轻量化、可批量配置、可溯源终端风险事件的终端管控工具；
4. **极简系统爱好者**：追求低内存占用、无冗余捆绑、静默后台运行，同时需要完整病毒、木马、流氓软件全维度防护。

### 在什么场景下使用

覆盖Windows终端全生命周期安全管控场景：日常办公文件下载、陌生程序样本运行、第三方软件安装部署、批量办公终端运维、恶意病毒样本安全隔离测试、系统底层引导安全加固、长期挂机设备后台防护；同时适配开发者二次拓展场景，可基于内置插件接口新增自定义检测、AI识别、云端威胁查询能力。

### 当前痛点

1. **功能割裂**：普通免费杀毒仅具备基础AV文件查杀，缺失EDR核心行为监控、进程全生命周期追踪、底层磁盘引导防护，无法拦截极速破坏型引导病毒；
2. **架构僵化**：绝大多数轻量化安全工具代码高度耦合，检测、评分、处置逻辑写死，新增规则、更换AI算法、拓展新功能需要大规模重构代码，迭代成本极高；
3. **风险管控粗糙**：无标准化进程状态流转机制，各检测模块独立下发处置指令，容易出现重复查杀、误终止正常程序、高危病毒处置力度不足等矛盾；
4. **日志与配置不可控**：日志无本地数据库持久存储，风险行为无法回溯；扫描频率、风险分值、白名单全部硬编码，用户无法自定义调整防护强度；
5. **程序易被破坏**：主流轻量工具缺少完整自保护防篡改机制，恶意程序可直接结束进程、删除程序文件、篡改防护配置，防护体系直接失效；
6. **拓展能力缺失**：无标准化插件接口，无法无缝接入YARA规则库、云端病毒信誉库、新型AI识别模型，长期使用会出现新型变种病毒漏判问题。

---

## 三、产品整体专业分层架构

> **前后端分离设计**：Qt图形GUI仅负责数据展示、用户交互，所有检测、分析、处置、存储逻辑全部独立后台多线程运行，完全解耦，互不干扰。

```
┌─────────────────────────────────────────────────────────────────┐
│                    顶层交互层：Qt可视化GUI界面                    │
│  主页 | 实时风险 | 进程列表 | 事件日志 | 隔离区 | 设置 | 更新     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              中枢调度层：三大核心调度模块                         │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │
│  │   配置中心     │  │   日志中心     │  │ AI评分中心    │        │
│  │  (JSON配置)   │  │ (SQLite数据库) │  │ (统一判定)    │        │
│  └───────────────┘  └───────────────┘  └───────────────┘        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              核心检测层：九大独立后台线程并行运行                  │
│  ETW | 新进程观测 | 句柄扫描 | 高速扫描 | MBR防护 | 注册表防护   │
│  文件扫描 | 网络审计 | AI分析                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              执行响应层：分级响应中心 + 状态机                      │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │
│  │   分级响应     │  │   状态机      │  │   规则引擎    │        │
│  │  (8级处置)    │  │ (6态流转)     │  │ (可配置规则)  │        │
│  └───────────────┘  └───────────────┘  └───────────────┘        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              拓展支撑层：三大长效拓展体系                         │
│  标准化插件接口 | 自保护Anti-Tamper | 云端拓展预留               │
└─────────────────────────────────────────────────────────────────┘
```

### 顶层交互层：Qt可视化GUI界面

仅承担数据渲染与操作下发，不参与任何风险检测计算，所有行为数据、风险结果均由后台线程推送。

覆盖完整可视化面板：系统安全主页、实时风险动态看板、全量进程观测列表、完整安全事件日志、病毒隔离管理区、开机启动项管控、系统服务/计划任务监控、全网网络连接审计、磁盘分区状态可视化、MBR引导快照对比、AI智能风险分析报告、全平台自定义配置、程序自动更新面板。

### 中枢调度层：三大核心调度模块

#### 1. 配置中心

全平台所有参数通过标准化JSON文件统一管理，扫描周期、风险阈值、AI评分权重、白名单规则、自保护策略全部可自定义，无需修改源码；所有配置实时同步至各个检测线程，支持一键导入导出防护配置，适配运维批量部署场景。

#### 2. 日志中心（内置SQLite本地数据库）

持久化存储全维度安全数据：ETW内核原始行为日志、AI风险分析记录、病毒查杀处置记录、系统修复操作、全网网络访问记录、文件静态扫描历史；GUI支持多条件检索、日志导出、风险行为溯源，完整复现病毒从落地到破坏的全链路行为。

#### 3. AI风险评分中心（全平台统一判定中枢）

汇总静态扫描、行为监控、底层磁盘监控三大模块的证据数据，搭配可配置规则引擎加权计分，各检测模块独立分配固定分值权重（静态扫描最高25分、行为监控最高40分、底层硬件监控最高18分、AI智能研判额外浮动加分），总分达到80分即判定高危威胁；不直接下发处置指令，仅输出风险分值、威胁说明、处置建议，交由响应中心统一执行。

**核心算法：多维度加权评分体系**

```c
// 评分中心核心评分逻辑 - score_center.c
typedef struct {
    DWORD pid;
    wchar_t name[64];
    wchar_t imagePath[512];
    int staticScore;        // 静态扫描: 0-25分
    int behaviorScore;      // 行为监控: 0-40分  
    int kernelScore;        // 底层监控: 0-18分
    int aiScore;            // AI研判: -10~+8分
    int totalScore;         // 总分 = 静态+行为+底层+AI
    uint64_t lastUpdateTime;
    ScoreEntry* next;
} ScoreEntry;

// 分级阈值常量
#define THRESHOLD_OBSERVED    10   // 进入观测状态
#define THRESHOLD_SUSPICIOUS  35   // 标记可疑
#define THRESHOLD_RESTRICTED  50   // 限制权限
#define THRESHOLD_QUARANTINED 70   // 隔离处置
#define THRESHOLD_REMOVED     80   // 彻底清除
```

### 核心检测层（九大独立后台线程并行运行）

#### 1. ETW全量行为采集线程

持续捕获进程创建、线程注入、模块加载、注册表修改、网络连接、DNS请求、文件读写、内核服务、驱动加载全维度内核事件，全部原始数据推送至AI评分中心做统一研判。

#### 2. 新进程重点观测线程

一旦ETW捕获CreateProcess新建进程事件，立刻将进程加入重点观察名单，以20ms高频轮询进程设备句柄，持续观测5秒，捕捉进程刚启动时的高危底层操作，观测周期结束后自动移出名单。

#### 3. 全局设备句柄低频扫描线程

**核心算法：NtQuerySystemInformation全局句柄扫描**

```c
// thread_modules.c - 实时句柄扫描算法
static BOOL ScanProcessHandles(CoreModules* cm) {
    // 动态获取NTAPI函数指针
    NtQuerySystemInformationFunc NtQuerySystemInformation = 
        (NtQuerySystemInformationFunc)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    NtQueryObjectFunc NtQueryObject = 
        (NtQueryObjectFunc)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    
    ULONG bufSize = 0x40000;
    BYTE* buf = (BYTE*)malloc(bufSize);
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, buf, bufSize, &bufSize);
    
    SYSTEM_HANDLE_INFORMATION* shi = (SYSTEM_HANDLE_INFORMATION*)buf;
    for (ULONG i = 0; i < shi->HandleCount; i++) {
        // 遍历所有进程句柄，检测敏感设备访问
        if (DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)shi->Handles[i].Handle, 
                           GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            NtQueryObject(hDup, ObjectNameInformation, objName, sizeof(objName), &retLen);
            // 检测PhysicalDrive/Volume等敏感设备句柄
            if (wcsstr(objName, L"PhysicalDrive") || wcsstr(objName, L"Volume")) {
                // 未签名进程访问敏感设备 → 立即终止
                ResponseCenterQueueResponse(&cm->rc, pid, procName, imagePath, 
                                           RESPONSE_TERMINATE, L"Unauthorized physical disk access");
            }
        }
    }
    return foundDangerous;
}
```

默认1000ms遍历系统全部进程打开的设备句柄，重点识别物理磁盘、分区、原始磁盘、底层驱动设备、系统核心对象；一旦捕获危险句柄，自动切换高速扫描模式。

#### 4. 高危进程高速扫描线程

针对标记可疑的风险进程，提升扫描频率至10ms持续轮询句柄，最长持续观测10秒，杜绝病毒延迟执行底层磁盘篡改操作。

#### 5. MBR引导分区防护线程

程序开机自动备份完整512字节MBR哈希快照；常态5秒低频校验引导扇区完整性；若检测到进程打开物理磁盘句柄，自动切换50ms高频哈希校验，一旦哈希篡改，自动调用备份快照一键恢复分区引导。

**核心算法：MBR实时哈希校验**

```c
// thread_modules.c - MBR防护算法
typedef struct {
    BYTE data[512];
    uint64_t hash;
} MbrBackup;

static uint64_t HashMBR(const BYTE* data, int size) {
    // 多项式滚动哈希算法
    uint64_t hash = 17;
    for (int i = 0; i < size; i++) {
        hash = hash * 31 + data[i];
    }
    return hash;
}

static BOOL CheckMBRIntegrity(void) {
    BYTE current[512] = {0};
    ReadMBR(current, 512);
    uint64_t currentHash = HashMBR(current, 512);
    if (currentHash != g_lastMbrHash) {
        g_lastMbrHash = currentHash;
        return FALSE;  // 哈希不一致，MBR被篡改
    }
    return TRUE;
}
```

#### 6. 注册表快照防护线程

持续监控开机启动项、服务配置、浏览器劫持项、Shell加载项、镜像劫持等高危注册表路径，自动维护原始快照，支持一键回滚篡改配置，同步记录注册表变更行为计入风险积分。

#### 7. 文件静态扫描线程

**核心算法：PE文件恶意导入检测**

```c
// thread_modules.c - PE文件静态分析
static BOOL CheckPEForMaliciousImports(const wchar_t* path) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    BYTE* buf = (BYTE*)malloc(fileSize);
    ReadFile(hFile, buf, fileSize, &br, NULL);
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(buf + importDir->VirtualAddress);
        
        while (importDesc->Name) {
            if (_stricmp(dllName, "ntdll.dll") == 0) {
                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(buf + importDesc->OriginalFirstThunk);
                while (thunk->u1.Function) {
                    IMAGE_IMPORT_BY_NAME* imp = (IMAGE_IMPORT_BY_NAME*)(buf + thunk->u1.AddressOfData);
                    // 检测恶意API导入：NtRaiseHardError(蓝屏), NtShutdownSystem
                    if (strcmp(imp->Name, "NtRaiseHardError") == 0 || 
                        strcmp(imp->Name, "NtShutdownSystem") == 0) {
                        return TRUE;
                    }
                    thunk++;
                }
            }
            importDesc++;
        }
    }
    return FALSE;
}
```

独立解析文件完整特征：SHA256哈希校验、PE程序结构解析、数字签名授信校验、YARA病毒规则匹配、程序字符串检索、导入导出API识别、文件熵值壳检测、程序版本校验，静态特征直接计入风险评分。

#### 8. 网络审计线程

记录所有进程TCP/UDP连接、DNS解析、HTTP/TLS网络上传下载行为，留存访问IP、域名、归属地域、关联进程，后台联网、数据窃取类行为持续叠加风险分数。

#### 9. AI独立分析线程

接收全检测线程推送的行为、文件、磁盘、注册表多维度证据，内置本地安全知识库关键词匹配，支持联网检索全网威胁样本库；输出风险等级、攻击链路溯源、威胁处置建议，为总分提供浮动加分，AI模块仅提供研判依据，无直接处置权限。

### 执行响应层：分级响应中心 + 标准化进程状态机

#### 1. 多级精细化处置策略

**核心算法：分级响应执行引擎**

```c
// response_center.c - 8级分级响应
typedef enum {
    RESPONSE_NONE = 0,
    RESPONSE_OBSERVE,              // 0: 观测
    RESPONSE_NOTIFY,               // 1: 通知
    RESPONSE_LIMIT_NETWORK,        // 2: 限制网络
    RESPONSE_SUSPEND_PROCESS,      // 3: 暂停进程
    RESPONSE_TERMINATE,            // 4: 终止进程
    RESPONSE_QUARANTINE,           // 5: 隔离文件
    RESPONSE_DELETE,               // 6: 删除文件
    RESPONSE_BLACKLIST,            // 7: 加入黑名单
    RESPONSE_RESTORE               // 8: 系统恢复
} ResponseAction;

BOOL ResponseCenterExecuteResponse(ResponseCenter* rc, ResponseEntry* entry) {
    switch (entry->action) {
        case RESPONSE_LIMIT_NETWORK:
            result = ResponseLimitNetwork(entry->pid); break;
        case RESPONSE_SUSPEND_PROCESS:
            result = ResponseSuspendProcess(entry->pid); break;  // NtSuspendProcess
        case RESPONSE_TERMINATE:
            result = ResponseTerminateProcess(entry->pid); break;
        case RESPONSE_QUARANTINE:
            result = ResponseQuarantine(entry->pid, entry->imagePath); break;
        case RESPONSE_DELETE:
            result = ResponseDelete(entry->pid, entry->imagePath); break;
        case RESPONSE_RESTORE:
            result = TRUE; break;
    }
    return result;
}
```

从轻到重分级执行：网络访问限制、进程线程临时暂停、进程挂起、强制终止恶意进程、文件隔离封存、恶意载荷彻底删除、系统配置快照恢复、恶意程序全局黑名单封禁。

#### 2. 标准化进程状态机管控（核心架构创新）

**核心算法：单向状态流转机**

```c
// state_machine.c - 6态单向流转状态机
typedef enum {
    PROC_STATE_UNKNOWN = 0,        // 未知
    PROC_STATE_OBSERVED,           // 观测中
    PROC_STATE_SUSPICIOUS,         // 可疑
    PROC_STATE_RESTRICTED,         // 受限
    PROC_STATE_QUARANTINED,        // 隔离
    PROC_STATE_REMOVED,            // 清除
    PROC_STATE_WHITELISTED,        // 白名单
    PROC_STATE_TRUSTED             // 信任
} ProcessState;

BOOL StateMachineTransition(StateMachineEntry* entry, ProcessState newState, const wchar_t* reason) {
    if (entry->state == newState) return FALSE;
    // 状态只能升级，不能降级（白名单/信任除外）
    if (newState < entry->state && 
        newState != PROC_STATE_WHITELISTED && 
        newState != PROC_STATE_TRUSTED) {
        return FALSE;
    }
    entry->state = newState;
    entry->stateEnterTime = GetTickCount64();
    return TRUE;
}
```

所有进程统一流转固定状态，各检测模块仅负责提交风险证据，响应中心依据当前状态自动匹配处置策略，逻辑高度清晰，无处置冲突：

```
Unknown(未知) → Observed(观测) → Suspicious(可疑) → Restricted(受限) → Quarantined(隔离) → Removed(清除)
     ↑                                                                                    |
     └─────────────────────────────────── 白名单/信任 ────────────────────────────────────┘
```

#### 3. 可配置规则引擎

**核心算法：模式匹配规则引擎**

```c
// rule_engine.c - 规则引擎条件评估
static BOOL MatchPattern(const wchar_t* input, const wchar_t* pattern) {
    // 支持通配符*匹配
    if (wcsstr(pattern, L"*")) {
        wchar_t* star = wcsstr(pattern, L"*");
        wchar_t prefix[512] = {0}, suffix[512] = {0};
        wcsncpy(prefix, pattern, star - pattern);
        wcscpy(suffix, star + 1);
        // 前缀匹配 + 后缀匹配
        if (wcslen(prefix) > 0 && wcsnicmp(input, prefix, wcslen(prefix)) != 0) return FALSE;
        if (wcslen(suffix) > 0 && _wcsicmp(input + wcslen(input) - wcslen(suffix), suffix) != 0) return FALSE;
        return TRUE;
    }
    return _wcsicmp(input, pattern) == 0;
}

static BOOL EvaluateCondition(const RuleCondition* cond, const wchar_t* processName,
                             const wchar_t* imagePath, const wchar_t* signer, 
                             BOOL isSigned, const wchar_t* eventType, const wchar_t* eventPath) {
    switch (cond->type) {
        case RULE_COND_TYPE_SIGNED:    return isSigned;
        case RULE_COND_TYPE_UNSIGNED:  return !isSigned;
        case RULE_COND_TYPE_PATH:      return MatchPattern(imagePath, cond->pattern);
        case RULE_COND_TYPE_HANDLE:    return _wcsicmp(eventType, L"handle") == 0;
        case RULE_COND_TYPE_MBR:       return _wcsicmp(eventType, L"mbr") == 0;
        case RULE_COND_TYPE_INJECTION: return _wcsicmp(eventType, L"injection") == 0;
        case RULE_COND_TYPE_CRITICAL_ATTACK: return _wcsicmp(eventType, L"critical_attack") == 0;
        // ... 更多条件类型
    }
}
```

所有风险判定规则以标准化文本配置存储，无需修改源码即可新增、删除、调整威胁分值、危险等级；示例规则：打开PhysicalDrive磁盘设备并执行写入操作，分值+35，等级高危；后续新增勒索、远控、流氓软件识别规则仅更新规则文件，无需重新编译软件。

### 信任白名单体系

不依靠单一文件名放行，采用多重特征综合授信校验：文件SHA256哈希、厂商数字签名、程序安装路径、软件版本、用户手动确认授信，系统自带Windows官方进程全局白名单，正规软件自动降低风险计分。

### 拓展支撑层：三大长效拓展体系

#### 1. 标准化通用插件接口

预留统一Plugin拓展入口，可无侵入接入YARA病毒规则库、云端全网查毒接口、新一代AI识别模型、OCR辅助分析、浏览器安全防护插件；后续新增任意功能无需改动主程序核心逻辑。

#### 2. 完整自保护防篡改Anti-Tamper机制

全方位守护软件本体不被恶意程序破坏：GUI界面被强行关闭时，后台守护线程自动拉起；守护进程被终止，界面自动重启；程序DLL、主程序文件被删除/覆盖，自动从内置备份恢复；防护配置被恶意篡改，一键回滚原始合规配置；未来可拓展内核驱动级深度自保护（ObRegisterCallbacks、MiniFilter过滤驱动、受保护进程）。

#### 3. 云端拓展预留架构

支持本地文件SHA256哈希上传云端威胁库比对，获取文件信誉评分；云端同步新型病毒规则、AI训练模型，持续迭代本地识别能力，实现云+端联动防护。

### 底层基础支撑

SQLite本地日志数据库、JSON标准化配置文件、通用插件管理器、全局程序自保护守护线程、系统快照备份恢复线程、程序自动更新线程。

---

## 四、价值与意义

### 1. 技术架构价值

本项目打破"轻量化用户态程序无法实现企业级EDR完整能力"的固有认知，在仅73MB无内核驱动、SYSTEM用户态权限的前提下，采用大型商用安全软件同款分层解耦架构、状态机管控、可配置规则引擎、插件拓展体系，彻底解决传统安全工具架构僵化、迭代困难、检测处置逻辑混乱的核心痛点。各模块完全独立解耦，更换AI算法、新增病毒检测手段、拓展云端联动功能仅需新增对应线程与插件，无需重构主程序，具备极强长期开发拓展性，是轻量化终端安全领域创新标杆。

### 2. 效率提升价值

独创"底层硬件行为前置拦截+常规行为AI异步分析"双路线检测体系，针对MBR篡改、物理磁盘写入、蓝屏触发等毫秒级极速破坏行为，脱离ETW异步日志依赖，高频句柄扫描线程提前阻断，从根源解决"事后补救、系统崩溃来不及处置"的行业通病；统一AI风险评分中枢+标准化进程状态机，统筹全维度检测数据，规避多模块处置冲突，自动分级管控恶意程序，全程静默全自动运行，无需人工反复弹窗确认，大幅降低用户系统安全运维时间成本。

### 3. 实用落地价值

一套产品同时覆盖AV病毒查杀+EDR终端行为管控双重能力，既能完美拦截彩虹猫、Petya骷髅勒索、熊猫烧香、银狐远控、黑莲花引导木马全系列高危病毒，也能深度压制多进程互保、弹窗广告、主页劫持、静默捆绑类顽固流氓软件；轻量化体积低资源占用，适配老旧低配电脑；支持自定义防护强度、批量配置导出、完整行为日志溯源，既满足普通个人用户日常防护需求，也能替代高价商业EDR，适配小微企业批量办公终端安全管控，落地门槛极低，适用场景覆盖广泛。

### 4. 长期迭代拓展价值

标准化插件接口、可配置规则引擎、云端预留架构赋予产品无限迭代空间，现阶段仅依靠用户态能力实现完整防护，未来可无缝拓展内核驱动级防护、云端威胁大数据、AI自主学习识别、批量终端运维管控等高级功能，产品生命周期与功能上限远超市面上同体量单一杀毒工具。

---

## 五、核心技术亮点总结

| 技术创新点 | 实现方式 | 解决的问题 |
|-----------|---------|-----------|
| **实时句柄扫描** | `NtQuerySystemInformation` 枚举所有进程句柄，200ms低频/10ms高频双模式 | 前置拦截物理磁盘访问，杜绝MBR篡改 |
| **MBR哈希校验** | 开机备份512字节MBR，500ms/50ms双频校验 | 检测MBR篡改并自动恢复 |
| **进程状态机** | 6态单向流转，各模块仅提交证据，响应中心统一处置 | 消除多模块处置冲突，逻辑清晰 |
| **多维度评分** | 静态(25)+行为(40)+底层(18)+AI(±8)加权计分 | 精准风险评估，减少误报漏报 |
| **可配置规则引擎** | 规则以JSON存储，支持通配符匹配、多条件组合 | 新增规则无需修改源码 |
| **分级响应** | 8级精细化处置策略，从轻到重逐步升级 | 避免过度处置，保护正常程序 |
| **同源进程清理** | 批量终止同名进程，防止看门狗复活 | 彻底清除多进程互保恶意软件 |
| **自保护机制** | GUI/守护进程互相拉起，文件/配置自动恢复 | 防止恶意程序破坏防护体系 |
