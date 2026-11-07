# exe-xray

[![tests](https://github.com/wc985732-lang/exe-xray/actions/workflows/tests.yml/badge.svg)](https://github.com/wc985732-lang/exe-xray/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/exe-xray.svg)](https://pypi.org/project/exe-xray/)
[![Python versions](https://img.shields.io/pypi/pyversions/exe-xray.svg)](https://pypi.org/project/exe-xray/)

[English](README.md) | 简体中文

一个给 Windows 可执行文件做**静态体检**的小工具，输出给人看，不输出给人猜。

把一个 `.exe` 或 `.dll` 丢给它，你会拿到一份说人话的报告：这是什么类型的程序、它能碰到哪些 API、文件里随身带着哪些字符串、有没有加壳、签名还能不能覆盖住这个文件，最后还有一句总结——*这大概率是个带自启动的键盘记录器*。

目标文件**从不**被执行、加载、映射或模拟运行，工具只读文件字节。纯 Python 标准库实现，零依赖，不联网。

```
$ python xray.py C:\Windows\System32\notepad.exe
```

## 目录

- [为什么还要再造一个](#为什么还要再造一个)
- [安装](#安装)
- [用法](#用法)
- [批量模式](#批量模式)
- [报告里有什么](#报告里有什么)
- [风险打分模型的四层证据](#风险打分模型的四层证据)
- [加壳检测：三层证据，以及它的边界](#加壳检测三层证据以及它的边界)
- [示例](#示例)
- [代码结构](#代码结构)
- [测试](#测试)
- [局限](#局限)
- [许可证](#许可证)

## 为什么还要再造一个

`dumpbin`、pe-bear、`pefile` 这一挂工具给你的是**字段**。这个工具给你的是**含义**：它把导入表映射到能力上（联网、注入、抓键盘、持久化、反调试……），给这些能力打分，然后写一句不懂 `SetWindowsHookExW` 是干嘛的人也能看懂的结论。

## 安装

```
pip install exe-xray
```

就这一条，装完能用。一个 wheel，零依赖，Python 3.9+。

想直接在仓库里跑也行，什么都不用装：

```
python xray.py <file>            # 直接在仓库里跑
python -m exe_xray <file>        # 等价写法
```

## 用法

```
exe-xray FILE [FILE ...] [options]
exe-xray --batch PATH [batch options]

  --json                 full structured report instead of prose
  --compact              one summary line per file
  --min-string-len N     shortest literal to keep (default 4)
  --max-strings N        samples kept per string category (default 4000)
  --no-strings           skip literal extraction: big win on string-dense files,
                         but on a huge image the checksum pass below is usually
                         the larger cost
  --no-checksum          skip the PE checksum verification, the most expensive
                         pass over the file; the report then says the checksum
                         was *not verified* instead of inventing a verdict
  --max-file-mb MB       refuse files above this size (default 512)
  --color {auto,always,never}
  --version

  batch mode:
  --batch PATH           directory, glob or single file; scanned recursively for
                         .exe/.dll/.sys/.cpl/.scr/.ocx
  --max-files N          stop after N files were analysed, in path order (default 500)
  --min-risk-level LVL   list only minimal|low|medium|high and above (default minimal)
  --csv                  CSV instead of the table: score,level,name,path,verdict
  --fail-on-risk N       exit 1 when any listed file scores N/100 or more
```

### 退出码语义

退出码是接口的一部分，CI 会按它分支，所以这里写死：

| 码 | 含义 |
| --- | --- |
| `0` | 至少产出了一份报告，且 `--fail-on-risk`（如果给了）没有触发 |
| `1` | 一份报告都没产出，或者 `--fail-on-risk` 门槛被踩中 |
| `2` | 命令行参数有问题 |
| `130` | 被 Ctrl+C 打断（已扫到的部分先打印出来再退出） |

三个容易被误读的地方，一次说清：

1. **解析失败的文件不进退出码。** 单文件模式下它会让 stderr 报错、让计数增加，但只要还有别的文件成功分析了，退出码仍是 `0`。批量模式下它会进 `errors` 列/错误的 CSV 行，扫描继续。只有"一个都没分析成"才是 `1`。
2. **`--fail-on-risk` 只看被列出来的行。** 门槛是在 `--min-risk-level` 过滤之后判定的，所以 CI 日志里永远不会出现"门槛踩了，但表里一行都没显示"这种自相矛盾的场面。
3. **`130` 优先于 `1`。** 被打断时先渲染已经扫完的结果，然后以 `130` 退出，即使门槛同时被踩中。

## 大文件

校验和是整个流程里最贵的一遍（段统计、导入表、字符串都是有界的）。在 220 MiB 的 `MRT.exe` 上，单是校验和曾经占掉 232 秒里的 166 秒。现在它改成了批量求和（见 `exe_xray/pe.py`），8 秒左右跑完；如果你只要导入表/字符串/结论，`--no-checksum` 连这 8 秒也能省掉。

```
$ python xray.py C:\Windows\System32\MRT.exe --no-checksum --compact
```

## 批量模式

`--batch` 会递归走一个目录、展开一个通配符、或者只吃一个文件，然后打印一张按风险分排序的表：分数、等级、文件名，以及从该文件报告里最尖锐的那条信号抽出来的一句话判断。

```
$ python xray.py --batch C:\Windows\System32 --max-files 50
SCORE  LEVEL    FILE                                      VERDICT
------------------------------------------------------------------------------------------------
   27  low      AcXtrnal.dll                              64-bit DLL: can write/inject code into another process (Que...
   25  low      accessibilitycpl.dll                      64-bit DLL: reads keyboard state (GetKeyState)
   25  low      AcSpecfc.dll                              64-bit DLL: talks to the service control manager
    3  minimal  aadtb.dll                                 64-bit DLL: 1 credential-shaped literal(s) in the image
   14  minimal  aclui.dll                                 64-bit DLL: checks for debuggers/analysis (OutputDebugStrin...
    5  minimal  acppage.dll                              64-bit DLL: launches commands through the shell (ShellExecu...
    3  minimal  ACPBackgroundManagerPolicy.dll            64-bit DLL: offensive-tooling marker in strings: lsass.exe
scanned 50 of 6365 candidate(s)  ·  listed 50  ·  errors 0  ·  18 unreadable dir(s)  ·  --max-files stopped at 50
```

注意最后一行：`ACPBackgroundManagerPolicy.dll` 被标出来，是因为它体内带着 `lsass.exe` 这个字面量——而一个微软的策略 DLL 合法地带这个字符串。工具只负责报告它找到了什么；这算不算问题，是分析员的活。

各部分的行为细节：

* **扩展名**：`.exe .dll .sys .cpl .scr .ocx`，大小写不敏感。显式点名的文件（`--batch C:\x\weird.bin`）照样分析——点名一个文件本身就是一个决定，如果字节其实不是 PE，分析器会自己解释清楚。
* **处理顺序**：候选按路径顺序取，`--max-files` 限的是**被分析**的数量，不是被列出的数量，所以这个上限真正约束的是运行时间。表在这之后才按分数降序排。
* **一个文件一行**：结论列先给结论类型，再给最严重的信号。超长就截断，绝不折行。
* **`--csv`**：同样的行、同样的顺序，一行一个文件（`score,level,name,path,verdict`）；在任何 `--color` 策略下都不带 ANSI 转义。解析失败的文件以 `level=error`、分数留空的形式出现，这样流水线能看见它们，而不是悄悄丢文件。**不可读的目录**只留在 stderr 和页脚里：目录不是文件。
* **`--min-risk-level`**：显示过滤器，在排序之前生效。下面的门槛看的是列出来的行，所以 CI 日志不会自相矛盾。
* **`--fail-on-risk N`**：渲染完成后判定，只要有被列出的文件 ≥ `N` 分就以 `1` 退出（`N` 含等号，`0` 表示"只要有人上榜就踩"）。批量和单文件模式都支持，这正是流水线需要的形态：

  ```powershell
  python xray.py --batch dist --min-risk-level medium --fail-on-risk 65
  if ($LASTEXITCODE -eq 1) { throw "release has a high-risk binary" }
  ```
* **`--json`**：输出 `{"batch": {…counts…}, "rows": […], "errors": […]}`，给宁肯解析也不想刮表格的下游用。
* **Ctrl+C**：已经分析的这批文件照样渲染出来，然后以 `130` 退出。
* **成本**：每个文件只调用一次分析器，绝不重读。在作者这台机器上，`C:\Windows\System32` 的前 200 个文件（候选共 6365 个）用默认流程跑四次是 **53–68 秒**，加 `--no-strings` 是 **7–10 秒**。中位数文件 61 ms；六个 3–6 MB 的镜像占了总耗时的近 25 秒——所以一次目录横扫真正买单的是字面量提取，不是校验和（同一个开关也会跳过它）。整棵树只想快速过一遍，用 `--no-strings`（或 `--no-checksum`）。

## 报告里有什么

| 版块 | 内容 |
| --- | --- |
| **FILE** | 大小、mtime、SHA-256 / SHA-1 / MD5 |
| **HEADERS** | PE32 还是 PE32+、machine、subsystem、链接器版本、编译时间戳、入口点、image base、DllCharacteristics（ASLR/NX/CFG）、校验和是否有效、.NET/CLR 头、PDB 路径、MSVC Rich-header 构建号 |
| **SIGNATURE** | 内嵌 Authenticode：PKCS#7 解析、签名者 DN、签发者、有效期窗口、是否带时间戳，以及**重算签名所承诺的文件摘要** |
| **SECTIONS** | 每个段的大小、熵、R/W/X 标志、overlay 大小 |
| **IMPORTS** | 每个 DLL 和 API，分桶到能力 |
| **STRINGS** | ASCII + UTF-16LE 字面量，分桶到 URL、IP、域名、注册表路径、文件路径、User-Agent、凭证形态字符串、SQL、base64 大块、钱包地址、外联端点、攻击工具特征 |
| **PACKING** | 段名特征（UPX/VMProtect/Themida/ASPack/MPRESS/…）、熵、W+X 段、VirtualSize≫RawSize、极小的导入表、overlay 比例——带评分 |
| **VERDICT** | 一句话结论 + 按严重度排序的信号 + 0–100 风险分 |

### 能力桶

`network`、`http`、`download`、`dns`、`netauth`、`netinfo`、`file`、`registry`、
`process`、`thread`、`injection`、`service`、`driver`、`crypto`、`dpapi`、
`keyboard`、`hook`、`screen`、`input`、`clipboard`、`privilege`、`shell-exec`、
`anti-debug`、`timing`、`enum`、`shadowcopy`、`wifi`、`audio`、`netapi`、`com`、
`ui`、`console`、`crt`、`runtime`。

映射表在 `exe_xray/capabilities.py` 里，就是一张朴素的表（`module -> [(api pattern, bucket)]`），本来就打算让人往里加东西。`api-ms-win-*` 这类 API set 会被折回它们真正的模块。

## 风险打分模型的四层证据

整套打分只遵守一条铁律：**导入表不能单独决定结论。** 导入表告诉你"这个程序够得着什么"，永远不告诉你"它做了什么"。所以导入表这一层的贡献被硬性封顶在 45/100，不管一个大型程序摸到了多少个桶。

在此之上，证据按四层叠加：

**第一层，能力广度（封顶 45）。** 把命中的能力桶按权重从高到低排，前 6 个桶按满权重计入，第 7–11 个桶按 1/6 衰减，再往后的桶直接忽略，最后 `min(和, 45)`。衰减是关键：一个什么都会的浏览器不该靠"桶多"就攒出高分。

**第二层，组合信号（+8…+15/条）。** 单个 API 往往人畜无害，组合起来才是行为。比如键盘读取单看是 `warn`，但"读键 + 开套接字"就直接 `high` 并 +15——那就是一条带外联通道的键盘记录器。同一层里还有：进程注入 +12、从 URL 下载 +8、驱动 +10、硬编码外联端点 +15、凭证形态字面量 +8、钱包地址 +5、攻击工具特征 +12、`...\CurrentVersion\Run` 自启动路径 +8、内嵌 URL +3。

**第三层，结构证据（+20…+35）。** 这一层不看程序想干什么，只看文件本身长什么样：判定为加壳/保护时 +35，并在报告里明说"上面的导入表和字符串只是它能干的事的一小片"；内嵌签名存在但与文件不符时 +20，并且**该文件的等级永远不会低于 `medium`**。

**第四层，正向抵扣（−35 / −20）。** 签名通过验证 −35；落在 System32/SysWOW64/WinSxS 且版本资源里 `CompanyName` 含 Microsoft 时 −20。这两条都要**真凭据**：签名抵扣只在 RSA PKCS#1 v1.5 验证确实通过时才给，所以把证书表里的 `messageDigest` 改一改，换不来任何折扣；系统组件抵扣要求"位置 + 发布者"两者同时成立，光有位置没用（任何东西都能被塞进 System32），光有公司名也没用（那会覆盖所有 redistributable）。

| 证据 | 效果 |
|---|---|
| 能力广度（封顶） | 0–45 |
| 签名通过验证、且对得上签名者证书 | −35 |
| 位于 System32/SysWOW64/WinSxS 且 `CompanyName` 为 Microsoft | −20 |
| 内嵌签名存在但与文件不符 | +20，且不低于 `medium` |
| 加壳 / 受保护的镜像 | +35 |
| 硬编码外联端点、键盘记录+套接字、攻击工具特征 | 每条 +8 … +15 |

分级：≥65 `high`、≥35 `medium`、≥15 `low`、其余 `minimal`；签名破损的文件会被强制抬到 `medium` 以上。

于是结果就合理了：一个开套接字又读写文件的浏览器停在 `minimal`，而五行代码——钩键盘、顺手回连——直接 `high`。签名被破坏的文件（签完之后被改过，或者签名是伪造的）**永远不会**被报成 `minimal`，因为"我们没能验证它"不能被读成"它看起来很干净"。

## 加壳检测：三层证据，以及它的边界

加壳这一节是**一堆静态证据的集合**，它不是脱壳器，也不是模拟器。证据按三层归类：

* **身份层**——段名就是壳自己的名字（`UPX0/UPX1`、`.vmp0/.vmp1`、`.aspack`、`.mpress1`、…），或者壳自己的 magic（`UPX!`）。命中一条就足以判 `likely packed / protected`。注意同一个壳只记一次分：`UPX0` 和 `UPX1` 是同一个观察被看了两遍，加起来会让一个两段的 stub 自己攒到 80 分。
* **结构层**——正常链接出来的镜像不可能有、而自解压 stub 必须有的性质：一个既可写又可执行、磁盘上却占 0 字节、且不小于最大的文件承载代码段的段（那就是解包目的地——压进去的东西不可能比解出来的大）；导入表被削成只剩 `LoadLibrary` + `GetProcAddress`；段名里含不可打印字节。（`ntoskrnl.exe` 里那种只读、discardable 的 `Pad2` 填充段不算：stub 必须能往那块内存里写，只读区域只会 fault。）命中一条是 `possibly`，两条是 `likely`。
* **佐证层**——可执行段熵超过 7.2、入口点不在第一个段、RWX 段、overlay、导入数量异常少、导入表为空。这些在合法软件里也都会出现（实测：随 Windows 发行的镜像里可执行段熵最高 7.83，而真壳载荷从 7.34 起步——**两个区间是重叠的**；`ntdll.dll` 和 VirtualBox 也都没有普通导入表），所以**任何单独一条都不能定罪**。只能佐证，不能定案：佐证信号凑够了但没有任何身份/结构证据时，分数会被压回 `possibly` 线以下，结论老实写成"无加壳迹象"。

已知边界：

* 托管（.NET）程序集不参与这个判断：它们的代码熵和导入表由 CLR 规定，测什么都没意义。托管保护壳（ConfuserEx 之流）完全不在范围内。
* 一个自定义 crypter，只要它把段改名、保留一张普通导入表、把载荷塞进一个已初始化的可执行段，最多只能拿到 "possibly packed"。
* VMProtect/Themida 的虚拟化段熵可能低于 7.2；这些靠段名抓，不靠熵。
* 工具回答的是"这个文件身上有没有加壳痕迹"，永远不是"代码是不是原版"，也永远不是"这是不是恶意软件"。后两个问题需要脱壳或动态分析。

真实样本验证（4,166 个随 Windows 发行的镜像 + 作者机器上 1,491 个第三方 `*.exe`）：3 个真壳（UPX ×2、VMProtect ×1）全部判成 `likely packed / protected`；Windows 自带镜像**零**误报；第三方样本里还剩 1 个 `possibly`（一个 OEM 托管程序，PE 头被重写过）。完整调查——样本表、每一个误报及其成因、每个权重背后的实测依据——在 [NOTES-packing.md](NOTES-packing.md)。回归测试在 `tests/test_packing.py`，在缺少这些样本的机器上会**跳过**；跳过意味着"这里没验证过"，永远不意味着"验证过是好的"。

## 示例

一个每台 Windows 上都有的真实文件（输出有删节）：

```
$ python xray.py C:\Windows\System32\notepad.exe --color never
exe-xray 0.1.0  ·  static PE inspection  ·  the target is never executed

FILE
  path      C:\Windows\System32\notepad.exe
  size      352 KiB (360,448 bytes)
  modified  2026-09-10 05:47:09Z
  sha256    468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e
  md5       8a1d8175ccca97054cdb25acbb4cc07e

HEADERS
  format    PE32+  x64 (AMD64)  EXE  subsystem=windows-gui  linker 14.38
  compiled  1979-02-19 18:32:04Z  (before 1980: not a plausible build time)
  entry     0x19c0   image base 0x140000000   image size 360 KiB
  flags     HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT, GUARD_CF, TERMINAL_SERVER_AWARE
  checksum  valid
  .NET      no (native image)
  PDB       notepad.pdb
  toolchain MSVC Rich header, build(s) 264, 261, 260, 259, 258

SIGNATURE
  status    unsigned  no IMAGE_DIRECTORY_ENTRY_SECURITY entry: no embedded signature (Windows may still trust the file through a system catalog)

SECTIONS
  name            virt       raw  entropy  flags
  .text        157,666   159,744      6.24  CODE X R
  fothk          4,096     4,096      0.02  CODE X R
  .rdata        42,696    45,056      5.58  IDATA R
  .data         10,048     4,096      1.62  IDATA R W
  .pdata         4,632     8,192      3.32  IDATA R
  .didat           248     4,096      0.25  IDATA R W
  .rsrc        123,344   126,976      6.97  IDATA R
  .reloc           860     4,096      1.62  IDATA DISCARDABLE R

VERSION INFO
  CompanyName        Microsoft Corporation
  FileDescription    Notepad
  FileVersion        10.0.26100.9278 (WinBuild.160101.0800)
  OriginalFilename   NOTEPAD.EXE
  ProductName        Microsoft® Windows® Operating System
  manifest requests: asInvoker

IMPORTS  56 DLLs, 315 functions, 224 resolved to generic runtime glue, 20 outside the table
  anti-debug     2x  api-ms-win-core-debug-l1-1-0.dll:IsDebuggerPresent, api-ms-win-core-debug-l1-1-0.dll:OutputDebugStringW
  process        2x  api-ms-win-core-processthreads-l1-1-0.dll:CreateProcessW, ...
  clipboard      1x  user32.dll:OpenClipboard
  file           9x  api-ms-win-core-file-l1-1-0.dll:DeleteFileW, ..., CreateFileW, ReadFile, ...

STRINGS  3,608 extracted, 2,379 unique
  URLs / endpoints (3)
    http://schemas.microsoft.com/SMI/2016/WindowsSettings
    https://go.microsoft.com/fwlink/?LinkId=834783
    https://go.microsoft.com/fwlink/p/?linkid=838060

PACKING  no packing indicators (score 0/100)
  - no packer signatures, normal entropy, healthy import table

VERDICT
  Most likely a 64-bit GUI application. From the import table: drives a window message
  loop, reads and writes files, can start or open other processes. Risk: minimal (0/100).
```

### 合成夹具

还有两个例子用的是测试夹具。它们**不在仓库里**：`tests/fixtures/` 被 git 忽略，文件由测试运行现场生成，所以刚克隆下来的时候，只有下面这样才跑得通，别的都不行：

```
$ python -m unittest discover -s tests      # writes tests/fixtures/*.exe
$ python xray.py tests\fixtures\suspicious.exe
```

```
IMPORTS  4 DLLs, 18 functions, 0 resolved to generic runtime glue, 0 outside the table
  injection      3x  kernel32.dll:CreateRemoteThread, kernel32.dll:WriteProcessMemory, kernel32.dll:VirtualAllocEx
  keyboard       1x  user32.dll:GetAsyncKeyState
  hook           1x  user32.dll:SetWindowsHookExA
  service        2x  advapi32.dll:CreateServiceW, advapi32.dll:OpenSCManagerA
  anti-debug     1x  kernel32.dll:IsDebuggerPresent
  network        6x  ws2_32.dll:WSAStartup, ws2_32.dll:socket, ws2_32.dll:connect, ...
  process        2x  kernel32.dll:OpenProcess, kernel32.dll:CreateProcessW
  registry       1x  advapi32.dll:RegSetValueExW

STRINGS  31 extracted, 31 unique
  URLs / endpoints (2)
    http://c2.example.invalid/gate.php?id=%s
    https://discord.com/api/webhooks/1234567890/abcdefg
  registry paths (1)
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
  exfiltration endpoints (1)
    https://discord.com/api/webhooks/1234567890/abcdefg

VERDICT
  Most likely a 32-bit GUI application. From the import table: drives a window message
  loop, talks to the network, touches the registry, can start or open other processes,
  can write into another process, hooks input. Worth a look: can write/inject code into
  another process (CreateRemoteThread, WriteProcessMemory, VirtualAllocEx); reads key
  state and also opens sockets: a keylogger with an exfil path; hard-coded exfiltration
  endpoint: https://discord.com/api/webhooks/1234567890/abcdefg. Risk: high (100/100).
  - HIGH           can write/inject code into another process (CreateRemoteThread, ...)
  - HIGH           reads key state and also opens sockets: a keylogger with an exfil path
  - HIGH           hard-coded exfiltration endpoint: https://discord.com/api/webhooks/...
  - WARN           installs Windows hooks (classic in-process injection vector)
  - WARN           autostart registry path referenced: HKEY_CURRENT_USER\...\Run
  - NOTE           checks for debuggers/analysis (IsDebuggerPresent)
```

专门冲着加壳启发式做的夹具（同样的警告适用于测试套件：这个夹具把自己的段名起成 `UPX0`/`UPX1`，也就是说它**直接把答案告诉**了检测器；它练的是段名表，不是真实壳的输出）：

```
$ python xray.py tests\fixtures\packed.exe
PACKING  likely packed / protected (score 100/100)
  - section name 'UPX0' is the signature of UPX
  - section name 'UPX1' is the signature of UPX
  - section UPX0 is both writable and executable
  - section UPX1 has entropy 7.78 (>7.2 is typical for compressed or encrypted code)
```

一个真实签过名的二进制，同一个工具：

```
$ python xray.py "C:\Program Files\Python312\python.exe"
```

```
SIGNATURE
  status    valid  SHA256 file digest matches the signed digest
  signer    CN=Python Software Foundation, O=Python Software Foundation, ...
            issuer CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, ...
  timestamped by an RFC3161/countersignature authority
```

### 签名验证的边界

这里最容易踩坑，先讲清楚工具到底验了什么、没验什么：

* **验了**：文件摘要。工具会用文件字节重算摘要，再拿它和内嵌 PKCS#7 里签名所承诺的摘要比对，并且做 RSA PKCS#1 v1.5 验签。这是"签名完整性"。
* **没验**：证书链、吊销状态、时间戳权威性。这些需要 CryptoAPI / `WinVerifyTrust`，本工具是纯标准库实现，不碰。
* **看不到**：目录签名（catalog signature）。绝大多数 Windows 系统二进制是靠 `.cat` 目录文件信任的，而不是内嵌签名。所以 Windows 可能告诉你"有效"，而本工具告诉你"没有内嵌签名"——**两句话都是真的**。

这个区分直接决定了打分逻辑：签名抵扣（−35）只在摘要比对真的通过时才发；但"签名存在却对不上"是反向证据（+20），因为它意味着文件在签名后被改过，或者签名本身就是伪造的。

### JSON

```
$ python xray.py app.exe --json --no-strings
{
  "tool": {"name": "exe-xray", "version": "0.1.0"},
  "file": {"path": "...", "size": 818512, "sha256": "...", "md5": "..."},
  "pe": {"format": "PE32+", "machine": "x64 (AMD64)", "subsystem": "windows-console",
         "checksum": {"stored": "0x...", "computed": "0x...", "valid": true},
         "sections": [{"name": ".text", "entropy": 6.37, "flags": ["CODE", "X", "R"]}]},
  "signature": {"present": true, "status": "valid",
                "signers": [{"subject": "CN=...", "issuer": "CN=...", "timestamped": true}]},
  "imports": {"dll_count": 42, "function_count": 237,
              "categories": {"network": {"weight": 5, "apis": [...]}}},
  "strings": {"total": 13526, "by_category": {"url": {"samples": [...]}}},
  "packing": {"score": 0, "verdict": "no packing indicators", "reasons": []},
  "risk": {"score": 12, "level": "low", "signals": [{"id": "embedded-urls", ...}]},
  "verdict": {"kind": "64-bit console application", "summary": "Most likely a ..."}
}
```

## 代码结构

```
xray.py                  thin launcher
exe_xray/pe.py           dependency-free PE/COFF parser (headers, sections, imports,
                         exports, resources + VS_VERSIONINFO, debug/PDB, Rich header,
                         CLR header, overlay, checksum)
exe_xray/der.py          small ASN.1 reader
exe_xray/authenticode.py PKCS#7 SignedData walk + Authenticode file digest check
exe_xray/strings.py      literal extraction + classification
exe_xray/capabilities.py import table -> capability table
exe_xray/analyze.py      pipeline, packing heuristics, risk scoring, verdict
exe_xray/report.py       human / JSON / compact / batch-table rendering
tests/make_fixtures.py   builds synthetic PE fixtures (no compiler involved)
tests/test_xray.py       unittest suite
tests/test_batch.py      unittest suite for --batch (discovery, table, CSV, exit codes)
```

## 测试

```
python -m unittest discover -s tests -v
```

测试套件自己生成输入：`setUpModule` 会调用 `tests/make_fixtures.py`，现场写出 `tests/fixtures/*.exe`（不用编译器、不联网、不执行任何东西）。那个目录在 `.gitignore` 里——夹具是构建产物，不是入库样本，所以刚克隆下来的仓库里没有 `tests/fixtures/`，跑一次上面的命令才有。`python tests/make_fixtures.py` 不跑测试也能达到同样效果。

95 个测试覆盖：头部解析、导入分类、字符串分桶、加壳判定、风险打分、错误处理、两种渲染器、CLI 退出码、批量校验和与旧的逐字节 oracle 对拍、`--no-checksum` 的报告标记、`--batch`（递归发现、扩展名过滤、通配符、`--max-files`、`--min-risk-level`、表格与 CSV 形状、`--fail-on-risk` 门槛在目录和单文件两种模式下的行为、一个坏文件不会终止整场扫描、Ctrl+C 打印部分结果），以及在文件确实存在的机器上跑真实的 `notepad.exe` 和一个签过名的 `python.exe`。

关于测试设计的三点说明：

* UPX 夹具把自己的段起名 `UPX0`/`UPX1`，所以它只能证明段名表仍然会触发。测试在 docstring 里直说了这一点，另外用一组负对照（高熵段 + 中性段名）覆盖了否则会漏测的那部分。
* 三个 Authenticode 负对照（截断的证书表、改了段但不修摘要、空证书表）需要一个真实的**内嵌**签名，所以在没有签名二进制的机器上它们会——显眼地——跳过。那里的 skip 意味着"未证明"。
* 没有任何跳过是为了掩盖一个意外答案：签名 `python.exe` 那条测试把状态断言在闭集 `{valid, unsigned}` 上，并统计这台机器上命中的是哪一种。

## 局限

诚实清单：

- **纯静态。** 加壳或虚拟化的二进制会把大部分导入和字符串藏起来；报告会说清楚这一点，但它看不见解包之后跑的是什么。
- **验的是签名完整性，不是信任。** 文件摘要会对着内嵌 PKCS#7 重新校验，但证书链、吊销和时间戳权威性**不**验证（那需要 CryptoAPI/WinVerifyTrust）。
- **目录签名不可见。** 大多数 Windows 系统二进制靠目录 `.cat` 文件获得信任，而不是内嵌签名；Windows 可能报"有效"，而本工具报"无内嵌签名"。两句话都是真的。
- **基于导入的推理有盲区。** 运行时解析的 API（对哈希调 `GetProcAddress`、直接 syscall）在导入表里不留痕迹。
- **不做模拟、不做反编译、不做反混淆。** 这是分诊仪器，不是判决书。
- 风险分是用来给文件**互相排序**的启发式，不是"这个东西是恶意软件"的概率。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
