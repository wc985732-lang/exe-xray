# 加壳检测：真实样本验证报告

工作笔记，供合并进 README 用。所有结论来自这台机器上真实存在的 PE 文件（只读取字节，不执行、不联网、不装 UPX）。

---

## 0. 结论先行

* **改之前，这套启发式撑不住"检测加壳"四个字。** 不是因为漏报少，而是因为它的三根支柱全都在真实数据上失灵：
  1. **段名命中**是对的方向，但把"一个 packer"记成了两次（UPX0 40 + UPX1 40 = 80），一个两段 stub 光靠段名就过线；
  2. **"熵 > 7.2" 和 "导入表函数数 < 12" 这两个信号在 .NET 程序集上系统性误报** —— 托管 IL 的 `.text` 天然 7.5–8.0，托管映像按 CLR 约定只导入 1 个函数。这一条把 **微软自家装的 Office 插件和全部 .NET 运行时 DLL** 判成 "possibly packed"；
  3. **"没有导入表"** 是 21 个误报里出现最多的理由（16 次）。命中对象包括纯资源 DLL（`sbresources.dll`/`spwizimg.dll`/`whesvc_assets.dll` —— 字符串、清单、ETW 元数据，根本没有代码段）、`ntdll.dll`（2523 个导出、0 个导入，走系统调用）、`winload.exe`/`winresume.exe`/`tcblaunch.exe`（自带加载器的引导程序）。同一条规则在第三方软件上把 **Oracle VirtualBox 的 4 个前端**判成 `possibly`。
  4. **"虚大段"（VirtualSize ≫ RawSize）在数据段上恒真**：`ntoskrnl.exe` 单靠 5 个按需分页数据段拿到 50 分。
  5. **"段熵 > 7.2" 加"段名不变"会把 Docker CLI 判成 100 分满壳**：`docker.exe`/`com.docker.build.exe` 里若干高熵段（段名 `/19`、`/32`、`/65`…）每段各记 20 分，5 段直接顶到 100。
* **改之后：** 3 个真壳（2×UPX、1×VMProtect）全部 `likely packed / protected`；**4166 个 System32 映像 0 误报**（改前 21 个）；第三方 1491 个 exe 只剩 2 个非零判定（1 个真 UPX + 1 个 PE 头被改写的 OEM 程序），**改前是 19 个（其中 18 个是误报）**；34 个"高熵代码段"样本里其余全部回到"无壳迹象"。
* **它现在能做什么：** 认得出**留下身份痕迹的壳**（段名/魔数）和**留下结构痕迹的壳**（未初始化的可写可执行段、只解析 LoadLibrary/GetProcAddress 的导入表、被改写的段名）。这两类覆盖了现实中绝大多数 UPX/ASPack/MPRESS/加壳机产出。
* **它做不到什么：** 认不出**没有结构痕迹的壳**——段名正常、导入表正常、payload 落在已初始化的可执行段里的自定义加密器，只能靠"熵高"这一个与合法高熵映像重叠的信号，因此本工具永远只能说 "possibly"，说不出"是"。托管加壳（ConfuserEx/.NET Reactor 一类）**完全不在能力范围内**，我们只认被改坏的 PE 头，不认加密后的 IL。**"检测加壳"这四个字它现在部分撑得住：撑得住命名壳与结构壳，撑不住"这文件到底有没有壳"这种二选一。**

---

## 1. 真实样本从哪来（没有下载任何东西）

用只读脚本遍历本机：`C:\Windows\System32`、`C:\Program Files`、`C:\Program Files (x86)`、`D:\steam`、`%LOCALAPPDATA%\Microsoft\WinGet`、`E:\Apps`，共读头 **14951** 个 PE。

* **找真壳**：按段名白名单（`upx0/upx1/.vmp0/.vmp1/.aspack/.mpress1/...`）扫头 → 命中 3 个；再按"可执行段熵 > 7.2"扫一遍 → 34 个，人工核对后确认其中 3 个就是前面那 3 个真壳，其余是托管 IL 或微软自带的高熵代码。
* **找误报**：把 System32 全部 4166 个 `*.exe`+`*.dll` 过一遍检测器。
* **判定"真壳"的硬证据**（不是猜）：
  * `istask.dll` / `CrashReport.exe`：段名 `UPX0`+`UPX1`，`UPX!` 魔数，`UPX0` 磁盘 0 字节/内存 64 KiB–905 KiB 且 RWX，入口点在 `UPX1`，导入表 8 个函数（`LoadLibraryA`/`GetProcAddress`/`VirtualProtect`）。
  * `wcprobe.dll`（微信 4.2.0.13，7.96 MB）：段名 `.vmp0`/`.vmp1`（3.3 MB + 1.9 MB），入口点落在 `.vmp1`（第 8/10 段），原始 `.text` 只有 2.29 MB —— VMProtect 虚拟化后的典型形状。

---

## 2. 真实样本调查表

熵 = 该映像**可执行段**里的最高熵（没有代码段的写 0.000）。工具判定写 `改前 → 改后`。

| 文件路径 | 大小 (B) | 熵 | 段名 | 导入函数数 | 工具判定 | 我认为真相 |
|---|---|---|---|---|---|---|
| `C:\Program Files\IGRS\Mechrevo\un_res\istask.dll` | 46 480 | 7.889 | UPX0, UPX1, .rsrc | 8 | 100 likely → **100 likely** | **UPX 壳** |
| `C:\Program Files\ToDesk\CrashReport.exe` | 681 360 | 7.929 | UPX0, UPX1, .rsrc | 8 | 100 likely → **100 likely** | **UPX 壳** |
| `C:\Program Files\Tencent\Weixin\4.2.0.13\wcprobe.dll` | 7 963 696 | 7.141 | .text … .vmp0, .vmp1, .reloc, .rsrc | 28 | 100 likely → **75 likely** | **VMProtect 壳**（虚拟化段熵只有 7.34/7.49，靠段名定性） |
| `C:\Program Files\OEM\机械革命控制中心\AiStoneService\GCUBridge.exe` | 682 208 | 7.991 | `7~I((CD\x1e`, .text, .rsrc | 0 | 80 likely → **40 possibly** | **托管壳/保护器**（段名含 0x1E 控制字节、RWX、无导入表 —— PE 头被改写过） |
| `C:\Windows\System32\notepad.exe` | 360 448 | 6.238 | .text, fothk, .rdata, … | 315 | 0 → **0** | 干净 |
| `C:\Windows\System32\cmd.exe` | 339 968 | 6.295 | .text, fothk, … | 286 | 10 → **0** | 干净（改前 `.data` 虚大被判"自解压 stub"） |
| `C:\Windows\System32\ntoskrnl.exe` | 13 131 136 | 6.506 | 39 段，含 Pad1–Pad4 | 211 | 50 possibly → **15** | 干净（WIN32K 内核，无壳） |
| `C:\Windows\System32\edit.exe` | 266 800 | 6.244 | .text, .rdata, .data, … | 106 | 30 possibly → **0** | 干净 |
| `C:\Windows\System32\winload.exe` | 1 905 856 | 6.542 | .text, TRANSIT, … | 0 | 35 possibly → **0** | 干净（引导程序自带加载器，0 导入是常态） |
| `C:\Windows\System32\hvax64.exe` | 1 990 008 | 6.469 | .rdata … Pad1, .text, Pad2 … | 1 | 30 possibly → **29** | 干净（Hyper-V hypervisor） |
| `C:\Windows\System32\ntdll.dll` | 2 558 392 | 6.456 | .text, SCPCFG…, .rdata … | 0 | 35 possibly → **0** | 干净（2523 导出、0 导入，走 syscall） |
| `C:\Windows\System32\msobjs.dll` | 73 728 | 0.000 | .rdata, .rsrc | 0 | 25 → **0** | 干净（纯资源 DLL，没有代码段） |
| `C:\Windows\System32\tzsync.exe` | 283 136 | 5.999 | .text, .rsrc | 0 | 25 → **0** | 干净（托管 EXE，微软自己就没给导入表） |
| `C:\Windows\System32\d3dcsx_42.dll` | 5 554 512 | **7.831** | .text, .data, .pdata, .rsrc, .reloc | 65 | 20 → **25** | 干净（着色器编译器，`.text` 里嵌着色器字节码，合法高熵） |
| `C:\Program Files\Microsoft Office\…\Microsoft.DataIntegration.RecommendTransform.Join.dll` | 999 264 | 7.982 | .text, .rsrc, .reloc | 1 | 40 possibly → **0** | 干净（托管程序集） |
| `C:\Program Files\dotnet\shared\…\System.Text.Encoding.CodePages.dll` | 871 088 | 7.519 | .text, .data, .reloc | 0 | 45 possibly → **0** | 干净（.NET Core 程序集，0 导入是 CoreCLR 约定） |
| `C:\Program Files\Git\mingw64\bin\Avalonia.DesignerSupport.dll` | 218 464 | 7.676 | .text, .rsrc, .reloc | 1 | 40 possibly → **0** | 干净（托管程序集） |
| `C:\Program Files\Python312\python.exe` | 103 704 | 5.635 | .text, .rdata, …, .rsrc | 44 | 0 → **0** | 干净 |
| `C:\Program Files\OEM\…\MyControlCenter\OSDTpDetect.exe` | 586 464 | 7.933 | .text, .rsrc | 0 | 45 possibly → **0** | **不确定**（托管、无导入表、IL 高熵；与 `tzsync.exe` 同形，头却是 OEM 工具的，无法只凭静态特征定性） |
| `C:\Program Files\OEM\…\DefaultTool\DefaultTool.exe` | 1 168 632 | 7.498 | .text, .rsrc | 0 | 45 possibly → **0** | **不确定**（同上） |
| `C:\Program Files (x86)\Mechrevo\机械革命电子保修卡\电子保修卡.exe` | 3 072 688 | 7.859 | .text, .rsrc, .reloc | 1 | 40 possibly → **0** | 干净（托管程序集，1 个 `_CorExeMain`） |
| `C:\Program Files\Oracle\VirtualBox\VBoxHeadless.exe` | 982 152 | 6.474 | .rdata … `.rwxpg` … .data | 0 | 50 possibly → **25** | 干净（自带 kLdr 加载器，`.rwxpg` 是 4 KiB 可执行页池） |
| `C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe` | 982 664 | 6.476 | 同上 | 0 | 50 possibly → **25** | 干净（同上） |

共 25 行：真壳 3 个（前 3 行），PE 头被改写的托管保护器 1 个（GCUBridge），干净 19 个，无法定性 2 个（均为 OEM 自带工具）。

---

## 3. 失灵清单（每条都带证据）

### 3.1 误报（正常程序被判成壳）

| # | 被误报的文件 | 改前分数 | 误报根因 | 证据 |
|---|---|---|---|---|
| F1 | 全部 .NET 程序集（Office ADDINS、.NET 运行时、Avalonia…） | 20–45 | `熵>7.2` + `导入<12` 在托管映像上恒成立 | `System.Text.Encoding.CodePages.dll`：`.text` 熵 7.519、导入 0 → 45 分。IL 里的 token 流和 `#US` 字符串堆本来就近随机 |
| F2 | `tzsync.exe`（Windows 自带） | 30 | "没有导入表" | 微软自己的托管 EXE 就没有导入目录（`dir[1]` 为空、文件里没有 `mscoree` 字串） |
| F3 | 纯资源 DLL（`sbresources.dll`/`spwizimg.dll`/`whesvc_assets.dll`/`msobjs.dll`/`Windows.UI.Xaml.Resources.*`…） | 25–45 | "没有导入表"（常叠加 `.rsrc` 熵） | 它们**没有可执行段**，从来不需要导入任何 API |
| F4 | `ntdll.dll` | 30 | "没有导入表" | 2523 个导出、0 个导入：用户态最底层，靠 syscall 进内核 |
| F5 | `ntoskrnl.exe` | 50 | 虚大段规则在数据段/`Pad` 段上发作 | `.data` 虚 1.8 MB/实 64 KB、`PAGEDATA` 虚 111 KB/实 8 KB —— 内核按需分页的正常形态 |
| F6 | `winload.exe` / `winresume.exe` / `tcblaunch.exe` | 35 | "没有导入表" | `windows-boot-driver`/`windows-boot-application`：自带 PE 加载器 |
| F7 | `edit.exe`（微软自带编辑器） | 30 | 512 字节段的虚大比 5× + `.rsrc` 熵 7.57 | 小段被文件对齐凑出来的比例毫无意义；`.rsrc` 里是压缩过的图标 |
| F8 | `hvax64.exe`/`hvix64.exe` | 30 | `导入=1` + `.data` 虚大 | hypervisor 只导入 `KDSTUB.dll` 一个入口 |
| F9 | `cmd.exe` | 10 | `.data` 虚 115 136/实 4 096 | 零初始化数据段，所有链接器都会产生 |
| F10 | Oracle VirtualBox 的 `VBoxHeadless.exe`/`VBoxNetDHCP.exe`/`VBoxNetNAT.exe`/`VirtualBoxVM.exe` | 50 | `.rwxpg` 单页(4 KiB) RWX 零填充段被判"解包目的地" + 空导入表 | VirtualBox 用自带加载器（kLdr）解析 API，所以导入表是空的；`.rwxpg` 是它自己的可执行页池，4 KiB 装不下 800 KiB 的 `.text` |
| F11 | `docker.exe` / `com.docker.build.exe` | **100（满壳）** | 5 个高熵段（段名 `/19`、`/32`、`/65`、`/78`、`/95`）每段各 +20 | Docker CLI 是 Go 产物，构建时被剥过段名；熵规则对**每个**高熵段都记分，叠加即满 |

**总账（用改前算法逐一对 4166 + 1491 个真实文件复算）：System32 21 个非零判定、全部误报；第三方 exe 19 个非零判定，其中 18 个是误报（只有 `CrashReport.exe` 那一个 UPX 是对的）。**

### 3.2 漏报（真壳判成没壳）—— 本次没有在真实机上找到漏报的具名壳

3 个真壳改前就已经 100 分（正是 F1–F9 的反面：段名规则太灵，噪声规则乱加分）。但代码里存在**结构性漏报**，改前改后都要承认：

| # | 漏报种类 | 为什么漏 | 现状 |
|---|---|---|---|
| M1 | 段名被改掉、payload 落在**已初始化**的可执行段里的自定义加密器，导入表"正常" | 只剩"熵高"一个信号，而它与 `d3dcsx_42.dll`（7.83）重叠 | 最高只能到 **possibly (25–55)**，说不了"是" |
| M2 | 托管加壳（ConfuserEx 等：IL 加密、方法体置零） | 本工具不解析 CLR 元数据，只看 PE 头 | 只能靠段名被改坏/新增 RWX 段才可能命中；否则判干净 |
| M3 | VMProtect/Themida 的**虚拟化段熵经常 < 7.2** | 虚拟化后是指令流不是压缩流 | 靠段名定性；段名被抹掉就漏（见 M1） |
| M4 | 只加密 `.rsrc`/数据段、代码段保持原样的壳 | 现在熵证据只看可执行段（这是刻意的取舍，见 §4.2） | 判干净 |

---

## 4. 改进：三层证据 + 每个阈值的出处

### 4.1 三层证据（权重与理由）

```
identity       段名就是 packer 自己的名字           60   一条即可定案
structure      正常链接产物不可能有、解包 stub 必须有  30   一条=可疑，两条=定案
corroboration  实测与合法映像重叠，只能辅证           5–25 单独永远不能定案
```

| 证据 | 权重 | 为什么是这个值 / 这个阈值 |
|---|---|---|
| `PACKER_NAME_EVIDENCE` | 60 | `UPX0`/`.vmp1` 这些字符串只存在于 packer 源码里，没有任何链接器会产出；**按 packer 家族记账，不按段记账**（改前 UPX0+UPX1 各 40 → 一条观测被算成 80） |
| `PACKER_MAGIC_EVIDENCE` | 30 | `UPX!` 魔数；只在段名没命中 UPX 时才计分（段名被改掉、魔数还在的情形）；扫描范围从"前 2 MB"改成**全文件**（3 MB 的 UPX 产物魔数可能落在 2 MB 之后） |
| `UNINITIALISED_CODE_EVIDENCE` | 30 | **可写 + 可执行 + 磁盘 0 字节 + 不小于最大的"有内容可执行段"**。前三条：解包目的地要能被写入（只读的零填充段写不进去），而"零填充 + 可执行"本身是微软链接器的 `Pad2`（`ntoskrnl.exe`/`hvax64.exe` 里各有一份，只读、`DISCARDABLE`）。第四条是不需要魔法数的物理不变量：解出来的程序**不可能比压缩进去的载荷更小**，所以目的地至少要和最大的"有内容可执行段"一样大 —— VirtualBox 的 `.rwxpg` 是 4 KiB 对 800 KiB，永远装不下 |
| `RESOLVER_ONLY_EVIDENCE` | 30 | 导入表 ≤ 12 项、且除了 `LoadLibrary*`+`GetProcAddress`（及 `VirtualProtect/VirtualAlloc/VirtualFree/ExitProcess/GetModuleHandle*` 这类 stub 记账项）之外**什么都没有**。壳必须能在解包后拿到任意 API，这就是那套机制；反过来说，导入表只剩它就说明其余 API 是运行时找的 |
| `MUTATED_SECTION_NAME_EVIDENCE` | 30 | 段名含**非可打印字节**（`GCUBridge.exe` 的 `7~I((CD\x1e`）。PE 段名是工具链选的 8 字节 ASCII，控制字节意味着头被非标准工具改写了 |
| `NO_IMPORTS_EVIDENCE` | **15（辅证）** | 只在**同时满足**：有可执行段、导出 < 25、非托管、非自带加载器的子系统时才计分，而且**不再是结构证据**。原因见 §4.2 末尾：VirtualBox 的 kLdr 证明"空导入表"既可能是壳，也可能是自带加载器的正常程序，PE 头分不出来 |
| `CODE_ENTROPY_EVIDENCE` | 25 | 见 §4.2，**永远不能单独定案** |
| `ENTRY_NOT_IN_FIRST_EVIDENCE` | 15 | 实测 4168 个 System32 映像：**3750 个（90%）入口在第 0 段**，405 个入口根本不在任何段（DLL 无入口），只有 13 个（0.3%）在后面 —— 且全是内核/固件类（`ntoskrnl`、`hvax64`、`mcupdate_*`）。UPX 的入口在 `UPX1`，VMProtect 的入口在 `.vmp1` |
| `FEW_IMPORTS_EVIDENCE` | 15 | `导入 < 12` **且** 文件 ≥ 64 KiB：小文件导入少只是因为它小 |
| `WRITABLE_CODE_EVIDENCE` | 10 | RWX 段；壳的解包目的地要写要执行，但个别 DRM/注入框架也这么干，只作辅证 |
| `SPARSE_CODE_EVIDENCE` | 10 | 可执行段虚 ≫ 实（> 4×）：大部分内容运行时才写进去 |
| `OVERLAY_EVIDENCE` | 10 | overlay > 50% 且 > 4 KiB：安装器/自解压也这样，只作辅证 |
| `UNNAMED_SECTION_EVIDENCE` | 5 | 段名完全空白。改前这段代码是**死代码**：解析器把空名换成 `<0>`，`.strip()` 永远为真，一次都没触发过 |

### 4.2 熵阈值 7.2 为什么不改，而是降权重

实测（每个映像取"最高熵的可执行段"）：

| 群体 | 样本数 | 中位数 | p99 | 最大 |
|---|---|---|---|---|
| System32 存量 Windows 映像 | 3 999 | 6.08 | 6.50 | **7.83**（`d3dcsx_42.dll`，着色器字节码） |
| 本机真实壳的载荷段 | 3 个壳 | — | — | 7.34（`.vmp0`）～ 7.93（`UPX1`） |

**两个区间是重叠的（7.34–7.83）。** 任何把阈值搬到重叠区之外的取值，都会同时错杀一边：抬到 8.0 → 一个壳都抓不到；压到 7.3 → `d3dcsx` 继续误报且抓不到 `.vmp0`。既然没有空隙可站，就把 7.2 留作经典值，**用权重表达它的不可靠**：25 分，单独永远到不了 30 分的可疑线。同理，"托管映像不做熵判断"——IL 熵高是 CLR 的常态，不是壳的证据。

**同样道理降级的两条**：
* "空导入表"（30 → 15，且不再是结构证据）。实测：`ntdll.dll`、一批纯资源 DLL、`tzsync.exe`、VirtualBox 的 4 个前端全都是空导入表。剩下的判据（"有代码 + 导出 < 25 + 非自带加载器子系统"）能把 Windows 自带的那批排除掉，却排不掉 VirtualBox —— 因为它真的用自带加载器。于是这条只能做辅证。
* "托管 EXE 没有 mscoree 导入"：直接删了。`C:\Windows\System32\tzsync.exe` 是微软自带的托管 EXE，导入目录为空、文件里没有 `mscoree` 字串 —— 这条推断不成立，现在只作为**提示**打印，不计分。

### 4.3 verdict 闸门

```
score >= 60 且 至少有一条 identity/structure  → likely packed / protected
score >= 30 且 至少有一条 identity/structure  → possibly packed
否则                                        → no packing indicators
```
没有结构证据时，分数被压到 29 —— 避免出现"判定写 no packing indicators、颜色却按黄色画、分数 45/100"这种自相矛盾的输出（`report.py` 按 60/30 上色，那个文件不在我的写域里）。

---

## 5. 改动前后对比（同一份样本，逐条）

| 文件 | 改前 | 改后 | 变化原因 |
|---|---|---|---|
| `istask.dll` (UPX) | 100 likely | **100 likely** | 段名一次计分 + 未初始化 RWX 段 + 熵 + 入口不在首段 |
| `CrashReport.exe` (UPX) | 100 likely | **100 likely** | 同上 |
| `wcprobe.dll` (VMProtect) | 100 likely | **75 likely** | 去掉 `.data`/`.pdata` 的熵噪声（那是数据段），保留段名 + 可执行段熵 |
| `GCUBridge.exe` | 80 likely | **40 possibly** | 放弃"托管 EXE 无导入表 = 必坏"这条不成立的推断（见 F2），改为：段名被改写 30 + RWX 10 |
| `OSDTpDetect.exe` / `DefaultTool.exe` | 45 possibly | **0** | 托管约定不再当证据 |
| 电子保修卡.exe / DataIntegration.Join.dll / CodePages.dll / Avalonia.dll | 40–45 possibly | **0** | 同上 |
| `ntoskrnl.exe` | 50 possibly | **15** | 虚大段只在可执行段上算，且零填充段必须可写 |
| `edit.exe` | 30 possibly | **0** | 数据段熵不计分，小段比例噪声消失 |
| `winload.exe` | 35 possibly | **0** | 自带加载器子系统豁免 + 要求有代码段 |
| `hvax64.exe` | 30 possibly | **29** | 只剩弱信号，被闸门压回不可疑 |
| `ntdll.dll` | 35 possibly | **0** | 导出 ≥ 25 的底层库豁免 |
| 纯资源 DLL（`sbresources.dll`/`spwizimg.dll`/`msobjs.dll`…） | 25–45 possibly | **0** | 无代码段豁免 |
| `tzsync.exe` | 25 possibly | **0** | 托管无导入表只留提示 |
| `d3dcsx_42.dll` | 20 | **25** | 熵仍是可见信号，但不再接近可疑线 |
| `cmd.exe` | 10 | **0** | 虚大段规则收窄 |
| VirtualBox 四个前端 | 50 possibly | **25** | 解包目的地必须装得下载荷（`.rwxpg` 4 KiB vs `.text` 800 KiB → 不算）+ 空导入表降为辅证 |
| `docker.exe` / `com.docker.build.exe` | **100 likely** | **0** | 那些 `/19`、`/32` 高熵段不是可执行段（Go 的元数据/资源段），熵规则只看代码段、且每个映像只记一次 |

**回归总量（逐文件复算，非抽样）**：
| 语料 | 文件数 | 改前非零判定 | 改后 |
|---|---|---|---|
| `C:\Windows\System32`（exe+dll，≤60 MB） | 4166 | 21（**全误报**） | **0** |
| 第三方 `*.exe`（Program Files / PF(x86) / E:\Apps / D:\steam，16 KiB–80 MB） | 1491 | 19（**1 真 + 18 误报**） | **2**（1 真 UPX + 1 个 PE 头被改写的 OEM 程序，`possibly`） |

**真壳：3/3 保持 `likely`。**

> 过程记录（自我揭短）：我在第一版改动里把"空导入表"升级成了结构证据，还加了"托管 EXE 无 mscoree 导入 = 一定跑不起来"这条推断。那个中间版本在 System32 上**反而更糟**（76 个非零判定）。是"拿全量语料回归"这一步抓出了它，也是它把 `tzsync.exe`（微软自带的空导入表托管 EXE）和 VirtualBox 逼出来的 —— 所以这两条现在分别是"仅提示"和"辅证"。**没有全量回归，这套阈值就是在自娱自乐。**

---

## 6. 残余局限（写进 README 的实话）

1. **本工具不脱壳、不模拟执行**，只看 PE 头与段字节。所以它回答的是"这个文件有没有留下壳的痕迹"，不是"这个文件的代码是不是原始编译产物"。
2. **命名壳、结构壳识别可靠；无痕迹的加密器只能到 "possibly"。** 自定义 crypter 如果把段名改正常、导入表做得像样、payload 放进已初始化的可执行段，本工具最高 25 分（熵），判定仍是"没发现壳的迹象"。
3. **托管（.NET）加壳基本盲区。** 我们只认被改坏的 PE 头（段名/权限/导入表异常），不解析 CLR 元数据、不判断 IL 是否加密。另一条已知边界：`tzsync.exe` 证明"托管 EXE 必须有 mscoree 导入"并不成立，所以这类推断已降级为提示。
4. **VMProtect/Themida 虚拟化段的熵可能低于 7.2**（本例 `.vmp0` = 7.34、`.vmp1` = 7.49，而 `.text` 只有 6.08）——它们靠段名定性；段名抹掉就到不了 30 分。
5. **自带加载器的程序与壳 stub 在 PE 头层面不可区分。** VirtualBox（kLdr）、`ntdll.dll` 这类程序本来就不需要导入表，`no imports` 因此只能是辅证。同理，`.rwxpg` 这类"可执行页池"看起来和"解包目的地"一样，只能靠尺寸不变量区分。
6. **`.tls` 回调、资源里的第二份 PE、加密的 `.rsrc`** 都不看；overlay 只看比例。
7. **阈值来自这台机器的实测**：读头 14 951 个 PE，逐文件复算 5 657 个（System32 4 166 + 第三方 exe 1 491）。换一个软件生态（大量 Go/Delphi/NativeAOT 产物）应重新测一遍：Go 的 `.text` 熵、NativeAOT 的段布局都可能移动 p99。
8. **真壳样本只有 3 个家族**（UPX×2、VMProtect×1）。ASPack/MPRESS/Themida 只验证了**段名查表**这一条路径，没有真样本验证它们的结构特征。

---

## 7. 给 README 的建议段落

> **加壳检测能做什么、做不到什么**
>
> `exe-xray` 的 packing 一节是**静态证据汇总**，不是脱壳器，也不模拟执行。它把证据分三层：
>
> * **身份**：段名就是壳自己的名字（`UPX0/UPX1`、`.vmp0/.vmp1`、`.aspack`、`.mpress1` …）或壳的魔数（`UPX!`）。一条即可判定"likely packed / protected"。
> * **结构**：正常链接产物不可能有、而自解压 stub 必须有的特征 —— 可写可执行且磁盘 0 字节的段（解包目的地，且它必须装得下要解出来的镜像）、只剩 `LoadLibrary`+`GetProcAddress` 的导入表、含非可打印字节的段名（头被改写）。一条是"possibly"，两条是"likely"。
> * **辅证**：可执行段熵 > 7.2、入口点不在首段、RWX 段、overlay 占比、导入函数偏少、空导入表。这些信号在合法软件里也出现（实测：Windows 自带映像的可执行段熵最高到 7.83，而真实壳的载荷段从 7.34 起，**两个区间重叠**；VirtualBox 和 `ntdll.dll` 本来就没有导入表），所以**单独任何一条都不能把文件判成壳**。
>
> 已知边界：
> * 托管（.NET）程序集的代码熵与导入表由 CLR 约定决定，**不参与判断**；托管加壳（ConfuserEx 等）不在检测范围内。
> * 段名被改掉、导入表做得正常、payload 落在已初始化可执行段里的自定义加密器，最多只能得到 "possibly packed"。
> * VMProtect/Themida 的虚拟化段熵可能低于 7.2，这类样本靠段名识别。
> * 检测器只看 PE 结构与段字节：它不会告诉你"这个程序解包后是什么"，也不会替你判断一个可疑文件是否恶意 —— 要那两件事，需要脱壳或动态分析。
>
> 真实样本验证（本机 4166 个 Windows 自带映像 + 1491 个第三方 `*.exe`）：3 个真壳（UPX×2、VMProtect×1）全部判为 `likely packed / protected`；Windows 自带映像**零误报**，第三方 exe 除真壳外只剩 1 个"possibly"（PE 头被改写过的 OEM 托管程序）。回归测试在 `tests/test_packing.py`，真实样本不在的机器上会 **skip**（skip 表示"此处未验证"，不是"验证通过"）。

---

## 8. 复现方式

```powershell
# 1. 单元 + 回归测试（新增 17 个，真实样本缺失时 skip）
cd <repo>
python -m unittest discover -s tests -q

# 2. 只看加壳相关
python -m unittest discover -s tests -p test_packing.py -v

# 3. 单文件
python -m exe_xray .\some.exe --no-color          # 人类可读
python -m exe_xray .\some.exe --json              # packing.score / verdict / reasons
```

调查用的只读脚本（扫描器、熵分布、真假壳清单）在仓库外的临时目录，未入库：它们只读字节、绝不执行被扫描文件。
