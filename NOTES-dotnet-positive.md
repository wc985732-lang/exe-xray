# 托管保护检测：正向路径测试报告

工作笔记，配套 `tests/test_dotnet.py` 第 7 节与 `NOTES-packing.md`。这一份只讲**能抓**的那一半：合成了哪些 CLR 镜像、每条计分路径被打出多少分、怎么证明这些测试真的会咬人、以及哪些东西到现在仍然是空白。全程只构造字节，不执行、不联网、不跑保护器。

---

## 0. 结论先行

* **改之前：`test_dotnet.py` 的 21 个测试全部是负向的。** 9 个真实程序集 `score=0`、原生程序 `applies=False`、返回结构锁死 —— 一个"分数恒等于 0"的检测器也能全绿。`analyze.py:170-190` 那 8 个权重里，**没有一个被触发过**；"能检测托管保护"在测试层面是不成立的断言。
* **改之后：+16 个正向测试，7 条计分路径全部被打到过。** 每个权重都有至少一个测试指名它、并断言它给出的分数；另外 4 个测试专门钉住"佐证不得单独成立"（`analyze.py:1239-1249` 的降级规则）。
* **做法：手搭 CLR 元数据。** `make_fixtures._clr_header()` 把 MetaData RVA 写死成 0，所以仓库里所有既有 CLR 夹具都停在 `managed metadata unreadable`（`analyze.py:1019-1020`），拿不到任何分数。要进计分器就必须有真正的 `<BSJB>` 元数据根 + `#~` 表流 + `#Strings` 堆 + 可解析的方法体。这部分约 180 行，全在测试文件里，`analyze.py`、`make_fixtures.py` 一个字节没动。
* **突变验证：9 个定点破坏，9 次变红。** 见 §4。没有一条是"改完还绿"。
* **最大空白没变：** 这台机器上**没有任何一个真实被保护的托管样本**。下面的分数证明的是"计分路径可达且标定正确"，不是"真 ConfuserEx 产物一定这样"。谁能拿到一个真样本，第一件事应该是把它塞进 `SAMPLES` 当正向基线。

---

## 1. 合成镜像长什么样

`test_dotnet.py` 里 `_managed_image(...)` 生成一个 PE32：

```
.text   0x400 字节   入口点，什么都不做
clr     CLR 段       0x000 COR20 头(72 字节, 指向下面的元数据根)
                     0x080 BSJB 元数据根
                           版本串 v4.0.30319
                           #~      Module / TypeDef / MethodDef / (ManifestResource)
                           #Strings
                           #GUID   #Blob
                           #US     可选
                     body区 每个方法一个小/胖体，MethodDef 的 RVA 列指向它
                     资源区 (可选) u32 长度 + 原始字节
```

几何是两遍算的：行宽固定，所以元数据长度与它携带的 RVA 数值无关 —— 先用 RVA=0 量长度，再按真实地址重建，并在代码里断言"两遍长度必须相等"，防止几何假设悄悄失效。每个开关只让**一个**被测量的属性为真：

| 开关 | 让什么为真 |
| --- | --- |
| `marker="ConfusedBy"` | `#Strings` 堆里出现保护器标识（真实布局：自定义特性名就在那儿） |
| `marker_wide=True` | 同一标识以 UTF-16LE 出现在 CLR 段尾部（原生 stub 布局） |
| `control_names=True` | 每个方法名以 `\x01` 开头 |
| `broken_rvas=True` | MethodDef 的 RVA 列指向 `0x00F00000`，任何段都不覆盖 |
| `il` 高熵字节 | 方法体是真 IL 的样子但字节不是 |
| `user_strings=bytes(range(256))` | `#US` 堆里是密文形状 |
| `user_strings=None` | 压根没有 `#US` 流 |
| `resource_blob=gzip 头` | 内嵌资源不以 `.NET` 资源魔数开头 |

---

## 2. 每条路径打出的分数（实测，非推算）

| 场景 | score | verdict | family |
| --- | --- | --- | --- |
| 干净合成程序集（8 方法） | 0 | no managed protection indicators | — |
| 只有 `ConfusedBy` 在 `#Strings` | **60** | likely managed protection | ConfuserEx |
| 只有 `.NET Reactor` 在 stub（UTF-16LE） | **60** | likely managed protection | .NET Reactor |
| 只有 12 个控制字符方法名 | **30** | possibly managed protection | — |
| 只有 20 个坏 RVA | **30** | possibly managed protection | — |
| 坏 RVA + Obfuscar 标识 | **90** | likely managed protection | Obfuscar |
| 控制字符名 + ConfuserEx 标识 | **90** | likely managed protection | ConfuserEx |
| 只有不可识别资源 | 0（+10 佐证被清掉） | no managed protection indicators | — |
| 只有高熵 IL（20 体，7.92 bits/byte） | 0（+15 被清掉） | no managed protection indicators | — |
| 只有密文 `#US`（熵 8.00） | 0（+15 被清掉） | no managed protection indicators | — |
| 200 方法、无 `#US` | 0（+10 被清掉） | no managed protection indicators | — |
| 200 方法无 `#US` + Obfuscar 标识 | **70** | likely managed protection | Obfuscar |
| 以上五种全叠在一个镜像上 | **95** | likely managed protection | ConfuserEx |
| 元数据根签名被打坏 | 0 | managed metadata unreadable | — |

分数与 `analyze.py:170-190` 的权重严格对得上：identity 60、rename 30、metadata 30、resource 10、IL 熵 15、`#US` 熵 15、字符串剥离 10，上限 100（`min(score, 100)`，这次没顶到）。

---

## 3. 测试固定下来的三条边界

1. **佐证永不单独成立。** 资源、高熵 IL、密文 `#US`、缺 `#US` 这四条都能在自己的镜像上打出正分，但最终 `score` 必须是 0，且 `reasons` 里必须出现 "corroborating only"（`analyze.py:1245-1248`）。这四个测试是对 `NOTES-packing.md` §4 那次教训的直接守卫。
2. **identity 单独就够判 `likely`。** 60 ≥ `LIKELY_PACKED`。这不是我选的，是现有常量决定的，测试把它钉死：一个只带保护器名字的干净镜像也会读到 `likely`。
3. **读不出来的元数据是结论、不是证据。** 打坏 `BSJB` 签名后 verdict 是 `managed metadata unreadable`、score 仍是 0（`analyze.py:1163-1167`）。测试同时断言 reasons 里写明"无法据此判断"，避免以后有人顺手给这里加分。

---

## 4. 突变验证（`%TEMP%` 副本上改，仓库不动）

| 突变 | 结果 |
| --- | --- |
| `MANAGED_IDENTITY_EVIDENCE = 60` → `0` | 9 个测试变红 |
| `decided = bool(identity or structural)` → `bool(identity)` | 3 红 |
| rename 规则条件改成永假 | 3 红 |
| metadata 规则条件改成永假 | 3 红 |
| 去掉 `(b"ConfusedBy", "ConfuserEx")` 针 | 4 红 |
| 删掉 `if not decided: score = 0` 降级块 | 9 红 |
| `IL_ENTROPY_CEILING` 6.6 → 8.5 | 5 红 |
| 字符串剥离阈值 200 → 200000 | 4 红 |
| 资源规则条件改成永假 | 5 红 |

复跑命令（副本上）：`python -m unittest discover -s tests -p test_dotnet.py -q`。

---

## 5. 没攻下来的东西，以及为什么

1. **没有真实被保护样本当正向基线 —— 这是最要紧的一条。** §2 全部是合成镜像。合成能证明路径可达、权重对得上、降级规则生效；**不能**证明真 ConfuserEx/.NET Reactor 产物会走到这些分支。缺的输入是"一个已知被保护的 .dll"，我这边无法获取（不联网）。
2. **"控制字符名 + 坏 RVA"在同一张镜像上不能共存。** 实测：`broken_rvas` 一开，`_measure_mdef_width`（`analyze.py:970-1004`）在 `spec/spec+2/spec+4` 里挑到一个错的行宽，MethodDef 的 Name 列读出来就是噪声，rename 规则只看到 3/9 而不是 12/13，于是不触发。所以这两个结构证据在这套几何里互斥，测试改成"坏 RVA + identity = 90"并把这个现象写进了注释。**真样本上没有这个矛盾**（行宽是对的，坏 RVA 只影响 RVA 列），但这一点我证明不了。
3. **坏 RVA 的 `rva_share` 不是 0，是 0.25。** 同一个原因：错行宽下有些行的字节碰巧落在段内。所以测试断言的是 `< MDEF_RVA_FLOOR`，不是 `== 0`。顺带一个已记录在案的脆弱点：如果某张镜像的垃圾列碰巧大量解析，`share` 有可能被抬到 0.90 以上而漏报 —— 我这套几何里只到 0.25，离阈值还远，但这条规则没有"下限证据"兜底（例如"RVA 列必须单调"）。
4. **MethodDef 行宽 +2 的那条路径没被合成到。** 注释说本机测过 2995 张真实镜像全部比 ECMA-335 宽两字节，`_measure_mdef_width` 的 `spec+2` 分支只由真实程序集覆盖。我的合成镜像用规范宽度（12 字节），所以那条分支仍只有 §1 那批干净样本能碰。
5. **`ConfusedBy` 只证明了"字符串在文件里"，没证明"它是 CustomAttribute 行"。** `_managed_marker_families`（`analyze.py:1128`）是纯字节扫描，所以真 ConfuserEx 用自定义特性表注册名字、和我在 `#Strings` 里塞同样字节，命中逻辑上等价 —— 但这意味着**任何**碰巧含有 `Dotfuscator` 字样的程序集都会拿 60 分（README 级别的误报面，测试没法证伪）。
6. **没做的结构族：** 方法体被整体加密（RVA 合法、IL 是密文——理论上走 IL 熵，但真混淆器常把 `code_size` 也一起改写）、`#Blob`/`#GUID` 异常、AssemblyRef 里的保护器名字（走的还是同一条字符串路径）、以及"元数据根被搬到非常规位置"。这些都属于同一个计分器的其它入口，不是新规则。
7. **文档缺口（不属于我的写域，报给上游）：** `analyze.py` 多处引用 `NOTES-dotnet.md`（`:1148`、`:1193`、`:1244`、`:976`），但仓库里只有 `NOTES-packing.md`，那个文件不存在。标定数字（2995 张镜像、IL 熵上限 6.6、`#US` 上限 6.2）目前没有可追溯的正文。

---

## 6. 复现

```
python -m unittest discover -s tests -p test_dotnet.py -q     # 37 个，全绿
python -m unittest discover -s tests -q                        # 131 个，全绿
```

新增 16 个，全部在 `tests/test_dotnet.py` 第 7 节，按 `TestSyntheticBaseline` / `TestIdentityEvidence` / `TestStructuralEvidence` / `TestCorroborationOnly` / `TestUnreadableMetadata` 分组；构造器是 `_managed_image`，落盘走 `_verdict_for`（临时文件 + `analyze(skip_strings=True)`，结束即删）。
