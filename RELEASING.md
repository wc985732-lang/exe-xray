# 发布手册 · exe-xray 上 PyPI

> 给 Chen 自己看的操作手册。目标：把 `exe-xray 0.1.0` 传到 <https://pypi.org>，让任何人 `pip install exe-xray` 就能用。
>
> 当前状态（2026-11-07 本地实测）：产物已在干净目录构建并通过全部检查，**只差一个 PyPI token 和一条 `twine upload` 命令**。

---

## 0. 一句话现状

| 项目 | 状态 |
| --- | --- |
| 构建产物 | ✅ wheel 76,234 B / sdist 105,318 B，已在干净临时目录产出 |
| 空 venv 安装 | ✅ wheel 和 sdist 都装在零依赖的空 venv 里，`exe-xray --version` 与真实分析都正常 |
| wheel 内容 | ✅ 16 项：10 个模块 + 6 个 dist-info 项，无 `tests/`、无 `*.exe`、无 `*.md`、无 `__pycache__` |
| `twine check` | ✅ 两个产物均 PASSED（twine 7.0.0 + readme-renderer 46.0） |
| PyPI 名字 | ✅ `exe-xray` 在 PyPI / TestPyPI 均返回 404，名字空着 |
| 版本号 | ✅ `0.1.0` 在 PyPI 上不存在，可以发 |
| 自动发布 | ❌ 没有。`.github/workflows/tests.yml` 只到「构建 + 检查 + 存 artifact」，不 upload |
| 账号 | ❌ 没有 PyPI 账号，需要你自己注册 |

**唯一的阻塞项就是账号和 token。** 剩下全在这份文档里。

---

## 1. 首次发布需要准备什么

### 1.1 账号

1. 注册：<https://pypi.org/account/register/>
2. 立刻开 2FA（TOTP，用 1Password / Authy / Microsoft Authenticator 扫码）。**PyPI 强制要求**上传账号开 2FA，不开会直接挡住上传。
3. 准备好恢复码，存进密码管理器。

### 1.2 API token

路径：登录后 → Account settings → **API tokens** → Add API token。

- **第一次只能建 account-scoped token**：因为项目 `exe-xray` 还不存在，PyPI 不允许给不存在的项目建 project-scoped token。
- 名字随便起，比如 `exe-xray-bootstrap`。
- token 长这样：`pypi-AgEIcHlwaS5vcmcCJD...`，**只显示一次**，关掉页面就再也看不到，只能重建。
- 首次上传成功后，建议：删掉这个 account-scoped token，改建一个 **project-scoped**（Scope 选 `exe-xray`），这样泄漏了也只能动这一个项目。

### 1.3 token 存哪（三选一，按推荐排序）

| 方案 | 适合 | 代价 |
| --- | --- | --- |
| **A. Windows 凭据管理器（keyring）** | 自己机器上反复发布 | 交互输入一次，之后 `twine upload` 自动取，磁盘上不留明文 |
| **B. `~/.pypirc`** | 要脚本化、要记 testpypi + pypi 两套 | 明文落在 `C:\Users\chen\.pypirc`，必须收紧 ACL |
| **C. 一次性环境变量** | 只发一次、发完就不想留痕 | 关窗口即失效，最干净但每次都要重来 |

**明确不要做的四件事**：写进 git 里任何文件、写进 `pyproject.toml`、写进提交过的 `.ps1`、贴进任何聊天窗口或 issue。

> `.gitignore` 里已经有 `*token.txt` 和 `.env`，这是第一道网，但它挡不住 `RELEASING.md` 里贴 token 这种自伤行为。

---

## 2. 构建产物

### 2.1 推荐：干净临时目录（本轮实测路径）

不要直接在仓库里 build，会留下 `build/`、`dist/`、`*.egg-info/`（虽然 `.gitignore` 已忽略，但会干扰下次 `pip wheel` 的判断）。

```powershell
# 1) 建临时目录 + 复制源码（排除 .git 和构建残留）
$T = Join-Path $env:TEMP "exe-xray-rel-$(Get-Random)"
New-Item -ItemType Directory $T | Out-Null
$REPO = "C:\Users\chen\Documents\deepseek-harness\default-workspace\exe-xray"
robocopy $REPO "$T\src" /E /XD .git build exe_xray.egg-info __pycache__ "tests\fixtures" /NFL /NDL /NJH /NJS | Out-Null

# 2) 在副本里构建
cd "$T\src"
python -m pip wheel . -w "$T\wheelhouse" --no-deps
python -c "from setuptools.build_meta import build_sdist; build_sdist(r'$T\dist')"

# 3) 看结果
Get-ChildItem "$T\wheelhouse", "$T\dist" | Select-Object Name, Length
```

等价的标准写法（要 `pip install "build>=1.2"`，CI 用的就是这条）：

```powershell
python -m build --sdist --wheel --outdir "$T\dist"
```

### 2.2 更省事：直接下 CI 的 artifact

GitHub → Actions → 最近一次 `tests` 运行 → job **`build sdist + wheel`** → 页面底部 Artifacts → 下载 `dist.zip`（保留 7 天）。
里面的 wheel / sdist 与本地构建结果一致（CI 里同样跑了 `twine check`、wheel 内容断言、空 venv 安装、`exe-xray --version`）。

**好处**：产物由 CI 的干净环境产出，比本机更可信。**前提**：那次 CI 是绿的、commit 就是你要发的那个 commit。

---

## 3. 上传前自检（30 秒）

```powershell
# 元数据 + 长描述渲染
python -m twine check "$T\dist\*", "$T\wheelhouse\*"

# 指纹留档（发给别人/写 CHANGELOG 时贴这个）
Get-ChildItem "$T\wheelhouse", "$T\dist" |
  ForEach-Object { "{0}  {1} B  {2}" -f $_.Name, $_.Length, (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
```

本轮实测值（用来核对是不是同一份东西）：

```
exe_xray-0.1.0-py3-none-any.whl   76,234 B  73f69dcd40829d3d6911f0fd62ff763dc47bf2314dc1bee32ccdbe67ee6379c0
exe_xray-0.1.0.tar.gz            105,318 B  5004828f249cf5f1ff3388baffcaa435e8b3a72d68e1cd9307b7006c0b41c20b
```

必须成立的硬条件（CI 里也断言了同一组，别绕过）：

- wheel 里 **只有 16 项**：`exe_xray/` 下 10 个 `.py` + `dist-info/` 下 6 项（METADATA、RECORD、WHEEL、entry_points.txt、licenses/LICENSE、top_level.txt）。
- **不允许**出现 `tests/`、任何 `*.exe`、任何 `*.md`、`*.txt`（dist-info 除外）、`__pycache__`。
- `METADATA` 里 `Name: exe-xray`、`Version: 0.1.0`、`Requires-Python: >=3.9`、4 条 `Project-URL`、`License-File: LICENSE`、15 条 `Classifier`。
- 空 venv 装完 `pip list` 里只有 `exe-xray` 和 `pip`（运行时零依赖）。

---

## 4. 上传

### 4.1 先打 TestPyPI 演习（首次强烈建议）

TestPyPI 是完全独立的沙盒，传错了没人看见，而且不占正式名字。

先注册 <https://test.pypi.org/account/register/>（独立账号，和正式站不通用），建一个 token，然后在 `C:\Users\chen\.pypirc` 里写好两个 section（见 §4.3），或者直接：

```powershell
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = "pypi-AgEI...（TestPyPI 的 token）"
python -m twine upload --repository-url https://test.pypi.org/legacy/ "$T\wheelhouse\*", "$T\dist\*"
Remove-Item Env:TWINE_PASSWORD
```

装回来验证（TestPyPI 上没有依赖的话，这条能跑通就说明元数据没问题）：

```powershell
python -m venv C:\Temp\v-test
C:\Temp\v-test\Scripts\python.exe -m pip install --index-url https://test.pypi.org/simple/ --no-deps exe-xray==0.1.0
C:\Temp\v-test\Scripts\exe-xray.exe --version
```

### 4.2 正式上传（真正的最后一步）

```powershell
# 方式 A：keyring（推荐）。第一次会问用户名/密码，之后自动记住
python -m twine upload "$T\wheelhouse\*", "$T\dist\*"
# 用户名填：__token__
# 密码填：pypi-AgEI...

# 方式 B：会话内环境变量（交互读取，不进 PowerShell 历史）
$sec = Read-Host -AsSecureString "PyPI token"
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
python -m twine upload "$T\wheelhouse\*", "$T\dist\*"
Remove-Item Env:TWINE_PASSWORD
```

`--repository` 的用法（默认就是 pypi，写不写都行）：

| 命令 | 目标 |
| --- | --- |
| `twine upload dist/*` | 正式 PyPI（`repository = pypi`，默认） |
| `twine upload --repository testpypi dist/*` | 走 `.pypirc` 里的 `[testpypi]` |
| `twine upload --repository-url https://test.pypi.org/legacy/ dist/*` | 直接给 URL，覆盖 `--repository` |
| `twine upload --skip-existing dist/*` | 文件已存在就跳过（只对 PyPI 有效） |
| `twine upload --verbose dist/*` | 卡住时看它到底在干什么 |

**别照抄网上的 `--password -`**：那是 `gh` / `poetry` 的写法，twine 不读 stdin（已翻 twine 7.0.0 源码确认无 stdin 分支）。twine 只认 `-p`、`TWINE_PASSWORD`、`.pypirc`、keyring 这四条路。

### 4.3 `~/.pypirc` 替代方案

文件：`C:\Users\chen\.pypirc`（注意前面那个点）

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-AgEI...（正式 token）

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-AgEI...（TestPyPI token）
```

写完一定要收紧权限（Windows 上等价于 `chmod 600`）：

```powershell
icacls "$env:USERPROFILE\.pypirc" /inheritance:r /grant:r "$($env:USERNAME):(R,W)"
```

放别处也行，用 `--config-file D:\secret\pypirc` 指定。

`.pypirc` 里的明文密码，任何能读你用户目录的进程都能拿到——**这是它的主要缺点**，所以只在需要脚本化时才用。

---

## 5. 发布后怎么验证

```powershell
# 1) 等 1–3 分钟（CDN 有缓存），在完全空的 venv 里装
python -m venv C:\Temp\v-py
C:\Temp\v-py\Scripts\python.exe -m pip install --no-cache-dir exe-xray==0.1.0

# 2) 跑起来
C:\Temp\v-py\Scripts\exe-xray.exe --version
#    期望输出：exe-xray 0.1.0

# 3) 真实分析（拿仓库里生成的合成样本，不是真恶意软件）
python C:\Users\chen\Documents\deepseek-harness\default-workspace\exe-xray\tests\make_fixtures.py
C:\Temp\v-py\Scripts\exe-xray.exe C:\Users\chen\Documents\deepseek-harness\default-workspace\exe-xray\tests\fixtures\packed.exe --compact

# 4) 确认零依赖
C:\Temp\v-py\Scripts\python.exe -m pip list
#    期望：只有 exe-xray 和 pip
```

再到网页上肉眼核对 4 件事：

1. <https://pypi.org/project/exe-xray/> 首页长描述渲染正常（标题、表格、代码块都在）。
2. 左侧栏 **Project links** 四条齐全：Homepage / Repository / Issues / Changelog。
3. **License** 显示 MIT，classifiers 里能看到 `Topic :: Security`。
4. **`README` 里的相对链接会 404**（详见 §8 第 1–3 条，发布前改掉即可）。

```powershell
# 5) 想确认 sdist 也能装
C:\Temp\v-py\Scripts\python.exe -m pip download exe-xray==0.1.0 -d C:\Temp\dl --no-deps --no-binary :all:
```

---

## 6. 版本号升级流程（现在是两处，真风险）

当前版本号写在**两个地方**，且两处都在生效：

| 文件 | 行 | 作用 |
| --- | --- | --- |
| `pyproject.toml` | `version = "0.1.0"` | 决定 wheel/sdist **文件名**、`METADATA` 里的 `Version`、PyPI 上显示的版本 |
| `exe_xray/__init__.py` | `__version__ = "0.1.0"` | 决定 `exe-xray --version` 打印什么（`cli.py` 里是 `from . import VERSION`） |

**漂移风险**：两处不一致时，`pip show exe-xray` 说 `0.1.1`，`exe-xray --version` 却说 `0.1.0`；更糟的是 `__init__.py` 忘了改，PyPI 上挂的是 0.1.1 但用户看到 0.1.0。
而且**目前没有任何测试断言二者一致**——`tests/` 里没有比对版本的用例，CI 也只打印 `VERSION` 不校验。也就是说这个漂移现在**无人拦截**。

### 解法 A（推荐，一处真源）：让 setuptools 从代码读版本

```toml
# pyproject.toml
[project]
name = "exe-xray"
dynamic = ["version"]        # 删掉 version = "0.1.0"

[tool.setuptools.dynamic]
version = { attr = "exe_xray.__version__" }
```

之后只改 `exe_xray/__init__.py` 一处，`pip wheel` 会自动读它。代价：构建时要 import 包（本包零依赖、无副作用，安全）。

### 解法 B（保留 pyproject 为真源）：让代码读安装元数据

```python
# exe_xray/__init__.py
from importlib.metadata import PackageNotFoundError, version as _dist_version

try:
    __version__ = _dist_version("exe-xray")     # 装好之后取真实安装版本
except PackageNotFoundError:                     # 从源码目录直接跑时没有元数据
    __version__ = "0.0.0.dev0"

VERSION = __version__
__all__ = ["VERSION", "__version__"]
```

代价：在未安装的 checkout 里 `--version` 会显示 `0.0.0.dev0`（`xray.py` 就是这种用法），需要接受这个行为差异。

### 无论选哪种，补一条测试守门

```python
def test_version_matches_metadata(self):
    from importlib.metadata import version
    import exe_xray
    self.assertEqual(exe_xray.__version__, version("exe-xray"))
```

### 发新版本的完整顺序

1. 改版本号（改哪处取决于上面选 A 还是 B，A 只改 `__init__.py`）。
2. `python -m unittest discover -s tests -v` —— 116 个测试要全绿。
3. 更新 `CHANGELOG.md`（加 `## [0.1.1] - YYYY-MM-DD` 段落）。
4. `git commit` + `git tag v0.1.1`（tag 与版本号一致，别写 `0.1.1` 和 `v0.1.0`）。
5. 重新构建（§2），`twine check` 后再传。
6. **`0.1.0` 一旦发出去就永远不能被覆盖**，见下一节。

---

## 7. 回滚与补救（PyPI 上的版本改不了，只能 yank）

PyPI 的核心规则：**同一个文件名只能上传一次，永远不能覆盖**。已发布的文件不可修改、不可替换。

| 想做的事 | 能不能做 | 怎么做 |
| --- | --- | --- |
| 改 README 错字 | ✅ 能 | 项目页 → Manage → 直接改 **Description**，不需要发新版 |
| 改错字但元数据是错的（如 classifiers） | ⚠️ 只能发新版 | 改 `pyproject.toml`，升 `0.1.1` 重发 |
| 发现代码有 bug | ⚠️ 只能发新版 | 升 `0.1.0.post1`（只修 bug，不算新功能）或 `0.1.1` |
| 让某个版本从 `pip install exe-xray` 里消失 | ✅ **yank** | 项目页 → Releases → 选版本 → **Yank release** |
| 彻底删除某个版本的文件 | ⚠️ 有条件 | Release 页 **Delete** 只在「该版本只剩一个文件」时可用；删完同号也**不能**再传 |
| 整包下架 | ❌ 自己做不了 | 邮件 `admin@pypi.org` 说明原因，只用于恶意包/法律问题 |

**yank 到底做什么**：给版本挂黄条「This release has been yanked」，`pip install exe-xray`（不带版本）会跳过它，但 `pip install exe-xray==0.1.0` 仍然装得上，`pip install exe-xray<0.2` 默认也会跳过。所以 yank 是「劝退」不是「删除」。可 un-yank。

**所以发布前的检查比发布后的补救便宜 100 倍。** §3 那 30 秒不要省。

---

## 8. 发布前查到的坑（需要你拍板，这些文件我一个都没动）

| # | 位置 | 问题 | PyPI 上的实际表现 | 建议 |
| --- | --- | --- | --- | --- |
| 1 | `README.md` 第 5 行 `[简体中文](README.zh-CN.md)` | 相对路径 | 变成 `https://pypi.org/project/exe-xray/0.1.0/README.zh-CN.md` → **404** | 改绝对：`https://github.com/wc985732-lang/exe-xray/blob/main/README.zh-CN.md` |
| 2 | `README.md` 第 238 行 `[NOTES-packing.md](NOTES-packing.md)` | 相对路径 | 同上 → **404**（这条最伤，它是打壳检测的完整推导文档） | 改绝对：`https://github.com/wc985732-lang/exe-xray/blob/main/NOTES-packing.md` |
| 3 | `README.md` 第 489 行 `[LICENSE](LICENSE)` | 相对路径 | 同上 → **404** | 改绝对：`https://github.com/wc985732-lang/exe-xray/blob/main/LICENSE` |
| 4 | `pyproject.toml` + `exe_xray/__init__.py` | 版本号两处，无测试守门 | 版本可见性漂移 | 见 §6 的解法 A / B |
| 5 | `.gitignore` | 已含 `build/`、`dist/`、`*.egg-info/`、`__pycache__/` | 没漏关键项 | 可选补 `wheelhouse/`、`.venv*/` |
| 6 | sdist 内容 | 带了 `tests/test_*.py` 4 个文件，但**不带** `tests/make_fixtures.py`，也不带 `tests/fixtures/` | `pip install` 不受影响；从 sdist 跑测试会 import 失败 | 二选一：`MANIFEST.in` 里 `prune tests`，或 `recursive-include tests *.py` 把 `make_fixtures.py` 一起带上 |
| 7 | `pyproject.toml` `license = { text = "MIT" }` | PEP 639 之前的旧写法 | twine 7 不报错，setuptools ≥77 会打 deprecation warning | 可以下次顺手改 `license = "MIT"` + `license-files = ["LICENSE"]`，不阻塞本次发布 |
| 8 | PyPI 名字 | `exe-xray` 目前无人占用（PyPI / TestPyPI 双 404） | — | 想发就尽早发，名字被别人抢了就只能改名 |

关于 `README.zh-CN.md` 和 `NOTES-packing.md` **自身**：

- `README.zh-CN.md` 里的 3 条相对链接（第 5 行 `README.md`、第 202 行 `NOTES-packing.md`、第 418 行 `LICENSE`）**在 PyPI 上不会被渲染**——这个文件根本没上传，PyPI 只显示 `README.md`。所以这 3 条只在 GitHub 上生效，**不用动**。
- `NOTES-packing.md` 全文没有任何相对链接，不需要改。
- `CHANGELOG.md` 只在 `pyproject.toml` 的 `Project-URL` 里出现，已经是绝对 URL，PyPI 上正常。README 正文其实**没有**链它——将来如果要链，记得直接用绝对地址。

---

## 9. 可选的下一步：Trusted Publishing（不用 token）

现在每次发布都得手工 `twine upload`。想让「打 tag 就自动发」，用 PyPI 的 OIDC 信任发布，**完全不需要 token**：

1. PyPI 侧：项目页 → Settings → Publishing → Add a new pending publisher
   - Owner: `wc985732-lang` / Repository: `exe-xray`
   - Workflow: `publish.yml` / Environment: `pypi`
2. 新增 `.github/workflows/publish.yml`：

```yaml
name: publish
on:
  release:
    types: [published]
permissions:
  contents: read
  id-token: write          # OIDC 必需
jobs:
  pypi:
    runs-on: ubuntu-latest
    environment: pypi
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python -m build --sdist --wheel
      - run: python -m twine check dist/*
      - uses: pypa/gh-action-pypi-publish@release/v1   # 不要传 password
```

首次发布建议还是手工走一遍（先确认产物和元数据没问题），之后再把这条链路接上。

---

## 附录 A：本轮验证记录（可复现）

环境：Windows 11 / Python 3.12.4 / twine 7.0.0 (readme-renderer 46.0) / 构建在 `%TEMP%` 下的独立副本，仓库未被写入。

**产物**

| 文件 | 大小 | SHA-256 |
| --- | --- | --- |
| `exe_xray-0.1.0-py3-none-any.whl` | 76,234 B | `73f69dcd40829d3d6911f0fd62ff763dc47bf2314dc1bee32ccdbe67ee6379c0` |
| `exe_xray-0.1.0.tar.gz` | 105,318 B | `5004828f249cf5f1ff3388baffcaa435e8b3a72d68e1cd9307b7006c0b41c20b` |

**`twine check`**

```
Checking ...\wheelhouse\exe_xray-0.1.0-py3-none-any.whl: PASSED
Checking ...\dist\exe_xray-0.1.0.tar.gz: PASSED
```

**wheel 内容（16 项，无泄漏）**

```
exe_xray/__init__.py          159      exe_xray-0.1.0.dist-info/METADATA   26,540
exe_xray/__main__.py           79      .../RECORD        1,258
exe_xray/analyze.py        69,220      .../WHEEL            91
exe_xray/authenticode.py   32,929      .../entry_points.txt 47
exe_xray/capabilities.py   19,089      .../licenses/LICENSE 1,078
exe_xray/cli.py            15,503      .../top_level.txt      9
exe_xray/der.py             5,063
exe_xray/pe.py             34,928
exe_xray/report.py         14,489
exe_xray/strings.py        11,996
```

**空 venv 安装 + 运行**

```
# wheel
pip list → exe-xray==0.1.0, pip==24.0      （零运行时依赖）
exe-xray --version → exe-xray 0.1.0
exe-xray tests\fixtures\clean.exe  → 退出码 0
exe-xray tests\fixtures\packed.exe → 退出码 0（VERDICT: packing likely，risk medium 35/100）

# sdist
pip list → exe-xray==0.1.0, pip==24.0
exe-xray --version → exe-xray 0.1.0
exe-xray tests\fixtures\suspicious.exe --json → 退出码 0
```

**METADATA 关键字段**

```
Metadata-Version: 2.4
Name: exe-xray
Version: 0.1.0
Summary: Static, human-readable health check for Windows executables
License: MIT
License-File: LICENSE
Requires-Python: >=3.9
Project-URL: Homepage / Repository / Issues / Changelog   (4 条，均为 github.com/wc985732-lang/exe-xray)
Classifier: 15 条（Dev Status 4-Beta / Console / Info Tech / MIT / OS Independent / Py3 3.9–3.13 / CPython / Topic :: Security / Disassemblers）
Provides-Extra: dev   →  build>=1.2, twine>=5.0
```

**PyPI 可用性**

```
https://pypi.org/pypi/exe-xray/json            → 404（名字空着）
https://pypi.org/pypi/exe-xray/0.1.0/json      → 404（版本空着）
https://test.pypi.org/pypi/exe-xray/json       → 404（TestPyPI 也空着）
```
