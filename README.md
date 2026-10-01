# seal-derive

把密钥材料以"版本"为单位封存，支持口令派生、轮换与吊销，并保留可审计的版本历史。

## 依赖

仅标准库（Python 3.10+）；PBKDF2-HMAC-SHA256 来自 hashlib。

## 安装与运行

无需安装，直接以模块方式运行（目录参数统一为 `--root`）：

```bash
python3 -m seal_derive --root ./state init
```

子命令：`init`、`seal <key_id> <material> [--password P] [--iterations N]`、`load <key_id> [--version V]`、`versions <key_id>`、`active <key_id>`、`set-active <key_id> <version>`、`revoke <key_id> <version>`、`report`。

## 公开接口

`seal_derive.KeyRing(root)`：

- `init() -> None` 建立空密钥环。
- `seal(key_id, material, password=None, iterations=200_000) -> int` 封存材料并返回版本号；给出 `password` 时以 PBKDF2-HMAC-SHA256 派生密钥加密并认证原始 material，持正确口令可完整取回。
- `load(key_id, version=None, password=None) -> bytes` 取回**原始 material 的 UTF-8 bytes**（不是派生值）；`version` 缺省取当前活动版本。一次 load 的版本解析（含缺省时读 active）、吊销校验与解密在同一共享锁快照内完成：并发的 `revoke`/`set_active` 要么在 load 开始前已提交（load 见到新状态），要么等 load 结束后才能提交，已完成的 load 不被稍后的变更追溯否定。解析到已吊销版本抛 `RevokedVersionError`（消息含“已吊销”，CLI 退出码 2）。受口令版本必须传 `password`：缺少口令抛含“缺少口令”的 `ValueError`，口令错误抛含“口令不匹配”的 `ValueError`，记录被篡改、截断或参数不全抛含“记录损坏”的 `ValueError`。旧的仅保存派生值的 `pbkdf2-sha256` 记录无法恢复原 material，抛含“不可恢复的旧记录”的 `ValueError`。
- `versions(key_id) -> list[int]` 升序返回全部版本。
- `active(key_id) -> int` 当前活动版本。
- `set_active(key_id, version) -> None` 把活动版本指向已有历史版本。
- `revoke(key_id, version) -> None` 标记某版本作废。
- `is_revoked(key_id, version) -> bool` 查询作废状态。

## 约定

- 所有写操作立即持久化；进程被杀死后 `recover`/`init` 之外的重开不得丢失已确认的写。
- 所有修改（`init`/`seal`/`set_active`/`revoke`）共用同一把跨进程写锁（目录内 `.keyring.lock`，标准库 `flock`/`msvcrt`，无第三方依赖），在锁内完成读取、校验、变更与 `keyring.json` 的原子替换；读操作取共享锁，配合临时文件 + `os.replace` 不会读到半份文件。
- 等待写锁超过 5 秒抛 `TimeoutError`（文本“获取密钥环写锁超时”，CLI 退出码 1）；持锁进程被强制结束或崩溃后锁由内核自动释放，后续调用在等待窗口内自动接管，不删除或改写 `keyring.json`。
- 非法输入抛出 `ValueError`，未知标识抛出 `KeyError`。
- 每个入口在返回或提交前都会完整校验 `keyring.json` 的已提交状态：顶层 `keys`/版本历史结构、`active` 为非布尔正整数且指向真实版本、版本号唯一且升序、`revoked` 为布尔、`scheme` 已识别、必要字段完整且 Base64/固定长度/iterations/明文 UTF-8 合法。被篡改、截断或结构非法的状态在所有入口统一抛含“记录损坏”的 `CorruptRecordError`（CLI 退出码 1）；写入入口在锁内校验失败时不产生任何修改或输出。口令封存记录的认证（check/tag）仍在 `load` 提供口令时核验。
- 退出码：0 成功，1 存储或校验错误，2 用法错误。

## 限制

- 未实现密钥材料的内存清零与常时比较。
- 派生参数只支持 PBKDF2-HMAC-SHA256。

## 语料

`corpus.md` 是本项目对应的技术标签语料（GitHub 热门技术标签）。`report` 子命令输出本域声明覆盖的分类与标签。
