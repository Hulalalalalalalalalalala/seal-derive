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
- `seal(key_id, material, password=None, iterations=200_000) -> int` 封存材料并返回版本号；给出 `password` 时材料用 PBKDF2-HMAC-SHA256 派生的密钥加密封存，可取回原文。
- `load(key_id, version=None, password=None) -> bytes` 取出原始 material 的 UTF-8 bytes；`version` 缺省取当前活动版本，受口令版本必须提供 `password`。
- `versions(key_id) -> list[int]` 升序返回全部版本。
- `active(key_id) -> int` 当前活动版本。
- `set_active(key_id, version) -> None` 把活动版本指向已有历史版本。
- `revoke(key_id, version) -> None` 标记某版本作废。
- `is_revoked(key_id, version) -> bool` 查询作废状态。

## 约定

- 所有写操作立即持久化；进程被杀死后 `recover`/`init` 之外的重开不得丢失已确认的写。
- 非法输入抛出 `ValueError`，未知标识抛出 `KeyError`。
- 受口令版本：缺少口令、口令错误、记录损坏（篡改/截断/参数不全/认证失败）分别抛出含"缺少口令""口令不匹配""记录损坏"的 `ValueError`。
- 旧的 `pbkdf2-sha256` 记录只保存派生值、无法还原 material，取回时抛出含"不可恢复的旧记录"的 `ValueError`；无口令版本继续可读且结果不变。
- 退出码：0 成功，1 存储或校验错误，2 用法或未知标识错误；失败只写 stderr。

## 限制

- 未实现密钥材料的内存清零与常时比较。
- 未实现多进程并发写保护。
- 派生参数只支持 PBKDF2-HMAC-SHA256。

## 语料

`corpus.md` 是本项目对应的技术标签语料（GitHub 热门技术标签）。`report` 子命令输出本域声明覆盖的分类与标签。
