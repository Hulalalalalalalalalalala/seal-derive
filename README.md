# seal-derive

把密钥材料以"版本"为单位封存，支持口令派生、轮换与吊销，并保留可审计的版本历史。

## 依赖

仅标准库（Python 3.10+）；PBKDF2-HMAC-SHA256 来自 hashlib。

## 安装与运行

无需安装，直接以模块方式运行（目录参数统一为 `--root`）：

```bash
python3 -m seal_derive --root ./state init
```

子命令：`init`、`seal <key_id> <material> [--password P] [--iterations N]`、`rotate-password <key_id> --new-password P [--password P] [--version V] [--iterations N] [--revoke-source] [--expected-active V]`、`load <key_id> [--version V]`、`versions <key_id>`、`active <key_id>`、`set-active <key_id> <version>`、`revoke <key_id> <version>`、`report`。

## 公开接口

`seal_derive.KeyRing(root)`：

- `init() -> None` 建立空密钥环。
- `seal(key_id, material, password=None, iterations=200_000) -> int` 封存材料并返回版本号；给出 `password` 时统一写入 `pbkdf2-sha256-sealed-v2` 记录：以 PBKDF2-HMAC-SHA256 派生密钥加密并认证原始 material，持正确口令可完整取回。v2 沿用既有派生参数与默认迭代次数，但认证 tag 的附加数据额外绑定封存时的完整 `key_id`（UTF-8 字节，带长度前缀；不含存储路径），因此记录只能在原 key_id 下通过认证：复制或移动到另一个 key_id、改名所属键、改写 version、篡改密文或 tag，`load` 一律抛含“记录损坏”的 `CorruptRecordError` 且不输出材料。键名按完整字符串区分，中文、emoji、空格与分隔符均可使用，大小写或 Unicode 表示不同的键不能相互通过认证。无口令封存仍写入 `plain`。成功后按原规则增加版本并更新 active。
- `rotate_password(key_id, new_password, password=None, version=None, iterations=200_000, revoke_source=False, expected_active=None) -> int` 为已有封存版本换口令并返回新版本号。`version` 缺省取当前活动版本；`plain` 来源忽略旧口令，v1/v2 来源按 `load` 的同一顺序与判定认证（未知标识 `KeyError`、已吊销来源 `RevokedVersionError`、旧派生记录 `UnrecoverableRecordError`、缺少或错误旧口令分别 `MissingPasswordError`、`BadPasswordError`、结构损坏或正确口令下认证失败 `CorruptRecordError`）。可选的 `expected_active` 是活动版本前置条件：省略或传 `None` 时行为不变；给出时只比较该键当前 active 的版本号（不要求等于来源 `version`，也不代表整个历史未变化），不等则抛 `ActiveVersionConflictError`（继承 `SealError`，可从 `seal_derive.core` 导入，消息含“活动版本冲突”并标明键名、预期与实际活动版本），且无论预期版本是否存在于历史中都同样抛冲突。前置条件判断与整个轮换在同一排他锁内原子完成，并发修改只能在该操作之前或之后生效；两个都预期同一初始活动版本的并发请求至多一个成功。取回的原始 material 字节不变，使用新盐与指定迭代次数写成 `pbkdf2-sha256-sealed-v2` 记录，tag 绑定键名和新版本号。新版本号取该键历史最大号加一，未吊销并设为 active；`revoke_source=True` 时一并吊销来源版本，其余版本与键不变。输入先于存储校验：`new_password` 限字符串、旧 `password` 限字符串或 `None`、`iterations` 限非布尔正整数、`revoke_source` 限布尔、`expected_active` 限 `None` 或非布尔正整数，否则抛 `ValueError`。整个读取—校验—认证—变更—提交在同一把排他写锁内原子完成；任何失败（含前置条件冲突与等待锁超时）都不修改 `keyring.json`。支持空或 Unicode 材料、空口令及新旧口令相同。CLI 成功仅输出版本号加换行；非法输入、未知标识、已吊销来源退出 2，活动版本冲突与其余错误退出 1（冲突时标准输出为空、标准错误含冲突消息）。
- `rotate_password_batch(requests) -> list[int]` 把同一密钥环内多把键的轮换作为一次整体变更；Python API 专用，不新增子命令。`requests` 是非空字典列表，每项必填 `key_id`、`new_password`，其余仅允许 `password`、`version`、`iterations`、`revoke_source`、`expected_active`，缺省值与类型规则沿用 `rotate_password`（旧口令缺省 `None`、版本缺省取 active、迭代次数 200_000、不吊销来源、`expected_active` 缺省 `None` 即不做前置条件）。非法结构、非字典项、缺失必填字段、未知字段、字段值非法及批次内 `key_id` 重复均抛 `ValueError`；整批输入先于存储校验（存储目录缺失时非法输入仍先抛 `ValueError`），且不改写调用方的输入。加锁后先校验整份存储并读取一个已提交快照，所有项全部取自该快照：按请求顺序逐项先判断键是否存在、再比较 `expected_active` 前置条件（不等抛 `ActiveVersionConflictError`，优先于该项的未知来源、吊销与口令错误，但不抢先于较早项的失败）、随后解析来源；缺省取该键 active，`plain`/v1/v2 按 `load` 语义取回材料；版本号取**对应键**历史最大值加一；每项保留材料字节、使用独立新盐和指定迭代次数生成绑定完整键名及新版本号的 v2 记录，新增版本未吊销并设为该键 active；仅按该项 `revoke_source` 吊销其来源，其他版本与键一律不变。按请求顺序报告首个失败：结构损坏或正确口令下认证失败 `CorruptRecordError`，未知键或版本 `KeyError`，活动版本冲突 `ActiveVersionConflictError`，已吊销 `RevokedVersionError`，旧派生记录 `UnrecoverableRecordError`，缺少或错误旧口令分别 `MissingPasswordError`、`BadPasswordError`；存储缺失 `FileNotFoundError`，等锁超时五秒 `TimeoutError`，其余存储错误沿用 `OSError`。任一项失败即在变更前中止，`keyring.json` 字节不变、不返回部分结果；并发调用只能观察到整批提交前或提交后的状态。成功按请求顺序返回各键新版本号列表。空口令、空材料及 Unicode 材料继续支持，键名仍按完整字符串区分。
- `load_batch(requests) -> list[bytes]` 一次取回同一密钥环内多份材料；Python API 专用，不新增子命令。`requests` 是非空字典列表，每项必填 `key_id`，其余仅允许 `version`、`password`，缺省值与类型规则沿用 `load`（版本缺省或为 `None` 取 active、否则限非布尔正整数；口令缺省为 `None`，仅接受字符串或 `None`）。空列表、非字典项、字段缺失或多余、非法字段值均抛 `ValueError`；整批输入先于存储访问校验（存储目录缺失时非法输入仍先抛 `ValueError`），且不改写调用方的输入。同一 `key_id` 可重复出现并请求不同历史版本。加共享锁后先校验整份存储（未请求记录的结构损坏同样抛 `CorruptRecordError`），再按请求顺序逐项处理，所有项取自同一个已提交快照：版本解析（含缺省读 active）、吊销判断与取出只可能对应并发轮换批量提交前或提交后的完整材料，`set_active`/`revoke` 只能在整批取出前或结束后提交，已完成的读取不被稍后的吊销追溯否定。按请求顺序报告首个失败：未知键或版本 `KeyError`，已吊销 `RevokedVersionError`，旧派生记录 `UnrecoverableRecordError`，缺少或错误口令分别 `MissingPasswordError`、`BadPasswordError`，正确口令下认证失败 `CorruptRecordError`；`plain` 忽略合法口令。存储缺失 `FileNotFoundError`，等锁超时五秒 `TimeoutError`，其余存储错误沿用 `OSError`。首个失败即终止，不返回或输出部分材料；成功或失败都不改写 `keyring.json`，不新增版本、不改 active 指针与吊销标记。成功按请求顺序返回 `list[bytes]`，保留重复项，材料字节与 `load` 一致。空口令、空材料及 Unicode 材料继续支持，v1/v2 读取均不升级记录，v2 保留完整键名绑定，键名不做规范化。
- `set_active_batch(requests) -> None` 把同一密钥环内多把键的活动指针作为一次整体切换；Python API 专用，不新增子命令。`requests` 是非空字典列表，每项必填 `key_id`、`version`，其余仅允许 `expected_active`；目标 `version` 必填且限非布尔正整数（没有“保持 active”的缺省），`expected_active` 缺省或为 `None` 表示不检查，否则限 `None` 或非布尔正整数。空列表、非字典项、字段缺失或多余、字段值非法及批次内 `key_id` 重复均抛 `ValueError`；整批输入先于存储访问校验（存储目录缺失时非法输入仍先抛 `ValueError`），且不改写调用方的输入。加排他写锁后先校验整份存储（未请求记录的结构损坏同样抛 `CorruptRecordError`），再按请求顺序逐项检查同一已提交快照：键存在（未知键 `KeyError`）、`expected_active` 与当前活动版本**号**比较（不要求预期版本存在于历史；不等抛 `ActiveVersionConflictError`，消息沿用轮换冲突规则）、目标版本存在（未知版本 `KeyError`）、目标版本未吊销（已吊销抛 `RevokedVersionError`，消息含“已吊销”）；只报告首个失败，且较早项的失败优先于较晚项。任何一项失败即在任何指针移动前中止，`keyring.json` 字节不变。全部通过后一次性重指活动指针：不新增版本、不解密或改动任何封存材料，其他键、版本历史与吊销标记均不变；目标本就活动的项仍完成全部检查（含前置条件与吊销判断），整批没有任何指针需要移动时不重写 `keyring.json`。并发修改只能在本批之前或之后生效；在没有其他修改时，两批对共享键预期同一旧活动值且目标均不同于旧值，至多一批成功，另一批抛 `ActiveVersionConflictError`。存储缺失 `FileNotFoundError`，等锁超时五秒 `TimeoutError`，其余存储错误沿用 `OSError`；存储失败不留部分切换。成功返回 `None`。键名不做规范化，旧封存格式继续按原有规则取出。
- `revoke_batch(requests) -> None` 整体吊销同一密钥环内多把键的历史版本，并可同步替换活动指针；Python API 专用，不新增子命令。`requests` 是非空字典列表，每项必填 `key_id`、`versions`，其余仅允许 `replacement_active`、`expected_active`；`versions` 为非空列表，成员为不重复的非布尔正整数，按列表顺序解析；两个可选项缺省或为 `None` 分别表示保持活动指针、不检查前置条件，否则均限非布尔正整数。空列表、非字典项、字段缺失或多余、字段值非法、批内 `key_id` 重复或单项内版本重复均抛 `ValueError`；整批输入先于存储校验（存储目录缺失时非法输入仍先抛 `ValueError`），且不改动调用方的输入。加排他写锁后先校验整份存储（未请求记录的结构损坏同样抛 `CorruptRecordError`），再基于同一已提交快照按请求顺序逐项检查：键存在（未知键 `KeyError`）、`expected_active` 只与当前活动版本**号**比较（不要求预期版本存在；不等抛 `ActiveVersionConflictError`，消息沿用既有规则）、`versions` 中各版本按列表顺序存在（未知版本 `KeyError`）、最后检查替代版本：替代版本必须存在（未知抛 `KeyError`），且既不能是已吊销版本、也不能属于本项吊销列表，否则抛含“已吊销”的 `RevokedVersionError`；已吊销目标再次吊销成功。只报告首个失败，较早项的失败优先于较晚项；任一项失败即在任何吊销或指针移动前中止，`keyring.json` 字节不变、不留部分变更。无替代值时即使吊销的是活动版本也保留原指针（可指向已吊销版本，与单版本 `revoke` 一致）；有替代值时无论原活动版本是否被吊销都把指针切到替代版本。吊销与切换在同一次原子替换中整体提交：不需要口令、不解密、不增删任何版本，材料、派生参数与其他键（含未提及的吊销标记与指针）均不变；四种现有记录格式（`plain`、`pbkdf2-sha256`、`pbkdf2-sha256-sealed`、`pbkdf2-sha256-sealed-v2`）均可吊销且可作为替代版本。整批已处于目标状态时仍完成全部检查，但不重写 `keyring.json`。并发修改及 `load_batch` 只能观察提交前或提交后的完整状态；两批对共享键预期同一旧活动值并替换指针时，至多一批成功，另一批抛 `ActiveVersionConflictError`。存储缺失 `FileNotFoundError`，等锁超过五秒 `TimeoutError`，其余存储错误沿用 `OSError`。成功返回 `None`，键名不做规范化。
- `load(key_id, version=None, password=None) -> bytes` 取回**原始 material 的 UTF-8 bytes**（不是派生值）；`version` 缺省取当前活动版本。一次 load 的版本解析（含缺省时读 active）、吊销校验与解密在同一共享锁快照内完成：并发的 `revoke`/`set_active` 要么在 load 开始前已提交（load 见到新状态），要么等 load 结束后才能提交，已完成的 load 不被稍后的变更追溯否定。解析到已吊销版本抛 `RevokedVersionError`（消息含“已吊销”，CLI 退出码 2）。受口令版本必须传 `password`：缺少口令抛含“缺少口令”的 `ValueError`，口令错误抛含“口令不匹配”的 `ValueError`，记录被篡改、截断或参数不全抛含“记录损坏”的 `ValueError`。旧的仅保存派生值的 `pbkdf2-sha256` 记录无法恢复原 material，抛含“不可恢复的旧记录”的 `ValueError`。
- 所有读取状态的入口（含缺省版本的 `load`、`load_batch`、`versions`、`active`、`is_revoked`）返回前统一校验整份 `keyring.json`；写入入口（`seal`、`rotate_password`、`rotate_password_batch`、`set_active`、`set_active_batch`、`revoke`、`revoke_batch`）在写锁内校验快照，再原子提交。顶层 `keys`、每个键的 `versions` 与非布尔正整数 `active`（必须指向真实版本）、版本记录的 `version`（非布尔正整数、键内唯一且按列表升序）、布尔 `revoked`、已识别 `scheme`（`plain`、`pbkdf2-sha256`、`pbkdf2-sha256-sealed`、`pbkdf2-sha256-sealed-v2`）、必要字段、Base64 与固定长度、正整数 `iterations` 均须合法；`plain` 的 Base64 内容必须是合法 UTF-8，两种 sealed 方案的 `salt`/`check`/`tag`/`material` 必须完整且口令取回时通过认证（v2 还要通过 key_id 绑定认证）。任何一项不满足，所有入口一致抛含“记录损坏”的 `CorruptRecordError`（CLI 退出码 1）；写入口遇坏状态不修改文件、不产生返回值。结构完整的旧 `pbkdf2-sha256` 记录仍只抛 `UnrecoverableRecordError`，不会误报为口令错误。
- 旧记录兼容：旧 `pbkdf2-sha256-sealed`（v1）记录仍可凭原口令取出，读取不追溯改写、不升级其 scheme，也不补绑 key_id（v1 记录被搬到其他键下仍按旧规则可开）；旧 `pbkdf2-sha256` 记录继续抛 `UnrecoverableRecordError`。同一键的不同版本继续按原规则读取；v2 的 tag 不绑定目录，整体搬迁存储目录不影响读取。
- `versions(key_id) -> list[int]` 升序返回全部版本。
- `active(key_id) -> int` 当前活动版本。
- `set_active(key_id, version) -> None` 把活动版本指向已有历史版本。
- `revoke(key_id, version) -> None` 标记某版本作废。
- `is_revoked(key_id, version) -> bool` 查询作废状态。

## 约定

- 所有写操作立即持久化；进程被杀死后 `recover`/`init` 之外的重开不得丢失已确认的写。
- 所有修改（`init`/`seal`/`rotate_password`/`rotate_password_batch`/`set_active`/`set_active_batch`/`revoke`/`revoke_batch`）共用同一把跨进程写锁（目录内 `.keyring.lock`，标准库 `flock`/`msvcrt`，无第三方依赖），在锁内完成读取、校验、变更与 `keyring.json` 的原子替换；读操作取共享锁，配合临时文件 + `os.replace` 不会读到半份文件。任何入口读到被篡改、截断或结构非法的状态都在返回/提交前抛 `CorruptRecordError`，写操作不会留下部分修改。
- 等待写锁超过 5 秒抛 `TimeoutError`（文本“获取密钥环写锁超时”，CLI 退出码 1）；持锁进程被强制结束或崩溃后锁由内核自动释放，后续调用在等待窗口内自动接管，不删除或改写 `keyring.json`。
- 非法输入抛出 `ValueError`，未知标识抛出 `KeyError`，缺少 `keyring.json` 抛出 `FileNotFoundError`；这三类之外的存储/校验异常（`CorruptRecordError`、`MissingPasswordError`、`BadPasswordError`、`UnrecoverableRecordError`、`ActiveVersionConflictError`、`TimeoutError`、`OSError`）CLI 退出码均为 1。
- 退出码：0 成功，1 存储或校验错误，2 用法错误（含未知 key/版本与已吊销版本的 `load`）。

## 限制

- 未实现密钥材料的内存清零与常时比较。
- 派生参数只支持 PBKDF2-HMAC-SHA256。

## 语料

`corpus.md` 是本项目对应的技术标签语料（GitHub 热门技术标签）。`report` 子命令输出本域声明覆盖的分类与标签。
