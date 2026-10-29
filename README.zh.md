# Secure File Share

[English](README.md) | 中文

> 本文译自 [README.md](README.md)，两者不一致时以英文版为准。

CSIT953 Assignment 2：一个文件存储与共享系统，把客户端密码学和以太坊智能合约结合在一起。

- 文件在 owner 自己的电脑上用 AES-256-GCM 加密，每个文件一把新生成的 256 位密钥，再用 ECDSA（secp256k1）签名。上传到存储的只有密文和签名后的 manifest，存储本身按不可信处理。
- `SecureFileShare` 合约登记公钥和文件，执行「申请 → 批准 / 拒绝 → 撤销」流程，只允许文件 owner 做决定，每一步都记成事件。
- 批准时，owner 用申请人登记的加密公钥加密文件密钥（ECIES：ECDH + HKDF-SHA256 + AES-256-GCM）。加密后的文件密钥（wrappedKey）有 93 字节，存在链上，只有申请人能解开。
- 申请人解密前，先拿链上记录核对下载的内容（见下文 V1–V6）。
- Tkinter 桌面应用覆盖 owner 和申请人两边的流程。界面从不显示私钥或文件密钥，只显示指纹。

设计决定、威胁模型和局限性见 [DESIGN.md](DESIGN.md)；合约接口、gas 用量和 Slither 结果见 [contracts/README.md](contracts/README.md)。这两份文档的中文版：[DESIGN.zh.md](DESIGN.zh.md)、[contracts/README.zh.md](contracts/README.zh.md)。

## 环境要求

| 工具 | 用途 |
|---|---|
| conda（Miniforge 或 Miniconda） | 用 `environment.yml` 创建 `secure-file-share` 环境：Python 3.11、Tk ≥ 8.6.13、cryptography、web3、eth-account、python-dotenv、pytest、py_ecc、bandit |
| [Foundry](https://book.getfoundry.sh/getting-started/installation) | `anvil`（本地链）和 `forge`（编译合约、跑合约测试） |

`forge-std` 已经放在 `contracts/lib/` 里，不用再执行 `forge install`。Windows 上的 Foundry 要在 Git Bash 或 WSL 里用；没装 Foundry 时，`scripts/deploy.py` 直接部署 `app/chain/abi/` 里已提交的 artifact。

## 本地链快速上手

所有命令都在项目根目录执行。

```sh
conda env create -f environment.yml
conda activate secure-file-share
cp .env.example .env.local

./scripts/start_chain.sh                     # 终端 1：Anvil，监听 127.0.0.1:8545，chain 31337
python scripts/deploy.py --network local     # 终端 2：编译、导出 ABI、部署，写入 CONTRACT_ADDRESS
python -m app.gui                            # 启动桌面应用
```

`start_chain.sh` 每 5 秒把链状态存到 `.chain/state.json`，按 Ctrl-C 退出时也会存一次，重启后合约和已登记的文件都还在。想从头开始，删掉 `.chain/` 和 `storage/`，再部署一次。

## 两个用户的完整流程

每个用户开一个窗口。同一台电脑上的所有窗口共用 `storage/`。

```sh
python -m app.gui --network local --keystore alice
python -m app.gui --network local --keystore bob
```

1. **创建 keystore**：在登录页选 *Create a new keystore*。应用生成三把密钥（发交易、文件签名、文件加密），用你的密码加密后存进 `keystore/<name>.json`（scrypt + AES-256-GCM，密码至少 8 个字符）。
2. **领测试币并登记公钥**：本地链上先点横幅里的 *Add 100 test ETH*，再点 *Register keys*。这笔交易把两把公钥绑定到账户地址。
3. **Alice 加密并登记文件**：*Protect a file* → 选文件，可以填一个公开标签。页面逐步显示加密、签名、上传、登记四步，并附上交易哈希、区块号和 gas。复制文件 ID。
4. **Bob 申请访问**：*Browse files* → 选中文件 → *Request access*。状态会自动刷新。
5. **Alice 做决定**：*My files* → 选中文件。点 *Approve* 时会显示 Bob 加密公钥的指纹，跟 Bob 那边申请旁显示的指纹核对一下。*Reject*、*Revoke access* 和 *Deactivate file* 也在这个页面。
6. **Bob 取回并验证**：*Retrieve and verify* 读取授权（即 wrappedKey），跑 V1–V4，解开文件密钥，解密，再跑 V5–V6。所有检查都通过后才能点 *Save decrypted file*。
7. **审计**：*Activity* 列出所有合约事件；*Export CSV* 把事件导出，留作证据。

| 检查 | 比对内容 | 能发现 |
|---|---|---|
| V1 | 下载对象的 SHA-256 与链上 ctHash | 密文被修改、替换或删除 |
| V2 | manifest 的 SHA-256 与链上 manifestHash | manifest 被修改 |
| V3 | manifest 里的 chain、contract、fileId、owner、ctHash 与链上记录 | 从别的文件或别的链拿来的 manifest |
| V4 | 用 owner **在链上登记的**签名公钥验 ECDSA 签名 | 伪造或重新签名的 manifest |
| Key | 用申请人的加密私钥做 ECIES 解封 | 为别的文件或别人加密的 wrappedKey |
| V5 | AES-256-GCM 认证标签 | 密文被修改，或文件上下文不符 |
| V6 | 解密数据的 SHA-256 与 owner 签过的摘要 | 内容与 owner 签名时不一致 |

### 安全演示

`SFS_DEMO=1 python -m app.gui`（或加 `--demo`）会多出一个 *Security demo* 页面：

- **Tamper with storage**：翻转密文里的一个比特、改掉 manifest 里的摘要，或者删掉密文，再打开 *Retrieve and verify*，看哪项检查失败。*Restore the originals* 把文件恢复原样。演示模式下，检查失败后验证页面仍提供解密选项，可以展示 GCM 标签检查（V5）如何发现改动。
- **Approve another owner's file**：用当前账户对一个不属于它的文件调用 `approveAccess`。gas 估算阶段就拦下了这次调用，交易不会发出；选 *Broadcast anyway* 则用固定 gas 上限强行发送，交易 revert 后照样会被打包，链上可以查到。

## 测试

```sh
(cd contracts && forge test)    # 合约：单元、fuzz（1,000 次）和 invariant 测试
pytest                          # Python：单元测试和集成测试
```

集成测试会在空闲端口上自己启动一个 Anvil 并部署新合约，不会碰 `.chain/` 和 `.env.local`。`PATH` 里找不到 `anvil` 时集成测试会跳过，可以用 `ANVIL_BIN` 指定它的位置。没有图形显示环境时，需要界面的测试也会跳过。

可选检查：

```sh
(cd contracts && forge coverage --no-match-coverage "test|lib")
(cd contracts && slither . --filter-paths "contracts/(lib|test)/")
bandit -r app scripts
```

### 安全测试矩阵

DESIGN.md §10.2 的每个场景都有自动化测试。Solidity 测试在 `contracts/test/`，Python 测试在 `tests/unit/` 和 `tests/integration/`。只跑某一个场景，用 `forge test --mt S1` 或 `pytest -k S6`。

| 编号 | 场景 | 预期结果 | 测试 |
|---|---|---|---|
| S1 | 其他用户对 Alice 的文件调用 `approveAccess` | revert `NotFileOwner` | `AccessControl.t.sol::test_strangerCannotApprove`, `Fuzz.t.sol::testFuzz_nonOwnerCannotManageFile`, `test_chain_client.py::test_revert_is_caught_before_sending`, `test_gui_demo.py::test_unauthorized_approve_is_rejected_before_and_after_broadcast` |
| S2 | Bob 批准自己的申请 | revert `NotFileOwner` | `AccessControl.t.sol::test_requesterCannotApproveOwnRequest` |
| S3 | 重复批准，或批准已拒绝的申请 | revert `InvalidStatus` | `AccessControl.t.sol::test_cannotApproveTwice`, `test_cannotApproveRejectedRequest` |
| S4 | owner 申请自己的文件；文件不存在；申请人没登记公钥 | revert `OwnerCannotRequest`、`FileNotFound`、`KeysNotRegistered` | `AccessControl.t.sol::test_requestAccess_unknownFileReverts`, `test_requestAccess_ownerCannotRequestOwnFile`, `test_requestAccess_requiresRegisteredKeys` |
| S5 | 用同一个 salt 登记两次 | revert `FileAlreadyExists` | `Registration.t.sol::test_registerFile_rejectsDuplicateSalt` |
| S6 | 翻转存储中密文的一个字节 | V1 失败；强行解密时 V5 失败 | `test_verification.py::test_flipped_ciphertext_byte`, `test_forced_decrypt_hits_the_gcm_tag`, `test_aead.py::test_any_flipped_byte_is_detected` |
| S7 | 改掉存储中 manifest 的 ptDigest | V2 和 V4 失败；强行解密时 V6 失败 | `test_verification.py::test_modified_pt_digest`, `test_forced_decrypt_fails_v6`, `test_signing.py::test_modified_pt_digest_is_detected` |
| S8 | 攻击者伪造 manifest 并用自己的密钥重新签名 | V4 失败，验签公钥取自链上 | `test_verification.py::test_attacker_re_signs_with_own_key`, `test_re_signed_manifest_fails_v4_even_if_hash_matched`, `test_signing.py::test_attacker_resigning_fails_with_onchain_key` |
| S9 | 把对象回滚到旧版本 | V1 失败 | `test_verification.py::test_rollback_to_an_older_version` |
| S10 | Mallory 用自己的私钥解 Bob 的 wrappedKey | 解封失败 | `test_verification.py::test_someone_elses_wrapped_key`, `test_ecies.py::test_other_users_key_fails` |
| S11 | 把文件 A 的 wrappedKey 用在文件 B 上 | 解封失败（HKDF info 和 AAD 都不同） | `test_verification.py::test_wrapped_key_of_another_file`, `test_ecies.py::test_wrapped_key_cannot_move_to_another_file` |
| S12 | 被拒绝或被撤销的申请人索要密钥 | 链上没有 wrappedKey；客户端拒绝 | `AccessControl.t.sol::test_rejectedAndRevokedRequestersHoldNoWrappedKey`, `test_workflows.py::TestRejectBranch`, `TestRevokeBranch` |
| S13 | keystore 密码错误 | 打不开；提示与文件损坏时相同 | `test_keystore.py::test_wrong_password`, `test_tampering_looks_like_a_wrong_password` |
| S14 | 登记格式错误或不在曲线上的公钥 | 合约 revert；owner 的客户端拒绝加密文件密钥 | `Registration.t.sol::test_registerKeys_rejectsWrongLength`, `test_registerKeys_rejectsBadPrefix`, `test_workflows.py::test_off_curve_encryption_key_is_refused` |
| S15 | 重放已上链的交易 | 节点拒绝已用过的 nonce | `test_chain_client.py::test_replayed_transaction_is_rejected` |
| S16 | 抢先用同一个 salt 登记（front-run） | fileId 不同；owner 不受影响 | `Registration.t.sol::test_frontRunWithSameSaltGetsDifferentFileId`, `Fuzz.t.sol::testFuzz_fileIdIsBoundToSender` |

## 目录结构

```
app/
  config.py      从 .env.<network> 读取网络配置
  crypto/        AES-256-GCM 文件加密、ECDSA manifest 签名、ECIES 密钥包装、keystore、规范编码
  storage/       用本地目录模拟不可信的对象存储
  chain/         web3.py 客户端、可读的 revert 信息、事件日志和 CSV 导出
  services/      owner 和申请人工作流、V1–V6 检查，不含 GUI 代码
  gui/           Tkinter 应用（python -m app.gui）
contracts/       Foundry 项目：SecureFileShare.sol 及其测试
scripts/         start_chain.sh（启动 Anvil）和 deploy.py（编译、导出 ABI、部署）
tests/           unit/ 和 integration/（pytest）
evidence/        EVIDENCE.md（报告用的测试和扫描结果）、logs/、collect.sh
```

以下内容运行时生成，git 会忽略：`keystore/`（加密后的密钥）、`storage/`（密文对象和签名 manifest）、`.chain/`（Anvil 状态）、`.env.local` 和 `.env.sepolia`。

## 配置

每个网络对应一个 `.env.<name>` 文件，从 `.env.example` 复制而来。登录页会列出找到的所有这类文件。

| 键 | 含义 |
|---|---|
| `RPC_URL` | 节点地址；可能带 API key，所以应用只显示主机名 |
| `CHAIN_ID` | 连接时与节点核对 |
| `CONTRACT_ADDRESS`, `DEPLOY_BLOCK` | 由 `scripts/deploy.py` 写入 |
| `EXPLORER_URL` | 可选，例如 `https://sepolia.etherscan.io`；设置后点交易哈希会在区块浏览器里打开 |
| `STORAGE_DIR` | 可选，默认 `storage/`；要看到同一批文件，各窗口必须用同一个目录 |

### Sepolia（可选）

任务书允许只用本地链。部署到 Sepolia 能留下任何人都可以核对的公开交易记录。用加密的部署者 keystore 部署、在 Etherscan 上验证源码，步骤见 [contracts/README.zh.md](contracts/README.zh.md#sepolia)。每个用户账户都需要 Sepolia ETH 付 gas。

## 已知局限

- 撤销会删掉合约存储里的 wrappedKey，但批准那笔交易仍留在链上；已经解密过的申请人也仍持有明文。要切断今后的访问，只能换一把新的文件密钥，也就是用 *Protect a file* 重新加密登记一次。
- 更换链上登记的密钥后，旧文件会出问题：V4 用 owner 当前的签名公钥核对；为旧加密公钥生成的 wrappedKey 也要用旧 keystore 才能解开。
- owner、申请人、时间戳和可选的公开标签在链上对所有人可见。
- 客户端信任自己连接的 RPC 节点。存储可以删掉文件，客户端能发现，但阻止不了。
- 应用运行期间，密钥和明文一直留在 Python 内存里；文件整个读入内存（上限约 50 MB）。

## 故障排查

| 现象 | 解决办法 |
|---|---|
| macOS 上点击没反应，或窗口绘制异常 | 在 `secure-file-share` conda 环境里运行（Tk ≥ 8.6.13）；Tk 版本过旧时应用会给出警告 |
| "No contract at … deploy it first" | 链被重置过；重新运行 `python scripts/deploy.py --network local` |
| "Cannot reach 127.0.0.1 …" | 启动 `./scripts/start_chain.sh` |
| "Not enough ETH in this account to pay for gas" | 本地链上点 *Add 100 test ETH*；Sepolia 上给这个地址转一些测试币 |
| "The on-chain keys for this address differ from this keystore" | 这个地址登记的是另一个 keystore 的公钥；改用那个 keystore，或在 Account 页面替换公钥（替换后，用旧密钥签名的文件 V4 会失败） |
| 集成测试被跳过 | 安装 Foundry，或设置 `ANVIL_BIN` |

## 打包

`git archive -o secure-file-share.zip HEAD` 只打包已提交的文件，keystore、`.env` 文件、本地存储和链状态都不会进压缩包。
