# contracts — SecureFileShare

> 中文备份：2026-10-18 改成英文之前的 contracts/README.md。英文版见 [README.md](README.md)。

DESIGN.md 第 5 节的合约实现。Foundry 项目，solc 0.8.30，optimizer 200 runs。

```
src/SecureFileShare.sol                  合约
test/utils/BaseTest.sol                  共用 fixture：Alice 是 owner，Bob/Carol 申请，Mallory 无权限，Nobody 没登记公钥
test/Registration.t.sol                  registerKeys、registerFile、view 函数
test/AccessControl.t.sol                 请求状态机、owner 检查、停用文件
test/Fuzz.t.sol                          随机调用者、随机字节串的性质测试
test/invariant/                          handler（带参考模型）+ 4 条 invariant
lib/forge-std                            测试库 v1.17.0，直接放进仓库，clone 后不用再装
```

## 常用命令（在 `contracts/` 下执行）

```sh
forge build
forge test                       # 59 个测试：单元 + fuzz 1000 次 + invariant 256 轮 × 64 步
forge test --mt S1 -vvv          # 只跑名字里带 S1 的用例
forge test --gas-report
forge coverage --no-match-coverage "test|lib"   # 当前 100% 行 / 语句 / 分支 / 函数
slither . --filter-paths "lib|test"
```

测试名里的 `S1`…`S16` 对应 DESIGN.md 10.2 的安全测试矩阵。合约层覆盖 S1–S5、S12、S14（长度和前缀）、S16；
S15 靠链的 nonce 机制，留给 pytest 集成测试；其余几项在客户端。

Invariant 测试的 handler 维护一份参考状态机，每次调用前先预测「该成功还是该 revert」，和合约实际结果对比。
4 条 invariant：非 owner 的 owner-only 调用从未成功；每次调用结果都与模型一致；链上状态与模型一致；
wrappedKey 非空 ⇔ status == Approved。在副本上试过 5 种故意引入的 bug，都被 invariant 测试抓到：
删掉 approve 的 `onlyFileOwner`；删掉 revoke 里的 `delete req.wrappedKey`；允许从 Approved 直接 reject；
approve 不检查 active；允许 Approved 状态再次申请。Demo 时可以现场演示其中一种。

## 部署

### 本地链

```sh
./scripts/start_chain.sh                        # 另开一个终端；状态存在 .chain/state.json
cp .env.example .env.local
conda activate 953-a2
python scripts/deploy.py --network local
```

`deploy.py` 依次执行：`forge build` → 把 ABI 和 bytecode 导出到 `app/chain/abi/SecureFileShare.json` →
核对 RPC 的 chainId 与 `.env.local` 一致 → 部署 → 把 `CONTRACT_ADDRESS`、`DEPLOY_BLOCK` 写回 `.env.local`。
本地链用 Anvil 托管的 0 号开发账户发交易，代码和配置里都没有私钥。
没装 Foundry 的组员（Windows）运行时会直接用仓库里已导出的 artifact 部署；`--export-only` 只导出不部署。

### Sepolia

```sh
cast wallet import deployer --interactive       # 私钥加密存到 ~/.foundry/keystores/deployer
cp .env.example .env.sepolia                    # 换成文件里注释掉的 Sepolia 三行
python scripts/deploy.py --network sepolia --keystore ~/.foundry/keystores/deployer
```

密码用 getpass 读取，不回显。在 Etherscan 上验证源码（API key 写在 `.env.sepolia`，不出现在命令行里）：

```sh
cd contracts
set -a; source ../.env.sepolia; set +a
forge verify-contract "$CONTRACT_ADDRESS" src/SecureFileShare.sol:SecureFileShare --chain sepolia --watch
```

## Gas（Anvil 实测，含 21000 基础费用）

| 操作 | gasUsed |
|---|---|
| 部署 | 1,295,598 |
| registerKeys（首次 / 轮换） | 162,342 / 54,444 |
| registerFile | 187,279 |
| requestAccess | 50,773 |
| approveAccess | 122,801 |
| rejectAccess | 31,554 |
| revokeAccess | 41,578 |
| deactivateFile | 28,477 |

DESIGN.md 10.4 的 Sepolia 取证（E1–E6，含 3 笔故意失败的交易）合计约 2.6M gas，乘以当时的 gas price 就是需要的测试币。

## Slither

`slither . --filter-paths "lib|test"`：102 个检测器，2 条结果，都是 `timestamp` 误报。
被标出的是 `getFile` 和 `_requireFileOwner` 里的 `owner == address(0)`、`owner != msg.sender`，比较的是地址；
Slither 把整个 `FileRecord` 标成了「受时间戳影响」，因为同一个 struct 里的 `registeredAt` 来自 `block.timestamp`。
合约里没有任何基于时间的判断。

## 与 DESIGN.md 5.2 / 5.3 的差异

1. 多了两个 error：`InvalidHash`（ctHash 或 manifestHash 为零）、`LabelTooLong`（publicLabel 超过 128 字节）。
   对应 5.6「所有输入做长度和非零校验」。
2. `registerKeys` 拒绝 sigPubKey 与 encPubKey 相同，把 4.1 的「用途分离」落实到合约。
3. `approveAccess` 要求文件仍是 active：停用后不能再批准新的人，但 reject 和 revoke 照常可用。
4. 新增 `computeFileId(owner, salt)` view。客户端加密前就要用 fileId 构造 AAD，调用它能保证和合约算法一致。
5. view 函数返回 struct：`getUserKeys` → `(sigPubKey, encPubKey)`，`getFile` → `FileRecord`，
   `getRequest` → `Request`。web3.py 拿到的是按字段顺序排列的 tuple。
   `getFile` 遇到不存在的文件会 revert `FileNotFound`；`getRequest` 对没申请过的组合返回 `Status.None`（0）。
6. `app/chain/abi/SecureFileShare.json` 的格式是 `{contractName, compiler, abi, bytecode}`，客户端读 `["abi"]`。

## 给客户端的提示

- `Status` 枚举：0 None、1 Pending、2 Approved、3 Rejected、4 Revoked。
- revert 在 web3.py 里抛 `ContractCustomError`，`exc.data` 前 4 字节是 error selector，可以用 ABI 里的 error 条目还原名字。
- 轮换 `sigPubKey` 以后，旧文件的 manifest 签名要用旧公钥验证，而 V4 从链上读到的是新公钥。
  可以从 `KeysRegistered` 事件里找文件登记时生效的公钥，或者干脆规定签名公钥不轮换。
  `encPubKey` 同理：批准后才轮换的话，旧 wrappedKey 只能用旧私钥解开。
