# RPM/DPKG 完整版本比较与 epoch 保留

> 版本基线：v0.0.4。已按本版核对「RPM/DPKG 完整版本比较与 epoch 保留」的操作、实现引用与适用边界；历史日期及验证结果仍只对应其原始提交。版本差异见[发布说明](releases/v0.0.4.md)，全部资料见[文档索引](README.md)。

基线模块已在约定范围完成验收，[PR #3](https://github.com/wybroot/alinksec/pull/3) 于2026-10-11合并。远端和本地 `main` 同步到 `06b9ad871d2d02bd9522eb0712d2ee8443ceea70`，其源码树与基线验收提交相同。漏洞模块从该提交创建 `vulnerability-applicability` 分支；本轮是完整版本比较与采集链的第一阶段，整个漏洞判断与修复适用性模块继续在此分支完善。

## 本轮实现

软件来源为 `rpm` 时，比较完整 `[epoch:]version[-release]`。缺省 epoch 为0，数值段忽略前导零并按长度与数字次序比较，字母段按ASCII次序比较；`~`早于正式版本，`^`晚于基础版本但早于下一普通版本段，发行版 release 参与比较。软件来源为 `dpkg` 时，分别比较 epoch、upstream version 和 Debian revision；缺省 revision按0比较，`~`、字母和其他合法符号使用Debian顺序。数值段无需转换为有限整数，避免长版本段溢出；Debian epoch遵守原生解析器的非负 `INT_MAX` 上限。

本实现对输入做255字符、有限ASCII和对应软件包语法校验。缺失、空白、控制字符、非法epoch、空release/revision或未知包来源不进入原生比较，也不在失败后回退到另一种算法。规则范围支持现有的单个比较条件和最多8个联合条件，完整版本被用于每个边界。旧非RPM/DPKG软件的上游比较路径保留，后续阶段还需完善其明确适用性。

RPM资产采集改为读取独立 `EPOCHNUM`、`VERSION`、`RELEASE` 字段，上报规范 `epoch:version-release`，同时保留厂商和安装时间。缺失epoch或release的行不构造完整版本。RPM修复后查询使用相同字段，不再丢弃epoch；复核规范化epoch，其他版本和release段仍须逐字相等。不能唯一解析的多条安装记录保持未验证，不把多个架构的结果拼接成一个版本。DPKG原有采集保留原生完整版本。

## 规则与修复边界

导入规则可以声明 `version_scheme` 为 `rpm`、`dpkg` 或 `upstream`；原生方案必须与规则的 `source` 相同，导入时核对原生版本边界的语法。未声明方案的旧规则按资产来源选择比较器；旧规则的来源、发行版和架构完整性仍需下一阶段处理。

新NVD映射明确标记 `upstream`。上游版本范围不会直接套用到RPM/DPKG发行版软件包；这样的映射保留公告和映射内容，新增导入时不计为可比对发行版规则。已有未标记的库记录尚未迁移，不把这一步解释为历史规则全部完成回移语义审核。匹配器不再从 `<版本` 上界推断 `fixed_version`；来源、回移声明、目标包头与修复审批现已由同组后续阶段实现，分别见[来源声明](48-漏洞规则来源与回移声明.md)、[包头复核](50-补丁包头核验与修复目标人工复核.md)和[派发闭环](51-漏洞覆盖历史与审批派发闭环.md)；显式字段本身仍是导入者声明。

比较器只回答两个完整版本的顺序，不证明CVE适用于该软件、厂商已回移补丁、仓库可信或修复已生效。本轮没有扩大Windows包修复、安装器信任或补丁元数据验证范围。

## 验证

Java边界测试覆盖epoch、release/revision、前导零、长数字、`~`/`^`、RPM与Debian不同的字母/数字顺序和未知输入拒绝。Go测试覆盖RPM资产字段、epoch保留、零epoch兼容、release不同和多条安装结果拒绝。真实SQLite导入及比对验证Debian发行版revision、RPMepoch、无推断修复版本、未知语法整批零写入，以及NVD上游映射不形成发行版命中。

`deploy/tests/package-version-native.py` 在两个独立Linux CI runner上，分别用 `dpkg --compare-versions` 和只读Rocky9容器中的 `rpm.labelCompare` 生成固定语料全部有序对的原生结果，再与同一Java生产比较器逐项核对。容器复用此前DNF原生验证镜像，禁用网络、限额96MiB、CPU1、移除全部能力并只读挂载源码；不安装软件、不查询或修改宿主包数据库。完整比较记录作为 `package-version-native-amd64/arm64` 产物保留。各架构内部检查串行，独立runner并行；本机重验证仍遵循资源看护限制。当前提交的成功CI记录才构成本轮验收，编写测试不等于测试通过。

语义依据：[RPM 4.18版本段比较](https://github.com/rpm-software-management/rpm/blob/rpm-4.18.0-release/rpmio/rpmvercmp.c)、[RPM EVR](https://github.com/rpm-software-management/rpm/blob/rpm-4.18.0-release/rpmio/rpmver.c)、[DPKG 1.22.6版本顺序](https://github.com/guillemj/dpkg/blob/1.22.6/lib/dpkg/version.c)、[DPKG版本解析](https://github.com/guillemj/dpkg/blob/1.22.6/lib/dpkg/parsehelp.c)。后续还需完成软件包架构与发行版身份、规则来源和回移修复证据、确认修复版本及补丁适用性、历史规则迁移、缺失信息展示和完整修复流程验收；整个模块完成之前不打开新PR。
