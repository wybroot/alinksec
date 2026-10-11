# APT 默认磁盘安装策略核查

独立 [定义](../deploy/baseline/apt-definitions.json) 与 [候选包](../deploy/baseline/packages/apt/linux-baseline.json) v1 将旧0052明确收窄为默认磁盘未认证安装声明。仅 Ubuntu24.04 完整安装 `apt` 与 `libapt-pkg6.0t64` **2.8.3**，管理员确认可信安装、默认入口及适用性。后端和Agent都必须更新；导入、审核、指定适用主机测试后才可发布。此候选不自动启用，无自动修复，不代表完整合规。

固定 `apt_install_policy`、target=`/etc/apt`、eq，完整参考为 `apt/apt-get:AllowUnauthenticated=false,Force-Yes=false`。定义不得弱化、加路径/命令/option或其他字段，包括null。Windows执行返回明确error；其他产品及包版本不在已验证范围。任务保留完整定义快照，执行异常阻止发布，新版本不能复用旧证据。

## 配置解释

生产只通过固定 `/usr/bin/dpkg-query --admindir=/var/lib/dpkg`，在清洁LC_ALL/PATH环境中前后确认两包完整安装和精确版本。一个共享deadline覆盖包查询、读取、解析和稳定性确认。不执行 `apt-config`、`apt`、`apt-get`、钩子，不更新索引或安装，不访问网络、源文件、密钥或仓库签名。包状态不证明可执行文件、库或安装来源可信，这仍由管理员确认。

固定枚举 `/etc/apt` 和 `/etc/apt/apt.conf.d`；片段目录必须存在。片段按ASCII字节排序；排除隐藏名、末尾点、不接受字符和扩展名。接受无扩展名或小写 `.conf`，名称字符为字母、数字、`_-. :`（不含空格）；冒号以该版本原生源码为准，文档的字符清单没有列出它。符合选择规则的非普通文件返回error，而不照原生悄悄忽略。忽略条目的内容不读取，名称集合仍参与稳定性检查。片段读完后才读取存在的 `apt.conf`；主文件不存在允许使用已核实版本默认值，期间创建/替换主文件会返回error。

有限语法支持大小写不敏感的 `::` 名称、单行无转义引号值、无标量值的作用域、普通列表、`//`／普通`#`行注释、独占整行的块注释和顶层 `#clear`。不支持带值作用域、引号名称、裸值、续行/转义、inline/mixed块注释、包含指令、配置索引指令、加载路径/RootDir声明或清除、嵌套Binary等形式。任何文件（包括无关选项）出现超出语法范围的内容均error，避免从局部命中推断整棵配置。

标量最后赋值覆盖；重新打开作用域保留原内容；`#clear`清空目标值和后代。分别将 `Binary::apt`、`Binary::apt-get` 的声明覆盖全局声明。保留空祖先节点，以便区分Binary清除后空值覆盖全局的语义；不读取 `Binary::apt-config` 作为这两个前端的策略。相关布尔项不得含列表或子项。

只接受0/1及明确的true/false、yes/no、on/off、with/without、enable/disable词（不分大小写）。缺失/空值按2.8.3安装认证读取代码的false默认解释，并记录global-default/binary-default来源；其他字符串返回error，即使原生会回退默认值，也不能把拼写错误转换为通过。参考同时要求两个前端的两个值均false；任一true为fail，失败与执行异常分开显示。

## 输入与结论边界

输入目录/文件需UID/GID0、组和其他不可写；文件需普通文件且单硬链接，不允许访问ACL，目录也不允许默认ACL。逐段O_PATH/NOFOLLOW持有句柄后读取同一inode；检查完成前重新确认inode、模式、身份、链接数、ctime、size、mtime、父身份/访问元数据及两个目录的名称集合。链接、特殊文件、ACL未知、读取失败、内容/集合变化均error。此检查不证明父目录完整授权、MAC或抵御拥有root权限的持续篡改。

最多32片段和一个主文件，每文件64KiB、总256KiB、4096行、每行4096字节、每目录128名称、作用域16层；每文件8192语句/32768tokens。超限、超时保持error，不产生成功默认值。

证据 `scope=default-on-disk-apt-install-policy`，`environment_state`、`command_line_state`、`source_trust_state`、`installation_state` 均 **unverified**。通过只表示支持的默认磁盘配置对两个前端均没有打开这两个全局安装绕过开关，不证明真实调用拒绝所有不可信包。实际 `APT_CONFIG`、`-c`、`-o`、`--allow-unauthenticated`、其他前端、源级Trusted/Allow-Insecure/Signed-By、密钥范围、仓库签名与安装行为须另核对。0053源信任规则继续标记未支持；本项不能替代它。

## 原生验证与来源

`deploy/tests/apt-native.sh` 的专用Ubuntu容器固定两包2.8.3、network=none、128MiB/192MiB含swap、CPU1、pids64、cap-drop ALL、no-new-privileges，源码只读挂载。仅容器私有夹具调用真正的apt-config，以固定argv[0]选择apt/apt-get专属覆盖，`shell .../b`输出作为数据解析，绝不eval或执行安装。APT_CONFIG仅用于原生夹具重定向，生产不用。20组配置共80个标量对照，包含默认、大小写、作用域、Force-Yes、两前端专属覆盖、主文件最后、字节排序、扩展名/隐藏名/冒号、清除、空值和不继承父值；钩子标记必须不存在。专用容器强制UID、访问/默认ACL、链接、超限、未知值、变更及deadline边界零skip。本地文件系统不具备的ACL夹具由该原生任务补齐。REST/浏览器报告是明确协议夹具，用于验证证据与流程，不是主机安装行为证据。

依据 [Ubuntu apt.conf 2.8.3手册](https://manpages.ubuntu.com/manpages/noble/man5/apt.conf.5.html)、[apt-get手册](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html)、[apt-secure手册](https://manpages.ubuntu.com/manpages/noble/man8/apt-secure.8.html) 和 [Ubuntu官方APT源包](https://packages.ubuntu.com/noble-updates/apt)。源包 [apt_2.8.3.tar.xz](https://archive.ubuntu.com/ubuntu/pool/main/a/apt/apt_2.8.3.tar.xz) SHA256=`088522b3613b28fdbcfa61f1f7e476bf6dc6b0120a8f74409e9527580c9f9d3b`，与官方dsc一致。重点核对 `apt-pkg/init.cc` 的加载顺序、`contrib/fileutl.cc`的文件选择、`contrib/configuration.cc` 的Clear/MoveSubTree/FindB、`contrib/strutl.cc`的布尔词、`apt-private/private-cmndline.cc`的专属覆盖以及`private-download.cc`中AllowUnauthenticated/Force-Yes的false默认。精确包是否可安装以原生CI实际仓库安装和dpkg查询为准。
