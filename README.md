# H3C Campus Network for Linux

Debian 有线校园网 802.1X/EAP-MD5 客户端，含桌面界面与命令行。独立实现，非 H3C 官方软件。仅使用自己的校园网账号。

## 安装

在 Debian 13 或更新版本上构建并安装：

```sh
./build.sh
sudo apt install ./dist/h3c-campus_0.2.4-1_all.deb
```

从应用菜单打开“至诚校园网”，选择有线网卡，输入账号和密码，点“连接”。授权窗口通过 `run0` 或 `pkexec` 获取原始网卡访问权。界面显示认证、IPv4 状态与事件；认证成功后发桌面提醒。“断开”发送下线报文。窗口关闭或最小化后驻留托盘；在托盘菜单点“退出”才会结束客户端。勾选“登录桌面时启动”可设置当前用户的 XDG 自启动，启动时最小化到托盘。密码只经标准输入传给客户端，不写入命令参数；桌面界面不保存密码。

每日 06:00 自动登入可启用 `h3c-campus-daily.timer`。管理员须先创建仅 root 可读的 `/etc/h3c-campus/daily.conf`（`INTERFACE`、`USERNAME`）及 `/etc/h3c-campus/password`（单行密码，权限 `0600`），再执行 `systemctl enable --now h3c-campus-daily.timer`。定时器不补跑错过的时刻；认证进程持续运行，需断开时执行 `systemctl stop h3c-campus-daily.service`。桌面界面的手动“连接”勿与定时服务同时运行。

已有其他 802.1X 客户端时，先退出同一网卡上的旧客户端。NetworkManager 有线连接宜设为自动 IPv4。本程序不覆盖 IP、路由或 DNS 配置；认证后仅请求现有网络管理器续租 DHCP。

命令行仍可用：

```sh
h3c-campus --list-interfaces
sudo h3c-campus --interface enp4s0 --renew-dhcp
sudo h3c-campus --interface enp4s0 --probe
```

将 `enp4s0` 改为实际有线网卡。`--probe` 仅发送 EAPOL Start，不发送账号密码；收到 `EAPOL_REACHABLE` 才证明二层可达。首次认证失败不会反复提交密码。已上线会话重认证失败时，最多重试三次。

## 状态

- `AUTH_SUCCESS`：交换机接受 802.1X 认证。
- `IPV4_PRESENT`：网卡已有 IPv4；仍需实际网络访问验证。
- `AUTH_REJECTED`：服务端拒绝认证。
- `NO_EAPOL_REPLY`：交换机未回复，先检查网线及有线网卡。
- `NO_IPV4_AFTER_AUTH`：认证成功，但尚无可用 IPv4。
- `UNSUPPORTED_SECURE_HEARTBEAT`：遇到尚未实现的旧式私有握手。

一次 Linux 实机测试收到了 `AUTH_SUCCESS`，取得 IPv4，且有线口可达公网 IP；随后在校网计划断网时段收到 `AUTH_REJECTED`。持续在线及不同校园网环境仍需自行验证。默认使用该场景观察到的广播 Start，可用 `--multicast` 切换标准 PAE 组播。EAP-MD5 按实际请求 ID 计算响应；H3C 版本扩展动态生成。私有安全心跳未实现，未知通知仅记事件、不记录原始载荷。

## 开发

```sh
python3 -m unittest discover -s tests -v
./build.sh
```

运行界面需 GTK 3 与 PyGObject（Debian 包自动安装）；认证需 Linux `AF_PACKET` 与 `CAP_NET_RAW`。托盘依赖桌面环境支持 XEmbed 状态图标，已在 KDE 测试。源码许可见 [LICENSE](LICENSE)。图标为[福州大学校徽](https://www.fzu.edu.cn/xxgk/xbxx.htm)，由用户提供，不在 MIT 许可范围内；本软件非学校官方产品。
