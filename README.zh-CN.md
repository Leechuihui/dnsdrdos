[English](README.md) | **简体中文**

# dnsdrdos — 2026 版

[![C](https://img.shields.io/badge/C-C11-red?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language)) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE) [![Category: Security](https://img.shields.io/badge/Category-Security-8b5cf6)](https://github.com/Leechuihui/dnsdrdos)

## 📋 概述

dnsdrdos 是一款高性能 DNS 分布式反射 DoS 攻击工具。
经过 2026 年升级版，引入了多线程攻击引擎、IPv6 支持、DNSSEC 感知和实时统计功能，同时保留了 noptrix 经典的 nullsecurity 版本精髓。

## 2026 新版本特性

| 特性 | 0.1 版（2010） | 2.6.0 版（2026） |
|----------------|---------------------|----------------------|
| 架构 | 单线程（1 线程） | 多线程线程池（默认 4，最多 64+） |
| 协议 | 仅 IPv4 | 双栈 IPv4 / IPv6 |
| 攻击模式 | 简单 A 记录反射 | ANY、TXT、MX、SOA、SRV、NS、DNSSEC、EDNS0 |
| 放大倍数 | 约 7:1 | DNSSEC + EDNS0 下最高 70:1 |
| 数据包大小 | 1400 字节 | 最高 1500 字节（支持巨帧） |
| 源端口 | rand() / 8 位 | 16 位随机 + 每线程偏移 |
| 统计 | 无 | 实时每线程计数器 + 累计统计 |
| DNSSEC | 基本感知 | EDNS0 OPT 记录、置位 DO-bit、大型 DNSSEC 查询 |
| 速率限制 | 无 | 可配置窗口（10ms 粒度） |
| 优雅退出 | Ctrl-C / SIGINT | 处理 SIGINT + SIGTERM + SIGHUP |
| 详细模式 | 无 | -v 参数实时展示攻击状态 |
| TTL / ToS | 固定（64）/ 0 | 自定义 TTL、自定义 ToS/DSCP 值 |
| 域名随机化 | 固定域名 | 唯一子域标签绕过 DNS 缓存 |
| DNS 服务器过滤 | 无 | 用 'D' 参数筛选支持 DNSSEC 的服务器 |
| UDP 分片 | 无 | 支持分片 |

---

## 核心技术升级

### 1. 多线程攻击引擎
原版（v0.1）通过单个 raw socket 顺序发送每个 DNS 数据包。
2026 版生成一个线程池（可通过 `-t` 配置），每个线程拥有自己的 socket、数据包缓冲区和统计计数器，实现 **CPU 并行**反射，最大化对目标服务器的网络饱和压测。

### 2. 双栈 IPv4 / IPv6 支持
在数据包结构中使用 **sockaddr_in** 与 **sockaddr_in6** 联合体增强。
新版本自动检测目标 IP 协议族，动态配置 raw socket、TTL 和地址族。

### 3. DNS 放大模式
新增专用 DNS 查询的数据包负载结构，最大化响应与请求的体积比：

- AMPL_TXT — TXT 记录可产生约 500-700 字节响应
- AMPL_ANY — ANY 查询返回所有记录（峰值放大）
- AMPL_DNSSEC — DNSKEY RR 产生 1500+ 字节响应
- AMPL_OPT — EDNS0 OPT 伪 RR，负载最高 **4096 字节**

### 4. DNSSEC 感知
DNS 查询中包含置位 **DO-bit** 的 EDNS0 OPT 伪记录，促使 DNS 服务器返回带 DNSSEC 签名的响应（约 830+ 字节，而裸 A 记录仅 40 字节）。

### 5. 源端口随机化
每个线程在源端口范围内使用各自的偏移（`base + thread_index * offset`），更有效地绕过**连接跟踪和 NAT 状态表。

### 6. 实时统计
专用统计结构按**线程**跟踪：
- 已发送数据包数
- 已发送字节数
- 发送错误数
- 累计发送字节数

---

## 用法

```bash
./dnsdrdos -f nameserver.lst -s 192.168.2.211 -d google.com -l 10000 -t 8 -m -vD46
```

| 标志 | 说明 |
|-------------|-------------------|
| `-f <file>` | DNS 服务器列表（每行一个） |
| `-s <addr>` | 伪造源地址 |
| `-d <domain>` | 目标域名（默认 `google.com.`） |
| `-l <loops>` | 遍历列表次数（默认 2500） |
| `-t <threads>` | 生成的线程数（默认 4） |
| `-m` | TXT 放大模式 |
| `-v` | 详细模式 |
| `-D` | DNS 服务器过滤（DNSSEC） |
| `-4` | 强制 IPv4 |
| `-6` | 强制 IPv6 |
| `-n` | 启用域名随机化 |
| `-h` | 帮助 |
| `-V` | 版本 |

---

## 版本对比

| 方面 | 旧版（v0.1） | 新版（v2.6.0） |
|--------|-----------|-------------|
| 单线程 | ✅ | ✅（现已并行化） |
| 包含 IP 头 | ✅ | ✅ |
| 仅 IPv4 | ✅ | ❌（双栈） |
| IPv6 | ❌ | ✅ |
| DNSSEC | 部分支持 | ✅（EDNS0 + DO-bit） |
| 放大倍数 | 约 7:1 | 约 70:1 |
| 速率限制 | ❌ | ✅ |
| 每线程统计 | ❌ | ✅ |
| 优雅退出 | SIGINT | SIGINT + SIGTERM + SIGHUP |
| 域名随机化 | ❌ | ✅ |
| 详细模式 | ❌ | ✅（-v 参数） |
| 分片 | ❌ | ✅ |
| 线程池 | ❌ | ✅ |
| 大查询支持 | ❌（42 字节） | ✅（最高 1500 字节） |

---

## ⚠️ 免责声明

`dnsdrdos` v2.6.0 仅供测试和学术研究目的使用。作者不对因使用或误用本程序而引起的任何直接或间接损失承担赔偿责任，包括但不限于网络中断、服务不可用、带宽耗尽和基础设施过载等情形。

在目标网络环境中对 DNS 服务发起分布式反射攻击之前，请确保已获得目标网络运营商或服务提供商的书面或口头许可。在未经授权的条件下使用本程序可能导致：

- 目标网络服务中断（DDoS 效应）
- DDoS 流量被反向追踪至本程序主机
- 服务提供商的带宽超额费用
- 网络服务条款（SLA）违反
- 法律诉讼风险

使用者须知：
- 本程序为单台主机设计的测试工具，适用于小规模实验性 DoS 攻击
- 建议用于测试目的，请勿在未经授权的条件下大规模使用
- 建议在可控环境中对特定 IP 地址进行测试
- 本程序不针对特定端口进行优化，可通过 `-l` 参数调整发送速率

版权说明：
- 原作者：`noptrix` (http://www.nullsecurity.net/)
- 2026 版升级作者：Leechuihui（2026 年 5 月）
- 许可协议：BSD-3（与 Nullsecurity 联合许可）
- 本程序保留原始作者著作权，2026 年升级版由 Leechuihui 独立设计

使用风险：
本程序按“现状”提供，不提供任何形式的保证。在没有任何明示或默示保证的情况下，作者不对程序的性能、功能和适用性承担责任。使用者需自行承担使用本程序的全部风险。

---

## 许可协议

完整细节见：[http://www.nullsecurity.net](http://www.nullsecurity.net)

与 Nullsecurity 双重许可（BSD-3-Clause）。

原版：`noptrix` — dnsdrdos（约 2010 年）
2026 升级版：Leechuihui

---

## 📁 发布内容

```
dnsdrdos/
├── dnsdrdos.c      — 主源代码（v2.6.0，2026 升级版）
├── README.md       — 本文件
└── LICENSE         — BSD-3 条款（包含在源码中）
```

编译：
```bash
gcc -O2 -o dnsdrdos dnsdrdos.c -lpthread
```

---

## 致谢

- noptrix — dnsdrdos 原作者，nullsecurity 创始人
- Leechuihui — 2026 升级版设计者与开发者
- Nullsecurity — 托管方与原始许可提供方

---

Built with ❤️ on May-25-2026 — 为 2026 年网络环境精心打造，献给每一位渗透测试者。
