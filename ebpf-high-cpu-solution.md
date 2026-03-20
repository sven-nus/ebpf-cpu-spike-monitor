# eBPF 高 CPU 尖峰监控与分析方案

## 目录

- [1. 方案概述](#1-方案概述)
- [2. 问题背景](#2-问题背景)
- [3. 技术架构](#3-技术架构)
- [4. 核心组件](#4-核心组件)
- [5. 工作流程](#5-工作流程)
- [6. 部署方案](#6-部署方案)
- [7. 数据分析方法](#7-数据分析方法)
- [8. 实战案例](#8-实战案例)
- [9. 最佳实践](#9-最佳实践)

---

## 1. 方案概述

### 1.1 方案定位

基于 eBPF (Extended Berkeley Packet Filter) 技术的零侵入式 CPU 性能监控方案，专门用于捕获和分析生产环境中的瞬时 CPU 尖峰问题。

### 1.2 核心价值

| 特性 | 说明 | 优势 |
|------|------|------|
| **零侵入** | 无需修改应用代码或重启服务 | 适用于生产环境 |
| **低开销** | 仅在检测到尖峰时采样 | CPU 开销 < 1% |
| **精准定位** | 同时捕获内核态和用户态堆栈 | 快速定位根因 |
| **自动化** | 自动检测、采样、生成报告 | 无需人工干预 |
| **实时性** | 2 秒检测周期，15 秒完成采样 | 不错过瞬时尖峰 |

### 1.3 适用场景

- ✅ ARM Graviton 实例 vCPU 负载不均衡
- ✅ 间歇性 CPU 尖峰排查（难以复现）
- ✅ 高性能服务性能调优
- ✅ 生产环境性能分析（低开销要求）
- ✅ 微服务容器化环境（K8s/ECS）

---

## 2. 问题背景

### 2.1 典型问题场景

**场景 1: ARM Graviton vCPU 不均衡**
```
vCPU 0:  ████████████████████████████████ 95%
vCPU 1:  ████ 12%
vCPU 2:  ███ 8%
vCPU 3:  ██ 5%
...
vCPU 15: █ 3%
```

**问题特征:**
- 单个 vCPU 持续高负载
- 其他 vCPU 空闲
- 应用响应延迟增加
- 传统监控工具只能看到平均值

**场景 2: 瞬时 CPU 尖峰**
```
时间轴: ─────▲─────────▲──────────▲─────
CPU:    20%  95%  18%   92%  15%   88%  22%
        ↑    ↑    ↑     ↑    ↑     ↑    ↑
        正常 尖峰 正常  尖峰 正常  尖峰 正常
```

**问题特征:**
- 持续时间短（几秒到几十秒）
- 难以复现
- 传统 profiling 工具无法捕获
- 影响用户体验但难以定位

### 2.2 传统方案的局限性

| 工具 | 局限性 | 对比 eBPF |
|------|--------|-----------|
| **top/htop** | 只能看实时快照，无法捕获瞬时尖峰 | eBPF 自动触发采样 |
| **perf** | 需要手动启动，开销较大 | eBPF 低开销，自动化 |
| **strace** | 只能跟踪系统调用，看不到用户态 | eBPF 同时捕获内核+用户态 |
| **应用 profiler** | 需要修改代码，有侵入性 | eBPF 零侵入 |
| **APM 工具** | 采样频率低，成本高 | eBPF 99Hz 高频采样 |

---

## 3. 技术架构

### 3.1 整体架构图

```
┌─────────────────────────────────────────────────────────────┐
│                        监控层 (Monitor)                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  mpstat -P ALL 1 1  (每 2 秒采样所有 vCPU)            │   │
│  │  ↓                                                     │   │
│  │  计算最大 vCPU 使用率                                  │   │
│  │  ↓                                                     │   │
│  │  检测 CPU 增长 > 30% ?  ──No──→ 继续监控              │   │
│  │  ↓ Yes                                                 │   │
│  │  触发 eBPF 采样                                        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      采样层 (eBPF/bpftrace)                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  profile:hz:99  (99Hz 频率采样)                       │   │
│  │  ↓                                                     │   │
│  │  过滤目标进程 (可配置)                                │   │
│  │  ↓                                                     │   │
│  │  捕获堆栈:                                             │   │
│  │    - kstack (内核态调用链)                            │   │
│  │    - ustack (用户态调用链)                            │   │
│  │  ↓                                                     │   │
│  │  聚合统计 (15 秒采样窗口)                             │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      输出层 (Report)                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  生成报告:                                             │   │
│  │    - 时间戳 + 触发 CPU 值                             │   │
│  │    - 堆栈聚合统计 (函数 + 调用次数)                   │   │
│  │    - 系统快照 (mpstat, 进程状态)                      │   │
│  │  ↓                                                     │   │
│  │  保存到 /tmp/ebpf_reports/spike_YYYYMMDD_HHMMSS.txt  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   可视化层 (Optional)                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Prometheus + Grafana                                  │   │
│  │    - 实时 vCPU 使用率曲线                             │   │
│  │    - Per-Core CPU 热力图                              │   │
│  │    - 尖峰事件告警                                      │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 数据流图

```
┌──────────┐   2s 轮询    ┌──────────┐   触发条件    ┌──────────┐
│  mpstat  │ ──────────→ │ 监控脚本  │ ──────────→ │ bpftrace │
│  (CPU)   │              │ (Bash)   │   CPU+30%    │  (eBPF)  │
└──────────┘              └──────────┘              └──────────┘
                                                           │
                                                           │ 15s 采样
                                                           ↓
                          ┌──────────┐              ┌──────────┐
                          │  报告    │ ←─────────  │  内核    │
                          │  文件    │   堆栈数据   │  BPF VM  │
                          └──────────┘              └──────────┘
                                │                         ↑
                                │                         │
                                ↓                         │
                          ┌──────────┐              ┌──────────┐
                          │ Grafana  │              │  目标    │
                          │ 可视化   │              │  进程    │
                          └──────────┘              └──────────┘
```

---

## 4. 核心组件

### 4.1 监控组件 (Monitor)

**功能:** 持续监控 vCPU 使用率，检测异常尖峰

**实现:**
```bash
get_max_vcpu_usage() {
    mpstat -P ALL 1 1 | awk '/Average:/ && $2 ~ /[0-9]/ {print 100-$NF}' | sort -rn | head -1
}

# 主循环
while true; do
    curr_cpu=$(get_max_vcpu_usage)
    delta=$(echo "$curr_cpu - $prev_cpu" | bc)
    
    if (( $(echo "$delta > $SPIKE_THRESHOLD" | bc -l) )); then
        capture_ebpf_trace "$timestamp" "$curr_cpu"
        cooldown=15  # 冷却 30 秒
    fi
    
    prev_cpu=$curr_cpu
    sleep 2
done
```

**关键参数:**
- `SPIKE_THRESHOLD=30`: CPU 增长阈值 (%)
- 检测周期: 2 秒
- 冷却时间: 30 秒 (防止频繁触发)

### 4.2 采样组件 (eBPF Tracer)

**功能:** 在 CPU 尖峰时高频采样进程堆栈

**eBPF 程序:**
```c
profile:hz:99 /comm == "my-server"/ {
    @cpu_stack[comm, kstack, ustack] = count();
}
END {
    print(@cpu_stack);
    clear(@cpu_stack);
}
```

**工作原理:**
1. **profile:hz:99**: 每秒采样 99 次 (10.1ms 间隔)
2. **进程过滤**: 只采样目标进程 (comm 字段)
3. **堆栈捕获**:
   - `kstack`: 内核态调用链 (系统调用、中断处理)
   - `ustack`: 用户态调用链 (应用函数)
4. **聚合统计**: 相同堆栈累加计数
5. **采样窗口**: 15 秒 (99 * 15 = 1485 个样本)

**关键参数:**
- 采样频率: 99 Hz
- 采样时长: 15 秒
- 目标进程: 可配置数组

### 4.3 报告组件 (Reporter)

**功能:** 生成结构化性能分析报告

**报告结构:**
```
spike_20260302_091254.txt
├── 触发信息
│   ├── 时间戳
│   ├── CPU 使用率
│   └── 采样时长
├── 堆栈统计
│   ├── 进程名
│   ├── 内核态调用链
│   ├── 用户态调用链
│   └── 出现次数
└── 系统快照
    ├── mpstat 输出
    └── 进程状态
```

**示例输出:**
```
[Mon Mar 2 09:12:54 UTC 2026] 检测到 vCPU 尖峰: 95.96%, 开始采样 15s...

@cpu_stack[my-server, 
    ep_poll+848                    # 内核: epoll 等待
    do_epoll_wait+236
    __arm64_sys_epoll_pwait+124
, 
    aeApiPoll.lto_priv.0+92       # 用户: 事件循环
    aeMain+564
    main+1188
]: 1247                            # 出现 1247 次

=== 系统快照 ===
时间: Mon Mar  2 09:13:09 UTC 2026
Average:     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
Average:     all   45.23    0.00   12.45    0.12    0.00    2.34    0.00    0.00    0.00   39.86
Average:       0   95.96    0.00   3.04    0.00    0.00    1.00    0.00    0.00    0.00    0.00
Average:       1   12.34    0.00   1.23    0.00    0.00    0.43    0.00    0.00    0.00   86.00
...
```

---

## 5. 工作流程

### 5.1 完整流程图

```
开始
  │
  ├─→ [初始化]
  │     ├─ 检查依赖 (bpftrace, mpstat)
  │     ├─ 创建报告目录
  │     └─ 设置参数 (阈值、目标进程)
  │
  ├─→ [监控循环]
  │     │
  │     ├─ 采样所有 vCPU 使用率 (mpstat)
  │     │
  │     ├─ 计算最大 vCPU 使用率
  │     │
  │     ├─ 计算与上次的增量 (delta)
  │     │
  │     ├─ delta > 30% ?
  │     │   │
  │     │   ├─ No ──→ 等待 2 秒 ──→ 返回监控循环
  │     │   │
  │     │   └─ Yes ──→ [触发采样]
  │     │                 │
  │     │                 ├─ 生成时间戳
  │     │                 │
  │     │                 ├─ 启动 bpftrace (15 秒)
  │     │                 │   ├─ 99Hz 采样频率
  │     │                 │   ├─ 过滤目标进程
  │     │                 │   ├─ 捕获 kstack + ustack
  │     │                 │   └─ 聚合统计
  │     │                 │
  │     │                 ├─ 并行采集系统快照
  │     │                 │   ├─ mpstat 输出
  │     │                 │   └─ 进程状态
  │     │                 │
  │     │                 ├─ 生成报告文件
  │     │                 │
  │     │                 ├─ 设置冷却期 (30 秒)
  │     │                 │
  │     │                 └─ 返回监控循环
  │     │
  │     └─ 冷却期 > 0 ?
  │           ├─ Yes ──→ 冷却计数 -1 ──→ 等待 2 秒 ──→ 返回监控循环
  │           └─ No ──→ 返回监控循环
  │
  └─→ [异常处理]
        ├─ Ctrl+C 信号 ──→ 清理资源 ──→ 退出
        └─ 错误 ──→ 记录日志 ──→ 返回监控循环
```

### 5.2 时序图

```
时间轴    监控脚本              mpstat              bpftrace            目标进程
  │
  0s      启动监控
  │         │
  2s        ├─ 采样 CPU ──→    执行
  │         │                   │
  │         │ ←─ 返回 CPU=25% ─┤
  │         │
  4s        ├─ 采样 CPU ──→    执行
  │         │                   │
  │         │ ←─ 返回 CPU=28% ─┤
  │         │
  6s        ├─ 采样 CPU ──→    执行
  │         │                   │
  │         │ ←─ 返回 CPU=62% ─┤  (增长 34% > 30%)
  │         │
  │         ├─ 触发采样 ──────────→ 启动 profile:hz:99
  │         │                                │
  │         │                                ├─ 过滤进程 ──→ 读取 comm
  │         │                                │                  │
  │         │                                │ ←─ my-server ┤
  │         │                                │
  6-21s     │                                ├─ 采样堆栈 (15s)
  │         │                                │   ├─ 捕获 kstack
  │         │                                │   ├─ 捕获 ustack
  │         │                                │   └─ 聚合计数
  │         │                                │
  21s       │ ←─ 返回堆栈统计 ───────────────┤
  │         │
  │         ├─ 生成报告
  │         │
  │         ├─ 设置冷却 (30s)
  │         │
  23s       ├─ 采样 CPU (冷却中)
  │         │
  ...       ...
  │
  51s       ├─ 冷却结束，恢复正常监控
  │         │
```

### 5.3 状态机

```
┌─────────────┐
│   INIT      │  初始化状态
│  (启动)     │
└──────┬──────┘
       │
       ↓
┌─────────────┐
│  MONITORING │  监控状态
│  (正常监控) │  ←──────────────┐
└──────┬──────┘                 │
       │                        │
       │ CPU 增长 > 30%         │
       ↓                        │
┌─────────────┐                 │
│  SAMPLING   │  采样状态        │
│  (eBPF采样) │                 │
└──────┬──────┘                 │
       │                        │
       │ 采样完成               │
       ↓                        │
┌─────────────┐                 │
│  REPORTING  │  报告状态        │
│  (生成报告) │                 │
└──────┬──────┘                 │
       │                        │
       │ 报告完成               │
       ↓                        │
┌─────────────┐                 │
│  COOLDOWN   │  冷却状态        │
│  (30秒冷却) │  ────────────────┘
└─────────────┘   冷却结束
```

---

## 6. 部署方案

### 6.1 方案对比

| 部署方式 | 适用场景 | 优势 | 劣势 |
|---------|---------|------|------|
| **独立脚本** | 单机调试、临时排查 | 简单快速、易于调试 | 需要手动管理 |
| **Systemd 服务** | 生产环境单机 | 自动启动、日志管理 | 仅限单机 |
| **K8s DaemonSet** | 容器化集群 | 自动部署、统一管理 | 需要 K8s 环境 |
| **ECS Task** | AWS ECS 环境 | 与 ECS 集成 | 配置复杂 |

### 6.2 独立脚本部署

**步骤 1: 安装依赖**
```bash
# Amazon Linux 2023 / AL2
sudo dnf install -y bcc-tools bpftrace kernel-devel-$(uname -r) sysstat bc

# Ubuntu / Debian
sudo apt-get install -y bpftrace linux-headers-$(uname -r) sysstat bc

# 验证安装
bpftrace --version
mpstat -V
```

**步骤 2: 下载脚本**
```bash
curl -O https://your-repo/ebpf-monitor-improved.sh
chmod +x ebpf-monitor-improved.sh
```

**步骤 3: 配置参数**
```bash
# 编辑脚本
vim ebpf-monitor-improved.sh

# 修改配置
SPIKE_THRESHOLD=30              # CPU 增长阈值
TARGET_PROCS=("my-server")      # 目标进程
SAMPLE_DURATION=15              # 采样时长
```

**步骤 4: 运行**
```bash
# 前台运行 (调试)
sudo ./ebpf-monitor-improved.sh

# 后台运行
nohup sudo ./ebpf-monitor-improved.sh > /tmp/ebpf-monitor.log 2>&1 &

# 查看日志
tail -f /tmp/ebpf-monitor.log

# 查看报告
ls -lh /tmp/ebpf_reports/
```

### 6.3 Systemd 服务部署

**步骤 1: 安装脚本**
```bash
sudo cp ebpf-monitor-improved.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/ebpf-monitor-improved.sh
```

**步骤 2: 创建服务文件**
```bash
sudo tee /etc/systemd/system/ebpf-monitor.service > /dev/null << 'EOF'
[Unit]
Description=eBPF vCPU Spike Monitor
After=network.target
Documentation=https://your-docs-url

[Service]
Type=simple
ExecStart=/usr/local/bin/ebpf-monitor-improved.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ebpf-monitor

# 安全加固
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

**步骤 3: 启动服务**
```bash
# 重载配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start ebpf-monitor

# 设置开机自启
sudo systemctl enable ebpf-monitor

# 查看状态
sudo systemctl status ebpf-monitor

# 查看日志
sudo journalctl -u ebpf-monitor -f
```

**步骤 4: 管理服务**
```bash
# 停止服务
sudo systemctl stop ebpf-monitor

# 重启服务
sudo systemctl restart ebpf-monitor

# 禁用自启
sudo systemctl disable ebpf-monitor
```

### 6.4 Kubernetes DaemonSet 部署

**步骤 1: 创建 ConfigMap**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ebpf-monitor-script
  namespace: monitoring
data:
  ebpf-monitor.sh: |
    #!/bin/bash
    # 脚本内容 (省略，见完整脚本)
```

**步骤 2: 创建 DaemonSet**
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-monitor
  namespace: monitoring
  labels:
    app: ebpf-monitor
spec:
  selector:
    matchLabels:
      app: ebpf-monitor
  template:
    metadata:
      labels:
        app: ebpf-monitor
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: monitor
        image: amazonlinux:2023
        command: ["/bin/bash", "/scripts/ebpf-monitor.sh"]
        securityContext:
          privileged: true
          capabilities:
            add:
            - SYS_ADMIN
            - SYS_RESOURCE
        volumeMounts:
        - name: scripts
          mountPath: /scripts
        - name: reports
          mountPath: /tmp/ebpf_reports
        - name: sys
          mountPath: /sys
        - name: debugfs
          mountPath: /sys/kernel/debug
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
      volumes:
      - name: scripts
        configMap:
          name: ebpf-monitor-script
          defaultMode: 0755
      - name: reports
        hostPath:
          path: /tmp/ebpf_reports
          type: DirectoryOrCreate
      - name: sys
        hostPath:
          path: /sys
      - name: debugfs
        hostPath:
          path: /sys/kernel/debug
```

**步骤 3: 部署**
```bash
# 应用配置
kubectl apply -f ebpf-monitor-configmap.yaml
kubectl apply -f ebpf-monitor-daemonset.yaml

# 查看状态
kubectl get daemonset -n monitoring
kubectl get pods -n monitoring -l app=ebpf-monitor

# 查看日志
kubectl logs -n monitoring -l app=ebpf-monitor -f

# 进入容器查看报告
kubectl exec -it -n monitoring <pod-name> -- ls -lh /tmp/ebpf_reports/
```

### 6.5 一键部署脚本 (AWS + K8s + Grafana)

**使用方法:**
```bash
# 下载部署脚本
curl -O https://your-repo/deploy-k8s-ebpf-grafana.sh
chmod +x deploy-k8s-ebpf-grafana.sh

# 执行部署 (约 10-15 分钟)
./deploy-k8s-ebpf-grafana.sh

# 输出示例:
# ==========================================
# ✓ 部署完成！
# ==========================================
# 
# 实例信息:
#   实例ID: i-0123456789abcdef0
#   公网IP: 54.123.45.67
# 
# 访问地址:
#   Grafana:    http://54.123.45.67:30300
#               用户名: admin
#               密码: admin
#   Prometheus: http://54.123.45.67:30090
#   SSH:        ssh -i k8s-arm-key.pem ec2-user@54.123.45.67
# 
# eBPF 报告位置: /tmp/ebpf_reports/
# ==========================================
```

**部署内容:**
- ✅ AWS EC2 实例 (t4g.medium ARM)
- ✅ K3s Kubernetes 集群
- ✅ eBPF 监控 DaemonSet
- ✅ Prometheus + Node Exporter
- ✅ Grafana + 预配置仪表板
- ✅ 自动配置数据源和告警

---

## 7. 数据分析方法

### 7.1 报告结构解读

**完整报告示例:**
```
[Mon Mar  2 09:12:54 UTC 2026] 检测到 vCPU 尖峰: 95.96%, 开始采样 15s...

@cpu_stack[my-server, 
    hrtimer_start_range_ns+220
    schedule_hrtimeout_range_clock+148
    ep_poll+848
    do_epoll_wait+236
    __arm64_sys_epoll_pwait+124
    invoke_syscall+80
    el0_svc_common.constprop.0+84
    do_el0_svc+60
    el0_svc+52
    el0t_64_sync_handler+188
, 
    epoll_pwait+36
    aeApiPoll.lto_priv.0+92
    aeMain+564
    main+1188
    __libc_start_main+156
    _start+48
]: 1247

@cpu_stack[my-server, 
    folio_add_lru+100
    lru_cache_add_inactive_or_unevictable+40
    do_anonymous_page+684
    handle_pte_fault+528
    __handle_mm_fault+520
    handle_mm_fault+236
    do_page_fault+368
    do_mem_abort+76
    el0_da+80
, 
    dictAddRaw+148
    initConfigValues+224
    main+1188
]: 89

=== 系统快照 ===
时间: Mon Mar  2 09:13:09 UTC 2026
Average:     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
Average:     all   45.23    0.00   12.45    0.12    0.00    2.34    0.00    0.00    0.00   39.86
Average:       0   95.96    0.00   3.04    0.00    0.00    1.00    0.00    0.00    0.00    0.00
Average:       1   12.34    0.00   1.23    0.00    0.00    0.43    0.00    0.00    0.00   86.00

=== 目标进程状态 ===
PID 1234: 95.2 2.3 /usr/bin/my-server *:6379
```

### 7.2 堆栈分析步骤

**步骤 1: 识别热点函数**

查看调用次数最多的堆栈:
```
]: 1247  ← 出现 1247 次 (占 93% 采样)
]: 89    ← 出现 89 次 (占 7% 采样)
```

**结论:** 第一个堆栈是主要热点

**步骤 2: 分析内核态堆栈**

```
内核态调用链 (从下往上读):
el0t_64_sync_handler+188    ← ARM64 系统调用入口
el0_svc+52                  ← 系统调用处理
do_el0_svc+60               ← 执行系统调用
invoke_syscall+80           ← 调用具体系统调用
__arm64_sys_epoll_pwait+124 ← epoll_pwait 系统调用
do_epoll_wait+236           ← epoll 等待实现
ep_poll+848                 ← epoll 轮询
schedule_hrtimeout_range_clock+148  ← 高精度定时器
hrtimer_start_range_ns+220  ← 启动定时器
```

**结论:** 进程在 epoll_pwait 系统调用中等待事件

**步骤 3: 分析用户态堆栈**

```
用户态调用链 (从下往上读):
_start+48                   ← 程序入口
__libc_start_main+156       ← C 运行时初始化
main+1188                   ← main 函数
aeMain+564                  ← 事件循环主函数
aeApiPoll.lto_priv.0+92     ← 事件 API 轮询
epoll_pwait+36              ← 用户态 epoll_pwait 调用
```

**结论:** 进程在事件循环中等待 I/O 事件

**步骤 4: 综合分析**

| 维度 | 分析结果 |
|------|---------|
| **CPU 消耗点** | epoll_pwait 系统调用 |
| **根本原因** | 单线程事件循环在单个 vCPU 上运行 |
| **优化方向** | 1. 启用多线程 I/O<br>2. 使用 CPU 亲和性绑定<br>3. 调整 epoll 超时参数 |

### 7.3 常见模式识别

**模式 1: I/O 等待**
```
特征:
- 内核栈: ep_poll, do_epoll_wait
- 用户栈: aeApiPoll, eventLoop

诊断: 单线程事件循环
优化: 启用 I/O 多线程
```

**模式 2: 内存分配**
```
特征:
- 内核栈: do_anonymous_page, handle_mm_fault
- 用户栈: malloc, dictAddRaw

诊断: 频繁内存分配导致缺页中断
优化: 预分配内存池、调整 jemalloc 参数
```

**模式 3: 锁竞争**
```
特征:
- 内核栈: futex_wait_queue, schedule
- 用户栈: pthread_mutex_lock

诊断: 多线程锁竞争
优化: 减少锁粒度、使用无锁数据结构
```

**模式 4: 系统调用开销**
```
特征:
- 内核栈: invoke_syscall, el0_svc
- 用户栈: write, read, send, recv

诊断: 频繁系统调用
优化: 批量操作、使用 io_uring
```

### 7.4 对比分析方法

**场景: 对比优化前后性能**

**步骤 1: 收集基线数据**
```bash
# 优化前运行 1 小时
ls /tmp/ebpf_reports/ | wc -l
# 输出: 12 (触发 12 次尖峰)
```

**步骤 2: 应用优化**
```bash
# 例如: 调整应用配置以优化性能
# 具体优化方式取决于目标进程类型
```

**步骤 3: 收集优化后数据**
```bash
# 优化后运行 1 小时
ls /tmp/ebpf_reports/ | wc -l
# 输出: 3 (触发 3 次尖峰)
```

**步骤 4: 对比堆栈分布**
```bash
# 提取热点函数
grep -A 20 "@cpu_stack" spike_before.txt | grep "^    " | sort | uniq -c
grep -A 20 "@cpu_stack" spike_after.txt | grep "^    " | sort | uniq -c
```

**步骤 5: 生成对比报告**
```
指标对比:
- 尖峰频率: 12 次/小时 → 3 次/小时 (降低 75%)
- 最大 CPU: 95.96% → 78.23% (降低 18%)
- 热点函数: epoll_pwait (93%) → 分散到多个线程 (< 40%)
```

---

## 8. 实战案例

### 8.1 案例 1: 容器 CPU 限流

**问题描述:**
- 环境: Kubernetes (EKS on Graviton3)
- 现象: Pod CPU 使用率显示 80%，但应用响应慢
- 影响: 用户投诉延迟高

**eBPF 采样结果:**
```
@cpu_stack[my-server,
    cpu_cfs_period_timer+156
    __hrtimer_run_queues+284
    hrtimer_interrupt+248
,
    (无用户态堆栈)
]: 1123  (75% 采样)
```

**根因分析:**
1. Kubernetes CPU 限流 (CFS throttling)
2. Pod CPU limit 设置过低 (500m)
3. 实际需求 > 限制，导致频繁限流

**验证限流:**
```bash
# 查看容器 CPU 限流统计
kubectl exec -it <pod> -- cat /sys/fs/cgroup/cpu/cpu.stat
nr_periods 1000000
nr_throttled 450000      # 45% 的时间被限流
throttled_time 2250000000000  # 累计限流 2250 秒
```

**优化方案:**
```yaml
# 调整 Pod 资源配置
resources:
  requests:
    cpu: 1000m      # 1 核
  limits:
    cpu: 2000m      # 2 核 (增加 headroom)
```

**优化效果:**
| 指标 | 优化前 | 优化后 | 改善 |
|------|--------|--------|------|
| CPU 限流比例 | 45% | 2% | ↓ 96% |
| P99 延迟 | 120ms | 8ms | ↓ 93% |
| 吞吐量 | 25K ops/s | 95K ops/s | ↑ 280% |

### 8.2 案例 2: NUMA 亲和性问题

**问题描述:**
- 环境: 大型实例 (m7g.16xlarge, 64 vCPU, 2 NUMA 节点)
- 现象: 跨 NUMA 访问导致延迟增加
- 影响: 性能不稳定

**eBPF 采样结果:**
```
@cpu_stack[my-server,
    __alloc_pages+324
    alloc_pages_vma+156
    do_numa_page+448
    handle_pte_fault+628
,
    dictAddRaw+148
]: 678  (45% 采样)
```

**根因分析:**
1. 进程在 NUMA 节点 0 运行
2. 内存分配在 NUMA 节点 1
3. 跨 NUMA 访问延迟高 (2-3x)

**验证 NUMA 分布:**
```bash
# 查看进程 NUMA 分布
numastat -p $(pgrep my-server)
                           Node 0          Node 1
                           --------------- ---------------
Huge                                  0.00            0.00
Heap                               1024.00         3072.00  # 大部分内存在节点 1
Stack                                 8.00            0.00
Private                             128.00          512.00
```

**优化方案:**
```bash
# 方案 1: 绑定到单个 NUMA 节点
numactl --cpunodebind=0 --membind=0 my-server /etc/my-server.conf

# 方案 2: 使用 CPU 亲和性
taskset -c 0-31 my-server /etc/my-server.conf  # 绑定到前 32 个 vCPU
```

**优化效果:**
| 指标 | 优化前 | 优化后 | 改善 |
|------|--------|--------|------|
| 跨 NUMA 访问 | 45% | 2% | ↓ 96% |
| 内存访问延迟 | 180ns | 65ns | ↓ 64% |
| P99 延迟 | 15ms | 4ms | ↓ 73% |

---

## 9. 最佳实践

### 9.1 参数调优指南

**CPU 阈值设置 (SPIKE_THRESHOLD)**

| 场景 | 推荐值 | 说明 |
|------|--------|------|
| 高敏感度 | 20-25% | 捕获更多尖峰，适合调试阶段 |
| 平衡模式 | 30-40% | 默认推荐，过滤噪音 |
| 低敏感度 | 50%+ | 只捕获严重尖峰，生产环境 |

**采样时长 (SAMPLE_DURATION)**

| 场景 | 推荐值 | 说明 |
|------|--------|------|
| 瞬时尖峰 | 5-10s | 快速捕获，减少开销 |
| 持续尖峰 | 15-30s | 默认推荐，数据充分 |
| 深度分析 | 60s+ | 详细分析，适合离线调试 |

**采样频率 (profile:hz)**

| 场景 | 推荐值 | 说明 |
|------|--------|------|
| 低开销 | 49 Hz | CPU 开销 < 0.5% |
| 平衡模式 | 99 Hz | 默认推荐，开销 < 1% |
| 高精度 | 199 Hz | 详细分析，开销 1-2% |

### 9.2 生产环境注意事项

**1. 权限管理**
```bash
# 最小权限原则
# 方案 1: 使用 CAP_BPF (Linux 5.8+)
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/bpftrace

# 方案 2: 使用 sudo 但限制命令
# /etc/sudoers.d/ebpf-monitor
monitor-user ALL=(ALL) NOPASSWD: /usr/bin/bpftrace, /usr/bin/mpstat
```

**2. 资源限制**
```bash
# 限制报告文件大小
LOG_DIR="/tmp/ebpf_reports"
MAX_REPORTS=100

# 清理旧报告
find $LOG_DIR -type f -mtime +7 -delete  # 删除 7 天前的报告
ls -t $LOG_DIR | tail -n +$((MAX_REPORTS+1)) | xargs -I {} rm $LOG_DIR/{}
```

**3. 告警集成**
```bash
# 发送告警到 Slack
send_alert() {
    local cpu=$1
    local report=$2
    curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
      -H 'Content-Type: application/json' \
      -d "{\"text\":\"🚨 CPU Spike Detected: ${cpu}%\nReport: ${report}\"}"
}
```

**4. 日志轮转**
```bash
# /etc/logrotate.d/ebpf-monitor
/tmp/ebpf_reports/*.txt {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
```

### 9.3 故障排查

**问题 1: bpftrace 无法启动**
```bash
# 症状
Error: failed to attach probe

# 排查步骤
# 1. 检查内核版本
uname -r  # 需要 >= 4.9

# 2. 检查 BPF 支持
zgrep CONFIG_BPF /proc/config.gz

# 3. 检查 debugfs
mount | grep debugfs
# 如果没有挂载:
sudo mount -t debugfs none /sys/kernel/debug

# 4. 检查权限
sudo bpftrace -e 'BEGIN { printf("OK\n"); exit(); }'
```

**问题 2: 采样数据为空**
```bash
# 症状
报告中没有堆栈数据

# 排查步骤
# 1. 检查进程名是否正确
ps aux | grep my-server

# 2. 手动测试 bpftrace
sudo bpftrace -e 'profile:hz:99 /comm == "my-server"/ { @[comm] = count(); }'

# 3. 检查符号表
file /usr/bin/my-server  # 确保 not stripped
```

**问题 3: CPU 开销过高**
```bash
# 症状
监控脚本本身占用 CPU > 5%

# 优化方案
# 1. 降低采样频率
profile:hz:49  # 从 99 降到 49

# 2. 增加检测周期
sleep 5  # 从 2 秒改为 5 秒

# 3. 减少采样时长
SAMPLE_DURATION=10  # 从 15 秒改为 10 秒
```

**问题 4: 报告文件过大**
```bash
# 症状
单个报告文件 > 100MB

# 优化方案
# 1. 限制堆栈深度
sudo bpftrace -e 'profile:hz:99 { @[kstack(5), ustack(5)] = count(); }'
                                          ↑        ↑
                                       限制为 5 层

# 2. 过滤低频堆栈
END {
    print(@cpu_stack, 10);  # 只输出 top 10
}
```

### 9.4 性能优化建议

**基于 eBPF 分析结果的通用优化策略:**

**1. I/O 密集型应用**
```bash
# 识别特征: epoll_wait, select, poll 占比高

# 优化方向:
- 启用多线程 I/O
- 使用 io_uring (Linux 5.1+)
- 调整 epoll 超时参数
- 批量处理请求
```

**2. 内存密集型应用**
```bash
# 识别特征: do_anonymous_page, handle_mm_fault 占比高

# 优化方向:
- 预分配内存池
- 使用 Huge Pages
- 调整 jemalloc/tcmalloc 参数
- 减少内存碎片
```

**3. 锁竞争问题**
```bash
# 识别特征: futex_wait, pthread_mutex_lock 占比高

# 优化方向:
- 减少锁粒度
- 使用读写锁 (rwlock)
- 使用无锁数据结构 (lock-free)
- 分片锁 (sharded locks)
```

**4. 系统调用开销**
```bash
# 识别特征: invoke_syscall, el0_svc 占比高

# 优化方向:
- 批量系统调用
- 使用 vDSO (virtual dynamic shared object)
- 减少上下文切换
- 使用用户态网络栈 (DPDK)
```

### 9.5 监控指标建议

**关键指标:**

| 指标 | 说明 | 告警阈值 |
|------|------|---------|
| **尖峰频率** | 每小时触发次数 | > 10 次/小时 |
| **最大 vCPU 使用率** | 单个 vCPU 峰值 | > 90% |
| **vCPU 不均衡度** | max/avg 比值 | > 5x |
| **采样成功率** | 成功采样 / 触发次数 | < 90% |
| **报告生成延迟** | 从触发到报告完成 | > 30s |

**Prometheus 指标示例:**
```prometheus
# 尖峰事件计数
ebpf_spike_total{instance="i-xxx"} 12

# 最大 vCPU 使用率
ebpf_max_vcpu_usage{instance="i-xxx"} 95.96

# vCPU 不均衡度
ebpf_vcpu_imbalance_ratio{instance="i-xxx"} 7.8

# 采样成功率
ebpf_sampling_success_rate{instance="i-xxx"} 0.95
```

### 9.6 安全加固

**1. 限制 eBPF 程序能力**
```bash
# 使用 seccomp 限制系统调用
# /etc/systemd/system/ebpf-monitor.service
[Service]
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
```

**2. 审计日志**
```bash
# 记录所有 eBPF 操作
auditctl -a always,exit -F arch=b64 -S bpf -k ebpf_monitor
```

**3. 网络隔离**
```bash
# 如果不需要网络访问
# /etc/systemd/system/ebpf-monitor.service
[Service]
PrivateNetwork=true
```

---

## 10. 附录

### 10.1 依赖版本要求

| 组件 | 最低版本 | 推荐版本 | 说明 |
|------|---------|---------|------|
| Linux Kernel | 4.9 | 5.10+ | eBPF 基础支持 |
| bpftrace | 0.9.0 | 0.18+ | 堆栈采样功能 |
| sysstat (mpstat) | 11.0 | 12.5+ | CPU 监控 |
| bash | 4.0 | 5.0+ | 脚本执行 |
| bc | 1.06 | 1.07+ | 浮点计算 |

### 10.2 内核配置检查

```bash
# 检查必需的内核配置
zgrep -E 'CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_BPF_JIT|CONFIG_HAVE_EBPF_JIT|CONFIG_BPF_EVENTS' /proc/config.gz

# 期望输出:
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
```

### 10.3 常用命令速查

```bash
# 查看 eBPF 程序
sudo bpftool prog list

# 查看 eBPF map
sudo bpftool map list

# 查看 vCPU 实时使用率
mpstat -P ALL 1

# 查看进程 CPU 亲和性
taskset -cp $(pgrep my-server)

# 查看 NUMA 分布
numastat -p $(pgrep my-server)

# 查看容器 CPU 限流
cat /sys/fs/cgroup/cpu/cpu.stat

# 手动触发采样
sudo timeout 15s bpftrace -e 'profile:hz:99 /comm == "my-server"/ { @[kstack, ustack] = count(); }'
```

### 10.4 参考资料

**官方文档:**
- [eBPF 官方文档](https://ebpf.io/)
- [bpftrace 参考指南](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)
- [Linux Perf Wiki](https://perf.wiki.kernel.org/)

**相关工具:**
- [BCC (BPF Compiler Collection)](https://github.com/iovisor/bcc)
- [Brendan Gregg's eBPF Tools](https://www.brendangregg.com/ebpf.html)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)

**性能分析:**
- [Systems Performance (Brendan Gregg)](https://www.brendangregg.com/systems-performance-2nd-edition-book.html)
- [Linux Performance Analysis in 60 Seconds](https://netflixtechblog.com/linux-performance-analysis-in-60-000-milliseconds-accc10403c55)

### 10.5 贡献与支持

**问题反馈:**
- GitHub Issues: https://github.com/your-repo/ebpf-monitor/issues
- 邮件列表: ebpf-monitor@your-domain.com

**贡献指南:**
1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

**许可证:**
MIT License - 详见 LICENSE 文件

---

## 总结

本方案提供了一套完整的基于 eBPF 的 CPU 性能监控和分析解决方案，具有以下特点:

✅ **零侵入**: 无需修改应用代码  
✅ **低开销**: 仅在尖峰时采样，CPU 开销 < 1%  
✅ **自动化**: 自动检测、采样、生成报告  
✅ **精准定位**: 同时捕获内核态和用户态堆栈  
✅ **生产就绪**: 支持多种部署方式，包含完整的监控和告警  

通过本方案，可以快速定位和解决生产环境中的 CPU 性能问题，特别适用于 ARM Graviton 实例的 vCPU 不均衡问题和间歇性 CPU 尖峰排查。

---

**文档版本:** v1.0  
**最后更新:** 2026-03-04  
**维护者:** Your Team
