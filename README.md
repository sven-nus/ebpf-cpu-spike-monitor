# eBPF CPU Spike Monitor

基于 eBPF/bpftrace 的轻量化 CPU 尖峰自动监控与分析工具。以零侵入方式持续监控目标进程 vCPU 使用率，在检测到 CPU 异常增长时自动触发堆栈采样，生成结构化分析报告，帮助快速定位生产环境中的瞬时 CPU 性能问题。

## 特性

- **自动 CPU 尖峰检测** — 持续监控目标进程归一化 CPU 使用率，超过阈值自动触发采样
- **eBPF 堆栈采样** — 使用 bpftrace profile 模式同时捕获内核态和用户态调用栈
- **动态采样窗口** — CPU 降幅达标或超时自动停止，避免过度采样
- **Valkey/Predixy 智能分析** — 自动识别 6 种 Valkey 和 4 种 Predixy 性能瓶颈模式并给出优化建议
- **并行数据采集** — bpftrace + atop + ENA 网络指标 + Valkey/Predixy INFO 同步采集
- **报告文件管理** — 自动归档、retention 策略、磁盘空间保护
- **优雅降级** — 可选依赖缺失时自动跳过，不影响核心监控
- **多种部署方式** — 独立脚本、Systemd 服务、Kubernetes DaemonSet

## 目标平台

- Rocky Linux 9.3 / 9.5
- AWS EC2 实例（Graviton ARM64 和 x86_64）
- 内核版本 >= 5.14

## 快速开始

```bash
# 需要 root 权限运行（eBPF 需要）
sudo ./ebpf-cpu-spike-monitor.sh
```

首次运行会自动安装缺失的必需依赖（bpftrace, sysstat, bc, atop）。

## 配置

所有参数在脚本顶部变量区配置：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `SPIKE_THRESHOLD` | 90 | 归一化 CPU 触发阈值 (%) |
| `CHECK_INTERVAL` | 2 | 检测周期 (秒) |
| `COOLDOWN_PERIOD` | 30 | 冷却期 (秒) |
| `TARGET_PROCS` | valkey-server:1, predixy:4 | 目标进程:vCPU数 |
| `SAMPLE_FREQ` | 99 | bpftrace 采样频率 (Hz) |
| `DROP_THRESHOLD` | 50 | CPU 降幅阈值 (%) |
| `MAX_SAMPLING_DURATION` | 60 | 最大采样时长 (秒) |
| `REPORT_DIR` | /tmp/ebpf_reports | 报告目录 |

## 部署

### Systemd 服务

```bash
sudo cp ebpf-cpu-spike-monitor.sh /usr/local/bin/
sudo cp deploy/ebpf-cpu-spike-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-cpu-spike-monitor
```

### Kubernetes DaemonSet

```bash
kubectl create configmap ebpf-cpu-spike-monitor-script \
  --from-file=ebpf-cpu-spike-monitor.sh -n monitoring
kubectl apply -f deploy/ebpf-cpu-spike-monitor-daemonset.yaml
```

## 测试

需要 [bats-core](https://github.com/bats-core/bats-core) 和 Bash 4+：

```bash
# Linux
bats tests/

# macOS (需要 Homebrew bash)
PATH="/opt/homebrew/bin:$PATH" bats tests/
```

## 依赖

| 依赖 | 类型 | 说明 |
|------|------|------|
| bpftrace | 必需 | eBPF 堆栈采样 |
| sysstat (mpstat/iostat) | 必需 | CPU 快照 |
| bc | 必需 | 浮点运算 |
| atop | 必需 | 系统性能采集 |
| ethtool | 可选 | ENA 网络指标 |
| valkey-cli | 可选 | Valkey 指标/配置 |
| redis-cli | 可选 | Predixy 指标 |

## License

MIT
