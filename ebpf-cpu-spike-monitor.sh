#!/bin/bash
#
# ebpf-cpu-spike-monitor.sh — eBPF CPU 尖峰自动监控与分析工具
#
# 通过 bpftrace 持续监控目标进程 CPU 使用率，在检测到归一化 CPU 超过阈值时
# 自动触发 eBPF 堆栈采样、atop 系统采集、ENA 网络指标采集和 Valkey/Predixy
# 运行时指标采集，生成结构化纯文本分析报告。
#

set -euo pipefail

# ============================================================================
# 配置区 — 所有可配置参数集中定义
# ============================================================================

# === 核心监控参数 ===
SPIKE_THRESHOLD=90              # 归一化 CPU 触发阈值 (%)
CHECK_INTERVAL=2                # 检测周期 (秒)
COOLDOWN_PERIOD=30              # 冷却期 (秒)

# === 目标进程配置 ===
# 格式: "进程名:vCPU数"
TARGET_PROCS=("valkey-server:1" "predixy:4")

# === 采样参数 ===
SAMPLE_FREQ=99                  # bpftrace 采样频率 (Hz)
DROP_THRESHOLD=50               # CPU 降幅阈值 (%)
MAX_SAMPLING_DURATION=60        # 最大采样时长 (秒)
ATOP_INTERVAL=1                 # atop 采样间隔 (秒)

# === 报告管理 ===
REPORT_DIR="/tmp/ebpf_reports"
ARCHIVE_DIR="${REPORT_DIR}/archived"
MAX_REPORTS=100                 # 最大报告数
MAX_RETENTION_DAYS=7            # 最大保留天数
MAX_DIR_SIZE_MB=500             # 目录大小上限 (MB)
MIN_DISK_FREE_MB=1024           # 最小磁盘剩余 (MB)
RETENTION_HOT_HOURS=24          # 热保留期 (小时)

# === 应用连接信息 ===
VALKEY_HOST="127.0.0.1"
VALKEY_PORT=6379
PREDIXY_HOST="127.0.0.1"
PREDIXY_PORT=7617

# ============================================================================
# 进程配置 — 关联数组
# ============================================================================

# key: 进程名, value: vCPU 数量
declare -A PROC_VCPU_MAP

# ============================================================================
# 全局状态变量
# ============================================================================

LAST_SAMPLING_END=0             # 上次采样完成时间戳（冷却期追踪）
BPFTRACE_PID=""                 # bpftrace 子进程 PID（清理用）
BPFTRACE_SCRIPT_FILE=""         # bpftrace 临时脚本文件路径（清理用）
ATOP_PID=""                     # atop 子进程 PID（清理用）
ENA_COLLECTOR_PID=""            # ENA 采集子进程 PID（清理用）
CURRENT_SAMPLING_DIR=""         # 当前采样临时目录（清理用）
BASELINE_FILE=""                # 基线文件路径引用
LOW_DISK_COUNT=0                # 连续磁盘空间不足告警计数

# ============================================================================
# 日志函数
# ============================================================================

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" >&2
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >&2
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

# ============================================================================
# 外部命令包装函数 — 隔离层，便于测试替换
# ============================================================================

_bpftrace() {
    exec bpftrace "$@"
}

_atop() {
    atop "$@"
}

_mpstat() {
    mpstat "$@"
}

_ethtool() {
    ethtool "$@"
}

_valkey_cli() {
    valkey-cli "$@"
}

_redis_cli() {
    redis-cli "$@"
}

_bc() {
    bc "$@"
}

# ============================================================================
# 目标进程解析
# ============================================================================

# 解析 TARGET_PROCS 数组，填充 PROC_VCPU_MAP 关联数组
# TARGET_PROCS 格式: ("进程名:vCPU数" ...)
parse_target_procs() {
    PROC_VCPU_MAP=()
    local entry proc_name vcpu_count
    for entry in "${TARGET_PROCS[@]}"; do
        proc_name="${entry%%:*}"
        vcpu_count="${entry##*:}"
        if [[ -z "$proc_name" || -z "$vcpu_count" ]]; then
            log_warn "无效的目标进程配置项: '$entry'，跳过"
            continue
        fi
        PROC_VCPU_MAP["$proc_name"]="$vcpu_count"
    done

    if [[ ${#PROC_VCPU_MAP[@]} -eq 0 ]]; then
        log_error "没有有效的目标进程配置"
        return 1
    fi

    log_info "已解析目标进程: ${!PROC_VCPU_MAP[*]}"
    for proc_name in "${!PROC_VCPU_MAP[@]}"; do
        log_info "  $proc_name -> vCPU: ${PROC_VCPU_MAP[$proc_name]}"
    done
    return 0
}

# ============================================================================
# 依赖检查与自动安装
# ============================================================================

# 依赖安装标记文件
DEPS_MARKER="${REPORT_DIR}/.deps_installed"

# 检查 root 权限
# 返回: 0 = root, 1 = 非 root
check_permissions() {
    if [[ $EUID -ne 0 ]]; then
        log_error "需要 root 权限运行此工具 (当前 EUID=$EUID)"
        return 1
    fi
    return 0
}

# detect_ena_interface
#   遍历 /sys/class/net/ 下的网络接口，通过 ethtool -i 检查 driver 字段
#   查找第一个使用 ENA 驱动的接口
#   输出: ENA 接口名称到 stdout（未找到时输出空字符串）
#   返回: 0 = 找到 ENA 接口, 1 = 未找到或 ethtool 不可用
detect_ena_interface() {
    # ethtool 不可用时直接返回
    if ! command -v ethtool &>/dev/null; then
        echo ""
        return 1
    fi

    local iface driver
    for iface_path in /sys/class/net/*; do
        iface=$(basename "$iface_path")

        # 跳过 lo 接口
        [[ "$iface" == "lo" ]] && continue

        # 通过 ethtool -i 获取 driver 字段
        driver=$(_ethtool -i "$iface" 2>/dev/null | awk -F': ' '/^driver:/{print $2}')

        if [[ "$driver" == "ena" ]]; then
            echo "$iface"
            return 0
        fi
    done

    echo ""
    return 1
}

# 快速检查已安装的必需依赖
# 用于标记文件存在时的快速验证
# 返回: 0 = 全部存在, 1 = 有缺失
quick_dependency_check() {
    local all_ok=true
    for cmd in bpftrace mpstat bc atop; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "必需依赖缺失: $cmd (删除 $DEPS_MARKER 可重新运行完整检查)"
            all_ok=false
        fi
    done
    $all_ok
}

# 生成依赖状态报告（功能验证 + 可用性总结）
# 返回: 0 = 必需依赖全部通过, 1 = 有必需依赖验证失败
generate_dependency_report() {
    local report_file="${REPORT_DIR}/dependency_report_$(date +%Y%m%d_%H%M%S).txt"
    local has_fatal=false
    mkdir -p "$REPORT_DIR"

    {
        echo "========================================"
        echo "依赖状态报告"
        echo "生成时间: $(date)"
        echo "平台: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"')"
        echo "内核: $(uname -r)"
        echo "========================================"
        echo ""
        echo "=== 必需依赖 ==="

        # bpftrace: 版本 + eBPF 功能验证
        if command -v bpftrace &>/dev/null; then
            local ver
            ver=$(bpftrace --version 2>&1 | head -1)
            if timeout 5 bpftrace -e 'BEGIN { printf("ok\n"); exit(); }' &>/dev/null; then
                echo "[✓] bpftrace    — $ver — 功能验证通过"
            else
                echo "[✗] bpftrace    — $ver — 已安装但功能验证失败（内核不支持或权限不足）"
                has_fatal=true
            fi
        else
            echo "[✗] bpftrace    — 未安装"
            has_fatal=true
        fi

        # mpstat: 执行测试
        if command -v mpstat &>/dev/null; then
            local ver
            ver=$(mpstat -V 2>&1 | head -1)
            if mpstat -P ALL 1 1 &>/dev/null; then
                echo "[✓] mpstat      — $ver — 功能验证通过"
            else
                echo "[✗] mpstat      — $ver — 执行失败"
                has_fatal=true
            fi
        else
            echo "[✗] mpstat      — 未安装 (sysstat)"
            has_fatal=true
        fi

        # bc: 浮点计算测试
        if command -v bc &>/dev/null; then
            if [ -n "$(echo '90.5 / 1' | bc -l 2>/dev/null)" ]; then
                echo "[✓] bc          — $(bc --version 2>&1 | head -1) — 功能验证通过"
            else
                echo "[✗] bc          — 计算测试失败"
                has_fatal=true
            fi
        else
            echo "[✗] bc          — 未安装"
            has_fatal=true
        fi

        # atop: 执行测试
        if command -v atop &>/dev/null; then
            local ver
            ver=$(atop -V 2>&1 | head -1)
            if timeout 3 atop -a 1 1 &>/dev/null; then
                echo "[✓] atop        — $ver — 功能验证通过"
            else
                echo "[✗] atop        — $ver — 执行失败"
                has_fatal=true
            fi
        else
            echo "[✗] atop        — 未安装"
            has_fatal=true
        fi

        echo ""
        echo "=== 可选依赖 ==="

        # ethtool + ENA 接口检测
        if command -v ethtool &>/dev/null; then
            local iface
            iface=$(detect_ena_interface 2>/dev/null)
            if [ -n "$iface" ]; then
                if ethtool -S "$iface" &>/dev/null; then
                    echo "[✓] ethtool     — ENA 接口 $iface 可用"
                else
                    echo "[△] ethtool     — ENA 接口 $iface 检测到但 ethtool -S 失败"
                fi
            else
                echo "[△] ethtool     — 已安装，未检测到 ENA 接口"
            fi
        else
            echo "[✗] ethtool     — 未安装，ENA 网络指标不可用"
        fi

        # valkey-cli + 连接测试
        if command -v valkey-cli &>/dev/null; then
            if timeout 2 valkey-cli -h "$VALKEY_HOST" -p "$VALKEY_PORT" PING 2>/dev/null | grep -q PONG; then
                echo "[✓] valkey-cli  — 连接 ${VALKEY_HOST}:${VALKEY_PORT} 成功"
            else
                echo "[△] valkey-cli  — 已安装，连接 ${VALKEY_HOST}:${VALKEY_PORT} 失败"
            fi
        else
            echo "[✗] valkey-cli  — 未安装，Valkey 指标/配置不可用"
        fi

        # redis-cli + 连接测试
        if command -v redis-cli &>/dev/null; then
            if timeout 2 redis-cli -h "$PREDIXY_HOST" -p "$PREDIXY_PORT" PING 2>/dev/null | grep -q PONG; then
                echo "[✓] redis-cli   — 连接 ${PREDIXY_HOST}:${PREDIXY_PORT} 成功"
            else
                echo "[△] redis-cli   — 已安装，连接 ${PREDIXY_HOST}:${PREDIXY_PORT} 失败"
            fi
        else
            echo "[✗] redis-cli   — 未安装，Predixy 指标不可用"
        fi

        # numactl
        command -v numactl &>/dev/null \
            && echo "[✓] numactl     — 已安装" \
            || echo "[✗] numactl     — 未安装，NUMA 拓扑不可用"

        # iostat
        command -v iostat &>/dev/null \
            && echo "[✓] iostat      — 已安装" \
            || echo "[✗] iostat      — 未安装，磁盘 I/O 快照不可用"

        echo ""
        echo "=== 功能可用性总结 ==="
        $has_fatal \
            && echo "核心监控 (Monitor + eBPF + Reporter):  ✗ 不可用" \
            || echo "核心监控 (Monitor + eBPF + Reporter):  ✓ 可用"
        command -v atop &>/dev/null \
            && echo "系统性能采集 (atop):                    ✓ 可用" \
            || echo "系统性能采集 (atop):                    ✗ 不可用"
        command -v ethtool &>/dev/null \
            && echo "ENA 网络指标:                           ✓ 可用" \
            || echo "ENA 网络指标:                           ✗ 不可用"
        command -v valkey-cli &>/dev/null \
            && echo "Valkey 指标/配置:                       ✓ 可用" \
            || echo "Valkey 指标/配置:                       ✗ 不可用"
        command -v redis-cli &>/dev/null \
            && echo "Predixy 指标:                           ✓ 可用" \
            || echo "Predixy 指标:                           ✗ 不可用"
        echo ""
        echo "图例: [✓] 可用  [△] 部分可用  [✗] 不可用"
        echo "========================================"
    } | tee "$report_file"

    log_info "依赖状态报告已保存: $report_file"

    $has_fatal && { log_error "必需依赖验证失败，无法启动"; return 1; }
    return 0
}

# 首次运行依赖检查与自动安装
# 通过标记文件判断是否需要完整安装流程
check_and_install_dependencies() {
    check_permissions || exit 1

    if [ -f "$DEPS_MARKER" ]; then
        quick_dependency_check || exit 1
        return 0
    fi

    log_info "首次运行，检查并安装依赖..."

    # 确保 EPEL 仓库可用（atop 需要）
    dnf install -y epel-release 2>/dev/null || true

    local missing_required=()
    local missing_optional=()

    command -v bpftrace &>/dev/null || missing_required+=("bpftrace")
    command -v mpstat &>/dev/null   || missing_required+=("sysstat")
    command -v bc &>/dev/null       || missing_required+=("bc")
    command -v atop &>/dev/null     || missing_required+=("atop")
    command -v ethtool &>/dev/null  || missing_optional+=("ethtool")

    if [ ${#missing_required[@]} -gt 0 ]; then
        log_info "安装缺失的必需依赖: ${missing_required[*]}"
        dnf install -y "${missing_required[@]}" || {
            log_error "必需依赖安装失败: ${missing_required[*]}"
        }
    fi

    if [ ${#missing_optional[@]} -gt 0 ]; then
        log_info "尝试安装可选依赖: ${missing_optional[*]}"
        dnf install -y "${missing_optional[@]}" 2>/dev/null || true
    fi

    # 可选依赖缺失告警（不影响继续运行）
    command -v valkey-cli &>/dev/null || log_warn "可选依赖缺失: valkey-cli — Valkey 指标/配置采集不可用"
    command -v redis-cli &>/dev/null  || log_warn "可选依赖缺失: redis-cli — Predixy 指标采集不可用"
    command -v ethtool &>/dev/null    || log_warn "可选依赖缺失: ethtool — ENA 网络指标采集不可用"
    command -v numactl &>/dev/null    || log_warn "可选依赖缺失: numactl — NUMA 拓扑信息不可用"
    command -v iostat &>/dev/null     || log_warn "可选依赖缺失: iostat — 磁盘 I/O 快照不可用"

    # 安装后执行功能验证并生成依赖状态报告
    generate_dependency_report || exit 1

    mkdir -p "$REPORT_DIR"
    date > "$DEPS_MARKER"
    log_info "依赖检查完成，标记文件已创建"
}

# ============================================================================
# Monitor 核心组件 — CPU 使用率
# ============================================================================

# 缓存 CPU 核心数（首次调用时初始化）
NUM_CPUS=""

# _get_num_cpus
#   获取系统 CPU 核心数，缓存到 NUM_CPUS
_get_num_cpus() {
    if [[ -z "$NUM_CPUS" ]]; then
        NUM_CPUS=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)
    fi
    echo "$NUM_CPUS"
}

# get_process_cpu PID
#   通过两次读取 /proc/<pid>/stat 计算进程 CPU 使用率
#   输出: CPU 百分比（浮点数）到 stdout
#   返回: 0 = 成功, 1 = PID 不存在或不可读
get_process_cpu() {
    local pid="$1"
    local stat_file="/proc/${pid}/stat"

    # 第一次读取进程 stat
    if [[ ! -r "$stat_file" ]]; then
        return 1
    fi
    local stat1
    stat1=$(cat "$stat_file" 2>/dev/null) || return 1

    # 第一次读取系统 stat
    local sys_stat1
    sys_stat1=$(head -1 /proc/stat 2>/dev/null) || return 1

    # 解析进程 utime(14) + stime(15)（1-indexed）
    # /proc/<pid>/stat 格式: pid (comm) state ... utime stime ...
    # comm 可能包含空格和括号，需要先去掉 (comm) 部分
    local fields1
    fields1=$(echo "$stat1" | sed 's/^[0-9]* ([^)]*) //')
    local utime1 stime1
    # 去掉 (comm) 后，state 是第 1 个字段，utime 是第 12 个，stime 是第 13 个
    utime1=$(echo "$fields1" | awk '{print $12}')
    stime1=$(echo "$fields1" | awk '{print $13}')

    if [[ -z "$utime1" || -z "$stime1" ]]; then
        return 1
    fi

    local proc_time1=$(( utime1 + stime1 ))

    # 解析系统总 jiffies（/proc/stat 第一行 cpu 行所有数值之和）
    local total1=0
    local val
    for val in $(echo "$sys_stat1" | awk '{for(i=2;i<=NF;i++) print $i}'); do
        total1=$(( total1 + val ))
    done

    # 等待检测周期
    sleep "$CHECK_INTERVAL"

    # 第二次读取
    if [[ ! -r "$stat_file" ]]; then
        return 1
    fi
    local stat2
    stat2=$(cat "$stat_file" 2>/dev/null) || return 1

    local sys_stat2
    sys_stat2=$(head -1 /proc/stat 2>/dev/null) || return 1

    local fields2
    fields2=$(echo "$stat2" | sed 's/^[0-9]* ([^)]*) //')
    local utime2 stime2
    utime2=$(echo "$fields2" | awk '{print $12}')
    stime2=$(echo "$fields2" | awk '{print $13}')

    if [[ -z "$utime2" || -z "$stime2" ]]; then
        return 1
    fi

    local proc_time2=$(( utime2 + stime2 ))

    local total2=0
    for val in $(echo "$sys_stat2" | awk '{for(i=2;i<=NF;i++) print $i}'); do
        total2=$(( total2 + val ))
    done

    # 计算差值
    local delta_process=$(( proc_time2 - proc_time1 ))
    local delta_total=$(( total2 - total1 ))

    if [[ "$delta_total" -eq 0 ]]; then
        echo "0.0"
        return 0
    fi

    local num_cpus
    num_cpus=$(_get_num_cpus)

    # CPU% = (delta_process * num_cpus * 100) / delta_total
    # Note: multiply before divide to avoid bc integer division truncation
    local cpu_pct
    cpu_pct=$(echo "scale=1; ($delta_process * $num_cpus * 100) / $delta_total" | _bc -l)
    echo "$cpu_pct"
    return 0
}

# get_normalized_cpu PROC_NAME VCPU_COUNT
#   获取进程的归一化 CPU 使用率
#   归一化 = raw_cpu / vcpu_count
#   输出: "normalized_cpu raw_cpu pid" 到 stdout
#   返回: 0 = 成功, 1 = 进程未找到
get_normalized_cpu() {
    local proc_name="$1"
    local vcpu_count="$2"

    # 通过 pgrep 查找进程 PID
    local pid
    pid=$(pgrep -x "$proc_name" | head -1)
    if [[ -z "$pid" ]]; then
        return 1
    fi

    # 获取原始 CPU 使用率
    local raw_cpu
    raw_cpu=$(get_process_cpu "$pid") || return 1

    # 归一化: normalized = raw_cpu / vcpu_count
    local normalized_cpu
    normalized_cpu=$(echo "scale=1; $raw_cpu / $vcpu_count" | _bc -l)

    echo "$normalized_cpu $raw_cpu $pid"
    return 0
}

# get_max_normalized_cpu
#   从所有目标进程中提取最大归一化 CPU 值及对应进程名
#   遍历 PROC_VCPU_MAP 中的所有进程
#   输出: "max_normalized_cpu proc_name pid raw_cpu" 到 stdout
#   返回: 0 = 成功, 1 = 没有找到任何进程
get_max_normalized_cpu() {
    local max_normalized="-1"
    local max_proc_name=""
    local max_pid=""
    local max_raw_cpu=""
    local found_any=false

    local proc_name
    for proc_name in "${!PROC_VCPU_MAP[@]}"; do
        local vcpu_count="${PROC_VCPU_MAP[$proc_name]}"
        local result
        result=$(get_normalized_cpu "$proc_name" "$vcpu_count" 2>/dev/null) || continue

        found_any=true

        local normalized_cpu raw_cpu pid
        normalized_cpu=$(echo "$result" | awk '{print $1}')
        raw_cpu=$(echo "$result" | awk '{print $2}')
        pid=$(echo "$result" | awk '{print $3}')

        # 比较是否大于当前最大值
        local is_greater
        is_greater=$(echo "$normalized_cpu > $max_normalized" | _bc -l)
        if [[ "$is_greater" -eq 1 ]]; then
            max_normalized="$normalized_cpu"
            max_proc_name="$proc_name"
            max_pid="$pid"
            max_raw_cpu="$raw_cpu"
        fi
    done

    if ! $found_any; then
        return 1
    fi

    echo "$max_normalized $max_proc_name $max_pid $max_raw_cpu"
    return 0
}

# ============================================================================
# Monitor 核心组件 — 触发决策与冷却
# ============================================================================

# is_in_cooldown
#   检查当前是否处于冷却期
#   使用全局变量 LAST_SAMPLING_END（上次采样完成的 epoch 时间戳，0 表示从未采样）
#   和 COOLDOWN_PERIOD（冷却期秒数）
#   输出: 如果处于冷却期，输出剩余冷却秒数到 stdout
#   返回: 0 = 处于冷却期 (true), 1 = 不在冷却期
is_in_cooldown() {
    # 从未采样过，不在冷却期
    if [[ "$LAST_SAMPLING_END" -eq 0 ]]; then
        return 1
    fi

    local now
    now=$(date +%s)
    local cooldown_end=$(( LAST_SAMPLING_END + COOLDOWN_PERIOD ))

    if [[ "$now" -lt "$cooldown_end" ]]; then
        local remaining=$(( cooldown_end - now ))
        echo "$remaining"
        return 0
    fi

    return 1
}

# should_trigger_sampling NORMALIZED_CPU
#   决定是否应触发采样
#   参数: $1 = 当前归一化 CPU 值（浮点数）
#   条件: CPU >= SPIKE_THRESHOLD 且不处于冷却期
#   返回: 0 = 应触发 (true), 1 = 不应触发
should_trigger_sampling() {
    local current_cpu="$1"

    # 检查 CPU 是否达到阈值
    local above_threshold
    above_threshold=$(echo "$current_cpu >= $SPIKE_THRESHOLD" | _bc -l)
    if [[ "$above_threshold" -ne 1 ]]; then
        return 1
    fi

    # 检查是否在冷却期
    if is_in_cooldown >/dev/null 2>&1; then
        return 1
    fi

    return 0
}

# ============================================================================
# Sampler 组件 — bpftrace 堆栈采样
# ============================================================================

# build_bpftrace_script
#   根据 TARGET_PROCS 生成 bpftrace 脚本
#   - profile:hz:SAMPLE_FREQ 探针
#   - comm 过滤（仅采样目标进程）
#   - kstack + ustack 聚合计数
#   输出: bpftrace 脚本文本到 stdout
build_bpftrace_script() {
    local filter=""
    local proc_entry proc_name
    for proc_entry in "${TARGET_PROCS[@]}"; do
        proc_name="${proc_entry%%:*}"
        if [[ -z "$proc_name" ]]; then
            continue
        fi
        [[ -n "$filter" ]] && filter+=" || "
        filter+="comm == \"${proc_name}\""
    done

    if [[ -z "$filter" ]]; then
        log_error "build_bpftrace_script: 没有有效的目标进程用于生成过滤条件"
        return 1
    fi

    cat <<EOF
profile:hz:${SAMPLE_FREQ} /${filter}/ {
    @cpu_stack[comm, kstack, ustack] = count();
}
END {
    print(@cpu_stack);
    clear(@cpu_stack);
}
EOF
    return 0
}

# run_bpftrace OUTPUT_FILE
#   将 bpftrace 脚本写入临时文件并后台启动 bpftrace
#   设置全局 BPFTRACE_PID
#   参数: $1 = bpftrace stdout 输出文件路径
#   返回: 0 = 成功, 1 = 失败
run_bpftrace() {
    local output_file="$1"
    local script_file
    script_file=$(mktemp /tmp/ebpf_bpftrace_XXXXXX.bt)

    # 生成 bpftrace 脚本并写入临时文件
    if ! build_bpftrace_script > "$script_file" 2>/dev/null; then
        log_error "run_bpftrace: 生成 bpftrace 脚本失败"
        rm -f "$script_file"
        return 1
    fi

    log_info "bpftrace 脚本已生成: $script_file"

    # 后台启动 bpftrace，stdout 重定向到 output_file
    _bpftrace "$script_file" > "$output_file" 2>/dev/null &
    BPFTRACE_PID=$!

    log_info "bpftrace 已启动 (PID=$BPFTRACE_PID, 采样频率=${SAMPLE_FREQ}Hz)"

    # 清理临时脚本文件（bpftrace 已读取，可安全删除）
    # 注意：某些 bpftrace 版本可能需要保留文件，延迟清理
    # 这里在采样结束后由 start_sampling 统一清理
    # 暂时保留 script_file 路径供后续清理
    BPFTRACE_SCRIPT_FILE="$script_file"

    return 0
}

# monitor_sampling_window PEAK_CPU PROC_NAME VCPU_COUNT
#   动态采样窗口控制：
#   - 持续检查触发进程 CPU 是否降至 Peak_CPU × (1 - DROP_THRESHOLD/100)
#   - 或达到 MAX_SAMPLING_DURATION 上限
#   - 或 bpftrace 进程异常退出
#   参数: $1 = Peak_CPU, $2 = 触发进程名, $3 = vCPU 数量
#   输出: 采样持续时间（秒）到 stdout
#   返回: 0
monitor_sampling_window() {
    local peak_cpu="$1"
    local proc_name="$2"
    local vcpu_count="$3"

    # 计算停止阈值: peak_cpu * (1 - DROP_THRESHOLD/100)
    local stop_threshold
    stop_threshold=$(echo "scale=1; $peak_cpu * (1 - $DROP_THRESHOLD / 100)" | _bc -l)
    log_info "动态采样窗口: Peak_CPU=${peak_cpu}%, 停止阈值=${stop_threshold}%, 最大时长=${MAX_SAMPLING_DURATION}s"

    local start_time
    start_time=$(date +%s)
    local elapsed=0

    while true; do
        sleep "$CHECK_INTERVAL"

        elapsed=$(( $(date +%s) - start_time ))

        # 检查 bpftrace 是否仍在运行
        if [[ -n "$BPFTRACE_PID" ]] && ! kill -0 "$BPFTRACE_PID" 2>/dev/null; then
            log_error "bpftrace 进程 (PID=$BPFTRACE_PID) 已异常退出，采样窗口提前结束 (已采样 ${elapsed}s)"
            BPFTRACE_PID=""
            break
        fi

        # 检查是否达到最大采样时长
        if [[ "$elapsed" -ge "$MAX_SAMPLING_DURATION" ]]; then
            log_info "达到最大采样时长 (${MAX_SAMPLING_DURATION}s)，结束采样"
            break
        fi

        # 获取触发进程当前 CPU
        local current_pid
        current_pid=$(pgrep -x "$proc_name" 2>/dev/null | head -1)
        if [[ -z "$current_pid" ]]; then
            log_warn "触发进程 $proc_name 已不存在，结束采样 (已采样 ${elapsed}s)"
            break
        fi

        local raw_cpu
        raw_cpu=$(get_process_cpu "$current_pid" 2>/dev/null) || {
            log_warn "无法获取进程 $proc_name (PID=$current_pid) CPU，继续采样"
            continue
        }

        # 归一化
        local current_cpu
        current_cpu=$(echo "scale=1; $raw_cpu / $vcpu_count" | _bc -l)

        # 检查是否降至停止阈值以下
        local below_threshold
        below_threshold=$(echo "$current_cpu < $stop_threshold" | _bc -l)
        if [[ "$below_threshold" -eq 1 ]]; then
            log_info "CPU 已降至 ${current_cpu}% (低于阈值 ${stop_threshold}%)，停止采样 (已采样 ${elapsed}s)"
            break
        fi
    done

    # 重新计算最终 elapsed（sleep 后的精确值）
    elapsed=$(( $(date +%s) - start_time ))
    echo "$elapsed"
    return 0
}

# start_sampling PROC_NAME MAX_CPU PID RAW_CPU
#   采样协调函数：
#   1. 创建临时采样目录
#   2. 记录 Peak_CPU 和触发元数据
#   3. 启动 bpftrace 堆栈采样
#   4. 控制动态采样窗口
#   5. 终止 bpftrace 并收集数据
#   6. 采集 mpstat 快照
#   7. 调用并行采集器占位（atop, ENA, metrics）
#   8. 调用报告生成（如已实现）
#   9. 清理临时文件
#   参数: $1 = 触发进程名, $2 = 归一化 CPU, $3 = PID, $4 = 原始 CPU
#   返回: 0
start_sampling() {
    local proc_name="$1"
    local max_cpu="$2"
    local pid="$3"
    local raw_cpu="$4"

    # 1. 创建临时采样目录
    local sampling_dir="/tmp/ebpf_sampling_$(date +%s)"
    mkdir -p "$sampling_dir"
    CURRENT_SAMPLING_DIR="$sampling_dir"
    log_info "采样目录已创建: $sampling_dir"

    # 2. 写入触发元数据
    local trigger_time
    trigger_time=$(date '+%Y-%m-%d_%H:%M:%S')
    local vcpu_count="${PROC_VCPU_MAP[$proc_name]:-1}"

    cat > "${sampling_dir}/metadata.txt" <<EOF
TRIGGER_TIME=${trigger_time}
TRIGGER_PROC=${proc_name}
TRIGGER_PID=${pid}
RAW_CPU=${raw_cpu}
NORMALIZED_CPU=${max_cpu}
PEAK_CPU=${max_cpu}
SAMPLING_DURATION=0
BASELINE_FILE=${BASELINE_FILE:-}
EOF
    log_info "触发元数据已记录: Peak_CPU=${max_cpu}%, 进程=${proc_name} (PID=${pid})"

    # 3. 启动 bpftrace 堆栈采样
    local bpftrace_output="${sampling_dir}/bpftrace_output.txt"
    if ! run_bpftrace "$bpftrace_output"; then
        log_error "bpftrace 启动失败，跳过本次采样"
        rm -rf "$sampling_dir"
        CURRENT_SAMPLING_DIR=""
        return 1
    fi

    # 4. 启动并行采集器
    # start_atop (Task 5.4 — 使用占位函数)
    if type -t start_atop &>/dev/null; then
        start_atop "${sampling_dir}/atop_output.txt" || log_warn "atop 启动失败"
    else
        log_info "atop 并行采集: 待集成 (Task 5.4)"
    fi

    # collect_ena_timeseries 后台运行 (Task 6.1)
    collect_ena_timeseries "$sampling_dir" "$MAX_SAMPLING_DURATION" &
    ENA_COLLECTOR_PID=$!
    log_info "ENA 指标采集已启动 (PID=$ENA_COLLECTOR_PID)"

    # collect_valkey_info / collect_predixy_info / collect_dynamic_sysinfo (Task 7.1)
    collect_valkey_info "$sampling_dir" || log_warn "Valkey 指标采集失败"
    collect_predixy_info "$sampling_dir" || log_warn "Predixy 指标采集失败"
    collect_dynamic_sysinfo "$sampling_dir" || log_warn "动态系统信息采集失败"

    # 5. 控制动态采样窗口
    local sampling_duration
    sampling_duration=$(monitor_sampling_window "$max_cpu" "$proc_name" "$vcpu_count")
    log_info "采样窗口结束，总采样时长: ${sampling_duration}s"

    # 6. 终止 bpftrace
    # 必须使用 SIGINT 而非 SIGTERM：bpftrace 只在收到 SIGINT 时执行 END 块，
    # 输出聚合的堆栈统计数据。SIGTERM 会直接终止进程，导致输出文件为空。
    if [[ -n "$BPFTRACE_PID" ]] && kill -0 "$BPFTRACE_PID" 2>/dev/null; then
        log_info "终止 bpftrace (PID=$BPFTRACE_PID)"
        kill -SIGINT "$BPFTRACE_PID" 2>/dev/null || true
        wait "$BPFTRACE_PID" 2>/dev/null || true
        BPFTRACE_PID=""
    else
        if [[ -z "$BPFTRACE_PID" ]]; then
            log_warn "bpftrace 已在采样窗口期间退出，使用部分数据"
        fi
    fi

    # 清理 bpftrace 临时脚本文件
    if [[ -n "${BPFTRACE_SCRIPT_FILE:-}" && -f "$BPFTRACE_SCRIPT_FILE" ]]; then
        rm -f "$BPFTRACE_SCRIPT_FILE"
        BPFTRACE_SCRIPT_FILE=""
    fi

    # 7. 停止 atop
    if type -t stop_atop &>/dev/null; then
        stop_atop || log_warn "atop 停止失败"
    fi

    # 8. 停止 ENA 采集后台进程
    if [[ -n "$ENA_COLLECTOR_PID" ]] && kill -0 "$ENA_COLLECTOR_PID" 2>/dev/null; then
        kill "$ENA_COLLECTOR_PID" 2>/dev/null || true
        wait "$ENA_COLLECTOR_PID" 2>/dev/null || true
        ENA_COLLECTOR_PID=""
    fi

    # 9. 更新元数据中的采样时长
    if [[ -f "${sampling_dir}/metadata.txt" ]]; then
        sed -i "s/^SAMPLING_DURATION=.*/SAMPLING_DURATION=${sampling_duration}/" "${sampling_dir}/metadata.txt"
    fi

    # 10. 采集 mpstat 快照
    if command -v mpstat &>/dev/null; then
        log_info "采集 mpstat 快照"
        _mpstat -P ALL 1 1 > "${sampling_dir}/mpstat_snapshot.txt" 2>/dev/null || {
            log_warn "mpstat 快照采集失败"
            echo "mpstat 数据: 不可用 (采集失败)" > "${sampling_dir}/mpstat_snapshot.txt"
        }
    else
        echo "mpstat 数据: 不可用 (mpstat 未安装)" > "${sampling_dir}/mpstat_snapshot.txt"
    fi

    # 11. 调用报告生成
    log_info "调用报告生成器"
    generate_report "$sampling_dir" || log_warn "报告生成失败"

    # 12. 清理临时采样目录
    if [[ -d "$sampling_dir" ]]; then
        log_info "清理临时采样目录: $sampling_dir"
        rm -rf "$sampling_dir"
    fi
    CURRENT_SAMPLING_DIR=""

    return 0
}

# ============================================================================
# Baseline_Collector 组件 — 系统基线信息采集
# ============================================================================

# collect_system_baseline
#   采集系统基础信息：OS 版本、内核版本、CPU 信息、内存、THP 状态、NUMA 拓扑、BPF 配置
#   直接写入 stdout（由调用方重定向到文件）
#   返回: 0
collect_system_baseline() {
    # --- 操作系统 ---
    echo "=== 操作系统 ==="
    if [[ -r /etc/os-release ]]; then
        cat /etc/os-release 2>/dev/null || echo "不可用 (读取 /etc/os-release 失败)"
    else
        echo "不可用 (/etc/os-release 不存在)"
    fi
    echo ""

    # --- 内核版本 ---
    echo "=== 内核版本 ==="
    uname -r 2>/dev/null || echo "不可用 (uname 执行失败)"
    echo ""

    # --- CPU 信息 ---
    echo "=== CPU 信息 ==="
    if command -v lscpu &>/dev/null; then
        lscpu 2>/dev/null || echo "不可用 (lscpu 执行失败)"
    else
        echo "不可用 (lscpu 命令未找到)"
    fi
    echo ""

    # --- 内存 ---
    echo "=== 内存 ==="
    if command -v free &>/dev/null; then
        free -h 2>/dev/null || echo "不可用 (free 执行失败)"
    else
        echo "不可用 (free 命令未找到)"
    fi
    echo ""

    # --- THP 状态 ---
    echo "=== THP 状态 ==="
    local thp_file="/sys/kernel/mm/transparent_hugepage/enabled"
    if [[ -r "$thp_file" ]]; then
        cat "$thp_file" 2>/dev/null || echo "不可用 (读取 THP 状态失败)"
    else
        echo "不可用 ($thp_file 不存在)"
    fi
    echo ""

    # --- NUMA 拓扑 ---
    echo "=== NUMA 拓扑 ==="
    if command -v numactl &>/dev/null; then
        numactl --hardware 2>/dev/null || echo "不可用 (numactl --hardware 执行失败)"
    else
        echo "不可用 (numactl 未安装)"
    fi
    echo ""

    # --- 内核 BPF 配置 ---
    echo "=== 内核 BPF 配置 ==="
    local bpf_found=false
    if [[ -r /proc/config.gz ]]; then
        if command -v zcat &>/dev/null; then
            local bpf_config
            bpf_config=$(zcat /proc/config.gz 2>/dev/null | grep -i BPF 2>/dev/null)
            if [[ -n "$bpf_config" ]]; then
                echo "$bpf_config"
                bpf_found=true
            fi
        fi
    fi
    if ! $bpf_found; then
        local kernel_ver
        kernel_ver=$(uname -r 2>/dev/null)
        local boot_config="/boot/config-${kernel_ver}"
        if [[ -r "$boot_config" ]]; then
            local bpf_config
            bpf_config=$(grep -i BPF "$boot_config" 2>/dev/null)
            if [[ -n "$bpf_config" ]]; then
                echo "$bpf_config"
                bpf_found=true
            fi
        fi
    fi
    if ! $bpf_found; then
        echo "不可用 (/proc/config.gz 和 /boot/config-$(uname -r) 均不可读)"
    fi
    echo ""

    return 0
}

# collect_ec2_metadata
#   通过 EC2 instance metadata 服务获取实例类型（2 秒超时）
#   直接写入 stdout
#   返回: 0
collect_ec2_metadata() {
    echo "=== EC2 实例信息 ==="
    local instance_type
    instance_type=$(curl -s --connect-timeout 2 --max-time 2 \
        http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null)
    local rc=$?

    if [[ $rc -eq 0 && -n "$instance_type" && "$instance_type" != *"<!DOCTYPE"* && "$instance_type" != *"Not Found"* ]]; then
        echo "实例类型: $instance_type"
    else
        echo "实例类型: 不可用 (非 EC2 环境或 metadata 服务不可达)"
    fi
    echo ""

    return 0
}

# collect_valkey_config
#   通过 valkey-cli CONFIG GET 采集 Valkey 关键配置项
#   直接写入 stdout
#   返回: 0
collect_valkey_config() {
    echo "=== Valkey 配置 ==="

    # valkey-cli 不可用时标注
    if ! command -v valkey-cli &>/dev/null; then
        echo "Valkey 配置: 不可用 (valkey-cli 未安装)"
        echo ""
        return 0
    fi

    # 需要采集的配置项列表
    local config_keys=(
        io-threads
        io-threads-do-reads
        maxmemory
        maxmemory-policy
        save
        appendonly
        appendfsync
        hz
        tcp-backlog
        timeout
        cluster-enabled
    )

    # 测试连接
    if ! timeout 2 _valkey_cli -h "$VALKEY_HOST" -p "$VALKEY_PORT" PING &>/dev/null; then
        echo "Valkey 配置: 不可用 (连接 ${VALKEY_HOST}:${VALKEY_PORT} 失败)"
        echo ""
        return 0
    fi

    local key value
    for key in "${config_keys[@]}"; do
        value=$(timeout 2 _valkey_cli -h "$VALKEY_HOST" -p "$VALKEY_PORT" CONFIG GET "$key" 2>/dev/null | tail -1)
        if [[ -n "$value" ]]; then
            printf "%-25s %s\n" "${key}:" "$value"
        else
            printf "%-25s %s\n" "${key}:" "N/A"
        fi
    done
    echo ""

    return 0
}

# collect_predixy_config
#   采集 Predixy 配置信息（通过 redis-cli INFO 获取）
#   直接写入 stdout
#   返回: 0
collect_predixy_config() {
    echo "=== Predixy 配置 ==="

    # redis-cli 不可用时标注
    if ! command -v redis-cli &>/dev/null; then
        echo "Predixy 配置: 不可用 (redis-cli 未安装)"
        echo ""
        return 0
    fi

    # 通过 redis-cli INFO 获取 Predixy 配置信息
    local raw_info
    raw_info=$(timeout 2 _redis_cli -h "$PREDIXY_HOST" -p "$PREDIXY_PORT" INFO 2>&1)
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        local err_msg
        if [[ $rc -eq 124 ]]; then
            err_msg="连接超时 (2s)"
        else
            err_msg=$(echo "$raw_info" | head -1)
        fi
        echo "Predixy 配置: 不可用 (连接失败: ${err_msg})"
        echo ""
        return 0
    fi

    echo "$raw_info"
    echo ""

    return 0
}

# collect_ena_baseline
#   采集 ENA 驱动版本和基线计数器
#   使用 detect_ena_interface()（已实现）检测 ENA 接口
#   直接写入 stdout
#   返回: 0
collect_ena_baseline() {
    echo "=== ENA 网络信息 ==="

    # ethtool 不可用时标注
    if ! command -v ethtool &>/dev/null; then
        echo "ENA 指标: 不可用 (ethtool 未安装)"
        echo ""
        return 0
    fi

    # 检测 ENA 接口
    local ena_iface
    ena_iface=$(detect_ena_interface 2>/dev/null)
    if [[ -z "$ena_iface" ]]; then
        echo "ENA 接口: 未检测到 (非 EC2 环境或未使用 ENA 驱动)"
        echo ""
        return 0
    fi

    echo "接口: $ena_iface"

    # 驱动版本
    local driver_info
    driver_info=$(_ethtool -i "$ena_iface" 2>/dev/null)
    if [[ -n "$driver_info" ]]; then
        local driver_ver
        driver_ver=$(echo "$driver_info" | awk -F': ' '/^version:/{print $2}')
        echo "驱动版本: ${driver_ver:-N/A}"
    else
        echo "驱动版本: 不可用 (ethtool -i 失败)"
    fi

    # 基线计数器
    local stats_output
    stats_output=$(_ethtool -S "$ena_iface" 2>/dev/null)
    if [[ -z "$stats_output" ]]; then
        echo "基线计数器: 不可用 (ethtool -S 失败)"
        echo ""
        return 0
    fi

    # Allowance 计数器
    echo "基线计数器:"
    local allowance_counters=(
        bw_in_allowance_exceeded
        bw_out_allowance_exceeded
        pps_allowance_exceeded
        conntrack_allowance_exceeded
        conntrack_allowance_available
        linklocal_allowance_exceeded
    )
    local counter val
    for counter in "${allowance_counters[@]}"; do
        val=$(echo "$stats_output" | awk -v name="$counter" '$1 == name":" {print $2}')
        printf "  %-35s %s\n" "${counter}:" "${val:-N/A}"
    done

    # SRD 指标
    echo "SRD 指标:"
    local srd_counters=(
        ena_srd_mode
        ena_srd_tx_pkts
        ena_srd_rx_pkts
        ena_srd_eligible_tx_pkts
        ena_srd_resource_utilization
    )
    for counter in "${srd_counters[@]}"; do
        val=$(echo "$stats_output" | awk -v name="$counter" '$1 == name":" {print $2}')
        printf "  %-35s %s\n" "${counter}:" "${val:-N/A}"
    done
    echo ""

    return 0
}

# collect_baseline
#   Baseline_Collector 入口函数
#   创建 REPORT_DIR（如需要），生成 baseline_YYYYMMDD_HHMMSS.txt，
#   调用所有子采集器写入基线文件，设置全局 BASELINE_FILE
#   返回: 0（任何子采集器失败都不影响返回值）
collect_baseline() {
    # 创建报告目录
    mkdir -p "$REPORT_DIR" 2>/dev/null || {
        log_warn "无法创建报告目录 $REPORT_DIR，跳过基线采集"
        return 0
    }

    # 生成基线文件名
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local baseline_file="${REPORT_DIR}/baseline_${timestamp}.txt"

    # 设置全局变量
    BASELINE_FILE="$baseline_file"

    log_info "开始采集系统基线信息..."

    # 写入基线文件
    {
        echo "================================================================================"
        echo "系统基线信息"
        echo "采集时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "================================================================================"
        echo ""

        # 系统基础信息
        collect_system_baseline 2>/dev/null || echo "[采集系统基础信息时发生错误]"

        # EC2 实例信息
        collect_ec2_metadata 2>/dev/null || echo "[采集 EC2 元数据时发生错误]"

        # ENA 网络信息
        collect_ena_baseline 2>/dev/null || echo "[采集 ENA 基线信息时发生错误]"

        # Valkey 配置
        collect_valkey_config 2>/dev/null || echo "[采集 Valkey 配置时发生错误]"

        # Predixy 配置
        collect_predixy_config 2>/dev/null || echo "[采集 Predixy 配置时发生错误]"

        echo "================================================================================"
        echo "基线信息结束"
        echo "================================================================================"
    } > "$baseline_file" 2>/dev/null

    log_info "系统基线信息已保存: $baseline_file"
    return 0
}

# ============================================================================
# Analyzer 组件 — 智能分析
# ============================================================================

# calc_stack_percentage FUNCTION_NAME STACK_DATA
#   计算特定函数在 bpftrace 堆栈采样数据中的采样占比
#   遍历所有堆栈条目，统计包含指定函数名的条目数量占总采样数的百分比
#   参数: $1 = 函数名, $2 = bpftrace 输出文本（堆栈数据）
#   输出: 百分比浮点数到 stdout（如 "85.3"）
#   返回: 0
calc_stack_percentage() {
    local function_name="$1"
    local stack_data="$2"

    # 提取所有 count 值（格式: ]: count）并计算总采样数
    local total_samples
    total_samples=$(echo "$stack_data" | grep -E '\]: [0-9]+$' | sed 's/.*]: //' | awk '{s+=$1} END {print s+0}')

    if [[ "$total_samples" -eq 0 ]]; then
        echo "0.0"
        return 0
    fi

    # 统计包含指定函数名的堆栈条目的 count 之和
    # 每个堆栈条目以 @cpu_stack[ 开头，以 ]: count 结尾
    # 我们需要逐条目检查是否包含 function_name，并累加其 count
    local matched_samples
    matched_samples=$(echo "$stack_data" | awk -v func="$function_name" '
    BEGIN { matched = 0; in_entry = 0; entry = "" }
    /^@cpu_stack\[/ { in_entry = 1; entry = $0; next }
    in_entry {
        entry = entry "\n" $0
        if ($0 ~ /\]: [0-9]+$/) {
            # End of entry — extract count and check for function
            count = $NF
            if (entry ~ func) {
                matched += count
            }
            in_entry = 0
            entry = ""
        }
    }
    END { print matched + 0 }
    ')

    # 计算百分比
    local percentage
    percentage=$(echo "scale=1; $matched_samples * 100 / $total_samples" | _bc -l)
    echo "$percentage"
    return 0
}

# get_top_functions STACK_DATA N
#   从 bpftrace 堆栈采样数据中提取 Top N 热点函数
#   解析堆栈中的函数名及其出现次数，按 count 降序排列
#   参数: $1 = bpftrace 输出文本（堆栈数据）, $2 = Top N 数量
#   输出: 每行格式 "count function_name percentage%" 到 stdout
#   返回: 0
get_top_functions() {
    local stack_data="$1"
    local top_n="$2"

    # 计算总采样数
    local total_samples
    total_samples=$(echo "$stack_data" | grep -E '\]: [0-9]+$' | sed 's/.*]: //' | awk '{s+=$1} END {print s+0}')

    if [[ "$total_samples" -eq 0 ]]; then
        return 0
    fi

    # 解析每个堆栈条目，提取函数名并关联 count
    # 堆栈格式:
    # @cpu_stack[valkey-server,
    # kstack_func1
    # kstack_func2
    # ,
    # ustack_func1
    # ustack_func2
    # ]: count
    #
    # 提取所有非空、非逗号、非 @cpu_stack 开头的行作为函数名
    # 每个函数名关联当前条目的 count
    echo "$stack_data" | awk -v total="$total_samples" -v n="$top_n" '
    BEGIN { in_entry = 0 }
    /^@cpu_stack\[/ {
        in_entry = 1
        delete funcs
        func_count = 0
        next
    }
    in_entry && /\]: [0-9]+$/ {
        # End of entry — get count
        count = $NF
        for (i = 0; i < func_count; i++) {
            func_totals[funcs[i]] += count
        }
        in_entry = 0
        next
    }
    in_entry {
        # Stack frame line — extract function name
        line = $0
        # Skip empty lines, comma separators, and comm name lines
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line == "" || line == "," || line ~ /^@cpu_stack/) next
        # Remove address prefix if present (e.g., "0xffff1234 func_name")
        # Typical bpftrace stack format: just function name or "func_name+offset"
        fname = line
        # Strip +offset suffix
        sub(/\+0x[0-9a-fA-F]+$/, "", fname)
        sub(/\+[0-9]+$/, "", fname)
        if (fname != "" && fname != ",") {
            funcs[func_count++] = fname
        }
    }
    END {
        # Sort by count descending and print top N
        count_idx = 0
        for (f in func_totals) {
            sorted_funcs[count_idx] = f
            sorted_counts[count_idx] = func_totals[f]
            count_idx++
        }
        # Simple selection sort for top N
        for (i = 0; i < count_idx && i < n; i++) {
            max_idx = i
            for (j = i + 1; j < count_idx; j++) {
                if (sorted_counts[j] > sorted_counts[max_idx]) {
                    max_idx = j
                }
            }
            if (max_idx != i) {
                tmp_f = sorted_funcs[i]; sorted_funcs[i] = sorted_funcs[max_idx]; sorted_funcs[max_idx] = tmp_f
                tmp_c = sorted_counts[i]; sorted_counts[i] = sorted_counts[max_idx]; sorted_counts[max_idx] = tmp_c
            }
            pct = (sorted_counts[i] * 100.0) / total
            printf "%d %s %.1f%%\n", sorted_counts[i], sorted_funcs[i], pct
        }
    }
    '
    return 0
}

# analyze_valkey_stacks STACK_DATA_FILE
#   对 valkey-server comm 的 eBPF 堆栈数据执行根因模式匹配
#   实现 6 种 Valkey 根因模式识别，未匹配时输出 Top 5 热点函数
#   参数: $1 = bpftrace 输出文件路径
#   输出: 分析结果文本到 stdout
#   返回: 0
analyze_valkey_stacks() {
    local stack_data_file="$1"

    if [[ ! -r "$stack_data_file" ]]; then
        echo "Valkey 堆栈分析: 不可用 (数据文件不可读: $stack_data_file)"
        return 0
    fi

    # 读取文件内容
    local full_data
    full_data=$(cat "$stack_data_file")

    # 过滤 valkey-server comm 的堆栈条目
    # bpftrace 输出格式:
    # @cpu_stack[valkey-server,
    # kstack
    # ,
    # ustack
    # ]: count
    local valkey_data
    valkey_data=$(echo "$full_data" | awk '
    BEGIN { in_entry = 0; entry = ""; is_valkey = 0 }
    /^@cpu_stack\[/ {
        in_entry = 1
        entry = $0
        # Check if this entry is for valkey-server
        is_valkey = ($0 ~ /valkey-server/) ? 1 : 0
        next
    }
    in_entry {
        entry = entry "\n" $0
        if ($0 ~ /\]: [0-9]+$/) {
            if (is_valkey) {
                print entry
            }
            in_entry = 0
            entry = ""
            is_valkey = 0
        }
    }
    ')

    if [[ -z "$valkey_data" ]]; then
        echo "Valkey 堆栈分析: 未检测到 valkey-server 堆栈数据"
        return 0
    fi

    echo "--- Valkey 根因分析 ---"

    local matched=false

    # === 模式 1: 单线程事件循环瓶颈 ===
    # 条件: aeMain 或 aeApiPoll 采样占比 > 80%
    local ae_main_pct ae_api_poll_pct
    ae_main_pct=$(calc_stack_percentage "aeMain" "$valkey_data")
    ae_api_poll_pct=$(calc_stack_percentage "aeApiPoll" "$valkey_data")

    # 取两者中较大值判断
    local ae_max_pct
    ae_max_pct=$(echo "$ae_main_pct" "$ae_api_poll_pct" | awk '{if ($1 > $2) print $1; else print $2}')

    local ae_above_80
    ae_above_80=$(echo "$ae_max_pct > 80" | _bc -l)
    if [[ "$ae_above_80" -eq 1 ]]; then
        matched=true
        echo "[模式] 单线程事件循环瓶颈"
        echo "[特征函数] aeMain (采样占比: ${ae_main_pct}%), aeApiPoll (采样占比: ${ae_api_poll_pct}%)"
        echo "[建议] 启用 io-threads 配置以分散 I/O 处理负载"
        echo ""
    fi

    # === 模式 2: fork 操作尖峰 ===
    # 条件: 出现 fork / copy_page_range / copy_pte_range 即匹配
    local fork_funcs=()
    local fork_pct
    for fname in fork copy_page_range copy_pte_range; do
        fork_pct=$(calc_stack_percentage "$fname" "$valkey_data")
        local fork_present
        fork_present=$(echo "$fork_pct > 0" | _bc -l)
        if [[ "$fork_present" -eq 1 ]]; then
            fork_funcs+=("${fname} (${fork_pct}%)")
        fi
    done

    if [[ ${#fork_funcs[@]} -gt 0 ]]; then
        matched=true
        echo "[模式] fork 操作导致的尖峰"
        echo "[特征函数] ${fork_funcs[*]}"
        echo "[建议] 检查 BGSAVE 和 BGREWRITEAOF 的调度配置, 检查 Transparent Huge Pages 设置"
        echo ""
    fi

    # === 模式 3: 慢命令阻塞 ===
    # 条件: 出现 sortCommand / keysCommand / lremCommand / sunionCommand 即匹配
    local slow_funcs=()
    local slow_pct
    for fname in sortCommand keysCommand lremCommand sunionCommand; do
        slow_pct=$(calc_stack_percentage "$fname" "$valkey_data")
        local slow_present
        slow_present=$(echo "$slow_pct > 0" | _bc -l)
        if [[ "$slow_present" -eq 1 ]]; then
            slow_funcs+=("${fname} (${slow_pct}%)")
        fi
    done

    if [[ ${#slow_funcs[@]} -gt 0 ]]; then
        matched=true
        echo "[模式] 慢命令阻塞事件循环"
        echo "[特征函数] ${slow_funcs[*]}"
        echo "[建议] 使用 SCAN 系列命令替代全量遍历操作"
        echo ""
    fi

    # === 模式 4: 内存分配热点 ===
    # 条件: 同时出现 (do_anonymous_page 或 handle_mm_fault) AND (dictAddRaw 或 zmalloc)
    local has_kernel_alloc=false
    local has_valkey_alloc=false
    local mem_funcs=()

    for fname in do_anonymous_page handle_mm_fault; do
        local mem_pct
        mem_pct=$(calc_stack_percentage "$fname" "$valkey_data")
        local mem_present
        mem_present=$(echo "$mem_pct > 0" | _bc -l)
        if [[ "$mem_present" -eq 1 ]]; then
            has_kernel_alloc=true
            mem_funcs+=("${fname} (${mem_pct}%)")
        fi
    done

    for fname in dictAddRaw zmalloc; do
        local mem_pct
        mem_pct=$(calc_stack_percentage "$fname" "$valkey_data")
        local mem_present
        mem_present=$(echo "$mem_pct > 0" | _bc -l)
        if [[ "$mem_present" -eq 1 ]]; then
            has_valkey_alloc=true
            mem_funcs+=("${fname} (${mem_pct}%)")
        fi
    done

    if $has_kernel_alloc && $has_valkey_alloc; then
        matched=true
        echo "[模式] 内存分配热点"
        echo "[特征函数] ${mem_funcs[*]}"
        echo "[建议] 调整内存分配器配置或启用 Huge Pages"
        echo ""
    fi

    # === 模式 5: key 过期清理风暴 ===
    # 条件: 出现 activeExpireCycle 即匹配
    local expire_pct
    expire_pct=$(calc_stack_percentage "activeExpireCycle" "$valkey_data")
    local expire_present
    expire_present=$(echo "$expire_pct > 0" | _bc -l)
    if [[ "$expire_present" -eq 1 ]]; then
        matched=true
        echo "[模式] key 过期清理风暴"
        echo "[特征函数] activeExpireCycle (采样占比: ${expire_pct}%)"
        echo "[建议] 分散 key 的过期时间以避免集中过期"
        echo ""
    fi

    # === 模式 6: AOF 写入延迟 ===
    # 条件: 同时出现 (fdatasync 或 write) AND AOF 相关函数
    local has_io_func=false
    local has_aof_func=false
    local aof_funcs=()

    for fname in fdatasync write; do
        local aof_pct
        aof_pct=$(calc_stack_percentage "$fname" "$valkey_data")
        local aof_present
        aof_present=$(echo "$aof_pct > 0" | _bc -l)
        if [[ "$aof_present" -eq 1 ]]; then
            has_io_func=true
            aof_funcs+=("${fname} (${aof_pct}%)")
        fi
    done

    for fname in flushAppendOnlyFile aofWrite aofRewriteBufferAppend feedAppendOnlyFile; do
        local aof_pct
        aof_pct=$(calc_stack_percentage "$fname" "$valkey_data")
        local aof_present
        aof_present=$(echo "$aof_pct > 0" | _bc -l)
        if [[ "$aof_present" -eq 1 ]]; then
            has_aof_func=true
            aof_funcs+=("${fname} (${aof_pct}%)")
        fi
    done

    if $has_io_func && $has_aof_func; then
        matched=true
        echo "[模式] AOF 写入延迟"
        echo "[特征函数] ${aof_funcs[*]}"
        echo "[建议] 调整 appendfsync 配置为 everysec"
        echo ""
    fi

    # === 未匹配任何模式 ===
    if ! $matched; then
        echo "未识别到已知 Valkey 性能模式"
        echo "Top 5 热点函数:"
        local top_output
        top_output=$(get_top_functions "$valkey_data" 5)
        if [[ -n "$top_output" ]]; then
            local rank=0
            while IFS= read -r line; do
                rank=$(( rank + 1 ))
                local count func pct
                count=$(echo "$line" | awk '{print $1}')
                func=$(echo "$line" | awk '{print $2}')
                pct=$(echo "$line" | awk '{print $3}')
                echo "  ${rank}. ${func} (采样: ${count}, 占比: ${pct})"
            done <<< "$top_output"
        else
            echo "  (无堆栈数据)"
        fi
        echo ""
    fi

    return 0
}

# analyze_predixy_stacks STACK_DATA_FILE
#   对 predixy comm 的 eBPF 堆栈数据执行根因模式匹配
#   实现 4 种 Predixy 根因模式识别，未匹配时输出 Top 5 热点函数
#   参数: $1 = bpftrace 输出文件路径
#   输出: 分析结果文本到 stdout
#   返回: 0
analyze_predixy_stacks() {
    local stack_data_file="$1"

    if [[ ! -r "$stack_data_file" ]]; then
        echo "Predixy 堆栈分析: 不可用 (数据文件不可读: $stack_data_file)"
        return 0
    fi

    # 读取文件内容
    local full_data
    full_data=$(cat "$stack_data_file")

    # 过滤 predixy comm 的堆栈条目
    local predixy_data
    predixy_data=$(echo "$full_data" | awk '
    BEGIN { in_entry = 0; entry = ""; is_predixy = 0 }
    /^@cpu_stack\[/ {
        in_entry = 1
        entry = $0
        is_predixy = ($0 ~ /predixy/) ? 1 : 0
        next
    }
    in_entry {
        entry = entry "\n" $0
        if ($0 ~ /\]: [0-9]+$/) {
            if (is_predixy) {
                print entry
            }
            in_entry = 0
            entry = ""
            is_predixy = 0
        }
    }
    ')

    if [[ -z "$predixy_data" ]]; then
        echo "Predixy 堆栈分析: 未检测到 predixy 堆栈数据"
        return 0
    fi

    echo "--- Predixy 根因分析 ---"

    local matched=false

    # === 模式 1: 连接池动态扩容 ===
    # 条件: 同时出现 ConnectionPool::addConnection AND (malloc 或 operator new)
    local has_conn_pool=false
    local has_alloc=false
    local conn_funcs=()

    local conn_pct
    conn_pct=$(calc_stack_percentage "ConnectionPool::addConnection" "$predixy_data")
    local conn_present
    conn_present=$(echo "$conn_pct > 0" | _bc -l)
    if [[ "$conn_present" -eq 1 ]]; then
        has_conn_pool=true
        conn_funcs+=("ConnectionPool::addConnection (${conn_pct}%)")
    fi

    for fname in malloc "operator new"; do
        local alloc_pct
        alloc_pct=$(calc_stack_percentage "$fname" "$predixy_data")
        local alloc_present
        alloc_present=$(echo "$alloc_pct > 0" | _bc -l)
        if [[ "$alloc_present" -eq 1 ]]; then
            has_alloc=true
            conn_funcs+=("${fname} (${alloc_pct}%)")
        fi
    done

    if $has_conn_pool && $has_alloc; then
        matched=true
        echo "[模式] 连接池动态扩容"
        echo "[特征函数] ${conn_funcs[*]}"
        echo "[建议] 通过 InitPoolSize 配置预分配连接池以减少运行时动态扩容开销"
        echo ""
    fi

    # === 模式 2: 内存分配热点 ===
    # 条件: 同时出现 (je_arena_malloc 或 std::allocator) AND Request::parse
    local has_jemalloc=false
    local has_request_parse=false
    local mem_funcs=()

    for fname in je_arena_malloc "std::allocator"; do
        local mem_pct
        mem_pct=$(calc_stack_percentage "$fname" "$predixy_data")
        local mem_present
        mem_present=$(echo "$mem_pct > 0" | _bc -l)
        if [[ "$mem_present" -eq 1 ]]; then
            has_jemalloc=true
            mem_funcs+=("${fname} (${mem_pct}%)")
        fi
    done

    local req_pct
    req_pct=$(calc_stack_percentage "Request::parse" "$predixy_data")
    local req_present
    req_present=$(echo "$req_pct > 0" | _bc -l)
    if [[ "$req_present" -eq 1 ]]; then
        has_request_parse=true
        mem_funcs+=("Request::parse (${req_pct}%)")
    fi

    if $has_jemalloc && $has_request_parse; then
        matched=true
        echo "[模式] 内存分配热点"
        echo "[特征函数] ${mem_funcs[*]}"
        echo "[建议] 调整 jemalloc 参数 (background_thread, dirty_decay_ms) 以优化内存分配性能"
        echo ""
    fi

    # === 模式 3: 多线程锁竞争 ===
    # 条件: 出现 pthread_mutex_lock 或 futex_wait 即匹配
    local lock_funcs=()

    for fname in pthread_mutex_lock futex_wait; do
        local lock_pct
        lock_pct=$(calc_stack_percentage "$fname" "$predixy_data")
        local lock_present
        lock_present=$(echo "$lock_pct > 0" | _bc -l)
        if [[ "$lock_present" -eq 1 ]]; then
            lock_funcs+=("${fname} (${lock_pct}%)")
        fi
    done

    if [[ ${#lock_funcs[@]} -gt 0 ]]; then
        matched=true
        echo "[模式] 多线程锁竞争"
        echo "[特征函数] ${lock_funcs[*]}"
        echo "[建议] 检查 Predixy 的 WorkerThreads 配置是否与 CPU 核心数匹配"
        echo ""
    fi

    # === 模式 4: epoll 事件循环瓶颈 ===
    # 条件: epoll_wait 采样占比 > 70%
    local epoll_pct
    epoll_pct=$(calc_stack_percentage "epoll_wait" "$predixy_data")
    local epoll_above_70
    epoll_above_70=$(echo "$epoll_pct > 70" | _bc -l)
    if [[ "$epoll_above_70" -eq 1 ]]; then
        matched=true
        echo "[模式] epoll 事件循环瓶颈"
        echo "[特征函数] epoll_wait (采样占比: ${epoll_pct}%)"
        echo "[建议] 检查后端连接数配置和超时参数"
        echo ""
    fi

    # === 未匹配任何模式 ===
    if ! $matched; then
        echo "未识别到已知 Predixy 性能模式"
        echo "Top 5 热点函数:"
        local top_output
        top_output=$(get_top_functions "$predixy_data" 5)
        if [[ -n "$top_output" ]]; then
            local rank=0
            while IFS= read -r line; do
                rank=$(( rank + 1 ))
                local count func pct
                count=$(echo "$line" | awk '{print $1}')
                func=$(echo "$line" | awk '{print $2}')
                pct=$(echo "$line" | awk '{print $3}')
                echo "  ${rank}. ${func} (采样: ${count}, 占比: ${pct})"
            done <<< "$top_output"
        else
            echo "  (无堆栈数据)"
        fi
        echo ""
    fi

    return 0
}

# analyze_stacks STACK_DATA_FILE
#   分析入口函数：根据堆栈数据中的 comm 字段分发到对应的分析器
#   - 检测 valkey-server comm → 调用 analyze_valkey_stacks()
#   - 检测 predixy comm → 调用 analyze_predixy_stacks()
#   - 两者都未检测到 → 输出提示信息
#   输出包裹在 "=== 智能分析 ===" section 中
#   参数: $1 = bpftrace 输出文件路径
#   输出: 完整分析文本到 stdout
#   返回: 0
analyze_stacks() {
    local stack_data_file="$1"

    echo "=== 智能分析 ==="

    # 检查数据文件是否可读
    if [[ ! -r "$stack_data_file" ]]; then
        echo "堆栈分析: 不可用 (数据文件不可读: $stack_data_file)"
        echo ""
        return 0
    fi

    local data
    data=$(cat "$stack_data_file" 2>/dev/null)

    if [[ -z "$data" ]]; then
        echo "堆栈分析: 不可用 (数据文件为空)"
        echo ""
        return 0
    fi

    local found_any=false

    # 检查是否包含 valkey-server comm 条目
    if echo "$data" | grep -q "valkey-server"; then
        found_any=true
        analyze_valkey_stacks "$stack_data_file"
    fi

    # 检查是否包含 predixy comm 条目
    if echo "$data" | grep -q "predixy"; then
        found_any=true
        analyze_predixy_stacks "$stack_data_file"
    fi

    # 两者都未检测到
    if ! $found_any; then
        echo "未检测到目标进程堆栈数据"
        echo ""
    fi

    return 0
}

# ============================================================================
# 采集/报告占位函数（后续任务实现）
# ============================================================================

# start_atop OUTPUT_FILE
#   启动 atop 后台进程，以 ATOP_INTERVAL 间隔采集系统级和进程级性能数据
#   使用 999 次迭代（实际上无限运行，采样结束时由 stop_atop 终止）
#   参数: $1 = atop stdout 输出文件路径
#   设置: 全局 ATOP_PID
#   返回: 0 = 成功, 1 = atop 命令不可用
start_atop() {
    local output_file="$1"

    # 检查 atop 命令是否可用
    if ! command -v atop &>/dev/null; then
        log_warn "atop 命令不可用，跳过 atop 并行采集"
        return 1
    fi

    # 后台启动 atop: -a 显示所有进程资源信息, ATOP_INTERVAL 秒间隔, 999 次迭代
    _atop -a "$ATOP_INTERVAL" 999 > "$output_file" 2>/dev/null &
    ATOP_PID=$!

    # 短暂等待确认 atop 进程已启动
    sleep 0.2
    if ! kill -0 "$ATOP_PID" 2>/dev/null; then
        log_error "atop 进程启动后立即退出 (PID=$ATOP_PID)"
        ATOP_PID=""
        return 1
    fi

    log_info "atop 已启动 (PID=$ATOP_PID, 间隔=${ATOP_INTERVAL}s)"
    return 0
}

# stop_atop
#   终止 atop 后台进程并收集输出数据
#   检查 ATOP_PID 是否有效且进程仍在运行，发送 SIGTERM 并等待退出
#   如果 atop 已提前退出，记录异常退出警告
#   清除全局 ATOP_PID
#   返回: 0
stop_atop() {
    # 没有启动过 atop，直接返回
    if [[ -z "$ATOP_PID" ]]; then
        log_info "stop_atop: 无 atop 进程需要终止"
        return 0
    fi

    # 检查 atop 进程是否仍在运行
    if kill -0 "$ATOP_PID" 2>/dev/null; then
        log_info "终止 atop (PID=$ATOP_PID)"
        kill -SIGTERM "$ATOP_PID" 2>/dev/null || true
        wait "$ATOP_PID" 2>/dev/null || true
    else
        # atop 已不在运行 — 异常退出
        log_warn "atop 进程 (PID=$ATOP_PID) 已异常退出，采样期间 atop 数据可能不完整"
    fi

    ATOP_PID=""
    return 0
}

# collect_valkey_info SAMPLING_DIR
#   通过 valkey-cli INFO 采集 Valkey 运行时关键指标
#   提取: latest_fork_usec, used_memory, used_memory_rss, connected_clients,
#         instantaneous_ops_per_sec, keyspace_hits, keyspace_misses, expired_keys
#   连接失败时记录错误日志并标注不可用
#   参数: $1 = 采样目录路径
#   返回: 0
collect_valkey_info() {
    local sampling_dir="$1"
    local output_file="${sampling_dir}/valkey_info.txt"

    # valkey-cli 不可用时优雅跳过
    if ! command -v valkey-cli &>/dev/null; then
        log_warn "valkey-cli 未安装，跳过 Valkey 指标采集"
        echo "Valkey 指标: 不可用 (valkey-cli 未安装)" > "$output_file"
        return 0
    fi

    # 执行 valkey-cli INFO，2 秒超时
    local raw_info
    raw_info=$(timeout 2 _valkey_cli -h "$VALKEY_HOST" -p "$VALKEY_PORT" INFO 2>&1)
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        local err_msg
        if [[ $rc -eq 124 ]]; then
            err_msg="连接超时 (2s)"
        else
            err_msg=$(echo "$raw_info" | head -1)
        fi
        log_error "Valkey INFO 采集失败: $err_msg"
        echo "Valkey 指标: 不可用 (连接失败: ${err_msg})" > "$output_file"
        return 0
    fi

    # 提取关键指标
    local metrics_keys=(
        latest_fork_usec
        used_memory
        used_memory_rss
        connected_clients
        instantaneous_ops_per_sec
        keyspace_hits
        keyspace_misses
        expired_keys
    )

    {
        echo "--- Valkey 指标 (${VALKEY_HOST}:${VALKEY_PORT}) ---"
        echo "采集时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        local key value
        for key in "${metrics_keys[@]}"; do
            value=$(echo "$raw_info" | grep -E "^${key}:" | cut -d: -f2 | tr -d '[:space:]')
            if [[ -n "$value" ]]; then
                printf "%-30s %s\n" "${key}:" "$value"
            else
                printf "%-30s %s\n" "${key}:" "N/A"
            fi
        done
    } > "$output_file"

    log_info "Valkey 指标已采集: $output_file"
    return 0
}

# collect_predixy_info SAMPLING_DIR
#   通过 redis-cli INFO 采集 Predixy 运行时指标
#   连接失败时记录错误日志并标注不可用
#   参数: $1 = 采样目录路径
#   返回: 0
collect_predixy_info() {
    local sampling_dir="$1"
    local output_file="${sampling_dir}/predixy_info.txt"

    # redis-cli 不可用时优雅跳过
    if ! command -v redis-cli &>/dev/null; then
        log_warn "redis-cli 未安装，跳过 Predixy 指标采集"
        echo "Predixy 指标: 不可用 (redis-cli 未安装)" > "$output_file"
        return 0
    fi

    # 执行 redis-cli INFO，2 秒超时
    local raw_info
    raw_info=$(timeout 2 _redis_cli -h "$PREDIXY_HOST" -p "$PREDIXY_PORT" INFO 2>&1)
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        local err_msg
        if [[ $rc -eq 124 ]]; then
            err_msg="连接超时 (2s)"
        else
            err_msg=$(echo "$raw_info" | head -1)
        fi
        log_error "Predixy INFO 采集失败: $err_msg"
        echo "Predixy 指标: 不可用 (连接失败: ${err_msg})" > "$output_file"
        return 0
    fi

    # 写入完整 INFO 输出
    {
        echo "--- Predixy 指标 (${PREDIXY_HOST}:${PREDIXY_PORT}) ---"
        echo "采集时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "$raw_info"
    } > "$output_file"

    log_info "Predixy 指标已采集: $output_file"
    return 0
}

# collect_dynamic_sysinfo SAMPLING_DIR
#   采集动态系统信息：uptime, free -m, iostat（如可用）, ss -s
#   每个部分带标题标签，缺失命令优雅跳过
#   参数: $1 = 采样目录路径
#   返回: 0
collect_dynamic_sysinfo() {
    local sampling_dir="$1"
    local output_file="${sampling_dir}/dynamic_sysinfo.txt"

    {
        echo "=== 动态系统信息 ==="
        echo "采集时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""

        # --- 系统负载 ---
        echo "--- 系统负载 (uptime) ---"
        if command -v uptime &>/dev/null; then
            uptime 2>/dev/null || echo "uptime 执行失败"
        else
            echo "不可用 (uptime 命令未找到)"
        fi
        echo ""

        # --- 内存使用 ---
        echo "--- 内存使用 (free -m) ---"
        if command -v free &>/dev/null; then
            free -m 2>/dev/null || echo "free 执行失败"
        else
            echo "不可用 (free 命令未找到)"
        fi
        echo ""

        # --- 磁盘 I/O ---
        echo "--- 磁盘 I/O (iostat) ---"
        if command -v iostat &>/dev/null; then
            iostat -x 1 1 2>/dev/null || echo "iostat 执行失败"
        else
            echo "不可用 (iostat 未安装)"
        fi
        echo ""

        # --- 网络连接 ---
        echo "--- 网络连接 (ss -s) ---"
        if command -v ss &>/dev/null; then
            ss -s 2>/dev/null || echo "ss 执行失败"
        else
            echo "不可用 (ss 命令未找到)"
        fi
    } > "$output_file"

    log_info "动态系统信息已采集: $output_file"
    return 0
}

# collect_ena_timeseries SAMPLING_DIR MAX_DURATION
#   ENA 网络指标时序采集：以每秒 1 次频率采集 ENA_Allowance_Metrics 和 ENA_SRD_Metrics，
#   计算逐秒增量，写入 ${SAMPLING_DIR}/ena_timeseries.txt
#   设计为后台运行（由 start_sampling 以 & 调用）
#   参数: $1 = 采样目录路径, $2 = 最大采集时长（秒）
#   返回: 0
collect_ena_timeseries() {
    local sampling_dir="$1"
    local max_duration="$2"
    local output_file="${sampling_dir}/ena_timeseries.txt"

    # ethtool 不可用时优雅跳过
    if ! command -v ethtool &>/dev/null; then
        echo "ENA 指标: 不可用 (ethtool 未安装)" > "$output_file"
        return 0
    fi

    # 检测 ENA 接口
    local ena_iface
    ena_iface=$(detect_ena_interface 2>/dev/null)
    if [[ -z "$ena_iface" ]]; then
        echo "ENA 指标: 不可用 (未检测到 ENA 接口)" > "$output_file"
        return 0
    fi

    # ENA 计数器名称列表
    local allowance_counters=(
        bw_in_allowance_exceeded
        bw_out_allowance_exceeded
        pps_allowance_exceeded
        conntrack_allowance_exceeded
        conntrack_allowance_available
        linklocal_allowance_exceeded
    )
    local srd_counters=(
        ena_srd_mode
        ena_srd_tx_pkts
        ena_srd_rx_pkts
        ena_srd_eligible_tx_pkts
        ena_srd_resource_utilization
    )
    local all_counters=("${allowance_counters[@]}" "${srd_counters[@]}")

    # _read_ena_counters: 从 ethtool -S 输出中提取所有计数器的当前值
    # 输出: 以空格分隔的计数器值（与 all_counters 顺序一致）
    _read_ena_counters() {
        local stats_output
        stats_output=$(_ethtool -S "$ena_iface" 2>/dev/null) || {
            # ethtool -S 失败，返回全零
            local zeros=""
            local i
            for (( i=0; i<${#all_counters[@]}; i++ )); do
                [[ -n "$zeros" ]] && zeros+=" "
                zeros+="0"
            done
            echo "$zeros"
            return 1
        }

        local values="" counter_name val
        for counter_name in "${all_counters[@]}"; do
            val=$(echo "$stats_output" | awk -v name="$counter_name" '$1 == name":" {print $2}')
            [[ -z "$val" ]] && val="0"
            [[ -n "$values" ]] && values+=" "
            values+="$val"
        done
        echo "$values"
    }

    # 写入文件头
    {
        echo "接口: $ena_iface"
        echo "采样窗口: ${max_duration} 秒"
        echo ""

        # 构建表头
        local header="时间(秒)"
        local c
        for c in "${all_counters[@]}"; do
            header+="  $c"
        done
        echo "$header"
    } > "$output_file"

    # 读取初始计数器值（基准）
    local prev_values
    prev_values=$(_read_ena_counters)

    # 逐秒采集循环
    local elapsed=0
    while [[ "$elapsed" -lt "$max_duration" ]]; do
        sleep 1
        elapsed=$(( elapsed + 1 ))

        local curr_values
        curr_values=$(_read_ena_counters)

        # 计算逐秒增量
        local prev_arr=($prev_values)
        local curr_arr=($curr_values)
        local delta_line="$elapsed"
        local i
        for (( i=0; i<${#all_counters[@]}; i++ )); do
            local prev_val="${prev_arr[$i]:-0}"
            local curr_val="${curr_arr[$i]:-0}"
            local delta=$(( curr_val - prev_val ))
            delta_line+="  $delta"
        done

        echo "$delta_line" >> "$output_file"

        prev_values="$curr_values"
    done

    return 0
}

# generate_report SAMPLING_DIR
#   聚合所有采样数据生成结构化纯文本分析报告
#   参数: $1 = 采样目录路径（包含 metadata.txt, bpftrace_output.txt 等数据文件）
#   流程:
#     1. 创建 REPORT_DIR 和 ARCHIVE_DIR（如不存在）
#     2. 生成报告文件名 spike_YYYYMMDD_HHMMSS.txt
#     3. 读取 metadata.txt 获取触发信息
#     4. 按设计文档格式组装报告各 section
#     5. 写入前执行 check_disk_space() 和 enforce_retention()
#   输出: 报告文件路径到 stdout
#   返回: 0 = 成功, 1 = 磁盘空间检查失败
generate_report() {
    local sampling_dir="$1"

    # --- 创建报告目录 ---
    mkdir -p "$REPORT_DIR" 2>/dev/null || {
        log_error "无法创建报告目录: $REPORT_DIR"
        return 1
    }
    mkdir -p "$ARCHIVE_DIR" 2>/dev/null || {
        log_error "无法创建归档目录: $ARCHIVE_DIR"
        return 1
    }

    # --- 生成报告文件名 ---
    local report_filename="spike_$(date '+%Y%m%d_%H%M%S').txt"
    local report_file="${REPORT_DIR}/${report_filename}"

    # --- 读取触发元数据 ---
    local trigger_time="" trigger_proc="" trigger_pid="" raw_cpu="" normalized_cpu=""
    local peak_cpu="" sampling_duration="" baseline_file_ref=""
    local metadata_file="${sampling_dir}/metadata.txt"

    if [[ -r "$metadata_file" ]]; then
        trigger_time=$(grep '^TRIGGER_TIME=' "$metadata_file" 2>/dev/null | cut -d= -f2-)
        trigger_proc=$(grep '^TRIGGER_PROC=' "$metadata_file" 2>/dev/null | cut -d= -f2-)
        trigger_pid=$(grep '^TRIGGER_PID=' "$metadata_file" 2>/dev/null | cut -d= -f2-)
        raw_cpu=$(grep '^RAW_CPU=' "$metadata_file" 2>/dev/null | cut -d= -f2-)
        normalized_cpu=$(grep '^NORMALIZED_CPU=' "$metadata_file" 2>/dev/null | cut -d= -f2-)
        peak_cpu=$(grep '^PEAK_CPU=' "$metadata_file" 2>/dev/null | cut -d= -f2-)
        sampling_duration=$(grep '^SAMPLING_DURATION=' "$metadata_file" 2>/dev/null | cut -d= -f2-)
        baseline_file_ref=$(grep '^BASELINE_FILE=' "$metadata_file" 2>/dev/null | cut -d= -f2-)
    else
        log_warn "元数据文件不可读: $metadata_file"
        trigger_time="不可用"
        trigger_proc="不可用"
        trigger_pid="不可用"
        raw_cpu="不可用"
        normalized_cpu="不可用"
        peak_cpu="不可用"
        sampling_duration="不可用"
        baseline_file_ref="不可用"
    fi

    # 获取触发进程的 vCPU 数
    local vcpu_count="${PROC_VCPU_MAP[${trigger_proc}]:-不可用}"

    # --- 执行磁盘空间检查和 retention ---
    if type -t check_disk_space &>/dev/null; then
        if ! check_disk_space; then
            log_warn "磁盘空间不足，跳过报告写入"
            return 1
        fi
    fi

    if type -t enforce_retention &>/dev/null; then
        enforce_retention 2>/dev/null || log_warn "Retention 策略执行失败"
    fi

    # --- 组装报告内容 ---
    {
        # ===== Header =====
        echo "================================================================================"
        echo "eBPF CPU 尖峰分析报告"
        echo "================================================================================"

        # ===== 触发信息 =====
        echo ""
        echo "=== 触发信息 ==="
        echo "触发时间:     ${trigger_time}"
        echo "触发进程:     ${trigger_proc} (PID: ${trigger_pid})"
        echo "原始 CPU:     ${raw_cpu}%"
        echo "归一化 CPU:   ${normalized_cpu}% (vCPU数: ${vcpu_count})"
        echo "采样时长:     ${sampling_duration} 秒"
        echo "基线文件:     ${baseline_file_ref:-不可用}"
        echo "================================================================================"

        # ===== eBPF 堆栈统计 =====
        echo ""
        echo "=== eBPF 堆栈统计 (按出现次数降序) ==="
        local bpftrace_file="${sampling_dir}/bpftrace_output.txt"
        if [[ -r "$bpftrace_file" ]] && [[ -s "$bpftrace_file" ]]; then
            # 解析 bpftrace 输出并按 count 降序排序
            # bpftrace 输出格式: 堆栈块以 ]: count 结尾
            # 策略: 将每个堆栈条目视为一个块，提取 count 值排序
            _sort_bpftrace_by_count "$bpftrace_file"
        else
            echo "eBPF 堆栈数据: 不可用 (bpftrace 输出文件为空或不可读)"
        fi

        # ===== 智能分析 =====
        echo ""
        if type -t analyze_stacks &>/dev/null; then
            analyze_stacks "$bpftrace_file"
        else
            echo "=== 智能分析 ==="
            echo "智能分析: 不可用 (分析器未加载)"
        fi

        # ===== 运行时指标 =====
        echo ""
        echo "=== 运行时指标 ==="
        # Valkey 指标
        local valkey_file="${sampling_dir}/valkey_info.txt"
        if [[ -r "$valkey_file" ]] && [[ -s "$valkey_file" ]]; then
            cat "$valkey_file"
        else
            echo "Valkey 指标: 不可用 (数据文件为空或不可读)"
        fi
        echo ""
        # Predixy 指标
        local predixy_file="${sampling_dir}/predixy_info.txt"
        if [[ -r "$predixy_file" ]] && [[ -s "$predixy_file" ]]; then
            cat "$predixy_file"
        else
            echo "Predixy 指标: 不可用 (数据文件为空或不可读)"
        fi

        # ===== ENA 网络指标 =====
        echo ""
        echo "=== ENA 网络指标 ==="
        local ena_file="${sampling_dir}/ena_timeseries.txt"
        if [[ -r "$ena_file" ]] && [[ -s "$ena_file" ]]; then
            cat "$ena_file"
        else
            echo "ENA 指标: 不可用 (数据文件为空或不可读)"
        fi

        # ===== 系统快照 =====
        echo ""
        echo "=== 系统快照 ==="

        # --- mpstat ---
        echo "--- mpstat ---"
        local mpstat_file="${sampling_dir}/mpstat_snapshot.txt"
        if [[ -r "$mpstat_file" ]] && [[ -s "$mpstat_file" ]]; then
            cat "$mpstat_file"
        else
            echo "mpstat 数据: 不可用 (数据文件为空或不可读)"
        fi
        echo ""

        # --- atop ---
        echo "--- atop ---"
        local atop_file="${sampling_dir}/atop_output.txt"
        if [[ -r "$atop_file" ]] && [[ -s "$atop_file" ]]; then
            cat "$atop_file"
        else
            echo "atop 数据: 不可用 (atop 在采样期间未运行或异常退出)"
        fi
        echo ""

        # --- 动态系统信息 ---
        local sysinfo_file="${sampling_dir}/dynamic_sysinfo.txt"
        if [[ -r "$sysinfo_file" ]] && [[ -s "$sysinfo_file" ]]; then
            cat "$sysinfo_file"
        else
            echo "--- 动态系统信息 ---"
            echo "动态系统信息: 不可用 (数据文件为空或不可读)"
        fi
        echo ""

        # --- 目标进程状态 ---
        echo "--- 目标进程状态 ---"
        local proc_name_iter
        for proc_name_iter in "${!PROC_VCPU_MAP[@]}"; do
            local ps_output
            ps_output=$(ps aux 2>/dev/null | grep -E "[${proc_name_iter:0:1}]${proc_name_iter:1}" 2>/dev/null)
            if [[ -n "$ps_output" ]]; then
                echo "$ps_output"
            else
                echo "${proc_name_iter}: 未运行"
            fi
        done

        # ===== Footer =====
        echo ""
        echo "================================================================================"
        echo "报告结束"
        echo "================================================================================"
    } > "$report_file"

    # --- 输出报告路径 ---
    echo "$report_file"
    log_info "报告已生成: $report_file"

    return 0
}

# _sort_bpftrace_by_count BPFTRACE_FILE
#   解析 bpftrace 输出并按 count 值降序排序输出
#   bpftrace 聚合输出格式示例:
#     @cpu_stack[comm, kstack, ustack]: count
#   每个条目可能跨多行（堆栈帧），以 ]: <number> 结尾
#   参数: $1 = bpftrace 输出文件路径
#   输出: 排序后的堆栈数据到 stdout
_sort_bpftrace_by_count() {
    local bpftrace_file="$1"

    # 使用 awk 解析 bpftrace 输出:
    # - 收集每个堆栈块（从 @cpu_stack 开始到 ]: count 结束）
    # - 提取 count 值
    # - 按 count 降序排序输出
    awk '
    BEGIN {
        block = ""
        count = 0
        idx = 0
    }
    {
        # 累积当前行到 block
        if (block == "") {
            block = $0
        } else {
            block = block "\n" $0
        }

        # 检查是否是块结尾（包含 ]: 数字）
        if ($0 ~ /\]: *[0-9]+/) {
            # 提取 count 值: 取 ]: 后面的数字
            tmp = $0
            sub(/.*\]: */, "", tmp)
            sub(/[^0-9].*/, "", tmp)
            count = tmp + 0
            blocks[idx] = block
            counts[idx] = count
            idx++
            block = ""
            count = 0
        }
    }
    END {
        # 如果有未闭合的块，也输出
        if (block != "") {
            blocks[idx] = block
            counts[idx] = 0
            idx++
        }

        # 简单选择排序（按 count 降序）
        for (i = 0; i < idx - 1; i++) {
            max_i = i
            for (j = i + 1; j < idx; j++) {
                if (counts[j] > counts[max_i]) {
                    max_i = j
                }
            }
            if (max_i != i) {
                tmp_b = blocks[i]; blocks[i] = blocks[max_i]; blocks[max_i] = tmp_b
                tmp_c = counts[i]; counts[i] = counts[max_i]; counts[max_i] = tmp_c
            }
        }

        # 输出排序后的块
        for (i = 0; i < idx; i++) {
            print blocks[i]
            if (i < idx - 1) print ""
        }
    }
    ' "$bpftrace_file"
}

# ============================================================================
# 报告文件管理与磁盘空间保护 (Task 11.1)
# ============================================================================

# archive_hot_reports
#   检查 REPORT_DIR 中的 spike_*.txt 报告文件年龄，
#   超过 RETENTION_HOT_HOURS 的文件用 gzip 压缩为 .txt.gz 并移至 ARCHIVE_DIR。
#   压缩完成后删除原始文件；gzip 失败时保留原始文件并记录错误日志。
#   返回: 0（始终返回 0）
archive_hot_reports() {
    # 确保归档目录存在
    mkdir -p "$ARCHIVE_DIR" 2>/dev/null || {
        log_error "archive_hot_reports: 无法创建归档目录 $ARCHIVE_DIR"
        return 0
    }

    # 计算热保留期阈值（秒）
    local hot_seconds=$(( RETENTION_HOT_HOURS * 3600 ))
    local now
    now=$(date +%s)

    # 遍历 REPORT_DIR 中的 spike_*.txt 文件（不递归进入 ARCHIVE_DIR）
    local file
    for file in "${REPORT_DIR}"/spike_*.txt; do
        # glob 无匹配时跳过
        [[ -f "$file" ]] || continue

        # 获取文件修改时间（epoch）
        local file_mtime
        file_mtime=$(stat -c '%Y' "$file" 2>/dev/null) || {
            log_warn "archive_hot_reports: 无法获取文件修改时间: $file"
            continue
        }

        # 计算文件年龄
        local file_age=$(( now - file_mtime ))

        # 文件年龄未超过热保留期，跳过
        if [[ "$file_age" -le "$hot_seconds" ]]; then
            continue
        fi

        # 文件超过热保留期，执行 gzip 压缩归档
        local basename
        basename=$(basename "$file")
        local archive_path="${ARCHIVE_DIR}/${basename}.gz"

        if gzip -c "$file" > "$archive_path" 2>/dev/null; then
            # 压缩成功，删除原始文件
            rm -f "$file"
            log_info "archive_hot_reports: 已归档 $basename -> ${ARCHIVE_DIR}/${basename}.gz"
        else
            # 压缩失败，保留原始文件，清理可能的不完整归档文件
            rm -f "$archive_path" 2>/dev/null
            log_error "archive_hot_reports: gzip 压缩失败，保留原始文件: $file"
        fi
    done

    return 0
}

# cleanup_old_reports [COUNT]
#   从最旧文件开始删除报告文件（含归档文件）
#   参数: $1 = 要删除的文件数量（默认 1）
#   返回: 0
cleanup_old_reports() {
    local count="${1:-1}"

    # 列出 REPORT_DIR 和 ARCHIVE_DIR 中所有报告文件，按修改时间排序（最旧优先）
    local files=()
    local f

    # 收集所有 .txt 和 .txt.gz 报告文件（排除非报告文件如 dependency_report、baseline）
    while IFS= read -r f; do
        [[ -n "$f" ]] && files+=("$f")
    done < <(
        {
            find "$REPORT_DIR" -maxdepth 1 -type f \( -name "spike_*.txt" -o -name "spike_*.txt.gz" \) 2>/dev/null
            if [[ -d "$ARCHIVE_DIR" ]]; then
                find "$ARCHIVE_DIR" -maxdepth 1 -type f \( -name "spike_*.txt" -o -name "spike_*.txt.gz" \) 2>/dev/null
            fi
        } | sort -t/ -k1,1
    )

    # 按修改时间排序（最旧优先）
    if [[ ${#files[@]} -eq 0 ]]; then
        log_info "cleanup_old_reports: 没有可清理的报告文件"
        return 0
    fi

    local sorted_files=()
    while IFS= read -r f; do
        [[ -n "$f" ]] && sorted_files+=("$f")
    done < <(
        for f in "${files[@]}"; do
            echo "$(stat -c '%Y' "$f" 2>/dev/null || echo 0) $f"
        done | sort -n | awk '{print $2}'
    )

    local deleted=0
    for f in "${sorted_files[@]}"; do
        if [[ "$deleted" -ge "$count" ]]; then
            break
        fi
        if [[ -f "$f" ]]; then
            rm -f "$f"
            log_info "cleanup_old_reports: 已删除 $f"
            deleted=$(( deleted + 1 ))
        fi
    done

    return 0
}

# check_disk_space
#   检查 REPORT_DIR 所在磁盘分区的剩余空间是否低于 MIN_DISK_FREE_MB
#   - 空间充足: 重置 LOW_DISK_COUNT 为 0，返回 0
#   - 空间不足: 递增 LOW_DISK_COUNT，输出告警日志，返回 1
#   - 连续 3 次空间不足: 尝试删除最旧文件后再返回 1
#   返回: 0 = 空间充足, 1 = 空间不足
check_disk_space() {
    # 确保 REPORT_DIR 存在
    mkdir -p "$REPORT_DIR" 2>/dev/null || true

    # 使用 df 获取 REPORT_DIR 所在分区的可用空间 (MB)
    local avail_kb
    avail_kb=$(df -k "$REPORT_DIR" 2>/dev/null | awk 'NR==2 {print $4}')

    if [[ -z "$avail_kb" ]]; then
        log_warn "check_disk_space: 无法获取磁盘空间信息"
        return 1
    fi

    local avail_mb=$(( avail_kb / 1024 ))

    if [[ "$avail_mb" -lt "$MIN_DISK_FREE_MB" ]]; then
        LOW_DISK_COUNT=$(( LOW_DISK_COUNT + 1 ))
        log_warn "check_disk_space: 磁盘剩余空间不足 (${avail_mb}MB < ${MIN_DISK_FREE_MB}MB)，连续告警次数: ${LOW_DISK_COUNT}"

        # 连续 3 次空间不足，尝试删除最旧文件
        if [[ "$LOW_DISK_COUNT" -ge 3 ]]; then
            log_warn "check_disk_space: 连续 ${LOW_DISK_COUNT} 次磁盘空间不足，尝试删除最旧报告文件"
            cleanup_old_reports 1
        fi

        return 1
    fi

    # 空间充足，重置计数器
    LOW_DISK_COUNT=0
    return 0
}

# enforce_retention
#   执行 retention 策略：
#   1. 最大保留数量 (MAX_REPORTS): 超过则删除最旧文件
#   2. 最大保留天数 (MAX_RETENTION_DAYS): 超期文件删除
#   3. 目录大小上限 (MAX_DIR_SIZE_MB): 超限则从最旧文件开始删除
#   返回: 0
enforce_retention() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    mkdir -p "$ARCHIVE_DIR" 2>/dev/null || true

    # --- 1. 检查最大报告数量 ---
    local total_count
    total_count=$(
        {
            find "$REPORT_DIR" -maxdepth 1 -type f \( -name "spike_*.txt" -o -name "spike_*.txt.gz" \) 2>/dev/null
            find "$ARCHIVE_DIR" -maxdepth 1 -type f \( -name "spike_*.txt" -o -name "spike_*.txt.gz" \) 2>/dev/null
        } | wc -l
    )

    if [[ "$total_count" -gt "$MAX_REPORTS" ]]; then
        local excess=$(( total_count - MAX_REPORTS ))
        log_info "enforce_retention: 报告数量 (${total_count}) 超过上限 (${MAX_REPORTS})，删除 ${excess} 个最旧文件"
        cleanup_old_reports "$excess"
    fi

    # --- 2. 检查最大保留天数 ---
    local expired_files=()
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] && expired_files+=("$f")
    done < <(
        {
            find "$REPORT_DIR" -maxdepth 1 -type f \( -name "spike_*.txt" -o -name "spike_*.txt.gz" \) -mtime +"$MAX_RETENTION_DAYS" 2>/dev/null
            find "$ARCHIVE_DIR" -maxdepth 1 -type f \( -name "spike_*.txt" -o -name "spike_*.txt.gz" \) -mtime +"$MAX_RETENTION_DAYS" 2>/dev/null
        }
    )

    if [[ ${#expired_files[@]} -gt 0 ]]; then
        log_info "enforce_retention: 发现 ${#expired_files[@]} 个超过 ${MAX_RETENTION_DAYS} 天的过期文件"
        for f in "${expired_files[@]}"; do
            if [[ -f "$f" ]]; then
                rm -f "$f"
                log_info "enforce_retention: 已删除过期文件 $f"
            fi
        done
    fi

    # --- 3. 检查目录大小上限 ---
    local dir_size_kb
    dir_size_kb=$(du -sk "$REPORT_DIR" 2>/dev/null | awk '{print $1}')
    dir_size_kb="${dir_size_kb:-0}"
    local dir_size_mb=$(( dir_size_kb / 1024 ))

    if [[ "$dir_size_mb" -gt "$MAX_DIR_SIZE_MB" ]]; then
        log_info "enforce_retention: 目录大小 (${dir_size_mb}MB) 超过上限 (${MAX_DIR_SIZE_MB}MB)，开始清理"

        # 循环删除最旧文件直到目录大小低于上限
        local max_iterations=50  # 安全上限，防止无限循环
        local iter=0
        while [[ "$dir_size_mb" -gt "$MAX_DIR_SIZE_MB" && "$iter" -lt "$max_iterations" ]]; do
            cleanup_old_reports 1

            # 重新计算目录大小
            dir_size_kb=$(du -sk "$REPORT_DIR" 2>/dev/null | awk '{print $1}')
            dir_size_kb="${dir_size_kb:-0}"
            dir_size_mb=$(( dir_size_kb / 1024 ))
            iter=$(( iter + 1 ))
        done

        if [[ "$dir_size_mb" -gt "$MAX_DIR_SIZE_MB" ]]; then
            log_warn "enforce_retention: 清理 ${iter} 个文件后目录仍超限 (${dir_size_mb}MB)，可能存在非报告文件"
        else
            log_info "enforce_retention: 目录大小已降至 ${dir_size_mb}MB"
        fi
    fi

    return 0
}

# ============================================================================
# 信号处理与资源清理
# ============================================================================

# cleanup
#   资源清理函数：终止所有子进程（bpftrace、atop、ENA collector），
#   清理临时采样目录，输出退出日志并以零退出码正常退出。
#   通过 kill + wait 确保采样进行中收到信号时等待子进程结束后再退出。
cleanup() {
    log_info "收到终止信号，正在清理..."
    [ -n "$BPFTRACE_PID" ] && kill -SIGINT "$BPFTRACE_PID" 2>/dev/null && wait "$BPFTRACE_PID" 2>/dev/null
    [ -n "$ATOP_PID" ] && kill "$ATOP_PID" 2>/dev/null && wait "$ATOP_PID" 2>/dev/null
    [ -n "$ENA_COLLECTOR_PID" ] && kill "$ENA_COLLECTOR_PID" 2>/dev/null && wait "$ENA_COLLECTOR_PID" 2>/dev/null
    [ -d "$CURRENT_SAMPLING_DIR" ] && rm -rf "$CURRENT_SAMPLING_DIR"
    log_info "清理完成，退出"
    exit 0
}

# setup_signal_handlers
#   注册 SIGINT 和 SIGTERM 信号处理器，收到信号时调用 cleanup() 执行优雅退出。
setup_signal_handlers() {
    trap cleanup SIGINT SIGTERM
    log_info "信号处理器已注册 (SIGINT, SIGTERM)"
}

# ============================================================================
# Monitor 核心组件 — 主监控循环
# ============================================================================

# monitor_loop
#   主监控循环：以 CHECK_INTERVAL 周期轮询所有目标进程 CPU，
#   集成触发决策逻辑，触发时调用 start_sampling()。
#   启动时输出配置参数摘要日志。
#   get_process_cpu() 内部已 sleep CHECK_INTERVAL，循环无需额外 sleep。
monitor_loop() {
    # 启动时输出配置参数摘要 (Req 11.1)
    log_info "===== 监控循环启动 ====="
    log_info "配置摘要:"
    log_info "  Spike_Threshold=${SPIKE_THRESHOLD}%"
    log_info "  Target_Process=${TARGET_PROCS[*]}"
    log_info "  Drop_Threshold=${DROP_THRESHOLD}%"
    log_info "  Max_Sampling_Duration=${MAX_SAMPLING_DURATION}s"
    log_info "  Check_Interval=${CHECK_INTERVAL}s"
    log_info "  Cooldown_Period=${COOLDOWN_PERIOD}s"
    log_info "  Report_Dir=${REPORT_DIR}"

    local loop_count=0
    local maintenance_interval=30  # 每 30 次迭代执行一次归档和 retention 维护
    local cooldown_log_interval=5  # 冷却期日志输出间隔（每 N 次循环输出一次）
    local cooldown_log_counter=0

    while true; do
        loop_count=$(( loop_count + 1 ))

        # 获取所有目标进程中最大归一化 CPU
        local cpu_result
        if ! cpu_result=$(get_max_normalized_cpu 2>/dev/null); then
            log_warn "未找到任何目标进程，等待 ${CHECK_INTERVAL} 秒后重试..."
            sleep "$CHECK_INTERVAL"
            continue
        fi

        local max_cpu proc_name pid raw_cpu
        max_cpu=$(echo "$cpu_result" | awk '{print $1}')
        proc_name=$(echo "$cpu_result" | awk '{print $2}')
        pid=$(echo "$cpu_result" | awk '{print $3}')
        raw_cpu=$(echo "$cpu_result" | awk '{print $4}')

        # 触发决策
        if should_trigger_sampling "$max_cpu"; then
            # 检测到 CPU 尖峰 (Req 11.2)
            log_info "检测到 CPU 尖峰: 时间=$(date '+%Y-%m-%d %H:%M:%S'), 进程=$proc_name (PID=$pid), 归一化CPU=${max_cpu}%, 原始CPU=${raw_cpu}%"

            # 调用采样
            if start_sampling "$proc_name" "$max_cpu" "$pid" "$raw_cpu"; then
                log_info "采样完成"
            else
                log_error "采样过程发生错误 (进程=$proc_name)"
            fi

            # 更新冷却期起始时间 (Req 11.4)
            LAST_SAMPLING_END=$(date +%s)
            log_info "进入冷却期: ${COOLDOWN_PERIOD} 秒"
            cooldown_log_counter=0
        else
            # 检查是否处于冷却期，适度输出冷却状态日志
            local remaining
            if remaining=$(is_in_cooldown 2>/dev/null); then
                cooldown_log_counter=$(( cooldown_log_counter + 1 ))
                if [[ "$cooldown_log_counter" -ge "$cooldown_log_interval" ]]; then
                    log_info "冷却中: 剩余 ${remaining} 秒"
                    cooldown_log_counter=0
                fi
            else
                cooldown_log_counter=0
            fi
        fi

        # 定期执行归档和 retention 维护
        if [[ $(( loop_count % maintenance_interval )) -eq 0 ]]; then
            archive_hot_reports 2>/dev/null || log_warn "归档检查失败"
            enforce_retention 2>/dev/null || log_warn "Retention 策略执行失败"
        fi
    done
}

# ============================================================================
# 主函数 — 完整流程串联
# ============================================================================

main() {
    log_info "eBPF CPU 尖峰监控器启动"
    log_info "配置: Spike_Threshold=${SPIKE_THRESHOLD}%, Check_Interval=${CHECK_INTERVAL}s, Cooldown=${COOLDOWN_PERIOD}s"
    log_info "配置: Drop_Threshold=${DROP_THRESHOLD}%, Max_Sampling_Duration=${MAX_SAMPLING_DURATION}s, Sample_Freq=${SAMPLE_FREQ}Hz"
    log_info "配置: Report_Dir=${REPORT_DIR}"

    # 1. 解析目标进程配置
    parse_target_procs || exit 1

    # 2. 依赖检查与自动安装
    check_and_install_dependencies

    # 3. 基线信息采集（一次性）
    collect_baseline

    # 4. 注册信号处理器
    setup_signal_handlers

    log_info "初始化完成，进入主监控循环"

    # 5. 主监控循环（不返回）
    monitor_loop
}

# ============================================================================
# 入口守卫 — 被 source 时不执行 main
# ============================================================================

if [[ "${SOURCED:-0}" != "1" ]]; then
    main "$@"
fi
