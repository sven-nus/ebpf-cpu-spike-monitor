#!/usr/bin/env bash
#
# test_helper.bash — bats-core 测试辅助函数和随机输入生成器
#
# 本文件为 eBPF CPU 尖峰监控器的属性测试提供：
#   1. 主脚本函数的 source 逻辑（通过 SOURCED=1 守卫避免执行 main）
#   2. 随机输入生成器（用于属性测试的随机化输入）
#   3. 通用测试辅助函数
#
# 注意：主脚本使用 declare -A（关联数组），需要 Bash 4+。
#       macOS 默认 Bash 3.2 不支持。测试必须在以下环境运行：
#         - Rocky Linux 9（Bash 5.x）— 目标平台
#         - macOS + Homebrew Bash 4+（/opt/homebrew/bin/bash 或 /usr/local/bin/bash）
#       运行方式示例：
#         bats tests/
#         /opt/homebrew/bin/bash -c 'bats tests/'
#

# ============================================================================
# 属性测试迭代次数（可通过环境变量覆盖）
# ============================================================================

PBT_ITERATIONS="${PBT_ITERATIONS:-100}"

# ============================================================================
# 主脚本 source 逻辑
# ============================================================================

# 项目根目录（tests/ 的上一级）
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 主脚本路径
MAIN_SCRIPT="${PROJECT_ROOT}/ebpf-cpu-spike-monitor.sh"

# source 主脚本（设置 SOURCED=1 防止执行 main 函数）
_source_main_script() {
    if [[ ! -f "$MAIN_SCRIPT" ]]; then
        echo "ERROR: 主脚本不存在: $MAIN_SCRIPT" >&2
        return 1
    fi
    export SOURCED=1
    # shellcheck source=../ebpf-cpu-spike-monitor.sh
    source "$MAIN_SCRIPT"
}

# ============================================================================
# bats setup — 每个测试用例执行前自动调用
# ============================================================================

setup() {
    _source_main_script
}

# ============================================================================
# 随机数生成器 — 用于属性测试的随机化输入
# ============================================================================

# random_int MIN MAX
#   生成 [MIN, MAX] 范围内的随机整数
#   使用 $RANDOM（Bash 内置，0-32767）进行模运算
random_int() {
    local min="$1"
    local max="$2"
    local range=$(( max - min + 1 ))
    echo $(( (RANDOM % range) + min ))
}

# random_float MIN MAX DECIMALS
#   生成 [MIN, MAX] 范围内的随机浮点数，保留 DECIMALS 位小数
#   通过整数运算模拟浮点：先生成放大后的整数，再插入小数点
random_float() {
    local min="$1"
    local max="$2"
    local decimals="${3:-1}"

    # 计算放大因子 (10^decimals)
    local factor=1
    local i
    for (( i = 0; i < decimals; i++ )); do
        factor=$(( factor * 10 ))
    done

    # 将 min/max 转为整数（去掉小数点）
    # 支持输入为整数或浮点
    local min_int max_int
    min_int=$(printf "%.0f" "$(echo "$min * $factor" | bc -l 2>/dev/null || echo "$min")")
    max_int=$(printf "%.0f" "$(echo "$max * $factor" | bc -l 2>/dev/null || echo "$max")")

    local range=$(( max_int - min_int + 1 ))
    if (( range <= 0 )); then
        range=1
    fi

    local rand_int=$(( (RANDOM % range) + min_int ))

    # 将整数转回浮点字符串
    local int_part=$(( rand_int / factor ))
    local dec_part=$(( rand_int % factor ))

    # 补零到指定小数位数
    printf "%d.%0${decimals}d\n" "$int_part" "$dec_part"
}

# random_string LENGTH
#   生成指定长度的随机字母数字字符串
#   使用 /dev/urandom 作为随机源
random_string() {
    local length="${1:-8}"
    # 从 /dev/urandom 读取随机字节，过滤为字母数字，截取指定长度
    LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
    echo
}

# random_proc_list MIN_COUNT MAX_COUNT
#   生成随机的 "procname:vcpu" 条目列表（每行一个）
#   进程名为 4-12 字符的随机字符串，vCPU 为 1-16 的随机整数
random_proc_list() {
    local min_count="${1:-1}"
    local max_count="${2:-5}"
    local count
    count=$(random_int "$min_count" "$max_count")

    local i
    for (( i = 0; i < count; i++ )); do
        local name_len
        name_len=$(random_int 4 12)
        local proc_name
        proc_name=$(random_string "$name_len")
        local vcpu
        vcpu=$(random_int 1 16)
        echo "${proc_name}:${vcpu}"
    done
}

# random_cpu_value
#   生成随机 CPU 百分比值（0.0 到 1600.0，1 位小数）
#   覆盖单线程（0-100%）和多线程（100-1600%）场景
random_cpu_value() {
    random_float 0 1600 1
}

# random_vcpu_count
#   生成随机 vCPU 数量（1 到 64）
random_vcpu_count() {
    random_int 1 64
}
