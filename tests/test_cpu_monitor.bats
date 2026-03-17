#!/opt/homebrew/bin/bats
#
# test_cpu_monitor.bats - Unit tests for CPU usage and normalization functions
#
# Tests: get_process_cpu(), get_normalized_cpu(), get_max_normalized_cpu(),
#        _get_num_cpus(), _bc() wrapper
#

load test_helper

# ============================================================================
# _get_num_cpus tests
# ============================================================================

@test "_get_num_cpus returns positive integer" {
    NUM_CPUS=""
    local result
    result=$(_get_num_cpus)
    [[ "$result" =~ ^[0-9]+$ ]]
    [[ "$result" -ge 1 ]]
}

@test "_get_num_cpus caches value across calls" {
    NUM_CPUS=""
    local result1 result2
    result1=$(_get_num_cpus)
    result2=$(_get_num_cpus)
    [[ "$result1" == "$result2" ]]
}

@test "_get_num_cpus returns cached value when NUM_CPUS is preset" {
    NUM_CPUS="8"
    local result
    result=$(_get_num_cpus)
    [[ "$result" == "8" ]]
}

# ============================================================================
# get_process_cpu tests
# ============================================================================

@test "get_process_cpu returns 1 for nonexistent PID" {
    run get_process_cpu 999999999
    [[ "$status" -eq 1 ]]
}

@test "get_process_cpu returns 1 for empty PID" {
    run get_process_cpu ""
    [[ "$status" -eq 1 ]]
}

@test "get_process_cpu returns valid CPU percentage for current shell PID" {
    # Only runs on Linux (requires /proc filesystem)
    if [[ ! -d /proc/self ]]; then
        skip "Requires /proc filesystem (Linux only)"
    fi

    # Use short interval to speed up test
    local orig_interval="$CHECK_INTERVAL"
    CHECK_INTERVAL=1

    local result
    result=$(get_process_cpu $$)
    local rc=$?
    CHECK_INTERVAL="$orig_interval"

    [[ "$rc" -eq 0 ]]
    # Result should be a number (possibly with decimal point)
    [[ "$result" =~ ^-?[0-9]+\.?[0-9]*$ ]]
}

# ============================================================================
# get_normalized_cpu tests
# ============================================================================

@test "get_normalized_cpu returns 1 for nonexistent process" {
    run get_normalized_cpu "nonexistent_process_xyz_12345" 4
    [[ "$status" -eq 1 ]]
}

# ============================================================================
# get_max_normalized_cpu tests
# ============================================================================

@test "get_max_normalized_cpu returns 1 when all processes in PROC_VCPU_MAP are missing" {
    # Re-declare with nonexistent processes (declare -A resets the array)
    declare -gA PROC_VCPU_MAP=(
        ["nonexistent_proc_aaa"]=1
        ["nonexistent_proc_bbb"]=4
    )

    run get_max_normalized_cpu
    [[ "$status" -eq 1 ]]
}

@test "get_max_normalized_cpu returns 1 for empty PROC_VCPU_MAP" {
    declare -gA PROC_VCPU_MAP=()

    run get_max_normalized_cpu
    [[ "$status" -eq 1 ]]
}

# ============================================================================
# _bc wrapper tests (float arithmetic)
# ============================================================================

@test "_bc basic division" {
    local result
    result=$(echo "scale=1; 360 / 4" | _bc -l)
    [[ "$result" == "90.0" ]]
}

@test "_bc normalization example: predixy 360 pct / 4 vCPU = 90.0" {
    local raw_cpu=360
    local vcpu=4
    local result
    result=$(echo "scale=1; $raw_cpu / $vcpu" | _bc -l)
    [[ "$result" == "90.0" ]]
}

@test "_bc normalization example: valkey 95 pct / 1 vCPU = 95.0" {
    local raw_cpu=95
    local vcpu=1
    local result
    result=$(echo "scale=1; $raw_cpu / $vcpu" | _bc -l)
    [[ "$result" == "95.0" ]]
}

@test "_bc comparison: greater than" {
    local result
    result=$(echo "95.2 > 90" | _bc -l)
    [[ "$result" -eq 1 ]]
}

@test "_bc comparison: less than" {
    local result
    result=$(echo "45.0 > 90" | _bc -l)
    [[ "$result" -eq 0 ]]
}
