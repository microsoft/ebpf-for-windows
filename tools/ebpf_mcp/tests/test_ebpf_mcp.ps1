# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT
#
# End-to-end tests for the ebpf_mcp Windows MCP server.
# Tests Windows-specific features: program types, helpers, ELF handling.
# Verifier semantics are tested in the prevail repo (test_mcp.cpp).
#
# Usage: .\tools/ebpf_mcp\tests\test_ebpf_mcp.ps1 [-McpExe x64\Debug\ebpf_mcp.exe]

param(
    [string]$McpExe = "x64\Debug\ebpf_mcp.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $McpExe)) {
    Write-Error "MCP executable not found: $McpExe"
    exit 1
}

# Resolve to absolute path.
$McpExe = (Resolve-Path $McpExe).Path

# ─── Helpers ────────────────────────────────────────────────────────────────────

$script:pass = 0
$script:fail = 0
$script:id_counter = 0

# Run the MCP exe with stdin piped via System.Diagnostics.Process.
function Invoke-Mcp {
    param([string]$InputText)
    $text = $InputText.TrimEnd() + "`n"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $McpExe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.StandardInput.Write($text)
    $proc.StandardInput.Close()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $null = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return $stdout
}

function Invoke-McpBatch {
    param([string[]]$Requests)
    $init = '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}'
    $all = @($init) + $Requests
    $batchInput = $all -join "`n"
    $output = Invoke-Mcp $batchInput
    $responses = @{}
    foreach ($line in ($output -split "`n")) {
        $line = $line.Trim()
        if (-not $line) { continue }
        try {
            $j = $line | ConvertFrom-Json -ErrorAction Stop
            if ($null -ne $j.id) { $responses["$($j.id)"] = $j }
        } catch {}
    }
    return $responses
}

function New-ToolCall {
    param([string]$Tool, [string]$ArgsJson)
    $script:id_counter++
    $id = $script:id_counter
    $req = "{`"jsonrpc`":`"2.0`",`"id`":$id,`"method`":`"tools/call`",`"params`":{`"name`":`"$Tool`",`"arguments`":$ArgsJson}}"
    return @{ id = $id; request = $req }
}

function Get-ToolResult {
    param($Responses, [int]$Id)
    $resp = $Responses["$Id"]
    if (-not $resp) { return $null }
    if ($resp.result.isError) { return @{ error = $resp.result.content[0].text } }
    try {
        return $resp.result.content[0].text | ConvertFrom-Json
    } catch {
        return @{ error = $resp.result.content[0].text }
    }
}

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = "")
    if ($Condition) {
        $script:pass++
    } else {
        $script:fail++
        Write-Host "  FAIL: $Name $(if ($Detail) { "($Detail)" })" -ForegroundColor Red
    }
}

# ─── Test: Server Identity ──────────────────────────────────────────────────────

Write-Host "Server identity..." -NoNewline
$responses = Invoke-McpBatch @()  # Just initialize
$init_resp = $responses["0"]
if ($init_resp) {
    Assert-True "server name" ($init_resp.result.serverInfo.name -eq "ebpf-verifier")
    Assert-True "protocol version" ($init_resp.result.protocolVersion -eq "2024-11-05")
} else {
    Assert-True "server responds" $false "no init response"
}
Write-Host " OK"

# ─── Test: Tool Listing ─────────────────────────────────────────────────────────

Write-Host "Tool listing..." -NoNewline
$script:id_counter++
$list_id = $script:id_counter
$list_req = "{`"jsonrpc`":`"2.0`",`"id`":$list_id,`"method`":`"tools/list`",`"params`":{}}"
$responses = Invoke-McpBatch @($list_req)
$tools = $null
$list_resp = $responses["$list_id"]
if ($list_resp) { $tools = $list_resp.result.tools }
$toolNames = $tools | ForEach-Object { $_.name }
Assert-True "has verify_program" ($toolNames -contains "verify_program")
Assert-True "has verify_assembly" ($toolNames -contains "verify_assembly")
Assert-True "has get_slice" ($toolNames -contains "get_slice")
Assert-True "has 11 tools" ($tools.Count -ge 11)
Write-Host " OK"

# ─── Test: Verify ELF Programs ──────────────────────────────────────────────────

Write-Host "ELF verification..." -NoNewline
$samples = @(
    @{ file = "x64\Debug\tail_call.o"; expect_pass = $true },
    @{ file = "x64\Debug\divide_by_zero.o"; expect_pass = $true }
)
$requests = @()
$ids = @{}
foreach ($s in $samples) {
    if (-not (Test-Path $s.file)) { continue }
    $absPath = (Resolve-Path $s.file).Path -replace '\\', '\\\\'
    $call = New-ToolCall "verify_program" "{`"elf_path`":`"$absPath`"}"
    $requests += $call.request
    $ids[$call.id] = $s
}
if ($requests.Count -gt 0) {
    $responses = Invoke-McpBatch $requests
    foreach ($id in $ids.Keys) {
        $s = $ids[$id]
        $result = Get-ToolResult $responses $id
        $name = Split-Path $s.file -Leaf
        if ($result -and -not $result.error) {
            Assert-True "$name passed=$($s.expect_pass)" ($result.passed -eq $s.expect_pass)
            Assert-True "$name has section" ($null -ne $result.section -and $result.section -ne "")
            Assert-True "$name has function" ($null -ne $result.function -and $result.function -ne "")
        } else {
            Assert-True "$name responded" $false "no result or error"
        }
    }
}
Write-Host " OK"

# ─── Test: Windows Program Types ─────────────────────────────────────────────────

Write-Host "Windows program types..." -NoNewline
$type_tests = @(
    @{ file = "x64\Debug\tail_call.o"; expect_section = "sample_ext" },
    @{ file = "x64\Debug\divide_by_zero.o"; expect_section = "sample_ext" }
)
$requests = @()
$ids = @{}
foreach ($t in $type_tests) {
    if (-not (Test-Path $t.file)) { continue }
    $absPath = (Resolve-Path $t.file).Path -replace '\\', '\\\\'
    $call = New-ToolCall "list_programs" "{`"elf_path`":`"$absPath`"}"
    $requests += $call.request
    $ids[$call.id] = $t
}
if ($requests.Count -gt 0) {
    $responses = Invoke-McpBatch $requests
    foreach ($id in $ids.Keys) {
        $t = $ids[$id]
        $result = Get-ToolResult $responses $id
        $name = Split-Path $t.file -Leaf
        if ($result -and $result.programs) {
            $sections = $result.programs | ForEach-Object { $_.section }
            Assert-True "$name has $($t.expect_section)" ($sections -contains $t.expect_section)
        } else {
            Assert-True "$name list_programs" $false "no result"
        }
    }
}
Write-Host " OK"

# ─── Test: verify_assembly with Windows Helpers ─────────────────────────────────

Write-Host "Assembly with Windows helpers..." -NoNewline
$asm_tests = @(
    @{
        name = "simple pass"
        args = '{"code":"r0 = 0\nexit"}'
        expect_pass = $true
    },
    @{
        name = "map_lookup (helper 1)"
        args = '{"code":"r2 = r10\nr2 += -4\nr3 = 0\n*(u32 *)(r10 - 4) = r3\ncall 1\nr0 = 0\nexit","pre":["r1.type=map_fd","r1.map_fd=1","r10.type=stack","r10.stack_offset=512"]}'
        expect_pass = $true
    },
    @{
        name = "bind program type"
        args = '{"code":"r0 = 0\nexit","program_type":"bind"}'
        expect_pass = $true
    },
    @{
        name = "sockops program type"
        args = '{"code":"r0 = 0\nexit","program_type":"sockops"}'
        expect_pass = $true
    }
)
$requests = @()
$ids = @{}
foreach ($t in $asm_tests) {
    $call = New-ToolCall "verify_assembly" $t.args
    $requests += $call.request
    $ids[$call.id] = $t
}
$responses = Invoke-McpBatch $requests
foreach ($id in $ids.Keys) {
    $t = $ids[$id]
    $result = Get-ToolResult $responses $id
    if ($result -and -not $result.error) {
        Assert-True $t.name ($result.passed -eq $t.expect_pass)
    } else {
        $detail = if ($result.error) { $result.error.Substring(0, [Math]::Min(60, $result.error.Length)) } else { "no response" }
        Assert-True $t.name $false $detail
    }
}
Write-Host " OK"

# ─── Test: Source Mapping with BTF ──────────────────────────────────────────────

Write-Host "Source mapping (BTF)..." -NoNewline
$btf_file = "x64\Debug\tail_call.o"
if (Test-Path $btf_file) {
    $absPath = (Resolve-Path $btf_file).Path -replace '\\', '\\\\'
    $call = New-ToolCall "get_source_mapping" "{`"elf_path`":`"$absPath`"}"
    $responses = Invoke-McpBatch @($call.request)
    $result = Get-ToolResult $responses $call.id
    if ($result -and $result.entries) {
        Assert-True "has BTF entries" ($result.entries.Count -gt 0)
        if ($result.entries.Count -gt 0) {
            Assert-True "entry has source.file" ($null -ne $result.entries[0].source.file)
            Assert-True "entry has source.line" ($null -ne $result.entries[0].source.line)
        }
    } else {
        Assert-True "source mapping" $false "no entries"
    }
} else {
    Write-Host " SKIP (no tail_call.o)" -ForegroundColor Yellow
}
Write-Host " OK"

# ─── Test: Failure Slicing ──────────────────────────────────────────────────────

Write-Host "Failure slicing..." -NoNewline
# Find a failing program to slice
$fail_files = @(
    "tests\verifier_diagnosis\build\nullmapref.o",
    "tests\verifier_diagnosis\build\badmapptr.o"
)
$fail_file = $fail_files | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($fail_file) {
    $absPath = (Resolve-Path $fail_file).Path -replace '\\', '\\\\'
    $requests = @()
    $verify_call = New-ToolCall "verify_program" "{`"elf_path`":`"$absPath`"}"
    $slice_call = New-ToolCall "get_slice" "{`"elf_path`":`"$absPath`"}"
    $requests += $verify_call.request
    $requests += $slice_call.request
    $responses = Invoke-McpBatch $requests
    $verify_result = Get-ToolResult $responses $verify_call.id
    $slice_result = Get-ToolResult $responses $slice_call.id
    if ($verify_result -and -not $verify_result.passed) {
        Assert-True "program fails" $true
        if ($slice_result) {
            Assert-True "slice has pc" ($null -ne $slice_result.pc)
            Assert-True "slice has error" ($null -ne $slice_result.error)
            Assert-True "slice has failure_slice" ($null -ne $slice_result.failure_slice)
        } else {
            Assert-True "get_slice responded" $false
        }
    } else {
        Write-Host " SKIP (no failing program found)" -ForegroundColor Yellow
    }
} else {
    Write-Host " SKIP (no failing .o files)" -ForegroundColor Yellow
}
Write-Host " OK"

# ─── Test: Error Handling ───────────────────────────────────────────────────────

Write-Host "Error handling..." -NoNewline
$err_tests = @(
    @{ name = "nonexistent file"; tool = "verify_program"; args = '{"elf_path":"C:\\\\nonexistent\\\\file.o"}' },
    @{ name = "empty assembly"; tool = "verify_assembly"; args = '{"code":""}' },
    @{ name = "invalid instruction"; tool = "verify_assembly"; args = '{"code":"not_valid"}' }
)
$requests = @()
$ids = @{}
foreach ($t in $err_tests) {
    $call = New-ToolCall $t.tool $t.args
    $requests += $call.request
    $ids[$call.id] = $t
}
$responses = Invoke-McpBatch $requests
foreach ($id in $ids.Keys) {
    $t = $ids[$id]
    $resp = $responses["$id"]
    $isError = $false
    if ($resp -and $resp.result) {
        $isError = $resp.result.isError -eq $true -or
            ($resp.result.content -and $resp.result.content[0].text -match "^Error:")
    }
    Assert-True $t.name $isError
}
Write-Host " OK"

# ─── Summary ────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Results: $($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail -gt 0) { "Red" } else { "Green" })
if ($script:fail -gt 0) { exit 1 }
