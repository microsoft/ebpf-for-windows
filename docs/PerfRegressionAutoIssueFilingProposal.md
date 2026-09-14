# Performance Regression Auto Issue Filing Proposal

## Overview

This document describes the automated monitoring and issue filing system for performance regressions in the eBPF for Windows project.

## Problem Statement

Performance results are uploaded to PostgreSQL database and regression queries are executed in CI, but there is no:
- Scheduled monitoring workflow that runs independently to catch regressions
- Detection of stale data (no recent perf results uploaded)
- Automated creation/updating of GitHub issues for regressed metrics

This leads to performance regressions potentially going unnoticed between CI runs.

## Solution

### Architecture

The solution consists of a scheduled GitHub Actions workflow that:
1. Queries the performance database for each platform
2. Detects performance regressions using statistical analysis
3. Detects stale data (no recent results)
4. Automatically files or updates GitHub issues

### Components

#### 1. Scheduled Workflow (`.github/workflows/monitor-perf-regressions.yml`)

**Triggers:**
- Schedule: Every 6 hours via cron
- Manual: `workflow_dispatch`

**Platforms Monitored:**
- Windows 2019
- Lab Windows 2022

**Process:**
1. Log into Azure and fetch PostgreSQL credentials from KeyVault
2. For each platform:
   - Check for stale data (last run > 3 days)
   - Run regression query using `check_perf_results.sql`
   - Parse results and upsert GitHub issues

#### 2. Stale Data Detection

For each platform, query:
```sql
SELECT MAX("timestamp") AS last_run
FROM benchmarkresults
WHERE platform = :'platform'
  AND repository = :'repository';
```

If `NOW() - last_run > INTERVAL '3 days'`, create/update a platform-level issue.

#### 3. Regression Detection

Use the existing `check_perf_results.sql` from `microsoft/bpf_performance`:

**Parameters:**
- `platform`: Windows platform name
- `repository`: `microsoft/ebpf-for-windows`
- `look_back`: `30 days`
- `max_sigma`: `3` (configurable, default 2σ can be too sensitive)

**Output CSV columns:**
- `timestamp`: When the regression was detected
- `metric`: Performance metric name
- `value`: Current value
- `mean_value`: Historical mean
- `stddev_value`: Historical standard deviation

#### 4. Issue Management

**Duplicate Prevention:**
Use HTML comment markers embedded in issue body:
```html
<!-- perf-regression: repository=microsoft/ebpf-for-windows platform=<platform> metric=<metric> -->
```

**Issue Upsert Logic:**

For each regressed metric:
1. Search open issues for matching marker
2. If exists: Add comment with latest stats
3. If not exists: Create new issue

**Stale Data Issues:**
- Title: `Perf: no recent results for <platform>`
- Marker: `<!-- perf-stale-data: repository=microsoft/ebpf-for-windows platform=<platform> -->`

**Regression Issues:**
- Title: `Perf regression: <platform>: <metric>`
- Labels: `tests`, optionally `perf-regression`
- Body includes:
  - Dashboard link
  - Statistics table (value, mean, stddev, z-score, percent delta)
  - Marker comment

#### 5. Noise Control

To reduce false positives (see issue #4115):

**Statistical Threshold:**
- Use `max_sigma=3` instead of default `2` for scheduled monitoring
- This reduces false positive rate from ~5% to ~0.3%

**Effect Size Gating (Optional):**
- `abs_percent_delta = 100 * |value - mean| / |mean|`
- Only file/update if `abs_percent_delta >= MIN_PERCENT_DELTA` (e.g., 5%)
- This filters out statistically significant but practically insignificant changes

**Configuration Variables:**
```yaml
env:
  MAX_SIGMA: 3
  MIN_PERCENT_DELTA: 5
  LOOK_BACK_DAYS: 30
  STALE_DATA_THRESHOLD_DAYS: 3
```

## Implementation Details

### Script Structure

The workflow uses a Python script embedded in the workflow to:
1. Parse CSV results from `check_perf_results.sql`
2. Calculate derived metrics (z-score, percent delta)
3. Search for existing issues via GitHub API
4. Create or update issues with appropriate content

### Security

- PostgreSQL credentials stored in Azure KeyVault: `bpfperformacesecrets`
- GitHub token: Uses built-in `GITHUB_TOKEN` with `issues: write` permission
- No secrets exposed in logs or issue content

### Dashboard Links

Issues include links to the performance dashboard:
- Main dashboard: https://microsoft.github.io/ebpf-for-windows/dashboard.html
- Platform-specific views with metric filtering

## Future Enhancements

1. **Require multiple consecutive regressions:** Wait for 2+ consecutive scheduled runs before filing
2. **Auto-close issues:** When metric returns to normal range
3. **Trend analysis:** Include sparkline or trend indicators
4. **Notification routing:** Tag specific teams/owners based on metric category
5. **Additional platforms:** Extend to more OS versions as they are added

## References

- Issue: microsoft/ebpf-for-windows#4115 (noise sensitivity)
- Script: https://github.com/microsoft/bpf_performance/blob/main/scripts/check_perf_results.sql
- Dashboard: https://microsoft.github.io/ebpf-for-windows/dashboard.html
