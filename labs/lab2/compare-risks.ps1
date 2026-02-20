Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  BASELINE vs SECURE COMPARISON" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$baselineRisks = Get-Content labs/lab2/baseline/risks.json | ConvertFrom-Json
$secureRisks = Get-Content labs/lab2/secure/risks.json | ConvertFrom-Json

$baselineGroups = $baselineRisks | Group-Object -Property category
$secureGroups = $secureRisks | Group-Object -Property category

$allCategories = ($baselineGroups.Name + $secureGroups.Name) | Select-Object -Unique | Sort-Object

$comparison = @()
foreach ($cat in $allCategories) {
    $baselineCount = ($baselineGroups | Where-Object { $_.Name -eq $cat }).Count
    $secureCount = ($secureGroups | Where-Object { $_.Name -eq $cat }).Count
    
    if ($null -eq $baselineCount) { $baselineCount = 0 }
    if ($null -eq $secureCount) { $secureCount = 0 }
    
    $delta = $secureCount - $baselineCount
    
    $comparison += [PSCustomObject]@{
        Category = $cat
        Baseline = $baselineCount
        Secure = $secureCount
        Delta = $delta
    }
}

Write-Host "=== RISK CATEGORY COMPARISON ===" -ForegroundColor Green
$comparison | Format-Table -AutoSize

$totalBaseline = ($baselineRisks | Measure-Object).Count
$totalSecure = ($secureRisks | Measure-Object).Count
$totalDelta = $totalSecure - $totalBaseline
$percentChange = if ($totalBaseline -gt 0) { [math]::Round(($totalDelta / $totalBaseline) * 100, 1) } else { 0 }

Write-Host "`n=== SUMMARY ===" -ForegroundColor Yellow
Write-Host "Total Baseline: $totalBaseline"
Write-Host "Total Secure: $totalSecure"
Write-Host "Delta: $totalDelta ($percentChange percent)"

if ($totalDelta -lt 0) {
    $absChange = [math]::Abs($percentChange)
    Write-Host "SUCCESS: Security controls reduced risks by $([math]::Abs($totalDelta)) ($absChange percent)" -ForegroundColor Green
} elseif ($totalDelta -gt 0) {
    Write-Host "WARNING: Risk count increased by $totalDelta" -ForegroundColor Yellow
} else {
    Write-Host "No change in total risk count" -ForegroundColor Gray
}

Write-Host "`n=== MARKDOWN TABLE FOR SUBMISSION ===" -ForegroundColor Green
Write-Host "| Category | Baseline | Secure | Delta |"
Write-Host "|----------|----------|--------|-------|"
foreach ($row in $comparison) {
    Write-Host "| $($row.Category) | $($row.Baseline) | $($row.Secure) | $($row.Delta) |"
}

Write-Host ""
Write-Host "**Total:** Baseline: $totalBaseline | Secure: $totalSecure | Delta: $totalDelta ($percentChange percent)"