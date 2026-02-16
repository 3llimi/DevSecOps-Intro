# Risk Analysis Script for Threagile
param(
    [string]$JsonPath = "labs/lab2/baseline/risks.json",
    [string]$Label = "BASELINE"
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  $Label RISK ANALYSIS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$risks = Get-Content $JsonPath | ConvertFrom-Json
Write-Host "Total Risks Found: $($risks.Count)" -ForegroundColor Yellow

# Define scoring
$severityScores = @{
    'critical' = 5
    'elevated' = 4
    'high' = 3
    'medium' = 2
    'low' = 1
}

$likelihoodScores = @{
    'very-likely' = 4
    'likely' = 3
    'possible' = 2
    'unlikely' = 1
}

$impactScores = @{
    'high' = 3
    'medium' = 2
    'low' = 1
}

# Calculate composite scores with null handling
$scoredRisks = $risks | ForEach-Object {
    $severity = if ($_.severity) { $severityScores[$_.severity] } else { 1 }
    $likelihood = if ($_.likelihood) { $likelihoodScores[$_.likelihood] } else { 2 }
    $impact = if ($_.impact) { $impactScores[$_.impact] } else { 2 }
    
    # Use exploitation fields as fallback
    if (-not $_.likelihood -and $_.exploitation_likelihood) {
        $likelihood = $likelihoodScores[$_.exploitation_likelihood]
    }
    if (-not $_.impact -and $_.exploitation_impact) {
        $impact = $impactScores[$_.exploitation_impact]
    }
    
    $compositeScore = ($severity * 100) + ($likelihood * 10) + $impact
    
    # Clean up title (remove HTML tags)
    $cleanTitle = $_.title -replace '<b>|</b>', ''
    
    [PSCustomObject]@{
        Title = $cleanTitle
        Severity = $_.severity
        Category = $_.category
        Asset = $_.most_relevant_technical_asset
        Likelihood = if ($_.likelihood) { $_.likelihood } else { $_.exploitation_likelihood }
        Impact = if ($_.impact) { $_.impact } else { $_.exploitation_impact }
        CompositeScore = $compositeScore
    }
}

# Sort and get top 5
$topRisks = $scoredRisks | Sort-Object -Property CompositeScore -Descending | Select-Object -First 5

Write-Host "`n=== TOP 5 RISKS BY COMPOSITE SCORE ===" -ForegroundColor Green
$topRisks | Format-Table -AutoSize

Write-Host "`n=== MARKDOWN TABLE (Copy this) ===" -ForegroundColor Green
Write-Host "| Rank | Risk Title | Severity | Category | Asset | Likelihood | Impact | Composite Score |"
Write-Host "|------|-----------|----------|----------|-------|------------|--------|-----------------|"

$rank = 1
foreach ($risk in $topRisks) {
    $title = $risk.Title
    if ($title.Length -gt 60) { $title = $title.Substring(0, 57) + "..." }
    Write-Host "| $rank | $title | $($risk.Severity) | $($risk.Category) | $($risk.Asset) | $($risk.Likelihood) | $($risk.Impact) | $($risk.CompositeScore) |"
    $rank++
}

Write-Host "`n=== CATEGORY SUMMARY ===" -ForegroundColor Green
$risks | Group-Object -Property category | Sort-Object -Property Count -Descending | Format-Table Name, Count -AutoSize

Write-Host "`n=== SEVERITY BREAKDOWN ===" -ForegroundColor Green
$risks | Group-Object -Property severity | Sort-Object -Property Count -Descending | Format-Table Name, Count -AutoSize