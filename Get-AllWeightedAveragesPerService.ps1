function Get-AllWeightedAveragesPerService($controlArray) {
    $allSrvcWeightedAverages = @()
    $reliabilityScores = @()
    $securityScores = @()
    $operationalExcellenceScores = @()
    $costOptimizationScores = @()
    $performanceEfficiencyScores = @()
    $customScores = @()

    foreach ($contr in $controlArray) {
        if ($contr.Pillars -contains 'Reliability') {$reliabilityScores += $contr}
        if ($contr.Pillars -contains 'Security') {$securityScores += $contr}
        if ($contr.Pillars -contains 'Operational Excellence') {$operationalExcellenceScores += $contr}
        if ($contr.Pillars -contains 'Cost Optimization') {$costOptimizationScores += $contr}
        if ($contr.Pillars -contains 'Performance Efficiency') {$performanceEfficiencyScores += $contr}
        if ($contr.Pillars -contains 'Custom') {$customScores += $contr}
    }

    $reliabilityWeightedAverage = Get-WeightedAverage($reliabilityScores)
    $securityWeightedAverage = Get-WeightedAverage($securityScores)
    $operationalExcellenceWeightedAverage = Get-WeightedAverage($operationalExcellenceScores)
    $costOptimizationWeightedAverage = Get-WeightedAverage($costOptimizationScores)
    $performanceEfficiencyWeightedAverage = Get-WeightedAverage($performanceEfficiencyScores)
    $customWeightedAverage = Get-WeightedAverage($customScores)

    if ($reliabilityWeightedAverage -notmatch 'NaN') {$allSrvcWeightedAverages += "Reliability Pillar;$reliabilityWeightedAverage"}
    if ($securityWeightedAverage -notmatch 'NaN') {$allSrvcWeightedAverages += "Security Pillar;$securityWeightedAverage"}
    if ($operationalExcellenceWeightedAverage -notmatch 'NaN') {$allSrvcWeightedAverages += "Operational Excellence Pillar;$operationalExcellenceWeightedAverage"}
    if ($costOptimizationWeightedAverage -notmatch 'NaN') {$allSrvcWeightedAverages += "Cost Optimization Pillar;$costOptimizationWeightedAverage"}
    if ($performanceEfficiencyWeightedAverage -notmatch 'NaN') {$allSrvcWeightedAverages += "Performance Efficiency Pillar;$performanceEfficiencyWeightedAverage"}
    if ($customWeightedAverage -notmatch 'NaN') {$allSrvcWeightedAverages += "Custom Checks;$customWeightedAverage"}

    return $allSrvcWeightedAverages
}