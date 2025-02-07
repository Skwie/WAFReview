function Get-WeightedAverage($array) {
    $score = $array | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $weight = $array | ForEach-Object { $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $weightedAverage = [math]::Round(($score / $weight),1)
    return $weightedAverage
}