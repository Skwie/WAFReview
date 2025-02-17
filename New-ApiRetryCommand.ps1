function New-ApiRetryCommand
{
    param (
        [Parameter(Mandatory=$true)][string]$uri, 
        [Parameter(Mandatory=$true)][hashtable]$headers
    )
    
    $maxRetries = 5
    $delay = 2

    $retryCount = 0
    $done = $false

    while (-not $done -and $retryCount -le $maxRetries) {
        try {
            Invoke-WebRequest -Uri $uri -Headers $headers -Method Get
            $done = $true
        } 
        catch {
            if ($Error[0].Exception.Message -like "*not found*" -or $Error[0].Exception.Message -like "*notfound*") {
                Write-Error ("API call failed because the resource was not found.") -ErrorAction Continue
                Break
            }
            if ($retryCount -ge $maxRetries) {
                Write-Error ("API call failed the maximum number of $($maxRetries) times.") -ErrorAction Continue
                Break
            } else {
                Write-Verbose ("API call did not complete successfully. Retrying in $($delay) seconds.")
                Start-Sleep $delay
                $retryCount++
            }
        }
    }
}