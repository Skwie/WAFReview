function New-RetryCommand
{
    param (
        [Parameter(Mandatory=$true)][string]$command, 
        [Parameter(Mandatory=$true)][hashtable]$args
    )
    
    $args.ErrorAction = "Stop"
    $maxRetries = 5
    $delay = 2

    $retryCount = 0
    $done = $false
    $scriptBlock = [ScriptBlock]::Create($command)

    while (-not $done -and $retryCount -le $maxRetries) {
        try {
            & $scriptBlock @args
            $done = $true
        } 
        catch {
            if ($retryCount -ge $maxRetries) {
                Write-Error ("Command $($command) failed the maximum number of $($maxRetries) times.") -ErrorAction Continue
                Break
            } else {
                Write-Verbose ("Command $($command) did not complete successfully. Retrying in $($delay) seconds.")
                Start-Sleep $delay
                $retryCount++
            }
        }
    }
}