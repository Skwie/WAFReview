<#
.SYNOPSIS
  Performs an Azure Well-Architected Framework assessment for one or more subscriptions.

.DESCRIPTION
  This script makes an inventory of specific or all fscp 3.0 subscriptions, and runs AZ CLI commands against those subscriptions to determine if resources in those subscriptions are in line with the Microsoft Azure Well-Architected Framework.

.PARAMETER <SubscriptionIds>
  Optional. An array of IDs for the subscriptions that you want to assess. If no SubscriptionId is entered, the script runs for all subscriptions.
  Example: @('b6307584-2248-4e8b-a911-2d7f1bd2613a', 'c405e642-15db-4786-9426-1e23c84d225a')

.PARAMETER <Filter>
  Optional. If a string is entered here, the script will only evaluate subscriptions where the name matches the given string. Note that this param is not evaluated if the SubscriptionIds param is filled.

.PARAMETER <OutputToFile>
  Optional. If OutputToFile is true, the script will output the results to a file in the results folder.
  If the script runs for many subscriptions at once, it is recommended to set this to true, as the output will be too large to read in the terminal.
    
.OUTPUTS
  The script progressively writes results to the terminal. After performing all checks it should also output a file per subscription listing all controls and scores.
  Possible ToDo is to make the file output compatible with the Microsoft powerpoint generation script.

.NOTES
  Version:        0.8.2
  Author:         Jordy Groenewoud
  Creation Date:  27/03/2024
  Last Updated:   15/07/2024
  
.EXAMPLE
  .\WAFAzCli.ps1 -Filter "-p-lz" -OutputToFile $False
  .\WAFAzCli.ps1 -SubscriptionIds @('b6307584-2248-4e8b-a911-2d7f1bd2613a', 'c405e642-15db-4786-9426-1e23c84d225a') -OutputToFile $True

#>


[CmdletBinding()]
param
(
    [Parameter(Mandatory=$false)]
    [Array]$SubscriptionIds,

    [Parameter(Mandatory=$false)]
    $Filter,

    [Parameter(Mandatory=$false)]
    $OutputToFile = $true
)

################# Region Functions #################

function Get-TotalWeights($array) {
    $totalWeight = 0
    foreach ($control in $array) {
        $totalWeight += $control.Weight
    }
    return $totalWeight
}

function Get-WeightedAverage($array) {
    $score = $array | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $weight = $array | ForEach-Object { $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $weightedAverage = [math]::Round(($score / $weight),1)
    return $weightedAverage
}

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

# End region

################# Region Setup #####################

if (!$azsession) {
    try {
        $azsession = az login
    }
    catch {
        Write-Output "Unable to login to Az CLI. Make sure the Az module is installed."
        throw
    }
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    $threadJobInstalled = Get-InstalledModule -Name Threadjob -ErrorAction SilentlyContinue
    if (!$threadJobInstalled) {
        Write-Output "ThreadJob module not found. Please install the ThreadJob module to run this script."
        throw
    }
}

if (!$SubscriptionIds) {
    # Only retrieve FSCP 3.0 subscriptions
    if ($ProdOnly) {
        $AllSubscriptions = $azsession | ConvertFrom-Json -Depth 10 | Select-Object name, id | Where-Object {$_.name -Match $Filter}
    }
    else {
        $AllSubscriptions = $azsession | ConvertFrom-Json -Depth 10 | Select-Object name, id
    }
}
else {
    $AllSubscriptions = @()
    foreach ($subId in $SubscriptionIds) {
        $AllSubscriptions += $azsession | ConvertFrom-Json -Depth 10 | Select-Object name, id | Where-Object {$_.id -Match $subId}
    }
}

# End region

foreach ($sub in $AllSubscriptions) {
    az account set --subscription $sub.id

    $DefenderActive = $false

    Write-Output "Running WAF assessment for subscription $($sub.name)."
    Write-Output "This may take a while, depending on the number of resources in the subscription."
    Write-Output ""

    $WAFResults = @()
    $lateReport = @()
    $WAFResults += ""
    $WAFResults += "#################################################################################"
    $WAFResults += "WAF Assessment results for subscription $($sub.name)"
    $WAFResults += "#################################################################################"
    $WAFResults += ""

    ############## Region Storage Accounts ##################
    
    Write-Output "Checking Storage Accounts for subscription $($sub.name)..."

    $StorageAccounts = az storage account list 2> $null | ConvertFrom-Json -Depth 10
    if (!$?) {
        Write-Error "Unable to retrieve storage accounts for subscription $($sub.name)." -ErrorAction Continue
    }

    # Define the checks to be done as well as their related pillars and weight
    $StorageControls = @(
        "Turn on Soft Delete for Blob Data;Reliability,Security,Operational Excellence;70"
        "Use Microsoft Entra ID to authorize access to blob data;Reliability,Security,Operational Excellence;70"
        "Use blob versioning or immutable blobs to store business-critical data;Reliability,Security,Operational Excellence;75"
        "Restrict default internet access for storage accounts;Reliability,Security,Operational Excellence;75"
        "Enable firewall rules;Reliability,Security,Operational Excellence;75"
        "Limit network access to specific networks;Reliability,Security,Operational Excellence;75"
        "Allow trusted Microsoft services to access the storage account;Reliability,Security,Operational Excellence;90"
        "Enable the Secure transfer required option on all your storage accounts;Reliability,Security,Operational Excellence;90"
        "Avoid and prevent using Shared Key authorization to access storage accounts;Reliability,Security,Operational Excellence;80"
        "Regenerate your account keys periodically;Reliability,Security,Operational Excellence;60"
        "Enable Azure Defender for all your storage accounts;Security,Operational Excellence;80"
        "Organize data into access tiers;Cost Optimization;60"
        "Use lifecycle policy to move data between access tiers;Cost Optimization;60"
        "Configure Minimum TLS Version;Custom;95"
        "Enable Infrastructure Encryption;Custom;85"
        "Private Endpoint in Use;Custom;75"
        "Storage Account Encryption using Customer Managed Keys;Custom;50"
    )

    $StorageResults = @()
    $StorageResults += "###########################################"
    $StorageResults += "WAF Assessment Results for Storage Accounts"
    $StorageResults += "###########################################"

    $storageTotalAvg = 0
    $storageTotalScore = 0

    # Do a subscription-level query so it's not repeated for all storage accounts
    $DefenderStatus = az security pricing show --name StorageAccounts | ConvertFrom-Json -Depth 10
    if ($DefenderStatus.pricingTier -match 'Standard') {
        $DefenderActive = $true
    }

    $storageJobs = @()

    foreach ($strg in $StorageAccounts) {

        Write-Output "Checking Storage Account $($strg.name)..."

        $storageJobs += Start-Threadjob -ScriptBlock {

            $strg = $using:strg

            $strgControlArray = @()

            foreach ($control in $using:StorageControls) {
                $strgCheck = $control.Split(';')
                $strgCheckName = $strgCheck[0]
                $strgCheckPillars = $strgCheck[1].Split(',')
                $strgCheckWeight = $strgCheck[2]
        
                $strgControlArray += [PSCustomObject]@{
                    Name = $strgCheckName
                    Pillars = $strgCheckPillars
                    Weight = $strgCheckWeight
                    Result = $null
                }
            }

            # Calculate total weight to calculate weighted average
            $strgTotalWeight = 0
            foreach ($control in $strgControlArray) {
                $strgTotalWeight += $control.Weight
            }

            $tempStorageResults = @()
            $tempStorageResults += ""
            $tempStorageResults += "----- Storage Account - $($strg.name) -----"
            $tempStorageResults += ""
            
            # Turn on soft delete for blob data
            $BlobProperties = az storage account blob-service-properties show --account-name $strg.name 2> $null 
            if ($?) {
                $RetentionPolicy = $BlobProperties | ConvertFrom-Json -Depth 10 | Select-Object deleteRetentionPolicy
            }
            else {
                Write-Error "Unable to check blob data retention settings for storage account $($strg.name)."
            }
            
            if ($RetentionPolicy.deleteRetentionPolicy.enabled) {
                $tempStorageResults += "Good: Soft Delete is active for $($strg.name)"
                $strgControlArray[0].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Soft Delete is NOT active for $($strg.name)"
                $strgControlArray[0].Result = 0
            }
            $RetentionPolicy = $null

            # Use Microsoft Entra ID to authorize access to blob data
            if ($strg.allowBlobPublicAccess -match 'False') {
                $tempStorageResults += "Good: Public access is disabled for blob data on storage account $($strg.name)."
                $strgControlArray[1].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Public access is ENABLED for blob data on storage account $($strg.name)."
                $strgControlArray[1].Result = 0
            }

            # Use blob versioning or immutable blobs to store business-critical data.
            ## Unable to query immutability due to this information being stored on container level, requiring a connection string, storage account key or SAS token.
            if (($BlobProperties | ConvertFrom-Json -Depth 10).isVersioningEnabled) {
                $tempStorageResults += "Good: Versioning is enabled for storage account $($strg.name)."
                $strgControlArray[2].Result = 100
            }
            else {
                $tempStorageResults += "Informational: Versioning is not enabled for storage account $($strg.name). Immutability might be enabled on container level, but can not be checked."
                $strgControlArray[2].Result = 50
            }
            #az storage container list --account-name $strg.name --query '[*].{"ContainerName":name, "TimeBasedRetentionPolicy":properties.hasImmutabilityPolicy, "LegalHoldPolicy": properties.hasLegalHold}'

            # Restrict default internet access for storage accounts.
            if ($strg.networkRuleSet.defaultAction -match 'Deny') {
                $tempStorageResults += "Good: Default internet access for storage account $($strg.name) is set to Deny."
                $strgControlArray[3].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Default internet access for storage account $($strg.name) is NOT set to Deny."
                $strgControlArray[3].Result = 0
            }

            # Enable firewall rules.
            if ($strg.networkRuleSet) {
                $tempStorageResults += "Good: Firewall is active for storage account $($strg.name)."
                $strgControlArray[4].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Firewall is NOT active for storage account $($strg.name)."
                $strgControlArray[4].Result = 0
            }

            # Limit network access to specific networks.
            if ($strg.allowBlobPublicAccess -match 'False') {
                $tempStorageResults += "Good: Blob Public Access is disabled for storage account $($strg.name)."
                $strgControlArray[5].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Blob Public Access is NOT disabled for storage account $($strg.name)."
                $strgControlArray[5].Result = 0
            }

            # Allow trusted Microsoft services to access the storage account.
            if ($strg.networkRuleSet.bypass -match 'AzureServices') {
                $tempStorageResults += "Good: Microsoft Azure Services are whitelisted for storage account $($strg.name)."
                $strgControlArray[6].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Microsoft Azure Services are NOT whitelisted for storage account $($strg.name)."
                $strgControlArray[6].Result = 0
            }

            # Enable the Secure transfer required option on all your storage accounts.
            if ($strg.enableHttpsTrafficOnly -match 'True') {
                $tempStorageResults += "Good: Secure Transfer (HTTPS) is enforced for storage account $($strg.name)."
                $strgControlArray[7].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Secure Transfer (HTTPS) is NOT enforced for storage account $($strg.name)."
                $strgControlArray[7].Result = 0
            }

            # Avoid and prevent using Shared Key authorization to access storage accounts.
            if ($strg.allowSharedKeyAccess -match 'False') {
                $tempStorageResults += "Good: Shared Key authorization is disabled for storage account $($strg.name)."
                $strgControlArray[8].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Shared Key authorization is NOT disabled for storage account $($strg.name)."
                $strgControlArray[8].Result = 0
            }
            
            # Regenerate your account keys periodically.
            $RegenerationLogs = az monitor activity-log list --resource-group $strg.resourceGroup --status Succeeded --offset 90d --query '[*].{authorization:authorization.action,eventTimestamp:eventTimestamp}' | ConvertFrom-Json -Depth 10
            $Regenerated = $false
            foreach ($RegenLog in $RegenerationLogs) {
                if ($RegenLog -match 'Microsoft.Storage/storageAccounts/regenerateKey/action') {
                    if ($RegenLog.eventTimestamp -gt (Get-Date).AddDays(-90)) {
                        $Regenerated = $true
                    }
                }
            }
            if ($Regenerated) {
                $tempStorageResults += "Good: Storage account keys have been regenerated in the past 90 days for storage account $($strg.name)."
                $strgControlArray[9].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Storage account keys have NOT been regenerated in the past 90 days for storage account $($strg.name)."
                $strgControlArray[9].Result = 0
            }

            # Enable Azure Defender for all your storage accounts.
            if ($using:DefenderActive) {
                $tempStorageResults += "Good: Defender for Storage is enabled for storage account $($strg.name)."
                $strgControlArray[10].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Defender for Storage is NOT enabled for storage account $($strg.name)."
                $strgControlArray[10].Result = 0
            }

            # Consider cost savings by reserving data capacity for block blob storage.
            ## This requires access to the container where the blob is stored, requiring a connection string, storage account key or SAS token.

            # Organize data into access tiers.
            if ($strg.accessTier -match 'Hot') {
                $tempStorageResults += "Informational: Storage account $($strg.name) has an access tier of 'Hot'. Depending on usage demand, costs could be reduced by choosing a lower tier."
                $strgControlArray[11].Result = 100
            }
            else {
                $tempStorageResults += "Informational: Storage account $($strg.name) has an access tier of '$($strg.accessTier)'."
                $strgControlArray[11].Result = 100
            }
            
            # Use lifecycle policy to move data between access tiers.
            $policy = az storage account management-policy show --account-name $strg.name --resource-group $strg.resourceGroup 2> $null | ConvertFrom-Json -Depth 10
            if (($BlobProperties | ConvertFrom-Json -Depth 10).lastAccessTimeTrackingPolicy) {
                $tempStorageResults += "Good: Last access time tracking Lifecycle policy found for storage account $($strg.name)."
                $strgControlArray[12].Result = 100
            }
            elseif ($policy) {
                if ($policy.policy.rules.type -match 'Lifecycle') {
                    $tempStorageResults += "Good: Data deletion Lifecycle policy found for storage account $($strg.name)."
                    $strgControlArray[12].Result = 100
                }
            }
            else {
                $tempStorageResults += "Bad: No Lifecycle policy found for storage account $($strg.name)."
                $strgControlArray[12].Result = 0
            }
            $policy = $null

            # Check for Publicly Accessible Web Containers
            ## Unable to query due to this information being stored on container level, requiring a connection string, storage account key or SAS token.
            #az storage container show --account-name $strg.name --name insights-operational-logs --query 'properties.publicAccess'

            # Configure Minimum TLS Version
            if ($strg.minimumTlsVersion -match 'TLS1_2') {
                $tempStorageResults += "Good: TLS 1.2 is the minimum TLS version allowed on storage account $($strg.name)."
                $strgControlArray[13].Result = 100
            }
            else {
                $tempStorageResults += "Bad: The minimum version is NOT set to TLS 1.2 on storage account $($strg.name)."
                $strgControlArray[13].Result = 0
            }

            # Enable Infrastructure Encryption
            if ($strg.encryption.requireInfrastructureEncryption -match $True) {
                $tempStorageResults += "Good: Storage Account Infrastructure Encryption is enabled for storage account $($strg.name)."
                $strgControlArray[14].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Storage Account Infrastructure Encryption is NOT enabled for storage account $($strg.name)."
                $strgControlArray[14].Result = 0
            }

            # Private Endpoint in Use
            if ($strg.privateEndpointConnections) {
                $tempStorageResults += "Good: A Private Endpoint is attached to storage account $($strg.name)."
                $strgControlArray[15].Result = 100
            }
            else {
                $tempStorageResults += "Bad: No Private Endpoint is attached to storage account $($strg.name)."
                $strgControlArray[15].Result = 0
            }

            # Storage Account Encryption using Customer Managed Keys
            if ($strg.encryption.keyVaultProperties.keyName) {
                $tempStorageResults += "Good: Storage account $($strg.name) is encrypted using Customer Managed Keys."
                $strgControlArray[16].Result = 100
            }
            else {
                $tempStorageResults += "Bad: Storage account $($strg.name) is NOT encrypted using Customer Managed Keys."
                $strgControlArray[16].Result = 0
            }

            # Calculate the weighted average for the storage account
            $storageScore = $strgControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $storageAvgScore = $storageScore / $strgTotalWeight
            $roundedStorageAvg = [math]::Round($storageAvgScore, 1)

            $tempStorageResults += ""
            $tempStorageResults += "Storage Account $($strg.name) has an average score of $roundedStorageAvg %."
        
            $tempStorageResults,$strgControlArray,$storageScore,$strgTotalWeight
        }
    }

    if ($storageAccounts) {
        Write-Output "Waiting for storage account checks to complete..."
        
        foreach ($job in ($storageJobs | Wait-Job)) {
            $tempStorageResults,$strgControlArray,$storageScore,$strgTotalWeight = Receive-Job -Job $job
            $StorageResults += $tempStorageResults
            $storageTotalScore += $storageScore
        }

        $storageTotalAvg = $storageTotalScore / ($strgTotalWeight * $StorageAccounts.Count)
        $roundedStorageTotalAvg = [math]::Round($storageTotalAvg, 1)

        $lateReport += "Total average score for all storage accounts in subscription $($sub.name) is $roundedStorageTotalAvg %."
    }
    else {
        $StorageResults += ""
        $StorageResults += "No storage accounts found for subscription $($sub.name)."
        $StorageResults += ""
    }

    $WAFResults += $StorageResults
    
    # End region

    ################# Region Key Vaults #####################

    Write-Output "Checking Key Vaults for subscription $($sub.name)..."

    $Keyvaults = az keyvault list 2> $null | ConvertFrom-Json -Depth 10
    if (!$?) {
        Write-Error "Unable to retrieve key vaults for subscription $($sub.name)." -ErrorAction Continue
    }

    $KeyvaultControls = @(
        "Check for presence of AppName tag;Custom;80"
        "Check for presence of CI tag;Custom;80"
        "Check for presence of CIA tag;Custom;80"
        "Check for Key Vault Full Administrator Permissions;Custom;75"
        "Audit event logging should be active for Azure Key Vault;Custom;90"
        "Purge Protection should be enabled for Azure Key Vault;Custom;75"
        "Soft Delete should be enabled for Azure Key Vault;Custom;75"
        "Allow trusted Microsoft services to access the Key Vault;Custom;60"
        "Restrict Default Network Access for Azure Key Vaults;Custom;80"
    )

    $VaultResults = @()
    $VaultResults += ""
    $VaultResults += "#####################################"
    $VaultResults += "WAF Assessment Results for Key Vaults"
    $VaultResults += "#####################################"

    $kvTotalAvg = 0
    $kvTotalScore = 0

    # Note: There are no controls described for Key Vaults in the Microsoft WAF documentation.
    # We will primarily be using custom ABN checks.

    $vaultJobs = @()
    
    foreach ($keyvault in $Keyvaults) {

        Write-Output "Checking Key Vault $($keyvault.name)..."

        $vaultJobs += Start-Threadjob -ScriptBlock {

            $keyvault = $using:keyvault

            $kvControlArray = @()

            foreach ($control in $using:KeyvaultControls) {
                $kvCheck = $control.Split(';')
                $kvCheckName = $kvCheck[0]
                $kvCheckPillars = $kvCheck[1].Split(',')
                $kvCheckWeight = $kvCheck[2]
        
                $kvControlArray += [PSCustomObject]@{
                    Name = $kvCheckName
                    Pillars = $kvCheckPillars
                    Weight = $kvCheckWeight
                    Result = $null
                }
            }

            # Calculate total weight to calculate weighted average
            $kvTotalWeight = 0
            foreach ($control in $kvControlArray) {
                $kvTotalWeight += $control.Weight
            }

            $tempVaultResults = @()
            $tempVaultResults += ""
            $tempVaultResults += "----- Key Vault - $($keyvault.name) -----"
            $tempVaultResults += ""

            # Check for presence of AppName tag
            if ($keyvault.tags.AppName) {
                $tempVaultResults += "Good: AppName tag is present on Key Vault $($keyvault.name)"
                $kvControlArray[0].Result = 100
            }
            else {
                $tempVaultResults += "Bad: AppName tag is NOT present on Key Vault $($keyvault.name)"
                $kvControlArray[0].Result = 0
            }

            # Check for presence of CI tag
            if ($keyvault.tags.'Business Application CI') {
                $tempVaultResults += "Good: Application CI tag is present on Key Vault $($keyvault.name)"
                $kvControlArray[1].Result = 100
            }
            else {
                $tempVaultResults += "Bad: Application CI tag is NOT present on Key Vault $($keyvault.name)"
                $kvControlArray[1].Result = 0
            }

            # Check for presence of CIA tag
            if ($keyvault.tags.CIA) {
                $tempVaultResults += "Good: CIA tag is present on Key Vault $($keyvault.name)"
                $kvControlArray[2].Result = 100
            }
            else {
                $tempVaultResults += "Bad: CIA tag is NOT present on Key Vault $($keyvault.name)"
                $kvControlArray[2].Result = 0
            }

            # Check for Key Vault Full Administrator Permissions
            $vaultsettings = az keyvault show --name $keyvault.name | ConvertFrom-Json -Depth 10
            if ('All' -in $vaultsettings.properties.accesspolicies.permissions.certificates -or 'All' -in $vaultsettings.properties.accesspolicies.permissions.keys -or 'All' -in $vaultsettings.properties.accesspolicies.permissions.secrets -or 'All' -in $vaultsettings.properties.accesspolicies.permissions.storage) {
                $tempVaultResults += "Bad: Full access permissions found on keyvault $($keyvault.name):"
                foreach ($perm in $vaultsettings.properties.accesspolicies) {
                    if ('All' -in $perm.permissions.certificates -or 'All' -in $perm.permissions.keys -or 'All' -in $perm.permissions.secrets -or 'All' -in $perm.permissions.storage) {
                        $tempVaultResults += "Principal with ID $($perm.objectId) has Full Access on one or all of Certificates/Keys/Secrets/Storage."
                    }
                }
                $kvControlArray[3].Result = 0
            }
            else {
                $tempVaultResults += "Good: No Full Access permissions found on keyvault $($keyvault.name)"
                $kvControlArray[3].Result = 100
            }

            # Audit event logging should be active for Azure Key Vault
            $diag = az monitor diagnostic-settings list --resource $keyvault.id --query '[*].logs | []' | ConvertFrom-Json -Depth 10
            if (($diag | Where-Object {$_.category -eq 'AuditEvent'}).enabled -eq $True) {
                $tempVaultResults += "Good: Audit Events are logged for keyvault $($keyvault.name)."
                $kvControlArray[4].Result = 100
            }
            else {
                $tempVaultResults += "Bad: Audit Events are NOT logged for keyvault $($keyvault.name)."
                $kvControlArray[4].Result = 0
            }

            # Purge Protection should be enabled for Azure Key Vault
            if ($vaultsettings.properties.enablePurgeProtection -eq 'True') {
                $tempVaultResults += "Good: Purge Protection is enabled for keyvault $($keyvault.name)"
                $kvControlArray[5].Result = 100
            }
            else {
                $tempVaultResults += "Bad: Purge Protection is NOT enabled for keyvault $($keyvault.name)"
                $kvControlArray[5].Result = 0
            }

            # Soft Delete should be enabled for Azure Key Vault
            if ($vaultsettings.properties.enableSoftDelete -eq 'True') {
                $tempVaultResults += "Good: Soft Delete is enabled for keyvault $($keyvault.name)"
                $kvControlArray[6].Result = 100
            }
            else {
                $tempVaultResults += "Bad: Soft Delete is NOT enabled for keyvault $($keyvault.name)"
                $kvControlArray[6].Result = 0
            }

            # Allow trusted Microsoft services to access the Key Vault
            if ($vaultsettings.properties.networkAcls.bypass -match 'AzureServices') {
                $tempVaultResults += "Good: Microsoft Azure services are whitelisted for $($keyvault.name)"
                $kvControlArray[7].Result = 100
            }
            else {
                $tempVaultResults += "Bad: Microsoft Azure services are NOT whitelisted for $($keyvault.name)"
                $kvControlArray[7].Result = 0
            }

            # Restrict Default Network Access for Azure Key Vaults
            if ($vaultsettings.properties.networkAcls.defaultAction -match 'Deny') {
                $tempVaultResults += "Good: Network access is denied by default for $($keyvault.name)"
                $kvControlArray[8].Result = 100
            }
            else {
                $tempVaultResults += "Bad: Network access is NOT denied by default for $($keyvault.name)"
                $kvControlArray[8].Result = 0
            }

            # Calculate the weighted average for the key vault
            $kvScore = $kvControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $kvAvgScore = $kvScore / $kvTotalWeight
            $roundedKvAvg = [math]::Round($kvAvgScore, 1)

            $tempVaultResults += ""
            $tempVaultResults += "Key Vault $($keyvault.name) has an average score of $roundedKvAvg %."

            $tempVaultResults,$kvControlArray,$kvScore,$kvTotalWeight
        }
    }

    if ($Keyvaults) {
        Write-Output "Waiting for key vault checks to complete..."

        foreach ($job in ($vaultJobs | Wait-Job)) {
            $tempVaultResults,$kvControlArray,$kvScore,$kvTotalWeight = Receive-Job -Job $job
            $VaultResults += $tempVaultResults
            $kvTotalScore += $kvScore
        }

        $kvTotalAvg = $kvTotalScore / ($kvTotalWeight * $Keyvaults.Count)
        $roundedKvTotalAvg = [math]::Round($kvTotalAvg, 1)

        $lateReport += "Total average score for all key vaults in subscription $($sub.name) is $roundedKvTotalAvg %."
    }
    else {
        $VaultResults += ""
        $VaultResults += "No key vaults found for subscription $($sub.name)."
        $VaultResults += ""
    }

    $WAFResults += $VaultResults

    # End region

    ################# Region Virtual Machines #####################

    # For Virtual Machines we currently assume that VM Scale Sets are not used, and that all VMs are standalone.

    Write-Output "Checking Virtual Machines for subscription $($sub.name)..."
    
    $VirtualMachines = az vm list 2> $null | ConvertFrom-Json -Depth 10
    if (!$?) {
        Write-Error "Unable to retrieve virtual machines for subscription $($sub.name)." -ErrorAction Continue
    }

    $VMControls = @(
        "Check for presence of AppName tag;Custom;80"
        "Check for presence of CI tag;Custom;80"
        "Check for presence of CIA tag;Custom;80"
        "Restrict public IP addresses for Azure Virtual Machines;Security;80"
        "Restrict IP forwarding for Azure Virtual Machines;Security;80"
        "Check if VM network interfaces have a Network Security Group attached;Security;80"
        "Enable Azure Disk Encryption for Azure Virtual Machines;Security;90"
        "Enable Endpoint Protection for Azure Virtual Machines;Security;90"
        "Enable Hybrid Benefit for Azure Virtual Machines;Cost Optimization;60"
        "Enable automatic upgrades for extensions on Azure Virtual Machines;Operational Excellence;70"
        "Enable Azure Monitor for Azure Virtual Machines;Operational Excellence;70"
        "Enable VM Insights for Azure Virtual Machines;Operational Excellence;70"
        "Enable boot diagnostics for Azure Virtual Machines;Operational Excellence;70"
        "Enable accelerated networking for Azure Virtual Machines;Performance Efficiency;70"
        "Use Managed Disks for Azure Virtual Machines;Custom;80"
        "Disable Premium SSD for Azure Virtual Machines;Custom;80"
        "Enable JIT Access for Azure Virtual Machines;Custom;80"
        "Enable VM Backup for Azure Virtual Machines;Custom;80"
    )

    $VMResults = @()
    $VMResults += ""
    $VMResults += "###########################################"
    $VMResults += "WAF Assessment Results for Virtual Machines"
    $VMResults += "###########################################"

    $vmTotalAvg = 0
    $vmTotalScore = 0

    # Query JIT policies once, as they are not VM-specific
    $jitPolicies = az security jit-policy list --query '[*].virtualMachines | []' | ConvertFrom-Json -Depth 10

    $vmJobs = @()

    foreach ($vm in $VirtualMachines) {

        Write-Output "Checking Virtual Machine $($vm.name)..."

        $vmJobs += Start-Threadjob -ScriptBlock {

            $vm = $using:vm

            $vmControlArray = @()

            foreach ($control in $using:VMControls) {
                $vmCheck = $control.Split(';')
                $vmCheckName = $vmCheck[0]
                $vmCheckPillars = $vmCheck[1].Split(',')
                $vmCheckWeight = $vmCheck[2]
        
                $vmControlArray += [PSCustomObject]@{
                    Name = $vmCheckName
                    Pillars = $vmCheckPillars
                    Weight = $vmCheckWeight
                    Result = $null
                }
            }

            # Calculate total weight to calculate weighted average
            $vmTotalWeight = 0
            foreach ($control in $vmControlArray) {
                $vmTotalWeight += $control.Weight
            }

            $tempVMResults = @()
            $tempVMResults += ""
            $tempVMResults += "----- Virtual Machine - $($vm.name) -----"
            $tempVMResults += ""

            # Check for presence of AppName tag
            if ($vm.tags.AppName) {
                $tempVMResults += "Good: AppName tag is present on VM $($vm.name)"
                $vmControlArray[0].Result = 100
            }
            else {
                $tempVMResults += "Bad: AppName tag is NOT present on VM $($vm.name)"
                $vmControlArray[0].Result = 0
            }

            # Check for presence of CI tag
            if ($vm.tags.'Business Application CI') {
                $tempVMResults += "Good: Application CI tag is present on VM $($vm.name)"
                $vmControlArray[1].Result = 100
            }
            else {
                $tempVMResults += "Bad: Application CI tag is NOT present on VM $($vm.name)"
                $vmControlArray[1].Result = 0
            }

            # Check for presence of CIA tag
            if ($vm.tags.CIA) {
                $tempVMResults += "Good: CIA tag is present on VM $($vm.name)"
                $vmControlArray[2].Result = 100
            }
            else {
                $tempVMResults += "Bad: CIA tag is NOT present on VM $($vm.name)"
                $vmControlArray[2].Result = 0
            }

            # Restrict public IP addresses for Azure Virtual Machines
            $VmIpAddresses = az vm list-ip-addresses --name $vm.name --resource-group $vm.resourceGroup | ConvertFrom-Json -Depth 10
            if ($VmIpAddresses.virtualMachine.network.publicIpAddresses) {
                $tempVMResults += "Bad: Public IP addresses are present on VM $($vm.name)"
                $vmControlArray[3].Result = 0
            }
            else {
                $tempVMResults += "Good: No Public IP addresses are present on VM $($vm.name)"
                $vmControlArray[3].Result = 100
            }

            # Restrict IP forwarding for Azure Virtual Machines
            $VmNICs = az network nic list --query "[?virtualMachine.id == '$($vm.id)']" | ConvertFrom-Json -Depth 10
            $enableForwarding = $false
            foreach ($nic in $VmNICs) {
                if ($nic.enableIpForwarding) {
                    $tempVMResults += "Bad: IP Forwarding is enabled on NIC $($nic.name) for VM $($vm.name)"
                    $enableForwarding = $true
                }
                else {
                    $tempVMResults += "Good: IP Forwarding is disabled on NIC $($nic.name) for VM $($vm.name)"
                }
            }
            if ($enableForwarding) {
                $vmControlArray[4].Result = 0
            }
            else {
                $vmControlArray[4].Result = 100
            }

            # Check if VM network interfaces have a Network Security Group attached
            # Set to true by default, and only set to false if a NIC is found without a NSG attached.
            $enableNSG = $true
            foreach ($nic in $VmNICs) {
                if ($nic.networkSecurityGroup) {
                    $tempVMResults += "Good: Network Security Group is attached to NIC $($nic.name) for VM $($vm.name)"
                }
                else {
                    $tempVMResults += "Bad: No Network Security Group is attached to NIC $($nic.name) for VM $($vm.name)"
                    $enableNSG = $false
                }
            }
            if ($enableNSG) {
                $vmControlArray[5].Result = 100
            }
            else {
                $vmControlArray[5].Result = 0
            }

            # Enable Azure Disk Encryption for Azure Virtual Machines
            $DiskEncryption = az vm encryption show --name $vm.name --resource-group $vm.resourceGroup 2> $null | ConvertFrom-Json -Depth 10
            if ($DiskEncryption) {
                $tempVMResults += "Good: Disk Encryption is enabled for VM $($vm.name)"
                $vmControlArray[6].Result = 100
            }
            else {
                $tempVMResults += "Bad: Disk Encryption is NOT enabled for VM $($vm.name)"
                $vmControlArray[6].Result = 0
            }

            # Enable Endpoint Protection for Azure Virtual Machines
            $enableMDE = $false
            foreach ($resource in $vm.resources) {
                if ($resource.id -match 'MDE.Windows') {
                    $enableMDE = $true
                }
            }
            if ($enableMDE) {
                $tempVMResults += "Good: Endpoint Protection is enabled for VM $($vm.name)"
                $vmControlArray[7].Result = 100
            }
            else {
                $tempVMResults += "Bad: Endpoint Protection is NOT enabled for VM $($vm.name)"
                $vmControlArray[7].Result = 0
            }

            # Enable Hybrid Benefit for Azure Virtual Machines
            $detailedVmInfo = az vm get-instance-view --name $vm.name --resource-group $vm.resourceGroup 2> $null | ConvertFrom-Json -Depth 15
            if ($detailedVmInfo.licenseType -match 'Windows_Server') {
                $tempVMResults += "Good: Hybrid Benefit is enabled for VM $($vm.name)"
                $vmControlArray[8].Result = 100
            }
            else {
                $tempVMResults += "Informational: Hybrid Benefit is not enabled for VM $($vm.name)"
                $vmControlArray[8].Result = 50
            }

            # Enable automatic upgrades for extensions on Azure Virtual Machines
            $extensionCount = 0
            $autoUpgradeEnabledCount = 0
            foreach ($resource in $vm.resources) {
                if ($resource.id -match 'HybridWorkerExtension' -or $resource.id -match 'DependencyAgentLinux'-or $resource.id -match 'DependencyAgentWindows' -or $resource.id -match 'ApplicationHealthLinux' -or $resource.id -match 'ApplicationHealthWindows' -or $resource.id -match 'GuestAttestation' -or $resource.id -match 'ConfigurationForLinux' -or $resource.id -match 'ConfigurationForWindows' -or $resource.id -match 'KeyVaultForLinux' -or $resource.id -match 'KeyVaultForWindows' -or $resource.id -match 'AzureMonitorLinuxAgent' -or $resource.id -match 'AzureMonitorWindowsAgent' -or $resource.id -match 'OmsAgentForLinux' -or $resource.id -match 'LinuxDiagnostic' -or $resource.id -match 'ServiceFabricLinuxNode') {
                    $extensionCount += 1
                    if ($resource.autoUpgradeMinorVersion -match 'True') {
                        $tempVMResults += "Good: Automatic upgrades are enabled for extension $($resource.id.split("/")[-1]) on VM $($vm.name)"
                        $autoUpgradeEnabledCount += 1
                    }
                    else {
                        $tempVMResults += "Bad: Automatic upgrades are NOT enabled for extension $($resource.id.split("/")[-1]) on VM $($vm.name)"
                    }   
                }
            }
            if ($extensionCount -gt 0) {
                $percValue = ($extensioncount / 100) * $autoUpgradeEnabledCount
                $vmControlArray[9].Result = $percValue
            }
            else {
                $tempVMResults += "Informational: No automatically upgradeable extensions found on VM $($vm.name)"
                $vmControlArray[9].Result = 100
                $vmControlArray[9].Weight = 0
            }

            # Enable Azure Monitor for Azure Virtual Machines
            $azMonEnabled = $false
            foreach ($resource in $vm.resources) {
                if ($resource.id -match 'AzureMonitorLinuxAgent' -or $resource.id -match 'AzureMonitorWindowsAgent') {
                    $azMonEnabled = $true
                }
            }
            if ($azMonEnabled) {
                $tempVMResults += "Good: Azure Monitor is enabled for VM $($vm.name)"
                $vmControlArray[10].Result = 100
            }
            else {
                $tempVMResults += "Bad: Azure Monitor is NOT enabled for VM $($vm.name)"
                $vmControlArray[10].Result = 0
            }

            # Enable VM Insights for Azure Virtual Machines
            $VMInsightsEnabled = $false
            foreach ($resource in $vm.resources) {
                if ($resource.id -match 'DependencyAgentLinux' -and $resource.id -match 'AzureMonitorLinuxAgent') {
                    $VMInsightsEnabled = $true
                }
                elseif ($resource.id -match 'DependencyAgentWindows' -and $resource.id -match 'AzureMonitorWindowsAgent') {
                    $VMInsightsEnabled = $true
                }
            }
            if ($VMInsightsEnabled) {
                $tempVMResults += "Good: VM Insights is enabled for VM $($vm.name)"
                $vmControlArray[11].Result = 100
            }
            else {
                $tempVMResults += "Bad: VM Insights is NOT enabled for VM $($vm.name)"
                $vmControlArray[11].Result = 0
            }

            # Enable boot diagnostics for Azure Virtual Machines
            if ($vm.diagnosticsProfile.bootDiagnostics.enabled -match 'True') {
                $tempVMResults += "Good: Boot Diagnostics are enabled for VM $($vm.name)"
                $vmControlArray[12].Result = 100
            }
            else {
                $tempVMResults += "Bad: Boot Diagnostics are NOT enabled for VM $($vm.name)"
                $vmControlArray[12].Result = 0
            }

            # Enable accelerated networking for Azure Virtual Machines
            $accelerationEnabled = $false
            foreach ($nic in $VmNICs) {
                if ($nic.enableAcceleratedNetworking) {
                    $tempVMResults += "Good: Accelerated Networking is enabled on NIC $($nic.name) for VM $($vm.name)"
                    $accelerationEnabled = $true
                }
                else {
                    $tempVMResults += "Bad: Accelerated Networking is NOT enabled on NIC $($nic.name) for VM $($vm.name)"
                }
            }
            if ($accelerationEnabled) {
                $vmControlArray[13].Result = 100
            }
            else {
                $vmControlArray[13].Result = 0
            }

            # Use Managed Disks for Azure Virtual Machines
            $managedDisks = $true
            foreach ($disk in $vm.storageProfile.osDisk.managedDisk) {
                if ($disk -match 'null') {
                    $managedDisks = $false
                }
            }
            if ($managedDisks) {
                $tempVMResults += "Good: Managed Disks are used for VM $($vm.name)"
                $vmControlArray[14].Result = 100
            }
            else {
                $tempVMResults += "Bad: Managed Disks are NOT used for VM $($vm.name)"
                $vmControlArray[14].Result = 0
            }

            # Disable Premium SSD for Azure Virtual Machines
            $premiumSSD = $false
            foreach ($disk in $vm.storageProfile.osDisk) {
                if ($disk.managedDisk.storageAccountType -match 'Premium') {
                    $tempVMResults += "Bad: Premium SSD is used for OS Disk on VM $($vm.name)"
                    $premiumSSD = $true
                }
                else {
                    $tempVMResults += "Good: Standard SSD is used for OS Disk on VM $($vm.name)"
                }
            }
            if ($premiumSSD) {
                $vmControlArray[15].Result = 0
            }
            else {
                $vmControlArray[15].Result = 100
            }

            # Enable JIT Access for Azure Virtual Machines
            if ($jitPolicies) {
                if ($vm.id -in $jitPolicies) {
                    $tempVMResults += "Good: JIT Access is enabled for VM $($vm.name)"
                    $vmControlArray[16].Result = 100
                }
                else {
                    $tempVMResults += "Bad: JIT Access is NOT enabled for VM $($vm.name)"
                    $vmControlArray[16].Result = 0
                }
            }
            else{
                $tempVMResults += "Bad: No JIT Policies found for VM $($vm.name)"
                $vmControlArray[16].Result = 0
            }

            # Enable VM Backup for Azure Virtual Machines
            $vaults = az backup vault list --query '[*].name' 2> $null | ConvertFrom-Json -Depth 10
            $vmBackedUp = $false
            foreach ($vault in $vaults) {
                $backupItems = az backup item list --vault-name $vault --resource-group $vm.resourceGroup --query '[*].properties.virtualMachineId' 2> $null | ConvertFrom-Json -Depth 10
                if ($backupItems -contains $vm.id) {
                    $vmBackedUp = $true
                }
            }
            if ($vmBackedUp) {
                $tempVMResults += "Good: VM Backup is enabled for VM $($vm.name)"
                $vmControlArray[17].Result = 100
            }
            else {
                $tempVMResults += "Bad: VM Backup is NOT enabled for VM $($vm.name)"
                $vmControlArray[17].Result = 0
            }

            # Calculate the weighted average for the virtual machine
            $vmScore = $vmControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $vmAvgScore = $vmScore / $vmTotalWeight
            $roundedVmAvg = [math]::Round($vmAvgScore, 1)

            $tempVMResults += ""
            $tempVMResults += "Virtual Machine $($vm.name) has an average score of $roundedVmAvg %."

            $tempVMResults,$vmControlArray,$vmScore,$vmTotalWeight
        }
    }

    if ($VirtualMachines) {
        Write-Output "Waiting for virtual machine checks to complete..."

        foreach ($job in ($vmJobs | Wait-Job)) {
            $tempVMResults,$vmControlArray,$vmScore,$vmTotalWeight = Receive-Job -Job $job
            $VMResults += $tempVMResults
            $vmTotalScore += $vmScore
        }

        $vmTotalAvg = $vmTotalScore / ($vmTotalWeight * $VirtualMachines.Count)
        $roundedVmTotalAvg = [math]::Round($vmTotalAvg, 1)

        $lateReport += "Total average score for all virtual machines in subscription $($sub.name) is $roundedVmTotalAvg %."
    }
    else {
        $VMResults += ""
        $VMResults += "No virtual machines found for subscription $($sub.name)."
        $VMResults += ""
    }

    $WAFResults += $VMResults

    # End region

    ################# Region App Services ####################

    Write-Output "Checking App Services for subscription $($sub.name)..."

    $AppServices = az webapp list 2> $null | ConvertFrom-Json -Depth 10
    if (!$?) {
        Write-Error "Unable to retrieve App Services for subscription $($sub.name)." -ErrorAction Continue
    }

    # Define controls for App Services
    $AppServiceControls = @(
        "Consider disabling ARR Affinity for your App Service;Reliability;60"
        "Enable Always On to ensure Web Jobs run reliably;Reliability,Performance Efficiency;80"
        "Access the on-prem database using private connections like Azure VPN or Express Route;Reliability;90"
        "Set up backup and restore;Reliability;90"
        "Understand IP Address deprecation impact;Reliability;70"
        "Ensure App Service Environments (ASE) are deployed in highly available configurations across Availability Zones;Reliability;80"
        "Plan for scaling out the ASE cluster;Reliability;35"
        "Use Deployment slots for resilient code deployments;Reliability,Operational Excellence;75"
        "Use Run From Package to avoid deployment conflicts;Reliability,Operational Excellence;80"
        "Use Basic or higher plans with two or more worker instances for high availability;Reliability,Operational Excellence;60"
        "Enable Health check to identify non-responsive workers;Reliability,Operational Excellence;85"
        "Enable Autoscale to ensure adequate resources are available to service requests;Reliability,Operational Excellence;60"
        "Enable Local Cache to reduce dependencies on cluster file servers;Reliability,Operational Excellence;50"
        "Enable Application Insights Alerts to signal fault conditions;Reliability,Operational Excellence;80"
        "Use a scale-out and scale-in rule combination to optimize costs;Cost Optimization;80"
        "Check for Latest Version of .NET Framework;Custom;80"
        "Check for latest version of Java;Custom;80"
        "Check for Latest Version of PHP;Custom;80"
        "Check for Latest Version of Python;Custom;80"
        "Check for sufficient backup retention period;Custom;80"
        "Check for TLS protocol version;Custom;90"
        "Check that Azure App Service is using the latest version of HTTP;Performance Efficiency;80"
        "Check if the Azure App Service requests incoming client certificates;Custom;80"
        "Disable plain FTP deployment;Custom;80"
        "Disable remote debugging;Custom;80"
        "Enable App Service Authentication;Custom;80"
        "Enable HTTPS-only traffic;Custom;80"
        "Enable registration with Microsoft Entra ID;Custom;80"
    )

    $AppServiceResults = @()
    $AppServiceResults += ""
    $AppServiceResults += "#######################################"
    $AppServiceResults += "WAF Assessment Results for App Services"
    $AppServiceResults += "#######################################"

    $AppServiceTotalAvg = 0
    $AppServiceTotalScore = 0
    $skippedAppServices = 0

    $appServiceJobs = @()

    foreach ($appservice in $AppServices) {

        Write-Output "Checking App Service $($appservice.name)..."

        $appServiceJobs += Start-Threadjob -ScriptBlock {

            $appService = $using:appservice
            $tempAppServiceResults = @()
            $tempSkippedAppServices = 0

            $appDetails = az webapp show --name $appservice.name --resource-group $appservice.resourceGroup | ConvertFrom-Json -Depth 10
            if (!$appDetails) {
                $skippedAppServices += 1
                $tempAppServiceResults += ""
                $tempAppServiceResults += "Unable to retrieve app details for App Service $($appservice.name). This is most likely due to insufficient permissions. Skipping..."
                $tempAppServiceResults += ""
                Continue
            }

            $appServiceControlArray = @()

            foreach ($control in $using:AppServiceControls) {
                $appServiceCheck = $control.Split(';')
                $appServiceCheckName = $appServiceCheck[0]
                $appServiceCheckPillars = $appServiceCheck[1].Split(',')
                $appServiceCheckWeight = $appServiceCheck[2]
        
                $appServiceControlArray += [PSCustomObject]@{
                    Name = $appServiceCheckName
                    Pillars = $appServiceCheckPillars
                    Weight = $appServiceCheckWeight
                    Result = $null
                }
            }

            # Calculate total weight to calculate weighted average
            $appServiceTotalWeight = 0
            foreach ($control in $appServiceControlArray) {
                $appServiceTotalWeight += $control.Weight
            }

            $tempAppServiceResults += ""
            $tempAppServiceResults += "----- App Service - $($appservice.name) -----"
            $tempAppServiceResults += ""

            # Consider disabling ARR Affinity for your App Service
            if ($appDetails.clientAffinityEnabled -match 'False') {
                $tempAppServiceResults += "Good: ARR Affinity is disabled for App Service $($appservice.name)"
                $appServiceControlArray[0].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: ARR Affinity is enabled for App Service $($appservice.name)"
                $appServiceControlArray[0].Result = 0
            }

            # Enable Always On to ensure Web Jobs run reliably
            if ($appDetails.siteConfig.alwaysOn -match 'True') {
                $tempAppServiceResults += "Good: Always On is enabled for App Service $($appservice.name)"
                $appServiceControlArray[1].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Always On is NOT enabled for App Service $($appservice.name)"
                $appServiceControlArray[1].Result = 0
            }

            # Access the on-prem database using private connections like Azure VPN or Express Route
            if ($appDetails.publicNetworkAccess -match 'Disabled') {
                $tempAppServiceResults += "Good: Public Network Access is disabled for App Service $($appservice.name)"
                $appServiceControlArray[2].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Public Network Access is enabled for App Service $($appservice.name)"
                $appServiceControlArray[2].Result = 0
            }

            # Set up backup and restore
            $backupConf = az webapp config backup show --resource-group $appservice.resourceGroup --webapp-name $appservice.name 2> $null | ConvertFrom-Json -Depth 10
            if (!$backupConf) {
                $tempAppServiceResults += "Bad: Backup and Restore is NOT configured for App Service $($appservice.name)"
                $appServiceControlArray[3].Result = 0
            }
            else {
                $tempAppServiceResults += "Good: Backup and Restore is configured for App Service $($appservice.name)"
                $appServiceControlArray[3].Result = 100
            }

            # Understand IP Address deprecation impact
            if ($appDetails.outboundIpAddresses -match 'null') {
                $tempAppServiceResults += "Bad: Outbound IP Addresses are deprecated for App Service $($appservice.name)"
                $appServiceControlArray[4].Result = 0
            }
            else {
                $tempAppServiceResults += "Good: Outbound IP Addresses are not deprecated for App Service $($appservice.name)"
                $appServiceControlArray[4].Result = 100
            }

            # Ensure App Service Environments (ASE) are deployed in highly available configurations across Availability Zones
            $aseDetails = az appservice plan show --id $appDetails.appServicePlanId | ConvertFrom-Json -Depth 10
            if ($aseDetails.properties.zoneRedundant -match 'True') {
                $tempAppServiceResults += "Good: ASE is deployed in a highly available configuration across Availability Zones for App Service $($appservice.name)"
                $appServiceControlArray[5].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: ASE is NOT deployed in a highly available configuration across Availability Zones for App Service $($appservice.name)"
                $appServiceControlArray[5].Result = 0
            }

            # Plan for scaling out the ASE cluster
            if ($aseDetails.sku.capacity -gt 1) {
                $tempAppServiceResults += "Informational: ASE cluster is scaled out for App Service $($appservice.name)"
                $appServiceControlArray[6].Result = 50
            }
            else {
                $tempAppServiceResults += "Informational: ASE cluster is NOT scaled out for App Service $($appservice.name)"
                $appServiceControlArray[6].Result = 50
            }

            # Use Deployment slots for resilient code deployments
            $deploymentSlots = az webapp deployment slot list --name $appservice.name --resource-group $appservice.resourceGroup --query '[*].name' | ConvertFrom-Json -Depth 10
            if ($deploymentSlots) {
                $tempAppServiceResults += "Good: Deployment slots are used for App Service $($appservice.name)"
                $appServiceControlArray[7].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: No Deployment slots are used for App Service $($appservice.name)"
                $appServiceControlArray[7].Result = 0
            }

            # Use Run From Package to avoid deployment conflicts
            $appSettings = az webapp config appsettings list --name $appservice.name --resource-group $appservice.resourceGroup | ConvertFrom-Json -Depth 10
            if (($appSettings -match 'WEBSITE_RUN_FROM_PACKAGE').slotSetting -match 'True') {
                $tempAppServiceResults += "Good: Run From Package is used for App Service $($appservice.name)"
                $appServiceControlArray[8].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Run From Package is NOT used for App Service $($appservice.name)"
                $appServiceControlArray[8].Result = 0
            }

            # Use Basic or higher plans with two or more worker instances for high availability
            if ($aseDetails.sku.capacity -ge 2) {
                if ($aseDetails.sku.tier -match 'Basic' -or $aseDetails.sku.tier -match 'Standard' -or $aseDetails.sku.tier -match 'Premium') {
                    $tempAppServiceResults += "Good: Basic or higher plans with two or more worker instances are used for App Service $($appservice.name)"
                    $appServiceControlArray[9].Result = 100
                }
                else {
                    $tempAppServiceResults += "Bad: Basic or higher plans with two or more worker instances are NOT used for App Service $($appservice.name)"
                    $appServiceControlArray[9].Result = 0
                }
            }
            else {
                $tempAppServiceResults += "Informational: Only one worker instance is active for $($appservice.name), so the app service plan is not evaluated."
                $appServiceControlArray[9].Result = 0
                $appServiceControlArray[9].Weight = 0
            }

            # Enable Health check to identify non-responsive workers
            if ($appDetails.siteConfig.healthCheckPath) {
                $tempAppServiceResults += "Good: Health check is enabled for App Service $($appservice.name)"
                $appServiceControlArray[10].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Health check is NOT enabled for App Service $($appservice.name)"
                $appServiceControlArray[10].Result = 0
            }

            # Enable Autoscale to ensure adequate resources are available to service requests
            $autoscale = az monitor autoscale list --resource-group $appservice.resourceGroup 2> $null | ConvertFrom-Json -Depth 10
            if ($autoscale.targetResourceUri -match $appservice.id -and $autoscale.enabled -match 'True') {
                $tempAppServiceResults += "Good: Autoscale is enabled for App Service $($appservice.name)"
                $appServiceControlArray[11].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Autoscale is NOT enabled for App Service $($appservice.name)"
                $appServiceControlArray[11].Result = 0
            }

            # Enable Local Cache to reduce dependencies on cluster file servers
            if ($aseDetails.sku.capacity -eq 1) {
                if ($appSettings -match 'WEBSITE_LOCAL_CACHE_OPTION') {
                    $tempAppServiceResults += "Good: Local Cache is enabled for App Service with single instance $($appservice.name)"
                    $appServiceControlArray[12].Result = 100
                }
                else {
                    $tempAppServiceResults += "Bad: Local Cache is NOT enabled for App Service with single instance $($appservice.name)"
                    $appServiceControlArray[12].Result = 0
                }
            }
            else {
                if ($appSettings -match 'WEBSITE_LOCAL_CACHE_OPTION') {
                    $tempAppServiceResults += "Bad: Local Cache is enabled for App Service with more than 1 instance $($appservice.name)"
                    $appServiceControlArray[12].Result = 0
                }
                else {
                    $tempAppServiceResults += "Good: Local Cache is not enabled for App Service with more than 1 instance $($appservice.name)"
                    $appServiceControlArray[12].Result = 100
                }
            }

            # Enable Application Insights Alerts to signal fault conditions
            if ($appSettings -match 'APPLICATIONINSIGHTS_CONNECTION_STRING' -or $appSettings -match 'APPINSIGHTS_INSTRUMENTATIONKEY') {
                $tempAppServiceResults += "Good: Application Insights Alerts are enabled for App Service $($appservice.name)"
                $appServiceControlArray[13].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Application Insights Alerts are NOT enabled for App Service $($appservice.name)"
                $appServiceControlArray[13].Result = 0
            }

            # Use a scale-out and scale-in rule combination to optimize costs if autoscale is used
            if ($autoscale.targetResourceUri -match $appservice.id -and $autoscale.enabled -match 'True') {
                if ($autoscale.profiles.rules.scaleaction.direction -match 'Increase' -and $autoscale.profiles.rules.scaleaction.direction -match 'Decrease') {
                    $tempAppServiceResults += "Good: Scale-out and Scale-in rules are used for App Service $($appservice.name)"
                    $appServiceControlArray[14].Result = 100
                }
                else {
                    $tempAppServiceResults += "Bad: No Scale-out and Scale-in rules are used for App Service $($appservice.name)"
                    $appServiceControlArray[14].Result = 0
                }
            }
            else {
                $tempAppServiceResults += "Informational: Autoscale is not enabled for App Service $($appservice.name), so the app service plan is not evaluated."
                $appServiceControlArray[14].Result = 0
                $appServiceControlArray[14].Weight = 0
            }

            # Check for Latest Version of .NET Framework
            if ($appDetails.siteConfig.netFrameworkVersion) {
                if ($appDetails.siteConfig.netFrameworkVersion -match 'v4.8') {
                    $tempAppServiceResults += "Good: Latest version of .NET Framework is used for App Service $($appservice.name)"
                    $appServiceControlArray[15].Result = 100
                }
                else {
                    $tempAppServiceResults += "Bad: Latest version of .NET Framework is NOT used for App Service $($appservice.name)"
                    $appServiceControlArray[15].Result = 0
                }
            }
            else {
                $tempAppServiceResults += "Informational: .NET Framework version is not set for App Service $($appservice.name)"
                $appServiceControlArray[15].Result = 0
                $appServiceControlArray[15].Weight = 0
            }

            # Check for latest version of Java
            if ($appDetails.siteConfig.javaVersion) {
                if ($appDetails.siteConfig.javaVersion -match '1.8') {
                    $tempAppServiceResults += "Good: Latest version of Java is used for App Service $($appservice.name)"
                    $appServiceControlArray[16].Result = 100
                }
                else {
                    $tempAppServiceResults += "Bad: Latest version of Java is NOT used for App Service $($appservice.name)"
                    $appServiceControlArray[16].Result = 0
                }
            }
            else {
                $tempAppServiceResults += "Informational: Java version is not set for App Service $($appservice.name)"
                $appServiceControlArray[16].Result = 0
                $appServiceControlArray[16].Weight = 0
            }

            # Check for Latest Version of PHP
            if ($appDetails.siteConfig.phpVersion) {
                if ($appDetails.siteConfig.phpVersion -match '8.2') {
                    $tempAppServiceResults += "Good: Latest version of PHP is used for App Service $($appservice.name)"
                    $appServiceControlArray[17].Result = 100
                }
                else {
                    $tempAppServiceResults += "Bad: Latest version of PHP is NOT used for App Service $($appservice.name)"
                    $appServiceControlArray[17].Result = 0
                }
            }
            else {
                $tempAppServiceResults += "Informational: PHP version is not set for App Service $($appservice.name)"
                $appServiceControlArray[17].Result = 0
                $appServiceControlArray[17].Weight = 0
            }

            # Check for Latest Version of Python
            if ($appDetails.siteConfig.pythonVersion) {
                if ($appDetails.siteConfig.pythonVersion -match '3.12') {
                    $tempAppServiceResults += "Good: Latest version of Python is used for App Service $($appservice.name)"
                    $appServiceControlArray[18].Result = 100
                }
                else {
                    $tempAppServiceResults += "Bad: Latest version of Python is NOT used for App Service $($appservice.name)"
                    $appServiceControlArray[18].Result = 0
                }
            }
            else {
                $tempAppServiceResults += "Informational: Python version is not set for App Service $($appservice.name)"
                $appServiceControlArray[18].Result = 0
                $appServiceControlArray[18].Weight = 0
            }

            # Check for sufficient backup retention period if backup is enabled
            if ($backupConf) {
                if ($backupConf.retentionPeriodInDays -ge 7) {
                    $tempAppServiceResults += "Good: Backup retention period is sufficient for App Service $($appservice.name)"
                    $appServiceControlArray[19].Result = 100
                }
                else {
                    $tempAppServiceResults += "Bad: Backup retention period is NOT sufficient for App Service $($appservice.name)"
                    $appServiceControlArray[19].Result = 0
                }
            }
            else {
                $tempAppServiceResults += "Informational: Backup is not configured for App Service $($appservice.name)"
                $appServiceControlArray[19].Result = 0
                $appServiceControlArray[19].Weight = 0
            }

            # Check for TLS protocol version
            if ($appDetails.siteConfig.minTlsVersion -match '1.2') {
                $tempAppServiceResults += "Good: TLS protocol version is set to 1.2 for App Service $($appservice.name)"
                $appServiceControlArray[20].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: TLS protocol version is NOT set to 1.2 for App Service $($appservice.name)"
                $appServiceControlArray[20].Result = 0
            }

            # Check that Azure App Service is using the latest version of HTTP
            if ($appDetails.siteConfig.http20Enabled -match 'True') {
                $tempAppServiceResults += "Good: Latest version of HTTP is used for App Service $($appservice.name)"
                $appServiceControlArray[21].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Latest version of HTTP is NOT used for App Service $($appservice.name)"
                $appServiceControlArray[21].Result = 0
            }

            # Check if the Azure App Service requests incoming client certificates
            if ($appDetails.clientCertEnabled -match 'True') {
                $tempAppServiceResults += "Good: Incoming client certificates are requested for App Service $($appservice.name)"
                $appServiceControlArray[22].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Incoming client certificates are NOT requested for App Service $($appservice.name)"
                $appServiceControlArray[22].Result = 0
            }

            # Disable plain FTP deployment
            if ($appDetails.siteConfig.ftpsState -match 'FtpsOnly' -or $appDetails.siteconfig.ftpsState -match 'Disabled') {
                $tempAppServiceResults += "Good: FTP access is disabled for App Service $($appservice.name)"
                $appServiceControlArray[23].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: FTP access is NOT disabled for App Service $($appservice.name)"
                $appServiceControlArray[23].Result = 0
            }

            # Disable remote debugging
            if ($appDetails.siteConfig.remoteDebuggingEnabled -match 'False') {
                $tempAppServiceResults += "Good: Remote debugging is disabled for App Service $($appservice.name)"
                $appServiceControlArray[24].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Remote debugging is NOT disabled for App Service $($appservice.name)"
                $appServiceControlArray[24].Result = 0
            }

            # Enable App Service Authentication
            $appAuth = az webapp auth show --ids $appservice.id 2> $null | ConvertFrom-Json -Depth 10
            if ($appAuth.enabled -match 'True') {
                $tempAppServiceResults += "Good: App Service Authentication is enabled for App Service $($appservice.name)"
                $appServiceControlArray[25].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: App Service Authentication is NOT enabled for App Service $($appservice.name)"
                $appServiceControlArray[25].Result = 0
            }

            # Enable HTTPS-only traffic
            if ($appDetails.httpsOnly -match 'True') {
                $tempAppServiceResults += "Good: HTTPS-only traffic is enabled for App Service $($appservice.name)"
                $appServiceControlArray[26].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: HTTPS-only traffic is NOT enabled for App Service $($appservice.name)"
                $appServiceControlArray[26].Result = 0
            }

            # Enable registration with Microsoft Entra ID
            $appIdentity = az webapp identity show --name $appservice.name --resource-group $appservice.resourceGroup 2> $null | ConvertFrom-Json -Depth 10
            if ($appIdentity.type -match 'SystemAssigned') {
                $tempAppServiceResults += "Good: Registration with Microsoft Entra ID is enabled for App Service $($appservice.name)"
                $appServiceControlArray[27].Result = 100
            }
            else {
                $tempAppServiceResults += "Bad: Registration with Microsoft Entra ID is NOT enabled for App Service $($appservice.name)"
                $appServiceControlArray[27].Result = 0
            }

            # Calculate the weighted average for the app service
            $appServiceScore = $appServiceControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $appServiceAvgScore = $appServiceScore / $appServiceTotalWeight
            $roundedAppServiceAvg = [math]::Round($appServiceAvgScore, 1)

            $tempAppServiceResults += ""
            $tempAppServiceResults += "App Service $($appservice.name) has an average score of $roundedAppServiceAvg %."

            $tempAppServiceResults,$appServiceControlArray,$appServiceScore,$appServiceTotalWeight,$tempSkippedAppServices
        }
    }

    if ($AppServices) {
        Write-Output "Waiting for App Service checks to complete..."

        foreach ($job in ($appServiceJobs | Wait-Job)) {
            $tempAppServiceResults,$appServiceControlArray,$appServiceScore,$appServiceTotalWeight,$tempSkippedAppServices = Receive-Job -Job $job
            if ($tempSkippedAppServices -eq 0) {
                $AppServiceResults += $tempAppServiceResults
                $appServiceTotalScore += $appServiceScore
            }
            else {
                $skippedAppServices += $tempSkippedAppServices
            }
            
        }
    }

    if (($appServices.Count - $skippedAppServices ) -gt 0) {
        $appServiceTotalAvg = $appServiceTotalScore / ($appServiceTotalWeight * $AppServices.Count)
        $roundedAppServiceTotalAvg = [math]::Round($appServiceTotalAvg, 1)

        $lateReport += "Total average score for all App Services in subscription $($sub.name) is $roundedAppServiceTotalAvg %."
    }
    else {
        $AppServiceResults += ""
        $AppServiceResults += "No App Services found for subscription $($sub.name) or all App Services have been skipped."
        $AppServiceResults += ""
    }

    $WAFResults += $AppServiceResults

    # End region

    ################## Region PostgreSQL #####################

    Write-Output "Checking PostgreSQL databases for subscription $($sub.name)..."

    $PostgreSQLServers = @()

    $PostgreSQLServers += az postgres server list 2> $null | ConvertFrom-Json -Depth 10
    if (!$?) {
        Write-Error "Unable to retrieve PostgreSQL single servers for subscription $($sub.name)." -ErrorAction Continue
    }

    $PostgreSQLServers += az postgres flexible-server list 2> $null | ConvertFrom-Json -Depth 10
    if (!$?) {
        Write-Error "Unable to retrieve PostgreSQL flexible servers for subscription $($sub.name)." -ErrorAction Continue
    }

    # Define controls for PostgreSQL
    $PostgreSQLControls = @(
        "Configure geo-redundancy backup;Reliability;80"
        "Monitor your server to ensure it's healthy and performing as expected;Reliability;90"
        "SSL and enforce encryption to secure data in transit;Security;90"
        "Implement network security groups and firewalls to control access to your database;Security;90"
        "Use Azure Active Directory for authentication and authorization to enhance identity management;Security;90"
        "Deploy to the same region as the app;Cost Optimization;80"
        "Set up automated backups and retention policies to maintain data availability and meet compliance requirements;Operational Excellence;90"
        "Check for PostgreSQL Log Retention Period;Custom;80"
        "Check for PostgreSQL Major Version;Custom;80"
        "Disable 'Allow access to Azure services' for PostgreSQL database servers;Custom;80"
        "Enable 'CONNECTION_THROTTLING' Parameter for PostgreSQL Servers;Custom;80"
        "Enable 'LOG_CHECKPOINTS' Parameter for PostgreSQL Servers;Custom;80"
        "Enable 'LOG_CONNECTIONS' Parameter for PostgreSQL Servers;Custom;80"
        "Enable 'LOG_DISCONNECTIONS' Parameter for PostgreSQL Servers;Custom;80"
        "Enable 'LOG_DURATION' Parameter for PostgreSQL Servers;Custom;80"
        "Enable 'log_checkpoints' Parameter for PostgreSQL Flexible Servers;Custom;80"
        "Enable Storage Auto-Growth;Custom;80"
    )

    $PostgreSQLResults = @()
    $PostgreSQLResults += ""
    $PostgreSQLResults += "#####################################"
    $PostgreSQLResults += "WAF Assessment Results for PostgreSQL"
    $PostgreSQLResults += "#####################################"

    $PostgreSQLTotalAvg = 0
    $PostgreSQLTotalScore = 0

    $postgreSQLJobs = @()

    foreach ($server in $PostgreSQLServers) {

        Write-Output "Checking PostgreSQL server $($server.name)..."

        $postgreSQLJobs += Start-Threadjob -ScriptBlock {

            $server = $using:server
            $tempPostgreSQLResults = @()

            $serverStatus = $null

            $serverDetails = az postgres server show --name $server.name --resource-group $server.resourceGroup | ConvertFrom-Json -Depth 10
            if ($?) {
                $serverStatus = "single"
                $tempPostgreSQLResults += ""
                $tempPostgreSQLResults += "$server.name is a PostgreSQL single server. Single server is due to be deprecated in March 2025. Consider migrating to a flexible server."
            }
            else {
                $serverDetails = az postgres flexible-server show --name $server.name --resource-group $server.resourceGroup | ConvertFrom-Json -Depth 10
                if ($?) {
                    $serverStatus = "flexible"
                }
            }
            
            if (!$serverDetails) {
                $tempPostgreSQLResults += ""
                $tempPostgreSQLResults += "Unable to retrieve server details for PostgreSQL server $($server.name). This is most likely due to insufficient permissions. Skipping..."
                $tempPostgreSQLResults += ""
                Continue
            }

            $postgreSQLControlArray = @()

            foreach ($control in $using:PostgreSQLControls) {
                $postgreSQLCheck = $control.Split(';')
                $postgreSQLCheckName = $postgreSQLCheck[0]
                $postgreSQLCheckPillars = $postgreSQLCheck[1].Split(',')
                $postgreSQLCheckWeight = $postgreSQLCheck[2]
        
                $postgreSQLControlArray += [PSCustomObject]@{
                    Name = $postgreSQLCheckName
                    Pillars = $postgreSQLCheckPillars
                    Weight = $postgreSQLCheckWeight
                    Result = $null
                }
            }

            # Calculate total weight to calculate weighted average
            $postgreSQLTotalWeight = 0
            foreach ($control in $postgreSQLControlArray) {
                $postgreSQLTotalWeight += $control.Weight
            }

            $tempPostgreSQLResults += ""
            $tempPostgreSQLResults += "----- PostgreSQL Server - $($server.name) -----"
            $tempPostgreSQLResults += ""

            # Configure geo-redundancy backup
            if ($serverStatus -match 'single') {
                if ($serverDetails.storageProfile.geoRedundantBackup -match 'Enabled') {
                    $tempPostgreSQLResults += "Good: Geo-redundancy backup is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[0].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Geo-redundancy backup is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[0].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                if ($serverDetails.backup.geoRedundantBackup -match 'Enabled') {
                    $tempPostgreSQLResults += "Good: Geo-redundancy backup is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[0].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Geo-redundancy backup is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[0].Result = 0
                }
            }

            # Monitor your server to ensure it's healthy and performing as expected
            $serverMetrics = az monitor metrics alert list --resource $server.id --resource-group $server.resourceGroup
            if ($serverMetrics) {
                $tempPostgreSQLResults += "Good: Server is monitored for PostgreSQL server $($server.name)"
                $postgreSQLControlArray[1].Result = 100
            }
            else {
                $tempPostgreSQLResults += "Bad: Server is NOT monitored for PostgreSQL server $($server.name)"
                $postgreSQLControlArray[1].Result = 0
            }

            # SSL and enforce encryption to secure data in transit
            if ($serverStatus -match 'single') {
                if ($serverDetails.sslEnforcement -match 'Enabled') {
                    $tempPostgreSQLResults += "Good: SSL is enforced for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[2].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: SSL is NOT enforced for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[2].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                if ($serverDetails.dataEncryption) {
                    $tempPostgreSQLResults += "Good: Data encryption is enforced for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[2].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Data encryption is NOT enforced for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[2].Result = 0
                }
            }

            # Implement network security groups and firewalls to control access to your database
            if ($serverStatus -match "single") {
                $firewallRules = az postgres server firewall-rule list --server-name $server.name --resource-group $server.resourceGroup | ConvertFrom-Json -Depth 10
                if ($firewallRules) {
                    $tempPostgreSQLResults += "Good: Firewall rules are implemented for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[3].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Firewall rules are NOT implemented for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[3].Result = 0
                }
            }
            if ($serverStatus -match "flexible") {
                $firewallRules = az postgres flexible-server firewall-rule list --name $server.name --resource-group $server.resourceGroup | ConvertFrom-Json -Depth 10
                if ($firewallRules) {
                    $tempPostgreSQLResults += "Good: Firewall rules are implemented for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[3].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Firewall rules are NOT implemented for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[3].Result = 0
                }
            }

            # Use Azure Active Directory for authentication and authorization to enhance identity management
            if ($serverDetails.identity -match 'SystemAssigned') {
                $tempPostgreSQLResults += "Good: Azure Active Directory is used for authentication and authorization for PostgreSQL server $($server.name)"
                $postgreSQLControlArray[4].Result = 100
            }
            else {
                $tempPostgreSQLResults += "Bad: Azure Active Directory is NOT used for authentication and authorization for PostgreSQL server $($server.name)"
                $postgreSQLControlArray[4].Result = 0
            }

            # Deploy to the same region as the app
            if ($server.location -match $appDetails.location) {
                $tempPostgreSQLResults += "Good: PostgreSQL server is deployed in the same region as the app for PostgreSQL server $($server.name)"
                $postgreSQLControlArray[5].Result = 100
            }
            else {
                $tempPostgreSQLResults += "Bad: PostgreSQL server is NOT deployed in the same region as the app for PostgreSQL server $($server.name)"
                $postgreSQLControlArray[5].Result = 0
            }

            # Set up automated backups and retention policies to maintain data availability and meet compliance requirements
            if ($serverStatus -match 'single') {
                if ($serverDetails.storageProfile.backupRetentionDays -ge 7) {
                    $tempPostgreSQLResults += "Good: Backup retention period is sufficient for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[6].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Backup retention period is NOT sufficient for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[6].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                if ($serverDetails.backup.retentionDays -ge 7) {
                    $tempPostgreSQLResults += "Good: Backup retention period is sufficient for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[6].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Backup retention period is NOT sufficient for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[6].Result = 0
                }
            }

            # Check for PostgreSQL Log Retention Period
            if ($serverStatus -match 'single') {
                $logretention = az postgres server configuration show --server-name $server.name --resource-group $server.resourceGroup --name log_retention_days
                if ($logretention.value -ge 7) {
                    $tempPostgreSQLResults += "Good: Log retention period is sufficient for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[7].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Log retention period is NOT sufficient for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[7].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                $logretention = az postgres flexible-server configuration show --name $server.name --resource-group $server.resourceGroup --config-name log_retention_days
                if ($logretention.value -ge 7) {
                    $tempPostgreSQLResults += "Good: Log retention period is sufficient for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[7].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: Log retention period is NOT sufficient for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[7].Result = 0
                }
            }

            # Check for PostgreSQL Major Version
            if ($serverStatus -match 'single') {
                if ($serverDetails.Version -match '11') {
                    $tempPostgreSQLResults += "Good: PostgreSQL server is using the latest major version for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[8].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: PostgreSQL server is NOT using the latest major version for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[8].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                if ($serverDetails.Version -match '16') {
                    $tempPostgreSQLResults += "Good: PostgreSQL server is using the latest major version for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[8].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: PostgreSQL server is NOT using the latest major version for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[8].Result = 0
                }
            }

            # Disable 'Allow access to Azure services' for PostgreSQL database servers
            if ($serverStatus -match 'single') {
                if ($serverDetails.allowAzureIps -match 'Disabled') {
                    $tempPostgreSQLResults += "Good: 'Allow access to Azure services' is disabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[9].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'Allow access to Azure services' is NOT disabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[9].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                if ($serverDetails.allowAzureIps -match 'Disabled') {
                    $tempPostgreSQLResults += "Good: 'Allow access to Azure services' is disabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[9].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'Allow access to Azure services' is NOT disabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[9].Result = 0
                }
            }

            # Enable 'CONNECTION_THROTTLING' Parameter for PostgreSQL Servers
            if ($serverStatus -match 'single') {
                $connectionThrottling = az postgres server configuration show --server-name $server.name --resource-group $server.resourceGroup --name connection_throttling
                if ($connectionThrottling.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'CONNECTION_THROTTLING' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[10].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'CONNECTION_THROTTLING' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[10].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                $connectionThrottling = az postgres flexible-server configuration show --name $server.name --resource-group $server.resourceGroup --config-name connection_throttling
                if ($connectionThrottling.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'CONNECTION_THROTTLING' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[10].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'CONNECTION_THROTTLING' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[10].Result = 0
                }
            }

            # Enable 'LOG_CHECKPOINTS' Parameter for PostgreSQL Servers
            if ($serverStatus -match 'single') {
                $logCheckpoints = az postgres server configuration show --server-name $server.name --resource-group $server.resourceGroup --name log_checkpoints
                if ($logCheckpoints.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'LOG_CHECKPOINTS' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[11].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'LOG_CHECKPOINTS' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[11].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                $logCheckpoints = az postgres flexible-server configuration show --name $server.name --resource-group $server.resourceGroup --config-name log_checkpoints
                if ($logCheckpoints.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'LOG_CHECKPOINTS' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[11].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'LOG_CHECKPOINTS' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[11].Result = 0
                }
            }

            # Enable 'LOG_CONNECTIONS' Parameter for PostgreSQL Servers
            if ($serverStatus -match 'single') {
                $logConnections = az postgres server configuration show --server-name $server.name --resource-group $server.resourceGroup --name log_connections
                if ($logConnections.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'LOG_CONNECTIONS' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[12].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'LOG_CONNECTIONS' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[12].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                $logConnections = az postgres flexible-server configuration show --name $server.name --resource-group $server.resourceGroup --config-name log_connections
                if ($logConnections.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'LOG_CONNECTIONS' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[12].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'LOG_CONNECTIONS' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[12].Result = 0
                }
            }

            # Enable 'LOG_DISCONNECTIONS' Parameter for PostgreSQL Servers
            if ($serverStatus -match 'single') {
                $logDisconnections = az postgres server configuration show --server-name $server.name --resource-group $server.resourceGroup --name log_disconnections
                if ($logDisconnections.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'LOG_DISCONNECTIONS' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[13].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'LOG_DISCONNECTIONS' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[13].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                $logDisconnections = az postgres flexible-server configuration show --name $server.name --resource-group $server.resourceGroup --config-name log_disconnections
                if ($logDisconnections.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'LOG_DISCONNECTIONS' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[13].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'LOG_DISCONNECTIONS' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[13].Result = 0
                }
            }

            # Enable 'LOG_DURATION' Parameter for PostgreSQL Servers
            if ($serverStatus -match 'single') {
                $logDuration = az postgres server configuration show --server-name $server.name --resource-group $server.resourceGroup --name log_duration
                if ($logDuration.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'LOG_DURATION' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[14].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'LOG_DURATION' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[14].Result = 0
                }
            }
            if ($serverStatus -match 'flexible') {
                $logDuration = az postgres flexible-server configuration show --name $server.name --resource-group $server.resourceGroup --config-name log_duration
                if ($logDuration.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'LOG_DURATION' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[14].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'LOG_DURATION' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[14].Result = 0
                }
            }

            # Enable 'log_checkpoints' Parameter for PostgreSQL Flexible Servers
            if ($serverStatus -match 'flexible') {
                $logCheckpoints = az postgres flexible-server configuration show --name $server.name --resource-group $server.resourceGroup --config-name log_checkpoints
                if ($logCheckpoints.value -match 'on') {
                    $tempPostgreSQLResults += "Good: 'log_checkpoints' parameter is enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[15].Result = 100
                }
                else {
                    $tempPostgreSQLResults += "Bad: 'log_checkpoints' parameter is NOT enabled for PostgreSQL server $($server.name)"
                    $postgreSQLControlArray[15].Result = 0
                }
            }

            # Enable Storage Auto-Growth
            if ($serverDetails.storageProfile.storageAutogrow -match 'Enabled') {
                $tempPostgreSQLResults += "Good: Storage Auto-Growth is enabled for PostgreSQL server $($server.name)"
                $postgreSQLControlArray[16].Result = 100
            }
            else {
                $tempPostgreSQLResults += "Bad: Storage Auto-Growth is NOT enabled for PostgreSQL server $($server.name)"
                $postgreSQLControlArray[16].Result = 0
            }

            # Calculate the weighted average for the PostgreSQL server
            $postgreSQLScore = $postgreSQLControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $postgreSQLAvgScore = $postgreSQLScore / $postgreSQLTotalWeight
            $roundedPostgreSQLAvg = [math]::Round($postgreSQLAvgScore, 1)

            $tempPostgreSQLResults += ""
            $tempPostgreSQLResults += "PostgreSQL server $($server.name) has an average score of $roundedPostgreSQLAvg %."

            $tempPostgreSQLResults,$postgreSQLControlArray,$postgreSQLScore,$postgreSQLTotalWeight
        }
    }

    if ($PostgreSQLServers.Count -gt 0) {
        Write-Output "Waiting for PostgreSQL checks to complete..."

        foreach ($job in ($postgreSQLJobs | Wait-Job)) {
            $tempPostgreSQLResults,$postgreSQLControlArray,$postgreSQLScore,$postgreSQLTotalWeight = Receive-Job -Job $job
            $PostgreSQLResults += $tempPostgreSQLResults
            $PostgreSQLTotalScore += $postgreSQLScore
        }

        $PostgreSQLTotalAvg = $PostgreSQLTotalScore / ($postgreSQLTotalWeight * $PostgreSQLServers.Count)
        $roundedPostgreSQLTotalAvg = [math]::Round($PostgreSQLTotalAvg, 1)

        $lateReport += "Total average score for all PostgreSQL servers in subscription $($sub.name) is $roundedPostgreSQLTotalAvg %."
    }
    else {
        $PostgreSQLResults += ""
        $PostgreSQLResults += "No PostgreSQL servers found for subscription $($sub.name)."
        $PostgreSQLResults += ""
    }

    $WAFResults += $PostgreSQLResults

    # End region

    #################### Region CosmosDB #####################

    Write-Output "Checking CosmosDB databases for subscription $($sub.name)..."

    $CosmosDBAccounts = @()

    $CosmosDBAccounts += az cosmosdb list 2> $null | ConvertFrom-Json -Depth 10
    if (!$?) {
        Write-Error "Unable to retrieve CosmosDB accounts for subscription $($sub.name)." -ErrorAction Continue
    }

    # Define controls for CosmosDB
    $CosmosDBControls = @(
        "Distribute your Azure Cosmos DB account across availability zones;Reliability;80"
        "Configure your Azure Cosmos DB account to span at least two regions;Reliability;70"
        "Enable service-managed failover for your account;Reliability;80"
        "Disable public endpoints and use private endpoints whenever possible;Security;90"
        "Use role-based access control to limit control-plane access to specific identities and groups and within the scope of well-defined assignments;Security;90"
        "Enable Microsoft Defender for Azure Cosmos DB;Security;90"
        "Implement time-to-live (TTL) to remove unused items;Cost Optimization;80"
        "Create alerts associated with host machine resources;Operational Excellence;80"
        "Create alerts for throughput throttling;Operational Excellence;80"
        "Restrict default network access;Custom;80"
    )

    $CosmosDBResults = @()
    $CosmosDBResults += ""
    $CosmosDBResults += "###################################"
    $CosmosDBResults += "WAF Assessment Results for CosmosDB"
    $CosmosDBResults += "###################################"

    $CosmosDBTotalAvg = 0
    $CosmosDBTotalScore = 0

    $cosmosDBJobs = @()

    foreach ($cosmosAcct in $CosmosDBAccounts) {
            
        Write-Output "Checking CosmosDB account $($cosmosAcct.name)..."

        $cosmosDBJobs += Start-Threadjob -ScriptBlock {
            
            $cosmosAcct = $using:cosmosAcct
            $tempCosmosDBResults = @()

            $cosmosDBControlArray = @()

            foreach ($control in $using:CosmosDBControls) {
                $cosmosDBCheck = $control.Split(';')
                $cosmosDBCheckName = $cosmosDBCheck[0]
                $cosmosDBCheckPillars = $cosmosDBCheck[1].Split(',')
                $cosmosDBCheckWeight = $cosmosDBCheck[2]
        
                $cosmosDBControlArray += [PSCustomObject]@{
                    Name = $cosmosDBCheckName
                    Pillars = $cosmosDBCheckPillars
                    Weight = $cosmosDBCheckWeight
                    Result = $null
                }
            }

            # Calculate total weight to calculate weighted average
            $cosmosDBTotalWeight = 0
            foreach ($control in $cosmosDBControlArray) {
                $cosmosDBTotalWeight += $control.Weight
            }

            $tempCosmosDBResults += ""
            $tempCosmosDBResults += "----- CosmosDB Account - $($cosmosAcct.name) -----"
            $tempCosmosDBResults += ""

            # Distribute your Azure Cosmos DB account across availability zones
            if ($cosmosAcct.enableMultipleWriteLocations -match 'True') {
                $tempCosmosDBResults += "Good: Azure Cosmos DB account is distributed across availability zones for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[0].Result = 100
            }
            else {
                $tempCosmosDBResults += "Bad: Azure Cosmos DB account is NOT distributed across availability zones for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[0].Result = 0
            }

            # Configure your Azure Cosmos DB account to span at least two regions
            if ($cosmosAcct.locations.Count -ge 2) {
                $tempCosmosDBResults += "Good: Azure Cosmos DB account spans at least two regions for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[1].Result = 100
            }
            else {
                $tempCosmosDBResults += "Bad: Azure Cosmos DB account does NOT span at least two regions for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[1].Result = 0
            }

            # Enable service-managed failover for your account
            if ($cosmosAcct.enableAutomaticFailover -match 'True') {
                $tempCosmosDBResults += "Good: Service-managed failover is enabled for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[2].Result = 100
            }
            else {
                $tempCosmosDBResults += "Bad: Service-managed failover is NOT enabled for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[2].Result = 0
            }

            # Disable public endpoints and use private endpoints whenever possible
            if ($cosmosAcct.publicNetworkAccess -match 'Disabled') {
                $tempCosmosDBResults += "Good: Public endpoints are disabled for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[3].Result = 100
            }
            else {
                $tempCosmosDBResults += "Bad: Public endpoints are NOT disabled for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[3].Result = 0
            }

            # Use role-based access control to limit control-plane access to specific identities and groups and within the scope of well-defined assignments
            $roleAssignments = az cosmosdb sql role assignment list --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup 2> $null
            if ($?) {
                if ($roleAssignments) {
                    $tempCosmosDBResults += "Good: Role-based access control is used for CosmosDB account $($cosmosAcct.name)"
                    $cosmosDBControlArray[4].Result = 100
                }
                else {
                    $tempCosmosDBResults += "Bad: Role-based access control is NOT used for CosmosDB account $($cosmosAcct.name)"
                    $cosmosDBControlArray[4].Result = 0
                }
            }
            else {
                $tempCosmosDBResults += "Informational: Unable to retrieve role assignments for CosmosDB account $($cosmosAcct.name). This is most likely due to the API type not supporting role assignments."
                $cosmosDBControlArray[4].Result = 100
                $cosmosDBControlArray[4].Weight = 0
            }

            # Enable Microsoft Defender for Azure Cosmos DB
            $defenderStatus = az security atp cosmosdb show --cosmosdb-account $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup | ConvertFrom-Json -Depth 10
            if ($defenderStatus.isEnabled) {
                $tempCosmosDBResults += "Good: Microsoft Defender is enabled for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[5].Result = 100
            }
            else {
                $tempCosmosDBResults += "Bad: Microsoft Defender is NOT enabled for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[5].Result = 0
            }

            # Implement time-to-live (TTL) to remove unused items
            # Check the type of db; Gremlin, Cassandra and SQL support TTL
            if ($cosmosAcct.capabilities.name -match 'EnableGremlin' ) {
                $gremlinDB = az cosmosdb gremlin database list --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup | ConvertFrom-Json -Depth 10
                $ttl = az cosmosdb gremlin database show --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup --name $gremlinDB[0].name | ConvertFrom-Json -Depth 10
                if ($ttl.defaultTtl -ge 1) {
                    $tempCosmosDBResults += "Good: Time-to-live (TTL) is implemented for CosmosDB account $($cosmosAcct.name)"
                    $cosmosDBControlArray[6].Result = 100
                }
                else {
                    $tempCosmosDBResults += "Bad: Time-to-live (TTL) is NOT implemented for CosmosDB account $($cosmosAcct.name)"
                    $cosmosDBControlArray[6].Result = 0
                }
            }
            elseif ($cosmosAcct.capabilities.name -match 'EnableCassandra') {
                $cassandraDB = az cosmosdb cassandra keyspace list --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup | ConvertFrom-Json -Depth 10
                $cassandraTable = az cosmosdb cassandra table list --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup --keyspace-name $cassandraDB[0].name | ConvertFrom-Json -Depth 10
                if ($cassandraTable.length -ge 1) {
                    $ttl = az cosmosdb cassandra table show --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup --keyspace-name $cassandraDB[0].name --name $cassandraTable[0].name | ConvertFrom-Json -Depth 10
                    if ($ttl.defaultTtl -ge 1) {
                        $tempCosmosDBResults += "Good: Time-to-live (TTL) is implemented for CosmosDB account $($cosmosAcct.name)"
                        $cosmosDBControlArray[6].Result = 100
                    }
                    else {
                        $tempCosmosDBResults += "Bad: Time-to-live (TTL) is NOT implemented for CosmosDB account $($cosmosAcct.name)"
                        $cosmosDBControlArray[6].Result = 0
                    }
                }
                else {
                    $tempCosmosDBResults += "Informational: No table found for Cassandra DB for CosmosDB account $($cosmosAcct.name)"
                    $cosmosDBControlArray[6].Result = 100
                    $cosmosDBControlArray[6].Weight = 0
                }
            }
            elseif ($cosmosAcct.capabilities.name -match 'EnableTable') {
                $tempCosmosDBResults += "Informational: Time-to-live (TTL) is not supported for Table API for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[6].Result = 100
                $cosmosDBControlArray[6].Weight = 0
            }
            elseif ($cosmosAcct.capabilities.name -match 'EnableMongo') {
                $tempCosmosDBResults += "Informational: Time-to-live (TTL) is not supported for MongoDB API for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[6].Result = 100
                $cosmosDBControlArray[6].Weight = 0
            }
            else {
                $sqlDB = az cosmosdb sql database list --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup | ConvertFrom-Json -Depth 10
                $sqlContainer = az cosmosdb sql container list --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup --db-name $sqlDB[0].name | ConvertFrom-Json -Depth 10
                if ($sqlContainer.length -ge 1) {
                    $ttl = az cosmosdb sql container show --account-name $cosmosAcct.name --resource-group $cosmosAcct.resourceGroup --db-name $sqlDB[0].name --name $sqlContainer[0].name | ConvertFrom-Json -Depth 10
                    if ($ttl.defaultTtl -ge 1) {
                        $tempCosmosDBResults += "Good: Time-to-live (TTL) is implemented for CosmosDB account $($cosmosAcct.name)"
                        $cosmosDBControlArray[6].Result = 100
                    }
                    else {
                        $tempCosmosDBResults += "Bad: Time-to-live (TTL) is NOT implemented for CosmosDB account $($cosmosAcct.name)"
                        $cosmosDBControlArray[6].Result = 0
                    }
                }
                else {
                    $tempCosmosDBResults += "Informational: No container found for SQL DB for CosmosDB account $($cosmosAcct.name)"
                    $cosmosDBControlArray[6].Result = 100
                    $cosmosDBControlArray[6].Weight = 0
                }
            }

            # Create alerts associated with host machine resources (Currently binary yes/no check, needs to be updated to check for specific alerts)
            $hostAlerts = az monitor metrics alert list --resource $cosmosAcct.id --resource-group $cosmosAcct.resourceGroup
            if ($hostAlerts) {
                $tempCosmosDBResults += "Good: Alerts are created for host machine resources for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[7].Result = 100
            }
            else {
                $tempCosmosDBResults += "Bad: Alerts are NOT created for host machine resources for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[7].Result = 0
            }

            # Create alerts for throughput throttling (Currently binary yes/no check, needs to be updated to check for specific alerts)
            $throttleAlerts = az monitor metrics alert list --resource $cosmosAcct.id --resource-group $cosmosAcct.resourceGroup
            if ($throttleAlerts) {
                $tempCosmosDBResults += "Good: Alerts are created for throughput throttling for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[8].Result = 100
            }
            else {
                $tempCosmosDBResults += "Bad: Alerts are NOT created for throughput throttling for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[8].Result = 0
            }

            # Restrict default network access
            if ($cosmosAcct.publicNetworkAccess -match 'Disabled') {
                $tempCosmosDBResults += "Good: Default network access is restricted for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[9].Result = 100
            }
            else {
                $tempCosmosDBResults += "Bad: Default network access is NOT restricted for CosmosDB account $($cosmosAcct.name)"
                $cosmosDBControlArray[9].Result = 0
            }
            
            # Calculate the weighted average for the CosmosDB account
            $cosmosDBScore = $cosmosDBControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $cosmosDBAvgScore = $cosmosDBScore / $cosmosDBTotalWeight
            $roundedCosmosDBAvg = [math]::Round($cosmosDBAvgScore, 1)

            $tempCosmosDBResults += ""
            $tempCosmosDBResults += "CosmosDB account $($cosmosAcct.name) has an average score of $roundedCosmosDBAvg %."

            $tempCosmosDBResults,$cosmosDBControlArray,$cosmosDBScore,$cosmosDBTotalWeight
        }
    }

    if ($CosmosDBAccounts.Count -gt 0) {
        Write-Output "Waiting for CosmosDB checks to complete..."

        foreach ($job in ($cosmosDBJobs | Wait-Job)) {
            $tempCosmosDBResults,$cosmosDBControlArray,$cosmosDBScore,$cosmosDBTotalWeight = Receive-Job -Job $job
            $CosmosDBResults += $tempCosmosDBResults
            $CosmosDBTotalScore += $cosmosDBScore
        }

        $CosmosDBTotalAvg = $CosmosDBTotalScore / ($cosmosDBTotalWeight * $CosmosDBAccounts.Count)
        $roundedCosmosDBTotalAvg = [math]::Round($CosmosDBTotalAvg, 1)

        $lateReport += "Total average score for all CosmosDB accounts in subscription $($sub.name) is $roundedCosmosDBTotalAvg %."
    }
    else {
        $CosmosDBResults += ""
        $CosmosDBResults += "No CosmosDB accounts found for subscription $($sub.name)."
        $CosmosDBResults += ""
    }

    $WAFResults += $CosmosDBResults

    # End region

    ###################### Region AKS ########################

    Write-Output "Checking AKS clusters for subscription $($sub.name)..."

    $AKSClusters = @()

    $AKSClusters += az aks list 2> $null | ConvertFrom-Json -Depth 10
    if (!$?) {
        Write-Error "Unable to retrieve AKS clusters for subscription $($sub.name)." -
        ErrorAction Continue
    }

    # Define controls for AKS
    $AKSControls = @(
        "Use availability zones to maximize resilience within an Azure region;Reliability;80"
        "Use Microsoft Entra integration;Security;90"
        "Authenticate with Microsoft Entra ID to Azure Container Registry;Security;90"
        "Secure network traffic to your API server with private AKS cluster;Security;90"
        "Protect the API server with Microsoft Entra RBAC;Security;90"
        "Use Azure network policies or Calico;Security;90"
        "Secure clusters and pods with Azure Policy;Security;90"
        "Secure container access to resources;Security;90"
        "Control cluster egress traffic;Security;90"
        "Use Microsoft Defender for Containers;Security;90"
        "Enable Cluster Autoscaler to automatically reduce the number of agent nodes in response to excess resource capacity;Cost Optimization,Performance Efficiency;80"
        "Enable Node Autoprovision to automate VM SKU selection;Cost Optimization;80"
        "Separate workloads into different node pools and consider scaling user node pools;Performance Efficiency;80"
        "Ensure that AKS clusters are using the latest available version of Kubernetes software;Security,Reliability;80"
        "Ensure that public access to Kubernetes API server is restricted;Security;90"
        "Ensure that AKS clusters are configured to use the Network Contributor role;Security;90"
        "Ensure that Azure Kubernetes clusters are using a private Key Vault for secret data encryption;Security;90"   
    )

    $AKSResults = @()
    $AKSResults += ""
    $AKSResults += "##############################"
    $AKSResults += "WAF Assessment Results for AKS"
    $AKSResults += "##############################"

    $AKSTotalAvg = 0
    $AKSTotalScore = 0

    $aksJobs = @()

    foreach ($aksCluster in $AKSClusters) {
            
        Write-Output "Checking AKS cluster $($aksCluster.name)..."

        $aksJobs += Start-Threadjob -ScriptBlock {
            
            $aksCluster = $using:aksCluster
            $tempAKSResults = @()

            $aksControlArray = @()

            $clusterDetails = az aks show --name $aksCluster.name --resource-group $aksCluster.resourceGroup 2> $null | ConvertFrom-Json -Depth 10

            foreach ($control in $using:AKSControls) {
                $aksCheck = $control.Split(';')
                $aksCheckName = $aksCheck[0]
                $aksCheckPillars = $aksCheck[1].Split(',')
                $aksCheckWeight = $aksCheck[2]
        
                $aksControlArray += [PSCustomObject]@{
                    Name = $aksCheckName
                    Pillars = $aksCheckPillars
                    Weight = $aksCheckWeight
                    Result = $null
                }
            }

            # Calculate total weight to calculate weighted average
            $aksTotalWeight = 0
            foreach ($control in $aksControlArray) {
                $aksTotalWeight += $control.Weight
            }

            $tempAKSResults += ""
            $tempAKSResults += "----- AKS Cluster - $($aksCluster.name) -----"
            $tempAKSResults += ""

            # Use availability zones to maximize resilience within an Azure region
            if ($aksCluster.agentPoolProfiles.availabilityZones) {
                $tempAKSResults += "Good: Availability zones are used to maximize resilience within an Azure region for AKS cluster $($aksCluster.name)"
                $aksControlArray[0].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Availability zones are NOT used to maximize resilience within an Azure region for AKS cluster $($aksCluster.name)"
                $aksControlArray[0].Result = 0
            }

            # Use Microsoft Entra integration
            if ($clusterDetails.aadProfile.tenantId) {
                $tempAKSResults += "Good: Microsoft Entra integration is used for AKS cluster $($aksCluster.name)"
                $aksControlArray[1].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Microsoft Entra integration is NOT used for AKS cluster $($aksCluster.name)"
                $aksControlArray[1].Result = 0
            }

            # Authenticate with Microsoft Entra ID to Azure Container Registry
            $acrEnabled = $false
            $acrs = az acr list 2> $null | ConvertFrom-Json -Depth 10
            if ($acrs) {
                foreach ($acr in $acrs) {
                    az aks check-acr --name $aksCluster.name --resource-group $aksCluster.resourceGroup --acr $acr.name 2> $null
                    if ($?) {
                        $acrEnabled = $true
                        $tempAKSResults += "Good: Microsoft Entra ID is used to authenticate with Azure Container Registry for AKS cluster $($aksCluster.name)"
                        $aksControlArray[2].Result = 100
                        break
                    }
                }
            }
            if (!$acrEnabled) {
                $tempAKSResults += "Bad: Microsoft Entra ID is NOT used to authenticate with Azure Container Registry for AKS cluster $($aksCluster.name)"
                $aksControlArray[2].Result = 0
            }

            # Secure network traffic to your API server with private AKS cluster
            if ($clusterDetails.apiServerAccessProfile.enablePrivateCluster -match "True") {
                $tempAKSResults += "Good: Network traffic to the API server is secured with a private AKS cluster for AKS cluster $($aksCluster.name)"
                $aksControlArray[3].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Network traffic to the API server is NOT secured with a private AKS cluster for AKS cluster $($aksCluster.name)"
                $aksControlArray[3].Result = 0
            }

            # Protect the API server with Microsoft Entra RBAC
            if ($clusterDetails.disableLocalAccounts -match "True") {
                $tempAKSResults += "Good: API server is protected with Microsoft Entra RBAC for AKS cluster $($aksCluster.name)"
                $aksControlArray[4].Result = 100
            }
            else {
                $tempAKSResults += "Bad: API server is NOT protected with Microsoft Entra RBAC for AKS cluster $($aksCluster.name)"
                $aksControlArray[4].Result = 0
            }

            # Use Azure network policies or Calico
            if ($clusterDetails.networkProfile.networkPolicy -match "Azure" -or $clusterDetails.networkProfile.networkPlugin -match "calico") {
                $tempAKSResults += "Good: Azure/Calico network policies are used for AKS cluster $($aksCluster.name)"
                $aksControlArray[5].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Azure/Calico network policies are NOT used for AKS cluster $($aksCluster.name)"
                $aksControlArray[5].Result = 0
            }

            # Secure clusters and pods with Azure Policy
            if ($clusterDetails.enablePodSecurityPolicy -match "True") {
                $tempAKSResults += "Good: Clusters and pods are secured with Azure Policy for AKS cluster $($aksCluster.name)"
                $aksControlArray[6].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Clusters and pods are NOT secured with Azure Policy for AKS cluster $($aksCluster.name)"
                $aksControlArray[6].Result = 0
            }

            # Secure container access to resources
            if ($clusterDetails.aadProfile.enableAzureRbac -match "True") {
                $tempAKSResults += "Good: Container access to resources is secured for AKS cluster $($aksCluster.name)"
                $aksControlArray[7].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Container access to resources is NOT secured for AKS cluster $($aksCluster.name)"
                $aksControlArray[7].Result = 0
            }

            # Control cluster egress traffic
            if ($clusterDetails.networkProfile.networkPlugin -match "azure") {
                $tempAKSResults += "Good: Cluster egress traffic is controlled for AKS cluster $($aksCluster.name)"
                $aksControlArray[8].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Cluster egress traffic is NOT controlled for AKS cluster $($aksCluster.name)"
                $aksControlArray[8].Result = 0
            }

            # Use Microsoft Defender for Containers
            if ($clusterDetails.securityProfile.defender) {
                $tempAKSResults += "Good: Microsoft Defender for Containers is used for AKS cluster $($aksCluster.name)"
                $aksControlArray[9].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Microsoft Defender for Containers is NOT used for AKS cluster $($aksCluster.name)"
                $aksControlArray[9].Result = 0
            }

            # Enable Cluster Autoscaler to automatically reduce the number of agent nodes in response to excess resource capacity
            if ($clusterDetails.autoScalerProfile.scaleDown) {
                $tempAKSResults += "Good: Cluster Autoscaler is enabled for AKS cluster $($aksCluster.name)"
                $aksControlArray[10].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Cluster Autoscaler is NOT enabled for AKS cluster $($aksCluster.name)"
                $aksControlArray[10].Result = 0
            }

            # Enable Node Autoprovision to automate VM SKU selection
            if ($clusterDetails.nodeProvisioningProfile.mode -match "auto") {
                $tempAKSResults += "Good: Node Autoprovision is enabled for AKS cluster $($aksCluster.name)"
                $aksControlArray[11].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Node Autoprovision is NOT enabled for AKS cluster $($aksCluster.name)"
                $aksControlArray[11].Result = 0
            }

            # Separate workloads into different node pools and consider scaling user node pools
            if ($clusterDetails.agentPoolProfiles.mode -match "User") {
                $tempAKSResults += "Good: Workloads are set to User mode and thus scaleable for AKS cluster $($aksCluster.name)"
                $aksControlArray[12].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Workloads are NOT set to User mode and thus not scaleable for AKS cluster $($aksCluster.name)"
                $aksControlArray[12].Result = 0
            }

            # Ensure that AKS clusters are using the latest available version of Kubernetes software
            $aksVersionStatus = az aks get-upgrades --name $aksCluster.name --resource-group $aksCluster.resourceGroup 2> $null | ConvertFrom-Json -Depth 10
            $latestVersion = $true
            foreach ($upgrade in $aksVersionStatus.controlPlaneProfile.upgrades) {
                if ($upgrade.kubernetesVersion -gt $aksVersionStatus.controlPlaneProfile.kubernetesVersion) {
                    $latestVersion = $false
                    break
                }
            }
            if ($latestVersion) {
                $tempAKSResults += "Good: AKS cluster is using the latest available version of Kubernetes software for AKS cluster $($aksCluster.name)"
                $aksControlArray[13].Result = 100
            }
            else {
                $tempAKSResults += "Bad: AKS cluster is NOT using the latest available version of Kubernetes software for AKS cluster $($aksCluster.name)"
                $aksControlArray[13].Result = 0
            }

            # Ensure that public access to Kubernetes API server is restricted
            if ($clusterDetails.apiServerAccessProfile.authorizedIpRanges) {
                $tempAKSResults += "Good: Public access to Kubernetes API server is restricted for AKS cluster $($aksCluster.name)"
                $aksControlArray[14].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Public access to Kubernetes API server is NOT restricted for AKS cluster $($aksCluster.name)"
                $aksControlArray[14].Result = 0
            }

            # Ensure that AKS clusters are configured to use the Network Contributor role
            $networkRole = az role assignment list --scope $aksCluster.id --role "Network Contributor" 2> $null
            if ($networkRole) {
                $tempAKSResults += "Good: AKS cluster is configured to use the Network Contributor role for AKS cluster $($aksCluster.name)"
                $aksControlArray[15].Result = 100
            }
            else {
                $tempAKSResults += "Bad: AKS cluster is NOT configured to use the Network Contributor role for AKS cluster $($aksCluster.name)"
                $aksControlArray[15].Result = 0
            }

            # Ensure that Azure Kubernetes clusters are using a private Key Vault for secret data encryption
            if ($clusterDetails.securityProfile.azureKeyVaultKms.keyvaultNetworkAccess -and $clusterDetails.securityProfile.azureKeyVaultKms.keyvaultNetworkAccess -notmatch "Public") {
                $tempAKSResults += "Good: Azure Kubernetes clusters are using a private Key Vault for secret data encryption for AKS cluster $($aksCluster.name)"
                $aksControlArray[16].Result = 100
            }
            else {
                $tempAKSResults += "Bad: Azure Kubernetes clusters are NOT using a private Key Vault for secret data encryption for AKS cluster $($aksCluster.name)"
                $aksControlArray[16].Result = 0
            }

            # Calculate the weighted average for the AKS cluster
            $aksScore = $aksControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $aksAvgScore = $aksScore / $aksTotalWeight
            $roundedAKSAvg = [math]::Round($aksAvgScore, 1)

            $tempAKSResults += ""
            $tempAKSResults += "AKS cluster $($aksCluster.name) has an average score of $roundedAKSAvg %."

            $tempAKSResults,$aksControlArray,$aksScore,$aksTotalWeight
        }
    }

    if ($AKSClusters.Count -gt 0) {
        Write-Output "Waiting for AKS checks to complete..."

        foreach ($job in ($aksJobs | Wait-Job)) {
            $tempAKSResults,$aksControlArray,$aksScore,$aksTotalWeight = Receive-Job -Job $job
            $AKSResults += $tempAKSResults
            $AKSTotalScore += $aksScore
        }

        $AKSTotalAvg = $AKSTotalScore / ($aksTotalWeight * $AKSClusters.Count)
        $roundedAKSTotalAvg = [math]::Round($AKSTotalAvg, 1)

        $lateReport += "Total average score for all AKS clusters in subscription $($sub.name) is $roundedAKSTotalAvg %."
    }
    else {
        $AKSResults += ""
        $AKSResults += "No AKS clusters found for subscription $($sub.name)."
        $AKSResults += ""
    }

    $WAFResults += $AKSResults

    # End region

    ################# Region Azure OpenAI ####################

    Write-Output "Checking Azure OpenAI resources for subscription $($sub.name)..."

    $OpenAIResources = @()

    $OpenAIResources += az cognitiveservices account list 2> $null | ConvertFrom-Json -Depth 10 | Where-Object { $_.kind -match "OpenAI" }
    if (!$?) {
        Write-Error "Unable to retrieve Azure OpenAI resources for subscription $($sub.name)." -
        ErrorAction Continue
    }

    # Define controls for Azure OpenAI
    $OpenAIControls = @(
        "Disable public access to Azure OpenAI unless your workload requires it;Security;90"
        "Use customer-managed keys for fine-tuned models and training data that's uploaded to Azure OpenAI;Security;80"
        "Enable and configure Diagnostics for the Azure OpenAI Service;Operational Excellence;80"
        "Ensure that Azure OpenAI service instances don't have administrative privileges;Custom;90"
    )

    $OpenAIResults = @()
    $OpenAIResults += ""
    $OpenAIResults += "#######################################"
    $OpenAIResults += "WAF Assessment Results for Azure OpenAI"
    $OpenAIResults += "#######################################"

    $OpenAITotalAvg = 0
    $OpenAITotalScore = 0

    $openAIJobs = @()

    foreach ($openAIResource in $OpenAIResources) {
            
        Write-Output "Checking Azure OpenAI resource $($openAIResource.name)..."

        $openAIJobs += Start-Threadjob -ScriptBlock {
            
            $openAIResource = $using:openAIResource
            $tempOpenAIResults = @()

            $openAIDetails = az cognitiveservices account show --name $openAIResource.name --resource-group $openAIResource.resourceGroup 2> $null | ConvertFrom-Json -Depth 10

            $openAIControlArray = @()

            foreach ($control in $using:OpenAIControls) {
                $openAICheck = $control.Split(';')
                $openAICheckName = $openAICheck[0]
                $openAICheckPillars = $openAICheck[1].Split(',')
                $openAICheckWeight = $openAICheck[2]
        
                $openAIControlArray += [PSCustomObject]@{
                    Name = $openAICheckName
                    Pillars = $openAICheckPillars
                    Weight = $openAICheckWeight
                    Result = $null
                }
            }

            # Calculate total weight to calculate weighted average
            $openAITotalWeight = Get-TotalWeights($openAIControlArray)

            $tempOpenAIResults += ""
            $tempOpenAIResults += "----- Azure OpenAI Resource - $($openAIResource.name) -----"
            $tempOpenAIResults += ""

            # Disable public access to Azure OpenAI unless your workload requires it
            if ($openAIResource.properties.publicNetworkAccess -match "Disabled") {
                $tempOpenAIResults += "Good: Public access to Azure OpenAI is disabled for OpenAI resource $($openAIResource.name)"
                $openAIControlArray[0].Result = 100
            }
            else {
                $tempOpenAIResults += "Bad: Public access to Azure OpenAI is NOT disabled for OpenAI resource $($openAIResource.name)"
                $openAIControlArray[0].Result = 0
            }

            # Use customer-managed keys for fine-tuned models and training data that's uploaded to Azure OpenAI
            if ($openAIDetails.properties.encryption.keyVaultProperties.keyName) {
                $tempOpenAIResults += "Good: Customer-managed keys are used for fine-tuned models and training data that's uploaded to Azure OpenAI for OpenAI resource $($openAIResource.name)"
                $openAIControlArray[1].Result = 100
            }
            else {
                $tempOpenAIResults += "Bad: Customer-managed keys are NOT used for fine-tuned models and training data that's uploaded to Azure OpenAI for OpenAI resource $($openAIResource.name)"
                $openAIControlArray[1].Result = 0
            }

            # Enable and configure Diagnostics for the Azure OpenAI Service
            $openAIDiagnostics = az monitor diagnostic-settings list --resource $openAIResource.id 2> $null | ConvertFrom-Json -Depth 10
            if ($openAIDiagnostics.type -match "Microsoft.Insights/diagnosticSettings") {
                $tempOpenAIResults += "Good: Diagnostics are enabled and configured for the Azure OpenAI Service for OpenAI resource $($openAIResource.name)"
                $openAIControlArray[2].Result = 100
            }
            else {
                $tempOpenAIResults += "Bad: Diagnostics are NOT enabled and configured for the Azure OpenAI Service for OpenAI resource $($openAIResource.name)"
                $openAIControlArray[2].Result = 0
            }

            # Ensure that Azure OpenAI service instances don't have administrative privileges
            $openAIControlArray[3].Result = 100
            $openAIIdentity = az cognitiveservices account identity show --name $openAIResource.name --resource-group $openAIResource.resourceGroup 2> $null | ConvertFrom-Json -Depth 10
            foreach ($identity in $openAIIdentity) {
                if ($openAIIdentity.type -match "SystemAssigned") {
                    Continue
                }
                else {
                    $roles = az role assignment list --assignee $identity.principalId --all 2> $null | ConvertFrom-Json -Depth 10
                    if ($roles.roleDefinitionName -eq "Owner" -or $roles.roleDefinitionName -eq "Contributor" -or $roles.roleDefinitionName -eq "User Access Administrator" -or $roles.roleDefinitionName -eq "Role Based Access Control Administrator") {
                        $openAIControlArray[3].Result = 0
                    }
                    else {
                        Continue
                    }
                }
            }

            if ($openAIControlArray[3].Result -eq 100) {
                $tempOpenAIResults += "Good: Azure OpenAI service instances don't have administrative privileges for OpenAI resource $($openAIResource.name)"
            }
            else {
                $tempOpenAIResults += "Bad: Azure OpenAI service instances have administrative privileges for OpenAI resource $($openAIResource.name)"
            }
            # Calculate the weighted average for the Azure OpenAI resource
            $openAIScore = $openAIControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            $openAIAvgScore = $openAIScore / $openAITotalWeight
            $roundedOpenAIAvg = [math]::Round($openAIAvgScore, 1)

            $tempOpenAIResults += ""
            $tempOpenAIResults += "Azure OpenAI resource $($openAIResource.name) has an average score of $roundedOpenAIAvg %."

            $tempOpenAIResults,$openAIControlArray,$openAIScore,$openAITotalWeight
        }
    }

    if ($OpenAIResources.Count -gt 0) {
        Write-Output "Waiting for Azure OpenAI checks to complete..."

        foreach ($job in ($openAIJobs | Wait-Job)) {
            $tempOpenAIResults,$openAIControlArray,$openAIScore,$openAITotalWeight = Receive-Job -Job $job
            $OpenAIResults += $tempOpenAIResults
            $OpenAITotalScore += $openAIScore
        }

        $OpenAITotalAvg = $OpenAITotalScore / ($openAITotalWeight * $OpenAIResources.Count)
        $roundedOpenAITotalAvg = [math]::Round($OpenAITotalAvg, 1)

        $lateReport += "Total average score for all Azure OpenAI resources in subscription $($sub.name) is $roundedOpenAITotalAvg %."
    }
    else {
        $OpenAIResults += ""
        $OpenAIResults += "No Azure OpenAI resources found for subscription $($sub.name)."
        $OpenAIResults += ""
    }

    $WAFResults += $OpenAIResults

    # End region

    ############### Region Score by Pillars ##################

    $allWeightedAverages = @()

    # Get all weighted averages for each service
    if ($strgControlArray) {
        $allStrgWeightedAverages = Get-AllWeightedAveragesPerService($strgControlArray)
        foreach ($strgWeightedAverage in $allStrgWeightedAverages) {
            $allWeightedAverages += $strgWeightedAverage
        }
    }

    if ($kvControlArray) {
        $allKvWeightedAverages = Get-AllWeightedAveragesPerService($kvControlArray)
        foreach ($kvWeightedAverage in $allKvWeightedAverages) {
            $allWeightedAverages += $kvWeightedAverage
        }
    }

    if ($vmControlArray) {
        $allVmWeightedAverages = Get-AllWeightedAveragesPerService($vmControlArray)
        foreach ($vmWeightedAverage in $allVmWeightedAverages) {
            $allWeightedAverages += $vmWeightedAverage
        }
    }

    if ($appServiceControlArray) {
        $allAppServiceWeightedAverages = Get-AllWeightedAveragesPerService($appServiceControlArray)
        foreach ($appServiceWeightedAverage in $allAppServiceWeightedAverages) {
            $allWeightedAverages += $appServiceWeightedAverage
        }
    }

    if ($postgreSQLControlArray) {
        $allPostgreSQLWeightedAverages = Get-AllWeightedAveragesPerService($postgreSQLControlArray)
        foreach ($postgreSQLWeightedAverage in $allPostgreSQLWeightedAverages) {
            $allWeightedAverages += $postgreSQLWeightedAverage
        }
    }

    if ($CosmosDBControlArray) {
        $allCosmosDBWeightedAverages = Get-AllWeightedAveragesPerService($cosmosDBControlArray)
        foreach ($cosmosDBWeightedAverage in $allCosmosDBWeightedAverages) {
            $allWeightedAverages += $cosmosDBWeightedAverage
        }
    }

    if ($AKSControlArray) {
        $allAKSWeightedAverages = Get-AllWeightedAveragesPerService($aksControlArray)
        foreach ($aksWeightedAverage in $allAKSWeightedAverages) {
            $allWeightedAverages += $aksWeightedAverage
        }
    }

    if ($OpenAIControlArray) {
        $allOpenAIWeightedAverages = Get-AllWeightedAveragesPerService($openAIControlArray)
        foreach ($openAIWeightedAverage in $allOpenAIWeightedAverages) {
            $allWeightedAverages += $openAIWeightedAverage
        }
    }

    $finalAverageArray = @(
        [PSCustomObject]@{
            Pillar = "Reliability Pillar"
            Count = 0
            Average = 0
        }
        [PSCustomObject]@{
            Pillar = "Security Pillar"
            Count = 0
            Average = 0
        }
        [PSCustomObject]@{
            Pillar = "Operational Excellence Pillar"
            Count = 0
            Average = 0
        }
        [PSCustomObject]@{
            Pillar = "Cost Optimization Pillar"
            Count = 0
            Average = 0
        }
        [PSCustomObject]@{
            Pillar = "Performance Efficiency Pillar"
            Count = 0
            Average = 0
        }
        [PSCustomObject]@{
            Pillar = "Custom Checks"
            Count = 0
            Average = 0
        }
    )

    # Loop through all weighted averages to get a count for each pillar
    foreach ($weightedAverage in $allWeightedAverages) {
        $pillar = $weightedAverage.Split(';')[0]
        $average = $weightedAverage.Split(';')[1]

        foreach ($pillarCount in $finalAverageArray) {
            if ($pillarCount.Pillar -match $pillar) {
                $pillarCount.Count++
                $pillarCount.Average += $average
            }
        }
    }

    # Calculate the final average for each pillar
    foreach ($finalAverage in $finalAverageArray) {
        if ($finalAverage.Count -gt 0) {
            $finalAverage.Average = [math]::Round($finalAverage.Average / $finalAverage.Count, 1)
        }
    }

    $WAFResults += ""
    $WAFResults += "##################"
    $WAFResults += "Summary of results"
    $WAFResults += "##################"
    $WAFResults += ""
    $WAFResults += $lateReport
    $WAFResults += ""
    $WAFResults += "Final Weighted Average by Pillar"
    $WAFResults += ""
    foreach ($finalAverage in $finalAverageArray) {
        $WAFResults += "$($finalAverage.Pillar) has an average score of $($finalAverage.Average) %."
    }
    $WAFResults += ""
    $WAFResults += "Note that a score of 0 % may indicate that the evaluated resources have no related checks in that pillar."
    $WAFResults += "The Custom Checks section is not part of the Microsoft WAF, and is used for additional checks."
    $WAFResults += ""

    # End region

    ################# Region Outputs #####################

    # This script currently writes results to the terminal, and optionally creates a txt log file in the results folder
    
    if ($OutputToFile) {
        $WAFResults | Out-File -FilePath ( New-Item -Path ".\results\$($sub.name).txt" -Force )
    }

    Write-Output $WAFResults

    Write-Output "Results may be truncated if they do not fit in the terminal. For full results, please check the output file."

    $Error > ".\results\errors.txt"

    # End region
}