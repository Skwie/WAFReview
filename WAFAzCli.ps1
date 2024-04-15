<#
.SYNOPSIS
  Performs an Azure Well-Architected Framework assessment for one or more subscriptions

.DESCRIPTION
  This script makes an inventory of specific or all fscp 3.0 subscriptions, and runs AZ CLI commands against those subscriptions to determine if resources in those subscriptions are in line with the Microsoft Azure Well-Architected Framework.

.PARAMETER <SubscriptionIds>
  Optional. An array of IDs for the subscriptions that you want to assess. If no SubscriptionId is entered, the script runs for all subscriptions.
  Example: @('b6307584-2248-4e8b-a911-2d7f1bd2613a', 'c405e642-15db-4786-9426-1e23c84d225a')

.PARAMETER <ProdOnly>
  Optional. If ProdOnly is true, the script will only evaluate production subscriptions. Note that this param is not evaluated if the SubscriptionIds param is filled.
  By default, this script runs only for production workloads.

.PARAMETER <OutputToFile>
  Optional. If OutputToFile is true, the script will output the results to a file in the results folder.
    
.OUTPUTS
  The script progressively writes results to the terminal. After performing all checks it should also output a file per subscription listing all controls and scores.
  Possible ToDo is to make the file output compatible with the Microsoft powerpoint generation script.

.NOTES
  Version:        0.1
  Author:         Jordy Groenewoud
  Creation Date:  27/03/2024
  
.EXAMPLE
  .\WAFAzCli.ps1 -ProdOnly $True -OutputToFile $True

#>


[CmdletBinding()]
param
(
    [Parameter(Mandatory=$false)]
    [Array]$SubscriptionIds,

    [Parameter(Mandatory=$false)]
    $ProdOnly = $true,

    [Parameter(Mandatory=$false)]
    $OutputToFile = $false
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

if (!$SubscriptionIds) {
    # Only retrieve FSCP 3.0 subscriptions.
    if ($ProdOnly) {
        $AllSubscriptions = $azsession | ConvertFrom-Json -Depth 10 | Select-Object name, id | Where-Object {$_.name -Match 'p-lz'}
    }
    else {
        $AllSubscriptions = $azsession | ConvertFrom-Json -Depth 10 | Select-Object name, id | Where-Object {$_.name -Match '-lz'}
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

    $WAFResults = @()
    $lateReport = @()
    $WAFResults += "#################################################################################"
    $WAFResults += "WAF Assessment results for subscription $($sub.name)"
    $WAFResults += "#################################################################################"
    $WAFResults += ""

    ############## Region Storage Accounts ##################
    try {
        $StorageAccounts = az storage account list 2> $null | ConvertFrom-Json -Depth 10
    }
    catch {
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

    foreach ($strg in $StorageAccounts) {

        $strgControlArray = @()

        foreach ($control in $StorageControls) {
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
        $strgTotalWeight = Get-TotalWeights($strgControlArray)

        $StorageResults += ""
        $StorageResults += "----- Storage Account - $($strg.name) -----"
        $StorageResults += ""
        
        # Turn on soft delete for blob data
        try {
            $BlobProperties = az storage account blob-service-properties show --account-name $strg.name 2> $null 
            $RetentionPolicy = $BlobProperties | ConvertFrom-Json -Depth 10 | Select-Object deleteRetentionPolicy
        }
        catch {
            Write-Error "Unable to check blob data retention settings for storage account $($strg.name)."
        }
        if ($RetentionPolicy.deleteRetentionPolicy.enabled) {
            $StorageResults += "Good: Soft Delete is active for $($strg.name)"
            $strgControlArray[0].Result = 100
        }
        else {
            $StorageResults += "Bad: Soft Delete is NOT active for $($strg.name)"
            $strgControlArray[0].Result = 0
        }
        $RetentionPolicy = $null

        # Use Microsoft Entra ID to authorize access to blob data
        if ($strg.allowBlobPublicAccess -match 'False') {
            $StorageResults += "Good: Public access is disabled for blob data on storage account $($strg.name)."
            $strgControlArray[1].Result = 100
        }
        else {
            $StorageResults += "Bad: Public access is ENABLED for blob data on storage account $($strg.name)."
            $strgControlArray[1].Result = 0
        }

        # Consider the principle of least privilege when you assign permissions to a Microsoft Entra security principal through Azure RBAC.
        ## This control is ambiguous. What exactly do we check for here? Needs to be discussed.

        # Use managed identities to access blob and queue data.
        ## Also ambiguous. Do we alert on users being assigned access to storage accounts?

        # Use blob versioning or immutable blobs to store business-critical data.
        ## Unable to query immutability due to this information being stored on container level, requiring a connection string, storage account key or SAS token.
        if (($BlobProperties | ConvertFrom-Json -Depth 10).isVersioningEnabled) {
            $StorageResults += "Good: Versioning is enabled for storage account $($strg.name)."
            $strgControlArray[2].Result = 100
        }
        else {
            $StorageResults += "Informational: Versioning is not enabled for storage account $($strg.name). Immutability might be enabled on container level, but can not be checked."
            $strgControlArray[2].Result = 50
        }
        #az storage container list --account-name $strg.name --query '[*].{"ContainerName":name, "TimeBasedRetentionPolicy":properties.hasImmutabilityPolicy, "LegalHoldPolicy": properties.hasLegalHold}'

        # Restrict default internet access for storage accounts.
        if ($strg.networkRuleSet.defaultAction -match 'Deny') {
            $StorageResults += "Good: Default internet access for storage account $($strg.name) is set to Deny."
            $strgControlArray[3].Result = 100
        }
        else {
            $StorageResults += "Bad: Default internet access for storage account $($strg.name) is NOT set to Deny."
            $strgControlArray[3].Result = 0
        }

        # Enable firewall rules.
        if ($strg.networkRuleSet) {
            $StorageResults += "Good: Firewall is active for storage account $($strg.name)."
            $strgControlArray[4].Result = 100
        }
        else {
            $StorageResults += "Bad: Firewall is NOT active for storage account $($strg.name)."
            $strgControlArray[4].Result = 0
        }

        # Limit network access to specific networks.
        if ($strg.allowBlobPublicAccess -match 'False') {
            $StorageResults += "Good: Blob Public Access is disabled for storage account $($strg.name)."
            $strgControlArray[5].Result = 100
        }
        else {
            $StorageResults += "Bad: Blob Public Access is NOT disabled for storage account $($strg.name)."
            $strgControlArray[5].Result = 0
        }

        # Allow trusted Microsoft services to access the storage account.
        if ($strg.networkRuleSet.bypass -match 'AzureServices') {
            $StorageResults += "Good: Microsoft Azure Services are whitelisted for storage account $($strg.name)."
            $strgControlArray[6].Result = 100
        }
        else {
            $StorageResults += "Bad: Microsoft Azure Services are NOT whitelisted for storage account $($strg.name)."
            $strgControlArray[6].Result = 0
        }

        # Enable the Secure transfer required option on all your storage accounts.
        if ($strg.enableHttpsTrafficOnly -match 'True') {
            $StorageResults += "Good: Secure Transfer (HTTPS) is enforced for storage account $($strg.name)."
            $strgControlArray[7].Result = 100
        }
        else {
            $StorageResults += "Bad: Secure Transfer (HTTPS) is NOT enforced for storage account $($strg.name)."
            $strgControlArray[7].Result = 0
        }

        # Limit shared access signature (SAS) tokens to HTTPS connections only.
        ## This can not be evaluated. It is set when a SAS token is generated, and can not be retrieved anymore after that point.
        ## Conformity mentions this as well in their documentation: https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/StorageAccounts/shared-access-signature-tokens-are-allowed-only-over-https.html

        # Avoid and prevent using Shared Key authorization to access storage accounts.
        if ($strg.allowSharedKeyAccess -match 'False') {
            $StorageResults += "Good: Shared Key authorization is disabled for storage account $($strg.name)."
            $strgControlArray[8].Result = 100
        }
        else {
            $StorageResults += "Bad: Shared Key authorization is NOT disabled for storage account $($strg.name)."
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
            $StorageResults += "Good: Storage account keys have been regenerated in the past 90 days for storage account $($strg.name)."
            $strgControlArray[9].Result = 100
        }
        else {
            $StorageResults += "Bad: Storage account keys have NOT been regenerated in the past 90 days for storage account $($strg.name)."
            $strgControlArray[9].Result = 0
            # NOTE: Every storage account currently returns this. It is still unclear whether the query does not return the correct results, or storage keys are not regenerated on any ABN storage account.
        }

        # Create a revocation plan and have it in place for any SAS that you issue to clients.
        ## This control describes a process, not an Azure resource.

        # Use near-term expiration times on an impromptu SAS, service SAS, or account SAS.
        ## This can not be evaluated. It is set when a SAS token is generated, and can not be retrieved anymore after that point.
        ## Conformity mentions this as well in their documentation: https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/StorageAccounts/shared-access-signature-tokens-expire-within-an-hour.html

        # Enable Azure Defender for all your storage accounts.
        if ($DefenderActive) {
            $StorageResults += "Good: Defender for Storage is enabled for storage account $($strg.name)."
            $strgControlArray[10].Result = 100
        }
        else {
            $StorageResults += "Bad: Defender for Storage is NOT enabled for storage account $($strg.name)."
            $strgControlArray[10].Result = 0
        }

        # Consider cost savings by reserving data capacity for block blob storage.
        ## This requires access to the container where the blob is stored, requiring a connection string, storage account key or SAS token.

        # Organize data into access tiers.
        if ($strg.accessTier -match 'Hot') {
            $StorageResults += "Informational: Storage account $($strg.name) has an access tier of 'Hot'. Depending on usage demand, costs could be reduced by choosing a lower tier."
            $strgControlArray[11].Result = 100
        }
        else {
            $StorageResults += "Informational: Storage account $($strg.name) has an access tier of '$($strg.accessTier)'."
            $strgControlArray[11].Result = 100
        }
        
        # Use lifecycle policy to move data between access tiers.
        $policy = az storage account management-policy show --account-name $strg.name --resource-group $strg.resourceGroup 2> $null | ConvertFrom-Json -Depth 10
        if (($BlobProperties | ConvertFrom-Json -Depth 10).lastAccessTimeTrackingPolicy) {
            $StorageResults += "Good: Last access time tracking Lifecycle policy found for storage account $($strg.name)."
            $strgControlArray[12].Result = 100
        }
        elseif ($policy) {
            if ($policy.policy.rules.type -match 'Lifecycle') {
                $StorageResults += "Good: Data deletion Lifecycle policy found for storage account $($strg.name)."
                $strgControlArray[12].Result = 100
            }
        }
        else {
            $StorageResults += "Bad: No Lifecycle policy found for storage account $($strg.name)."
            $strgControlArray[12].Result = 0
        }
        $policy = $null

        ## Extra checks ##

        $StorageResults += ""
        $StorageResults += "Extra checks"
        $StorageResults += ""

        # Check for Publicly Accessible Web Containers
        ## Unable to query due to this information being stored on container level, requiring a connection string, storage account key or SAS token.
        #az storage container show --account-name $strg.name --name insights-operational-logs --query 'properties.publicAccess'

        # Configure Minimum TLS Version
        if ($strg.minimumTlsVersion -match 'TLS1_2') {
            $StorageResults += "Good: TLS 1.2 is the minimum TLS version allowed on storage account $($strg.name)."
            $strgControlArray[13].Result = 100
        }
        else {
            $StorageResults += "Bad: The minimum version is NOT set to TLS 1.2 on storage account $($strg.name)."
            $strgControlArray[13].Result = 0
        }

        # Enable Infrastructure Encryption
        $EncryptStatus = az storage account show --name $strg.name --query '{"requireInfrastructureEncryption":encryption.requireInfrastructureEncryption}' 2> $null | ConvertFrom-Json -Depth 10
        if ($EncryptStatus.requireInfrastructureEncryption -match $True) {
            $StorageResults += "Good: Storage Account Infrastructure Encryption is enabled for storage account $($strg.name)."
            $strgControlArray[14].Result = 100
        }
        else {
            $StorageResults += "Bad: Storage Account Infrastructure Encryption is NOT enabled for storage account $($strg.name)."
            $strgControlArray[14].Result = 0
        }

        # Private Endpoint in Use
        $pep = az storage account show --name $strg.name --query 'privateEndpointConnections' 2> $null
        if ($pep -match '\[\]') {
            $StorageResults += "Bad: No Private Endpoint attached to storage account $($strg.name)."
            $strgControlArray[15].Result = 0
        }
        else {
            $StorageResults += "Good: A Private Endpoint is attached to storage account $($strg.name)."
            $strgControlArray[15].Result = 100
        }

        # Storage Account Encryption using Customer Managed Keys
        if (az storage account show --name $strg.name --query 'encryption.keyVaultProperties.keyName' 2> $null) {
            $StorageResults += "Good: Storage account $($strg.name) is encrypted using Customer Managed Keys."
            $strgControlArray[16].Result = 100
        }
        else {
            $StorageResults += "Bad: Storage account $($strg.name) is NOT encrypted using Customer Managed Keys."
            $strgControlArray[16].Result = 0
        }

        # Calculate the weighted average for the storage account
        $storageScore = $strgControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        $storageAvgScore = $storageScore / $strgTotalWeight
        $roundedStorageAvg = [math]::Round($storageAvgScore, 1)

        $StorageResults += ""
        $StorageResults += "Storage Account $($strg.name) has an average score of $roundedStorageAvg %."
        $StorageResults += ""

        $storageTotalScore += $storageScore
    }

    $storageTotalAvg = $storageTotalScore / ($strgTotalWeight * $StorageAccounts.Count)
    $roundedStorageTotalAvg = [math]::Round($storageTotalAvg, 1)

    $lateReport += "Total average score for all storage accounts in subscription $($sub.name) is $roundedStorageTotalAvg %."

    if (!$StorageAccounts) {
        $StorageResults += "No storage accounts found for subscription $($sub.name)."
        $StorageResults += ""
    }

    $WAFResults += $StorageResults
    
    # End region

    ################# Region Key Vaults #####################

    try {
        $Keyvaults = az keyvault list 2> $null | ConvertFrom-Json -Depth 10
    }
    catch {
        Write-Error "Unable to retrieve storage accounts for subscription $($sub.name)." -ErrorAction Continue
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

    # Note: There are no controls described for Key Vaults in the Microsoft WAF documentation.
    # We will primarily be using the Conformity checks, as well as IT Guardrail checks.
    
    foreach ($keyvault in $Keyvaults) {

        $kvControlArray = @()

        foreach ($control in $KeyvaultControls) {
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
        $kvTotalWeight = Get-TotalWeights($kvControlArray)

        $VaultResults += ""
        $VaultResults += "----- Key Vault - $($keyvault.name) -----"
        $VaultResults += ""

        # Check for presence of AppName tag
        if ($keyvault.tags.AppName) {
            $VaultResults += "Good: AppName tag is present on Key Vault $($keyvault.name)"
            $kvControlArray[0].Result = 100
        }
        else {
            $VaultResults += "Bad: AppName tag is NOT present on Key Vault $($keyvault.name)"
            $kvControlArray[0].Result = 0
        }

        # Check for presence of CI tag
        if ($keyvault.tags.'Business Application CI') {
            $VaultResults += "Good: Application CI tag is present on Key Vault $($keyvault.name)"
            $kvControlArray[1].Result = 100
        }
        else {
            $VaultResults += "Bad: Application CI tag is NOT present on Key Vault $($keyvault.name)"
            $kvControlArray[1].Result = 0
        }

        # Check for presence of CIA tag
        if ($keyvault.tags.CIA) {
            $VaultResults += "Good: CIA tag is present on Key Vault $($keyvault.name)"
            $kvControlArray[2].Result = 100
        }
        else {
            $VaultResults += "Bad: CIA tag is NOT present on Key Vault $($keyvault.name)"
            $kvControlArray[2].Result = 0
        }

        # Check for Key Vault Full Administrator Permissions
        $perms = az keyvault show --name $keyvault.name --query 'properties.accessPolicies[*].{"PrincipalId":objectId, "permissions":permissions}' | ConvertFrom-Json -Depth 10
        if ('All' -in $perms.permissions.certificates -or 'All' -in $perms.permissions.keys -or 'All' -in $perms.permissions.secrets -or 'All' -in $perms.permissions.storage) {
            $VaultResults += "Bad: Full access permissions found on keyvault $($keyvault.name):"
            foreach ($perm in $perms) {
                if ('All' -in $perm.permissions.certificates -or 'All' -in $perm.permissions.keys -or 'All' -in $perm.permissions.secrets -or 'All' -in $perm.permissions.storage) {
                    $VaultResults += "Principal with ID $($perm.PrincipalId) has Full Access on one or all of Certificates/Keys/Secrets/Storage."
                }
            }
            $kvControlArray[3].Result = 0
        }
        else {
            $VaultResults += "Good: No Full Access permissions found on keyvault $($keyvault.name)"
            $kvControlArray[3].Result = 100
        }

        # Audit event logging should be active for Azure Key Vault
        $diag = az monitor diagnostic-settings list --resource $keyvault.id --query '[*].logs | []' | ConvertFrom-Json -Depth 10
        if (($diag | Where-Object {$_.category -eq 'AuditEvent'}).enabled -eq $True) {
            $VaultResults += "Good: Audit Events are logged for keyvault $($keyvault.name)."
            $kvControlArray[4].Result = 100
        }
        else {
            $VaultResults += "Bad: Audit Events are NOT logged for keyvault $($keyvault.name)."
            $kvControlArray[4].Result = 0
        }

        # Purge Protection should be enabled for Azure Key Vault
        $vaultsettings = az keyvault show --name $keyvault.name | ConvertFrom-Json -Depth 10
        if ($vaultsettings.properties.enablePurgeProtection -eq 'True') {
            $VaultResults += "Good: Purge Protection is enabled for keyvault $($keyvault.name)"
            $kvControlArray[5].Result = 100
        }
        else {
            $VaultResults += "Bad: Purge Protection is NOT enabled for keyvault $($keyvault.name)"
            $kvControlArray[5].Result = 0
        }

        # Soft Delete should be enabled for Azure Key Vault
        if ($vaultsettings.properties.enableSoftDelete -eq 'True') {
            $VaultResults += "Good: Soft Delete is enabled for keyvault $($keyvault.name)"
            $kvControlArray[6].Result = 100
        }
        else {
            $VaultResults += "Bad: Soft Delete is NOT enabled for keyvault $($keyvault.name)"
            $kvControlArray[6].Result = 0
        }

        # Allow trusted Microsoft services to access the Key Vault
        if ($vaultsettings.properties.networkAcls.bypass -match 'AzureServices') {
            $VaultResults += "Good: Microsoft Azure services are whitelisted for $($keyvault.name)"
            $kvControlArray[7].Result = 100
        }
        else {
            $VaultResults += "Bad: Microsoft Azure services are NOT whitelisted for $($keyvault.name)"
            $kvControlArray[7].Result = 0
        }

        # Restrict Default Network Access for Azure Key Vaults
        if ($vaultsettings.properties.networkAcls.defaultAction -match 'Deny') {
            $VaultResults += "Good: Network access is denied by default for $($keyvault.name)"
            $kvControlArray[8].Result = 100
        }
        else {
            $VaultResults += "Bad: Network access is NOT denied by default for $($keyvault.name)"
            $kvControlArray[8].Result = 0
        }

        # Calculate the weighted average for the key vault
        $kvScore = $kvControlArray | ForEach-Object { $_.Result * $_.Weight } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        $kvAvgScore = $kvScore / $kvTotalWeight
        $roundedKvAvg = [math]::Round($kvAvgScore, 1)

        $VaultResults += ""
        $VaultResults += "Key Vault $($keyvault.name) has an average score of $roundedKvAvg %."
        $VaultResults += ""

    }

    $kvTotalAvg = $kvScore / ($kvTotalWeight * $Keyvaults.Count)
    $roundedKvTotalAvg = [math]::Round($kvTotalAvg, 1)

    $lateReport += "Total average score for all key vaults in subscription $($sub.name) is $roundedKvTotalAvg %."

    $WAFResults += $VaultResults

    # End region

    ################# Region Virtual Machines #####################

    # For Virtual Machines we currently assume that VM Scale Sets are not used, and that all VMs are standalone.

    try {
        $VirtualMachines = az vm list 2> $null | ConvertFrom-Json -Depth 10
    }
    catch {
        Write-Error "Unable to retrieve virtual machines for subscription $($sub.name)." -ErrorAction Continue
    }

    $VMControls = @(
        "Check for presence of AppName tag;Security;80"
        "Check for presence of CI tag;Security;80"
        "Check for presence of CIA tag;Security;80"
        "Restrict public IP addresses for Azure Virtual Machines;Security;80"
        "Restrict IP forwarding for Azure Virtual Machines;Security;80"
        "Check if VM network interfaces have a Network Security Group attached;Security;80"
        "Restrict public network access to Azure Virtual Machines;Security;80"
        "Enable Azure Disk Encryption for Azure Virtual Machines;Security;90"
        "Enable Endpoint Protection for Azure Virtual Machines;Security;90"
        "Enable Hybrid Benefit for Azure Virtual Machines;Cost Optimization;60"
        "Enable automatic upgrades for extensions on Azure Virtual Machines;Operational Excellence;70"
        "Enable Azure Monitor for Azure Virtual Machines;Operational Excellence;70"
        "Enable VM Insights for Azure Virtual Machines;Operational Excellence;70"
        "Enable boot diagnostics for Azure Virtual Machines;Operational Excellence;70"
        "Enable accelerated networking for Azure Virtual Machines;Performance Efficiency;70"
    )



    # End region

    ############# Region Score by Pillars ################

    $allWeightedAverages = @()
    $allStrgWeightedAverages = @()
    $allKvWeightedAverages = @()

    $strgReliabilityScores = @()
    $strgSecurityScores = @()
    $strgOperationalExcellenceScores = @()
    $strgCostOptimizationScores = @()
    $strgPerformanceEfficiencyScores = @()
    $strgCustomScores = @()
    $kvReliabilityScores = @()
    $kvSecurityScores = @()
    $kvOperationalExcellenceScores = @()
    $kvCostOptimizationScores = @()
    $kvPerformanceEfficiencyScores = @()
    $kvCustomScores = @()

    if ($StorageAccounts) {
        foreach ($contr in $strgControlArray) {
            if ($contr.Pillars -contains 'Reliability') {$strgReliabilityScores += $contr}
            if ($contr.Pillars -contains 'Security') {$strgSecurityScores += $contr}
            if ($contr.Pillars -contains 'Operational Excellence') {$strgOperationalExcellenceScores += $contr}
            if ($contr.Pillars -contains 'Cost Optimization') {$strgCostOptimizationScores += $contr}
            if ($contr.Pillars -contains 'Performance Efficiency') {$strgPerformanceEfficiencyScores += $contr}
            if ($contr.Pillars -contains 'Custom') {$strgCustomScores += $contr}
        }

        $strgReliabilityWeightedAverage = Get-WeightedAverage($strgReliabilityScores)
        $strgSecurityWeightedAverage = Get-WeightedAverage($strgSecurityScores)
        $strgOperationalExcellenceWeightedAverage = Get-WeightedAverage($strgOperationalExcellenceScores)
        $strgCostOptimizationWeightedAverage = Get-WeightedAverage($strgCostOptimizationScores)
        $strgPerformanceEfficiencyWeightedAverage = Get-WeightedAverage($strgPerformanceEfficiencyScores)
        $strgCustomWeightedAverage = Get-WeightedAverage($strgCustomScores)

        if ($strgReliabilityWeightedAverage -notmatch 'NaN') {$allStrgWeightedAverages += "Reliability Pillar;$strgReliabilityWeightedAverage"}
        if ($strgSecurityWeightedAverage -notmatch 'NaN') {$allStrgWeightedAverages += "Security Pillar;$strgSecurityWeightedAverage"}
        if ($strgOperationalExcellenceWeightedAverage -notmatch 'NaN') {$allStrgWeightedAverages += "Operational Excellence Pillar;$strgOperationalExcellenceWeightedAverage"}
        if ($strgCostOptimizationWeightedAverage -notmatch 'NaN') {$allStrgWeightedAverages += "Cost Optimization Pillar;$strgCostOptimizationWeightedAverage"}
        if ($strgPerformanceEfficiencyWeightedAverage -notmatch 'NaN') {$allStrgWeightedAverages += "Performance Efficiency Pillar;$strgPerformanceEfficiencyWeightedAverage"}
        if ($strgCustomWeightedAverage -notmatch 'NaN') {$allStrgWeightedAverages += "Custom Checks;$strgCustomWeightedAverage"}

    }

    if ($Keyvaults) {
        foreach ($contr in $kvControlArray) {
            if ($contr.Pillars -contains 'Reliability') {$kvReliabilityScores += $contr}
            if ($contr.Pillars -contains 'Security') {$kvSecurityScores += $contr}
            if ($contr.Pillars -contains 'Operational Excellence') {$kvOperationalExcellenceScores += $contr}
            if ($contr.Pillars -contains 'Cost Optimization') {$kvCostOptimizationScores += $contr}
            if ($contr.Pillars -contains 'Performance Efficiency') {$kvPerformanceEfficiencyScores += $contr}
            if ($contr.Pillars -contains 'Custom') {$kvCustomScores += $contr}
        }

        $kvReliabilityWeightedAverage = Get-WeightedAverage($kvReliabilityScores)
        $kvSecurityWeightedAverage = Get-WeightedAverage($kvSecurityScores)
        $kvOperationalExcellenceWeightedAverage = Get-WeightedAverage($kvOperationalExcellenceScores)
        $kvCostOptimizationWeightedAverage = Get-WeightedAverage($kvCostOptimizationScores)
        $kvPerformanceEfficiencyWeightedAverage = Get-WeightedAverage($kvPerformanceEfficiencyScores)
        $kvCustomWeightedAverage = Get-WeightedAverage($kvCustomScores)

        if ($kvReliabilityWeightedAverage -notmatch 'NaN') {$allKvWeightedAverages += "Reliability Pillar;$kvReliabilityWeightedAverage"}
        if ($kvSecurityWeightedAverage -notmatch 'NaN') {$allKvWeightedAverages += "Security Pillar;$kvSecurityWeightedAverage"}
        if ($kvOperationalExcellenceWeightedAverage -notmatch 'NaN') {$allKvWeightedAverages += "Operational Excellence Pillar;$kvOperationalExcellenceWeightedAverage"}
        if ($kvCostOptimizationWeightedAverage -notmatch 'NaN') {$allKvWeightedAverages += "Cost Optimization Pillar;$kvCostOptimizationWeightedAverage"}
        if ($kvPerformanceEfficiencyWeightedAverage -notmatch 'NaN') {$allKvWeightedAverages += "Performance Efficiency Pillar;$kvPerformanceEfficiencyWeightedAverage"}
        if ($kvCustomWeightedAverage -notmatch 'NaN') {$allKvWeightedAverages += "Custom Checks;$kvCustomWeightedAverage"}

    }

    foreach ($strgWeightedAverage in $allStrgWeightedAverages) {
        $allWeightedAverages += $strgWeightedAverage
    }
    foreach ($kvWeightedAverage in $allKvWeightedAverages) {
        $allWeightedAverages += $kvWeightedAverage
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
            $finalAverage.Average = $finalAverage.Average / $finalAverage.Count
        }
    }

    $WAFResults += $lateReport
    $WAFResults += ""
    $WAFResults += "#################################"
    $WAFResults += "Final Weighted Average by Pillar"
    $WAFResults += "#################################"
    $WAFResults += ""
    foreach ($finalAverage in $finalAverageArray) {
        $WAFResults += "$($finalAverage.Pillar) has an average score of $($finalAverage.Average) %."
    }
    $WAFResults += ""
    $WAFResults += "Note that a score of 0 % may indicate that the evaluated resources have no related checks in that pillar."
    $WAFResults += "The Custom Checks section is not part of the Microsoft WAF, and is used for additional checks."

    # End region

    ################# Region Outputs #####################

    # This script currently writes results to the terminal, and optionally creates a txt log file.
    # ToDo: output results as csv to be used with MS tool.
    # Perhaps even integrate MS tool into this script? Need to check under which license it is released.


    
    if ($OutputToFile) {
        $WAFResults | Out-File -FilePath ( New-Item -Path ".\results\$($sub.name).txt" -Force )
    }

    Write-Output $WAFResults

    # End region
}