# WAFReview
Automated assessment for the Azure WAF

## WAFAzCli.ps1

This script is a tool built in Powershell for performing automated assessments of the Azure Well-Architected Framework (WAF). It leverages the Azure CLI module to interact with the Azure platform.
This tool is currently still a Work in Progress (WIP).

### Prerequisites

Before running this script, ensure that you have the following prerequisites:

- Az module installed. You can install it by running the following command:

    ```powershell
    Install-Module -Name Az
    ```

### Usage

To use this script, follow these steps:

1. Determine whether you wish to run the script on a selection of subscriptions or all subscriptions you have access to.

2. If you wish to run the script for specific subscriptions, look up their subscriptionId, and add them to an array like this:
@('b6307584-2248-4e8b-a911-2d7f1bd2613a','c405e642-15db-4786-9426-1e23c84d225a')

Note that if no subscriptionIDs are proviced, subscriptions are currently filtered to check if they match a pattern (name ending in -lz).
You may want to modify this to a pattern that matches your particular environment, or omit the filter.

3. If you wish the results to be written to a file, set the OutputToFile boolean to $true.

### Features

- **Assessment**: The script performs an automated assessment of adherence to the Azure WAF for Azure resources.
- **Reporting**: After the assessment is completed, the script generates a detailed report in txt format, providing an overview of the findings and recommendations for improving the WAF configuration.

### Examples

To run the assessment for all subscriptions and generate a report, use the following command:

  .\WAFAzCli.ps1 -ProdOnly $False -OutputToFile $True