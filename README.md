# WAFReview
Automated assessment for the Azure WAF

## WAFAzCli.ps1

This script is a tool built in Powershell for performing automated assessments of the Azure Well-Architected Framework (WAF). It leverages the Azure REST API to interact with the Azure platform.
This tool is currently still a Work in Progress (WIP).

### Prerequisites

Before running this script, ensure that you have the following prerequisites:

- Powershell 7
  This script does not function properly with Powershell 5.
- Az module
  The Az module is required for authentication to Azure.
  It can be installed with:
    ```
    Install-Module Az
    ```

### Usage

To use this script, follow these steps:

1. Determine whether you wish to run the script on a selection of subscriptions or all subscriptions you have access to.

2. If you wish to run the script for specific subscriptions, look up their subscriptionId, and add them to an array like this:
@('b6307584-2248-4e8b-a911-2d7f1bd2613a','c405e642-15db-4786-9426-1e23c84d225a')

Note that if no subscriptionIDs are provided, the script runs for all subscriptions you have access to.
If you have access to many subscriptions, the runtime of this script may be extremely long.
You can use the -Filter param to limit the subscription filter to those matching a provided string.

3. If you want to generate a Powerpoint presentation, set the GeneratePowerPoint boolean to $true.
If you get permission errors, manually open the WAF_PowerPointReport_Template, select a label (public), and save it to enable editing.

### Features

- **Assessment**: The script performs an automated assessment of adherence to the Azure WAF for Azure resources.
- **Reporting**: After the assessment is completed, the script generates a detailed report in txt format, providing an overview of the findings and recommendations for improving your WAF posture. Powerpoint generation is also supported.

### Examples

To run the assessment for all subscriptions matching a string, use the following command:

  .\WAFAzCli.ps1 -Filter '-p-lz'

To generate a Powerpoint report, use the GeneratePowerPoint boolean:
  .\WAFAzCli.ps1 -Filter 'aec-p-lz' -GeneratePowerPoint $true