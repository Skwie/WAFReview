BeforeAll {
    . $PSScriptRoot\Get-WeightedAverage.ps1
    . $PSScriptRoot\Get-AllWeightedAveragesPerService.ps1
    . $PSScriptRoot\New-RetryCommand.ps1
    . $PSScriptRoot\New-ApiRetryCommand.ps1
}

Describe "Get-WeightedAverage" {
    It "Should return the weighted average of the given array" {
        $array = @(
            @{ Result = 1; Weight = 1 },
            @{ Result = 2; Weight = 2 },
            @{ Result = 3; Weight = 3 }
        )
        $result = Get-WeightedAverage $array
        $result | Should -Be 2.3
    }

    It "Should return Not a Number if the array is empty" {
        $array = @()
        $result = Get-WeightedAverage $array
        $result | Should -Be 'NaN'
    }

    It "Should return a result of type double" {
        $array = @(
            @{ Result = 1; Weight = 1 },
            @{ Result = 2; Weight = 2 },
            @{ Result = 3; Weight = 3 }
        )
        $result = Get-WeightedAverage $array
        $result | Should -BeOfType Double
    }
}

Describe "Get-AllWeightedAveragesPerService" {
    It "Should return a list of all weighted averages per service" {
        $arr = @()
        $arr += [PSCustomObject]@{
            Name = "ServiceName"
            Pillars = "Reliability"
            Weight = 50
            Result = 60
        }
        $arr += [PSCustomObject]@{
            Name = "ServiceName"
            Pillars = "Performance"
            Weight = 50
            Result = 70
        }
        $result = Get-AllWeightedAveragesPerService -controlArray $arr
        $result | Should -BeOfType Array
    }

    It "Should return a string if the array contains one object" {
        $arr = @()
        $arr += [PSCustomObject]@{
            Name = "ServiceName"
            Pillars = "Reliability"
            Weight = 50
            Result = 60
        }
        $result = Get-AllWeightedAveragesPerService -controlArray $arr
        $result | Should -BeOfType String
    }

    It "Should return null if the array is empty" {
        $result = Get-AllWeightedAveragesPerService
        $result | Should -BeNullOrEmpty
    }
}

Describe "New-RetryCommand" {
    It "Should execute a given command properly if given a valid command" {
        $command = "Get-Date"
        $args = @{}
        $result = New-RetryCommand -command $command -args $args
        $result | Should -BeOfType DateTime
    }

    It "Should stop execution after the maximum number of retries" {
        $command = "Get-Datee"
        $args = @{}
        $result = New-RetryCommand -command $command -args $args -ErrorVariable err
        $err[-1].Exception.Message | Should -Be "Command Get-Datee failed the maximum number of 5 times."
    }
}

Describe "New-ApiRetryCommand" {
    It "Should execute a given API call properly if given a valid URI" {
        $uri = "https://dogapi.dog/api/v2/facts"
        $headers = @{}
        $result = New-ApiRetryCommand -uri $uri -headers $headers
        $result.StatusCode | Should -Be 200
    }

    It "Should stop execution after the maximum number of retries" {
        $uri = "https://iamnotarealapiendpoint"
        $headers = @{}
        $result = New-ApiRetryCommand -uri $uri -headers $headers -ErrorVariable err
        $err[-1].Exception.Message | Should -Be "API call failed the maximum number of 5 times."
    }
}