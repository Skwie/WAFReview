

#---------------------------------------------------------[Initialisations]--------------------------------------------------------
# How to run the powershell script:
#.\WAF_GenerateReport.ps1 -AssessmentReport ".\ME-MngEnv877982-dbhuyan-1.csv"

param 
(
    [Parameter(Mandatory=$True)]
    [ValidateScript({Test-Path $_ }, ErrorMessage = "Unable to find the selected file. Please select a valid Well-Architected Assessment report in the <filename>.csv format.")]
    [string] $AssessmentReport
)

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Get the working directory from the script
$workingDirectory = (Get-Location).Path

#Set the assessment type to Go-Live
$AssessmentType = "Go-Live"

#Get PowerPoint template and description file
$reportTemplate = "$workingDirectory\WAF_PowerPointReport_Template.pptx"


#Initialize variables
$summaryAreaIconX = 385.1129
$localReportDate = Get-Date -Format g
$reportDate = Get-Date -Format "yyyy-MM-dd hh-MM"
$summaryAreaIconY = @(180.4359, 221.6319, 262.3682, 303.1754, 343.8692, 386.6667)

#-----------------------------------------------------------[Functions]------------------------------------------------------------


function Edit-Slide($Slide, $StringToFindAndReplace, $Gauge, $Counter)
{
    $StringToFindAndReplace.GetEnumerator() | ForEach-Object { 

        if($_.Key -like "*Threshold*")
        {
            $Slide.Shapes[$_.Key].Left = [single]$_.Value
        }
        else
        {
            #$Slide.Shapes[$_.Key].TextFrame.TextRange.Text = $_.Value
            $Slide.Shapes[$_.Key].TextFrame.TextRange.Text = $_.Value -join ' '
        }

        if($Gauge)
        {
            $Slide.Shapes[$Gauge].Duplicate() | Out-Null
            $Slide.Shapes[$Slide.Shapes.Count].Left = [single]$summaryAreaIconX
            $Slide.Shapes[$Slide.Shapes.Count].Top = $summaryAreaIconY[$Counter]
        }
    }
}

function Clear-Presentation($Slide)
{
    $slideToRemove = $Slide.Shapes | Where-Object {$_.TextFrame.TextRange.Text -match '^\[Pillar\]$'}
    $shapesToRemove = $Slide.Shapes | Where-Object {$_.TextFrame.TextRange.Text -match '^\[(W|Resource_Type_|Recommendation_)?[0-9]\]$'}

    if($slideToRemove)
    {
        $Slide.Delete()
    }
    elseif ($shapesToRemove)
    {
        foreach($shapeToRemove in $shapesToRemove)
        {
            $shapeToRemove.Delete()
        }
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Check PowerShell version
if ( $PSVersionTable.PSVersion.Major -lt 7 )
{
    Write-Host "ERROR: This script requires PowerShell Core 7 or later. Please install the latest PowerShell Core version from https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell"
    exit
}

# Read the csv file content
$csvContent = Get-Content $AssessmentReport

#Instantiate PowerPoint variables
$application = New-Object -ComObject PowerPoint.Application
$reportTemplateObject = $application.Presentations.Open($reportTemplate)
$slides = @{
    "Cover" = $reportTemplateObject.Slides[1];
    "Summary" = $reportTemplateObject.Slides[2]    
    # "Result" = $reportTemplateObject.Slides[16];  
    # "Detail" = $reportTemplateObject.Slides[16];
    # "End"  = $reportTemplateObject.Slides[17]
}

#Edit cover slide
$coverSlide = $slides.Cover
$stringsToReplaceInCoverSlide = @{ "Cover - Report_Date" = "Report generated: $localReportDate" }
Edit-Slide -Slide $coverSlide -StringToFindAndReplace $stringsToReplaceInCoverSlide

#Edit summary slide
#Get findings
$summarySlide = $slides.Summary

$findingsStartIdentifier = $csvContent | Where-Object { $_.Contains("Final Weighted Average by Pillar") } | Select-Object -Unique -First 1

$findingsStart = $csvContent.IndexOf($findingsStartIdentifier)

$endStringIdentifier = $csvContent | Where-Object{$_.Contains("The Custom Checks section is not part of the Microsoft WAF, and is used for additional checks.")} | Select-Object -Unique -First 1
$findingsEnd = $csvContent.IndexOf($endStringIdentifier) - 1

$findings = $csvContent[$findingsStart..$findingsEnd]
$findings = $findings | Join-String -Separator "`n"
$findings = $findings.Replace('"', '')



# # # Access the shapes collection of a slide and get the shapes in the slide
# $shapes = $slides["Summary"].Shapes

# # # Iterate over the shapes collection
# foreach ($shape in $shapes) {
#     # Print the name of the shape
#     Write-Host $shape.Name
# }

# Get the summary slide

$stringsToReplaceInSummarySlide = @{ "Cover - Report_Date" = $findings }
Edit-Slide -Slide $summarySlide -StringToFindAndReplace $stringsToReplaceInSummarySlide

################## Edit Scores for each Azure Resources #############################################
$lines = $csvContent -split "`n"

# Filter the lines that contain "Azure Resource"
$azureResourceScores = $lines | Where-Object { $_ -match "Azure Resource" }

# Remove "Azure Resources - " from each line
$azureResourceScores = $azureResourceScores | ForEach-Object { $_ -replace "Azure Resource -", "" -replace "has an average", "" -replace "of", ":" -replace "of", ":"}

# Define the maximum number of lines per slide
$maxLinesPerSlide = 20

# Split the content into chunks of lines
$chunks = [System.Collections.ArrayList]::new()
for ($i = 0; $i -lt $azureResourceScores.Count; $i += $maxLinesPerSlide) {
    $chunks.Add($azureResourceScores[$i..[math]::Min($i + $maxLinesPerSlide - 1, $azureResourceScores.Count - 1)])
}

foreach ($chunk in $chunks) {
    # Create a new slide by duplicating the summary slide
    $newSlide = $reportTemplateObject.Slides.AddSlide($reportTemplateObject.Slides.Count + 1, $summarySlide.CustomLayout)

    # Add the lines to the new slide
    # Assuming the slide has a single text box shape
    $newSlide.Shapes[2].TextFrame.TextRange.Text = $chunk -join "`n"

    # Set the font size and font of the text box
    $newSlide.Shapes[2].TextFrame.TextRange.Font.Size = 13  # Replace with the actual font size
    $newSlide.Shapes[2].TextFrame.TextRange.Font.Name = "Arial" 

    $newSlide.Shapes[1].TextFrame.TextRange.Text = "Scores for each Service"  # Replace with the actual font size
    $newSlide.Shapes[1].TextFrame.TextRange.Font.Name = "Arial" 
    $newSlide.Shapes[1].TextFrame.TextRange.Font.Size = 18
        
    # Add margins by adjusting the position and size of the text box
    $newSlide.Shapes[1].Top -= 170 
    $newSlide.Shapes[1].Left +=40
    $newSlide.Shapes[2].Top -= 150
}

####################### Edit result slide #############################################

$startIndex = 9
$maxLinesPerSlide = 25

# Loop through the content and create a new slide for each chunk
for ($i = $startIndex; $i -lt $csvContent.Count; $i += $chunkSize) {
    
    # Modify the chunk size depending on the content
    if ($csvContent[$i+1] -match "WAF Assessment Results for") {
        $chunkSize = 4
        Continue
    }
    elseif ($csvContent[$i] -match "----- ") {
        foreach ($line in $csvContent[$i..$csvContent.Count]) {
            if ($line -match "Azure Resource -") {
                $chunkSize = $csvContent[$i..$csvContent.Count].IndexOf($line) + 2
                Break
            }
        }
    }
    elseif ($csvContent[$i+1] -match "Summary of results") {
        Break
    }
    elseif ($csvContent[$i+1] -match "found for subscription") {
        $chunkSize = 4
        Continue
    }
    elseif ($csvContent[$i] -match "found for subscription") {
        $chunkSize = 3
        Continue
    }

    # Get the next chunk of lines
    $detailChunk = $csvContent[$i..($i + $chunkSize - 1)]
    $detailChunk = $detailChunk.Replace('"', '')

    # Split the content into chunks of lines
    $chunks = [System.Collections.ArrayList]::new()
    for ($j = 0; $j -lt $detailChunk.Count; $j += $maxLinesPerSlide) {
        $chunks.Add($detailChunk[$j..[math]::Min($j + $maxLinesPerSlide - 1, $detailChunk.Count - 1)])
    }

    foreach ($chunk in $chunks) {
        # Create a new slide by duplicating the summary slide
        $newSlide = $reportTemplateObject.Slides.AddSlide($reportTemplateObject.Slides.Count + 1, $summarySlide.CustomLayout)
    
        $newSlide.Shapes[2].TextFrame.TextRange.Text = $chunk -join "`n"
        
        # Set the font size and font of the text box
        $newSlide.Shapes[2].TextFrame.TextRange.Font.Size = 11  # Replace with the actual font size
        $newSlide.Shapes[2].TextFrame.TextRange.Font.Name = "Arial" 

        $newSlide.Shapes[1].TextFrame.TextRange.Text = "Detailed Results for each Service"  # Replace with the actual font size
        $newSlide.Shapes[1].TextFrame.TextRange.Font.Name = "Arial" 
        $newSlide.Shapes[1].TextFrame.TextRange.Font.Size = 18
            
        # Add margins by adjusting the position and size of the text box
        
        $newSlide.Shapes[1].Top -= 170 
        $newSlide.Shapes[1].Left +=20
        $newSlide.Shapes[2].Top -= 200        
    }
}

#Remove empty detail slides
Clear-Presentation -Slide $slides.Detail

# Remove the last slide
$reportTemplateObject.Slides[$reportTemplateObject.Slides.Count].Delete()

#Save presentation and close object
$reportTemplateObject.SavecopyAs(“$workingDirectory\results\Azure Well-Architected $AssessmentType Review - Executive Summary - $reportDate.pptx”)
$reportTemplateObject.Close()

$application.quit()
$application = $null
[gc]::collect()
[gc]::WaitForPendingFinalizers()