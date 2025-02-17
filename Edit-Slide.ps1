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