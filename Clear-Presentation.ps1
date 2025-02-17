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