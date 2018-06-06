
$GridTableBlue = @{
  'WdAutoFitBehavior'    = 'wdAutoFitWindow'
  'WdDefaultTableBehavior' = 'wdWord9TableBehavior'
  'GridTable'            = 'Grid Table 4'
  'GridAccent'           = 'Accent 1'
  'BandedRow'            = $False
}

$GridTableBlack = @{
  'WdAutoFitBehavior'    = 'wdAutoFitWindow'
  'WdDefaultTableBehavior' = 'wdWord9TableBehavior'
  'GridTable'            = 'Grid Table 4'
  'BandedRow'            = $False
}

$GridTableGrey = @{
  'WdAutoFitBehavior'    = 'wdAutoFitWindow'
  'WdDefaultTableBehavior' = 'wdWord9TableBehavior'
  'GridTable'            = 'Grid Table 4'
  'GridAccent'           = 'Accent 3'
  'BandedRow'            = $False
}

New-WordInstance
New-WordDocument
if($templatefile)
{
    Add-WordTemplate -filename $templatefile
}

#Turn of spelling to speed up creating doc
(get-wordInstance).options.checkspellingasyoutype = $false

. .\files\coverpage.ps1

. .\files\overview.ps1

. .\files\ipnetwork.ps1

. .\files\SignalingAndMedia.ps1

. .\files\administration.ps1

. .\files\troubleshoot.ps1 

. .\files\appendix.ps1

. .\files\endpage.ps1

Update-WordTOC