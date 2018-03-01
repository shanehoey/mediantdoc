
function Convertfrom-MediantDocConfigIni 
{
  param ( $MediantConfigini )

  #Credit Oliver Lipkau
  #https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
    
  $ini = @{}
  $section = 'Mediant'
  $ini[$section] = @{}

  switch -regex ($MediantConfigini) {
    '^(;.*)'  
    {
      #Comment
      Write-Verbose -Message "COMMENT -> $_"
      $value = $matches[1]
      $CommentCount = $CommentCount + 1
      $name = 'Comment' + $CommentCount
      $ini[$section][$name] = $value
      continue
    } 
    '^\[([^\\].+)\]'  
    {
      #Section
      Write-Host -Object "Imported:   $($matches[1].Replace(' ',''))" -ForegroundColor cyan
      Write-Verbose -Message "SECTION -> $_"
      $section = $matches[1].Replace(' ','')
      $ini[$section] = @{}
      $CommentCount = 0
      continue
    }
    '^(.+?)\s*=(.*)'  
    {
      #Key
      Write-Verbose -Message "KEY    -> $_"
      $name, $value = $matches[1..2]
      $ini[$section][$name] = $value
      continue
    }
    default 
    {
      Write-Verbose -Message "Ignore -> $_"
    }
  }
  return $ini
}
function ConvertFrom-MediantDocTable 
{ 
    [CmdletBinding()]
    param (
        $item,
        $itemindex,
        $ini = $ini
        )

    Write-Verbose -Message "Converting $item"

    try 
    {
        $object = $ini[$item]
        if ($object -eq $null) { throw "Not Configured $item" }

        [array]$objectIndex = $object["FORMAT $($item)_Index"].trim().trimend(';').Split(',').trim()

        foreach ($o in ($object.keys.where( { $_ -like "$item*" })) ) 
        { 
            try
            { 
                $result = New-Object $item
                $result | Add-Member -membertype NoteProperty -Name ("$($item)_Index") -Value $o -Force
                Write-Verbose -Message "class $item" 
            }
            catch 
            {
                $result = New-Object -TypeName PSCustomObject
                $result | Add-Member -membertype NoteProperty -Name ("$($item)_Index") -Value $o -Force
                foreach ($i in $itemindex)
                {
                  $result | Add-Member -membertype NoteProperty -Name $i -Value ''
                }
                $result.pstypenames.insert(0,"$item")
                Write-Verbose -Message "psCustomObject $item"
            }
        
            for ($i = 0; $i -lt $objectIndex.Count; $i++) 
            {
                try 
                {
                    $result.($objectIndex[$i]) = $($object.$o.trim().trimend(';').Split(',')[$i].trim().trimstart([char]0x0022).trimend([char]0x0022))
                    Write-Verbose -Message "$($objectIndex[$i]) = $($result.($objectIndex[$i]))"
                }
                catch 
                {
                    Write-Warning "   *** Parameter not documented ->  [$item]$($objectIndex[$i])" 
                    $Script:MissingParameter = $TRUE
                    $result | Add-Member -MemberType NoteProperty -Name ($objectIndex[$i]) -Value $($object.$o.trim().trimend(';').Split(',')[$i].trim().trimstart([char]0x0022).trimend([char]0x0022))
                    Write-Verbose -Message "$($objectIndex[$i]) = $($result.($objectIndex[$i]))"
                }
            }
        $result 
    }
    Update-TypeData -TypeName "$item" -MemberType Scriptmethod -MemberName 'view' -Value { $this  } -Force
    Write-Host -Object "Converted:  $item" -ForegroundColor DarkCyan
  }
  catch 
  {
    Write-Host -Object "Skipping:   $item" -ForegroundColor DarkCyan
  }
}

function ConvertFrom-MediantDocMediantParameter {
    $item = 'Mediant'
    $result = New-Object $item

    Switch -regex ($ini[$item].Values) 
    {
      '^;Board: (.*)$' { $result | Add-Member -Name 'Mediant_Board' -Value $matches[1] -MemberType NoteProperty -Force }
      '^;Board Type: (.*)$' { $result | Add-Member -Name 'Mediant_BoardType' -Value $matches[1] -MemberType NoteProperty -Force }
      '^;;;Key features:(.*)$'  { $result | Add-Member -Name 'Mediant_KeyFeatures' -Value $matches[1].split(';') -MemberType NoteProperty -Force }
      '^;Serial Number: (.*)$'  { $result | Add-Member -Name 'Mediant_SerialNumber' -Value $matches[1] -MemberType NoteProperty -Force }
      '^;Software Version: (.*)$' { $result | Add-Member -Name 'Mediant_SoftwareVersion' -Value $matches[1] -MemberType NoteProperty -Force }
      '^;DSP Software Version: (.*)$' { $result | Add-Member -Name 'Mediant_DSPSoftwareVersion' -Value $matches[1] -MemberType NoteProperty -Force  }
    }
    return $result
}

function ConvertFrom-MediantDocList 
{ 
  [CmdletBinding()]
  param (
    $item,
    $itemindex,
    $ini = $ini
  )

  Write-Verbose -Message "Converting $item" 

  try 
  {
    $object = $ini[$item]

    if ($object.keys.where({ $_ -notlike 'Comment*' }).count -eq 0)
    {
      throw "Skipping Empty $item" 
    }

    try
    {
      $result = New-Object $item
      Write-Verbose -Message "class $item" 
    }
    catch 
    {
      $result = New-Object -TypeName PSCustomObject
      if ($itemindex) {
          foreach ($i in $itemindex) {
             $result | Add-Member -MemberType NoteProperty -Name $i -Value $null -Force
             Write-Verbose -Message "Adding member $i"
          }
      }
      $result.pstypenames.insert(0,"$item")
      Write-Verbose -Message "PSCustomObject $item"
    }

    foreach ($o in ( $object.keys.where({ $_ -notlike 'Comment*' }) ) ) 
    {
        try 
        {     
            $result.$o = $object[$o]
        }
        catch
        {
            Write-Warning "   *** Parameter not documented ->  [$item]$o"
            $Script:MissingParameter = $true
            $result | Add-Member -MemberType NoteProperty -Name $o -Value $object[$o] -Force
        }
    }
    Update-TypeData -TypeName "$item" -MemberType Scriptmethod -MemberName 'view' -Value { $this } -Force
    Write-Host -Object "Converted:  $item" -ForegroundColor DarkCyan
    $result
  }
  catch 
  {
    Write-Host -Object "Skipping:   $item" -ForegroundColor DarkCyan
  }
}

function update-mediantDocParameter 
{
  [CmdletBinding()]
  Param ( 
    [Parameter(Position = 0, mandatory = $true)]
    [AllowEmptyString()]
    [string]$Parameter,  
    [Parameter(Position = 1, mandatory = $false)]
    [AllowEmptyString()]
    [string]$DefaultValue = '',
    [Parameter(Position = 2, mandatory = $false)]
  [hashtable]$ParameterLookup)
    
  Write-Verbose -Message "Parameter->       $Parameter" 
  Write-Verbose -Message "DefaultValue->    $DefaultValue"
  Write-Verbose -Message "ParameterLookup-> $ParameterLookup"

  if ($Parameter -eq '') 
  {
    $Parameter = $DefaultValue 
  }
    
  if ($PSBoundParameters.ContainsKey('ParameterLookup')) 
  {
    if ($ParameterLookup.containskey($Parameter)) 
    {
      return $ParameterLookup[$Parameter] 
    }
    else 
    {
      return $Parameter 
    }
  }
  else 
  {
    return $Parameter
  }
}

function Add-mediantDocParagraph 
{
  param(
    [Parameter(Position = 3, mandatory = $false)]
    [switch]$NewPage,
    [Parameter(Position = 0, mandatory = $false)]
    [string]$heading,
    [Parameter(Position = 1, mandatory = $false)]
    [ValidateSet('1', '2', '3', '4')]
    [String]$headingtype = 2,
    [Parameter(Position = 2, mandatory = $false)]
    [array]$text
  )

  if ($NewPage) 
  {
    Add-WordBreak -breaktype NewPage
  }
  if ($heading) 
  {
    Write-Host -Object "Documenting $heading" -ForegroundColor Cyan
    Add-WordText -text $heading -WDBuiltinStyle "wdStyleHeading$headingtype"
    Add-WordBreak -breaktype Paragraph
  }
  if ($text) 
  {
    foreach ($t in $text) 
    {
      Add-WordText -text $t -WDBuiltinStyle wdStyleNormal
    }
    Add-WordBreak -breaktype Paragraph
  }
}
