
if($section.CoverPage) { 
    
    #CoverPage
    for ($i = 0; $i -lt 3; $i++) 
    {
      Add-WordBreak -breaktype Paragraph 
    }
    Add-WordText -text 'Mediant Configuration' -WDBuiltinStyle wdStyleTitle
    for ($i = 0; $i -lt 3; $i++) 
    {
      Add-WordBreak -breaktype Paragraph 
    }
    Add-WordText -text 'for' -WDBuiltinStyle wdStyleTitle
    for ($i = 0; $i -lt 3; $i++) 
    {
      Add-WordBreak -breaktype Paragraph 
    }
    Add-WordText -text 'Customer Name' -WDBuiltinStyle wdStyleTitle
    Add-WordBreak -breaktype NewPage
    
    #License
    $license = "MIT License`nCopyright (c) 2016-2018 Shane Hoey`rPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:`nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.`nTHE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
    Add-WordBreak -breaktype Paragraph
    Add-WordText -text 'This document has been created with MediantDoc which has been distributed under the MIT license. For more information visit http://shanehoey.github.io/worddoc/mediant' -WDBuiltinStyle wdStyleBookTitle
    Add-WordBreak -breaktype Paragraph
    #bug with bold/italic in worddoc module
    $selection = (Get-WordDocument).application.selection
    $selection.font.Bold = $False
    $selection.ParagraphFormat.Alignment = 3
    Add-WordText -text $license -WDBuiltinStyle wdStyleNormal
    Add-WordBreak -breaktype NewPage
    
    #Shameless Plug
    for ($i = 0; $i -lt 3; $i++) 
    {
      Add-WordBreak -breaktype Paragraph 
    }
    Add-WordText -text 'Are you using this commercially? Show your appreciation and encourage more development of this script at https://paypal.me/shanehoey' -WDBuiltinStyle wdStyleIntenseQuote
    for ($i = 0; $i -lt 3; $i++) 
    {
      Add-WordBreak -breaktype Paragraph 
    }
    Add-WordText -text 'Have a suggestion on how to improve the script ? https://github.com/shanehoey/mediantdoc/issues/' -WDBuiltinStyle wdStyleIntenseQuote
    
    #TOC
    Add-WordBreak -breaktype NewPage
    Add-WordText -text 'Contents' -WDBuiltinStyle wdStyleTOCHeading 
    Add-WordTOC 
    Add-WordBreak -breaktype NewPage

    #builtinProperty
    Set-WordBuiltInProperty -WdBuiltInProperty wdPropertytitle -text 'MediantDodc'
    Set-WordBuiltInProperty -WdBuiltInProperty wdPropertySubject -text 'Cloud Connector Implementation'
    Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyAuthor -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAbgBlAGgAbwBlAHkA')))
    Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyComments -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBzAGgAYQBuAGUAaABvAGUAeQAvAHcAbwByAGQAZABvAGMALwBtAGUAZABpAGEAbgB0AGQAbwBjAA==')))
    Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyManager -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAbgBlAGgAbwBlAHkA')))

    }