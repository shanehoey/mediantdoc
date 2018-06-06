
if($section.CoverPage) { 

  #Add Coverpage
  for ($i = 0; $i -lt 18; $i++) { Add-WordBreak -breaktype Paragraph }
  Add-WordText -text $DocumentTitle -WDBuiltinStyle wdStyleTitle -TextColor wdColorWhite
  Add-WordText -text $DocumentCustomer -WDBuiltinStyle wdStyleSubtitle -TextColor wdColorWhite
  for ($i = 0; $i -lt  4; $i++) { Add-WordBreak -breaktype Paragraph }

  $fa_github  = [char]0xf09b
  $fontawesometext = "Font Awesome 5 Brands Regular"
  add-wordtext  -text $fa_github -Font $fontawesometext -Size 18 -NoParagraph -TextColor wdColorWhite
  add-wordtext " https://shanehoey.github.io/worddoc/" -Size 18 -TextColor wdColorWhite

  $pagewidth = (get-worddocument).pagesetup.pagewidth
  $pageheight = (get-worddocument).pagesetup.pageheight
  add-wordshape -shape msoShapeRectangle -left 0 -top 0 -Width $pagewidth -Height ($pageheight/2) -zorder msoSendBehindText -UserPicture "http://source.unsplash.com/YXemfQiPR_E/800x600" -PictureEffect msoEffectPaintBrush
  add-wordshape -shape msoShapeRectangle -left 0 -top ($pageheight/2) -Width $pagewidth -Height ($pageheight/2) -zorder msoSendBehindText -themecolor msoThemeColorDark1

  #Fixes to implement into modules 
  #set to RelativeVerticalPosition
  (Get-WordDocument).Shapes(1).LockAnchor = -1
  (Get-WordDocument).Shapes(2).LockAnchor = -1

  Add-WordBreak -breaktype Section

  #AddLicense
  Add-WordBreak -breaktype Paragraph
  Add-WordText -text 'This document has been created with wordDoc which has been distributed under the MIT license. For more information visit http://shanehoey.github.io/worddoc/' -Align wdAlignParagraphJustify
  $license = "MIT License`nCopyright (c) 2016-2018 Shane Hoey`rPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:`nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.`nTHE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
  Add-WordText -text $license -WDBuiltinStyle wdStyleNormal -Bold -Align wdAlignParagraphJustify
  #Add Shameless Plug
  for ($i = 0; $i -lt 3; $i++) 
  {
      Add-WordBreak -breaktype Paragraph 
  }
  Add-WordText -text 'Are you using this commercially? Show your appreciation and encourage more development of this script at https://paypal.me/shanehoey' -WDBuiltinStyle wdStyleIntenseQuote -TextColor wdColorBlack

  #Table of Contents
  Add-WordBreak -breaktype NewPage
  Add-WordText -text 'Contents' -WDBuiltinStyle wdStyleTOCHeading -TextColor wdColorBlack

  Add-WordTOC 
  Add-WordBreak -breaktype NewPage

  #Update Document Settings
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertytitle -text $DocumentTitle
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertySubject -text "$Documenttitle for $documentCustomer"
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyAuthor -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAbgBlACAASABvAGUAeQA=')))
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyComments -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAHMAaABhAG4AZQBoAG8AZQB5AC4AZwBpAHQAaAB1AGIALgBpAG8ALwB3AG8AcgBkAGQAbwBjAC8A')))
  Set-WordBuiltInProperty -WdBuiltInProperty wdPropertyManager -text $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAbgBlACAASABvAGUAeQA=')))

    
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
    

    }