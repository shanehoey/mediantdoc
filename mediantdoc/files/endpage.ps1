if ($section.EndPage)  
{
   Add-WordBreak -breaktype NewPage  
  for ($i = 0; $i -lt 16; $i++) { Add-WordBreak -breaktype Paragraph }
  $fa_github  = [char]0xf09b
  $fontawesometext = "Font Awesome 5 Brands Regular"
  add-wordtext  -text $fa_github -Font $fontawesometext -Size 18 -NoParagraph -TextColor wdColorWhite
  add-wordtext " https://shanehoey.github.io/worddoc/" -Size 18 -TextColor wdColorWhite -Align wdAlignParagraphCenter

  $pagewidth = (get-worddocument).pagesetup.pagewidth
  $pageheight = (get-worddocument).pagesetup.pageheight
  add-wordshape -shape msoShapeRectangle -left 0 -top 0 -Width $pagewidth -Height $pageheight -zorder msoSendBehindText -themecolor msoThemeColorDark1

}