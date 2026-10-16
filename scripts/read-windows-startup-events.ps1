# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
<#
.SYNOPSIS
Reads existing error records only. Never enables WER, tracing or dumps, changes
security, opens a process, starts a child fixture or accesses an RDX device.
.PARAMETER Since
Exact UTC beginning of the CI child-test observation window (milliseconds).
.PARAMETER Until
Exact UTC end, at most five minutes after Since.
#>
param([Parameter(Mandatory=$true)][string]$Since, [Parameter(Mandatory=$true)][string]$Until)
<#
.SYNOPSIS
Parses bounded local event XML into private captured fields without external XML
resolution. Emits one row or throws on malformed input; never changes OS state.
.PARAMETER Text
Captured XML from one retained event record, at most 131,072 characters.
.PARAMETER Channel
Fixed local query channel.
.PARAMETER Provider
Provider metadata from the retained record.
.PARAMETER EventId
Event identifier from the retained record.
.PARAMETER Created
Record timestamp, normalized to UTC milliseconds for the Node classifier.
#>
function ConvertTo-StartupEventRow([string]$Text,[string]$Channel,[string]$Provider,[int]$EventId,[DateTime]$Created){
 if($Text.Length -gt 131072){throw 'event-xml-bound'}
 $settings=New-Object Xml.XmlReaderSettings
 $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
 $settings.XmlResolver=$null
 $settings.MaxCharactersInDocument=131072
 $textReader=New-Object IO.StringReader($Text)
 $xmlReader=[Xml.XmlReader]::Create($textReader,$settings)
 try{$xml=New-Object Xml.XmlDocument;$xml.XmlResolver=$null;$xml.Load($xmlReader)}finally{$xmlReader.Dispose();$textReader.Dispose()}
 $keys=@('AppName','ModuleName','ExceptionCode','EventName','P1','P4','P7','Caption','Message','Application')
 $fields=[ordered]@{}
 foreach($data in $xml.Event.EventData.Data){
  $name=[string]$data.Name
  if($name -notin $keys){continue}
  $value=[string]$data.InnerText
  if($fields.Contains($name) -or $value.Length -gt 8192){throw 'event-field-shape'}
  $fields[$name]=$value
 }
 return [ordered]@{channel=$Channel;provider=$Provider;id=$EventId;time=$Created.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ",[Globalization.CultureInfo]::InvariantCulture);fields=$fields}
}
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$OutputEncoding=New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding=$OutputEncoding
$culture=[Globalization.CultureInfo]::InvariantCulture
$style=[Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
$start=[DateTime]::ParseExact($Since,"yyyy-MM-ddTHH:mm:ss.fffZ",$culture,$style)
$end=[DateTime]::ParseExact($Until,"yyyy-MM-ddTHH:mm:ss.fffZ",$culture,$style)
if($end -lt $start -or ($end-$start).TotalSeconds -gt 300){throw 'observation-window-invalid'}
$watch=[Diagnostics.Stopwatch]::StartNew()
$rows=New-Object 'Collections.Generic.List[object]'
$channels=New-Object 'Collections.Generic.List[object]'
# Both channels are local, fixed and read-only. No query reads rendered messages.
foreach($channel in @('Application','System')){
 $status='complete';$reader=$null;$count=0
 try{
  $xpath="*[System[(EventID=1000 or EventID=1001 or EventID=26) and TimeCreated[@SystemTime >= '$Since' and @SystemTime <= '$Until']]]"
  $query=New-Object Diagnostics.Eventing.Reader.EventLogQuery($channel,[Diagnostics.Eventing.Reader.PathType]::LogName,$xpath)
  $query.ReverseDirection=$true
  $reader=New-Object Diagnostics.Eventing.Reader.EventLogReader($query)
  while($true){
   if($watch.ElapsedMilliseconds -ge 5000 -or $count -ge 32){$status='bounded';break}
   $record=$reader.ReadEvent([TimeSpan]::FromMilliseconds(100))
   if($null -eq $record){break}
   $count++
   try{
    if($record.ProviderName -notin @('Application Error','Windows Error Reporting','Application Popup')){continue}
    if($null -eq $record.TimeCreated){throw 'event-time-unavailable'}
    $rows.Add((ConvertTo-StartupEventRow -Text $record.ToXml() -Channel $channel -Provider $record.ProviderName -EventId $record.Id -Created $record.TimeCreated))
   }finally{$record.Dispose()}
  }
 }catch{$status='failed'}finally{if($null -ne $reader){$reader.Dispose()}}
 $channels.Add([ordered]@{name=$channel;status=$status})
}
# This private captured response is consumed by the Node classifier. Only its
# reconstructed fixed categories, never this raw response, are logged by CI.
[ordered]@{channels=@($channels.ToArray());records=@($rows.ToArray())}|ConvertTo-Json -Depth 6 -Compress
