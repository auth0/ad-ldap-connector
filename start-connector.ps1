$json = Get-Content './config.json' | Out-String | ConvertFrom-Json
$maxHeaderSize = if ($json.MAX_HEADER_SIZE -and $json.MAX_HEADER_SIZE -ne "") { $json.MAX_HEADER_SIZE } else { 16384 }
node --max-http-header-size=$maxHeaderSize ./server.js 2>&1 | Out-File -FilePath "logs.log" -Encoding ASCII -Append
