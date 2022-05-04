# script
$body = @{
    "client_id"=$AADAppId
    "scope"="https://graph.microsoft.com/.default"
    "client_secret"=$AADAppSecret
    "grant_type"="client_credentials"
}

$c_tenant_id = $AADtenantID
$tokenquery = Invoke-RestMethod -uri https://login.microsoftonline.com/$($c_tenant_id)/oauth2/v2.0/token -body $body -Method Post -ContentType 'application/x-www-form-urlencoded'
#$tokenquery
	$headers = @{
		"content-type" = "Application/Json"
		"authorization" = "Bearer $($tokenquery.access_token)"
	}
$a = Invoke-RestMethod -uri "https://graph.microsoft.com/v1.0/sites" -Method GET -Headers $headers
$a.value | Where { $_.webUrl -notmatch '/personal/'} | Sort-Object displayName | foreach { Write-Output $_ }
