# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$folderid = $datasource.selectedFolder.id
$siteid = $datasource.selectedSite.id
$role = "read"

Write-Information "Generating Microsoft Graph API Access Token.."
$baseUri = "https://login.microsoftonline.com/"
$authUri = $baseUri + "$AADTenantID/oauth2/token"
$body = @{
    grant_type      = "client_credentials"
    client_id       = "$AADAppId"
    client_secret   = "$AADAppSecret"
    resource        = "https://graph.microsoft.com"
}
 
$Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
$accessToken = $Response.access_token;

#Add the authorization header to the request
$authorization = @{
    Authorization = "Bearer $accesstoken";
    'Content-Type' = "application/json";
    Accept = "application/json";
}

try {
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/users" + '?$select=id,UserPrincipalName,displayName,department,jobTitle,companyName' + '&$top=999'
 
        $azureADUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADUsers = $azureADUsersResponse.value
        while (![string]::IsNullOrEmpty($azureADUsersResponse.'@odata.nextLink')) {
            $azureADUsersResponse = Invoke-RestMethod -Uri $azureADUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
            $azureADUsers += $azureADUsersResponse.value
        }  
        $azureADUsers = $azureADUsers | Select-Object id,UserPrincipalName,displayName,department,jobTitle,companyName | Sort-Object -Property DisplayName
         
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD Users. Error: $($_.Exception.Message)" + $errorDetailsMessage)
}

try {
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/groups" + '?$select=id,description,displayname' + '&$top=999'
 
        $azureADGroupsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADGroups = $azureADGroupsResponse.value
        while (![string]::IsNullOrEmpty($azureADGroupsResponse.'@odata.nextLink')) {
            $azureADGroupsResponse = Invoke-RestMethod -Uri $azureADGroupsResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
            $azureADGroups += $azureADGroupsResponse.value
        }  
        $azureADGroups = $azureADGroups | Sort-Object -Property displayname
         
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD Groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
}
  
$grantedWrite = ((Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites/$siteid/drive/items/$folderid/permissions" -Method Get -Headers $authorization -Verbose:$false).Value | where {$_.roles -contains $role}).GrantedTo

$assigned = foreach ($granted in $grantedWrite) {
    $azureADGroups | where {  $granted.User.id -eq $_.id } | Select-Object id, description, displayname
}

if (($assigned | Measure-Object).Count -ge 1) {
   foreach ($assign in $assigned) {
       $members = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$($assign.id)/members" -Method Get -Headers $authorization).Value
       $members | Select-Object id,UserPrincipalName,displayName,department,jobTitle,companyName | Sort-Object -Property DisplayName | foreach { Write-Output $_ }
   }
}
foreach ($granted in $grantedWrite) {
    $azureADUsers | where {  $granted.User.id -eq $_.id } | foreach { Write-Output $_ }
}
