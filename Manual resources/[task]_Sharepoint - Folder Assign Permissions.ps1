$body = @{
    "client_id"=$AADAppId
    "scope"="https://graph.microsoft.com/.default"
    "client_secret"=$AADAppSecret
    "grant_type"="client_credentials"
}
$siteid = $form.dropDownSites.id
$sitename = $form.dropDownSites.name
$folderid = $form.dropDownFolder.id
$foldername = $form.dropDownFolder.name
$readPermissionsAdd = $form.dualListRead.leftToRight
$readPermissionsRemove = $form.dualListRead.rightToLeft
$writePermissionsAdd = $form.dualListWrite.leftToRight
$writePermissionsRemove = $form.dualListWrite.rightToLeft

$tokenquery = Invoke-RestMethod -uri https://login.microsoftonline.com/$($AADtenantID)/oauth2/v2.0/token -body $body -Method Post -ContentType 'application/x-www-form-urlencoded'

$baseGraphUri = "https://graph.microsoft.com/"
$headers = @{
    "content-type" = "Application/Json"
    "authorization" = "Bearer $($tokenquery.access_token)"
}

 $baseSearchUri = "https://graph.microsoft.com/"
try {
        $searchUri = $baseSearchUri + "v1.0/groups" + '?$select=id,description,displayname' + '&$top=999'
 
        $azureADGroupsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $headers -Verbose:$false
        $azureADGroups = $azureADGroupsResponse.value
        while (![string]::IsNullOrEmpty($azureADGroupsResponse.'@odata.nextLink')) {
            $azureADGroupsResponse = Invoke-RestMethod -Uri $azureADGroupsResponse.'@odata.nextLink' -Method Get -Headers $headers -Verbose:$false
            $azureADGroups += $azureADGroupsResponse.value
        }  
        $azureADGroups = $azureADGroups | Sort-Object -Property displayname
         
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD Groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
}

$grantedWrite = ((Invoke-RestMethod -Uri ($baseSearchUri + "v1.0/sites/$siteid/drive/items/$folderid/permissions") -Method Get -Headers $headers -Verbose:$false).Value | where {$_.roles -contains "Write"}).GrantedTo
$grantedRead = ((Invoke-RestMethod -Uri ($baseSearchUri + "v1.0/sites/$siteid/drive/items/$folderid/permissions") -Method Get -Headers $headers -Verbose:$false).Value | where {$_.roles -contains "Read"}).GrantedTo

$assignedWrite = foreach ($granted in $grantedWrite) {
    $azureADGroups | where {  $granted.User.id -eq $_.id -and $_.description -match $folderid } | Select id,description,displayname
}
$assignedRead = foreach ($granted in $grantedRead) {
    $azureADGroups | where {  $granted.User.id -eq $_.id -and $_.description -match $folderid } | Select id,description,displayname
}

$groupreadfound = $false
if (($assignedRead | Measure-Object).Count -eq 0)
{
    $readcreated = $false
    try
    {
        $mailnick = $sitename + "_" + $foldername
        $mailnick = $mailnick -replace " ", "_"
        $bodygroupread = @{
            "description" = "$folderid - READ"
            "displayName" = "Read Group for Site $sitename and folder $foldername"
            "mailEnabled" = $false
            "mailNickName" = $mailnick + "_read"
            "securityEnabled" = $true
        }
        $aread = Invoke-RestMethod -uri "https://graph.microsoft.com/v1.0/groups" -Method POST -body ($bodygroupread | ConvertTo-Json) -Headers $headers
        Write-Information "Read Group created for folder"
        $readcreated = $true
    }
    catch {
        Write-Error "Failed Create Read Group for $folderid"
    }
    
    if ($readcreated)
    {
        for ($i = 0; $i -lt 20; $i++)
        {    
            try {
                $bodyinviteread = @{
                    "requireSignIn" = $true
                    "sendInvitation" = $false
                    "roles" = @("read")
                    "recipients" =  @(@{"objectId" = "$($aread.id)"})
                }
                $ainviteread = Invoke-RestMethod -uri "https://graph.microsoft.com/v1.0/sites/$siteid/drive/items/$folderid/invite" -Method POST -body ($bodyinviteread | ConvertTo-Json) -Headers $headers
                
                Write-Information "Read Group invited to folder"
            }
            catch {
                Start-Sleep -Seconds 20
            }
        }
    }
} else {
    $aread = $assignedRead
    $groupreadfound = $true
}
$groupwritefound = $false
if (($assignedWrite | Measure-Object).Count -eq 0)
{
    $writecreated = $false
    try
    {
        $mailnick = $sitename + "_" + $foldername
        $mailnick = $mailnick -replace " ", "_"
        $bodygroupread = @{
            "description" = "$folderid - WRITE"
            "displayName" = "Write Group for Site $sitename and folder $foldername"
            "mailEnabled" = $false
            "mailNickName" = $mailnick + "_write"
            "securityEnabled" = $true
        }
        $awrite = Invoke-RestMethod -uri "https://graph.microsoft.com/v1.0/groups" -Method POST -body ($bodygroupread | ConvertTo-Json) -Headers $headers
        Write-Information "Write Group created for folder"
        $writecreated = $true
    }
    catch {
        Write-Error "Failed Create Write Group for $folderid"
    }
    
    if ($writecreated)
    {
        for ($i = 0; $i -lt 20; $i++)
        {    
            try {                
                $bodyinvitewrite = @{
                    "requireSignIn" = $true
                    "sendInvitation" = $false
                    "roles" = @("write")
                    "recipients" =  @(@{"objectId" = "$($awrite.id)"})
                }
                $ainviteread = Invoke-RestMethod -uri "https://graph.microsoft.com/v1.0/sites/$siteid/drive/items/$folderid/invite" -Method POST -body ($bodyinvitewrite | ConvertTo-Json) -Headers $headers
                
                Write-Information "Write Group invited to folder"
            }
            catch {
                Start-Sleep -Seconds 20
            }
        }
    }
} else {
    $awrite = $assignedWrite
    $groupwritefound = $true
}


if ($groupreadfound)
{   
    if($readPermissionsAdd -ne $null){
        try {
            foreach($user in $readPermissionsAdd){                
                $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($aread.id)/members" + '/$ref'
                $body = @{ "@odata.id"= "$baseGraphUri/v1.0/users/$($user.id)" } | ConvertTo-Json -Depth 10
    
                $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $headers -Verbose:$false
            }
    
            Write-Information "Finished adding AzureAD users [$($readPermissionsAdd | ConvertTo-Json)] to AzureAD group [$($bodygroupwrite.displayName)]"
        } catch {
            Write-Error "Could not add AzureAD users [$($readPermissionsAdd | ConvertTo-Json)] to AzureAD group [$($bodygroupwrite.displayName)]. Error: $($_.Exception.Message)"
        }
    }
    if($readPermissionsRemove -ne $null){
        try {
            foreach($user in $readPermissionsRemove){                
                $removeGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($aread.id)/members/$($user.id)" + '/$ref'
                
                $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $headers -Verbose:$false
            }
    
            Write-Information "Finished removing AzureAD users [$($readPermissionsRemove | ConvertTo-Json)] from AzureAD group [$($bodygroupwrite.displayName)]"
        } catch {
            Write-Error "Could not remove AzureAD users [$($readPermissionsRemove | ConvertTo-Json)] from AzureAD group [$($bodygroupwrite.displayName)]. Error: $($_.Exception.Message)"
        }
    }
    if($readPermissionsAdd -ne "[]"){
        try {
            $usersToAddJson = $readPermissionsAdd | ConvertFrom-Json
    
            foreach($user in $usersToAddJson){
                #Add the authorization header to the request
                $authorization = @{
                    Authorization = "Bearer $accesstoken";
                    'Content-Type' = "application/json";
                    Accept = "application/json";
                }
    
                $baseGraphUri = "https://graph.microsoft.com/"
                $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($aread.id)/members" + '/$ref'
                $body = @{ "@odata.id"= "https://graph.microsoft.com/v1.0/users/$($user.id)" } | ConvertTo-Json -Depth 10
    
                $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $headers -Verbose:$false
            }
    
            HID-Write-Status -Message "Finished adding AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json)" -Event Success
            HID-Write-Summary -Message "Successfully added AzureAD user [$userPrincipalName] to AzureAD groups" -Event Success
        } catch {
            HID-Write-Status -Message "Could not add AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json). Error: $($_.Exception.Message)" -Event Error
            HID-Write-Summary -Message "Failed to add AzureAD user [$userPrincipalName] to AzureAD groups" -Event Failed
        }
    }
    if($readPermissionsRemove -ne "[]"){
        try {
            $usersToAddJson = $readPermissionsRemove | ConvertFrom-Json
    
            foreach($user in $usersToAddJson){
                #Add the authorization header to the request
                $authorization = @{
                    Authorization = "Bearer $accesstoken";
                    'Content-Type' = "application/json";
                    Accept = "application/json";
                }
    
                $baseGraphUri = "https://graph.microsoft.com/"
                $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($aread.id)/members/$($user.id)" + '/$ref'
                $response = Invoke-RestMethod -Method DELETE -Uri $addGroupMembershipUri -Body $body -Headers $headers -Verbose:$false
            }
    
            HID-Write-Status -Message "Finished adding AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json)" -Event Success
            HID-Write-Summary -Message "Successfully added AzureAD user [$userPrincipalName] to AzureAD groups" -Event Success
        } catch {
            HID-Write-Status -Message "Could not add AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json). Error: $($_.Exception.Message)" -Event Error
            HID-Write-Summary -Message "Failed to add AzureAD user [$userPrincipalName] to AzureAD groups" -Event Failed
        }
    }
}
if ($groupwritefound)
{   
    if($writePermissionsAdd -ne $null){
        try {
            foreach($user in $writePermissionsAdd){                
                $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($awrite.id)/members" + '/$ref'
                $body = @{ "@odata.id"= "$baseGraphUri/v1.0/users/$($user.id)" } | ConvertTo-Json -Depth 10
    
                $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $headers -Verbose:$false
            }
    
            Write-Information "Finished adding AzureAD users [$($writePermissionsAdd | ConvertTo-Json)] to AzureAD group [$($bodygroupwrite.displayName)]"
        } catch {
            Write-Error "Could not add AzureAD users [$($writePermissionsAdd | ConvertTo-Json)] to AzureAD group [$($bodygroupwrite.displayName)]. Error: $($_.Exception.Message)"
        }
    }
    if($writePermissionsRemove -ne $null){
        try {
            foreach($user in $writePermissionsRemove){                
                $removeGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($awrite.id)/members/$($user.id)" + '/$ref'
                
                $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $headers -Verbose:$false
            }
    
            Write-Information "Finished removing AzureAD users [$($writePermissionsRemove | ConvertTo-Json)] from AzureAD group [$($bodygroupwrite.displayName)]"
        } catch {
            Write-Error "Could not remove AzureAD users [$($writePermissionsRemove | ConvertTo-Json)] from AzureAD group [$($bodygroupwrite.displayName)]. Error: $($_.Exception.Message)"
        }
    }
}
