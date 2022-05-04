# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Sharepoint") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADtenantID
$tmpName = @'
AADtenantID
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> AADAppSecret
$tmpName = @'
AADAppSecret
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> companyName
$tmpName = @'
companyName
'@ 
$tmpValue = @'
{{company.name}}
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "get-permissions-write" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$folderid = $datasource.selectedFolder.id
$siteid = $datasource.selectedSite.id
$role = "write"

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
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"userPrincipalName","type":0},{"key":"displayName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedFolder","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedSite","type":0,"options":1}]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
get-permissions-write
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "get-permissions-write" #>

<# Begin: DataSource "get-users" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
          
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
 
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/users" + '?$select=id,UserPrincipalName,displayName,department,jobTitle,companyName' + '&$top=999'
 
        $azureADUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADUsers = $azureADUsersResponse.value
        while (![string]::IsNullOrEmpty($azureADUsersResponse.'@odata.nextLink')) {
            $azureADUsersResponse = Invoke-RestMethod -Uri $azureADUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
            $azureADUsers += $azureADUsersResponse.value
        }  
        $azureADUsers = $azureADUsers | Sort-Object -Property DisplayName
        $resultCount = @($azureADUsers).Count
        Write-Information "Result count: $resultCount"
          
        if($resultCount -gt 0){
            $azureADUsers | foreach { Write-Output $_ }
        }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
}
  
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"userPrincipalName","type":0},{"key":"displayName","type":0},{"key":"department","type":0},{"key":"jobTitle","type":0},{"key":"companyName","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_5 = [PSCustomObject]@{} 
$dataSourceGuid_5_Name = @'
get-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_5_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_5) 
<# End: DataSource "get-users" #>

<# Begin: DataSource "get-users" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
          
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
 
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/users" + '?$select=id,UserPrincipalName,displayName,department,jobTitle,companyName' + '&$top=999'
 
        $azureADUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADUsers = $azureADUsersResponse.value
        while (![string]::IsNullOrEmpty($azureADUsersResponse.'@odata.nextLink')) {
            $azureADUsersResponse = Invoke-RestMethod -Uri $azureADUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
            $azureADUsers += $azureADUsersResponse.value
        }  
        $azureADUsers = $azureADUsers | Sort-Object -Property DisplayName
        $resultCount = @($azureADUsers).Count
        Write-Information "Result count: $resultCount"
          
        if($resultCount -gt 0){
            $azureADUsers | foreach { Write-Output $_ }
        }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
}
  
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"userPrincipalName","type":0},{"key":"displayName","type":0},{"key":"department","type":0},{"key":"jobTitle","type":0},{"key":"companyName","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
get-users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "get-users" #>

<# Begin: DataSource "get-sites" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"createdDateTime","type":0},{"key":"id","type":0},{"key":"lastModifiedDateTime","type":0},{"key":"name","type":0},{"key":"webUrl","type":0},{"key":"displayName","type":0},{"key":"siteCollection","type":0},{"key":"root","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
get-sites
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "get-sites" #>

<# Begin: DataSource "get-folders" #>
$tmpPsScript = @'
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
$a = Invoke-RestMethod -uri "https://graph.microsoft.com/v1.0/sites/$($datasource.selectedSite.id)/drive/root/children" -Method GET -Headers $headers
$a.value | Sort-Object name | foreach { Write-Output $_ }
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"name","type":0},{"key":"webUrl","type":0},{"key":"folder","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedSite","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
get-folders
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "get-folders" #>

<# Begin: DataSource "get-permissions-read" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"id","type":0},{"key":"userPrincipalName","type":0},{"key":"displayName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedSite","type":0,"options":1},{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedFolder","type":0,"options":1}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
get-permissions-read
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "get-permissions-read" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Sharepoint - Folder Assign Permissions - Clone 1" #>
$tmpSchema = @"
[{"key":"dropDownSites","templateOptions":{"label":"Select Site","required":true,"useObjects":false,"useDataSource":true,"useFilter":true,"options":["Option 1","Option 2","Option 3"],"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[]}},"valueField":"id","textField":"displayName"},"type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"dropDownFolder","templateOptions":{"label":"Select Folder","useObjects":false,"useDataSource":true,"useFilter":true,"options":["Option 1","Option 2","Option 3"],"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedSite","otherFieldValue":{"otherFieldKey":"dropDownSites"}}]}},"valueField":"id","textField":"name","required":true},"hideExpression":"!model[\"dropDownSites\"]","type":"dropdown","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"dualListRead","templateOptions":{"label":"Read Permissions","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"id","optionDisplayProperty":"userPrincipalName","labelLeft":"All Users","labelRight":"Assigned Users"},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedSite","otherFieldValue":{"otherFieldKey":"dropDownSites"}},{"propertyName":"selectedFolder","otherFieldValue":{"otherFieldKey":"dropDownFolder"}}]}},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[]}}},"hideExpression":"!model[\"dropDownFolder\"]","type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"dualListWrite","templateOptions":{"label":"Write Permissions","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"id","optionDisplayProperty":"userPrincipalName","labelLeft":"All Users","labelRight":"Assigned Users"},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[{"propertyName":"selectedFolder","otherFieldValue":{"otherFieldKey":"dropDownFolder"}},{"propertyName":"selectedSite","otherFieldValue":{"otherFieldKey":"dropDownSites"}}]}},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_5","input":{"propertyInputs":[]}}},"hideExpression":"!model[\"dropDownFolder\"]","type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Sharepoint - Folder Assign Permissions - Clone 1
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Sharepoint - Folder Assign Permissions
'@
$tmpTask = @'
{"name":"Sharepoint - Folder Assign Permissions","script":"$body = @{\r\n    \"client_id\"=$AADAppId\r\n    \"scope\"=\"https://graph.microsoft.com/.default\"\r\n    \"client_secret\"=$AADAppSecret\r\n    \"grant_type\"=\"client_credentials\"\r\n}\r\n$siteid = $form.dropDownSites.id\r\n$sitename = $form.dropDownSites.name\r\n$folderid = $form.dropDownFolder.id\r\n$foldername = $form.dropDownFolder.name\r\n$readPermissionsAdd = $form.dualListRead.leftToRight\r\n$readPermissionsRemove = $form.dualListRead.rightToLeft\r\n$writePermissionsAdd = $form.dualListWrite.leftToRight\r\n$writePermissionsRemove = $form.dualListWrite.rightToLeft\r\n\r\n$tokenquery = Invoke-RestMethod -uri https://login.microsoftonline.com/$($AADtenantID)/oauth2/v2.0/token -body $body -Method Post -ContentType \u0027application/x-www-form-urlencoded\u0027\r\n\r\n$baseGraphUri = \"https://graph.microsoft.com/\"\r\n$headers = @{\r\n    \"content-type\" = \"Application/Json\"\r\n    \"authorization\" = \"Bearer $($tokenquery.access_token)\"\r\n}\r\n\r\n $baseSearchUri = \"https://graph.microsoft.com/\"\r\ntry {\r\n        $searchUri = $baseSearchUri + \"v1.0/groups\" + \u0027?$select=id,description,displayname\u0027 + \u0027\u0026$top=999\u0027\r\n \r\n        $azureADGroupsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $headers -Verbose:$false\r\n        $azureADGroups = $azureADGroupsResponse.value\r\n        while (![string]::IsNullOrEmpty($azureADGroupsResponse.\u0027@odata.nextLink\u0027)) {\r\n            $azureADGroupsResponse = Invoke-RestMethod -Uri $azureADGroupsResponse.\u0027@odata.nextLink\u0027 -Method Get -Headers $headers -Verbose:$false\r\n            $azureADGroups += $azureADGroupsResponse.value\r\n        }  \r\n        $azureADGroups = $azureADGroups | Sort-Object -Property displayname\r\n         \r\n} catch {\r\n    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message\r\n    Write-Error (\"Error searching for AzureAD Groups. Error: $($_.Exception.Message)\" + $errorDetailsMessage)\r\n}\r\n\r\n$grantedWrite = ((Invoke-RestMethod -Uri ($baseSearchUri + \"v1.0/sites/$siteid/drive/items/$folderid/permissions\") -Method Get -Headers $headers -Verbose:$false).Value | where {$_.roles -contains \"Write\"}).GrantedTo\r\n$grantedRead = ((Invoke-RestMethod -Uri ($baseSearchUri + \"v1.0/sites/$siteid/drive/items/$folderid/permissions\") -Method Get -Headers $headers -Verbose:$false).Value | where {$_.roles -contains \"Read\"}).GrantedTo\r\n\r\n$assignedWrite = foreach ($granted in $grantedWrite) {\r\n    $azureADGroups | where {  $granted.User.id -eq $_.id -and $_.description -match $folderid } | Select id,description,displayname\r\n}\r\n$assignedRead = foreach ($granted in $grantedRead) {\r\n    $azureADGroups | where {  $granted.User.id -eq $_.id -and $_.description -match $folderid } | Select id,description,displayname\r\n}\r\n\r\n$groupreadfound = $false\r\nif (($assignedRead | Measure-Object).Count -eq 0)\r\n{\r\n    $readcreated = $false\r\n    try\r\n    {\r\n        $mailnick = $sitename + \"_\" + $foldername\r\n        $mailnick = $mailnick -replace \" \", \"_\"\r\n        $bodygroupread = @{\r\n            \"description\" = \"$folderid - READ\"\r\n            \"displayName\" = \"Read Group for Site $sitename and folder $foldername\"\r\n            \"mailEnabled\" = $false\r\n            \"mailNickName\" = $mailnick + \"_read\"\r\n            \"securityEnabled\" = $true\r\n        }\r\n        $aread = Invoke-RestMethod -uri \"https://graph.microsoft.com/v1.0/groups\" -Method POST -body ($bodygroupread | ConvertTo-Json) -Headers $headers\r\n        Write-Information \"Read Group created for folder\"\r\n        $readcreated = $true\r\n    }\r\n    catch {\r\n        Write-Error \"Failed Create Read Group for $folderid\"\r\n    }\r\n    \r\n    if ($readcreated)\r\n    {\r\n        for ($i = 0; $i -lt 20; $i++)\r\n        {    \r\n            try {\r\n                $bodyinviteread = @{\r\n                    \"requireSignIn\" = $true\r\n                    \"sendInvitation\" = $false\r\n                    \"roles\" = @(\"read\")\r\n                    \"recipients\" =  @(@{\"objectId\" = \"$($aread.id)\"})\r\n                }\r\n                $ainviteread = Invoke-RestMethod -uri \"https://graph.microsoft.com/v1.0/sites/$siteid/drive/items/$folderid/invite\" -Method POST -body ($bodyinviteread | ConvertTo-Json) -Headers $headers\r\n                \r\n                Write-Information \"Read Group invited to folder\"\r\n            }\r\n            catch {\r\n                Start-Sleep -Seconds 20\r\n            }\r\n        }\r\n    }\r\n} else {\r\n    $aread = $assignedRead\r\n    $groupreadfound = $true\r\n}\r\n$groupwritefound = $false\r\nif (($assignedWrite | Measure-Object).Count -eq 0)\r\n{\r\n    $writecreated = $false\r\n    try\r\n    {\r\n        $mailnick = $sitename + \"_\" + $foldername\r\n        $mailnick = $mailnick -replace \" \", \"_\"\r\n        $bodygroupread = @{\r\n            \"description\" = \"$folderid - WRITE\"\r\n            \"displayName\" = \"Write Group for Site $sitename and folder $foldername\"\r\n            \"mailEnabled\" = $false\r\n            \"mailNickName\" = $mailnick + \"_write\"\r\n            \"securityEnabled\" = $true\r\n        }\r\n        $awrite = Invoke-RestMethod -uri \"https://graph.microsoft.com/v1.0/groups\" -Method POST -body ($bodygroupread | ConvertTo-Json) -Headers $headers\r\n        Write-Information \"Write Group created for folder\"\r\n        $writecreated = $true\r\n    }\r\n    catch {\r\n        Write-Error \"Failed Create Write Group for $folderid\"\r\n    }\r\n    \r\n    if ($writecreated)\r\n    {\r\n        for ($i = 0; $i -lt 20; $i++)\r\n        {    \r\n            try {                \r\n                $bodyinvitewrite = @{\r\n                    \"requireSignIn\" = $true\r\n                    \"sendInvitation\" = $false\r\n                    \"roles\" = @(\"write\")\r\n                    \"recipients\" =  @(@{\"objectId\" = \"$($awrite.id)\"})\r\n                }\r\n                $ainviteread = Invoke-RestMethod -uri \"https://graph.microsoft.com/v1.0/sites/$siteid/drive/items/$folderid/invite\" -Method POST -body ($bodyinvitewrite | ConvertTo-Json) -Headers $headers\r\n                \r\n                Write-Information \"Write Group invited to folder\"\r\n            }\r\n            catch {\r\n                Start-Sleep -Seconds 20\r\n            }\r\n        }\r\n    }\r\n} else {\r\n    $awrite = $assignedWrite\r\n    $groupwritefound = $true\r\n}\r\n\r\n\r\nif ($groupreadfound)\r\n{   \r\n    if($readPermissionsAdd -ne $null){\r\n        try {\r\n            foreach($user in $readPermissionsAdd){                \r\n                $addGroupMembershipUri = $baseGraphUri + \"v1.0/groups/$($aread.id)/members\" + \u0027/$ref\u0027\r\n                $body = @{ \"@odata.id\"= \"$baseGraphUri/v1.0/users/$($user.id)\" } | ConvertTo-Json -Depth 10\r\n    \r\n                $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $headers -Verbose:$false\r\n            }\r\n    \r\n            Write-Information \"Finished adding AzureAD users [$($readPermissionsAdd | ConvertTo-Json)] to AzureAD group [$($bodygroupwrite.displayName)]\"\r\n        } catch {\r\n            Write-Error \"Could not add AzureAD users [$($readPermissionsAdd | ConvertTo-Json)] to AzureAD group [$($bodygroupwrite.displayName)]. Error: $($_.Exception.Message)\"\r\n        }\r\n    }\r\n    if($readPermissionsRemove -ne $null){\r\n        try {\r\n            foreach($user in $readPermissionsRemove){                \r\n                $removeGroupMembershipUri = $baseGraphUri + \"v1.0/groups/$($aread.id)/members/$($user.id)\" + \u0027/$ref\u0027\r\n                \r\n                $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $headers -Verbose:$false\r\n            }\r\n    \r\n            Write-Information \"Finished removing AzureAD users [$($readPermissionsRemove | ConvertTo-Json)] from AzureAD group [$($bodygroupwrite.displayName)]\"\r\n        } catch {\r\n            Write-Error \"Could not remove AzureAD users [$($readPermissionsRemove | ConvertTo-Json)] from AzureAD group [$($bodygroupwrite.displayName)]. Error: $($_.Exception.Message)\"\r\n        }\r\n    }\r\n    if($readPermissionsAdd -ne \"[]\"){\r\n        try {\r\n            $usersToAddJson = $readPermissionsAdd | ConvertFrom-Json\r\n    \r\n            foreach($user in $usersToAddJson){\r\n                #Add the authorization header to the request\r\n                $authorization = @{\r\n                    Authorization = \"Bearer $accesstoken\";\r\n                    \u0027Content-Type\u0027 = \"application/json\";\r\n                    Accept = \"application/json\";\r\n                }\r\n    \r\n                $baseGraphUri = \"https://graph.microsoft.com/\"\r\n                $addGroupMembershipUri = $baseGraphUri + \"v1.0/groups/$($aread.id)/members\" + \u0027/$ref\u0027\r\n                $body = @{ \"@odata.id\"= \"https://graph.microsoft.com/v1.0/users/$($user.id)\" } | ConvertTo-Json -Depth 10\r\n    \r\n                $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $headers -Verbose:$false\r\n            }\r\n    \r\n            HID-Write-Status -Message \"Finished adding AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json)\" -Event Success\r\n            HID-Write-Summary -Message \"Successfully added AzureAD user [$userPrincipalName] to AzureAD groups\" -Event Success\r\n        } catch {\r\n            HID-Write-Status -Message \"Could not add AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json). Error: $($_.Exception.Message)\" -Event Error\r\n            HID-Write-Summary -Message \"Failed to add AzureAD user [$userPrincipalName] to AzureAD groups\" -Event Failed\r\n        }\r\n    }\r\n    if($readPermissionsRemove -ne \"[]\"){\r\n        try {\r\n            $usersToAddJson = $readPermissionsRemove | ConvertFrom-Json\r\n    \r\n            foreach($user in $usersToAddJson){\r\n                #Add the authorization header to the request\r\n                $authorization = @{\r\n                    Authorization = \"Bearer $accesstoken\";\r\n                    \u0027Content-Type\u0027 = \"application/json\";\r\n                    Accept = \"application/json\";\r\n                }\r\n    \r\n                $baseGraphUri = \"https://graph.microsoft.com/\"\r\n                $addGroupMembershipUri = $baseGraphUri + \"v1.0/groups/$($aread.id)/members/$($user.id)\" + \u0027/$ref\u0027\r\n                $response = Invoke-RestMethod -Method DELETE -Uri $addGroupMembershipUri -Body $body -Headers $headers -Verbose:$false\r\n            }\r\n    \r\n            HID-Write-Status -Message \"Finished adding AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json)\" -Event Success\r\n            HID-Write-Summary -Message \"Successfully added AzureAD user [$userPrincipalName] to AzureAD groups\" -Event Success\r\n        } catch {\r\n            HID-Write-Status -Message \"Could not add AzureAD user [$userPrincipalName] to AzureAD groups $($groupsToAddJson | ConvertTo-Json). Error: $($_.Exception.Message)\" -Event Error\r\n            HID-Write-Summary -Message \"Failed to add AzureAD user [$userPrincipalName] to AzureAD groups\" -Event Failed\r\n        }\r\n    }\r\n}\r\nif ($groupwritefound)\r\n{   \r\n    if($writePermissionsAdd -ne $null){\r\n        try {\r\n            foreach($user in $writePermissionsAdd){                \r\n                $addGroupMembershipUri = $baseGraphUri + \"v1.0/groups/$($awrite.id)/members\" + \u0027/$ref\u0027\r\n                $body = @{ \"@odata.id\"= \"$baseGraphUri/v1.0/users/$($user.id)\" } | ConvertTo-Json -Depth 10\r\n    \r\n                $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $headers -Verbose:$false\r\n            }\r\n    \r\n            Write-Information \"Finished adding AzureAD users [$($writePermissionsAdd | ConvertTo-Json)] to AzureAD group [$($bodygroupwrite.displayName)]\"\r\n        } catch {\r\n            Write-Error \"Could not add AzureAD users [$($writePermissionsAdd | ConvertTo-Json)] to AzureAD group [$($bodygroupwrite.displayName)]. Error: $($_.Exception.Message)\"\r\n        }\r\n    }\r\n    if($writePermissionsRemove -ne $null){\r\n        try {\r\n            foreach($user in $writePermissionsRemove){                \r\n                $removeGroupMembershipUri = $baseGraphUri + \"v1.0/groups/$($awrite.id)/members/$($user.id)\" + \u0027/$ref\u0027\r\n                \r\n                $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $headers -Verbose:$false\r\n            }\r\n    \r\n            Write-Information \"Finished removing AzureAD users [$($writePermissionsRemove | ConvertTo-Json)] from AzureAD group [$($bodygroupwrite.displayName)]\"\r\n        } catch {\r\n            Write-Error \"Could not remove AzureAD users [$($writePermissionsRemove | ConvertTo-Json)] from AzureAD group [$($bodygroupwrite.displayName)]. Error: $($_.Exception.Message)\"\r\n        }\r\n    }\r\n}","runInCloud":true}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-folder-open" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

