# Variables configured in form
$group = $form.group
$user = $form.user
$action = $form.action

# Fixed values
$scopes = @(
    "https://www.googleapis.com/auth/admin.directory.group"
    "https://www.googleapis.com/auth/admin.directory.user"
)

# Global variables
$p12CertificateBase64 = $GoogleP12CertificateBase64
$p12CertificatePassword = $GoogleP12CertificatePassword
$serviceAccountEmail = $GoogleServiceAccountEmail
$userId = $GoogleAdminEmail # Email address of admin with permissions to manage groups and users.

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-GoogleError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }

        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $httpErrorObj.FriendlyMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $httpErrorObj.FriendlyMessage = $httpErrorObj.FriendlyMessage + ". Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.error
                }
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject
            }
        }
        catch {
            if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
                $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject.Exception.Message
            }
        }
            
        Write-Output $httpErrorObj
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.Powershell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

try {
    #region Create access token
    $actionMessage = "creating acess token"

    # Create a JWT (JSON Web Token) header
    $header = @{
        alg = "RS256"
        typ = "JWT"
    } | ConvertTo-Json
    $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

    # Calculate the Unix timestamp for 'exp' and 'iat'
    $now = [Math]::Round((Get-Date (Get-Date).ToUniversalTime() -UFormat "%s"), 0)
    $createDate = $now
    $expiryDate = $createDate + 3540 # Expires in 59 minutes

    # Create a JWT payload
    $payload = [Ordered]@{
        iss   = "$serviceAccountEmail"
        sub   = "$userId"
        scope = "$($scopes -join " ")"
        aud   = "https://www.googleapis.com/oauth2/v4/token"
        exp   = "$expiryDate"
        iat   = "$createDate"
    } | ConvertTo-Json
    $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload))

    # Convert Base64 string to certificate
    $rawP12Certificate = [system.convert]::FromBase64String($p12CertificateBase64)
    $p12Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawP12Certificate, $p12CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

    # Extract the private key from the P12 certificate
    $rsaPrivate = $P12Certificate.PrivateKey
    $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
    $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

    # Sign the JWT
    $signatureInput = "$base64Header.$base64Payload"
    $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), "SHA256")
    $base64Signature = [System.Convert]::ToBase64String($signature)

    # Create the JWT token
    $jwtToken = "$signatureInput.$base64Signature"

    $createAccessTokenBody = [Ordered]@{
        grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assertion  = $jwtToken
    }

    $createAccessTokenSplatParams = @{
        Uri         = "https://www.googleapis.com/oauth2/v4/token"
        Method      = "POST"
        Body        = $createAccessTokenBody
        ContentType = "application/x-www-form-urlencoded"
        Verbose     = $false
        ErrorAction = "Stop"
    }

    $createAccessTokenResponse = Invoke-RestMethod @createAccessTokenSplatParams

    Write-Verbose "Created access token. Result: $($createAccessTokenResponse | ConvertTo-Json)."
    #endregion Create access token

    #region Create headers
    $actionMessage = "creating headers"

    $headers = @{
        "Authorization" = "Bearer $($createAccessTokenResponse.access_token)"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json;charset=utf-8"
    }

    Write-Verbose "Created headers. Result: $($headers | ConvertTo-Json)."
    #endregion Create headers
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage

    Write-Error $auditMessage
}

if ($null -ne $headers) {
    switch ($action) {
        "addUserToGroup" {
            try {
                #region Add member to group
                # Google docs: https://developers.google.com/admin-sdk/directory/reference/rest/v1/members/insert
                # Define user object to add as member
                $user = @{
                    id          = $user.primaryEmail
                    displayName = $user.fullName
                }
        
                # Define group object to add the member to
                $group = @{
                    id          = $group.email
                    displayName = $group.name
                }
        
                $actionMessage = "adding member with displayname [$($user.displayName)] and id [$($user.id)] to group with displayname [$($group.displayName)] and id [$($group.id)]"
        
                $addMemberBody = @{
                    email = $user.id
                    role  = "MEMBER"
                }
                    
                $addMemberSplatParams = @{
                    Uri         = "https://www.googleapis.com/admin/directory/v1/groups/$($group.id)/members"
                    Headers     = $headers
                    Method      = "POST"
                    Body        = ($addMemberBody | ConvertTo-Json -Depth 10)
                    ContentType = "application/json; charset=utf-8"
                    Verbose     = $false 
                    ErrorAction = "Stop"
                }
        
                $addMemberResponse = Invoke-RestMethod @addMemberSplatParams
        
                Write-Verbose "Added member with displayname [$($user.displayName)] and id [$($user.id)] to group with displayname [$($group.displayName)] and id [$($group.id)]."
                #endregion Add member to group
        
                #region Send auditlog to HelloID
                $actionMessage = "sending auditlog to HelloID"
        
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Google" # optional (free format text) 
                    Message           = "Added user with displayname [$($user.displayName)] and id [$($user.id)] to group with displayname [$($group.displayName)] and id [$($group.id)]." # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = [string]$group.displayName # optional (free format text)
                    TargetIdentifier  = [string]$group.id # optional (free format text)
                }
                Write-Information -Tags "Audit" -MessageData $log
                #endregion Send auditlog to HelloID
            }
            catch {
                $ex = $PSItem
                if ($($ex.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or
                    $($ex.Exception.GetType().FullName -eq "System.Net.WebException")) {
                    $errorObj = Resolve-GoogleError -ErrorObject $ex
                    $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
                    $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
                }
                else {
                    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                }
        
                if ($auditMessage -like "*Member already exists*") {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
        
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = "Skipped adding user with displayname [$($user.displayName)] and id [$($user.id)] to group with displayname [$($group.displayName)] and id [$($group.id)]. Reason: User is already a member of the group." # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$group.displayName # optional (free format text)
                        TargetIdentifier  = [string]$group.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
                }
                else {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
        
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = $auditMessage # required (free format text)
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$group.displayName # optional (free format text)
                        TargetIdentifier  = [string]$group.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
        
                    Write-Warning $warningMessage
        
                    Write-Error $auditMessage
                }
            }
        }
        "removeUserFromGroup" {
            try {
                #region Remove member from group
                # Google docs: https://developers.google.com/admin-sdk/directory/reference/rest/v1/members/delete
                # Define user object to remove as member
                $user = @{
                    id          = $user.primaryEmail
                    displayName = $user.fullName
                }
                # Define group object to remove the member from
                $group = @{
                    id          = $group.email
                    displayName = $group.name
                }
    
                $actionMessage = "removing member with displayname [$($user.displayName)] and id [$($user.id)] from group with displayname [$($group.displayName)] and id [$($group.id)]"
                
                $removeMemberSplatParams = @{
                    Uri         = "https://www.googleapis.com/admin/directory/v1/groups/$($group.id)/members/$($user.id)"
                    Headers     = $headers
                    Method      = "DELETE"
                    Verbose     = $false 
                    ErrorAction = "Stop"
                }
    
                $removeMemberResponse = Invoke-RestMethod @removeMemberSplatParams
    
                Write-Verbose "Removed member with displayname [$($user.displayName)] and id [$($user.id)] from group with displayname [$($group.displayName)] and id [$($group.id)]."
                #endregion Remove member from group
    
                #region Send auditlog to HelloID
                $actionMessage = "sending auditlog to HelloID"
    
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Google" # optional (free format text) 
                    Message           = "Removed user with displayname [$($user.displayName)] and id [$($user.id)] from group with displayname [$($group.displayName)] and id [$($group.id)]." # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = [string]$group.displayName # optional (free format text)
                    TargetIdentifier  = [string]$group.id # optional (free format text)
                }
                Write-Information -Tags "Audit" -MessageData $log
                #endregion Send auditlog to HelloID
            }
            catch {
                $ex = $PSItem
                if ($($ex.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or
                    $($ex.Exception.GetType().FullName -eq "System.Net.WebException")) {
                    $errorObj = Resolve-GoogleError -ErrorObject $ex
                    $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
                    $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
                }
                else {
                    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
                    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                }
    
                if ($auditMessage -like "*Resource Not Found: memberKey*") {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
    
                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = "Skipped removing user with displayname [$($user.displayName)] and id [$($user.id)] from group with displayname [$($group.displayName)] and id [$($group.id)]. Reason: User is already no longer a member." # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$group.displayName # optional (free format text)
                        TargetIdentifier  = [string]$group.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
                }
                elseif ($auditMessage -like "*Resource Not Found: groupKey*") {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
    
                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = "Skipped removing user with displayname [$($user.displayName)] and id [$($user.id)] from group with displayname [$($group.displayName)] and id [$($group.id)]. Reason: The group no longer exists." # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$group.displayName # optional (free format text)
                        TargetIdentifier  = [string]$group.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
                }
                else {
                    #region Send auditlog to HelloID
                    $actionMessage = "sending auditlog to HelloID"
    
                    $Log = @{
                        Action            = "RevokeMembership" # optional. ENUM (undefined = default)
                        System            = "Google" # optional (free format text)
                        Message           = $auditMessage # required (free format text)
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = [string]$group.displayName # optional (free format text)
                        TargetIdentifier  = [string]$group.id # optional (free format text)
                    }
                    Write-Information -Tags "Audit" -MessageData $log
                    #endregion Send auditlog to HelloID
    
                    Write-Warning $warningMessage
    
                    Write-Error $auditMessage
                }
            }
        }
    }
}
