<#
.SYNOPSIS
    Functions to obtain bearer tokens from Azure AD using certificates, client secrets, and managed identities.

.DESCRIPTION
    This module provides functions to obtain bearer tokens using certificates, client secrets, and managed identities from Azure AD. It includes helper functions for modularity and ease of maintenance.

#>

# Helper function to get certificate
Function Get-Certificate {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$certStore,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$thumbprint
    )
    $cert = Get-Item -Path "Cert:\$($certStore)\My\$($thumbprint)"
    if (-not $cert) {
        throw "Certificate not found."
    }
    return $cert
}

# Helper function to create JWT header
Function Create-JwtHeader {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )
    return @{
        alg = "RS256"
        typ = "JWT"
        x5t = [System.Convert]::ToBase64String($cert.GetCertHash()).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
}

# Helper function to create JWT payload
Function Create-JwtPayload {
    param (
        [Parameter(Mandatory = $true)]
        [string]$tenantId,
        [Parameter(Mandatory = $true)]
        [string]$applicationId
    )
    return @{
        aud = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
        iss = $applicationId
        sub = $applicationId
        jti = [System.Guid]::NewGuid().ToString()
        nbf = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        exp = ([System.DateTimeOffset]::UtcNow.AddMinutes(10)).ToUnixTimeSeconds()
    }
}

# Helper function to encode JWT
Function Encode-Jwt {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$header,
        [Parameter(Mandatory = $true)]
        [hashtable]$payload
    )
    $headerJson = $header | ConvertTo-Json -Compress
    $payloadJson = $payload | ConvertTo-Json -Compress
    $headerEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $payloadEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return "$headerEncoded.$payloadEncoded"
}

# Helper function to sign JWT
# Helper function to sign JWT
Function Sign-Jwt {
    param (
        [Parameter(Mandatory = $true)]
        [string]$token,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )
    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $privateKey) {
        throw "Private key not found in the certificate."
    }
    $signature = [System.Convert]::ToBase64String($privateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($token), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return "$token.$signature"
}


<#
.SYNOPSIS
    Get a bearer token using a certificate.

.DESCRIPTION
    This function obtains a bearer token from Azure AD using a certificate. It uses helper functions to get the certificate, create the JWT header and payload, encode the JWT, and sign the JWT.

.PARAMETER certStore
    The certificate store location ('LocalMachine' or 'CurrentUser').

.PARAMETER thumbprint
    The thumbprint of the certificate.

.PARAMETER tenantId
    The Azure AD tenant ID.

.PARAMETER applicationId
    The Azure AD application ID.

.PARAMETER scope
    The scope for the token request. Default is 'https://graph.microsoft.com/.default'.

.EXAMPLE
    # Get a bearer token using a certificate
    $token = Get-CertBearerToken -certStore 'LocalMachine' -thumbprint 'YOUR_CERT_THUMBPRINT' -tenantId 'YOUR_TENANT_ID' -applicationId 'YOUR_APP_ID'
    Write-Output $token
#>
Function Get-CertBearerToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$certStore,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$thumbprint,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$tenantId,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$applicationId,
        [string]$scope = 'https://graph.microsoft.com/.default'
    )

    try {
        $cert = Get-Certificate -certStore $certStore -thumbprint $thumbprint
        $header = Create-JwtHeader -cert $cert
        $payload = Create-JwtPayload -tenantId $tenantId -applicationId $applicationId
        $token = Encode-Jwt -header $header -payload $payload
        $jwt = Sign-Jwt -token $token -cert $cert

        $body = @{
            client_id             = $applicationId
            scope                 = $scope
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion      = $jwt
            grant_type            = "client_credentials"
        }

        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        return $response.access_token
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}

<#
.SYNOPSIS
    Get a bearer token using a client secret.

.DESCRIPTION
    This function obtains a bearer token from Azure AD using a client secret.

.PARAMETER tenantId
    The Azure AD tenant ID.

.PARAMETER applicationId
    The Azure AD application ID.

.PARAMETER clientSecret
    The Azure AD client secret.

.EXAMPLE
    # Get a bearer token using a client secret
    $token = Get-SecretBearerToken -tenantId 'YOUR_TENANT_ID' -applicationId 'YOUR_APP_ID' -clientSecret 'YOUR_CLIENT_SECRET'
    Write-Output $token
#>
Function Get-SecretBearerToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$tenantId,
        [Parameter(Mandatory = $true)]
        [string]$applicationId,
        [Parameter(Mandatory = $true)]
        [string]$clientSecret
    )

    try {
        $body = @{
            client_id     = $applicationId
            scope         = "https://graph.microsoft.com/.default"
            client_secret = $clientSecret
            grant_type    = "client_credentials"
        }

        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        return $response.access_token
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}

<#
.SYNOPSIS
    Get a bearer token using a managed identity.

.DESCRIPTION
    This function obtains a bearer token from Azure AD using a managed identity in an Azure Runbook.

.PARAMETER resource
    The resource for which the token is requested. Default is 'https://graph.microsoft.com'.

.EXAMPLE
    # Get a bearer token using a managed identity
    $token = Get-ManagedIdentityBearerToken -resource 'https://graph.microsoft.com'
    Write-Output $token
#>
Function Get-ManagedIdentityBearerToken {
    [CmdletBinding()]
    param (
        [string]$resource = 'https://graph.microsoft.com'
    )

    try {
        if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
            $response = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resource" -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"; 'Metadata' = 'True' }).RawContentStream.ToArray()) | ConvertFrom-Json
            return $response.access_token
        }
        else {
            $response = Invoke-RestMethod -Method Get -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$resource" -Headers @{Metadata = "true" }
            return $response.access_token
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}


# Export only the public function
Export-ModuleMember -Function Get-CertBearerToken, Get-SecretBearerToken, Get-ManagedIdentityBearerToken