<#

PowerShell script for renewing ADFS server certificates

This PowerShell script is designed to renew the service communication, Token-Signing, and Token-Decrypting certificates of an ADFS server once a new certificate is generated by Let's Encrypt via the Acme package in pfSense.

It includes all the necessary steps to update the ADFS certificate, both on the ADFS side and on the HPE GreenLake side, to ensure the SAML SSO domain configuration is up-to-date.

This script is associated with a blog post on configuring HPE GreenLake SAML SSO Authentication with ADFS. For more details, visit: https://jullienl.github.io/Configuring-HPE-GreenLake-SSO-SAML-Authentication-with-ADFS/

This script must be executed every 60 days (so before the Let’s Encrypt certificate expires) on all ADFS servers in an ADFS farm and includes:

 - Downloading the ADFS certificate from pfSense (generated from Let’s Encrypt using the Acme package/service).
    
 - Updating the ADFS Windows server certificate:
    - Checking that the new and existing certificates found in the ADFS server personal trust store are identical.
    - If not identical, removing the existing certificate and importing the new one to the ADFS server personal trust store.
    - Assigning full control permission to the new certificate private key for the ADFS service account.
    - Updating the ADFS service communication, Token-Signing and Token-Decrypting certificates
    - Restarting the ADFS service.
    
 - Updating HPE GreenLake workspace SAML SSO details with the new ADFS certificate:
    - Connecting to the HPE GreenLake workspace using the SAML SSO recovery email (the only user who can update the SAML SSO domain using the HPECOMCmdlets module).
    - Checking that the HPE GreenLake SAML SSO Domain is set with the correct ADFS server certificate.
    - If different, modifying the SAML SSO domain with the new ADFS certificate using the HPECOMCmdlets PowerShell module.
    
 - Updating the ADFS Relying Party with the HPE GreenLake certificate (only if needed):
    - Retrieving the X509 certificate thumbprint of the Service Provider (HPE GreenLake).
    - Comparing it with the one configured in ADFS.
    - If different, updating the ADFS Relying Party set for HPE GreenLake with the new HPE GreenLake certificate.

Requirements: 
 - ACME package installed and properly configured in pfSense.
 - 'Write Certificates' Acme package option must be enable to save the Let's Encrypt signed certificate in the **/cf/conf/acme** folder of pfsense
 - IP address of pfSense and credential with administrative priviledge.
 - Recovery email credential of the HPE GreenLake workspace SAML SSO domain.

During execution, the script installs the pfSense and HPECOMCmdlets PowerShell modules if they are not already installed.

Note: This script has been tested with PowerShell 7.4.6 Core edition and does not include the certificate update of Web Application Proxy (WAP) servers.


Commands to create the scheduled task to run the script every 60 days (must be run as administrator priviledge):

> $trigger = New-JobTrigger -Daily -DaysInterval 60 -At 2am 
> $options = New-ScheduledJobOption -RunElevated
> Register-ScheduledJob -Trigger $trigger -FilePath "<path>\Renew-ADFS-certificate.ps1" -Name ADFS-Certificate--60d-Renewal -ScheduledJobOption $options

Other useful commands:
> Get-ScheduledJobOption ADFS-Certificate--60d-Renewal
> Get-ScheduledJob -Name ADFS-Certificate--60d-Renewal
> Unregister-scheduledjob -Name ADFS-Certificate--60d-Renewal


Sample output:

    Retrieving Let's Encrypt certificate 'example.com' from pfSense '192.168.1.1' in progress...
    20250115_094129 : [INFO] : Export path = C:\Certificate-renewal-script\example.com.p12
    The Let's Encrypt certificate is different from the one currently installed on the ADFS server. Renewal of the ADFS certificates is in progress...
    Existing ADFS server certificate 406DF116715FBB7A677799D9220A743C73998AC5 has been removed!
    The new Let's Encrypt certificate 66BE2C643461E9CAEF0D2E3B487AB161489EA88E has been imported successfully!
    Full control permissions have been successfully assigned to the new certificate's private key for the ADFS service account!
    Auto Certificate Rollover has been disabled successfully.
    ADFS Token-Signing certificate updated successfully.
    Old ADFS Token-Signing certificate has been removed successfully.
    ADFS Token-Decrypting certificate updated successfully.
    Old ADFS Token-Decrypting certificate has been removed successfully.
    ADFS Service Communication certificate updated successfully.  
    ADFS service restarted successfully.
    ADFS metadata file has been successfully downloaded.
    Retreiving the current ADFS certificate set in the SAML SSO domain 'example.com'
    The new ADFS server certificate is different from the one currently defined in GreenLake. Updating the SAML SSO domain with the new certificate is in progress...
    The HPE GreenLake SAML SSO domain 'example.com' has been successfully updated with the new ADFS certificate.
    Retreiving the current SP certificate set in the SAML SSO domain 'example.com'.
    Retreiving the relying party trust 'HPE GreenLake' set in ADFS for HPE GreenLake.
    The X509 certificate of the relying party 'example.com' in ADFS is not valid. Update in progress...
    The SP metadata file for the SAML SSO domain 'example.com' has been successfully downloaded from HPE GreenLake.
    Relying party 'HPE GreenLake' has been updated successfully with the new metadata information.
    ADFS service restarted successfully. Update completed! The new certificate is now in use.


Author: lionel.jullien@hpe.com
Date: January 2024

#>

#################################################################################
#        (C) Copyright 2022 Hewlett Packard Enterprise Development LP           #
#################################################################################
#                                                                               #
# Permission is hereby granted, free of charge, to any person obtaining a copy  #
# of this software and associated documentation files (the "Software"), to deal #
# in the Software without restriction, including without limitation the rights  #
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     #
# copies of the Software, and to permit persons to whom the Software is         #
# furnished to do so, subject to the following conditions:                      #
#                                                                               #
# The above copyright notice and this permission notice shall be included in    #
# all copies or substantial portions of the Software.                           #
#                                                                               #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    #
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      #
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   #
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        #
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, #
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN     #
# THE SOFTWARE.                                                                 #
#                                                                               #
#################################################################################


#--------------------------------------------- Variables ---------------------------------------------------------------------------------------

# Name of the Let's Encrypt certificate generated by the Acme package in pfSense
$CERTNAME = $DomainName = "example.com" 

# Define the SP metadata URL and the relying party trust name
$ADFSmetadataURL = "https://$DomainName/federationmetadata/2007-06/federationmetadata.xml"

# Name of the relying party trust set in ADFS for HPE GreenLake
$relyingPartyTrustName = "HPE GreenLake"  

# pfsense user credential
$pfsense = "192.168.1.1"
# Username of your pfsense appliance
$PFSENSE_Username = "admin"  
# Password of your pfsense user account
$PFSENSE_EncryptedPassword = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000ef250ff78a6a674ba7d7796227547f8e0000000002000000000003660000c000000010000000e3d8b298b95168c23b535ce38ab18f1b0000000004800000a0000000100000006060bd55ffc74afbb89b3acc8b462d9828000000742ef6dadfaf7bd6216f87229c84d80ae439191ca218e818a4679e26b25d94115ff19b14b3f15a9d14000000185deac40c7d405468d058017bfb9939e16c2780" 

# To encrypt your password, use
# $Password = 'YourPlainTextPassword'
# ConvertTo-SecureString -String $Password -AsPlainText -Force | ConvertFrom-SecureString  

# HPE GreenLake User credential
$GLP_Username = "sso_re_248aa396805c11ed88e216588ab64ce9@example.com"
$GLP_EncryptedPassword = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000009051e8a93f01ed4a8b02456367bbd13c0000000002000000000003660000c000000010000000084007ecc92cf8321cc3b711bb889e610000000004800000a00000001000000083164401bb180f6b082cf61cbb3933c4380000005197cc46ecc9cab4ef223d897fb047c174fdce3f60d8f6702c5bc90648d81533c8c4f26284fc10813b332492392425f84b89fe69bcb09d4714000000cefa579bffc658512e6527ba90e8e3a884ff0905"

# Name of the HPE GreenLake workspace
$WorkspaceName = "HPE Mougins" 

# Location on your Windows ADFS server where the certificate will be temporarily stored 
$CERTDIR = "C:\Certificate-renewall-script" 

# Service account used by ADFS
$account = "NT SERVICE\ADFSSRV"



#---------------------------------------------PowerShell modules to install ---------------------------------------------------------------------------------------


if (!(Get-Module -Name "pfsense" -ListAvailable)) {
    # Install the pfsense module 
    Install-Module -Name "pfsense" -Scope CurrentUser -Force
}

if (!(Get-Module -Name "HPECOMCmdlets" -ListAvailable)) {
    # Install the pfsense module 
    Install-Module -Name "HPECOMCmdlets" -Scope CurrentUser -Force
}


#---------------------------------------------Update the ADFS Windows server certificate ---------------------------------------------------------------------------------------

$PFSENSE_SecurePassword = ConvertTo-SecureString $PFSENSE_EncryptedPassword
$credentials = New-Object System.Management.Automation.PSCredential ($PFSENSE_Username, $PFSENSE_SecurePassword)


Function Get-pfSenseCert {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
        HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $false, Position = 1,
        HelpMessage = 'CRL name or ID'
        )] [String] $Name
        )
        
        Begin {
            # Debugging for scripts
            $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        }
        
        Process {
            # Variables
        $errorActionSilent = 'SilentlyContinue'
        $objOfHolding = @()
        
        # Export the server config to XML object
        [xml] $objXmlFile = Backup-pfSenseConfig -Session $Session -OutputXML 
        $objXmlCert = $objXmlFile.pfsense.cert
        
        # Don't want the cert info to be displayed by default... too messy.
        [String[]] $defaultDisplaySet = 'Name', 'Cert_ID', 'CA'
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(
            'DefaultDisplayPropertySet', [string[]]$defaultDisplaySet
        )
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

        
        # Iterate thru the certs and return their infos...
        Foreach ($objCRL in $objXmlFile.pfsense.cert) {
            $objBuilder = New-Object -TypeName PSObject
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Name' -Value $objCRL.descr.'#cdata-section'
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Cert_ID' -Value $objCRL.refid
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Data' -Value $objCRL.text.'#cdata-section'
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Serial' -Value $objCRL.serial
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'LifeTime' -Value $objCRL.lifetime
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Method' -Value $objCRL.method
            
            $cert = $objXmlCert | Where-Object { $_.refid -eq $objCRL.caref }
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CA' -Value $cert.descr.'#cdata-section'
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CA_ID' -Value $cert.refid
            
            $objBuilder.PSObject.TypeNames.Insert(0, 'CRL Information')
            $objBuilder | Add-Member -MemberType MemberSet PSStandardMembers $PSStandardMembers
            
            # Add the builder object to our array object
            $objOfHolding += $objBuilder
        }
        
        # Returning data... we're done with the work now
        If ($Name) {
            $objOfHolding | ? { $_.CRL -eq $Name -or $_.CRL_ID -eq $Name }
        }
        Else {
            $objOfHolding
        }
        
        # Clean up
        Remove-Variable objXmlFile -Force -ErrorAction $errorActionSilent -WarningAction $errorActionSilent
    }
    
    End {
        [GC]::Collect()
    }
}

Function Export-pfSenseCert {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
        HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $true, Position = 1,
        HelpMessage = 'Certificate name'
        )] [String] $Name,
        
        [Parameter(Position = 2)]
        [ValidateSet('Cert', 'Key', 'P12')]
        [String] $CertAction = 'Cert',
        
        [Parameter(Position = 3)]
        [ValidateScript({
            try {
                    $Folder = Get-Item $($_ | Split-Path -Parent) -ErrorAction Stop
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    Throw [System.Management.Automation.ItemNotFoundException] "${_} Maybe there are network issues?"
                }
                if ($Folder.PSIsContainer) {
                    $True
                }
                else {
                    Throw [System.Management.Automation.ValidationMetadataException] "The path '${_}' is not a container."
                }
            })]
        [String] $FilePath
        )
        
        Begin {
            # Debugging for scripts
            $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
            
            Function Script:Extract-WebTable {
                # code from Lee Holmes 
                # http://www.leeholmes.com/blog/2015/01/05/extracting-tables-from-powershells-invoke-webrequest/
            Param
            (
                [Parameter(Mandatory = $true)]
                [Microsoft.PowerShell.Commands.HtmlWebResponseObject] $WebRequest,

                [Parameter(Mandatory = $true)]
                [int] $TableNumber
                )
                
                ## Extract the tables out of the web request

                $tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))

                $table = $tables[$TableNumber]
                
            $titles = @()
            
            $rows = @($table.Rows)

            ## Go through all of the rows in the table

            Foreach ($row in $rows) {
                $cells = @($row.Cells)

                ## If we've found a table header, remember its titles

                If ($cells[0].tagName -eq "TH") {
                    $titles = @($cells | ForEach-Object { ("" + $_.InnerText).Trim() })

                    continue
                }
                
                ## If we haven't found any table headers, make up names "P1", "P2", etc.
                
                If (-not $titles) {
                    $titles = @(1..($cells.Count + 2) | ForEach-Object { "P$_" })
                }

                ## Now go through the cells in the the row. For each, try to find the

                ## title that represents that column and create a hashtable mapping those
                
                ## titles to content
                
                $resultObject = [Ordered] @{}
                
                For ($intCounter = 0; $intCounter -lt $cells.Count; $intCounter++) {
                    
                    $title = $titles[$intCounter]

                    If (-not $title) { continue }

                    $resultObject[$title] = ("" + $cells[$intCounter].InnerText).Trim()

                }
                
                ## And finally cast that hashtable to a PSCustomObject
                
                [PSCustomObject] $resultObject
            }
        }
    }
    
    Process {
        # Variables
        $Server = $Session.host
        [bool] $NoTLS = $Session.NoTLS 
        [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session[0]
        $uri = 'https://{0}/system_certmanager.php' -f $Server
        
        
        If ($NoTLS) {
            # highway to tha Danger Zone!!!
            $uri = $uri -Replace "^https:", 'http:'
          
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
        
        # # Get the page contents so we can parse the table. We'll need the iterated ID based on the web table.
        # $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
        
        # $objTable = Extract-WebTable -WebRequest $request -TableNumber 0
        
        # # get the ID of the user on the page
        # $userID = $objTable.IndexOf(($objTable | Where-Object {$_.name -match $UserName})[0])
        
        $Cert_ID = get-pfsensecert -Session $Session | ? name -eq $name | Select-Object -ExpandProperty Cert_ID
        
        
        Switch ($CertAction) {
            Key {
                $uri += ('?act=key&id={0}' -f $Cert_ID)
                $fExt = 'key'
                Break
            }
            
            P12 {
                $uri += ('?act=p12&id={0}' -f $Cert_ID)
                $fExt = 'p12'
                Break
            }
            
            Default {
                $uri += ('?act=exp&id={0}' -f $Cert_ID)
                $fExt = 'crt'
                Break
            }
        }
        
        If (!$FilePath) {
            [String] $FilePath = ('{0}\{1}_pfSenseUserCertificate.{2}' -f $($PWD.Path), $Name, $fExt)
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value ('Export path = {0}' -f $FilePath) -Force 
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value ('URI = {0}' -f $uri.ToString())
        
        $exRequest = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
        
        ConvertFrom-HexToFile -HexString $exRequest.Content -FilePath $FilePath
    }
    
    End {
        
    }
}

$CertStoreLocation = "Cert:\LocalMachine\My"

try {
    $Session = Connect-pfSense -Server $pfsense -Credential $credentials 
    
}
catch {
    Write-Error "Fail to connect to pfSense '$pfsense'. Error: $_"
    return
}

# Download the ADFS certificate from pfsense (generated from Let's Encrypt using the Acme package/service)
try {
    Write-Host "Retrieving Let's Encrypt certificate '$CERTNAME' from pfSense '$pfsense' in progress..."
    Export-pfSenseCert -Session $Session -Name $CERTNAME -CertAction P12 -FilePath "$CERTDIR\$CERTNAME.p12" 
}
catch {
    Write-Error "Fail to download the ADFS certificate from pfSense. Error: $_"
    return
}


# Check that new and existing certificates are identical
$NewCertificateThumbprint = Get-pfxCertificate -FilePath "$CERTDIR\$CERTNAME.p12"  | Select-Object -ExpandProperty Thumbprint #select thumbprint for further action

$CurrentCertificate = Get-ChildItem $certStoreLocation | Where Subject -match $CERTNAME 

if ($CurrentCertificate) {
    $CurrentCertificateThumbprint = $CurrentCertificate |  Select-Object -ExpandProperty Thumbprint 
}
else {
    Write-Output "No existing certificate found with the subject name $CERTNAME."
    return
} 

if ($NewCertificateThumbprint -eq $CurrentCertificateThumbprint) {
    
    Write-Host "The Let's Encrypt certificate is identical to the one currently installed on the ADFS server. Operation aborted!"
    return
}
else {

    Write-Host "The Let's Encrypt certificate is different from the one currently installed on the ADFS server. Renewal of the ADFS certificates is in progress..."
    
    # Remove existing certificate
    Remove-Item -Path $CurrentCertificate.PSPath | out-Null
    Write-Output "Existing ADFS server certificate $CurrentCertificateThumbprint has been removed!"

    # Import new p12 certificate to the ADFS server personal trust store
    Import-pfxCertificate -FilePath "$CERTDIR\$CERTNAME.p12" -CertStoreLocation $CertStoreLocation -Exportable | Out-Null
    Write-Output "The new Let's Encrypt certificate $NewCertificateThumbprint has been imported successfully!"
   
    # Assign full control permission to the new certificate private key for the ADFS service account #####
    $Newcertificate = Get-ChildItem $certStoreLocation | Where thumbprint -eq $NewCertificateThumbprint
    $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Newcertificate)
    $fileName = $rsaCert.key.UniqueName
    $path = "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$fileName"
    $permissions = Get-Acl -Path $path
    $access_rule = New-Object System.Security.AccessControl.FileSystemAccessRule($account, "FullControl", 'None', 'None', 'Allow')
    $permissions.AddAccessRule($access_rule)
    Set-Acl -Path $path -AclObject $permissions
    Write-Output "Full control permissions have been successfully assigned to the new certificate's private key for the ADFS service account!"

    
    # Disable Auto Certificate Rollover if enabled (required to add or set signing and encryption certificates)
    if ((Get-AdfsProperties | Select-Object -ExpandProperty AutoCertificateRollover) -eq $True){

        Set-AdfsProperties -AutoCertificateRollover $false
        Write-Output "Auto Certificate Rollover has been disabled successfully."

    }

    # Update the ADFS Token-Signing Certificate
    try {
        Add-AdfsCertificate -CertificateType Token-Signing -Thumbprint $NewCertificateThumbprint -IsPrimary
        Write-Output "ADFS Token-Signing certificate updated successfully."
    } 
    catch {
        Write-Error "Fail to update ADFS Token-Signing certificate. Error: $_"
        return
    }

    # Remove old ADFS Token-Signing certificate
    if ($oldTokenSigningCertificate) {
            
        try {
            $oldTokenSigningCertificate = Get-AdfsCertificate -CertificateType Token-Signing | Where-Object {$_.Thumbprint -ne $NewCertificateThumbprint} 
            Remove-AdfsCertificate -CertificateType Token-Signing -Thumbprint  $oldTokenSigningCertificate.Thumbprint
            Write-Output "Old ADFS Token-Signing certificate has been removed successfully."
        } 
        catch {
            Write-Error "Fail to remove old ADFS Token-Signing certificate. Error: $_"
            return
        }
    }

    # Update the ADFS Token-Decrypting Certificate
    try {
        Add-AdfsCertificate -CertificateType Token-Decrypting -Thumbprint $NewCertificateThumbprint -IsPrimary
        Write-Output "ADFS Token-Decrypting certificate updated successfully."
    } 
    catch {
        Write-Error "Fail to update ADFS Token-Decrypting certificate. Error: $_"
        return
    }

    # Remove old ADFS Token-Decrypting certificate
    if ($oldTokenDecryptingCertificate) {

        try {
            $oldTokenDecryptingCertificate = Get-AdfsCertificate -CertificateType Token-Decrypting | Where-Object {$_.Thumbprint -ne $NewCertificateThumbprint}     
            Remove-AdfsCertificate -CertificateType Token-Decrypting -Thumbprint  $oldTokenDecryptingCertificate.Thumbprint
            Write-Output "Old ADFS Token-Decrypting certificate has been removed successfully."
        } 
        catch {
            Write-Error "Fail to remove old ADFS Token-Decrypting certificate. Error: $_"
            return
        }
    }


    # Update the ADFS Service Communication Certificate
    try {
        Set-AdfsSslCertificate -Thumbprint $NewCertificateThumbprint
        Write-Output "ADFS Service Communication certificate updated successfully."
    } 
    catch {
        Write-Error "Fail to update ADFS Service Communication certificate. Error: $_"
        return
    }


    # Restarting adfssrv service to enable the new certificate
    try {
        Restart-Service adfssrv > $null 2>&1
        Write-Output "ADFS service restarted successfully."
    } catch {
        Write-Error "Failed to restart the ADFS service. Error: $_"
    }
    
    Start-Sleep -Seconds 5


    #--------------------------------------------- Update HPE GreenLake workspace SAML SSO details with new ADFS certificate ---------------------------------------------


    # Check that GLP SAML SSO Domain is set with the correct ADFS server certificate

    # Get the X509 certificate of the ADFS server from the metadata file
    try {
        [xml]$MetadataXMLFile = Invoke-RestMethod -Uri $ADFSmetadataURL -Method Get 
        Write-Output "ADFS metadata file has been successfully downloaded."
    } 
    catch {
        Write-Error "Fail to retreive ADFS metadata file. Error: $_"
        return
    }

    $NewADFSX509Certificate = $MetadataXMLFile.EntityDescriptor.IDPSSODescriptor.KeyDescriptor | Where-Object { $_.use -eq "signing" } | Select-Object -ExpandProperty KeyInfo | Select-Object -ExpandProperty X509Data | Select-Object -ExpandProperty X509Certificate
    
    # Connect to GLP using the SAML SSO recovery email (only user that can update the SAML SSO domain)
    $GLP_SecurePassword = ConvertTo-SecureString $GLP_EncryptedPassword
    $credentials = New-Object System.Management.Automation.PSCredential ($GLP_Username, $GLP_SecurePassword)
    
    try {
        Connect-HPEGL -Credential $credentials -Workspace $WorkspaceName > $null 2>&1
    } 
    catch {
        Write-Error "Fail to connect to the HPE GreenLake workspace '$WorkspaceName'. Error: $_"
        return
    }

    try {
        $CurrentADFSX509CertificateSetinGLP = Get-HPEGLWorkspaceSAMLSSODomain -DomainName $DomainName -ShowIDPCertificate
        Write-Output "Retreiving the current ADFS certificate set in the SAML SSO domain '$DomainName'."

    } 
    catch {
        Write-Error "Failed to fetch the current ADFS certificate set in the SAML SSO domain '$DomainName'. Error: $_"
        return
    }

    # Compare curent ADFS certificate set in GLP SAML SSO Domain with the new one
    if ($NewADFSX509Certificate -eq $CurrentADFSX509CertificateSetinGLP){
        
        Write-Host "The new ADFS server certificate is identical to the one currently configured in the SAML SSO domain. Operation aborted!"
        return
    }
    else {      
        
        # Updating GreenLake workspace SAML SSO details with new ADFS certificate 

        Write-Host "The new ADFS server certificate is different from the one currently defined in GreenLake. Updating the SAML SSO domain with the new certificate is in progress..."

        # Update the SAML SSO domain with the new ADFS certificate
        try {
            $response = Set-HPEGLWorkspaceSAMLSSODomain -DomainName $DomainName -X509Certificate $NewADFSX509Certificate 
        } 
        catch {
            Write-Error "Fail to update the SAML SSO domain '$DomainName' with the new ADFS certificate. Error: $_"
            return
        }
    
        if ($response.details -match "Successfully"){
            Write-Host "The HPE GreenLake SAML SSO domain '$DomainName' has been successfully updated with the new ADFS certificate."

        }

        # Get-HPEGLWorkspaceSAMLSSODomain -DomainName $DomainName  -ShowIDPCertificate 
    

        #--------------------------------------------- Update ADFS Relying party with the HPE GreenLake server certificate (only if renewed) ------------------------------------------------- 


        # Check that ADFS Relying party is set with the correct HPE GreenLake server certificate
        
        # Get the X509 certificate Thumbprint of the Service Provider (HPE GreenLake)  
        try { 
            $CurrentSPcertificate = Get-HPEGLWorkspaceSAMLSSODomain -DomainName $DomainName -ShowSPCertificate
            Write-Output "Retreiving the current SP certificate set in the SAML SSO domain '$DomainName'."
        } 
        catch {
            Write-Error "Failed to fetch the SP certificate set in the SAML SSO domain '$DomainName'. Error: $_"
            return
        }
        # Convert the base64 string to a byte array
        $certificateBytes = [Convert]::FromBase64String($CurrentSPcertificate)
        # Create an X509Certificate2 object from the byte array using the constructor
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateBytes)
        # Get the SP certificate thumbprint
        $ServiceProviderCertificateThumbprint = $certificate.Thumbprint
        
        # Get the X509 certificate thumbprint of the Relying Party Trust set in ADFS (HPE GreenLake)   
        try {
            $HPEGreenLakeRelyingPartyTrust = Get-ADFSRelyingPartyTrust -Name $relyingPartyTrustName
            Write-Output "Retreiving the relying party trust '$relyingPartyTrustName' set in ADFS for HPE GreenLake."
        } 
        catch {
            Write-Error "Failed to fetch the relying party '$relyingPartyTrustName' set in ADFS for HPE GreenLake. Error: $_"
            return
        }
        # Get the signature certificate thumbprint
        $HPEGreenLakeRelyingPartyTrustCertificateThumbprint = $HPEGreenLakerelyingPartyTrust.RequestSigningCertificate.thumbprint

        # Compare curent SP certificate set in ADFS Relying party with the HPE GreenLake server certificate
        if ($ServiceProviderCertificateThumbprint -eq $HPEGreenLakeRelyingPartyTrustCertificateThumbprint) {
            
            Write-Host "The X509 certificate of the relying party '$relyingPartyTrustName' in ADFS is up-to-date. No change is needed!"
            return
            
        }
        else {

            # Update the ADFS configuration with any certificate changes from HPE GreenLake (Service Provider) 
            Write-Host "The X509 certificate of the relying party '$relyingPartyTrustName' in ADFS is not valid. Update in progress..."

            try {
                Get-HPEGLWorkspaceSAMLSSODomain -DomainName $DomainName -DownloadServiceProviderMetadata ./metadata.xml 
                Write-Output "The SP metadata file for the SAML SSO domain '$DomainName' has been successfully downloaded from HPE GreenLake."

            } 
            catch {
                Write-Error "Failed to fetch the SP metadata file for the SAML SSO domain '$DomainName' from HPE GreenLake. Error: $_"
                return
            }
    
            # Update the signature certificate for the relying party trust
            try {
                Update-ADFSRelyingPartyTrust -TargetName $relyingPartyTrustName -MetadataFile ./metadata.xml 
                Write-Output "Relying party '$relyingPartyTrustName' has been updated successfully with the new metadata information."
    
            } catch {
                Write-Error "Failed to update the ADFS relying party '$relyingPartyTrustName' certificate. Error: $_"
                return
            }
                
            # Restart the ADFS service to apply the changes 
            try {
                Restart-Service adfssrv > $null 2>&1
                Write-Output "ADFS service restarted successfully. Update completed! The new certificate is now in use."
            } catch {
                Write-Error "Failed to restart the ADFS service. Error: $_"
            }
        }               
    }

    Disconnect-HPEGL

}
    


# Cleanup actions 
Remove-Item "$CERTDIR\$CERTNAME.p12" -Force  
Remove-Item ./metadata.xml  -Force  

