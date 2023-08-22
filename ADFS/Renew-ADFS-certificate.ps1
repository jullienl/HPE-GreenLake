<#
PowerShell script that can be run every 60 days (so before the Let's Encrypt certificate expires) from an ADFS Windows server to:
1. Export the Let's Encrypt certificate from pfsense to the ADFS server in a p12 format
2. Import the p12 certificate in ADFS server's personal trust store 
3. Update the Active Directory Federation Services with the new p12 certificate and reload the ADFS services


Requirements: 
- ACME package must be installed and properly configured in pfsense
- 'Write Certificates' Acme package option must be enable to save the Let's Encrypt signed certificate in the **/cf/conf/acme** folder of pfsense

Commands to create the scheduled task to run the script every 60 days (must be run as administrator priviledge):

> $trigger = New-JobTrigger -Daily -DaysInterval 60 -At 2am 
> $options = New-ScheduledJobOption -RunElevated
> Register-ScheduledJob -Trigger $trigger -FilePath "C:\Certificate-renewall-script\Renew-ADFS-certificate.ps1" -Name ADFS-Certificate--60d-Renewal -ScheduledJobOption $options

Other useful commands:
> Get-ScheduledJobOption ADFS-Certificate--60d-Renewal
> Get-ScheduledJob -Name ADFS-Certificate--60d-Renewal
> Unregister-scheduledjob -Name ADFS-Certificate--60d-Renewal


Author: lionel.jullien@hpe.com
Date:   August 2023
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

# Variables

$pfsense = "192.168.1.1"
$PFSENSE_USERNAME = "admin" # Username of your pfsense appliance 
$PFSENSE_EncryptedPassword = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000ef250ff78a6a674ba7d7796227547f8e0000000002000000000003660000c000000010000000e3d8b298b95168c23b535ce38ab18f1b0000000004800000a0000000100000006060bd55ffc74afbb89b3acc8b462d9828000000742ef6dadfaf7bd6216f87229c84d80ae439191ca218e818a4679e26b25d94115ff19b14b3f15a9d14000000185deac40c7d405468d058017bfb9939e16c2780" #Password of your restricted useraccount

$CERTNAME = "acme.com" # Name of the Let's Encrypt certificate
$CERTDIR = "C:\Certificate-renewall-script" # Location on your Windows ADFS server where the certificate will be temporarily stored 
  

#------------------------------------------------------------------------------------------------------------------------------------

if (!(Get-Module -Name "pfsense" -ListAvailable)) {
    # Install the pfsense module 
    Install-Module -Name "pfsense" -Scope CurrentUser -Force
}

$PFSENSE_SecurePassword = ConvertTo-SecureString $PFSENSE_EncryptedPassword
$credentials = New-Object System.Management.Automation.PSCredential ($PFSENSE_USERNAME, $PFSENSE_SecurePassword)


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

$Session = Connect-pfSense -Server $pfsense -Credential $credentials 

Export-pfSenseCert -Session $Session -Name $CERTNAME -CertAction P12 -FilePath "$CERTDIR\$CERTNAME.p12" 

# Import p12 certificate to the server personal trust store
$thumbprint = Import-pfxCertificate -FilePath "$CERTDIR\$CERTNAME.p12" -CertStoreLocation Cert:\LocalMachine\My | Select-Object -ExpandProperty Thumbprint #select thumbprint for further action

# ADFS commands for renewing the certificate and reloading the services
Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $thumbprint # Import certificate into ADFS
Update-AdfsCertificate -Urgent # Urgently update the ADFS certificate
Restart-Service adfssrv # Restart the ADFS service
Set-AdfsSslCertificate -Thumbprint $thumbprint # Set the right Certificate thumbprint for the ADFS certificate

# Cleanup actions for the certificates
Remove-Item "$CERTDIR\$CERTNAME.p12" -Force 
