########################################################################
## Link GPO Permissions for AGPM MSA                                  ##
## Written By: Craig Forster (appended by: Nathan Ziehnert            ##
## Website: http://z-nerd.com/                                        ##
## Version: 1.0                                                       ##
########################################################################
<#
.SYNOPSIS
    This script assigns Link GPO permissions to the specified
    account.
.DESCRIPTION
    When using an MSA for AGPM, this will set the link permissions
    to all GPO objects at the root of the domain for the MSA.
    
    Read More Here:
    https://blogs.technet.microsoft.com/craigf/2015/06/24/running-agpm-with-a-managed-service-account-msa-or-gmsa/
.PARAMETER Verbose
    This script is verbose enabled. Use this switch to get verbose output.
.PARAMETER MSAccount [string]
    A single string for the name of the MSA (ex "MSA.AGPM$")
.PARAMETER WhatIf
    A switch to keep the script from actually performing any changes to AD and Group Policy. Use in conjunction with the -Verbose switch to see what the script would have done.
.NOTES
    File Name: Set-LinkGPO.ps1
    Author: Craig Forster (appended by: Nathan Ziehnert)
.LINK
    https://blogs.technet.microsoft.com/craigf/2015/06/24/running-agpm-with-a-managed-service-account-msa-or-gmsa/
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$MSAccount,
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory
} else {
    Write-Warning "ActiveDirectory Module not available and is required."
    exit
}
$agpmserviceaccountname = $MSAccount #set account
Write-Verbose "MSA is: $agpmserviceaccountname"

$domaindn = (Get-ADDomain).distinguishedname #get domain distinguished name
Write-Verbose "Domain DN is: $domaindn"

try{
    $agpmaccountsid = (get-adserviceaccount $($agpmserviceaccountname)).sid #get SID of AGPM MSA account
}catch{
    $agpmaccountsid = (get-adaccount $($agpmserviceaccountname)).sid #get SID of AGPM MSA account
}
Write-Verbose "MSA SID is: $agpmaccountsid"

$newsddl = "(OA;CI;RPWP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;;$($agpmaccountsid))" #set SDDL perms
$objsecurity = get-acl -Path "ad:\$($domaindn)" #get current ACL
Write-Verbose "Getting Current ACL for $domaindn"

if($WhatIf){
    Write-Verbose "WHAT IF: Adding new SDDL to ACL"
}else{
    $objsecurity.SetSecurityDescriptorSddlForm($objsecurity.sddl+$newsddl) #add new SDDL
    Write-Verbose "Adding new SDDL to ACL"
}
if($WhatIf){
    Write-Verbose "WHAT IF: Setting new ACL"
}else{
    Set-Acl -Path "ad:\$($domaindn)" -AclObject $objsecurity #set new ACL
    Write-Verbose "Setting new ACL"
}
