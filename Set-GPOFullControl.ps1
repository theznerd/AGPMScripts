############################################
## Existing GPO Full Control Fix for AGPM ##
## Written By: Nathan Ziehnert            ##
## Website: http://z-nerd.com/            ##
## Version: 1.0                           ##
############################################
<#
.SYNOPSIS
    This script assigns full control privileges to the specified
    GPOs in the domain to the specified AD account or group.

.DESCRIPTION
    When creating the AGPM Service Accoount with least privilege, 
    you will notice that importing existing policies doesn't work.
    This is because you have to delegate ownership privileges to
    the AGPM Service account (or to a group that the service 
    account belongs to.

    This script is designed to take care of that programmatically
    so that you don't have to do the work manually. The script
    can target specific OUs (passed as a single OU or an array of
    OUs).

.PARAMETER Verbose
    This script is verbose enabled. Use this switch to get verbose output.

.PARAMETER All
    A switch to apply it to all policies.

.PARAMETER OUName [string]
    Either a single OU name or an array of OU names. This will find ALL OUs with this name, so be cautious...

.PARAMETER DistinguishedName [string]
    Either a single DN for an OU, or an array of DNs for OUs. This would be necessary if you have OUs with the same name and you want to manage one (or more) of them.

.PARAMETER FullControlAccount [string]
    A single samAccountName for either the user or group that will have FullControl rights over the modified group policies.

.PARAMETER WhatIf
    A switch to keep the script from actually performing any changes to AD and Group Policy. Use in conjunction with the -Verbose switch to see what the script would have done.

.NOTES
    File Name: Set-GPOFullControl.ps1
    Author: Nathan Ziehnert

.LINK
    http://z-nerd.com/2016/12/gpos-screw-it-well-do-it-live-part-iv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$All,
    [Parameter(Mandatory=$false)]
    [string[]]$OUName=@(),
    [Parameter(Mandatory=$false)]
    [string[]]$DistinguishedName=@(),
    [Parameter(Mandatory=$true)]
    [string]$FullControlAccount,
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

## Time to get some information...
Write-Verbose "Getting Domain"
$root = [adsi]"LDAP://RootDSE"
$domain = $root.Get("rootDomainNamingContext")

## Check to make sure we aren't searching too many things... I get tired.
if(($OUName.Count -gt 0) -and ($DistinguishedName.Count -gt 0)){
    Write-Host "ERROR: You may use either OUName or DistinguishedName, but not both" -ForegroundColor Red
    Exit
}

## Collect a list of Group Policy Objects
Write-Verbose "Collecting list of group policies"
$GroupPoliciesToModify = @()
if($All){
    Write-Verbose "-All Switch Used - Searching Entire Domain"
    $searcher = New-Object DirectoryServices.DirectorySearcher ##Create New Searcher
    $searcher.Filter = '(objectCategory=groupPolicyContainer)' ##Set the filter to group policies
    $searcher.SearchRoot = "LDAP://$domain"                    ##Search the whole domain baby.
    $SearchResults = $searcher.FindAll()                       ##Gotta catch 'em all...
    foreach($searchResult in $SearchResults){ $GroupPoliciesToModify += [adsi]"$($SearchResult.Path)" } ##Add all the found policies to a list
}
elseif($OUName){
    Write-Verbose "-OUName switch used, searching given OUs"
    $OUsToSearch = @()
    foreach($OU in $OUName){
        $searcher = New-Object DirectoryServices.DirectorySearcher ##Create New Searcher
        $searcher.Filter = '(objectCategory=organizationalUnit)'   ##Set the filter to OU
        Write-Verbose "Finding OUs by name: $OU"
        $OUsToSearch += $searcher.FindAll() | Where-Object {$_.Path -like "*$OU*"} ##Here's all the matching OUs...
    }
    $GPODNs = @()
    foreach($OUToSearch in $OUsToSearch){
        Write-Verbose "Finding GPOs in OU: $($OUToSearch.Path)"
        ##Now that we have all of the OUs, add all the policy DNs from each OU to a list for later - this may cause duplicates, but that's okay aside from the time cost.
        $GPODNs += ((($OUToSearch.Properties.gplink) -split "\[LDAP://") -replace ";[0-9]\]","").Split("",[System.StringSplitOptions]::RemoveEmptyEntries) 
    }
    foreach($GPODN in $GPODNs){
        $GroupPoliciesToModify += [adsi]"LDAP://$GPODN" ##Add all the individual GPOs to a list for later
    }
}else{
    Write-Verbose "-DistinguishedName switch used, searching given DNs" 
    $OUsToSearch = @()
    foreach($DN in $DistinguishedName){
    Write-Verbose "Finding OU by DN: $DN"
        $OUsToSearch += [adsi]"LDAP://$DN" ##Get a list of OUs to search
    }    
    $GPODNs = @()
    foreach($OUToSearch in $OUsToSearch){
        Write-Verbose "Finding GPOs in OU: $($OUToSearch.Path)"
        ##Now that we have all of the OUs, add all the policy DNs from each OU to a list for later - this may cause duplicates, but that's okay aside from the time cost.
        $GPODNs += ((($OUToSearch.Properties.gplink) -split "\[LDAP://") -replace ";[0-9]\]","").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
    }
    foreach($GPODN in $GPODNs){
        $GroupPoliciesToModify += [adsi]"LDAP://$GPODN" ##Add all the individual GPOs to a list for later
    }
}

Write-Verbose "Finished building list of GPOs"

Write-Verbose "Build new access control entry"
$CMNTAccount = new-object System.Security.Principal.NTAccount("$FullControlAccount") ##This should work... get an NT account by name...
$ActiveDirectoryRights = "GenericAll" ##FullControl
$AccessControlType = "Allow" ##Instead of Deny, duh.
$Inherit = "SelfAndChildren" ##Probably not necessary, but I think required for the ActiveDirectoryAccessRule
$nullGUID = [guid]'00000000-0000-0000-0000-000000000000' ##Again, kinda stupid, but necessary for ActiveDirectoryAccessRule
##Time to make the new ACE object.
$newACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $CMNTAccount, $ActiveDirectoryRights, $AccessControlType, $Inherit, $nullGUID

Write-Verbose "Begin to add new ACE to GPOs"
foreach($GPO in $GroupPoliciesToModify){
    if($WhatIf){
        Write-Verbose "WHAT IF: Add ACE to $($GPO.Path)" ##Just say what you'd do here... don't do it...
    }else{
        Write-Verbose "Add ACE to $($GPO.Path)"
        $GPO.psbase.ObjectSecurity.AddAccessRule($newACE) ##Add the ACE to the GPO
        $GPO.psbase.commitchanges() ##Save Changes...
    }
}
Write-Verbose "Script Complete."
