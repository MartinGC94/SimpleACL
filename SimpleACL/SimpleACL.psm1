#region Owner functions
# No point in creating a function when the default view for get-acl already shows the owner.
New-Alias -Name "Get-Owner" -Value "Get-ACL"
function Set-Owner
{
    param
    ( 
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [String[]]$Path,

        [Parameter(Mandatory=$true,Position=1)]
        [String]$NewOwner
    )
    begin
    {
        $NewOwnerReference=Convert-StringToIdentityReference -String $NewOwner
    }
    process
    {
        foreach ($item in $Path)
        {
            $ItemObject,$AclObject=Get-SimpleACL -Path $item

            $AclObject.SetOwner($NewOwnerReference)

            Set-SimpleACL -ItemObject $ItemObject -AclObject $AclObject
        }
    }
}
#endregion

#region Access functions
function Disable-AccessInheritance
{
    param
    ( 
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [String[]]$Path,

        [switch]$RemoveInheritedRules
    )
    process
    {
        foreach ($item in $Path)
        {
            $ItemObject,$AclObject=Get-SimpleACL -Path $item

            $AclObject.SetAccessRuleProtection($true,!$RemoveInheritedRules)

            Set-SimpleACL -ItemObject $ItemObject -AclObject $AclObject
        }
    }
}
function Enable-AccessInheritance
{
    param
    ( 
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [String[]]$Path,

        [switch]$RemoveExplicitRules
    )
    process
    {
        foreach ($item in $Path)
        {
            $ItemObject,$AclObject=Get-SimpleACL -Path $item

            $AclObject.SetAccessRuleProtection($false,$null)
            if ($RemoveExplicitRules)
            {
                [void]($AclObject.Access.Where({$_.IsInherited -eq $false}).foreach({$AclObject.RemoveAccessRule($_)}))
            }

            Set-SimpleACL -ItemObject $ItemObject -AclObject $AclObject
        }
    }
}
function New-AccessRule
{
    [cmdletbinding(DefaultParameterSetName="Advanced")]
    [OutputType([System.Security.AccessControl.FileSystemAccessRule[]])]
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity,

        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.FileSystemRights[]]$FileSystemRights,

        [parameter(ParameterSetName="Advanced")]
        [System.Security.AccessControl.InheritanceFlags[]]$InheritanceFlags=@("ContainerInherit","ObjectInherit"),

        [parameter(ParameterSetName="Advanced")]
        [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="None",

        [System.Security.AccessControl.AccessControlType]$Type="Allow",

        [parameter(ParameterSetName="UserFriendly", Mandatory=$true)]
        [validateset(
            "ThisFolderOnly",
            "ThisFolderAndSubfoldersAndFiles",
            "ThisFolderAndSubFolders",
            "ThisFolderAndFiles",
            "OnlyFilesAndSubFolders",
            "OnlySubFolders",
            "OnlyFiles"
        )]
        [String]$AppliesTo,

        [parameter(ParameterSetName="UserFriendly")]
        [switch]$OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer
    )
    begin
    {
        $IdentityReference=Convert-StringToIdentityReference -String $Identity
        if ($AppliesTo)
        {
            $Flags=Convert-FriendlyRulesToFlags -AppliesTo $AppliesTo -OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer:$OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer
            $InheritanceFlags=$Flags.InheritanceFlags
            $PropagationFlags=$Flags.PropagationFlags
        }
    }
    Process
    {
        foreach ($User in $IdentityReference)
        {
            [System.Security.AccessControl.FileSystemAccessRule]::new($User,$FileSystemRights,$inheritanceFlags,$propagationFlags,$type)
        }
    }
}
function Add-AccessRuleForItem
{
    param
    ( 
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [String[]]$Path,

        [Parameter(Mandatory=$true,ParameterSetName="WithAccessRule",Position=1)]
        [System.Security.AccessControl.AccessRule[]]$AccessRule,

        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=1)]
        [String[]]$Identity,

        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=2)]
        [System.Security.AccessControl.FileSystemRights[]]$Permissions,

        [Parameter(ParameterSetName="WithUser",Position=3)]
        [System.Security.AccessControl.AccessControlType]$Type='Allow',

        [Parameter(ParameterSetName="WithUser",Position=4)]
        [validateset(
            "ThisFolderOnly",
            "ThisFolderAndSubfoldersAndFiles",
            "ThisFolderAndSubFolders",
            "ThisFolderAndFiles",
            "OnlyFilesAndSubFolders",
            "OnlySubFolders",
            "OnlyFiles"
        )]
        [string]$AppliesTo,

        [parameter(ParameterSetName="WithUser")]
        [switch]$OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer
    )
    begin
    {
        if ($Identity)
        {
            $NewRuleSplat=@{
                Identity=$Identity
                FileSystemRights=$Permissions
                Type=$Type
            }
            switch ($PSBoundParameters.Keys)
            {
                'AppliesTo'
                {
                    $NewRuleSplat.Add('AppliesTo',$AppliesTo)
                }
                'OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer'
                {
                    $NewRuleSplat.Add('OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer',$OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer)
                }         
                Default {}
            }

            $AccessRule= New-AccessRule @NewRuleSplat
        }
    }
    process
    {
        foreach ($item in $Path)
        {
            $ItemObject,$AclObject=Get-SimpleACL -Path $item

            foreach ($rule in $AccessRule)
            {
                $AclObject.AddAccessRule($rule)
            }

            Set-SimpleACL -ItemObject $ItemObject -AclObject $AclObject
        }
    }
}
function Remove-AccessRuleForItem
{
    param
    ( 
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [String[]]$Path,

        [Parameter(Mandatory=$true,ParameterSetName="WithAccessRule",Position=1)]
        [System.Security.AccessControl.AccessRule[]]$AccessRule,

        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=1)]
        [String[]]$Identity
    )
    begin
    {
        if ($Identity)
        {        
            $IdentityReference=Convert-StringToIdentityReference -String $Identity
        }
    }
    process
    {
        foreach ($item in $Path)
        {
            $ItemObject,$AclObject=Get-SimpleACL -Path $item

            if ($IdentityReference)
            {
                foreach ($User in $IdentityReference)
                {
                    $AclObject.PurgeAccessRules($User)
                }
            }
            else
            {
                foreach ($rule in $AccessRule)
                {
                    [void]($AclObject.RemoveAccessRule($rule))
                }
            }

            Set-SimpleACL -ItemObject $ItemObject -AclObject $AclObject   
        }
    }
}
New-Alias -Name "Remove-AccessRuleFromItem" -Value "Remove-AccessRuleForItem"
function Set-AccessRuleForItem
{
    param
    ( 
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [String[]]$Path,

        [Parameter(Mandatory=$true,ParameterSetName="WithAccessRule",Position=1)]
        [System.Security.AccessControl.AccessRule]$NewAccessRule,

        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=1)]
        [String[]]$Identity,

        [Parameter(ParameterSetName="WithUser",Position=2)]
        [System.Security.AccessControl.FileSystemRights[]]$NewFileSystemRights,

        [Parameter(ParameterSetName="WithUser",Position=3)]
        [System.Security.AccessControl.AccessControlType]$NewType,

        [Parameter(ParameterSetName="WithUser",Position=4)]
        [validateset(
            "ThisFolderOnly",
            "ThisFolderAndSubfoldersAndFiles",
            "ThisFolderAndSubFolders",
            "ThisFolderAndFiles",
            "OnlyFilesAndSubFolders",
            "OnlySubFolders",
            "OnlyFiles"
        )]
        [string]$NewAppliesTo,

        [parameter(ParameterSetName="WithUser")]
        [System.Security.AccessControl.InheritanceFlags[]]$NewInheritanceFlags,

        [parameter(ParameterSetName="WithUser")]
        [System.Security.AccessControl.PropagationFlags[]]$NewPropagationFlags
    )
    process
    {
        foreach ($item in $Path)
        {
            $ItemObject,$AclObject=Get-SimpleACL -Path $item
            
            if ($Identity)
            {
                foreach ($User in $Identity)
                {
                    $OldRule=Get-AccessRuleForItem -Path $item -Identity $User | Select-Object -First 1
                    if ($OldRule)
                    {
                        $NewRuleSplat=@{
                            Identity=$User
                            FileSystemRights=$OldRule.FileSystemRights
                            Type=$OldRule.AccessControlType
                            InheritanceFlags=$OldRule.InheritanceFlags
                            PropagationFlags=$OldRule.PropagationFlags
                        }
                        
                        switch ($PSBoundParameters.Keys)
                        {
                            'NewFileSystemRights'
                            {
                                $NewRuleSplat["FileSystemRights"]=$PSBoundParameters["NewFileSystemRights"]
                            }
                            'NewType'
                            {
                                $NewRuleSplat["Type"]=$PSBoundParameters["NewType"]
                            }
                            'NewAppliesTo'
                            {
                                $ConvertedFlags=Convert-FriendlyRulesToFlags -AppliesTo $PSBoundParameters['NewAppliesTo']
                                $NewRuleSplat["InheritanceFlags"]=$ConvertedFlags.InheritanceFlags
                                $NewRuleSplat["PropagationFlags"]=$ConvertedFlags.PropagationFlags
                            }
                            'NewInheritanceFlags'
                            {
                                $NewRuleSplat["InheritanceFlags"]=$PSBoundParameters["NewInheritanceFlags"]
                            }
                            'NewPropagationFlags'
                            {
                                $NewRuleSplat["PropagationFlags"]=$PSBoundParameters["NewPropagationFlags"]
                            }
                            Default {}
                        }
                        $AclObject.ResetAccessRule((New-AccessRule @NewRuleSplat))
                    }
                    else
                    {
                        Write-Information -MessageData "$User did not have an existing rule to $item, so no changes have been made for this identity on this object."
                    }
                }
            }
            else
            {
                $AclObject.ResetAccessRule($NewAccessRule)
            }
            Set-SimpleACL -ItemObject $ItemObject -AclObject $AclObject        
        }
    }
}
function Get-AccessRuleForItem
{
    [OutputType([System.Security.AccessControl.FileSystemAccessRule[]])]
    param
    ( 
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [String[]]$Path,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity,

        [Parameter(Mandatory=$false,Position=2)]
        [System.Security.AccessControl.FileSystemRights[]]$FileSystemRights,

        [Parameter()]
        [System.Security.AccessControl.AccessControlType[]]$Type,

        [Parameter()]
        [switch]$ExcludeInheritedRules,

        [Parameter()]
        [switch]$ExcludeExplicitRules
    )
    begin
    {
        if ($Identity)
        {
            $IdentityReference=Convert-StringToIdentityReference -String $Identity
        }
    }
    process
    {
        try
        {
            $AccessRules=(Get-Item -Path $Path).GetAccessControl().GetAccessRules(!$ExcludeExplicitRules,!$ExcludeInheritedRules,[System.Security.Principal.NTAccount])
        }
        catch
        {
            $AccessRules=(Get-ACL -Path $Path).Access
        }
        switch ($PSBoundParameters.Keys)
        {
            'ExcludeInheritedRules'
            {
                $AccessRules=$AccessRules.Where({$_.IsInherited -ne $true})
            }
            'ExcludeExplicitRules'
            {
                $AccessRules=$AccessRules.Where({$_.IsInherited -ne $false})
            }
            'Identity'
            {
                $AccessRules=$AccessRules.Where({$_.IdentityReference -in $IdentityReference})
            }
            'FileSystemRights'
            {
                $AccessRules=$AccessRules.Where({$_.FileSystemRights -eq $FileSystemRights})
            }
            'Type'
            {
                $AccessRules=$AccessRules.Where({$_.AccessControlType -in $Type})
            }
        }
        $AccessRules
    }
}
#endregion

#region Audit functions (unfinished)
#function Disable-AuditInheritance
#{
#    param
#    ( 
#        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
#        [String[]]$Path,
#
#        [switch]$RemoveInheritedRules
#    )
#    process
#    {
#        if ($RemoveInheritedRules)
#        {
#            $PreserveInheritedRules=$false
#        }
#        else
#        {
#            $PreserveInheritedRules=$true
#        }
#        foreach ($item in $Path)
#        {
#            $FileSystemObject=Get-Item -Path $item
#            $AclObject= $FileSystemObject.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
#            $AclObject.SetAuditRuleProtection($true,$PreserveInheritedRules)
#
#            #SetAccessControl sometimes fails where Set-ACL doesn't, and vice versa
#            try
#            {
#                $FileSystemObject.SetAccessControl($AclObject)
#            }
#            catch
#            {
#                Set-Acl -Path $item -AclObject $AclObject
#            }           
#        }
#    }
#}
#function Enable-AuditInheritance
#{
#    param
#    ( 
#        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
#        [String[]]$Path,
#
#        [switch]$RemoveExplicitRules
#    )
#    process
#    {
#        foreach ($item in $Path)
#        {
#            $FileSystemObject=Get-Item -Path $item
#            $AclObject= $FileSystemObject.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
#            $AclObject.SetAuditRuleProtection($false,$null)
#            
#            if ($RemoveExplicitRules)
#            {
#                [void]($AclObject.GetAuditRules($true,$false,[System.Security.Principal.NTAccount]).foreach({$AclObject.RemoveAuditRule($_)}))
#            }
#
#            #SetAccessControl sometimes fails where Set-ACL doesn't, and vice versa
#            try
#            {
#                $FileSystemObject.SetAccessControl($AclObject)
#            }
#            catch
#            {
#                Set-Acl -Path $item -AclObject $AclObject
#            }
#        }
#    }
#}
#function New-AuditRule
#{
#    [OutputType([System.Security.AccessControl.FileSystemAuditRule[]])]
#    Param
#    (
#        # Param1 help description
#        [Parameter(Mandatory=$true)]
#        [ValidateNotNullOrEmpty()]
#        [string[]]$Identity,
#
#        # Param2 help description
#        [Parameter(Mandatory=$true)]
#        [System.Security.AccessControl.FileSystemRights[]]$FileSystemRights,
#
#        # Param2 help description
#        [System.Security.AccessControl.InheritanceFlags[]]$inheritanceFlags=@("ContainerInherit","ObjectInherit"),
#
#        # Param2 help description
#        [System.Security.AccessControl.PropagationFlags[]]$propagationFlags="None",
#
#        # Param2 help description
#        [System.Security.AccessControl.AuditFlags[]]$type=@("Success","Failure")
#    )
#    Process
#    {
#        foreach ($User in $Identity)
#        {
#            [System.Security.AccessControl.FileSystemAuditRule]::new($User,$FileSystemRights,$inheritanceFlags,$propagationFlags,$type)
#        }
#    }
#}
#function Add-AuditRuleForItem
#{
#    param
#    ( 
#        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
#        [String[]]$Path,
#
#        [Parameter(Mandatory=$true,ParameterSetName="WithAuditRule",Position=1)]
#        [System.Security.AccessControl.AuditRule[]]$AuditRule,
#
#        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=1)]
#        [String[]]$Identity,
#
#        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=2)]
#        [System.Security.AccessControl.FileSystemRights[]]$Permissions,
#
#        [System.Security.AccessControl.AuditFlags[]]$Type=@("Success","Failure")
#    )
#    process
#    {
#        if ($Identity)
#        {
#            $AuditRule= New-AuditRule -Identity $Identity -FileSystemRights $Permissions -type $Type
#        }
#        foreach ($item in $Path)
#        {
#            $FileSystemObject=Get-Item -Path $item
#            $AclObject= $FileSystemObject.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
#            foreach ($rule in $AuditRule)
#            {
#                $AclObject.AddAuditRule($rule)
#            }
#
#            #SetAccessControl sometimes fails where Set-ACL doesn't, and vice versa
#            try
#            {
#                $FileSystemObject.SetAccessControl($AclObject)
#            }
#            catch
#            {
#                Set-Acl -Path $item -AclObject $AclObject
#            }           
#        }
#    }
#}
#function Remove-AuditRuleForItem
#{
#    param
#    ( 
#        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
#        [String[]]$Path,
#
#        [Parameter(Mandatory=$true,ParameterSetName="WithAuditRule",Position=1)]
#        [System.Security.AccessControl.AuditRule[]]$AuditRule,
#
#        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=1)]
#        [String[]]$Identity
#    )
#    process
#    {
#        foreach ($item in $Path)
#        {
#            $FileSystemObject=Get-Item -Path $item
#            $AclObject= $FileSystemObject.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
#            if ($Identity)
#            {
#                foreach ($user in $Identity)
#                {
#                    $AclObject.PurgeAuditRules([System.Security.Principal.NTAccount]::new($user))
#                }
#            }
#            else
#            {
#                foreach ($rule in $AccessRule)
#                {
#                    $AclObject.RemoveAuditRule($rule)
#                }
#            }
#
#            #SetAccessControl sometimes fails where Set-ACL doesn't, and vice versa
#            try
#            {
#                $FileSystemObject.SetAccessControl($AclObject)
#            }
#            catch
#            {
#                Set-Acl -Path $item -AclObject $AclObject
#            }           
#        }
#    }
#}
#New-Alias -Name "Remove-AccessRuleFromItem" -Value "Remove-AccessRuleForItem"
#function Set-AuditRuleForItem
#{
#    param
#    ( 
#        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
#        [String[]]$Path,
#
#        [Parameter(Mandatory=$true,ParameterSetName="WithAccessRule",Position=1)]
#        [System.Security.AccessControl.AuditRule]$NewAuditRule,
#
#        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=1)]
#        [String[]]$Identity,
#
#        [Parameter(Mandatory=$true,ParameterSetName="WithUser",Position=2)]
#        [System.Security.AccessControl.FileSystemRights[]]$NewFileSystemRights,
#
#        [Parameter(Mandatory=$false,ParameterSetName="WithUser",Position=3)]
#        [System.Security.AccessControl.AuditFlags[]]$NewType=@("Success","Failure")
#    )
#    process
#    {
#        foreach ($item in $Path)
#        {
#            $FileSystemObject=Get-Item -Path $item
#            $AclObject= $FileSystemObject.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
#            
#            
#            if ($Identity)
#            {
#                foreach ($User in $Identity)
#                {
#                    $tempRule=New-AuditRule -Identity $User -FileSystemRights $NewFileSystemRights -type $NewType
#                    $AclObject.RemoveAuditRuleAll($tempRule)
#                    $AclObject.AddAuditRule($tempRule)
#                }
#            }
#            else
#            {
#                    $AclObject.RemoveAuditRuleAll($NewAuditRule)
#                    $AclObject.AddAuditRule($NewAuditRule)
#            }
#
#            #SetAccessControl sometimes fails where Set-ACL doesn't, and vice versa
#            try
#            {
#                $FileSystemObject.SetAccessControl($AclObject)
#            }
#            catch
#            {
#                Set-Acl -Path $item -AclObject $AclObject
#            }           
#        }
#    }
#}
#function Get-AuditRuleForItem
#{
#    param
#    ( 
#        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
#        [String[]]$Path,
#
#        [Parameter()]
#        [System.Security.AccessControl.AuditFlags[]]$Type=@("Success","Failure"),
#
#        [Parameter()]
#        [switch]$ExcludeInheritedRules,
#
#        [Parameter()]
#        [switch]$ExcludeExplicitRules
#    )
#    process
#    {
#        $includeExplicit=$true
#        $includeInherited=$true
#        if($ExcludeInheritedRules)
#        {
#            $includeInherited=$false
#        }
#        if($ExcludeExplicitRules)
#        {
#            $includeExplicit=$false
#        }
#
#        (Get-Item -Path $Path).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit).GetAuditRules($includeExplicit,$includeInherited,[System.Security.Principal.NTAccount]).Where({$_.Auditflags -eq $Type})
#    }
#}
#endregion

#region internal (and ugly) functions
function Convert-FriendlyRulesToFlags
{
    param
    (
        [parameter(Mandatory=$true)]
        [validateset(
            "ThisFolderOnly",
            "ThisFolderAndSubfoldersAndFiles",
            "ThisFolderAndSubFolders",
            "ThisFolderAndFiles",
            "OnlyFilesAndSubFolders",
            "OnlySubFolders",
            "OnlyFiles"
        )]
        [String]$AppliesTo,

        [parameter()]
        [switch]$OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer
    )

    switch ($AppliesTo)
    {
        'ThisFolderOnly'
        {
            [System.Security.AccessControl.InheritanceFlags[]]$InheritanceFlags="None"
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="None"
        }
        'ThisFolderAndSubfoldersAndFiles'
        {
            [System.Security.AccessControl.InheritanceFlags[]]$InheritanceFlags="ContainerInherit", "ObjectInherit"
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="None"
        }
        'ThisFolderAndSubFolders'
        {
            [System.Security.AccessControl.InheritanceFlags[]]$InheritanceFlags="ContainerInherit"
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="None"
        }
        'ThisFolderAndFiles'
        {
            [System.Security.AccessControl.InheritanceFlags[]]$InheritanceFlags="ObjectInherit"
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="None"
        }
        'OnlyFilesAndSubFolders'
        {
            [System.Security.AccessControl.InheritanceFlags[]]$InheritanceFlags="ContainerInherit", "ObjectInherit"
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="InheritOnly"
        }
        'OnlySubFolders'
        {
            [System.Security.AccessControl.InheritanceFlags[]]$InheritanceFlags="ContainerInherit"
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="InheritOnly"
        }
        'OnlyFiles'
        {
            [System.Security.AccessControl.InheritanceFlags[]]$InheritanceFlags="ObjectInherit"
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="InheritOnly"
        }
        Default {}
    }
    if ($OnlyApplyThesePermissionsToObjectsAndContainersWithinThisContainer)
    {
        if ($PropagationFlags -contains "None")
        {
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags="NoPropagateInherit"
        }
        else
        {
            [System.Security.AccessControl.PropagationFlags[]]$PropagationFlags+="NoPropagateInherit"
        }
    }
    [pscustomobject]@{
        InheritanceFlags=$InheritanceFlags
        PropagationFlags=$PropagationFlags
    }
}
function Convert-StringToIdentityReference
{
    param
    (
        [string[]]$String
    )
    foreach ($User in $String)
    {
        if ($User -like '*@*')
        {
            $UserName,$DomainName=$User.Split('@')
            $DomainName=$DomainName.Split('.')[0]
            [System.Security.Principal.NTAccount]::new($DomainName,$UserName)
        }
        else
        {
            if ($User.StartsWith('S-1-'))
            {
                [System.Security.Principal.SecurityIdentifier]::new($User)
            }
            else
            {
                [System.Security.Principal.NTAccount]::new($User)
            }
        }
    }
}
function Get-SimpleACL ($Path)
{
    $ItemObject=Get-Item -Path $Path
    try
    {
        $AclObject= $ItemObject.GetAccessControl()
    }
    catch
    {
        $AclObject= Get-Acl -Path $Path
    }
    $ItemObject
    $AclObject
}
function Set-SimpleACL ($ItemObject,$AclObject)
{
    #SetAccessControl sometimes fails where Set-ACL doesn't, and vice versa
    try
    {
        $ItemObject.SetAccessControl($AclObject)
    }
    catch
    {
        Set-Acl -Path $item -AclObject $AclObject
    }
}
#endregion