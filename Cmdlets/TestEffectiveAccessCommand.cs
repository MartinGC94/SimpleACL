using System;
using System.IO;
using System.Management.Automation;
using System.Security.Principal;

namespace SimpleACL
{
    [Cmdlet(VerbsDiagnostic.Test, "EffectiveAccess")]

    public sealed class TestEffectiveAccessCommand : Cmdlet
    {
        #region parameters
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline =true,ValueFromPipelineByPropertyName =true)]
        [ValidateNotNullOrEmpty()]
        public string[] Path { get; set; }

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        public string[] Identity { get; set; } = {Environment.UserDomainName + '\\' + Environment.UserName};
        #endregion

        protected override void ProcessRecord()
        {
            foreach (String pathItem in Path)
            {
                if (Directory.Exists(pathItem) == false && File.Exists(pathItem) == false)
                {
                    WriteError(new ErrorRecord
                        (new ItemNotFoundException
                        ("Cannot find path \'" + pathItem + "\' because it does not exist."), "PathNotFound", ErrorCategory.ObjectNotFound, pathItem));
                }
                else
                {
                    foreach (String user in Identity)
                    {
                        try
                        {
                            WriteObject(new ACLTestResult(pathItem, user));
                        }
                        catch (UnauthorizedAccessException e)
                        {
                            WriteError(new ErrorRecord(e, "UnauthorizedAccess", ErrorCategory.PermissionDenied, pathItem));
                        }
                        catch (IdentityNotMappedException e)
                        {
                            WriteError(new ErrorRecord(e, "InvalidIdentity", ErrorCategory.ObjectNotFound, user));
                        }
                    }
                }
            }
        }
    }
}