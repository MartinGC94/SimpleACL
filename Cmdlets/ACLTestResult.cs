using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SimpleACL
{
    public class ACLTestResult
    {
        #region Properties
        public string Path { get; }
        public string Identity { get; }
        public bool FullControl { get; } = false;
        public bool TraverseFolderAndExecuteFile { get; } = false;
        public bool ListFolderAndReadData { get; } = false;
        public bool ReadAttributes { get; } = false;
        public bool ReadExtendedAttributes { get; } = false;
        public bool CreateFilesAndWriteData { get; } = false;
        public bool CreateFoldersAndAppendData { get; } = false;
        public bool WriteAttributes { get; } = false;
        public bool WriteExtendedAttributes { get; } = false;
        public bool DeleteSubfoldersAndFiles { get; } = false;
        public bool Delete { get; } = false;
        public bool ReadPermissions { get; } = false;
        public bool ChangePermissions { get; } = false;
        public bool TakeOwnership { get; } = false;
        #endregion

        public ACLTestResult(String InputPath, String InputIdentity)
        {
            Path = InputPath;
            Identity = InputIdentity;

            IntPtr pSidOwner, pSidGroup, pDacl, pSacl, pSecurityDescriptor;
            ACCESS_MASK mask = new ACCESS_MASK();
            uint ret = GetNamedSecurityInfo(InputPath,
                SE_OBJECT_TYPE.SE_FILE_OBJECT,
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION | SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION,
                out pSidOwner, out pSidGroup, out pDacl, out pSacl, out pSecurityDescriptor);

            IntPtr hManager = IntPtr.Zero;

            bool f = AuthzInitializeResourceManager(1, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, null, out hManager);

            NTAccount ac = new NTAccount(InputIdentity);
            SecurityIdentifier sid = (SecurityIdentifier)ac.Translate(typeof(SecurityIdentifier));
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            String _psUserSid = "";
            foreach (byte si in bytes)
            {
                _psUserSid += si;
            }

            LUID unusedSid = new LUID();
            IntPtr UserSid = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, UserSid, bytes.Length);
            IntPtr pClientContext = IntPtr.Zero;

            if (f)
            {
                f = AuthzInitializeContextFromSid(0, UserSid, hManager, IntPtr.Zero, unusedSid, IntPtr.Zero, out pClientContext);


                AUTHZ_ACCESS_REQUEST request = new AUTHZ_ACCESS_REQUEST();
                request.DesiredAccess = 0x02000000;
                request.PrincipalSelfSid = null;
                request.ObjectTypeList = null;
                request.ObjectTypeListLength = 0;
                request.OptionalArguments = IntPtr.Zero;

                AUTHZ_ACCESS_REPLY reply = new AUTHZ_ACCESS_REPLY();
                reply.GrantedAccessMask = IntPtr.Zero;
                reply.ResultListLength = 0;
                reply.SaclEvaluationResults = IntPtr.Zero;
                IntPtr AccessReply = IntPtr.Zero;
                reply.Error = Marshal.AllocHGlobal(1020);
                reply.GrantedAccessMask = Marshal.AllocHGlobal(sizeof(uint));
                reply.ResultListLength = 1;
                int i = 0;

                f = AuthzAccessCheck(0, pClientContext, ref request, IntPtr.Zero, pSecurityDescriptor, null, 0, ref reply, out AccessReply);
                if (f)
                {
                    int granted_access = Marshal.ReadInt32(reply.GrantedAccessMask);

                    mask = (ACCESS_MASK)granted_access;

                    foreach (ACCESS_MASK item in Enum.GetValues(typeof(ACCESS_MASK)))
                    {
                        if ((mask & item) == item)
                        {
                            switch (item)
                            {
                                case ACCESS_MASK.FILE_TRAVERSE:
                                    TraverseFolderAndExecuteFile = true;
                                    break;
                                case ACCESS_MASK.FILE_LIST_DIRECTORY:
                                    ListFolderAndReadData = true;
                                    break;
                                case ACCESS_MASK.FILE_READ_ATTRIBUTES:
                                    ReadAttributes = true;
                                    break;
                                case ACCESS_MASK.FILE_READ_EA:
                                    ReadExtendedAttributes = true;
                                    break;
                                case ACCESS_MASK.FILE_ADD_FILE:
                                    CreateFilesAndWriteData = true;
                                    break;
                                case ACCESS_MASK.FILE_ADD_SUBDIRECTORY:
                                    CreateFoldersAndAppendData = true;
                                    break;
                                case ACCESS_MASK.FILE_WRITE_ATTRIBUTES:
                                    WriteAttributes = true;
                                    break;
                                case ACCESS_MASK.FILE_WRITE_EA:
                                    WriteExtendedAttributes = true;
                                    break;
                                case ACCESS_MASK.FILE_DELETE_CHILD:
                                    DeleteSubfoldersAndFiles = true;
                                    break;
                                case ACCESS_MASK.DELETE:
                                    Delete = true;
                                    break;
                                case ACCESS_MASK.READ_CONTROL:
                                    ReadPermissions = true;
                                    break;
                                case ACCESS_MASK.WRITE_DAC:
                                    ChangePermissions = true;
                                    break;
                                case ACCESS_MASK.WRITE_OWNER:
                                    TakeOwnership = true;
                                    break;
                                default:
                                    break;
                            }
                            i++;
                        }
                    }
                }
                else
                {
                    Marshal.FreeHGlobal(reply.GrantedAccessMask);
                    throw new UnauthorizedAccessException();
                }
                Marshal.FreeHGlobal(reply.GrantedAccessMask);

                if (i == 16)
                {
                    FullControl = true;
                }
            }
        }

        #region DLLImports and enums
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint GetEffectiveRightsFromAcl(IntPtr pDacl, ref TRUSTEE pTrustee, ref ACCESS_MASK pAccessRights);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 4)]
        struct TRUSTEE
        {
            IntPtr pMultipleTrustee; // must be null
            public int MultipleTrusteeOperation;
            public TRUSTEE_FORM TrusteeForm;
            public TRUSTEE_TYPE TrusteeType;
            [MarshalAs(UnmanagedType.LPStr)]
            public string ptstrName;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 4)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct AUTHZ_ACCESS_REQUEST
        {
            public int DesiredAccess;
            public byte[] PrincipalSelfSid;
            public OBJECT_TYPE_LIST[] ObjectTypeList;
            public int ObjectTypeListLength;
            public IntPtr OptionalArguments;
        };
        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_TYPE_LIST
        {
            OBJECT_TYPE_LEVEL Level;
            int Sbz;
            IntPtr ObjectType;
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct AUTHZ_ACCESS_REPLY
        {
            public int ResultListLength;
            public IntPtr GrantedAccessMask;
            public IntPtr SaclEvaluationResults;
            public IntPtr Error;
        };

        private enum OBJECT_TYPE_LEVEL : int
        {
            ACCESS_OBJECT_GUID = 0,
            ACCESS_PROPERTY_SET_GUID = 1,
            ACCESS_PROPERTY_GUID = 2,
            ACCESS_MAX_LEVEL = 4
        };
        enum TRUSTEE_FORM
        {
            TRUSTEE_IS_SID,
            TRUSTEE_IS_NAME,
            TRUSTEE_BAD_FORM,
            TRUSTEE_IS_OBJECTS_AND_SID,
            TRUSTEE_IS_OBJECTS_AND_NAME
        }

        enum AUTHZ_RM_FLAG : uint
        {
            AUTHZ_RM_FLAG_NO_AUDIT = 1,
            AUTHZ_RM_FLAG_INITIALIZE_UNDER_IMPERSONATION = 2,
            AUTHZ_RM_FLAG_NO_CENTRAL_ACCESS_POLICIES = 4,
        }

        enum TRUSTEE_TYPE
        {
            TRUSTEE_IS_UNKNOWN,
            TRUSTEE_IS_USER,
            TRUSTEE_IS_GROUP,
            TRUSTEE_IS_DOMAIN,
            TRUSTEE_IS_ALIAS,
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            TRUSTEE_IS_DELETED,
            TRUSTEE_IS_INVALID,
            TRUSTEE_IS_COMPUTER
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        static extern uint GetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            out IntPtr pSidOwner,
            out IntPtr pSidGroup,
            out IntPtr pDacl,
            out IntPtr pSacl,
            out IntPtr pSecurityDescriptor);
        [DllImport("authz.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, EntryPoint = "AuthzInitializeContextFromSid", CharSet = CharSet.Unicode)]
        static extern private bool AuthzInitializeContextFromSid(
                                               int Flags,
                                               IntPtr UserSid,
                                               IntPtr AuthzResourceManager,
                                               IntPtr pExpirationTime,
                                               LUID Identitifier,
                                               IntPtr DynamicGroupArgs,
                                               out IntPtr pAuthzClientContext
                                               );



        [DllImport("authz.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, EntryPoint = "AuthzInitializeResourceManager", CharSet = CharSet.Unicode)]
        static extern private bool AuthzInitializeResourceManager(
                                        int flags,
                                        IntPtr pfnAccessCheck,
                                        IntPtr pfnComputeDynamicGroups,
                                        IntPtr pfnFreeDynamicGroups,
                                        string name,
                                        out IntPtr rm
                                        );
        [DllImport("authz.dll", EntryPoint = "AuthzAccessCheck", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool AuthzAccessCheck(int flags,
                                                    IntPtr hAuthzClientContext,
                                                     ref AUTHZ_ACCESS_REQUEST pRequest,
                                                     IntPtr AuditEvent,
                                                     IntPtr pSecurityDescriptor,
                                                    byte[] OptionalSecurityDescriptorArray,
                                                    int OptionalSecurityDescriptorCount,
                                                    ref AUTHZ_ACCESS_REPLY pReply,
                                                    out IntPtr phAccessCheckResults);

        enum ACCESS_MASK : uint
        {
            FILE_TRAVERSE = 0x20,
            FILE_LIST_DIRECTORY = 0x1,
            FILE_READ_DATA = 0x1,
            FILE_READ_ATTRIBUTES = 0x80,
            FILE_READ_EA = 0x8,
            FILE_ADD_FILE = 0x2,
            FILE_WRITE_DATA = 0x2,
            FILE_ADD_SUBDIRECTORY = 0x4,
            FILE_APPEND_DATA = 0x4,
            FILE_WRITE_ATTRIBUTES = 0x100,
            FILE_WRITE_EA = 0x10,
            FILE_DELETE_CHILD = 0x40,
            DELETE = 0x10000,
            READ_CONTROL = 0x20000,
            WRITE_DAC = 0x40000,
            WRITE_OWNER = 0x80000,


            ////////FILE_EXECUTE =0x20,   
        }

        [Flags]
        enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
        }

        enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY
        }
        #endregion
    }
}