# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

Function Get-ServiceCredential {
    <#
    .SYNOPSIS
    Retrieve the username and plaintext password for all services installed on the local computer.

    .DESCRIPTION
    Will retrieve the username and plaintext password for the service(s) specified. This must be run as an
    administrator as a limited user does not have the necessary rights to perform this lookup.

    .PARAMETER Name
    The name of the service(s) to get the credential for. Omit to get the credentials for all the installed services.
    The name can be either the service or display name that is accepted by 'Get-Service'.

    .INPUTS Name
    The name(s) of the services can also be inputed through the pipeline as a string or array of strings.

    .OUTPUTS
    [ServiceCredential]
        Name: The name of the service the credential is for.
        Username: The NTAccount representing the username the service is set to run as.
        Password: The password as a plaintext string. Will be set to $null if the service has no password set.

    .EXAMPLE Get credentials for all services
    Get-ServiceCredential

    .EXAMPLE Get credentials for a single service
    Get-ServiceCredential -Name "My service"

    .EXAMPLE Get credentials for multiple services
    Get-ServiceCredential -Name "My service 1", "My service 2"

    .NOTES
    This cmdlet works by looking up the service secret in LSA but to do this it needs to create a temporary copy of
    the credential in 'HKLM:\Security\Policy\Secrets\_SC_<name>' which is only accesible by the SYSTEM account. If the
    cmdlet is not run as the SYSTEM account already it tried to impersonate the account for you.

    Runs on both PowerShell Desktop and PowerShell Core for Windows.
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [String[]]
        $Name
    )

    begin {
        try {
            $addTypeParams = @{
                TypeDefinition = @'
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ServiceHelper
{
    internal class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public class LSA_OBJECT_ATTRIBUTES
        {
            public UInt32 Length = 0;
            public IntPtr RootDirectory = IntPtr.Zero;
            public IntPtr ObjectName = IntPtr.Zero;
            public UInt32 Attributes = 0;
            public IntPtr SecurityDescriptor = IntPtr.Zero;
            public IntPtr SecurityQualityOfService = IntPtr.Zero;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;

            public static explicit operator string(LSA_UNICODE_STRING s)
            {
                byte[] strBytes = new byte[s.Length];
                Marshal.Copy(s.Buffer, strBytes, 0, s.Length);
                return Encoding.Unicode.GetString(strBytes);
            }

            public static SafeMemoryBuffer CreateSafeBuffer(string s)
            {
                if (s == null)
                    return new SafeMemoryBuffer(IntPtr.Zero);

                byte[] stringBytes = Encoding.Unicode.GetBytes(s);
                int structSize = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
                IntPtr buffer = Marshal.AllocHGlobal(structSize + stringBytes.Length);
                try
                {
                    LSA_UNICODE_STRING lsaString = new LSA_UNICODE_STRING()
                    {
                        Length = (UInt16)(stringBytes.Length),
                        MaximumLength = (UInt16)(stringBytes.Length),
                        Buffer = IntPtr.Add(buffer, structSize),
                    };
                    Marshal.StructureToPtr(lsaString, buffer, false);
                    Marshal.Copy(stringBytes, 0, lsaString.Buffer, stringBytes.Length);
                    return new SafeMemoryBuffer(buffer);
                }
                catch
                {
                    // Make sure we free the pointer before raising the exception.
                    Marshal.FreeHGlobal(buffer);
                    throw;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VmOperation = 0x00000008,
            VmRead = 0x00000010,
            VmWrite = 0x00000020,
            DupHandle = 0x00000040,
            CreateProcess = 0x00000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            SuspendResume = 0x00000800,
            QueryLimitedInformation = 0x00001000,
            Delete = 0x00010000,
            ReadControl = 0x00020000,
            WriteDac = 0x00040000,
            WriteOwner = 0x00080000,
            Synchronize = 0x00100000,
        }

        public enum TokenInformationClass : uint
        {
            TokenUser = 1,
        }
    }

    internal class NativeMethods
    {
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            SafeNativeHandle TokenHandle,
            NativeHelpers.TokenInformationClass TokenInformationClass,
            SafeMemoryBuffer TokenInformation,
            UInt32 TokenInformationLength,
            out UInt32 ReturnLength);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            SafeNativeHandle hToken);

        [DllImport("Advapi32.dll")]
        public static extern UInt32 LsaClose(
            IntPtr ObjectHandle);

        [DllImport("Advapi32.dll")]
        public static extern UInt32 LsaFreeMemory(
            IntPtr Buffer);

        [DllImport("Advapi32.dll")]
        internal static extern Int32 LsaNtStatusToWinError(
            UInt32 Status);

        [DllImport("Advapi32.dll")]
        public static extern UInt32 LsaOpenPolicy(
            IntPtr SystemName,
            NativeHelpers.LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            UInt32 AccessMask,
            out SafeLsaHandle PolicyHandle);

        [DllImport("Advapi32.dll")]
        public static extern UInt32 LsaRetrievePrivateData(
            SafeLsaHandle PolicyHandle,
            SafeMemoryBuffer KeyName,
            out SafeLsaMemory PrivateData);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern SafeNativeHandle OpenProcess(
            NativeHelpers.ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            UInt32 dwProcessId);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            SafeNativeHandle ProcessHandle,
            TokenAccessLevels DesiredAccess,
            out SafeNativeHandle TokenHandle);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
    }

    internal class SafeLsaMemory : SafeBuffer
    {
        internal SafeLsaMemory() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]

        protected override bool ReleaseHandle()
        {
            return NativeMethods.LsaFreeMemory(handle) == 0;
        }
    }

    internal class SafeMemoryBuffer : SafeBuffer
    {
        internal SafeMemoryBuffer() : base(true) { }

        internal SafeMemoryBuffer(int cb) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(cb));
        }

        internal SafeMemoryBuffer(IntPtr ptr) : base(true)
        {
            base.SetHandle(ptr);
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]

        protected override bool ReleaseHandle()
        {
            if (handle != IntPtr.Zero)
                Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal class SafeLsaHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeLsaHandle() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]

        protected override bool ReleaseHandle()
        {
            return NativeMethods.LsaClose(handle) == 0;
        }
    }

    internal class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNativeHandle() : base(true) { }
        public SafeNativeHandle(IntPtr handle) : base(true) { this.handle = handle; }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
    }

    internal class AccessToken
    {
        public static IEnumerable<SafeNativeHandle> EnumerateUserTokens(SecurityIdentifier sid,
            TokenAccessLevels access = TokenAccessLevels.Query)
        {
            foreach (System.Diagnostics.Process process in System.Diagnostics.Process.GetProcesses())
            {
                // We always need the Query access level so we can query the TokenUser
                using (process)
                using (SafeNativeHandle hToken = TryOpenAccessToken(process, access | TokenAccessLevels.Query))
                {
                    if (hToken == null)
                        continue;

                    if (!sid.Equals(GetTokenUser(hToken)))
                        continue;

                    yield return hToken;
                }
            }
        }

        private static SafeMemoryBuffer GetTokenInformation(SafeNativeHandle hToken,
            NativeHelpers.TokenInformationClass infoClass)
        {
            UInt32 tokenLength;
            bool res = NativeMethods.GetTokenInformation(hToken, infoClass, new SafeMemoryBuffer(IntPtr.Zero), 0,
                out tokenLength);
            int errCode = Marshal.GetLastWin32Error();
            if (!res && errCode != 24 && errCode != 122)  // ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH
                throw new Win32Exception(errCode, String.Format("GetTokenInformation({0}) failed to get buffer length",
                    infoClass.ToString()));

            SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer((int)tokenLength);
            if (!NativeMethods.GetTokenInformation(hToken, infoClass, tokenInfo, tokenLength, out tokenLength))
                throw new Win32Exception(String.Format("GetTokenInformation({0}) failed", infoClass.ToString()));

            return tokenInfo;
        }

        private static SecurityIdentifier GetTokenUser(SafeNativeHandle hToken)
        {
            using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken,
                NativeHelpers.TokenInformationClass.TokenUser))
            {
                NativeHelpers.TOKEN_USER tokenUser = (NativeHelpers.TOKEN_USER)Marshal.PtrToStructure(
                    tokenInfo.DangerousGetHandle(),
                    typeof(NativeHelpers.TOKEN_USER));
                return new SecurityIdentifier(tokenUser.User.Sid);
            }
        }

        private static SafeNativeHandle OpenProcess(Int32 pid, NativeHelpers.ProcessAccessFlags access, bool inherit)
        {
            SafeNativeHandle hProcess = NativeMethods.OpenProcess(access, inherit, (UInt32)pid);
            if (hProcess.IsInvalid)
                throw new Win32Exception(String.Format("Failed to open process {0} with access {1}",
                    pid, access.ToString()));

            return hProcess;
        }

        private static SafeNativeHandle OpenProcessToken(SafeNativeHandle hProcess, TokenAccessLevels access)
        {
            SafeNativeHandle hToken;
            if (!NativeMethods.OpenProcessToken(hProcess, access, out hToken))
                throw new Win32Exception(String.Format("Failed to open proces token with access {0}",
                    access.ToString()));

            return hToken;
        }

        private static SafeNativeHandle TryOpenAccessToken(System.Diagnostics.Process process, TokenAccessLevels access)
        {
            try
            {
                using (SafeNativeHandle hProcess = OpenProcess(process.Id,
                    NativeHelpers.ProcessAccessFlags.QueryInformation, false))
                    return OpenProcessToken(hProcess, access);
            }
            catch (Win32Exception)
            {
                return null;
            }
        }
    }

    public class Win32Exception : System.ComponentModel.Win32Exception
    {
        private string _msg;
        public Win32Exception(string message) : this(Marshal.GetLastWin32Error(), message) { }
        public Win32Exception(int errorCode, string message) : base(errorCode)
        {
            _msg = String.Format("{0} ({1}, Win32ErrorCode {2} - 0x{2:X8})", message, base.Message, errorCode);
        }
        public override string Message { get { return _msg; } }
        public static explicit operator Win32Exception(string message) { return new Win32Exception(message); }
    }

    public class Impersonation : IDisposable
    {
        public Impersonation(SecurityIdentifier sid)
        {
            bool success = false;
            foreach (SafeNativeHandle handle in AccessToken.EnumerateUserTokens(sid,
                TokenAccessLevels.Duplicate | TokenAccessLevels.Impersonate))
            {
                if (NativeMethods.ImpersonateLoggedOnUser(handle))
                {
                    success = true;
                    break;
                }
            }

            if (!success)
                throw new Exception(String.Format("Failed to impersonate existing token for sid {0}", sid.Value));
        }

        public void Dispose()
        {
            NativeMethods.RevertToSelf();
            GC.SuppressFinalize(this);
        }
        ~Impersonation() { this.Dispose(); }
    }

    public class LsaUtil
    {
        public static string RetrievePrivateData(string key)
        {
            NativeHelpers.LSA_OBJECT_ATTRIBUTES oa = new NativeHelpers.LSA_OBJECT_ATTRIBUTES();
            SafeLsaHandle lsaHandle;
            UInt32 res = NativeMethods.LsaOpenPolicy(IntPtr.Zero, oa, 0x00000004, out lsaHandle);
            if (res != 0)
                throw new Win32Exception(NativeMethods.LsaNtStatusToWinError(res), "LsaOpenPolicy(GetPrivateInformation) failed");

            using (lsaHandle)
            using (SafeMemoryBuffer keyBuffer = NativeHelpers.LSA_UNICODE_STRING.CreateSafeBuffer(key))
            {
                SafeLsaMemory buffer;
                res = NativeMethods.LsaRetrievePrivateData(lsaHandle, keyBuffer, out buffer);
                using (buffer)
                {
                    if (res != 0)
                    {
                        // If the data object was not found we return null to indicate it isn't set.
                        if (res == 0xC0000034)  // STATUS_OBJECT_NAME_NOT_FOUND
                            return null;

                        throw new Win32Exception(NativeMethods.LsaNtStatusToWinError(res),
                            String.Format("LsaRetrievePrivateData({0}) failed", key));
                    }

                    NativeHelpers.LSA_UNICODE_STRING lsaString = (NativeHelpers.LSA_UNICODE_STRING)
                        Marshal.PtrToStructure(buffer.DangerousGetHandle(),
                        typeof(NativeHelpers.LSA_UNICODE_STRING));
                    return (string)lsaString;
                }
            }
        }
    }
}
'@
            }

            # PowerShell Core must reference a few different DLLs to compile the C# code.
            $coreClr = Get-Variable -Name IsCoreCLR -ErrorAction Ignore
            if ($null -ne $coreClr -and $coreClr.Value) {
                $addTypeParams.ReferencedAssemblies = @(
                    ([System.ComponentModel.Component].Assembly.Location),
                    ([System.ComponentModel.Win32Exception].Assembly.Location),
                    ([System.Diagnostics.Process].Assembly.Location),
                    ([System.Security.Principal.SecurityIdentifier].Assembly.Location)
                )
            }
            Add-Type @addTypeParams

            $typeData = @{
                TypeName = 'ServiceCredential'
                DefaultDisplayPropertySet = 'Name', 'Username', 'Password'
                Force = $true
            }
            Update-TypeData @typeData

            # Call Win32_Service once and cache the results so that we don't waste cycles calling it multiple times
            # on each pipeline input.
            $installedServices = Get-CimInstance -ClassName Win32_Service -Property 'Name', 'Caption', 'StartName'
            $lsaSecretPath = "HKLM:\SECURITY\Policy\Secrets"

            # To access the reg key hive HKLM:\Security we need to impersonate the SYSTEM account if we are not
            # already that account.
            $systemSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @(
                [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null
            )
            $impersonation = $null
            $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            if (-not ([Security.Principal.WindowsPrincipal]$currentIdentity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
                $msg = "Current user does not have Administrative rights, cannot get service credentials"
                Write-Error -Message $msg -ErrorAction Stop
            }
            elseif ($currentIdentity.User -ne $systemSid) {
                $impersonation = New-Object -TypeName ServiceHelper.Impersonation -ArgumentList @(
                    $systemSid
                )
            }
        }
        catch {
            if ($null -ne $impersonation) {
                $impersonation.Dispose()
            }
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }

    process {
        try {
            if ($null -eq $Name) {
                $Name = $installedServices | Select-Object -ExpandProperty Name
            }

            foreach ($serviceName in $Name) {
                $win32Service = $installedServices | Where-Object { $serviceName -in @($_.Name, $_.Caption) }
                if ($null -eq $win32Service) {
                    Write-Error -Message "Failed to find an installed service with the name '$serviceName'"
                    continue
                }
                $serviceName = $win32Service.Name  # Make sure we are using the service name not the display name.

                # Parse the username from the string WMI returns to an actual NTAccount object
                $username = $win32Service.StartName
                if ($username -eq 'LocalSystem') {
                    $username = $systemSid.Translate([System.Security.Principal.NTAccount])
                }
                elseif ($username) {
                    # We translate to a SID and back again to make sure we return the NTAccount in a common format.
                    if ($username.StartsWith('.\')) {
                        $username = $username.Substring(2)
                    }

                    try {
                        $ntAccount = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $username
                        $accountSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                        $username = $accountSid.Translate([System.Security.Principal.NTAccount])
                    }
                    catch [System.Security.Principal.IdentityNotMappedException] {
                        Write-Warning -Message "Failed to normalize username for '$serviceName' user '$username': $_"
                    }
                }
                else {
                    # Make sure that an empty string is returned as $null for uniformity.
                    $username = $null
                }

                $lsaSecretName = "_SC_$serviceName"
                if (Get-Item -LiteralPath "$lsaSecretPath\$lsaSecretName" -ErrorAction SilentlyContinue) {
                    # It seems like RetrievePrivateData fails with Access Denied with the _ prefix. We do a temp copy
                    # to a new path without that prefix then delete the temp copy once we are done.
                    $tempName = ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object -Process { [char]$_ }) -join ""
                    Copy-Item -Path "$lsaSecretPath\$lsaSecretName" -Destination "$lsaSecretPath\$tempName" -Recurse -Force
                    try {
                        $password = [ServiceHelper.LsaUtil]::RetrievePrivateData($tempName)
                    }
                    finally {
                        Remove-Item -Path "$lsaSecretPath\$tempName" -Force -Recurse
                    }
                }
                else {
                    $password = $null
                }

                [PSCustomObject]@{
                    PSTypeName = 'ServiceCredential'
                    Name = $serviceName
                    Username = $username
                    Password = $password
                }
            }
        }
        catch {
            # Make sure that we dispose of the impersonation context if a terminating error is reached.
            if ($null -ne $impersonation) {
                $impersonation.Dispose()
            }
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }

    end {
        try {
            if ($null -ne $impersonation) {
                $impersonation.Dispose()
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
}
