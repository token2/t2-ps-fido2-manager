#Requires -Version 5.1
<#
  T2-PS-FIDO2-Manager-1.0.1-CTAP-Compat.ps1  -  T2 PS FIDO2 Manager
  Manage Token2 T2F2 / PIN+ FIDO2 security keys in pure PowerShell.
  Relies only on standard Windows DLLs (hid, setupapi, kernel32, winscard).
  No modules, no libfido2, nothing else to install. Admin rights required.

  ADMIN RIGHTS
    Everything except the serial number needs an elevated session.
      serial (vendor APDU)  works unelevated
      CTAP over NFC         needs admin - SCardTransmit returns
                            SCARD_E_INSUFFICIENT_BUFFER (0x80100027) on the
                            applet SELECT otherwise
      CTAP over USB-HID     needs admin - CreateFile returns ACCESS_DENIED
    The script warns and continues; it does not self-elevate.

  TRANSPORTS
    ccid  PC/SC via winscard.dll, over USB or NFC. Carries the vendor
          serial/config commands. Over USB it does NOT carry CTAP2
          (INS 0x10 -> 6D00 or 6985). Over NFC it does.
    hid   USB-HID CTAPHID via setupapi/hid.dll. Carries CTAP2 over USB.
          Cannot read the vendor serial.

    -Transport auto (default) prefers hid when elevated, else ccid.

  USAGE
    .\T2-PS-FIDO2-Manager.ps1 -Gui                graphical window
    .\T2-PS-FIDO2-Manager.ps1                     serial (exit 0/1)
    .\T2-PS-FIDO2-Manager.ps1 -Info               CTAP2 getInfo
    .\T2-PS-FIDO2-Manager.ps1 -Config             vendor config bits [ccid]
    .\T2-PS-FIDO2-Manager.ps1 -PinRetries         PIN retry counter
    .\T2-PS-FIDO2-Manager.ps1 -Pin                set or change the PIN
    .\T2-PS-FIDO2-Manager.ps1 -Pin -DryRun        print CBOR, send nothing
    .\T2-PS-FIDO2-Manager.ps1 -CredsMeta          storage stats
    .\T2-PS-FIDO2-Manager.ps1 -CredsList          list resident credentials
    .\T2-PS-FIDO2-Manager.ps1 -CredsDelete <hex>  delete one credential
    .\T2-PS-FIDO2-Manager.ps1 -Reset              factory reset

  POLICY (authenticatorConfig 0x0D, needs the acfg permission)
    -AlwaysUv on|off        require PIN/fingerprint for every assertion, even
                            where the service did not ask. Sub-command 0x02 is
                            a TOGGLE, so the current state is read first and the
                            call is skipped when it already matches.
    -MinPinLength <n>       raise the shortest accepted PIN. One-way: lowering
                            it again needs a factory reset. If the current PIN
                            is shorter, the key forces a change by itself.
    -ForcePinChange         next interaction must set a new PIN. Combine with
                            -MinPinLength, or use alone to leave the length as-is.

  FINGERPRINTS (authenticatorBioEnrollment 0x09, needs the be permission)
    -BioList                sensor info + enrolled fingerprints
    -BioEnroll [-BioName x] enroll a new finger; touch the sensor repeatedly
    -BioRename <hex> -BioName <name>
    -BioDelete <hex>        remove one enrollment by template id

    Only works on a key with a fingerprint sensor - getInfo must advertise
    bioEnroll. The vendor config byte's FingerprintPresent flag is NOT
    reliable across models; the CTAP options map is.

    -Transport ccid|hid to force one. -Debug2 to trace hex.

  NOTES
    PIN protocol v1: its shared secret is SHA-256 of the raw ECDH point, which
    CNG's Hash KDF produces natively. v2 needs DeriveRawSecretAgreement -
    .NET Core only, absent from PS 5.1.

    Tokens come from getPinUvAuthTokenUsingPinWithPermissions (0x09), not the
    legacy getPinToken (0x05): a 0x05 token carries only implicit mc/ga
    permissions, so credMgmt rejects it with 0x33.

    A wrong PIN at token acquisition DOES decrement the retry counter.
#>
param(
    [switch]$Gui,
    [switch]$Config,
    [switch]$Info,
    [switch]$PinRetries,
    [switch]$Pin,
    [switch]$DryRun,
    [switch]$Reset,
    [switch]$CredsMeta,
    [switch]$CredsList,
    [string]$CredsDelete,
    [ValidateSet('on','off')]
    [string]$AlwaysUv,
    [int]$MinPinLength = 0,
    [switch]$ForcePinChange,
    [switch]$BioList,
    [switch]$BioEnroll,
    [string]$BioName,
    [string]$BioRename,
    [string]$BioDelete,
    [ValidateSet('auto','ccid','hid')]
    [string]$Transport = 'auto',
    [switch]$Debug2
)

# ======================= P/Invoke: PC/SC =======================
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class T2SC {
    [DllImport("winscard.dll")] public static extern int SCardEstablishContext(int scope, IntPtr r1, IntPtr r2, out IntPtr ctx);
    [DllImport("winscard.dll")] public static extern int SCardReleaseContext(IntPtr ctx);
    [DllImport("winscard.dll", CharSet=CharSet.Unicode)] public static extern int SCardListReaders(IntPtr ctx, string groups, char[] readers, ref int len);
    [DllImport("winscard.dll", CharSet=CharSet.Unicode)] public static extern int SCardConnect(IntPtr ctx, string reader, int share, int prefProto, out IntPtr card, out int activeProto);
    [DllImport("winscard.dll")] public static extern int SCardDisconnect(IntPtr card, int disp);
    [DllImport("winscard.dll")] public static extern int SCardTransmit(IntPtr card, ref IO pioSend, byte[] send, int sendLen, IntPtr pioRecv, byte[] recv, ref int recvLen);
    [StructLayout(LayoutKind.Sequential)] public struct IO { public int Protocol; public int PciLength; }
}
'@ -ErrorAction SilentlyContinue

# ======================= P/Invoke: USB-HID =======================
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class T2HID {
    [DllImport("setupapi.dll", SetLastError=true)]
    public static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, uint Flags);
    [DllImport("setupapi.dll", SetLastError=true)]
    public static extern bool SetupDiEnumDeviceInterfaces(IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid, uint MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);
    [DllImport("setupapi.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData, IntPtr DeviceInterfaceDetailData, uint DeviceInterfaceDetailDataSize, ref uint RequiredSize, IntPtr DeviceInfoData);
    [DllImport("setupapi.dll", SetLastError=true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVICE_INTERFACE_DATA {
        public uint cbSize; public Guid InterfaceClassGuid; public uint Flags; public IntPtr Reserved;
    }

    [DllImport("hid.dll")] public static extern void HidD_GetHidGuid(out Guid HidGuid);
    [DllImport("hid.dll", SetLastError=true)] public static extern bool HidD_GetPreparsedData(IntPtr h, out IntPtr pp);
    [DllImport("hid.dll")] public static extern bool HidD_FreePreparsedData(IntPtr pp);
    [DllImport("hid.dll", SetLastError=true)] public static extern int HidP_GetCaps(IntPtr pp, ref HIDP_CAPS caps);
    [DllImport("hid.dll", SetLastError=true)] public static extern bool HidD_GetAttributes(IntPtr h, ref HIDD_ATTRIBUTES a);
    [DllImport("hid.dll", CharSet=CharSet.Unicode)] public static extern bool HidD_GetProductString(IntPtr h, StringBuilder b, int len);

    [StructLayout(LayoutKind.Sequential)]
    public struct HIDP_CAPS {
        public ushort Usage; public ushort UsagePage;
        public ushort InputReportByteLength; public ushort OutputReportByteLength; public ushort FeatureReportByteLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=17)] public ushort[] Reserved;
        public ushort NumberLinkCollectionNodes;
        public ushort NumberInputButtonCaps; public ushort NumberInputValueCaps; public ushort NumberInputDataIndices;
        public ushort NumberOutputButtonCaps; public ushort NumberOutputValueCaps; public ushort NumberOutputDataIndices;
        public ushort NumberFeatureButtonCaps; public ushort NumberFeatureValueCaps; public ushort NumberFeatureDataIndices;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct HIDD_ATTRIBUTES { public int Size; public ushort VendorID; public ushort ProductID; public ushort VersionNumber; }

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteFile(IntPtr h, byte[] buf, uint toWrite, out uint written, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadFile(IntPtr h, byte[] buf, uint toRead, out uint read, IntPtr ov);
}
'@ -ErrorAction SilentlyContinue

# ============================ Constants ============================
$script:selFido    = [byte[]](0x00,0xA4,0x04,0x00,0x08, 0xA0,0x00,0x00,0x06,0x47,0x2F,0x00,0x01)
$script:selOtp     = [byte[]](0x00,0xA4,0x04,0x00,0x08, 0xF0,0x00,0x00,0x01,0x4F,0x74,0x70,0x01)
$script:vendorInfo = [byte[]](0x80,0x33,0x00,0x00,0x12, 0xD1,0x10) + (New-Object byte[] 16)
$script:readCfg    = [byte[]](0x80,0xC5,0x02,0x00, 0x40)

$CTAP_GET_INFO   = 0x04
$CTAP_CLIENT_PIN = 0x06
$CTAP_RESET      = 0x07
$CTAP_CRED_MGMT  = 0x0A
# CTAP 2.0 credentialManagementPreview; paired with legacy getPinToken.
$CTAP_CRED_MGMT_PREVIEW = 0x41
$CTAP_CONFIG     = 0x0D
$CTAP_BIO        = 0x09
$CTAP_BIO_PREVIEW = 0x40
$PERM_CRED_MGMT  = 0x04
$PERM_BIO_ENROLL = 0x08
$PERM_AUTHNR_CFG = 0x20
$BIO_MODALITY_FINGERPRINT = 0x01

$FIDO_USAGE_PAGE = 0xF1D0
# The L suffix forces [long] parsing: PowerShell reads 0x80000000 as a signed
# [int] otherwise, so it is already negative before any [uint32] cast sees it.
$ACCESS_RW       = [uint32](0x80000000L -bor 0x40000000L)
$SHARE_RW        = [uint32]3
$OPEN_EXISTING   = [uint32]3
$INVALID_HANDLE  = [IntPtr](-1)
$HIDP_STATUS_SUCCESS   = 0x00110000
$DIGCF_PRESENT         = 0x02
$DIGCF_DEVICEINTERFACE = 0x10
$CTAPHID_INIT      = 0x86
$CTAPHID_CBOR      = 0x10
$CTAPHID_CANCEL    = 0x11
$CTAPHID_KEEPALIVE = 0xBB
$CTAPHID_ERROR     = 0xBF

$script:mode   = $null
$script:card   = [IntPtr]::Zero
$script:ctx    = [IntPtr]::Zero
$script:io     = $null
$script:hid    = [IntPtr]::Zero
$script:cid    = $null
$script:Debug2 = $Debug2
$script:Log    = { param($msg, $level) }   # replaced by the CLI or GUI
$script:OnTouchNeeded = $null   # set by the enroll dialog; else keepalives log
$script:bioUi   = $null         # enroll dialog controls, while one is open
$script:bioBeat = 0             # keepalive pulse phase
$script:bioIdle = $true         # true = not currently awaiting a touch (muted)
$script:bioCancel = $false      # set by the enroll dialog's Cancel button
$script:bioCancelSent = $false  # true once CTAPHID_CANCEL has been sent once
$script:bioDone = 0             # samples captured so far
# CTAP-COMPAT 1.0.1: selected credential-management command for this run.
$script:credMgmtCmd = $CTAP_CRED_MGMT

function Write-Log([string]$msg, [string]$level = 'info') { & $script:Log $msg $level }

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ======================== CCID plumbing ========================
function Send-Apdu([byte[]]$apdu) {
    $rsp = New-Object byte[] 4096
    $rl  = $rsp.Length
    $rc = [T2SC]::SCardTransmit($script:card,[ref]$script:io,$apdu,$apdu.Length,[IntPtr]::Zero,$rsp,[ref]$rl)
    if ($rc -ne 0) {
        if ($script:Debug2) {
            $head = ($apdu[0..([Math]::Min(6,$apdu.Length-1))] | ForEach-Object {'{0:X2}' -f $_}) -join ' '
            Write-Log ("SCardTransmit rc=0x{0:X8} on {1}..." -f $rc, $head) 'debug'
        }
        # 0x80100027 = SCARD_E_INSUFFICIENT_BUFFER. Observed on the applet
        # SELECT when the session is not elevated; the vendor 80 33 command
        # still transmits, which is why the serial works without admin.
        if ($rc -eq 0x80100027 -and -not (Test-Elevated)) {
            throw "SCardTransmit refused (0x80100027) - CTAP over PC/SC needs an elevated session"
        }
        return $null
    }
    if ($rl -lt 2) { return $null }

    $data = @()
    if ($rl -gt 2) { $data = $rsp[0..($rl-3)] }
    $sw1 = $rsp[$rl-2]; $sw2 = $rsp[$rl-1]

    # T=0 continuation: 61 xx means xx more bytes are waiting.
    $guard = 0
    while ($sw1 -eq 0x61) {
        $get = [byte[]](0x00,0xC0,0x00,0x00,$sw2)
        $rl  = $rsp.Length
        if ([T2SC]::SCardTransmit($script:card,[ref]$script:io,$get,$get.Length,[IntPtr]::Zero,$rsp,[ref]$rl) -ne 0) { break }
        if ($rl -lt 2) { break }
        if ($rl -gt 2) { $data += $rsp[0..($rl-3)] }
        $sw1 = $rsp[$rl-2]; $sw2 = $rsp[$rl-1]
        if (++$guard -gt 64) { break }
    }
    @{ Data = $data; SW1 = $sw1; SW2 = $sw2 }
}

function Get-PcscReaders {
    if ($script:ctx -eq [IntPtr]::Zero) {
        if ([T2SC]::SCardEstablishContext(2,[IntPtr]::Zero,[IntPtr]::Zero,[ref]$script:ctx) -ne 0) { return @() }
    }
    $len = 0
    [void][T2SC]::SCardListReaders($script:ctx,$null,$null,[ref]$len)
    if ($len -le 0) { return @() }
    $buf = New-Object char[] $len
    [void][T2SC]::SCardListReaders($script:ctx,$null,$buf,[ref]$len)
    @((-join $buf).Split([char]0) | Where-Object { $_ })
}

function Connect-CcidReader([string]$reader) {
    $c = [IntPtr]::Zero; $proto = 0
    # Shared first, then Exclusive (mirrors keyroost's transport).
    $rc = [T2SC]::SCardConnect($script:ctx,$reader,2,3,[ref]$c,[ref]$proto)
    if ($rc -ne 0) { $rc = [T2SC]::SCardConnect($script:ctx,$reader,1,3,[ref]$c,[ref]$proto) }
    if ($rc -ne 0) { return $false }
    $script:card = $c
    $script:io = New-Object T2SC+IO
    $script:io.Protocol = $proto
    $script:io.PciLength = 8
    if ($script:Debug2) { Write-Log "connected: $reader proto=$proto" 'debug' }
    $true
}
function Disconnect-Ccid {
    if ($script:card -ne [IntPtr]::Zero) { [void][T2SC]::SCardDisconnect($script:card,0); $script:card = [IntPtr]::Zero }
}
function Close-CcidContext {
    Disconnect-Ccid
    if ($script:ctx -ne [IntPtr]::Zero) { [void][T2SC]::SCardReleaseContext($script:ctx); $script:ctx = [IntPtr]::Zero }
}

# ======================== HID plumbing ========================
# No `continue` inside these try/finally blocks: in PowerShell that does not
# reliably continue the enclosing loop and can escape it entirely, which
# silently returned $null even with the key plugged in. Each interface is
# inspected by a helper that returns a value instead.
function Get-HidInterfacePath($devInfo, [ref]$hidGuid, [int]$index) {
    $ifData = New-Object T2HID+SP_DEVICE_INTERFACE_DATA
    $ifData.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"T2HID+SP_DEVICE_INTERFACE_DATA")
    if (-not [T2HID]::SetupDiEnumDeviceInterfaces($devInfo, [IntPtr]::Zero, $hidGuid, $index, [ref]$ifData)) { return $null }

    $req = 0
    [void][T2HID]::SetupDiGetDeviceInterfaceDetail($devInfo, [ref]$ifData, [IntPtr]::Zero, 0, [ref]$req, [IntPtr]::Zero)
    if ($req -eq 0) { return '' }

    $detail = [Runtime.InteropServices.Marshal]::AllocHGlobal([int]$req)
    try {
        # cbSize is the fixed header size (8 on x64 / 6 on x86), NOT the buffer
        # size. Classic SetupAPI trap.
        #
        # The value written to cbSize and the offset DevicePath is read from are
        # NOT the same number. cbSize is a declared struct size the API validates
        # against; DevicePath begins immediately after the 4-byte cbSize field,
        # at offset 4, on both architectures. Reading at 8 silently strips the
        # two leading backslashes of "\\?\hid#..." and every CreateFile then
        # fails with 0x7B ERROR_INVALID_NAME.
        [Runtime.InteropServices.Marshal]::WriteInt32($detail, 0, $(if ([IntPtr]::Size -eq 8) { 8 } else { 6 }))
        if (-not [T2HID]::SetupDiGetDeviceInterfaceDetail($devInfo, [ref]$ifData, $detail, $req, [ref]$req, [IntPtr]::Zero)) { return '' }
        $maxChars = [int](($req - 4) / 2)
        if ($maxChars -le 0) { return '' }
        $p = [Runtime.InteropServices.Marshal]::PtrToStringAuto([IntPtr]::Add($detail, 4), $maxChars)
        if ($p) { return $p.Split([char]0)[0] }
        return ''
    }
    finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($detail) }
}

function Test-FidoHidPath([string]$path) {
    # Probe with dwDesiredAccess = 0: metadata-only access. GetPreparsedData /
    # GetCaps / GetAttributes / GetProductString all work on a zero-access
    # handle, which is all identification needs, and it avoids opening every
    # keyboard and mouse on the bus read/write just to look at them. Some HID
    # devices are exclusively held by the OS and refuse RW to anyone; a
    # zero-access probe identifies those too. RW is requested later, in
    # Connect-Hid, only for the device we actually talk to.
    $h = [T2HID]::CreateFile($path, 0, $SHARE_RW, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
    if ($h -eq $INVALID_HANDLE) {
        if ($script:Debug2) {
            $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Log ("  open failed 0x{0:X} {1}" -f $e, $path) 'debug'
        }
        return $null
    }
    $result = $null
    try {
        $pp = [IntPtr]::Zero
        if ([T2HID]::HidD_GetPreparsedData($h, [ref]$pp)) {
            try {
                $caps = New-Object T2HID+HIDP_CAPS
                $st = [T2HID]::HidP_GetCaps($pp, [ref]$caps)
                if ($script:Debug2 -and $st -ne $HIDP_STATUS_SUCCESS) {
                    Write-Log ("  GetCaps 0x{0:X} {1}" -f $st, $path) 'debug'
                }
                if ($script:Debug2 -and $st -eq $HIDP_STATUS_SUCCESS -and $caps.UsagePage -ne $FIDO_USAGE_PAGE) {
                    Write-Log ("  usage page 0x{0:X4} (want 0x{1:X4}) {2}" -f $caps.UsagePage, $FIDO_USAGE_PAGE, $path) 'debug'
                }
                if ($st -eq $HIDP_STATUS_SUCCESS -and $caps.UsagePage -eq $FIDO_USAGE_PAGE) {
                    $attr = New-Object T2HID+HIDD_ATTRIBUTES
                    $attr.Size = [Runtime.InteropServices.Marshal]::SizeOf([type]"T2HID+HIDD_ATTRIBUTES")
                    [void][T2HID]::HidD_GetAttributes($h, [ref]$attr)
                    $sb = New-Object System.Text.StringBuilder 256
                    $prod = ''
                    if ([T2HID]::HidD_GetProductString($h, $sb, 512)) { $prod = $sb.ToString() }
                    $result = @{
                        Path = $path; Product = $prod
                        VID = '0x{0:X4}' -f $attr.VendorID
                        PID = '0x{0:X4}' -f $attr.ProductID
                    }
                }
            }
            finally { [void][T2HID]::HidD_FreePreparsedData($pp) }
        }
    }
    finally { [void][T2HID]::CloseHandle($h) }
    $result
}

function Find-FidoHidDevices {
    $hidGuid = [Guid]::Empty
    [T2HID]::HidD_GetHidGuid([ref]$hidGuid)
    $devInfo = [T2HID]::SetupDiGetClassDevs([ref]$hidGuid, [IntPtr]::Zero, [IntPtr]::Zero, ($DIGCF_PRESENT -bor $DIGCF_DEVICEINTERFACE))
    if ($devInfo -eq $INVALID_HANDLE) { return @() }

    $found = @()
    $scanned = 0
    try {
        for ($i = 0; $i -lt 512; $i++) {
            $path = Get-HidInterfacePath $devInfo ([ref]$hidGuid) $i
            if ($null -eq $path) { break }
            $scanned++
            if ($path -eq '') { continue }
            $d = Test-FidoHidPath $path
            if ($d) { $found += $d }
        }
    }
    finally { [void][T2HID]::SetupDiDestroyDeviceInfoList($devInfo) }
    if ($script:Debug2) { Write-Log "HID scan: $scanned interfaces, $($found.Count) FIDO device(s)" 'debug' }
    # Plain output, not ,$found - see the note in Get-T2Devices. The caller
    # wraps in @(), which handles the 0-and-1 element cases correctly.
    $found
}

# Windows wants 65 bytes to send a 64-byte report: report ID 0 + payload.
function Write-HidReport([byte[]]$report64) {
    $buf = New-Object byte[] 65
    $buf[0] = 0
    [Array]::Copy($report64, 0, $buf, 1, 64)
    $written = 0
    if (-not [T2HID]::WriteFile($script:hid, $buf, 65, [ref]$written, [IntPtr]::Zero)) {
        $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "WriteFile failed: 0x$('{0:X}' -f $e) - $((New-Object ComponentModel.Win32Exception($e)).Message)"
    }
}
function Read-HidReport {
    $buf = New-Object byte[] 65
    $read = 0
    if (-not [T2HID]::ReadFile($script:hid, $buf, 65, [ref]$read, [IntPtr]::Zero)) {
        $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "ReadFile failed: 0x$('{0:X}' -f $e) - $((New-Object ComponentModel.Win32Exception($e)).Message)"
    }
    if ($read -lt 2) { throw "short read: $read bytes" }
    ,$buf[1..64]
}

function Initialize-CtapHid {
    $nonce = New-Object byte[] 8
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($nonce)

    $pkt = New-Object byte[] 64
    $pkt[0]=0xFF; $pkt[1]=0xFF; $pkt[2]=0xFF; $pkt[3]=0xFF   # broadcast CID
    $pkt[4] = $CTAPHID_INIT
    $pkt[5] = 0
    $pkt[6] = 8
    [Array]::Copy($nonce, 0, $pkt, 7, 8)
    Write-HidReport $pkt

    $r = Read-HidReport
    if ($r[4] -eq $CTAPHID_ERROR) { throw "CTAPHID_ERROR 0x$('{0:X2}' -f $r[7])" }
    if ($r[4] -ne $CTAPHID_INIT)  { throw "unexpected CMD 0x$('{0:X2}' -f $r[4])" }
    # We open with FILE_SHARE_READ|WRITE, so confirm the reply is ours.
    if (Compare-Object $nonce $r[7..14]) { throw "CTAPHID_INIT nonce mismatch" }
    if (-not ($r[23] -band 0x04)) { throw "device reports no CBOR capability over HID" }
    ,$r[15..18]
}

#   init packet: CID(4) | CMD|0x80 (1) | BCNTH | BCNTL | data[57]
#   cont packet: CID(4) | SEQ(1)       | data[59]
function Send-CtapHid([byte]$cmd, [byte[]]$payload) {
    $len = $payload.Length
    if ($len -gt 7609) { throw "payload too long: $len" }   # 57 + 128*59

    $pkt = New-Object byte[] 64
    [Array]::Copy($script:cid, 0, $pkt, 0, 4)
    $pkt[4] = $cmd -bor 0x80
    $pkt[5] = [byte](($len -shr 8) -band 0xFF)
    $pkt[6] = [byte]($len -band 0xFF)
    $first = [Math]::Min(57, $len)
    if ($first -gt 0) { [Array]::Copy($payload, 0, $pkt, 7, $first) }
    Write-HidReport $pkt

    $off = $first; $seq = 0
    while ($off -lt $len) {
        $c = New-Object byte[] 64
        [Array]::Copy($script:cid, 0, $c, 0, 4)
        $c[4] = [byte]$seq
        $n = [Math]::Min(59, $len - $off)
        [Array]::Copy($payload, $off, $c, 5, $n)
        Write-HidReport $c
        $off += $n; $seq++
        if ($seq -gt 127) { throw "sequence overflow" }
    }

    while ($true) {
        $r = Read-HidReport
        if ($r[4] -eq $CTAPHID_KEEPALIVE) {
            # status 2 = UP_NEEDED: the key wants a touch. This repeats about
            # twice a second for the whole wait, so it is routed through a hook:
            # the enroll dialog animates on it instead of logging a line per beat.
            if ($r[7] -eq 2) {
                if ($script:OnTouchNeeded) { & $script:OnTouchNeeded }
                else { Write-Log "touch the key..." 'warn' }
            }
            # A keepalive is the only moment the host regains control during a
            # touch wait - ReadFile is blocking, so cancel cannot be seen inside
            # the enroll loop while it waits here. Send CTAPHID_CANCEL on this
            # channel: the key aborts the pending command and replies with
            # KEEPALIVE_CANCEL (0x2D), which unwinds the enroll call cleanly.
            if ($script:bioCancel -and -not $script:bioCancelSent) {
                $script:bioCancelSent = $true
                $cx = New-Object byte[] 64
                [Array]::Copy($script:cid, 0, $cx, 0, 4)
                $cx[4] = $CTAPHID_CANCEL -bor 0x80
                $cx[5] = 0; $cx[6] = 0
                try { Write-HidReport $cx } catch { }
            }
            continue
        }
        if ($r[4] -eq $CTAPHID_ERROR) { throw "CTAPHID_ERROR 0x$('{0:X2}' -f $r[7])" }

        $rlen = ([int]$r[5] -shl 8) -bor [int]$r[6]
        $data = New-Object byte[] $rlen
        $take = [Math]::Min(57, $rlen)
        if ($take -gt 0) { [Array]::Copy($r, 7, $data, 0, $take) }
        $got = $take
        while ($got -lt $rlen) {
            $c = Read-HidReport
            $n = [Math]::Min(59, $rlen - $got)
            [Array]::Copy($c, 5, $data, $got, $n)
            $got += $n
        }
        return ,$data
    }
}

function Connect-Hid($dev) {
    if ([string]::IsNullOrEmpty($dev.HidPath)) { throw "HID device has no path" }
    $h = [T2HID]::CreateFile($dev.HidPath, $ACCESS_RW, $SHARE_RW, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
    if ($h -eq $INVALID_HANDLE) {
        $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($e -eq 5) { throw "HID open denied (0x5) - run elevated" }
        throw "HID CreateFile failed: 0x$('{0:X}' -f $e) on $($dev.HidPath)"
    }
    $script:hid = $h
    $script:cid = Initialize-CtapHid
}
function Disconnect-Hid {
    if ($script:hid -ne [IntPtr]::Zero) { [void][T2HID]::CloseHandle($script:hid); $script:hid = [IntPtr]::Zero }
}

# ========================= CBOR decode =========================
function Read-Cbor {
    param([byte[]]$b, [ref]$i)

    if ($i.Value -ge $b.Count) { return $null }
    $ib = $b[$i.Value]; $i.Value++
    $major = $ib -shr 5
    $ai = $ib -band 0x1F

    # Cast every byte wider before shifting: PowerShell's -shl on a [byte]
    # wraps within byte width, so 0x01 -shl 8 is 0, not 256. That silently
    # truncated every 2-byte uint to its low byte (288 came back as 32).
    $val = 0
    if ($ai -lt 24) { $val = [int]$ai }
    elseif ($ai -eq 24) { $val = [int]$b[$i.Value]; $i.Value++ }
    elseif ($ai -eq 25) {
        $val = ([int]$b[$i.Value] -shl 8) -bor [int]$b[$i.Value+1]
        $i.Value += 2
    }
    elseif ($ai -eq 26) {
        $val = ([uint32]$b[$i.Value] -shl 24) -bor ([uint32]$b[$i.Value+1] -shl 16) -bor ([uint32]$b[$i.Value+2] -shl 8) -bor [uint32]$b[$i.Value+3]
        $i.Value += 4
    }
    elseif ($ai -eq 27) {
        $v = [uint64]0
        for ($k=0; $k -lt 8; $k++) { $v = ($v -shl 8) -bor [uint64]$b[$i.Value+$k] }
        $val = $v; $i.Value += 8
    }

    switch ($major) {
        0 { return $val }
        1 { return (-1 - $val) }
        2 { $out = if ($val -gt 0) { $b[$i.Value..($i.Value+$val-1)] } else { @() }; $i.Value += $val; return ,$out }
        3 { $s = if ($val -gt 0) { [Text.Encoding]::UTF8.GetString($b[$i.Value..($i.Value+$val-1)]) } else { '' }; $i.Value += $val; return $s }
        4 { $arr = @(); for ($k=0; $k -lt $val; $k++) { $arr += ,(Read-Cbor $b $i) }; return ,$arr }
        5 {
            $m = [ordered]@{}
            for ($k=0; $k -lt $val; $k++) {
                $key = Read-Cbor $b $i
                $m[[string]$key] = Read-Cbor $b $i
            }
            return $m
        }
        7 {
            if ($ai -eq 20) { return $false }
            if ($ai -eq 21) { return $true }
            if ($ai -eq 22) { return $null }
            return $val
        }
    }
    return $null
}

# ========================= CBOR encode =========================
function Write-CborUint([uint64]$v, [int]$major) {
    $mb = $major -shl 5
    if ($v -lt 24)         { return ,([byte[]]@([byte]($mb -bor $v))) }
    if ($v -le 0xFF)       { return ,([byte[]]@([byte]($mb -bor 24), [byte]$v)) }
    if ($v -le 0xFFFF)     { return ,([byte[]]@([byte]($mb -bor 25), [byte]($v -shr 8), [byte]($v -band 0xFF))) }
    if ($v -le 0xFFFFFFFF) { return ,([byte[]]@([byte]($mb -bor 26), [byte]($v -shr 24), [byte](($v -shr 16) -band 0xFF), [byte](($v -shr 8) -band 0xFF), [byte]($v -band 0xFF))) }
    throw "uint too large"
}
function Write-CborInt([int64]$v)    { if ($v -ge 0) { Write-CborUint ([uint64]$v) 0 } else { Write-CborUint ([uint64](-1 - $v)) 1 } }
function Write-CborBytes([byte[]]$b) { ,([byte[]]((Write-CborUint ([uint64]$b.Count) 2) + $b)) }
function Write-CborText([string]$s)  { $u=[Text.Encoding]::UTF8.GetBytes($s); ,([byte[]]((Write-CborUint ([uint64]$u.Count) 3) + $u)) }

# Values are pre-encoded byte[]. GetEnumerator() avoids the OrderedDictionary
# indexer, which treats an int subscript as a *position*, not a key.
function Write-CborIntMap($m) {
    $out = [byte[]](Write-CborUint ([uint64]$m.Count) 5)
    foreach ($entry in $m.GetEnumerator()) {
        $out += [byte[]](Write-CborInt ([int64]$entry.Key))
        $out += [byte[]]$entry.Value
    }
    ,$out
}

# Platform COSE_Key (EC2 / P-256 / ECDH-ES+HKDF-256).
function Write-CoseKey([byte[]]$x, [byte[]]$y) {
    $b  = [byte[]](Write-CborUint 5 5)
    $b += [byte[]](Write-CborInt 1);  $b += [byte[]](Write-CborInt 2)
    $b += [byte[]](Write-CborInt 3);  $b += [byte[]](Write-CborInt -25)
    $b += [byte[]](Write-CborInt -1); $b += [byte[]](Write-CborInt 1)
    $b += [byte[]](Write-CborInt -2); $b += [byte[]](Write-CborBytes $x)
    $b += [byte[]](Write-CborInt -3); $b += [byte[]](Write-CborBytes $y)
    ,$b
}

# ====================== Crypto (PIN protocol v1) ======================
function New-EcdhClientKey {
    $ecdh = New-Object System.Security.Cryptography.ECDiffieHellmanCng 256
    $ecdh.KeyDerivationFunction = [System.Security.Cryptography.ECDiffieHellmanKeyDerivationFunction]::Hash
    $ecdh.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256
    $ecdh
}
function Get-EcdhPublicXY($ecdh) {
    $blob = $ecdh.PublicKey.ToByteArray()   # magic(4) cbKey(4) X(32) Y(32)
    @{ X = [byte[]]$blob[8..39]; Y = [byte[]]$blob[40..71] }
}
function Import-EcdhPeer([byte[]]$x, [byte[]]$y) {
    $blob = New-Object byte[] 72
    # BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345 ("ECK1" little-endian)
    [BitConverter]::GetBytes([uint32]0x314B4345).CopyTo($blob,0)
    [BitConverter]::GetBytes([uint32]32).CopyTo($blob,4)
    $x.CopyTo($blob,8); $y.CopyTo($blob,40)
    [System.Security.Cryptography.CngKey]::Import($blob, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
}
function Get-SharedSecretV1($ecdh, [byte[]]$peerX, [byte[]]$peerY) {
    $peer = Import-EcdhPeer $peerX $peerY
    try { ,$ecdh.DeriveKeyMaterial($peer) } finally { $peer.Dispose() }
}
function Invoke-AesCbcEncrypt([byte[]]$key, [byte[]]$data) {
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = 'CBC'; $aes.Padding = 'None'; $aes.KeySize = 256
    $aes.Key = $key; $aes.IV = New-Object byte[] 16      # v1: zero IV
    $enc = $aes.CreateEncryptor()
    $out = $enc.TransformFinalBlock($data, 0, $data.Length)
    $enc.Dispose(); $aes.Dispose()
    ,$out
}
function Invoke-AesCbcDecrypt([byte[]]$key, [byte[]]$data) {
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = 'CBC'; $aes.Padding = 'None'; $aes.KeySize = 256
    $aes.Key = $key; $aes.IV = New-Object byte[] 16
    $dec = $aes.CreateDecryptor()
    $out = $dec.TransformFinalBlock($data, 0, $data.Length)
    $dec.Dispose(); $aes.Dispose()
    ,$out
}
function Get-HmacSha256([byte[]]$key, [byte[]]$data) {
    $h = New-Object System.Security.Cryptography.HMACSHA256
    $h.Key = $key
    $r = $h.ComputeHash($data)
    $h.Dispose()
    ,$r
}
function Get-Sha256([byte[]]$data) {
    $s = [System.Security.Cryptography.SHA256]::Create()
    $r = $s.ComputeHash($data)
    $s.Dispose()
    ,$r
}

# ==================== CTAP dispatch ====================
function Get-CtapErrorText([byte]$code) {
    switch ($code) {
        0x11 { 'CBOR_UNEXPECTED_TYPE - the key rejected the request shape' }
        0x12 { 'INVALID_CBOR / INVALID_LENGTH - on enumerateRPs this usually just means no credentials are stored' }
        0x14 { 'INVALID_OPTION' }
        0x27 { 'USER_ACTION_TIMEOUT - no touch registered' }
        0x2E { 'NO_CREDENTIALS - none stored' }
        0x30 { 'NOT_ALLOWED - rejected in this state (reset needs a fresh power-up)' }
        0x31 { 'PIN_INVALID - wrong PIN (a retry was consumed)' }
        0x32 { 'PIN_BLOCKED - too many wrong PINs; power-cycle the key' }
        0x33 { 'PIN_AUTH_INVALID - pinUvAuthParam rejected (wrong token or missing permission)' }
        0x34 { 'PIN_POLICY_VIOLATION - PIN does not meet the key policy' }
        0x35 { 'PIN_TOKEN_EXPIRED - fetch a fresh token' }
        0x36 { 'PIN_NOT_SET - no PIN on this key' }
        0x37 { 'PIN_REQUIRED - this command needs a PIN' }
        0x3F { 'UV_BLOCKED - user verification locked out' }
        default { 'see CTAP2 spec section 1.7' }
    }
}

function Send-Ctap([byte]$cmd, [byte[]]$cborPayload) {
    $d = $null
    if ($script:mode -eq 'hid') {
        $d = Send-CtapHid $CTAPHID_CBOR ([byte[]](,$cmd + $cborPayload))
    }
    else {
        # The FIDO applet must be current. Read-Serial and Read-Config switch
        # applets behind our back, so re-SELECT before every CTAP command. The
        # SW is ignored on purpose: some PIN+ firmware answers 6A81 yet still
        # switches, which is what the reference client relies on.
        [void](Send-Apdu $script:selFido)

        $body = [byte[]](,$cmd + $cborPayload)
        if ($body.Count -gt 255) { throw "payload $($body.Count) bytes exceeds short Lc" }
        $apdu = [byte[]](0x80,0x10,0x00,0x00) + [byte]$body.Count + $body + [byte]0x00
        $r = Send-Apdu $apdu
        if (-not $r) { throw "transmit failed" }
        if ($r.SW1 -ne 0x90 -or $r.SW2 -ne 0x00) {
            if ($r.SW1 -eq 0x6D -or ($r.SW1 -eq 0x69 -and $r.SW2 -eq 0x85)) {
                throw ("SW={0:X2}{1:X2}: this interface does not carry CTAP2 (USB-CCID is serial/config only - use -Transport hid or an NFC reader)" -f $r.SW1,$r.SW2)
            }
            throw ("APDU failed: SW={0:X2}{1:X2}" -f $r.SW1, $r.SW2)
        }
        $d = $r.Data
    }

    if ($d.Count -lt 1) { throw "empty CTAP response" }
    if ($d[0] -ne 0x00) {
        # 0x2D = CTAP2_ERR_KEEPALIVE_CANCEL: the expected reply after we send
        # CTAPHID_CANCEL. Tag it so the enroll loop treats it as a clean cancel
        # rather than a failure.
        if ($d[0] -eq 0x2D) { throw "CTAP_CANCELLED" }
        throw ("CTAP error 0x{0:X2}: {1}" -f $d[0], (Get-CtapErrorText $d[0]))
    }
    if ($script:Debug2) {
        Write-Log ("resp: " + (($d[0..([Math]::Min(31,$d.Count-1))] | ForEach-Object {'{0:X2}' -f $_}) -join ' ') + " ...") 'debug'
    }
    if ($d.Count -eq 1) { return $null }
    $idx = 1
    Read-Cbor ([byte[]]$d) ([ref]$idx)
}

# ================== Vendor reads (CCID only) ==================
function Read-Serial {
    [void](Send-Apdu $script:selFido)
    $r = Send-Apdu $script:vendorInfo
    if (-not $r -or $r.SW1 -ne 0x90 -or $r.SW2 -ne 0x00) { return $null }
    $d = $r.Data
    if ($d.Count -lt 2 -or $d[0] -ne 0xD1) { return $null }
    $snLen = $d[1]
    if ($d.Count -lt 2 + $snLen) { return $null }
    $ascii = [Text.Encoding]::ASCII.GetString($d[2..(1+$snLen)])
    if ($ascii.Length % 2 -ne 0) { return $null }
    # The serial is double-encoded: ASCII-hex chars that decode to bytes.
    $bytes = for ($i=0; $i -lt $ascii.Length; $i+=2) { [Convert]::ToByte($ascii.Substring($i,2),16) }
    ($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ''
}

function Read-Config {
    # READ_CONFIG lives on the OTP applet, not FIDO.
    [void](Send-Apdu $script:selOtp)
    $r = Send-Apdu $script:readCfg
    if (-not $r -or $r.SW1 -ne 0x90 -or $r.SW2 -ne 0x00) { return $null }
    $cfg = $r.Data
    if ($cfg.Count -lt 1) { return $null }

    $b0 = $cfg[0]
    $hasCfg = $cfg.Count -ge 2
    $b1 = if ($hasCfg) { $cfg[1] } else { 0 }
    $hasExt = $cfg.Count -ge 10
    $b9 = if ($hasExt) { $cfg[9] } else { 0 }
    $unk = '(unknown)'

    [pscustomobject]@{
        RawLen                = $cfg.Count
        Raw                   = ($cfg | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
        FidoDisabled          = [bool]($b0 -band 0x01)
        HotpKeystrokeDisabled = [bool]($b0 -band 0x02)
        CcidDisabled          = [bool]($b0 -band 0x04)
        FidoPinSet            = if ($hasCfg) { [bool]($b1 -band 0x02) } else { $unk }
        HotpSupported         = if ($hasCfg) { [bool]($b1 -band 0x04) } else { $unk }
        FingerprintPresent    = if ($hasCfg) { [bool]($b1 -band 0x08) } else { $unk }
        NfcSupported          = if ($hasCfg) { [bool]($b1 -band 0x10) } else { $unk }
        HotpLongPress         = if ($hasCfg) { [bool]($b1 -band 0x20) } else { $unk }
        PinLocked             = if ($hasCfg) { [bool]($b1 -band 0x40) } else { $unk }
        ButtonHotpConfigured  = if ($hasCfg) { [bool]($b1 -band 0x80) } else { $unk }
        TotpSupported         = if ($hasExt) { [bool]($b9 -band 0x01) } else { $unk }
        Fido21Supported       = if ($hasExt) { [bool]($b9 -band 0x02) } else { $unk }
        CcidSupported         = if ($hasExt) { [bool]($b9 -band 0x10) } else { $unk }
        ButtonHotpSupported   = if ($hasExt) { [bool](($b9 -band 0x20) -eq 0) } else { $unk }
    }
}

# ==================== CTAP2 commands ====================
function Read-FidoInfo {
    $map = Send-Ctap $CTAP_GET_INFO @()
    if (-not $map) { return $null }
    $opts   = $map['4']
    $aaguid = $map['3']
    [pscustomobject]@{
        Versions        = ($map['1'] -join ', ')
        Extensions      = ($map['2'] -join ', ')
        Aaguid          = if ($aaguid) { ($aaguid | ForEach-Object { '{0:x2}' -f $_ }) -join '' } else { $null }
        Transports      = ($map['9'] -join ', ')
        PinProtocols    = ($map['6'] -join ', ')
        MaxMsgSize      = $map['5']
        MaxCredIdLength = $map['8']
        FirmwareVersion = $map['14']
        ClientPin       = if ($opts) { $opts['clientPin'] } else { $null }
        Uv              = if ($opts) { $opts['uv'] } else { $null }
        BioEnroll       = if ($opts) { $opts['bioEnroll'] } else { $null }
        CredMgmt        = if ($opts) { $opts['credMgmt'] } else { $null }
        CredentialMgmtPreview = if ($opts) { $opts['credentialMgmtPreview'] } else { $null }
        Rk              = if ($opts) { $opts['rk'] } else { $null }
        AlwaysUv        = if ($opts) { $opts['alwaysUv'] } else { $null }
        Options         = if ($opts) { ($opts.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ' } else { $null }
    }
}

function Get-PinRetryCount {
    $m = [ordered]@{}
    $m.Add(1, (Write-CborInt 1))       # pinUvAuthProtocol = 1
    $m.Add(2, (Write-CborInt 0x01))    # getPinRetries
    $resp = Send-Ctap $CTAP_CLIENT_PIN (Write-CborIntMap $m)
    if ($resp) { $resp['3'] } else { $null }
}

function Get-KeyAgreement($ecdh) {
    $m = [ordered]@{}
    $m.Add(1, (Write-CborInt 1))
    $m.Add(2, (Write-CborInt 0x02))    # getKeyAgreement
    $resp = Send-Ctap $CTAP_CLIENT_PIN (Write-CborIntMap $m)
    if (-not $resp) { throw "no keyAgreement in response" }
    $cose = $resp['1']
    if (-not $cose) { throw "keyAgreement missing" }
    @{ X = [byte[]]$cose['-2']; Y = [byte[]]$cose['-3'] }   # COSE EC2: -2=x, -3=y
}

function Set-Fido2Pin {
    param([string]$NewPin, [switch]$WhatIfMode)

    $pinBytes = [Text.Encoding]::UTF8.GetBytes($NewPin)
    if ($pinBytes.Count -lt 4 -or $pinBytes.Count -gt 63) { throw "PIN must be 4-63 bytes" }

    $ecdh = New-EcdhClientKey
    try {
        $peer   = Get-KeyAgreement $ecdh
        $shared = Get-SharedSecretV1 $ecdh $peer.X $peer.Y
        $pub    = Get-EcdhPublicXY $ecdh

        # newPinEnc = AES-CBC(shared, newPin zero-padded to 64)
        $padded = New-Object byte[] 64
        $pinBytes.CopyTo($padded, 0)
        $newPinEnc = Invoke-AesCbcEncrypt $shared $padded
        # pinUvAuthParam = HMAC-SHA256(shared, newPinEnc)[0..15]
        $auth = (Get-HmacSha256 $shared $newPinEnc)[0..15]

        $m = [ordered]@{}
        $m.Add(1, (Write-CborInt 1))
        $m.Add(2, (Write-CborInt 0x03))                  # setPIN
        $m.Add(3, (Write-CoseKey $pub.X $pub.Y))
        $m.Add(4, (Write-CborBytes ([byte[]]$auth)))
        $m.Add(5, (Write-CborBytes $newPinEnc))
        $payload = Write-CborIntMap $m

        if ($WhatIfMode) { return "DRY RUN, not sent. CBOR ($($payload.Count) bytes): " + (($payload | ForEach-Object {'{0:X2}' -f $_}) -join ' ') }
        [void](Send-Ctap $CTAP_CLIENT_PIN $payload)
        'PIN set.'
    } finally { $ecdh.Dispose() }
}

function Set-Fido2PinChange {
    param([string]$OldPinVal, [string]$NewPin, [switch]$WhatIfMode)

    $newBytes = [Text.Encoding]::UTF8.GetBytes($NewPin)
    if ($newBytes.Count -lt 4 -or $newBytes.Count -gt 63) { throw "new PIN must be 4-63 bytes" }

    $ecdh = New-EcdhClientKey
    try {
        $peer   = Get-KeyAgreement $ecdh
        $shared = Get-SharedSecretV1 $ecdh $peer.X $peer.Y
        $pub    = Get-EcdhPublicXY $ecdh

        $padded = New-Object byte[] 64
        $newBytes.CopyTo($padded, 0)
        $newPinEnc = Invoke-AesCbcEncrypt $shared $padded
        # pinHashEnc = AES-CBC(shared, SHA-256(oldPin)[0..15])
        $oldHash    = (Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($OldPinVal)))[0..15]
        $pinHashEnc = Invoke-AesCbcEncrypt $shared ([byte[]]$oldHash)
        # pinUvAuthParam = HMAC(shared, newPinEnc || pinHashEnc)[0..15]
        $auth = (Get-HmacSha256 $shared ([byte[]]($newPinEnc + $pinHashEnc)))[0..15]

        $m = [ordered]@{}
        $m.Add(1, (Write-CborInt 1))
        $m.Add(2, (Write-CborInt 0x04))                  # changePIN
        $m.Add(3, (Write-CoseKey $pub.X $pub.Y))
        $m.Add(4, (Write-CborBytes ([byte[]]$auth)))
        $m.Add(5, (Write-CborBytes $newPinEnc))
        $m.Add(6, (Write-CborBytes $pinHashEnc))
        $payload = Write-CborIntMap $m

        if ($WhatIfMode) { return "DRY RUN, not sent. CBOR ($($payload.Count) bytes): " + (($payload | ForEach-Object {'{0:X2}' -f $_}) -join ' ') }
        [void](Send-Ctap $CTAP_CLIENT_PIN $payload)
        "PIN changed. Retries now: $(Get-PinRetryCount)"
    } finally { $ecdh.Dispose() }
}

# getPinUvAuthTokenUsingPinWithPermissions (0x09).
# A legacy 0x05 token carries only implicit mc/ga permissions, so credMgmt
# rejects it with 0x33. Requesting the cm bit via 0x09 is what fixes it.
function Get-PinToken {
    param([string]$PinVal, [int]$Permissions = 0x04, [string]$RpId)

    $ecdh = New-EcdhClientKey
    try {
        $peer   = Get-KeyAgreement $ecdh
        $shared = Get-SharedSecretV1 $ecdh $peer.X $peer.Y
        $pub    = Get-EcdhPublicXY $ecdh

        $pinHash    = (Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($PinVal)))[0..15]
        $pinHashEnc = Invoke-AesCbcEncrypt $shared ([byte[]]$pinHash)

        $m = [ordered]@{}
        $m.Add(1, (Write-CborInt 1))                     # pinUvAuthProtocol
        $m.Add(2, (Write-CborInt 0x09))                  # subCommand
        $m.Add(3, (Write-CoseKey $pub.X $pub.Y))         # keyAgreement
        $m.Add(6, (Write-CborBytes $pinHashEnc))         # pinHashEnc
        $m.Add(9, (Write-CborInt $Permissions))          # permissions
        if ($RpId) { $m.Add(10, (Write-CborText $RpId)) }

        $resp = Send-Ctap $CTAP_CLIENT_PIN (Write-CborIntMap $m)
        if (-not $resp) { throw "no pinUvAuthToken in response" }
        $encToken = [byte[]]$resp['2']
        if (-not $encToken) { throw "pinUvAuthToken missing from response" }

        $token = Invoke-AesCbcDecrypt $shared $encToken
        if ($token.Count -ne 16 -and $token.Count -ne 32) {
            throw "pinUvAuthToken decrypted to $($token.Count) bytes (spec allows 16 or 32) - bad shared secret"
        }
        ,$token
    } finally { $ecdh.Dispose() }
}

# CTAP 2.0 compatibility: getPinToken (0x05) is valid only with
# credentialManagementPreview (0x41). It MUST NOT be used with final credMgmt.
function Get-LegacyPinToken {
    param([string]$PinVal)

    $ecdh = New-EcdhClientKey
    try {
        $peer   = Get-KeyAgreement $ecdh
        $shared = Get-SharedSecretV1 $ecdh $peer.X $peer.Y
        $pub    = Get-EcdhPublicXY $ecdh
        $pinHash    = (Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($PinVal)))[0..15]
        $pinHashEnc = Invoke-AesCbcEncrypt $shared ([byte[]]$pinHash)

        $m = [ordered]@{}
        $m.Add(1, (Write-CborInt 1))                     # pinUvAuthProtocol
        $m.Add(2, (Write-CborInt 0x05))                  # getPinToken
        $m.Add(3, (Write-CoseKey $pub.X $pub.Y))         # keyAgreement
        $m.Add(6, (Write-CborBytes $pinHashEnc))         # pinHashEnc

        $resp = Send-Ctap $CTAP_CLIENT_PIN (Write-CborIntMap $m)
        if (-not $resp) { throw "no legacy pinToken in response" }
        $encToken = [byte[]]$resp['2']
        if (-not $encToken) { throw "legacy pinToken missing from response" }

        $token = Invoke-AesCbcDecrypt $shared $encToken
        if ($token.Count -ne 16 -and $token.Count -ne 32) {
            throw "legacy pinToken decrypted to $($token.Count) bytes (spec allows 16 or 32) - bad shared secret"
        }
        ,$token
    } finally { $ecdh.Dispose() }
}

function Get-CredMgmtToken {
    param([string]$PinVal, $FidoInfo)

    if (-not $FidoInfo) { throw "cannot read getInfo" }
    if ($FidoInfo.CredMgmt -eq $true) {
        try {
            $script:credMgmtCmd = $CTAP_CRED_MGMT
            return Get-PinToken -PinVal $PinVal -Permissions $PERM_CRED_MGMT
        }
        catch {
            # 0x01 means the command was rejected before PIN validation. Do not
            # fall back on PIN_INVALID or any other PIN/authentication error.
            if ($_.Exception.Message -notmatch 'CTAP error 0x01' -or $FidoInfo.CredentialMgmtPreview -ne $true) { throw }
            Write-Log "getPinUvAuthTokenUsingPinWithPermissions unsupported; using credentialManagementPreview compatibility path." 'warn'
        }
    }
    if ($FidoInfo.CredentialMgmtPreview -ne $true) {
        throw "this key does not advertise a usable credential-management API"
    }
    $script:credMgmtCmd = $CTAP_CRED_MGMT_PREVIEW
    Get-LegacyPinToken -PinVal $PinVal
}

# pinUvAuthParam = HMAC-SHA256(token, subCmdByte || cbor(params))[0..15]
function Send-CredMgmt([byte[]]$Token, [byte]$Sub, [byte[]]$ParamsCbor) {
    $authInput = [byte[]]@($Sub)
    if ($ParamsCbor) { $authInput += $ParamsCbor }
    $auth = (Get-HmacSha256 $Token $authInput)[0..15]

    $m = [ordered]@{}
    $m.Add(1, (Write-CborInt $Sub))
    if ($ParamsCbor) { $m.Add(2, $ParamsCbor) }
    $m.Add(3, (Write-CborInt 1))                       # pinUvAuthProtocol
    $m.Add(4, (Write-CborBytes ([byte[]]$auth)))
    Send-Ctap $script:credMgmtCmd (Write-CborIntMap $m)
}

function Get-CredsMetadata([byte[]]$Token) {
    try { $r = Send-CredMgmt $Token 0x01 $null }
    catch {
        if ($_.Exception.Message -match '0x2E|0x12') { return [pscustomobject]@{ Existing = 0; MaxRemaining = $null } }
        throw
    }
    if (-not $r) { return $null }
    [pscustomobject]@{ Existing = $r['1']; MaxRemaining = $r['2'] }
}

function Get-ResidentCredentials([byte[]]$Token) {
    $out = @()
    try { $rp = Send-CredMgmt $Token 0x02 $null }      # enumerateRPsBegin
    catch {
        # An empty key is not an error. 0x2E is the documented NO_CREDENTIALS;
        # some firmware answers 0x12 (INVALID_LENGTH) instead when there is
        # nothing to enumerate. Both mean "none stored".
        if ($_.Exception.Message -match '0x2E|0x12') { return @() }
        throw
    }
    if (-not $rp) { return @() }

    $totalRPs = [int]$rp['5']
    if ($totalRPs -gt 4096) { throw "implausible RP count $totalRPs" }

    $rps = @()
    $rps += ,@{ RP = $rp['3']; Hash = [byte[]]$rp['4'] }
    for ($i = 1; $i -lt $totalRPs; $i++) {
        $n = Send-CredMgmt $Token 0x03 $null           # enumerateRPsNext
        if (-not $n) { break }
        $rps += ,@{ RP = $n['3']; Hash = [byte[]]$n['4'] }
    }

    foreach ($entry in $rps) {
        $rpId = if ($entry.RP) { $entry.RP['id'] } else { '(unknown)' }
        # subCommandParams = { 1: <rpIdHash> }
        $params = [byte[]](Write-CborUint 1 5) + [byte[]](Write-CborInt 1) + [byte[]](Write-CborBytes $entry.Hash)

        try { $c = Send-CredMgmt $Token 0x04 $params } # enumerateCredsBegin
        catch {
            if ($_.Exception.Message -match '0x2E|0x12') { continue }
            throw
        }
        if (-not $c) { continue }

        $totalCreds = [int]$c['9']
        if ($totalCreds -gt 4096) { throw "implausible credential count" }

        $emit = {
            param($m)
            $user = $m['6']
            $cid  = $m['7']
            [pscustomobject]@{
                RP           = $rpId
                UserName     = if ($user) { $user['name'] } else { $null }
                DisplayName  = if ($user) { $user['displayName'] } else { $null }
                UserId       = if ($user -and $user['id']) { (([byte[]]$user['id']) | ForEach-Object {'{0:x2}' -f $_}) -join '' } else { $null }
                CredentialId = if ($cid -and $cid['id']) { (([byte[]]$cid['id']) | ForEach-Object {'{0:x2}' -f $_}) -join '' } else { $null }
            }
        }
        $out += & $emit $c
        for ($j = 1; $j -lt $totalCreds; $j++) {
            $n = Send-CredMgmt $Token 0x05 $null       # enumerateCredsNext
            if (-not $n) { break }
            $out += & $emit $n
        }
    }
    # Plain output, not ,$out - see Get-BioEnrollments. The GUI caller wraps in
    # @(), so a comma here nests the list and the grid renders System.Object[].
    $out
}

function Remove-ResidentCredential([byte[]]$Token, [string]$CredIdHex) {
    $hex = $CredIdHex -replace '[^0-9A-Fa-f]',''
    if ($hex.Length % 2 -ne 0) { throw "credentialId hex length is odd" }
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2,2),16) }

    # subCommandParams = { 2: { "id": <bytes>, "type": "public-key" } }
    $inner  = [byte[]](Write-CborUint 2 5)
    $inner += [byte[]](Write-CborText 'id')   + [byte[]](Write-CborBytes $bytes)
    $inner += [byte[]](Write-CborText 'type') + [byte[]](Write-CborText 'public-key')
    $params = [byte[]](Write-CborUint 1 5) + [byte[]](Write-CborInt 2) + $inner

    [void](Send-CredMgmt $Token 0x06 $params)
    'Credential deleted.'
}

# ==================== authenticatorConfig (0x0D) ====================
# The pinUvAuthParam target here is NOT the credMgmt one. Per CTAP 6.11 it is:
#     0xff * 32 || 0x0d || subCommand || cbor(subCommandParams)
# credMgmt signs subCommand || cbor(params) with no prefix. Using the wrong
# shape returns 0x33 and looks exactly like a bad token.
function Send-AuthnrConfig([byte[]]$Token, [byte]$Sub, [byte[]]$ParamsCbor) {
    $authInput = New-Object byte[] 32
    for ($i=0; $i -lt 32; $i++) { $authInput[$i] = 0xFF }
    $authInput += [byte]$CTAP_CONFIG
    $authInput += [byte]$Sub
    if ($ParamsCbor) { $authInput += $ParamsCbor }
    $auth = (Get-HmacSha256 $Token $authInput)[0..15]

    $m = [ordered]@{}
    $m.Add(1, (Write-CborInt $Sub))
    if ($ParamsCbor) { $m.Add(2, $ParamsCbor) }
    $m.Add(3, (Write-CborInt 1))                       # pinUvAuthProtocol
    $m.Add(4, (Write-CborBytes ([byte[]]$auth)))
    # Config sub-commands return no data on success.
    [void](Send-Ctap $CTAP_CONFIG (Write-CborIntMap $m))
}

# Sub-command 0x02 TOGGLES alwaysUv - it is not a setter. Read the current
# state from getInfo and only fire when it differs from the target.
function Set-AlwaysUv([byte[]]$Token, [bool]$Enable) {
    $fi = Read-FidoInfo
    if (-not $fi) { throw "cannot read getInfo" }
    if ($fi.AlwaysUv -eq $null) { throw "this authenticator does not report alwaysUv" }
    if ([bool]$fi.AlwaysUv -eq $Enable) {
        return "alwaysUv is already $(if($Enable){'on'}else{'off'}) - nothing to do."
    }
    Send-AuthnrConfig $Token 0x02 $null
    $after = (Read-FidoInfo).AlwaysUv
    "alwaysUv is now $after"
}

# newMin can only ever be raised; the key rejects a lower value and a reset is
# the only way back down. forceChange is set implicitly by the key if the
# current PIN is shorter than newMin.
function Set-MinPinLength {
    param([byte[]]$Token, [int]$NewMin = 0, [string[]]$RpIds = @(), [switch]$ForceChange)

    $entries = [ordered]@{}
    if ($NewMin -gt 0)      { $entries.Add(1, (Write-CborInt $NewMin)) }
    if ($RpIds.Count -gt 0) {
        $arr = [byte[]](Write-CborUint ([uint64]$RpIds.Count) 4)
        foreach ($r in $RpIds) { $arr += [byte[]](Write-CborText $r) }
        $entries.Add(2, $arr)
    }
    if ($ForceChange)       { $entries.Add(3, [byte[]]@(0xF5)) }   # CBOR true
    if ($entries.Count -eq 0) { throw "nothing to set" }

    Send-AuthnrConfig $Token 0x03 (Write-CborIntMap $entries)
    $bits = @()
    if ($NewMin -gt 0)      { $bits += "minimum PIN length now $NewMin" }
    if ($RpIds.Count -gt 0) { $bits += "$($RpIds.Count) RP id(s) allowed to read it" }
    if ($ForceChange)       { $bits += "a PIN change is now forced on next use" }
    ($bits -join '; ') + '.'
}

function Set-ForcePinChange([byte[]]$Token) {
    Set-MinPinLength -Token $Token -ForceChange
}

# ============ authenticatorBioEnrollment (0x09, preview 0x40) ============
# A THIRD pinUvAuthParam shape. Per CTAP 2.1 6.7 the auth input is:
#     modality (0x01) || subCommand || cbor(subCommandParams)
# credMgmt signs subCommand || cbor(params); authenticatorConfig prefixes
# 0xff*32 || 0x0d. The leading modality byte is the bio-specific difference.
# Token needs the be (bioEnroll) permission = 0x08.
function Send-BioEnroll([byte[]]$Token, [byte]$Sub, [byte[]]$ParamsCbor, [byte]$Cmd = 0x09) {
    $authInput = [byte[]]@([byte]$BIO_MODALITY_FINGERPRINT, $Sub)
    if ($ParamsCbor) { $authInput += $ParamsCbor }
    $auth = (Get-HmacSha256 $Token $authInput)[0..15]

    $m = [ordered]@{}
    $m.Add(1, (Write-CborInt $BIO_MODALITY_FINGERPRINT))
    $m.Add(2, (Write-CborInt $Sub))
    if ($ParamsCbor) { $m.Add(3, $ParamsCbor) }
    $m.Add(4, (Write-CborInt 1))                       # pinUvAuthProtocol
    $m.Add(5, (Write-CborBytes ([byte[]]$auth)))
    Send-Ctap $Cmd (Write-CborIntMap $m)
}

# Which command byte does this key speak? Prefer the standard 0x09.
function Get-BioCmdByte($fi) {
    if ($fi.Options -match 'bioEnroll=') { return $CTAP_BIO }
    if ($fi.Options -match 'userVerificationMgmtPreview=True') { return $CTAP_BIO_PREVIEW }
    $CTAP_BIO
}

function Get-BioSensorInfo([byte[]]$Token, [byte]$Cmd = 0x09) {
    $r = Send-BioEnroll $Token 0x07 $null $Cmd
    if (-not $r) { return $null }
    [pscustomobject]@{
        FingerprintKind    = $r['2']     # 1 = touch, 2 = swipe
        MaxCaptureSamples  = $r['3']
        MaxFriendlyNameLen = $r['8']
    }
}

function Get-BioEnrollments([byte[]]$Token, [byte]$Cmd = 0x09) {
    try { $r = Send-BioEnroll $Token 0x04 $null $Cmd }
    catch {
        # CTAP 2.1 6.7.6: with nothing enrolled the key answers
        # INVALID_OPTION (0x2C) rather than an empty list.
        if ($_.Exception.Message -match '0x2C') { return @() }
        throw
    }
    if (-not $r) { return @() }
    $arr = $r['7']
    if (-not $arr) { return @() }

    $out = @()
    foreach ($ti in $arr) {
        if (-not $ti) { continue }
        $id = [byte[]]$ti['1']
        $out += [pscustomobject]@{
            TemplateId   = if ($id) { ($id | ForEach-Object {'{0:x2}' -f $_}) -join '' } else { $null }
            FriendlyName = $ti['2']
        }
    }
    # Plain output, not ,$out: callers wrap in @(), and @() around a
    # comma-wrapped array yields @( @(...) ) - a 1-element array holding the
    # real one, which grids then render as System.Object[] per column.
    $out
}

function Get-BioSampleStatusText([int]$status) {
    switch ($status) {
        0x00 { 'good sample captured' }
        0x01 { 'sample too high or partial - try again' }
        0x02 { 'sample too low or partial - try again' }
        0x03 { 'sample partial - center your finger on the sensor' }
        0x04 { 'too many samples failed - enrollment may need restarting' }
        0x05 { 'low quality - clean the sensor and your finger, then retry' }
        0x06 { 'too close to a previous sample - adjust finger position' }
        0x07 { 'sensor timeout - touch the sensor' }
        default { 'retry the sample' }
    }
}

function Start-BioEnroll([byte[]]$Token, [int]$TimeoutMs = 0, [byte]$Cmd = 0x09) {
    $params = $null
    if ($TimeoutMs -gt 0) {
        $p = [ordered]@{}
        $p.Add(3, (Write-CborInt $TimeoutMs))
        $params = Write-CborIntMap $p
    }
    $r = Send-BioEnroll $Token 0x01 $params $Cmd
    if (-not $r) { throw "enrollBegin returned nothing" }
    $id = [byte[]]$r['4']
    if (-not $id) { throw "enrollBegin gave no template id" }
    [pscustomobject]@{
        TemplateId       = ($id | ForEach-Object {'{0:x2}' -f $_}) -join ''
        TemplateIdBytes  = $id
        LastSampleStatus = [int]$r['5']
        RemainingSamples = [int]$r['6']
    }
}

function Step-BioEnroll([byte[]]$Token, [byte[]]$TemplateId, [int]$TimeoutMs = 0, [byte]$Cmd = 0x09) {
    if (-not $TemplateId -or $TemplateId.Count -eq 0) {
        throw "enrollCaptureNext called without a template id"
    }
    $p = [ordered]@{}
    $p.Add(1, (Write-CborBytes $TemplateId))
    if ($TimeoutMs -gt 0) { $p.Add(3, (Write-CborInt $TimeoutMs)) }
    $r = Send-BioEnroll $Token 0x02 (Write-CborIntMap $p) $Cmd
    if (-not $r) { throw "enrollCaptureNext returned nothing" }
    # Carry the template id through. Callers loop with "$st = Step-BioEnroll
    # $tok $st.TemplateIdBytes", so omitting it here makes the id null from the
    # second iteration on - the key then gets enrollCaptureNext with no
    # templateId and answers 0x12 INVALID_LENGTH. The key does not resend the
    # id (it is only in enrollBegin's reply), so it must be threaded through.
    [pscustomobject]@{
        TemplateId       = ($TemplateId | ForEach-Object {'{0:x2}' -f $_}) -join ''
        TemplateIdBytes  = $TemplateId
        LastSampleStatus = [int]$r['5']
        RemainingSamples = [int]$r['6']
    }
}

function Stop-BioEnroll([byte[]]$Token, [byte]$Cmd = 0x09) {
    [void](Send-BioEnroll $Token 0x03 $null $Cmd)
    'Enrollment cancelled.'
}

function Rename-BioEnrollment([byte[]]$Token, [string]$TemplateIdHex, [string]$Name, [byte]$Cmd = 0x09) {
    $hex = $TemplateIdHex -replace '[^0-9A-Fa-f]',''
    if ($hex.Length % 2 -ne 0) { throw "template id hex length is odd" }
    $id = New-Object byte[] ($hex.Length / 2)
    for ($i=0; $i -lt $id.Length; $i++) { $id[$i] = [Convert]::ToByte($hex.Substring($i*2,2),16) }

    $p = [ordered]@{}
    $p.Add(1, (Write-CborBytes $id))
    $p.Add(2, (Write-CborText $Name))
    [void](Send-BioEnroll $Token 0x05 (Write-CborIntMap $p) $Cmd)
    "Renamed to '$Name'."
}

function Remove-BioEnrollment([byte[]]$Token, [string]$TemplateIdHex, [byte]$Cmd = 0x09) {
    $hex = $TemplateIdHex -replace '[^0-9A-Fa-f]',''
    if ($hex.Length % 2 -ne 0) { throw "template id hex length is odd" }
    $id = New-Object byte[] ($hex.Length / 2)
    for ($i=0; $i -lt $id.Length; $i++) { $id[$i] = [Convert]::ToByte($hex.Substring($i*2,2),16) }

    $p = [ordered]@{}
    $p.Add(1, (Write-CborBytes $id))
    [void](Send-BioEnroll $Token 0x06 (Write-CborIntMap $p) $Cmd)
    'Fingerprint removed.'
}

function Invoke-FactoryReset {
    [void](Send-Ctap $CTAP_RESET @())
    'Key reset. All credentials and the PIN are gone.'
}

# ==================== Device discovery ====================
function Get-T2Devices {
    $devs = @()

    foreach ($r in @(Get-PcscReaders)) {
        $sn = $null
        if (Connect-CcidReader $r) {
            try { $sn = Read-Serial } catch { }
            Disconnect-Ccid
        }
        $devs += [pscustomobject]@{
            Kind    = 'ccid'
            Name    = $r
            Serial  = $sn
            HidPath = $null
            # A USB-CCID interface answers the vendor commands but not CTAP; an
            # NFC reader answers both. They cannot be told apart by name, so
            # CTAP capability is discovered on first use, not assumed.
            Display = "CCID  $r" + $(if ($sn) { "  [$sn]" } else { '' })
        }
    }

    # @() guards the 0-and-1 element cases: a single hashtable must not be
    # mistaken for a scalar, and an empty result must iterate zero times.
    foreach ($d in @(Find-FidoHidDevices)) {
        $devs += [pscustomobject]@{
            Kind    = 'hid'
            Name    = $d.Product
            Serial  = $null
            HidPath = $d.Path
            Display = "HID   $($d.Product)  VID=$($d.VID) PID=$($d.PID)"
        }
    }
    # Emit the elements, not the array. A unary-comma return (,$devs) hands the
    # caller ONE object - the array itself - and @(Get-T2Devices) then collects
    # that single object into @( @(ccid,hid) ): Count=1, holding the real array.
    # foreach then binds $d to the whole array, and "$d.Kind -eq 'hid'" on an
    # array is a FILTER returning a non-empty (truthy) array, so both branches
    # match and the same nested array is added twice - exactly the observed
    # "pool: 2 element(s), both COUNT=2, both identical".
    # Both callers already wrap in @(), which correctly handles the 0-and-1
    # element cases, so plain output is what they need.
    $devs
}

function Open-T2Device($dev) {
    Close-T2Device
    if ($dev.Kind -eq 'hid') {
        Connect-Hid $dev
        $script:mode = 'hid'
    } else {
        if (-not (Connect-CcidReader $dev.Name)) { throw "cannot connect to $($dev.Name)" }
        $script:mode = 'ccid'
    }
}
function Close-T2Device {
    Disconnect-Hid
    Disconnect-Ccid
    $script:mode = $null
}

# ============================ GUI ============================
function Show-Gui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $elevated = Test-Elevated

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'T2 PS FIDO2 Manager'
    $form.Size = New-Object System.Drawing.Size(920, 660)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    # --- theme ------------------------------------------------------------
    # A small, quiet palette applied after all controls exist (see the walk
    # near ShowDialog). Flat surfaces, one accent, restrained greys - the
    # goal is "current Windows app", not a skin.
    $Theme = @{
        Bg      = [System.Drawing.Color]::FromArgb(247,248,250)  # window
        Card    = [System.Drawing.Color]::White                  # panels/grids
        Ink     = [System.Drawing.Color]::FromArgb(32,36,42)      # primary text
        Muted   = [System.Drawing.Color]::FromArgb(110,116,124)   # secondary text
        Line    = [System.Drawing.Color]::FromArgb(224,227,231)   # borders
        Accent  = [System.Drawing.Color]::FromArgb(24,119,242)    # primary action
        AccentHi= [System.Drawing.Color]::FromArgb(64,146,247)    # accent hover
        Danger  = [System.Drawing.Color]::FromArgb(210,54,54)     # destructive
        Subtle  = [System.Drawing.Color]::FromArgb(238,240,243)   # secondary btn
    }
    $form.BackColor = $Theme.Bg
    $form.ForeColor = $Theme.Ink

    # Style a button as primary (filled accent), secondary (subtle), or danger.
    $StyleButton = {
        param($b, $kind = 'secondary')
        $b.FlatStyle = 'Flat'
        $b.FlatAppearance.BorderSize = 0
        $b.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $b.Cursor = 'Hand'
        $b.Height = [Math]::Max($b.Height, 28)
        switch ($kind) {
            'primary' {
                $b.BackColor = $Theme.Accent; $b.ForeColor = [System.Drawing.Color]::White
                $b.FlatAppearance.MouseOverBackColor = $Theme.AccentHi
            }
            'danger' {
                $b.BackColor = $Theme.Danger; $b.ForeColor = [System.Drawing.Color]::White
                $b.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(224,80,80)
            }
            default {
                $b.BackColor = $Theme.Subtle; $b.ForeColor = $Theme.Ink
                $b.FlatAppearance.BorderColor = $Theme.Line
                $b.FlatAppearance.BorderSize = 1
                $b.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(228,231,235)
            }
        }
    }

    # Recolour a DataGridView to match the flat theme.
    $StyleGrid = {
        param($g)
        $g.EnableHeadersVisualStyles = $false
        $g.BackgroundColor = $Theme.Card
        $g.BorderStyle = 'None'
        $g.GridColor = $Theme.Line
        $g.ColumnHeadersDefaultCellStyle.BackColor = $Theme.Card
        $g.ColumnHeadersDefaultCellStyle.ForeColor = $Theme.Muted
        $g.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
        $g.ColumnHeadersBorderStyle = 'Single'
        $g.RowHeadersVisible = $false
        $g.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(219,234,254)
        $g.DefaultCellStyle.SelectionForeColor = $Theme.Ink
        $g.DefaultCellStyle.BackColor = $Theme.Card
        $g.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248,249,251)
    }


    # Window / taskbar icon: a "T2" monogram badge in the Token2 style, drawn to
    # a bitmap at runtime and converted to an HICON - no .ico file to ship. This
    # is an original monogram, not a reproduction of the Token2 logo artwork.
    $makeIcon = {
        $bmp = New-Object System.Drawing.Bitmap 32, 32
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAlias
        $g.Clear([System.Drawing.Color]::Transparent)

        # Rounded-square badge in the Token2 green.
        $brand = [System.Drawing.Color]::FromArgb(0,158,110)
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $r = 7; $x = 1; $y = 1; $w = 30; $h = 30
        $path.AddArc($x, $y, $r, $r, 180, 90)
        $path.AddArc(($x+$w-$r), $y, $r, $r, 270, 90)
        $path.AddArc(($x+$w-$r), ($y+$h-$r), $r, $r, 0, 90)
        $path.AddArc($x, ($y+$h-$r), $r, $r, 90, 90)
        $path.CloseFigure()
        $bg = New-Object System.Drawing.SolidBrush $brand
        $g.FillPath($bg, $path)

        # "T2" wordmark-ish monogram, white, tight.
        $fnt = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
        $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
        $rect = New-Object System.Drawing.RectangleF 0, 0, 32, 32
        $g.DrawString('T2', $fnt, $white, $rect, $sf)

        $bg.Dispose(); $white.Dispose(); $fnt.Dispose(); $sf.Dispose(); $path.Dispose(); $g.Dispose()
        $hicon = $bmp.GetHicon()
        [System.Drawing.Icon]::FromHandle($hicon)
    }
    try { $form.Icon = & $makeIcon } catch { }

    # --- elevation banner ---
    $banner = New-Object System.Windows.Forms.Label
    $banner.Dock = 'Top'
    $banner.Height = 36
    $banner.TextAlign = 'MiddleLeft'
    $banner.Padding = New-Object System.Windows.Forms.Padding(8,0,0,0)
    if ($elevated) {
        $banner.Text = 'Running elevated - all features available.'
        $banner.BackColor = [System.Drawing.Color]::FromArgb(223, 240, 216)
        $banner.ForeColor = [System.Drawing.Color]::FromArgb(60, 118, 61)
    } else {
        $banner.Text = 'NOT elevated - only the serial number will work. Close this and re-run PowerShell as Administrator for everything else.'
        $banner.BackColor = [System.Drawing.Color]::FromArgb(252, 248, 227)
        $banner.ForeColor = [System.Drawing.Color]::FromArgb(138, 109, 59)
    }

    # --- device picker ---
    $top = New-Object System.Windows.Forms.Panel
    $top.Dock = 'Top'; $top.Height = 40

    $lblDev = New-Object System.Windows.Forms.Label
    $lblDev.Text = 'Device:'
    $lblDev.Location = New-Object System.Drawing.Point(8,12)
    $lblDev.AutoSize = $true

    $cboDev = New-Object System.Windows.Forms.ComboBox
    $cboDev.Location = New-Object System.Drawing.Point(60,8)
    $cboDev.Size = New-Object System.Drawing.Size(600,24)
    $cboDev.DropDownStyle = 'DropDownList'

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = 'Refresh'
    $btnRefresh.Location = New-Object System.Drawing.Point(670,7)
    $btnRefresh.Size = New-Object System.Drawing.Size(80,25)

    $top.Controls.AddRange(@($lblDev, $cboDev, $btnRefresh))

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'

    # --- Info tab (loads automatically on device selection) ---
    $tabInfo = New-Object System.Windows.Forms.TabPage
    $tabInfo.Text = 'Info'
    $gridInfo = New-Object System.Windows.Forms.DataGridView
    $gridInfo.Dock = 'Fill'
    $gridInfo.ReadOnly = $true
    $gridInfo.AllowUserToAddRows = $false
    $gridInfo.RowHeadersVisible = $false
    $gridInfo.AutoSizeColumnsMode = 'Fill'
    $gridInfo.BorderStyle = 'None'
    $gridInfo.BackgroundColor = [System.Drawing.Color]::White
    $gridInfo.ColumnCount = 2
    $gridInfo.Columns[0].Name = 'Property'
    $gridInfo.Columns[1].Name = 'Value'
    $gridInfo.Columns[0].FillWeight = 32
    $gridInfo.Columns[0].DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)

    $infoHead = New-Object System.Windows.Forms.Panel
    $infoHead.Dock = 'Top'; $infoHead.Height = 52
    $infoHead.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)
    $lblSummary = New-Object System.Windows.Forms.Label
    $lblSummary.Location = New-Object System.Drawing.Point(10,8)
    $lblSummary.Size = New-Object System.Drawing.Size(700,20)
    $lblSummary.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $lblSummary.Text = 'No device selected'
    $lblSummary2 = New-Object System.Windows.Forms.Label
    $lblSummary2.Location = New-Object System.Drawing.Point(10,29)
    $lblSummary2.Size = New-Object System.Drawing.Size(820,18)
    $lblSummary2.ForeColor = [System.Drawing.Color]::FromArgb(110,110,110)
    $lblSummary2.Text = ''
    $infoHead.Controls.AddRange(@($lblSummary,$lblSummary2))

    $tabInfo.Controls.AddRange(@($gridInfo, $infoHead))

    # --- Credentials tab ---
    $tabCreds = New-Object System.Windows.Forms.TabPage
    $tabCreds.Text = 'Credentials'
    $gridCreds = New-Object System.Windows.Forms.DataGridView
    $gridCreds.Dock = 'Fill'
    $gridCreds.ReadOnly = $true
    $gridCreds.AllowUserToAddRows = $false
    $gridCreds.RowHeadersVisible = $false
    $gridCreds.SelectionMode = 'FullRowSelect'
    $gridCreds.MultiSelect = $false
    $gridCreds.AutoSizeColumnsMode = 'Fill'
    $gridCreds.ColumnCount = 5
    $gridCreds.Columns[0].Name = 'RP'
    $gridCreds.Columns[1].Name = 'UserName'
    $gridCreds.Columns[2].Name = 'DisplayName'
    $gridCreds.Columns[3].Name = 'UserId'
    $gridCreds.Columns[4].Name = 'CredentialId'
    $gridCreds.Columns[3].Visible = $false
    $gridCreds.Columns[4].Visible = $false
    $gridCreds.BorderStyle = 'None'
    $gridCreds.BackgroundColor = [System.Drawing.Color]::White
    $gridCreds.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248,248,248)

    $lblCredsEmpty = New-Object System.Windows.Forms.Label
    $lblCredsEmpty.Text = "No credentials loaded.`r`nClick 'List credentials' - you will be asked for the PIN."
    $lblCredsEmpty.TextAlign = 'MiddleCenter'
    $lblCredsEmpty.Dock = 'Fill'
    $lblCredsEmpty.ForeColor = [System.Drawing.Color]::FromArgb(140,140,140)
    $lblCredsEmpty.BackColor = [System.Drawing.Color]::White

    $credBar = New-Object System.Windows.Forms.Panel
    $credBar.Dock = 'Top'; $credBar.Height = 34
    $btnCreds = New-Object System.Windows.Forms.Button
    $btnCreds.Text = 'List credentials'
    $btnCreds.Location = New-Object System.Drawing.Point(4,4)
    $btnCreds.Size = New-Object System.Drawing.Size(110,26)
    $btnDelete = New-Object System.Windows.Forms.Button
    $btnDelete.Text = 'Delete selected'
    $btnDelete.Location = New-Object System.Drawing.Point(120,4)
    $btnDelete.Size = New-Object System.Drawing.Size(110,26)
    $btnDelete.Enabled = $false
    $lblMeta = New-Object System.Windows.Forms.Label
    $lblMeta.Location = New-Object System.Drawing.Point(244,9)
    $lblMeta.AutoSize = $true
    $credBar.Controls.AddRange(@($btnCreds, $btnDelete, $lblMeta))
    $tabCreds.Controls.AddRange(@($lblCredsEmpty, $gridCreds, $credBar))
    $gridCreds.Visible = $false

    # --- PIN tab ---
    $tabPin = New-Object System.Windows.Forms.TabPage
    $tabPin.Text = 'PIN'
    $lblPinState = New-Object System.Windows.Forms.Label
    $lblPinState.Location = New-Object System.Drawing.Point(12,12)
    $lblPinState.Size = New-Object System.Drawing.Size(640,20)
    $lblPinState.Text = 'Select a device and click Check.'
    $btnPinCheck = New-Object System.Windows.Forms.Button
    $btnPinCheck.Text = 'Check'
    $btnPinCheck.Location = New-Object System.Drawing.Point(12,38)
    $btnPinCheck.Size = New-Object System.Drawing.Size(90,26)
    $lblOld = New-Object System.Windows.Forms.Label
    $lblOld.Text = 'Current PIN:'
    $lblOld.Location = New-Object System.Drawing.Point(12,84)
    $lblOld.AutoSize = $true
    $txtOld = New-Object System.Windows.Forms.TextBox
    $txtOld.Location = New-Object System.Drawing.Point(120,81)
    $txtOld.Size = New-Object System.Drawing.Size(220,24)
    $txtOld.UseSystemPasswordChar = $true
    $lblNew = New-Object System.Windows.Forms.Label
    $lblNew.Text = 'New PIN:'
    $lblNew.Location = New-Object System.Drawing.Point(12,116)
    $lblNew.AutoSize = $true
    $txtNew = New-Object System.Windows.Forms.TextBox
    $txtNew.Location = New-Object System.Drawing.Point(120,113)
    $txtNew.Size = New-Object System.Drawing.Size(220,24)
    $txtNew.UseSystemPasswordChar = $true
    $lblNew2 = New-Object System.Windows.Forms.Label
    $lblNew2.Text = 'Confirm:'
    $lblNew2.Location = New-Object System.Drawing.Point(12,148)
    $lblNew2.AutoSize = $true
    $txtNew2 = New-Object System.Windows.Forms.TextBox
    $txtNew2.Location = New-Object System.Drawing.Point(120,145)
    $txtNew2.Size = New-Object System.Drawing.Size(220,24)
    $txtNew2.UseSystemPasswordChar = $true
    $chkDry = New-Object System.Windows.Forms.CheckBox
    $chkDry.Text = 'Dry run (build the CBOR, send nothing)'
    $chkDry.Location = New-Object System.Drawing.Point(120,176)
    $chkDry.AutoSize = $true
    $btnPinApply = New-Object System.Windows.Forms.Button
    $btnPinApply.Text = 'Apply'
    $btnPinApply.Location = New-Object System.Drawing.Point(120,204)
    $btnPinApply.Size = New-Object System.Drawing.Size(100,28)
    $tabPin.Controls.AddRange(@($lblPinState,$btnPinCheck,$lblOld,$txtOld,$lblNew,$txtNew,$lblNew2,$txtNew2,$chkDry,$btnPinApply))

    # --- Reset tab ---
    $tabDanger = New-Object System.Windows.Forms.TabPage
    $tabDanger.Text = 'Reset'
    $lblDanger = New-Object System.Windows.Forms.Label
    $lblDanger.Location = New-Object System.Drawing.Point(12,12)
    $lblDanger.Size = New-Object System.Drawing.Size(840,90)
    $lblDanger.Text = "Factory reset wipes EVERY passkey and the PIN. This cannot be undone.`r`n`r`nThe key only accepts a reset within about 10 seconds of powering up: unplug and replug it (or lift it off the NFC pad and put it back), then click Factory reset immediately."
    $btnReset = New-Object System.Windows.Forms.Button
    $btnReset.Text = 'Factory reset'
    $btnReset.Location = New-Object System.Drawing.Point(12,110)
    $btnReset.Size = New-Object System.Drawing.Size(120,30)
    $btnReset.ForeColor = [System.Drawing.Color]::DarkRed
    $tabDanger.Controls.AddRange(@($lblDanger,$btnReset))

    # --- Policy tab (authenticatorConfig 0x0D) ---
    $tabPolicy = New-Object System.Windows.Forms.TabPage
    $tabPolicy.Text = 'Policy'

    $lblPolState = New-Object System.Windows.Forms.Label
    $lblPolState.Location = New-Object System.Drawing.Point(12,12)
    $lblPolState.Size = New-Object System.Drawing.Size(700,20)
    $lblPolState.Text = 'Select a device - policy state loads with the Info tab.'
    $lblPolState.ForeColor = [System.Drawing.Color]::FromArgb(110,110,110)

    $grpUv = New-Object System.Windows.Forms.GroupBox
    $grpUv.Text = 'Always require user verification'
    $grpUv.Location = New-Object System.Drawing.Point(12,40)
    $grpUv.Size = New-Object System.Drawing.Size(840,86)
    $lblUv = New-Object System.Windows.Forms.Label
    $lblUv.Location = New-Object System.Drawing.Point(12,20)
    $lblUv.Size = New-Object System.Drawing.Size(810,32)
    $lblUv.Text = "Every assertion needs a PIN or fingerprint, even for services that did not ask for it.`r`nWhether this survives a factory reset is vendor-specific."
    $lblUv.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)
    # One button: sub-command 0x02 is a toggle, not a setter. The label
    # reflects what pressing it will do, driven by the alwaysUv state read
    # in $loadInfo.
    $btnUvToggle = New-Object System.Windows.Forms.Button
    $btnUvToggle.Text = 'Toggle'
    $btnUvToggle.Location = New-Object System.Drawing.Point(12,54)
    $btnUvToggle.Size = New-Object System.Drawing.Size(110,25)
    $lblUvNow = New-Object System.Windows.Forms.Label
    $lblUvNow.Location = New-Object System.Drawing.Point(132,59)
    $lblUvNow.AutoSize = $true
    $grpUv.Controls.AddRange(@($lblUv,$btnUvToggle,$lblUvNow))

    $grpMin = New-Object System.Windows.Forms.GroupBox
    $grpMin.Text = 'Minimum PIN length'
    $grpMin.Location = New-Object System.Drawing.Point(12,134)
    $grpMin.Size = New-Object System.Drawing.Size(840,104)
    $lblMin = New-Object System.Windows.Forms.Label
    $lblMin.Location = New-Object System.Drawing.Point(12,20)
    $lblMin.Size = New-Object System.Drawing.Size(810,32)
    $lblMin.Text = "Raise the shortest PIN the key will accept. This can only go UP - lowering it again needs a factory reset.`r`nIf the current PIN is shorter than the new minimum, the key forces a PIN change by itself."
    $lblMin.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)
    $numMin = New-Object System.Windows.Forms.NumericUpDown
    $numMin.Location = New-Object System.Drawing.Point(12,58)
    $numMin.Size = New-Object System.Drawing.Size(60,24)
    $numMin.Minimum = 4; $numMin.Maximum = 63; $numMin.Value = 6
    $chkMinForce = New-Object System.Windows.Forms.CheckBox
    $chkMinForce.Text = 'also force a PIN change now'
    $chkMinForce.Location = New-Object System.Drawing.Point(82,60)
    $chkMinForce.AutoSize = $true
    $btnMinApply = New-Object System.Windows.Forms.Button
    $btnMinApply.Text = 'Apply'
    $btnMinApply.Location = New-Object System.Drawing.Point(280,57)
    $btnMinApply.Size = New-Object System.Drawing.Size(90,25)
    $grpMin.Controls.AddRange(@($lblMin,$numMin,$chkMinForce,$btnMinApply))

    $grpForce = New-Object System.Windows.Forms.GroupBox
    $grpForce.Text = 'Force a PIN change on next use'
    $grpForce.Location = New-Object System.Drawing.Point(12,246)
    $grpForce.Size = New-Object System.Drawing.Size(840,86)
    $lblForce = New-Object System.Windows.Forms.Label
    $lblForce.Location = New-Object System.Drawing.Point(12,20)
    $lblForce.Size = New-Object System.Drawing.Size(810,32)
    $lblForce.Text = "The next platform interaction must set a new PIN. Useful before handing the key to someone else.`r`nThe minimum length is left unchanged."
    $lblForce.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)
    $btnForce = New-Object System.Windows.Forms.Button
    $btnForce.Text = 'Force PIN change'
    $btnForce.Location = New-Object System.Drawing.Point(12,54)
    $btnForce.Size = New-Object System.Drawing.Size(130,25)
    $grpForce.Controls.AddRange(@($lblForce,$btnForce))

    $tabPolicy.Controls.AddRange(@($lblPolState,$grpUv,$grpMin,$grpForce))

    # --- Fingerprints tab (authenticatorBioEnrollment 0x09) ---
    $tabBio = New-Object System.Windows.Forms.TabPage
    $tabBio.Text = 'Fingerprints'

    $gridBio = New-Object System.Windows.Forms.DataGridView
    $gridBio.Dock = 'Fill'
    $gridBio.ReadOnly = $true
    $gridBio.AllowUserToAddRows = $false
    $gridBio.RowHeadersVisible = $false
    $gridBio.SelectionMode = 'FullRowSelect'
    $gridBio.MultiSelect = $false
    $gridBio.AutoSizeColumnsMode = 'Fill'
    $gridBio.BorderStyle = 'None'
    $gridBio.BackgroundColor = [System.Drawing.Color]::White
    $gridBio.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248,248,248)
    $gridBio.ColumnCount = 2
    $gridBio.Columns[0].Name = 'FriendlyName'
    $gridBio.Columns[1].Name = 'TemplateId'
    $gridBio.Columns[0].FillWeight = 40
    $gridBio.Visible = $false

    $lblBioEmpty = New-Object System.Windows.Forms.Label
    $lblBioEmpty.Text = "No fingerprints loaded.`r`nClick 'List' - you will be asked for the PIN."
    $lblBioEmpty.TextAlign = 'MiddleCenter'
    $lblBioEmpty.Dock = 'Fill'
    $lblBioEmpty.ForeColor = [System.Drawing.Color]::FromArgb(140,140,140)
    $lblBioEmpty.BackColor = [System.Drawing.Color]::White

    $bioBar = New-Object System.Windows.Forms.Panel
    $bioBar.Dock = 'Top'; $bioBar.Height = 34
    $btnBioList = New-Object System.Windows.Forms.Button
    $btnBioList.Text = 'List'
    $btnBioList.Location = New-Object System.Drawing.Point(4,4)
    $btnBioList.Size = New-Object System.Drawing.Size(70,26)
    $btnBioAdd = New-Object System.Windows.Forms.Button
    $btnBioAdd.Text = 'Enroll new'
    $btnBioAdd.Location = New-Object System.Drawing.Point(80,4)
    $btnBioAdd.Size = New-Object System.Drawing.Size(90,26)
    $btnBioRename = New-Object System.Windows.Forms.Button
    $btnBioRename.Text = 'Rename'
    $btnBioRename.Location = New-Object System.Drawing.Point(176,4)
    $btnBioRename.Size = New-Object System.Drawing.Size(80,26)
    $btnBioRename.Enabled = $false
    $btnBioDel = New-Object System.Windows.Forms.Button
    $btnBioDel.Text = 'Delete'
    $btnBioDel.Location = New-Object System.Drawing.Point(262,4)
    $btnBioDel.Size = New-Object System.Drawing.Size(80,26)
    $btnBioDel.Enabled = $false
    $lblBioInfo = New-Object System.Windows.Forms.Label
    $lblBioInfo.Location = New-Object System.Drawing.Point(352,9)
    $lblBioInfo.AutoSize = $true
    $lblBioInfo.ForeColor = [System.Drawing.Color]::FromArgb(110,110,110)
    $bioBar.Controls.AddRange(@($btnBioList,$btnBioAdd,$btnBioRename,$btnBioDel,$lblBioInfo))
    $tabBio.Controls.AddRange(@($lblBioEmpty, $gridBio, $bioBar))

    # --- About tab ---
    $tabAbout = New-Object System.Windows.Forms.TabPage
    $tabAbout.Text = 'About'

    # Large T2 badge, same monogram as the window icon.
    $aboutLogo = New-Object System.Windows.Forms.Panel
    $aboutLogo.Location = New-Object System.Drawing.Point(24,24)
    $aboutLogo.Size = New-Object System.Drawing.Size(72,72)
    $aboutLogo.BackColor = [System.Drawing.Color]::Transparent
    $aboutLogo.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAlias
        $brand = [System.Drawing.Color]::FromArgb(0,158,110)
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $r = 16; $x = 2; $y = 2; $w = 68; $h = 68
        $path.AddArc($x, $y, $r, $r, 180, 90)
        $path.AddArc(($x+$w-$r), $y, $r, $r, 270, 90)
        $path.AddArc(($x+$w-$r), ($y+$h-$r), $r, $r, 0, 90)
        $path.AddArc($x, ($y+$h-$r), $r, $r, 90, 90)
        $path.CloseFigure()
        $bg = New-Object System.Drawing.SolidBrush $brand
        $g.FillPath($bg, $path)
        $fnt = New-Object System.Drawing.Font('Segoe UI', 34, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
        $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
        $g.DrawString('T2', $fnt, $white, (New-Object System.Drawing.RectangleF 0,0,72,72), $sf)
        $bg.Dispose(); $white.Dispose(); $fnt.Dispose(); $sf.Dispose(); $path.Dispose()
    })

    $aboutTitle = New-Object System.Windows.Forms.Label
    $aboutTitle.Text = 'T2 PS FIDO2 Manager'
    $aboutTitle.Font = New-Object System.Drawing.Font('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
    $aboutTitle.Location = New-Object System.Drawing.Point(112,30)
    $aboutTitle.AutoSize = $true

    $aboutSub = New-Object System.Windows.Forms.Label
    $aboutSub.Text = 'Pure PowerShell, relying only on standard Windows DLLs - nothing else to install.'
    $aboutSub.Location = New-Object System.Drawing.Point(114,64)
    $aboutSub.Size = New-Object System.Drawing.Size(560,20)
    $aboutSub.ForeColor = [System.Drawing.Color]::FromArgb(110,116,124)

    $aboutGhLbl = New-Object System.Windows.Forms.Label
    $aboutGhLbl.Text = 'Project:'
    $aboutGhLbl.Location = New-Object System.Drawing.Point(24,124)
    $aboutGhLbl.AutoSize = $true

    # Project repository.
    $script:projectUrl = 'https://github.com/token2/t2-ps-fido2-manager'
    $aboutGh = New-Object System.Windows.Forms.LinkLabel
    $aboutGh.Text = $script:projectUrl
    $aboutGh.Location = New-Object System.Drawing.Point(80,124)
    $aboutGh.AutoSize = $true
    $aboutGh.LinkColor = [System.Drawing.Color]::FromArgb(24,119,242)
    $aboutGh.Add_LinkClicked({
        try { Start-Process $script:projectUrl } catch { Write-Log "could not open browser: $($_.Exception.Message)" 'warn' }
    })

    $aboutSiteLbl = New-Object System.Windows.Forms.Label
    $aboutSiteLbl.Text = 'Website:'
    $aboutSiteLbl.Location = New-Object System.Drawing.Point(24,150)
    $aboutSiteLbl.AutoSize = $true
    $aboutSite = New-Object System.Windows.Forms.LinkLabel
    $aboutSite.Text = 'https://www.token2.com'
    $aboutSite.Location = New-Object System.Drawing.Point(80,150)
    $aboutSite.AutoSize = $true
    $aboutSite.LinkColor = [System.Drawing.Color]::FromArgb(24,119,242)
    $aboutSite.Add_LinkClicked({
        try { Start-Process 'https://www.token2.com' } catch { Write-Log "could not open browser: $($_.Exception.Message)" 'warn' }
    })

    $aboutCopyright = New-Object System.Windows.Forms.Label
    $aboutCopyright.Text = ([char]0x00A9) + " $((Get-Date).Year) Token2 Sarl. All rights reserved."
    $aboutCopyright.Location = New-Object System.Drawing.Point(24,196)
    $aboutCopyright.Size = New-Object System.Drawing.Size(500,18)
    $aboutCopyright.ForeColor = [System.Drawing.Color]::FromArgb(110,116,124)

    $aboutNote = New-Object System.Windows.Forms.Label
    $aboutNote.Text = 'Provided as-is, without warranty.'
    $aboutNote.Location = New-Object System.Drawing.Point(24,218)
    $aboutNote.Size = New-Object System.Drawing.Size(560,18)
    $aboutNote.ForeColor = [System.Drawing.Color]::FromArgb(150,155,160)

    $tabAbout.Controls.AddRange(@($aboutLogo,$aboutTitle,$aboutSub,$aboutGhLbl,$aboutGh,$aboutSiteLbl,$aboutSite,$aboutCopyright,$aboutNote))

    $tabs.TabPages.AddRange(@($tabInfo,$tabCreds,$tabPin,$tabBio,$tabPolicy,$tabDanger,$tabAbout))

    # --- log ---
    $log = New-Object System.Windows.Forms.TextBox
    $log.Dock = 'Bottom'
    $log.Height = 130
    $log.Multiline = $true
    $log.ScrollBars = 'Vertical'
    $log.ReadOnly = $true
    $log.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $log.ForeColor = [System.Drawing.Color]::FromArgb(220,220,220)
    $log.Font = New-Object System.Drawing.Font('Consolas', 8.5)

    $script:Log = {
        param($msg, $level)
        $ts = (Get-Date).ToString('HH:mm:ss')
        $tag = switch ($level) { 'error' {'ERR '} 'warn' {'WARN'} 'debug' {'dbg '} default {'    '} }
        $log.AppendText("[$ts] $tag $msg`r`n")
    }

    $status = New-Object System.Windows.Forms.Label
    $status.Dock = 'Bottom'
    $status.Height = 22
    $status.TextAlign = 'MiddleLeft'
    $status.Padding = New-Object System.Windows.Forms.Padding(8,0,0,0)
    $status.BackColor = [System.Drawing.Color]::FromArgb(240,240,240)
    $status.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)
    $status.Text = 'Ready'

    $form.Controls.AddRange(@($tabs, $top, $banner, $log, $status))

    # --- helpers ---
    $script:guiDevices = @()
    # Remembered PIN: in-memory, this window only. Deliberately never written to
    # disk - a FIDO2 PIN on disk is a worse risk than retyping it, and the key
    # itself is what the PIN protects. Cleared on Refresh and on rejection.
    $script:pinCache = $null
    $script:allDevices = @()    # includes CCID rows hidden from the dropdown
    $script:ccidDevice = $null  # serial/config source, listed or not

    $refresh = {
        $cboDev.Items.Clear()
        # A remembered PIN belongs to the key that was plugged in. Refresh may
        # mean a different key, so drop it.
        if ($script:pinCache) { $script:pinCache = $null; Write-Log 'remembered PIN cleared (rescan)' }
        $status.Text = 'Scanning...'
        $form.Cursor = 'WaitCursor'
        [System.Windows.Forms.Application]::DoEvents()
        try {
            $script:allDevices = @(Get-T2Devices)

            # A Token2 key on USB exposes BOTH a HID interface (CTAP2) and a
            # USB-CCID interface (serial/config only, answers 6985 to CTAP).
            # Listing both is noise: the CCID row cannot do anything the HID row
            # cannot, except serial/config, which we read from it silently.
            # A real NFC reader has no HID twin, so it stays listed.
            $hasHid = @($script:allDevices | Where-Object { $_.Kind -eq 'hid' }).Count -gt 0
            if ($hasHid) {
                $script:guiDevices = @($script:allDevices | Where-Object { $_.Kind -ne 'ccid' })
                $hidden = $script:allDevices.Count - $script:guiDevices.Count
                if ($hidden -gt 0) { Write-Log "hiding $hidden USB-CCID interface(s) - HID carries CTAP2" }
            } else {
                $script:guiDevices = $script:allDevices
            }

            # Serial/config come from the CCID interface even when it is hidden.
            $script:ccidDevice = @($script:allDevices | Where-Object { $_.Kind -eq 'ccid' }) | Select-Object -First 1

            foreach ($d in $script:guiDevices) { [void]$cboDev.Items.Add($d.Display) }
            Write-Log "found $($script:allDevices.Count) device(s)"
            $status.Text = "$($script:guiDevices.Count) device(s)"
            if ($cboDev.Items.Count -gt 0) {
                # Setting the index fires SelectedIndexChanged, which loads Info.
                $cboDev.SelectedIndex = 0
            } else {
                $lblSummary.Text = 'No device found'
                $lblSummary2.Text = 'Plug in a key or place one on the NFC reader, then click Refresh.'
            }
        }
        catch { Write-Log $_.Exception.Message 'error'; $status.Text = 'Scan failed' }
        finally { $form.Cursor = 'Default' }
    }

    # Open the selected device, run $action, always close.
    $withDevice = {
        param($action, $what)
        if ($cboDev.SelectedIndex -lt 0) { Write-Log 'no device selected' 'warn'; return }
        $dev = $script:guiDevices[$cboDev.SelectedIndex]
        $form.Cursor = 'WaitCursor'
        $status.Text = if ($what) { "$what..." } else { 'Working...' }
        $status.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)
        [System.Windows.Forms.Application]::DoEvents()
        try {
            Open-T2Device $dev
            & $action $dev
            $status.Text = if ($what) { "$what - done" } else { 'Done' }
        }
        catch {
            # A remembered PIN that is wrong would silently spend a retry on
            # every action. Any PIN-related refusal drops it so the next action
            # prompts again. 0x31 = PIN_INVALID, 0x33 = PIN_AUTH_BLOCKED,
            # 0x34 = PIN_BLOCKED, 0x36 = PIN_AUTH_INVALID.
            if ($_.Exception.Message -match '0x31|0x33|0x34|0x36|PIN') {
                if ($script:pinCache) {
                    $script:pinCache = $null
                    Write-Log 'remembered PIN cleared - it was rejected' 'warn'
                }
            }
            Write-Log $_.Exception.Message 'error'
            $status.Text = $_.Exception.Message
            $status.ForeColor = [System.Drawing.Color]::FromArgb(180,40,40)
        }
        finally { Close-T2Device; $form.Cursor = 'Default' }
    }

    # Modeless progress window for enrollment. The key emits a KEEPALIVE
    # (UP_NEEDED) about twice a second for the whole touch wait; $OnTouchNeeded
    # turns that beat into a pulse here instead of a log line per beat.
    # Modeless progress window for enrollment. The key emits a KEEPALIVE
    # (UP_NEEDED) about twice a second for the whole touch wait; $OnTouchNeeded
    # turns that beat into a pulse here instead of a log line per beat.
    $newBioDialog = {
        param($total)
        $d = New-Object System.Windows.Forms.Form
        $d.Text = 'Enrolling fingerprint'
        $d.ClientSize = New-Object System.Drawing.Size(380,262)
        # CenterParent only applies to ShowDialog(); this dialog is modeless
        # (.Show) so the position must be set by hand against the owner bounds.
        $d.StartPosition = 'Manual'
        $d.FormBorderStyle = 'FixedDialog'
        $d.MinimizeBox = $false; $d.MaximizeBox = $false
        $d.ControlBox = $false
        $d.BackColor = [System.Drawing.Color]::White
        try { $d.Icon = $form.Icon } catch { }

        # --- animated fingerprint, drawn with GDI+ (no icon font dependency) ---
        $fp = New-Object System.Windows.Forms.Panel
        $fp.Location = New-Object System.Drawing.Point(20,20)
        $fp.Size = New-Object System.Drawing.Size(84,84)
        $fp.BackColor = [System.Drawing.Color]::Transparent
        $fp.Add_Paint({
            param($sender, $e)
            $g = $e.Graphics
            $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $cx = 42; $cy = 46
            # Ridges animate outward: the active ring is highlighted, the rest
            # sit muted, which reads as a pulse without needing an image.
            for ($i = 0; $i -lt 5; $i++) {
                $r = 8 + ($i * 7)
                $on = ($i -eq $script:bioBeat)
                $col = if ($script:bioIdle) {
                    [System.Drawing.Color]::FromArgb(205,205,205)
                } elseif ($on) {
                    [System.Drawing.Color]::FromArgb(30,120,200)
                } else {
                    [System.Drawing.Color]::FromArgb(170,200,225)
                }
                $w = if ($on -and -not $script:bioIdle) { 3.0 } else { 2.0 }
                $pen = New-Object System.Drawing.Pen $col, $w
                $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
                $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
                # Open arcs on alternating sides look like fingerprint ridges.
                if ($i % 2 -eq 0) { $g.DrawArc($pen, ($cx-$r), ($cy-$r), (2*$r), (2*$r), 200, 250) }
                else              { $g.DrawArc($pen, ($cx-$r), ($cy-$r), (2*$r), (2*$r), 160, 250) }
                $pen.Dispose()
            }
            # Core.
            $b = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(30,120,200))
            if ($script:bioIdle) { $b.Color = [System.Drawing.Color]::FromArgb(205,205,205) }
            $g.FillEllipse($b, ($cx-3), ($cy-3), 6, 6)
            $b.Dispose()
        })

        $big = New-Object System.Windows.Forms.Label
        $big.Text = 'Touch the sensor'
        $big.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
        $big.Location = New-Object System.Drawing.Point(118,24)
        $big.Size = New-Object System.Drawing.Size(245,28)

        $sub = New-Object System.Windows.Forms.Label
        $sub.Text = 'Lift your finger and touch again for each sample.'
        $sub.Location = New-Object System.Drawing.Point(118,54)
        $sub.Size = New-Object System.Drawing.Size(245,32)
        $sub.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)

        $bar = New-Object System.Windows.Forms.ProgressBar
        $bar.Location = New-Object System.Drawing.Point(20,124)
        $bar.Size = New-Object System.Drawing.Size(340,18)
        $bar.Minimum = 0
        # remaining_samples is device-reported and may not be known up front.
        $bar.Maximum = if ($total -gt 0) { $total } else { 100 }
        $bar.Value = 0

        $st = New-Object System.Windows.Forms.Label
        $st.Text = 'Waiting for the first touch...'
        $st.Location = New-Object System.Drawing.Point(20,152)
        $st.Size = New-Object System.Drawing.Size(340,18)

        $pulse = New-Object System.Windows.Forms.Label
        $pulse.Text = ''
        $pulse.Location = New-Object System.Drawing.Point(20,174)
        $pulse.Size = New-Object System.Drawing.Size(340,18)
        $pulse.ForeColor = [System.Drawing.Color]::FromArgb(160,110,40)

        $hint = New-Object System.Windows.Forms.Label
        $hint.Text = 'Cancel stops the enrollment and discards it from the key.'
        $hint.Location = New-Object System.Drawing.Point(20,200)
        $hint.Size = New-Object System.Drawing.Size(340,28)
        $hint.ForeColor = [System.Drawing.Color]::FromArgb(150,150,150)

        $big.ForeColor = [System.Drawing.Color]::FromArgb(32,36,42)

        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text = 'Cancel'
        $btnCancel.Size = New-Object System.Drawing.Size(90,28)
        # Own row, bottom-right, clear of the hint text above it.
        $btnCancel.Location = New-Object System.Drawing.Point(270,230)
        $btnCancel.FlatStyle = 'Flat'
        $btnCancel.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(224,227,231)
        $btnCancel.FlatAppearance.BorderSize = 1
        $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(238,240,243)
        $btnCancel.Cursor = 'Hand'
        $btnCancel.Add_Click({
            # CTAPHID_CANCEL is sent from the keepalive loop the moment this flag
            # is seen (which happens within ~100ms, on the next keepalive), so
            # the key aborts the touch wait itself - no need to wait for a real
            # touch or a sensor timeout.
            $script:bioCancel = $true
            if ($script:bioUi) {
                $script:bioUi.Cancel.Enabled = $false
                $script:bioUi.Cancel.Text = 'Cancelling...'
                $script:bioUi.Status.Text = 'Cancelling...'
            }
        })

        $d.Controls.AddRange(@($fp,$big,$sub,$bar,$st,$pulse,$hint,$btnCancel))

        # The keepalive only beats while the key waits for a touch. A timer keeps
        # the ridges moving between beats so the window never looks frozen.
        $tmr = New-Object System.Windows.Forms.Timer
        $tmr.Interval = 120
        $tmr.Add_Tick({
            if (-not $script:bioIdle) {
                $script:bioBeat = ($script:bioBeat + 1) % 5
                if ($script:bioUi) { $script:bioUi.Fp.Invalidate() }
            }
        })
        $tmr.Start()

        [pscustomobject]@{ Form=$d; Bar=$bar; Status=$st; Pulse=$pulse; Title=$big; Fp=$fp; Timer=$tmr; Cancel=$btnCancel }
    }


    $askPin = {
        if ($script:pinCache) { return $script:pinCache }
        $dlg = New-Object System.Windows.Forms.Form
        $dlg.Text = 'PIN required'
        $dlg.Size = New-Object System.Drawing.Size(330,190)
        $dlg.StartPosition = 'CenterParent'
        $dlg.FormBorderStyle = 'FixedDialog'
        $dlg.MinimizeBox = $false; $dlg.MaximizeBox = $false
        $l = New-Object System.Windows.Forms.Label
        $l.Text = 'Enter the FIDO2 PIN.'
        $l.Location = New-Object System.Drawing.Point(10,10)
        $l.Size = New-Object System.Drawing.Size(300,18)
        $l2 = New-Object System.Windows.Forms.Label
        $l2.Text = 'A wrong PIN costs a retry.'
        $l2.Location = New-Object System.Drawing.Point(10,28)
        $l2.Size = New-Object System.Drawing.Size(300,18)
        $l2.ForeColor = [System.Drawing.Color]::FromArgb(160,110,40)
        $t = New-Object System.Windows.Forms.TextBox
        $t.Location = New-Object System.Drawing.Point(10,52)
        $t.Size = New-Object System.Drawing.Size(295,24)
        $t.UseSystemPasswordChar = $true
        $chk = New-Object System.Windows.Forms.CheckBox
        $chk.Text = 'Remember for this session (not saved to disk)'
        $chk.Location = New-Object System.Drawing.Point(10,80)
        $chk.Size = New-Object System.Drawing.Size(295,20)
        $ok = New-Object System.Windows.Forms.Button
        $ok.Text = 'OK'
        $ok.Size = New-Object System.Drawing.Size(76,28)
        $ok.Location = New-Object System.Drawing.Point(146,110)
        $ok.DialogResult = 'OK'
        $cancel = New-Object System.Windows.Forms.Button
        $cancel.Text = 'Cancel'
        $cancel.Size = New-Object System.Drawing.Size(76,28)
        $cancel.Location = New-Object System.Drawing.Point(228,110)
        $cancel.DialogResult = 'Cancel'
        & $StyleButton $ok 'primary'
        & $StyleButton $cancel 'secondary'
        $dlg.BackColor = $Theme.Card
        try { $dlg.Icon = $form.Icon } catch { }
        $dlg.Controls.AddRange(@($l,$l2,$t,$chk,$ok,$cancel))
        $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
        if ($dlg.ShowDialog($form) -eq 'OK' -and $t.Text) {
            if ($chk.Checked) { $script:pinCache = $t.Text }
            return $t.Text
        }
        $null
    }

    # --- wiring ---
    $btnRefresh.Add_Click($refresh)

    # Info loads whenever the selection changes - no button to press.
    $loadInfo = {
        & $withDevice {
            param($dev)
            $gridInfo.Rows.Clear()
            # The HID interface cannot read the serial - it is a vendor APDU on
            # the CCID interface of the same key. Fall back to the (possibly
            # hidden) CCID entry so the serial still shows on HID.
            $sn = if ($dev.Serial) { $dev.Serial } elseif ($script:ccidDevice) { $script:ccidDevice.Serial } else { $null }
            $lblSummary.Text = if ($sn) { "Serial $sn" } else { $dev.Name }
            $bits = @("transport: $($script:mode)")

            if ($sn) { [void]$gridInfo.Rows.Add('Serial', $sn) }
            [void]$gridInfo.Rows.Add('Transport', $script:mode)

            $fi = $null
            try { $fi = Read-FidoInfo } catch { Write-Log $_.Exception.Message 'warn' }
            if ($fi) {
                foreach ($p in $fi.PSObject.Properties) { [void]$gridInfo.Rows.Add($p.Name, "$($p.Value)") }
                if ($fi.Versions)  { $bits += $fi.Versions }
                if ($fi.ClientPin -eq $true) { $bits += 'PIN set' } elseif ($fi.ClientPin -eq $false) { $bits += 'no PIN' }
                Write-Log 'getInfo ok'
            } else {
                $bits += 'CTAP2 unavailable on this interface'
            }

            # Vendor config is a CCID-only APDU. When the selected device is the
            # HID interface, borrow the (hidden) CCID interface of the same key:
            # close HID, read, then reopen HID so the caller's device is intact.
            $cfgDev = if ($dev.Kind -eq 'ccid') { $dev } else { $script:ccidDevice }
            if ($cfgDev) {
                # Read-Config selects the OTP applet; run it after getInfo.
                try {
                    if ($cfgDev -ne $dev) { Open-T2Device $cfgDev }
                    $cfg = Read-Config
                    if ($cfg) {
                        foreach ($p in $cfg.PSObject.Properties) { [void]$gridInfo.Rows.Add("cfg:$($p.Name)", "$($p.Value)") }
                        Write-Log 'vendor config ok'
                    }
                } catch { Write-Log $_.Exception.Message 'warn' }
                finally {
                    if ($cfgDev -ne $dev) {
                        try { Open-T2Device $dev } catch { Write-Log $_.Exception.Message 'warn' }
                    }
                }
            }
            $lblSummary2.Text = $bits -join '   |   '

            # Mirror the policy state onto the Policy tab.
            if ($fi) {
                $uv = if ($fi.AlwaysUv -eq $null) { 'not reported' } else { "$($fi.AlwaysUv)" }
                $lblUvNow.Text = "currently: $uv"
                $cfgOk = ($fi.Options -match 'authnrCfg=True')
                $minOk = ($fi.Options -match 'setMinPINLength=True')
                $btnUvToggle.Enabled = $cfgOk
                $btnUvToggle.Text = if ($fi.AlwaysUv -eq $null) { 'Toggle' }
                                    elseif ([bool]$fi.AlwaysUv) { 'Turn off' }
                                    else { 'Turn on' }
                $btnMinApply.Enabled = ($cfgOk -and $minOk)
                $btnForce.Enabled = ($cfgOk -and $minOk)

                # getInfo is the standard source for sensor presence. The
                # vendor config byte's FingerprintPresent claimed True on a key
                # whose options map has no bioEnroll at all - trust CTAP.
                $bioOk = ($fi.Options -match 'bioEnroll=|userVerificationMgmtPreview=True')
                $btnBioList.Enabled = $bioOk
                $btnBioAdd.Enabled = $bioOk
                if (-not $bioOk) {
                    $lblBioEmpty.Text = "This key has no fingerprint sensor." + [Environment]::NewLine + "getInfo does not advertise bioEnroll."
                    $lblBioEmpty.Visible = $true; $gridBio.Visible = $false
                    $lblBioInfo.Text = ''
                }
                $lblPolState.Text = if ($cfgOk) {
                    'authenticatorConfig supported.' + $(if (-not $minOk) { '  setMinPINLength is NOT - those two controls are disabled.' } else { '' })
                } else {
                    'This key does not advertise authenticatorConfig - policy changes are unavailable.'
                }
            } else {
                $lblUvNow.Text = ''
                $lblPolState.Text = 'CTAP2 unavailable on this interface.'
                $btnUvToggle.Enabled = $false
                $btnMinApply.Enabled = $false; $btnForce.Enabled = $false
            }
        } 'Reading device info'
    }
    $cboDev.Add_SelectedIndexChanged($loadInfo)

    $btnCreds.Add_Click({
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $gridCreds.Rows.Clear()
            $tok = Get-CredMgmtToken -PinVal $pin -FidoInfo (Read-FidoInfo)
            $meta = Get-CredsMetadata $tok
            if ($meta) {
                $free = if ($meta.MaxRemaining -ne $null) { $meta.MaxRemaining } else { '?' }
                $lblMeta.Text = "stored: $($meta.Existing)    free: $free"
            }
            $creds = @(Get-ResidentCredentials $tok)
            foreach ($c in $creds) {
                [void]$gridCreds.Rows.Add($c.RP, $c.UserName, $c.DisplayName, $c.UserId, $c.CredentialId)
            }
            Write-Log "listed $($creds.Count) credential(s)"
            $btnDelete.Enabled = ($creds.Count -gt 0)
            if ($creds.Count -eq 0) {
                $lblCredsEmpty.Text = 'This key has no resident credentials.'
                $lblCredsEmpty.Visible = $true
                $gridCreds.Visible = $false
            } else {
                $lblCredsEmpty.Visible = $false
                $gridCreds.Visible = $true
            }
        } 'Listing credentials'
    })

    $btnDelete.Add_Click({
        if ($gridCreds.SelectedRows.Count -lt 1) { Write-Log 'select a row first' 'warn'; return }
        $row = $gridCreds.SelectedRows[0]
        $cid = $row.Cells[4].Value
        $who = "$($row.Cells[0].Value) / $($row.Cells[1].Value)"
        if (-not $cid) { Write-Log 'no credential id on that row' 'error'; return }
        $ans = [System.Windows.Forms.MessageBox]::Show("Delete this credential?`n`n$who`n`nThis cannot be undone.", 'Confirm delete', 'YesNo', 'Warning')
        if ($ans -ne 'Yes') { return }
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $tok = Get-CredMgmtToken -PinVal $pin -FidoInfo (Read-FidoInfo)
            Write-Log (Remove-ResidentCredential $tok $cid)
            $gridCreds.Rows.Remove($row)
            if ($gridCreds.Rows.Count -eq 0) {
                $lblCredsEmpty.Text = 'This key has no resident credentials.'
                $lblCredsEmpty.Visible = $true
                $gridCreds.Visible = $false
                $btnDelete.Enabled = $false
            }
        } 'Deleting credential'
    })

    $btnPinCheck.Add_Click({
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            if (-not $fi) { Write-Log 'getInfo failed' 'error'; return }
            if ($fi.ClientPin -eq $true) {
                $r = Get-PinRetryCount
                $lblPinState.Text = "A PIN is set. Retries remaining: $r"
                $txtOld.Enabled = $true
                Write-Log "PIN is set, $r retries left"
            } else {
                $lblPinState.Text = 'No PIN set. Leave "Current PIN" blank to set the first one.'
                $txtOld.Enabled = $false
                Write-Log 'no PIN set on this key'
            }
        } 'Checking PIN state'
    })

    $btnPinApply.Add_Click({
        if ($txtNew.Text -cne $txtNew2.Text) {
            [void][System.Windows.Forms.MessageBox]::Show('The new PINs do not match.','PIN mismatch','OK','Warning')
            return
        }
        if ([Text.Encoding]::UTF8.GetByteCount($txtNew.Text) -lt 4) {
            [void][System.Windows.Forms.MessageBox]::Show('PIN must be at least 4 bytes.','PIN too short','OK','Warning')
            return
        }
        $old = $txtOld.Text
        $new = $txtNew.Text
        $dry = $chkDry.Checked
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            if ($fi.ClientPin -eq $true) {
                if (-not $old) { Write-Log 'a PIN is already set - enter the current one' 'error'; return }
                $r = Get-PinRetryCount
                if ($r -ne $null -and $r -lt 3) { Write-Log "refusing: only $r retries left, reset the key instead" 'error'; return }
                Write-Log (Set-Fido2PinChange -OldPinVal $old -NewPin $new -WhatIfMode:$dry)
            } else {
                Write-Log (Set-Fido2Pin -NewPin $new -WhatIfMode:$dry)
            }
            if (-not $dry) { $txtOld.Clear(); $txtNew.Clear(); $txtNew2.Clear() }
        } $(if ($dry) { 'Building CBOR (dry run)' } else { 'Applying PIN' })
    })

    # Policy handlers are written flat, matching $btnCreds: prompt for the PIN
    # first, then ONE $withDevice call with the work inline. An earlier version
    # wrapped these in a $withCfgToken helper that invoked a scriptblock from
    # inside the scriptblock passed to $withDevice; that extra nesting froze the
    # WinForms message loop even though the same operations worked from the CLI.
    #
    # Config sub-commands need a token with the acfg permission, not cm.

    $btnUvToggle.Add_Click({
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            if (-not $fi) { throw "getInfo failed" }
            if ($fi.Options -notmatch 'authnrCfg=True') { throw "this key does not support authenticatorConfig" }
            $tok = Get-PinToken -PinVal $pin -Permissions $PERM_AUTHNR_CFG
            # 0x02 is a toggle: fire it directly and read back the result.
            Send-AuthnrConfig $tok 0x02 $null
            $after = (Read-FidoInfo).AlwaysUv
            Write-Log "alwaysUv is now $after"
            $lblUvNow.Text = "currently: $after"
            $btnUvToggle.Text = if ([bool]$after) { 'Turn off' } else { 'Turn on' }
        } 'Toggling alwaysUv'
    })

    $btnMinApply.Add_Click({
        $n = [int]$numMin.Value
        $f = $chkMinForce.Checked
        $msg = "Raise the minimum PIN length to $n?`n`nThis can only be increased - lowering it again requires a factory reset, which wipes every passkey."
        if ($f) { $msg += "`n`nA PIN change will also be forced on next use." }
        if ([System.Windows.Forms.MessageBox]::Show($msg,'Confirm','YesNo','Warning') -ne 'Yes') { return }
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            if (-not $fi) { throw "getInfo failed" }
            if ($fi.Options -notmatch 'authnrCfg=True') { throw "this key does not support authenticatorConfig" }
            if ($fi.Options -notmatch 'setMinPINLength=True') { throw "this key does not support setMinPINLength" }
            $tok = Get-PinToken -PinVal $pin -Permissions $PERM_AUTHNR_CFG
            Write-Log (Set-MinPinLength -Token $tok -NewMin $n -ForceChange:$f)
        } 'Setting minimum PIN length'
    })

    $btnForce.Add_Click({
        if ([System.Windows.Forms.MessageBox]::Show(
            "Force a PIN change on next use?`n`nThe current PIN keeps working until then, but the next platform interaction will require setting a new one.",
            'Confirm','YesNo','Question') -ne 'Yes') { return }
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            if (-not $fi) { throw "getInfo failed" }
            if ($fi.Options -notmatch 'authnrCfg=True') { throw "this key does not support authenticatorConfig" }
            if ($fi.Options -notmatch 'setMinPINLength=True') { throw "this key does not support setMinPINLength" }
            $tok = Get-PinToken -PinVal $pin -Permissions $PERM_AUTHNR_CFG
            Write-Log (Set-ForcePinChange $tok)
        } 'Forcing PIN change'
    })

    # Simple text prompt (fingerprint names are not secret).
    $askText = {
        param($title, $prompt, $preset)
        $dlg = New-Object System.Windows.Forms.Form
        $dlg.Text = $title
        $dlg.Size = New-Object System.Drawing.Size(330,150)
        $dlg.StartPosition = 'CenterParent'
        $dlg.FormBorderStyle = 'FixedDialog'
        $dlg.MinimizeBox = $false; $dlg.MaximizeBox = $false
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $prompt
        $l.Location = New-Object System.Drawing.Point(10,10)
        $l.Size = New-Object System.Drawing.Size(300,18)
        $t = New-Object System.Windows.Forms.TextBox
        $t.Location = New-Object System.Drawing.Point(10,34)
        $t.Size = New-Object System.Drawing.Size(295,24)
        if ($preset) { $t.Text = $preset }
        $ok = New-Object System.Windows.Forms.Button
        $ok.Text = 'OK'; $ok.Size = New-Object System.Drawing.Size(76,28)
        $ok.Location = New-Object System.Drawing.Point(146,68)
        $ok.DialogResult = 'OK'
        $cancel = New-Object System.Windows.Forms.Button
        $cancel.Text = 'Cancel'; $cancel.Size = New-Object System.Drawing.Size(76,28)
        $cancel.Location = New-Object System.Drawing.Point(228,68)
        $cancel.DialogResult = 'Cancel'
        & $StyleButton $ok 'primary'
        & $StyleButton $cancel 'secondary'
        $dlg.BackColor = $Theme.Card
        try { $dlg.Icon = $form.Icon } catch { }
        $dlg.Controls.AddRange(@($l,$t,$ok,$cancel))
        $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
        if ($dlg.ShowDialog($form) -eq 'OK' -and $t.Text) { return $t.Text }
        $null
    }

    # Populates the fingerprint grid from an already-open device and an existing
    # token. Split out of $btnBioList so the enroll handler can refresh the list
    # without re-prompting for the PIN or nesting another $withDevice.
    $fillBioGrid = {
        param($tok, $bc)
        $gridBio.Rows.Clear()
        $en = @(Get-BioEnrollments $tok $bc)
        foreach ($e in $en) { [void]$gridBio.Rows.Add($e.FriendlyName, $e.TemplateId) }
        Write-Log "listed $($en.Count) fingerprint(s)"
        $btnBioRename.Enabled = ($en.Count -gt 0)
        $btnBioDel.Enabled = ($en.Count -gt 0)
        if ($en.Count -eq 0) {
            $lblBioEmpty.Text = 'No fingerprints enrolled on this key.'
            $lblBioEmpty.Visible = $true; $gridBio.Visible = $false
        } else {
            $lblBioEmpty.Visible = $false; $gridBio.Visible = $true
        }
    }

    # Bio handlers: flat, like $btnCreds - PIN first, then one $withDevice.
    $btnBioList.Add_Click({
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            if (-not $fi) { throw "getInfo failed" }
            if ($fi.Options -notmatch 'bioEnroll=|userVerificationMgmtPreview=True') {
                throw "this key does not advertise bioEnroll - no fingerprint sensor"
            }
            $bc = Get-BioCmdByte $fi
            $tok = Get-PinToken -PinVal $pin -Permissions $PERM_BIO_ENROLL

            $si = $null
            try { $si = Get-BioSensorInfo $tok $bc } catch { }
            if ($si) {
                $kind = switch ([int]$si.FingerprintKind) { 1 {'touch'} 2 {'swipe'} default {'unknown'} }
                $lblBioInfo.Text = "$kind sensor, ~$($si.MaxCaptureSamples) samples per enrollment"
            }

            & $fillBioGrid $tok $bc
        } 'Listing fingerprints'
    })

    $btnBioAdd.Add_Click({
        $name = & $askText 'Enroll fingerprint' 'Name for this finger (optional):' ''
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            if (-not $fi) { throw "getInfo failed" }
            if ($fi.Options -notmatch 'bioEnroll=|userVerificationMgmtPreview=True') {
                throw "this key does not advertise bioEnroll - no fingerprint sensor"
            }
            $bc = Get-BioCmdByte $fi
            $tok = Get-PinToken -PinVal $pin -Permissions $PERM_BIO_ENROLL

            # How many samples this sensor wants, if it will say.
            $want = 0
            try { $si = Get-BioSensorInfo $tok $bc; if ($si) { $want = [int]$si.MaxCaptureSamples } } catch { }

            # $ui goes in script scope rather than being captured with
            # GetNewClosure(): a closure runs the block in its own module, where
            # script-level functions like Get-BioSampleStatusText are NOT
            # visible, and the call fails at runtime with "not recognized".
            $script:bioIdle = $true
            $script:bioBeat = 0
            $script:bioUi = & $newBioDialog $want
            # Centre on the main window by hand - StartPosition=CenterParent is
            # ignored by .Show() (it only applies to ShowDialog).
            $script:bioUi.Form.Location = New-Object System.Drawing.Point(
                ($form.Location.X + [int](($form.Width  - $script:bioUi.Form.Width)  / 2)),
                ($form.Location.Y + [int](($form.Height - $script:bioUi.Form.Height) / 2))
            )
            $script:bioUi.Form.Show($form)
            [System.Windows.Forms.Application]::DoEvents()

            # Turn the key's UP_NEEDED keepalive beat into a pulse in the dialog
            # rather than a log line every half second. The beat also marks the
            # window as "awaiting touch", which un-mutes the ridge animation.
            $script:OnTouchNeeded = {
                $script:bioIdle = $false
                if ($script:bioUi) {
                    $script:bioUi.Pulse.Text = 'waiting for your finger...'
                    [System.Windows.Forms.Application]::DoEvents()
                }
            }

            $updateUi = {
                param($s)
                # A sample landed: stop animating until the key asks again.
                $script:bioIdle = $true
                $script:bioUi.Pulse.Text = ''
                $script:bioUi.Fp.Invalidate()
                $txt = Get-BioSampleStatusText $s.LastSampleStatus
                $script:bioUi.Status.Text = "$txt - $($s.RemainingSamples) more touch(es)"
                if ($s.RemainingSamples -gt 0) {
                    # Derive a total when the sensor did not report one.
                    if ($script:bioUi.Bar.Maximum -lt ($script:bioDone + $s.RemainingSamples)) {
                        $script:bioUi.Bar.Maximum = $script:bioDone + $s.RemainingSamples
                    }
                    $script:bioUi.Bar.Value = [Math]::Min($script:bioDone, $script:bioUi.Bar.Maximum)
                } else {
                    $script:bioUi.Bar.Value = $script:bioUi.Bar.Maximum
                }
                [System.Windows.Forms.Application]::DoEvents()
            }

            $cancelled = $false
            $script:bioCancel = $false
            $script:bioCancelSent = $false
            try {
                $script:bioDone = 0
                $st = Start-BioEnroll $tok 0 $bc
                $script:bioDone++
                Write-Log ("sample: {0}  (remaining {1})" -f (Get-BioSampleStatusText $st.LastSampleStatus), $st.RemainingSamples)
                & $updateUi $st
                # Cancel may have been clicked during the first-touch wait.
                if ($script:bioCancel) { $cancelled = $true }

                # Host-owned cap: remaining_samples is device-reported, and a key
                # that never counts down would loop forever, each pass costing a
                # touch. Real sensors want 4-17.
                $n = 0
                while ($st.RemainingSamples -gt 0) {
                    # Cancel is checked here, between samples: the click cannot
                    # interrupt the blocking read inside Step-BioEnroll, but it
                    # lands during the DoEvents in $updateUi, so the loop sees it
                    # on the next pass. Stop-BioEnroll (in finally) discards the
                    # partial template on the key.
                    if ($script:bioCancel) { $cancelled = $true; break }
                    if (++$n -gt 64) {
                        throw "the key kept asking for samples past the host cap (64)"
                    }
                    $st = Step-BioEnroll $tok $st.TemplateIdBytes 0 $bc
                    $script:bioDone++
                    Write-Log ("sample: {0}  (remaining {1})" -f (Get-BioSampleStatusText $st.LastSampleStatus), $st.RemainingSamples)
                    & $updateUi $st
                    if ($script:bioCancel) { $cancelled = $true; break }
                }

                if ($cancelled) {
                    # Discard the half-built template so it does not linger.
                    try { [void](Stop-BioEnroll $tok $bc) } catch { }
                    $script:bioIdle = $true
                    $script:bioUi.Title.Text = 'Enrollment cancelled'
                    $script:bioUi.Status.Text = 'No fingerprint was added.'
                    $script:bioUi.Pulse.Text = ''
                    $script:bioUi.Fp.Invalidate()
                    [System.Windows.Forms.Application]::DoEvents()
                    Start-Sleep -Milliseconds 500
                } else {
                    $script:bioIdle = $true
                    $script:bioUi.Title.Text = 'Fingerprint enrolled'
                    $script:bioUi.Status.Text = "template id $($st.TemplateId)"
                    $script:bioUi.Pulse.Text = ''
                    $script:bioUi.Fp.Invalidate()
                    [System.Windows.Forms.Application]::DoEvents()
                    Start-Sleep -Milliseconds 700
                }
            }
            catch {
                if ($_.Exception.Message -match 'CTAP_CANCELLED') {
                    # We asked the key to cancel; this is the expected unwind,
                    # not a fault. Fall through to the cancelled path.
                    $cancelled = $true
                    try { [void](Stop-BioEnroll $tok $bc) } catch { }
                    if ($script:bioUi) {
                        $script:bioIdle = $true
                        $script:bioUi.Title.Text = 'Enrollment cancelled'
                        $script:bioUi.Status.Text = 'No fingerprint was added.'
                        $script:bioUi.Pulse.Text = ''
                        $script:bioUi.Fp.Invalidate()
                        [System.Windows.Forms.Application]::DoEvents()
                        Start-Sleep -Milliseconds 400
                    }
                }
                else {
                    # A half-finished enrollment stays on the key and shows up in
                    # the list as a stray template. Cancel it before rethrowing.
                    try { [void](Stop-BioEnroll $tok $bc) ; Write-Log 'partial enrollment cancelled' 'warn' } catch { }
                    throw
                }
            }
            finally {
                $script:OnTouchNeeded = $null
                $script:bioIdle = $true
                $script:bioCancel = $false
                $script:bioCancelSent = $false
                if ($script:bioUi) {
                    # Stop the timer before disposing the form: a tick against a
                    # disposed control throws on the UI thread.
                    $script:bioUi.Timer.Stop(); $script:bioUi.Timer.Dispose()
                    $script:bioUi.Form.Close(); $script:bioUi.Form.Dispose()
                    $script:bioUi = $null
                }
            }

            if ($cancelled) {
                Write-Log 'enrollment cancelled' 'warn'
                return
            }
            Write-Log "enrolled. template id $($st.TemplateId)"
            if ($name) { Write-Log (Rename-BioEnrollment $tok $st.TemplateId $name $bc) }

            # Refresh the list in place. The device is still open and the token
            # still valid, so this reuses both - no second PIN prompt. Runs after
            # the rename so the new name shows rather than the default.
            & $fillBioGrid $tok $bc
        } 'Enrolling fingerprint'
    })

    $btnBioRename.Add_Click({
        if ($gridBio.SelectedRows.Count -lt 1) { Write-Log 'select a row first' 'warn'; return }
        $row = $gridBio.SelectedRows[0]
        $tid = $row.Cells[1].Value
        $cur = $row.Cells[0].Value
        if (-not $tid) { Write-Log 'no template id on that row' 'error'; return }
        $name = & $askText 'Rename fingerprint' 'New name:' $cur
        if (-not $name) { return }
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            $bc = Get-BioCmdByte $fi
            $tok = Get-PinToken -PinVal $pin -Permissions $PERM_BIO_ENROLL
            Write-Log (Rename-BioEnrollment $tok $tid $name $bc)
            $row.Cells[0].Value = $name
        } 'Renaming fingerprint'
    })

    $btnBioDel.Add_Click({
        if ($gridBio.SelectedRows.Count -lt 1) { Write-Log 'select a row first' 'warn'; return }
        $row = $gridBio.SelectedRows[0]
        $tid = $row.Cells[1].Value
        $who = $row.Cells[0].Value
        if (-not $tid) { Write-Log 'no template id on that row' 'error'; return }
        if ([System.Windows.Forms.MessageBox]::Show("Delete this fingerprint?`n`n$who`n`nThis cannot be undone.",'Confirm delete','YesNo','Warning') -ne 'Yes') { return }
        $pin = & $askPin
        if (-not $pin) { return }
        & $withDevice {
            param($dev)
            $fi = Read-FidoInfo
            $bc = Get-BioCmdByte $fi
            $tok = Get-PinToken -PinVal $pin -Permissions $PERM_BIO_ENROLL
            Write-Log (Remove-BioEnrollment $tok $tid $bc)
            $gridBio.Rows.Remove($row)
            if ($gridBio.Rows.Count -eq 0) {
                $lblBioEmpty.Text = 'No fingerprints enrolled on this key.'
                $lblBioEmpty.Visible = $true; $gridBio.Visible = $false
                $btnBioRename.Enabled = $false; $btnBioDel.Enabled = $false
            }
        } 'Deleting fingerprint'
    })

    $btnReset.Add_Click({
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "This wipes EVERY passkey and the PIN on the selected device.`n`nUnplug and replug the key first - reset only works within ~10s of power-up - then click Yes.`n`nProceed?",
            'Factory reset', 'YesNo', 'Warning')
        if ($ans -ne 'Yes') { return }
        & $withDevice {
            param($dev)
            Write-Log (Invoke-FactoryReset)
        } 'Factory reset'
    })

    # --- apply theme -----------------------------------------------------
    # Walk the whole control tree once: buttons get flat styling, grids get
    # recoloured, panels/labels pick up the palette. Specific accents (primary
    # actions, the danger button) are set explicitly afterward.
    $applyTheme = {
        param($ctrl)
        foreach ($c in $ctrl.Controls) {
            if     ($c -is [System.Windows.Forms.Button])        { & $StyleButton $c 'secondary' }
            elseif ($c -is [System.Windows.Forms.DataGridView])  { & $StyleGrid $c }
            elseif ($c -is [System.Windows.Forms.TabControl])    { $c.Padding = New-Object System.Drawing.Point(14,6) }
            elseif ($c -is [System.Windows.Forms.TabPage])       { $c.BackColor = $Theme.Bg; $c.UseVisualStyleBackColor = $false }
            if ($c.Controls.Count -gt 0) { & $applyTheme $c }
        }
    }
    & $applyTheme $form

    # Primary actions filled with the accent; the reset button reads as danger.
    & $StyleButton $btnRefresh 'primary'
    & $StyleButton $btnBioAdd  'primary'
    & $StyleButton $btnReset   'danger'
    # The device picker and status strip sit on cards, not the window grey.
    $top.BackColor = $Theme.Card
    $status.BackColor = $Theme.Card
    $status.ForeColor = $Theme.Muted

    $form.Add_Shown({ & $refresh })
    $form.Add_FormClosed({ Close-T2Device; Close-CcidContext })

    [void]$form.ShowDialog()
}

# ============================ CLI ============================
function Read-PinPrompt([string]$prompt) {
    $ss = Read-Host -Prompt $prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Invoke-Cli {
    $needsCtap = $Info -or $PinRetries -or $Pin -or $Reset -or $CredsMeta -or $CredsList -or $CredsDelete -or $AlwaysUv -or ($MinPinLength -gt 0) -or $ForcePinChange -or $BioList -or $BioEnroll -or $BioRename -or $BioDelete
    $elevated  = Test-Elevated

    $script:Log = {
        param($msg, $level)
        $c = switch ($level) { 'error' {'Red'} 'warn' {'Yellow'} 'debug' {'DarkGray'} default {'Gray'} }
        Write-Host "  $msg" -ForegroundColor $c
    }

    if ($needsCtap -and -not $elevated) {
        Write-Host "Not elevated: CTAP needs admin (PC/SC SELECT gives 0x80100027, HID open gives 0x5)." -ForegroundColor Yellow
    }

    $devs = @(Get-T2Devices)
    if ($devs.Count -eq 0) { Write-Host "No readers or FIDO devices found." -ForegroundColor Red; return 1 }

    # The serial is a vendor APDU: CCID only, whatever transport CTAP uses.
    $serial = ($devs | Where-Object { $_.Kind -eq 'ccid' -and $_.Serial } | Select-Object -First 1).Serial

    if (-not $needsCtap -and -not $Config) {
        if ($serial) { $serial; return 0 }
        Write-Host "No serial (needs a CCID reader)." -ForegroundColor Red
        return 1
    }

    $want = $Transport
    if ($want -eq 'auto') { $want = if ($elevated) { 'hid' } else { 'ccid' } }
    # Preference, not exclusion: order by the preferred Kind but keep every
    # device in the pool, so a HID failure falls through to a CTAP-capable NFC
    # reader instead of aborting. ArrayList + element-wise Add rather than
    # array concatenation: Add never unrolls or re-wraps what it is given.
    $pool = New-Object System.Collections.ArrayList
    if ($Transport -eq 'auto') {
        foreach ($d in $devs) { if ($d.Kind -eq $want) { [void]$pool.Add($d) } }
        foreach ($d in $devs) { if ($d.Kind -ne $want) { [void]$pool.Add($d) } }
    } else {
        foreach ($d in $devs) { if ($d.Kind -eq $want) { [void]$pool.Add($d) } }
    }
    if ($pool.Count -eq 0) { Write-Host "No $want device found." -ForegroundColor Red; return 1 }

    if ($script:Debug2) {
        Write-Log ("pool: {0} element(s)" -f $pool.Count) 'debug'
        for ($i = 0; $i -lt $pool.Count; $i++) {
            $e = $pool[$i]
            $t = if ($null -eq $e) { 'null' } else { $e.GetType().FullName }
            $c = if ($e -is [Array]) { " COUNT=$($e.Count) <-- NESTED" } else { '' }
            Write-Log ("  [{0}] {1}{2} Kind={3} HidPath=[{4}]" -f $i, $t, $c, $e.Kind, $e.HidPath) 'debug'
        }
    }

    # Try each candidate until one answers. A USB-CCID interface looks the same
    # as an NFC reader by name but cannot carry CTAP, so capability is
    # discovered rather than assumed.
    $chosen = $null
    foreach ($d in $pool) {
        if (-not $needsCtap) { $chosen = $d; break }
        try {
            Open-T2Device $d
            [void](Read-FidoInfo)
            $chosen = $d
            break
        }
        catch {
            Write-Host "  skip $($d.Display): $($_.Exception.Message)" -ForegroundColor DarkGray
            Close-T2Device
        }
    }
    if (-not $chosen) { Write-Host "No device could carry CTAP2." -ForegroundColor Red; return 1 }

    Write-Host "Device: $($chosen.Display)" -ForegroundColor DarkGray
    if ($serial) { Write-Host "Serial: $serial" -ForegroundColor DarkGray }

    try {
        if ($PinRetries) { "Retries: $(Get-PinRetryCount)"; return 0 }

        if ($Pin) {
            $fi = Read-FidoInfo
            if ($fi.ClientPin -ne $true) {
                Write-Host "No PIN is set. Setting an initial PIN." -ForegroundColor Cyan
                $p1 = Read-PinPrompt 'New PIN (4-63 chars)'
                $p2 = Read-PinPrompt 'Confirm new PIN'
                if ($p1 -cne $p2) { Write-Host "PINs do not match." -ForegroundColor Red; return 1 }
                Write-Host (Set-Fido2Pin -NewPin $p1 -WhatIfMode:$DryRun) -ForegroundColor Green
                return 0
            }
            $r = Get-PinRetryCount
            Write-Host "A PIN is already set. Retries remaining: $r" -ForegroundColor Cyan
            if ($r -ne $null -and $r -lt 3) { Write-Host "Refusing: only $r retries left. Reset the key instead." -ForegroundColor Red; return 1 }
            $po = Read-PinPrompt 'Current PIN'
            $p1 = Read-PinPrompt 'New PIN (4-63 chars)'
            $p2 = Read-PinPrompt 'Confirm new PIN'
            if ($p1 -cne $p2) { Write-Host "PINs do not match." -ForegroundColor Red; return 1 }
            if ($DryRun) {
                Write-Host "The ECDH key agreement DID run - the device's public key is needed to" -ForegroundColor Yellow
                Write-Host "build this - but no PIN changed and no retry was consumed." -ForegroundColor Yellow
            }
            Write-Host (Set-Fido2PinChange -OldPinVal $po -NewPin $p1 -WhatIfMode:$DryRun) -ForegroundColor Green
            return 0
        }

        if ($Reset) {
            Write-Host "This wipes EVERY passkey and the PIN. Irreversible." -ForegroundColor Red
            Write-Host "Reset must arrive within ~10s of power-up: replug the key, then confirm." -ForegroundColor Yellow
            $c = Read-Host "Type RESET to proceed"
            if ($c -cne 'RESET') { Write-Host "Cancelled." -ForegroundColor Yellow; return 1 }
            Write-Host (Invoke-FactoryReset) -ForegroundColor Green
            return 0
        }

        if ($AlwaysUv -or ($MinPinLength -gt 0) -or $ForcePinChange) {
            $fi = Read-FidoInfo
            if ($fi.Options -notmatch 'authnrCfg=True') {
                Write-Host "This key does not support authenticatorConfig." -ForegroundColor Red
                return 1
            }
            if (($MinPinLength -gt 0 -or $ForcePinChange) -and $fi.Options -notmatch 'setMinPINLength=True') {
                Write-Host "This key does not support setMinPINLength." -ForegroundColor Red
                return 1
            }
            if ($MinPinLength -gt 0) {
                Write-Host "Raising the minimum PIN length can never be undone without a factory reset." -ForegroundColor Yellow
                $c = Read-Host "Type YES to set the minimum to $MinPinLength"
                if ($c -cne 'YES') { Write-Host "Cancelled." -ForegroundColor Yellow; return 1 }
            }
            Write-Host "A wrong PIN here consumes a retry." -ForegroundColor Yellow
            $p = Read-PinPrompt 'PIN'
            if (-not $p) { Write-Host "Cancelled." -ForegroundColor Yellow; return 1 }
            $tok = Get-PinToken -PinVal $p -Permissions $PERM_AUTHNR_CFG

            if ($AlwaysUv) {
                Write-Host (Set-AlwaysUv $tok ($AlwaysUv -eq 'on')) -ForegroundColor Green
            }
            if ($MinPinLength -gt 0) {
                Write-Host (Set-MinPinLength -Token $tok -NewMin $MinPinLength -ForceChange:$ForcePinChange) -ForegroundColor Green
            }
            elseif ($ForcePinChange) {
                Write-Host (Set-ForcePinChange $tok) -ForegroundColor Green
            }
            return 0
        }

        if ($BioList -or $BioEnroll -or $BioRename -or $BioDelete) {
            $fi = Read-FidoInfo
            # getInfo advertises bioEnroll only on a key with a sensor. Our
            # test keys report it absent while the vendor config byte claims a
            # fingerprint is present - the CTAP options map is the standard
            # source and wins.
            if ($fi.Options -notmatch 'bioEnroll=|userVerificationMgmtPreview=True') {
                Write-Host "This key does not advertise bioEnroll - no fingerprint sensor." -ForegroundColor Red
                Write-Host "getInfo options: $($fi.Options)" -ForegroundColor DarkGray
                return 1
            }
            $bioCmd = Get-BioCmdByte $fi
            Write-Host "A wrong PIN here consumes a retry." -ForegroundColor Yellow
            $p = Read-PinPrompt 'PIN'
            if (-not $p) { Write-Host "Cancelled." -ForegroundColor Yellow; return 1 }
            $tok = Get-PinToken -PinVal $p -Permissions $PERM_BIO_ENROLL

            if ($BioList) {
                $si = $null
                try { $si = Get-BioSensorInfo $tok $bioCmd } catch { }
                if ($si) {
                    $kind = switch ([int]$si.FingerprintKind) { 1 {'touch'} 2 {'swipe'} default {'unknown'} }
                    Write-Host "Sensor: $kind, up to $($si.MaxCaptureSamples) samples per enrollment, names up to $($si.MaxFriendlyNameLen) bytes" -ForegroundColor DarkGray
                }
                $en = @(Get-BioEnrollments $tok $bioCmd)
                if ($en.Count -eq 0) { Write-Host "No fingerprints enrolled." -ForegroundColor Gray }
                else { $en | Format-Table -AutoSize }
                return 0
            }

            if ($BioEnroll) {
                $si = $null
                try { $si = Get-BioSensorInfo $tok $bioCmd } catch { }
                $maxS = if ($si -and $si.MaxCaptureSamples) { [int]$si.MaxCaptureSamples } else { 0 }
                Write-Host "Touch the sensor repeatedly until the enrollment completes." -ForegroundColor Cyan
                if ($maxS -gt 0) { Write-Host "This sensor wants about $maxS good samples." -ForegroundColor DarkGray }

                $st = Start-BioEnroll $tok 0 $bioCmd
                Write-Host ("  sample: {0}" -f (Get-BioSampleStatusText $st.LastSampleStatus))
                Write-Host ("  remaining: {0}" -f $st.RemainingSamples)

                # Host-owned cap. remaining_samples is device-reported, and a
                # key that never counts down would loop forever - each pass
                # costing the user a touch. Real sensors want 4-17 samples.
                $cap = 64
                $n = 0
                while ($st.RemainingSamples -gt 0) {
                    if (++$n -gt $cap) {
                        Write-Host "The key kept asking for more samples past the host cap ($cap). Cancelling." -ForegroundColor Red
                        try { Write-Host (Stop-BioEnroll $tok $bioCmd) -ForegroundColor Yellow } catch { }
                        return 1
                    }
                    $st = Step-BioEnroll $tok $st.TemplateIdBytes 0 $bioCmd
                    Write-Host ("  sample: {0}" -f (Get-BioSampleStatusText $st.LastSampleStatus))
                    Write-Host ("  remaining: {0}" -f $st.RemainingSamples)
                }
                Write-Host "Fingerprint enrolled. Template id: $($st.TemplateId)" -ForegroundColor Green
                if ($BioName) {
                    Write-Host (Rename-BioEnrollment $tok $st.TemplateId $BioName $bioCmd) -ForegroundColor Green
                }
                return 0
            }

            if ($BioRename) {
                if (-not $BioName) { Write-Host "-BioRename needs -BioName." -ForegroundColor Red; return 1 }
                Write-Host (Rename-BioEnrollment $tok $BioRename $BioName $bioCmd) -ForegroundColor Green
                return 0
            }

            if ($BioDelete) {
                Write-Host (Remove-BioEnrollment $tok $BioDelete $bioCmd) -ForegroundColor Green
                return 0
            }
        }

        if ($CredsMeta -or $CredsList -or $CredsDelete) {
            $r = $null
            try { $r = Get-PinRetryCount } catch { }
            if ($r -ne $null) { Write-Host "PIN retries remaining: $r" -ForegroundColor Cyan }
            Write-Host "A wrong PIN here consumes a retry." -ForegroundColor Yellow
            $p = Read-PinPrompt 'PIN'
            if (-not $p) { Write-Host "Cancelled." -ForegroundColor Yellow; return 1 }

            $tok = $null
            try { $tok = Get-CredMgmtToken -PinVal $p -FidoInfo (Read-FidoInfo) }
            catch {
                Write-Host $_.Exception.Message -ForegroundColor Red
                $left = $null
                try { $left = Get-PinRetryCount } catch { }
                if ($left -ne $null) { Write-Host "Retries now: $left" -ForegroundColor Yellow }
                return 1
            }

            # Format-* writes formatting records to the success stream. The CLI
            # ends with exit, so force immediate host rendering; otherwise the
            # records are discarded before Out-Default gets to render them.
            if ($CredsMeta) { Get-CredsMetadata $tok | Format-List | Out-Host }
            if ($CredsList) {
                $creds = @(Get-ResidentCredentials $tok)
                if ($creds.Count -eq 0) { Write-Host "No resident credentials." -ForegroundColor Gray }
                else { $creds | Format-List | Out-Host }
            }
            if ($CredsDelete) { Write-Host (Remove-ResidentCredential $tok $CredsDelete) -ForegroundColor Green }
            return 0
        }

        # -Info / -Config
        $out = [ordered]@{}
        $out['Device'] = $chosen.Display
        if ($serial) { $out['Serial'] = $serial }
        if ($Info) {
            $fi = Read-FidoInfo
            if ($fi) { foreach ($p in $fi.PSObject.Properties) { $out[$p.Name] = $p.Value } }
        }
        if ($Config) {
            if ($chosen.Kind -ne 'ccid') {
                Write-Host "-Config needs a CCID reader (it is a vendor APDU)." -ForegroundColor Yellow
            } else {
                # Read-Config selects the OTP applet; run it after getInfo.
                $cfg = Read-Config
                if ($cfg) { foreach ($p in $cfg.PSObject.Properties) { $out[$p.Name] = $p.Value } }
            }
        }
        [pscustomobject]$out | Format-List | Out-Host
        return 0
    }
    finally { Close-T2Device }
}

# ============================ Entry ============================
try {
    if ($Gui) { Show-Gui; exit 0 }
    $rc = Invoke-Cli
    exit $rc
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
finally { Close-CcidContext }
