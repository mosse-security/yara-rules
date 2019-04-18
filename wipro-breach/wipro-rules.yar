/*
 * YARA rules to hunt for files related to the Wipro breach public IOCs.
 *
 * IOCs: https://krebsonsecurity.com/wp-content/uploads/2019/04/wiproiocs.txt
 * 
 * These rules may be suitable for compromise assessment and incident response purposes but
 * not threat research and/or threat intelligence purposes.
 *
 * For quality assurance purposes, these rules were tested against 30GB+ worth of files known 
 * to be safe. Typical assurance recommendation is +1TB. Hence, in a large scale network, you
 * may encounter false positives.
 * 
 * Any hits should be validated by qualified security analysts prior to asserting
 * whether or not your organisation is affected by the Wipro network breach.
 *
 * Password to extract the samples: infected
 */
import "math"
import "pe"

rule apt_ZZ_ScreenConnect_PowerShell {
  meta:
    author = "Benjamin Mossé <contact@mosse-security.com>, Mossé Security"
    type = "APT"
    filetype = "PowerShell"
    date = "2019/04/18"
    version = "0.1"
    sha256 = "38599685f23d1840533ce5cbf5bf5114e2252435d191a3d9321093ae0bb8f88b"
    reference = "https://krebsonsecurity.com/wp-content/uploads/2019/04/wiproiocs.txt"

  strings:

    $a1 = "DoNotFindMe" wide ascii fullword
    $a2 = "-Name \"ProductName\" -NewName \"XYZ\"" wide ascii
    $a3 = "SomeThingIsGood" wide ascii fullword
    $a4 = "ScreenConnect" wide ascii fullword

  condition:
    (uint16(0) != 0x5A4D) and filesize < 1MB and ($a3 or ($a1 and $a2 and $a4))
}

rule legit_ScreenConnect_EXE1 {
  meta:
    author = "Benjamin Mossé <contact@mosse-security.com>, Mossé Security"
    type = "Legitimate Software"
    filetype = "Win32 EXE"
    date = "2019/04/18"
    version = "0.1"
    sha256 = "fb387fb2f49c59dd2fb308f7db84e93ac95ca8396c3a1ccc8839ef4002001652"
    reference = "https://krebsonsecurity.com/wp-content/uploads/2019/04/wiproiocs.txt"

  strings:
    $a1 = "USERTRUST" wide ascii fullword
    $a2 = "jmorgan" wide ascii fullword
    $a3 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\Release\\DotNetServiceRunner.pdb" wide ascii
    $a4 = "UTN-USERFirst-Object" wide ascii
    $a5 = "screenconnect.com"

  condition:
    (uint16(0) == 0x5A4D)

    and filesize < 1MB

    and all of them
}

rule legit_ScreenConnect_EXE2 {
  meta:
    author = "Benjamin Mossé <contact@mosse-security.com>, Mossé Security"
    type = "Legitimate Software"
    filetype = "Win32 EXE"
    date = "2019/04/18"
    version = "0.1"
    sha256 = "7ec40c85e1aea0d495f1e875d4ac2d2115aa2afe8fa729ef2bc641123f4b7e2d"
    reference = "https://krebsonsecurity.com/wp-content/uploads/2019/04/wiproiocs.txt"

  strings:
    $a1 = "USERTRUST" wide ascii fullword
    $a2 = "jmorgan" ascii
    $a3 = "ScreenConnect.WindowsClient.exe" wide
    $a4 = "runas" wide fullword

    $b1 = "RegDisablePredefinedCache"
    $b2 = "UrlMkSetSessionOption"
    $b3 = "VkKeyScan"
    $b4 = "WTSQueryUserToken"

  condition:
    (uint16(0) == 0x5A4D)

    and filesize < 1MB

    and all of them
}

rule legit_ScreenConnect_DLL1 {
  meta:
    author = "Benjamin Mossé <contact@mosse-security.com>, Mossé Security"
    type = "Legitimate Software"
    filetype = "Win32 DLL"
    date = "2019/04/18"
    version = "0.1"
    sha256 = "9c7bd9a52866034b8a1570ca4e3d790decb17d47acf91b742fd9bbf47e859d90"
    reference = "https://krebsonsecurity.com/wp-content/uploads/2019/04/wiproiocs.txt"

  strings:
    $a1 = "C:\\boot.ini.old" ascii wide
    $a2 = "C:\\boot.ini" ascii wide
    $a3 = "ScreenConnect.ClientService.dll" ascii wide
    $a4 = "bcdedit.exe" ascii wide
    $a5 = "System.Security.Cryptography" ascii wide
    $a6 = "ScreenConnect Software" ascii wide

    $b1 = "CloseDesktop" ascii wide
    $b2 = "CreateDesktop" ascii wide
    $b3 = "SwitchDesktop" ascii wide
    $b4 = "OpenDesktop" ascii wide
    $b5 = "ExitWindowsEx" ascii wide
    $b6 = "DuplicateToken" ascii wide
    $b7 = "DeleteService" ascii wide
    $b8 = "WTSQueryUserToken" ascii wide
    $b9 = "GetTempPath" ascii wide
    $b10 = "OpenProcessToken" ascii wide
    $b11 = "CreateProcessAsUser" ascii wide
    $b12 = "WritePrivateProfileString" ascii wide
    $b13 = "GetPrivateProfileString" ascii wide

  condition:
    (uint16(0) == 0x5A4D)

    and filesize < 1MB

    and all of ($b*)

    and (4 of ($a*))
}

rule legit_ScreenConnect_DLL2 {
  meta:
    author = "Benjamin Mossé <contact@mosse-security.com>, Mossé Security"
    type = "Legitimate Software"
    filetype = "Win32 DLL"
    date = "2019/04/18"
    version = "0.1"
    sha256 = "1cf3e5979c43ecbde6964165ac21095d9c95b43507eca8940f2a39ddc794f52e"
    reference = "https://krebsonsecurity.com/wp-content/uploads/2019/04/wiproiocs.txt"

  strings:
    $a1 = "c:\\lq*" ascii fullword
    $a2 = "No IP address found for" wide
    $a3 = "Connecting with proxy" wide
    $a4 = "Started secure channel" wide
    $a5 = "ScreenConnect" wide

    $b1 = "CabinetWClass" wide fullword
    $b2 = "ExploreWClass" wide fullword

  condition:
    (uint16(0) == 0x5A4D)

    and filesize < 1MB

    and (2 of ($a*))

    and all of ($b*)
}

rule legit_ScreenConnect_DLL3 {
  meta:
    author = "Benjamin Mossé <contact@mosse-security.com>, Mossé Security"
    type = "Legitimate Software"
    filetype = "Win32 DLL"
    date = "2019/04/18"
    version = "0.1"
    sha256 = "0f34e137fe5dc344cb7c5cd8a319fabbdeeae4c05cb2c3d03066d76d076c72b1"
    reference = "https://krebsonsecurity.com/wp-content/uploads/2019/04/wiproiocs.txt"

  strings:
    $a1 = "sclzma.dll"ascii fullword
    $a2 = "zlibvc.dll" ascii fullword
    $a3 = "libwebp.dll" ascii fullword
    $a4 = "CharacteristicsUnionedWithOriginalFirstThunk" ascii
    $a5 = "TemporarilySwitchProcessToWindowStation" ascii

  condition:
    (uint16(0) == 0x5A4D)

    and filesize < 5MB

    and all of them
}

rule legit_ScreenConnect_DLL4 {
  meta:
    author = "Benjamin Mossé <contact@mosse-security.com>, Mossé Security"
    type = "Legitimate Software"
    filetype = "Win32 DLL"
    date = "2019/04/18"
    version = "0.1"
    sha256 = "5eeb493480e03ffde2f68b558f20848a776722c4bc014df7bfffb6164a3b388b"
    reference = "https://krebsonsecurity.com/wp-content/uploads/2019/04/wiproiocs.txt"

  strings:
    $a1 = "powershell.exe;cmd.exe" ascii
    $a2 = "CreateDecryptor" ascii
    $a3 = "CreateEncryptor" ascii
    $a4 = "filePathForMetadata" ascii

  condition:
    (uint16(0) == 0x5A4D)

    and filesize < 1MB

    and all of them
}