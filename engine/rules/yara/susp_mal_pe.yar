import "pe"

rule MAL_Hogfish_Report_Related_Sample {
   meta:
      description = "Detects APT10 / Hogfish related samples"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
      date = "2018-05-01"
      hash1 = "f9acc706d7bec10f88f9cfbbdf80df0d85331bd4c3c0188e4d002d6929fe4eac"
      hash2 = "7188f76ca5fbc6e57d23ba97655b293d5356933e2ab5261e423b3f205fe305ee"
      hash3 = "4de5a22cd798950a69318fdcc1ec59e9a456b4e572c2d3ac4788ee96a4070262"
      id = "7fc4fdda-b71f-5c9c-87a4-5d8290b99348"
   strings:
      $s1 = "R=user32.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.imphash() == "efad9ff8c0d2a6419bf1dd970bcd806d" or
         1 of them
      )
}



rule MAL_RedLeaves_Apr18_1 {
   meta:
      description = "Detects RedLeaves malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
      date = "2018-05-01"
      hash1 = "f6449e255bc1a9d4a02391be35d0dd37def19b7e20cfcc274427a0b39cb21b7b"
      hash2 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"
      hash3 = "d956e2ff1b22ccee2c5d9819128103d4c31ecefde3ce463a6dea19ecaaf418a1"
      id = "578b40d7-6818-56d5-92ce-535141c0aa8e"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.imphash() == "7a861cd9c495e1d950a43cb708a22985" or
         pe.imphash() == "566a7a4ef613a797389b570f8b4f79df"
      )
}


rule SUSP_ScheduledTasks_Nimbus_Manticore_Persistence_May26 {
   meta:
      description = "Detects scheduled task used for persistence by Nimbus Manticore (UNC1549). The task is used to persistenly load a custom implant that features data exfiltration and remote control capabilities."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-27"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      score = 75
   strings:
      $a0 = "<Task version=" wide
      $a1 = "xmlns=\"http://schemas.microsoft.com/windows/" wide

      $x1 = "<Arguments>doit" wide
   condition:
      uint16(0) == 0xfeff
      and all of them
}



rule MAL_APT_Nimbus_Manticore_Stager_May26 {
   meta:
      description = "Detects .NET based stager using AppDomain Hijacking observed to be used by Nimbus Manticore (UNC1549). The stager drops another payload and establishes persistence via scheduled task."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-20"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      hash = "eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71"
      score = 80
   strings:
      $x1 = "MyCompany-Product-TOTP-Salt-2024!@#$" wide fullword
      $x2 = "TOTPGuardRunner" ascii fullword
      $x3 = "\\AppDomainInjection-metlifeScenario\\TOTP" ascii

      $sa1 = "EncData" ascii fullword
      $sa2 = "DecryptAndSaveToDesktop" ascii fullword
      $sa3 = "CopyHelloToDesktop" ascii fullword

      $sb1 = "doit" wide fullword
      $sb2 = "DailyTrigger" wide fullword
      $sb3 = "GetTypeFromCLSID" ascii
      $sb4 = "yyyy-MM-ddTHH:mm:ss" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and
      (
         1 of ($x*)
         or all of ($sa*)
         or all of ($sb*)
      )
}



rule MAL_APT_Nimbus_Manticore_Agent_May26 {
   meta:
      description = "Detects Nimbus Manticore (UNC1549) agent implant featuring data exfiltration and remote control."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-28"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      hash = "dfa1e3137a032ee8561a1cd5e1a0f71a10bebb36aef7c336c878638a9c1239ee"
      score = 80
   strings:
      $a1 = "Chrome/146.0.0.0 Safari/537.36" wide
      $a2 = ".azurewebsites.net" wide

      $s1 = "/agent/poll?token=" wide fullword
      $s2 = "/agent/init" wide fullword
      $s3 = "/agent/result" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and 1 of ($a*) 
      and 1 of ($s*)
      or 3 of them
}



rule MAL_Sindoor_Decryptor_Aug25 {
   meta:
      description = "Detects AES decryptor used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 80
      reference = "Internal Research"
      hash = "9a1adb50bb08f5a28160802c8f315749b15c9009f25aa6718c7752471db3bb4b"
      id = "3c0c5217-b125-51a3-8129-30af5f0c7263"
   strings:
      $s1 = "Go build"
      $s2 = "main.rc4EncryptDecrypt"
      $s3 = "main.processFile"
      $s4 = "main.deriveKeyAES"
      $s5 = "use RC4 instead of AES"
   condition:
      filesize < 100MB
      and (
         uint16(0) == 0x5a4d // Windows
         or uint32be(0) == 0x7f454c46  // Linux
         or (uint32be(0) == 0xcafebabe and uint32be(4) < 0x20)  // Universal mach-O App with dont-match-java-class-file hack
         or uint32(0) == 0xfeedface  // 32-bit mach-O
         or uint32(0) == 0xfeedfacf  // 64-bit mach-O
      )
      and all of them
}



rule MAL_Sindoor_Downloader_Aug25 {
   meta:
      description = "Detects Sindoor downloader related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 80
      reference = "Internal Research"
      hash = "38b6b93a536cbab5c289fe542656d8817d7c1217ad75c7f367b15c65d96a21d4"
      id = "c1188abc-2bea-5cbc-a39d-9690626c0821"
   strings:
      $s1 = "Go build"
      $s2 = "main.downloadFile.deferwrap"
      $s3 = "main.decrypt"
      $s4 = "main.HiddenHome"
      $s5 = "main.RealCheck"
   condition:
      filesize < 100MB
      and (
         uint16(0) == 0x5a4d // Windows
         or uint32be(0) == 0x7f454c46  // Linux
         or (uint32be(0) == 0xcafebabe and uint32be(4) < 0x20)  // Universal mach-O App with dont-match-java-class-file hack
         or uint32(0) == 0xfeedface  // 32-bit mach-O
         or uint32(0) == 0xfeedfacf  // 64-bit mach-O
      )
      and all of them
}



rule MAL_PE_Type_BabyShark_Loader {
   meta:
      description = "Detects PE Type babyShark loader mentioned in February 2019 blog post by PaloAltNetworks"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/"
      date = "2019-02-24"
      hash1 = "6f76a8e16908ba2d576cf0e8cdb70114dcb70e0f7223be10aab3a728dc65c41c"
      id = "141e7a67-7930-5fd8-ac91-5d31b99e4ff3"
   strings:
      $x1 = "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Command Processor\" /v AutoRun /t REG_SZ /d \"%s\" /f" fullword ascii
      $x2 = /mshta\.exe http:\/\/[a-z0-9\.\/]{5,30}\.hta/

      $xc1 = { 57 69 6E 45 78 65 63 00 6B 65 72 6E 65 6C 33 32
               2E 44 4C 4C 00 00 00 00 } 
   condition:
      uint16(0) == 0x5a4d and (
         pe.imphash() == "57b6d88707d9cd1c87169076c24f962e" or
         1 of them or
         for any i in (0 .. pe.number_of_signatures) : (
            pe.signatures[i].issuer contains "thawte SHA256 Code Signing CA" and
            pe.signatures[i].serial == "0f:ff:e4:32:a5:3f:f0:3b:92:23:f8:8b:e1:b8:3d:9d"
         )
      )
}



rule MAL_Emdivi_Gen3 {
   meta:
      description = "Detects Emdivi Malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
      date = "2015-08-20"
      modified = "2023-01-06"
      super_rule = 1
      score = 80
      hash1 = "008f4f14cf64dc9d323b6cb5942da4a99979c4c7d750ec1228d8c8285883771e"
      hash2 = "a94bf485cebeda8e4b74bbe2c0a0567903a13c36b9bf60fab484a9b55207fe0d"
      id = "c3d712ae-3f8e-578c-81cd-fd3e48213875"
   strings:
      $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword ascii

      $s2 = "\\Mozilla\\Firefox\\Profiles\\" ascii
      $s4 = "\\auto.cfg" ascii
      $s5 = "/ncsi.txt" fullword ascii
      $s6 = "/en-us/default.aspx" fullword ascii
      $s7 = "cmd /c" fullword ascii
      $s9 = "APPDATA" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 850KB and
      (
         ( $x1 and 1 of ($s*) ) or
         ( 4 of ($s*) )
      )
}



rule MAL_DevilsTongue_HijackDll {
   meta:
      description = "Detects SOURGUM's DevilsTongue hijack DLL"
      author = "Microsoft Threat Intelligence Center (MSTIC)"
      date = "2021-07-15"
      reference = "https://www.microsoft.com/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/"
      score = 80
      id = "390b8b73-6740-513d-8c70-c9002be0ce69"
   strings:
      $str1 = "windows.old\\windows" wide
      $str2 = "NtQueryInformationThread"
      $str3 = "dbgHelp.dll" wide
      $str4 = "StackWalk64"
      $str5 = "ConvertSidToStringSidW"
      $str6 = "S-1-5-18" wide
      $str7 = "SMNew.dll" // DLL original name
      // Call check in stack manipulation
      // B8 FF 15 00 00   mov     eax, 15FFh
      // 66 39 41 FA      cmp     [rcx-6], ax
      // 74 06            jz      short loc_1800042B9
      // 80 79 FB E8      cmp     byte ptr [rcx-5], 0E8h ;
      $code1 = { B8 FF 15 00 00 66 39 41 FA 74 06 80 79 FB E8 }
      // PRNG to generate number of times to sleep 1s before exiting
      // 44 8B C0 mov r8d, eax
      // B8 B5 81 4E 1B mov eax, 1B4E81B5h
      // 41 F7 E8 imul r8d
      // C1 FA 05 sar edx, 5
      // 8B CA    mov ecx, edx
      // C1 E9 1F shr ecx, 1Fh
      // 03 D1    add edx, ecx
      // 69 CA 2C 01 00 00 imul ecx, edx, 12Ch
      // 44 2B C1 sub r8d, ecx
      // 45 85 C0 test r8d, r8d
      // 7E 19    jle  short loc_1800014D0
      $code2 = { 44 8B C0 B8 B5 81 4E 1B 41 F7 E8 C1 FA 05 8B CA C1 E9 1F 03 D1 69 CA 2C 01 00 00 44 2B C1 45 85 C0 7E 19 }
   condition:
      filesize < 800KB and
      uint16(0) == 0x5A4D and
      ( pe.characteristics & pe.DLL ) and
      (
         4 of them or
         ( $code1 and $code2 ) or
         pe.imphash() == "9a964e810949704ff7b4a393d9adda60"
      )
}


rule MAL_Cisco_RayInitiator_Stage_3_LINE_VIPER_ShellCode {
   meta:
      author = "NCSC"
      description = "Detects RayInitiator GRUB bootkit stage 3 deploy phase code that copies LINE VIPER shellcode stub and marks executable."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      id = "91545ed8-b798-5c0c-a229-e7d37ed7d271"
   strings:
      $xc1 = {
         48 89 FA 48 83 C7 40 4C 89 CE B9 D0 01 00 00 F3 A4 48
         89 D7 48 83 C7 40 48 89 3A 48 C1 EF 0C 48 C1 E7 0C BA
         07 00 00 00 48 C7 C6 00 20 00 00
      }
   condition:
      $xc1
}



rule MAL_Cisco_LINE_VIPER_Shellcode_Deobfuscation_Routine {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of a shellcode deobfuscation routine."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
      id = "608282b5-f296-5d21-b88b-92cd53128d89"
   strings:
      $xc1 = {
         48 8B 7F 08 48 8D 5F 70 49 C7 C1 00 18 00 00 49 C7 C0
         20 00 00 00 48 89 DF 8A 01 32 07 48 FF C7 41 FF C8 4D 85 C0 75 F3
         88 01 48 FF C1 41 FF C9 4D 85 C9 75 DA
      }
      $x1 = "SIt/CEiNX3BJx8EAGAAAScfAIAAAAEiJ34oBMgdI/8dB/8hNhcB184gBSP/BQf/JTYXJdd"
      $x2 = "iLfwhIjV9wScfBABgAAEnHwCAAAABIid+KATIHSP/HQf/ITYXAdfOIAUj/wUH/yU2FyXXa"
      $x3 = "Ii38ISI1fcEnHwQAYAABJx8AgAAAASInfigEyB0j/x0H/yE2FwHXziAFI/8FB/8lNhcl12"
   condition:
      1 of them
}



rule MAL_Cisco_LINE_VIPER_Shellcode_Initial_Execution {
   meta:
      author = "NCSC (modifier by Florian Roth)"
      description = "Detects LINE VIPER Cisco ASA malware code as part of shellcode initial execution."
      date = "2025-09-25"
      modified = "2025-09-27"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
      id = "ca88eff7-bf0d-5959-b614-1afb6d68879e"
   strings:
      $xc1 = {
         48 8D B7 80 00 00 00 BA 00 20 00 00 [19] 48 C7 C6 00
         90 00 00 BA 07 00 00 00
      }
      // $x1 = /SI23gAAAALoAIAAA[A-Za-z0-9+\/]{26}jHxgCQAAC6BwAAA/
      // $x2 = /iNt4AAAAC6ACAAA[A-Za-z0-9+\/]{26}Ix8YAkAAAugcAAA/
      // $x3 = /IjbeAAAAAugAgAA[A-Za-z0-9+\/]{26}SMfGAJAAALoHAAAA/
      $xe1 = { 53 49 32 33 67 41 41 41 41 4c 6f 41 49 41 41 41 [26] 6a 48 78 67 43 51 41 41 43 36 42 77 41 41 41 }
      $xe2 = { 69 4e 74 34 41 41 41 41 43 36 41 43 41 41 41 [26] 49 78 38 59 41 6b 41 41 41 75 67 63 41 41 41 }
      $xe3 = { 49 6a 62 65 41 41 41 41 41 75 67 41 67 41 41 [26] 53 4d 66 47 41 4a 41 41 41 4c 6f 48 41 41 41 41 }
   condition:
      1 of them
}



rule MAL_Cisco_LINE_VIPER_RSA_Enc_Random_AES_Key_Gen {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of RSA encrypted random AES key generation."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
      id = "ef37a3cf-aab8-513b-b859-7f7704fce622"
   strings:
      $xc1 = {
         48 31 C0 49 89 06 49 89 46 08 49 83 C6 10 49 83 ED 10
         4D 85 ED 75 D8 BF 30 00 00 00
      }
      $xc2 = {
         0F 85 57 01 00 00 49 8B 44 24 08 48 83 F8 2F 7C 33 41
         BD F0 02 00 00 4D 8D 74 24 10 49 8B 3E
      }
      $xc3 = {
         85 C0 0F 8E EE 00 00 00 41 BD F0 02 00 00 4D 8D 7C 24
         10 49 8B 3F 48 85 FF 74 0D 49 83 C7 10 49 83 ED 10 4D 85 ED 75 EB
         4D 89 37 BF 70 00 00 00
      }
      $xc4 = {
         48 85 C0 0F 84 3F 00 00 00 48 89 45 B0 BF 80 00 00 00
         4C 89 EE 48 89 C2 48 8B 4D A8 41 B8 01 00 00 00
      }
   condition:
      1 of them
}



rule MAL_Cisco_LINE_VIPER_AES_Enc_Tasking_Exfil {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of AES encrypted tasking and exfiltration."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
      id = "9f3d77a6-3e31-588c-a65d-f1f9d9bc84df"
   strings:
      $ = {
         48 31 C0 48 89 45 D8 49 89 FC 49 89 F5 49 89 D6 48 8B
         47 08 48 89 45 B8 48 8D 40 40 48 89 45 E0 48 8D 70 E0 48 89 75 B0
         48 8D 78 F0 48 89 7D E8 BA 10 00 00 00
      }
      $ = {
         48 85 C0 0F 84 EA 00 00 00 48 89 45 A8 4C 89 EF 48 89
         C6 4C 89 F2 48 8B 4D A0 4C 8B 45 B0 4D 31 C9
      }
      $ = {
         48 85 C0 0F 84 82 00 00 00 49 89 C7 48 8B 7D E0 BE 00
         01 00 00 48 8B 55 A0
      }
      $ = {
         48 8B 7D D0 49 83 C7 10 49 C1 EF 04 49 C1 E7 04 4C 89
         FE 48 8D 55 D8
      }
   condition:
      3 of them
}



rule MAL_Cisco_LINE_VIPER_ICMP_Tasking_Shellcode_Payloads {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of ICMP tasking shellcode payloads."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
      id = "7f8df075-8ed6-5d24-9743-cf3da9a48ec4"
   strings:
      $ = {
         55 53 41 54 41 55 41 56 41 57 48 89 E5 48 83 EC 60 48
         31 C0 B9 07 00 00 00 48 8D 7D A8 F3 48 AB BF 01 00 00
         00 BE 30 00 00 00
      }
      $ = {
         49 89 C7 48 C7 C2 38 DF FF FF 64 48 8B 0A 48 8B 99 00
         01 00 00 48 89 81 00 01 00 00
      }
      $ = {
         49 8B 47 10 48 8D 55 B0 BE 01 20 01 00 4C 89 FF FF 90
         90 00 00 00 48 8B 7D B0 48 85 FF 0F 84 3C 00 00 00
      }
      $ = {
         49 8B 47 10 BE 08 20 01 00 4C 89 FF 48 8D 55 A8 FF 90
         90 00 00 00 48 8B 7D B0 49 89 7E 20 48 8B 7D A8 49 89
         7E 28
      }
   condition:
      3 of them
}


rule MAL_G_Dropper_BRICKSTEAL_1 {
   meta:
      description = "Detects backdoor BRICKSTEAL dropper used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
      id = "c96eeeb0-ccb4-572c-80b5-638ce3bb51a9"
   strings:
      $str1 = "Base64.getDecoder().decode"
      $str2 = "Thread.currentThread().getContextClassLoader()"
      $str3 = ".class.getDeclaredMethod"
      $str4 = "byte[].class"
      $str5 = "method.invoke"
      $str6 = "filterClass.newInstance()"
      $str7 = "/websso/SAML2/SSO/*"
   condition:
      all of them
}



rule MAL_G_Dropper_BRICKSTEAL_2 {
   meta:
      description = "Detects backdoor BRICKSTEAL dropper used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
      id = "8139f8c0-4c18-51bd-bf23-8c4cdc3fd555"
   strings:
      // $str1 = /\(Class<\?>\)\smethod\.invoke\(\w{1,20},\s\w{1,20},\s0,\s\w{1,20}\.length\);/i ascii wide
      $str1_alt = "(Class<?>) method.invoke(" ascii wide
      $str2 = "(\"yv66vg" ascii wide
      $str3 = "request.getSession().getServletContext" ascii wide
      $str4 = ".getClass().getDeclaredField(" ascii wide
      $str5 = "new FilterDef();" ascii wide
      $str6 = "new FilterMap();" ascii wide
   condition:
      all of them
}


rule MAL_Netfilter_Dropper_Jun_2021_1 {
   meta:
        description = "Detects the dropper of Netfilter rootkit"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/struppigel/status/1405483373280235520"
        date = "2020-06-18"
        hash1 = "a5c873085f36f69f29bb8895eb199d42ce86b16da62c56680917149b97e6dac"
        hash2 = "659e0d1b2405cadfa560fe648cbf6866720dd40bb6f4081d3dce2dffe20595d9"
        hash3 = "d0a03a8905c4f695843bc4e9f2dd062b8fd7b0b00103236b5187ff3730750540"
        tlp = "White"
        adversary = "Chinese APT Group"
        id = "d91f48aa-9580-572d-a72c-19b80624cdbe"
   strings:
        $seq1 = { b8 ff 00 00 00 50 b8 00 00 00 00 50 8d 85 dd fe ff ff 50 e8 ?? 0d 00 00 83 c4 0c b8 00 00 00 00 88 85 dc fd ff ff b8 ff 00 00 00 50 b8 00 00 00 00 50 8d 85 dd fd ff ff 50 e8 ?? 0d 00 00 83 c4 0c b8 00 00 50 00 50 e8 ?? 0d 00 00 83 c4 04 89 85 d8 fd ff ff 8b 85 d8 fd ff ff 89 85 d4 fd ff ff b8 00 00 50 00 50 b8 00 00 00 00 50 8b 85 d8 fd ff ff 50 e8 ?? 0c 00 00 83 c4 0c 8b 45 0c 8b 8d d8 fd ff ff 89 08 b8 3c 00 00 00 50 b8 00 00 00 00 50 8d 85 98 fd ff ff 50 e8 ?? 0c 00 00 83 c4 0c b8 3c 00 00 00 89 85 98 fd ff ff 8d 85 98 fd ff ff 83 c0 10 8d 8d dc fe ff ff 89 08 8d 85 98 fd ff ff 83 c0 14 b9 00 01 00 00 89 08 8d 85 98 fd ff ff 83 c0 2c 8d 8d dc fd ff ff 89 08 8d 85 98 fd ff ff 83 c0 30 b9 00 01 00 00 89 08 b8 0a 31 40 00 50 e8 ?? 0c 00 00 89 85 94 fd ff ff b8 16 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0c 00 00 89 45 fc b8 28 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0c 00 00 89 45 f8 b8 36 31 40 00 50 8b 85 94 fd ff ff 50 e8 [2] 00 00 89 45 f4 b8 47 31 40 00 50 8b 85 94 fd ff ff 50 e8 [2] 00 00 89 45 f0 b8 58 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 ec b8 69 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e8 b8 7a 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e4 b8 8e 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e0 8b 45 08 50 e8 ?? 0b 00 00 83 c4 04 8d 8d 98 fd ff ff 51 b9 00 00 00 00 51 50 8b 45 08 50 8b 45 fc ff d0 85 }
        $seq2 =  { b8 00 00 00 00 89 85 90 fd ff ff b8 00 00 00 00 89 85 8c fd ff ff b8 00 00 00 00 89 85 88 fd ff ff b8 00 00 00 00 89 85 84 fd ff ff b8 04 00 00 00 89 85 80 fd ff ff b8 00 00 00 00 88 85 7f f5 ff ff b8 00 08 00 00 50 b8 00 00 00 00 50 8d 85 80 f5 ff ff 50 e8 ?? 0b 00 00 83 c4 0c b8 00 00 00 00 50 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 9d 31 40 00 50 8b 45 f8 ff d0 89 85 90 fd ff ff 8b 85 }
        $s1 = "%s\\netfilter.sys" fullword ascii
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\netfilter" fullword ascii
        $s3 = "\\\\.\\netfilter" fullword ascii
   condition:
        uint16(0) == 0x5a4d 
        and filesize > 6KB and filesize < 1000KB
        and (all of ($seq*) or 2 of ($s*))
}



rule MAL_Netfilter_May_2021_1 {
   meta:
        description = "Detects Netfilter rootkit"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/struppigel/status/1405483373280235520"
        date = "2020-06-18"
        hash1 = "63d61549030fcf46ff1dc138122580b4364f0fe99e6b068bc6a3d6903656aff0"
        hash2 = "8249e9c0ac0840a36d9a5b9ff3e217198a2f533159acd4bf3d9b0132cc079870"
        hash3 = "d64f906376f21677d0585e93dae8b36248f94be7091b01fd1d4381916a326afe"
        tlp = "White"
        adversary = "Chinese APT Group"
        id = "0ac01eb3-435b-52b0-b8e8-ace2ebb34f60"
   strings:
        $seq1 = { 48 8b 05 a9 57 ff ff 45 33 c9 49 b8 32 a2 df 2d 99 2b 00 00 48 85 c0 74 05 49 3b c0 75 38 0f 31 48 c1 e2 20 48 8d 0d 85 57 ff ff 48 0b c2 48 33 c1 48 89 05 78 57 ff ff 66 44 89 0d 76 57 ff ff 48 8b 05 69 57 ff ff 48 85 c0 75 0a 49 8b c0 48 89 05 5a 57 ff ff 48 f7 d0 48 89 05 58 57 }
        $seq2 = { 48 83 ec 38 48 83 64 24 20 00 48 8d 05 83 4c 00 00 48 8d 15 24 d1 00 00 48 89 44 24 28 48 8d 4c 24 20 e8 4d 05 00 00 85 c0 78 16 4c 8d 05 22 d1 00 00 83 ca ff 48 8d 0d 00 d1 00 00 e8 39 05 00 00 48 83 c4 }
        $seq3 = { 45 33 c0 48 8d 4c 24 40 41 8d 50 01 ff 15 5d 62 00 00 c6 84 24 88 00 00 00 01 48 8d 84 24 88 00 00 00 48 89 46 18 48 8d 0d e2 fe ff ff 48 89 9e c0 00 00 00 48 8d 44 24 40 48 89 46 50 48 8d 44 24 30 48 89 46 48 65 48 8b 04 25 88 01 00 00 48 89 86 98 00 00 00 48 8b 86 b8 00 00 00 40 88 7e 40 c6 40 b8 06 4c 89 78 e0 48 89 58 e8 c7 40 c0 01 00 00 00 c7 40 c8 0d 00 00 00 48 89 58 d0 48 8b 86 b8 00 00 00 48 89 48 f0 48 8d 4c 24 40 48 89 48 f8 c6 40 bb e0 48 8b 43 28 48 85 c0 74 2f 48 8b 48 10 48 85 c9 74 07 48 21 78 10 4c 8b f1 48 8b 08 48 85 c9 74 06 48 21 38 48 8b e9 48 8b 48 08 48 85 c9 74 08 48 83 60 08 00 48 8b f9 48 8b d6 49 8b cf ff 15 74 61 00 00 3d 03 01 00 00 75 19 48 83 64 24 20 00 48 8d 4c 24 40 41 b1 01 45 33 c0 33 d2 ff 15 64 61 00 00 48 8b 43 28 48 85 c0 74 1a 4d }
        $seq4 = { 8b 84 24 80 00 00 00 48 8d 54 24 38 48 8b 4c 24 30 44 8b ce 89 44 24 28 45 33 c0 48 89 7c 24 20 ff 15 66 2e 00 00 48 8b 4c 24 30 8b d8 ff 15 49 2e 00 00 48 8b 4c 24 30 ff 15 26 2d 00 00 8b }
        $s1 = "%sc=%s" fullword ascii
        $s2 = { 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 }
        $s3 = "NETIO.SYS" fullword ascii
   condition:
        uint16(0) == 0x5a4d 
        and filesize > 20KB and filesize < 1000KB
        and (3 of ($seq*) or 2 of ($s*))
}

rule MAL_DNSPIONAGE_Malware_Nov18 {
   meta:
      description = "Detects DNSpionage Malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html"
      date = "2018-11-30"
      modified = "2023-01-06"
      hash1 = "2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec"
      hash2 = "45a9edb24d4174592c69d9d37a534a518fbe2a88d3817fc0cc739e455883b8ff"
      id = "5a0b498b-b2e9-5827-9908-63586b2cf947"
   strings:
      $x1 = ".0ffice36o.com" ascii

      $s1 = "/Client/Login?id=" ascii
      $s2 = ".\\Configure.txt" ascii
      $s5 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii
      $s6 = "Content-Disposition: form-data; name=\"txts\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 2 of them )
}



rule MAL_ME_RawDisk_Agent_Jan20_1 {
   meta:
      description = "Detects suspicious malware using ElRawDisk"
      author = "Florian Roth (Nextron Systems)"
      reference = "Saudi National Cybersecurity Authority - Destructive Attack DUSTMAN"
      date = "2020-01-02"
      modified = "2022-12-21"
      hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
      id = "0efaae51-1407-5039-9e5a-9c2f13d6a971"
   strings:
      $x1 = "\\drv\\agent.plain.pdb" ascii
      $x2 = " ************** Down With Saudi Kingdom, Down With Bin Salman ************** " fullword ascii

      $s1 = ".?AVERDError@@" fullword ascii
      $s2 = "b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d" fullword wide
      $s3 = "\\\\?\\ElRawDisk" fullword wide
      $s4 = "\\??\\c:" wide

      $op1 = { e9 3d ff ff ff 33 c0 48 89 05 0d ff 00 00 48 8b }
      $op2 = { 0f b6 0c 01 88 48 34 48 8b 8d a8 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and ( 1 of ($x*) or 4 of them )
}



rule MAL_ME_RawDisk_Agent_Jan20_2 {
   meta:
      description = "Detects suspicious malware using ElRawDisk"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/jfslowik/status/1212501454549741568?s=09"
      date = "2020-01-02"
      modified = "2022-12-21"
      hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
      id = "9817fb22-7bed-5869-aa92-66c458b81c7f"
   strings:
      $x1 = "\\Release\\Dustman.pdb" ascii
      $x2 = "/c agent.exe A" fullword ascii

      $s1 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $s2 = "The Magic Word!" fullword ascii
      $s3 = "Software\\Oracle\\VirtualBox" fullword wide
      $s4 = "\\assistant.sys" wide
      $s5 = "Down With Bin Salman" fullword wide

      $sc1 = { 00 5C 00 5C 00 2E 00 5C 00 25 00 73 }

      $op1 = { 49 81 c6 ff ff ff 7f 4c 89 b4 24 98 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 3000KB and ( 1 of ($x*) or 3 of them )
}


rule MAL_ExileRAT_Feb19_1 {
   meta:
      description = "Detects Exile RAT"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.talosintelligence.com/2019/02/exilerat-shares-c2-with-luckycat.html"
      date = "2019-02-04"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3eb026d8b778716231a07b3dbbdc99e2d3a635b1956de8a1e6efc659330e52de"
      id = "f0a510f3-5fea-59a7-8991-9d06dc478b2a"
   strings:
      $x1 = "Content-Disposition:form-data;name=\"x.bin\"" fullword ascii

      $s1 = "syshost.dll" fullword ascii
      $s2 = "\\scout\\Release\\scout.pdb" ascii
      $s3 = "C:\\data.ini" fullword ascii
      $s4 = "my-ip\" value=\"" fullword ascii
      $s5 = "ver:%d.%d.%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "da8475fc7c3c90c0604ce6a0b56b5f21" or
         3 of them
      )
}


rule SUSP_VEST_Encryption_Core_Accumulator_Jan21 {
   meta:
      description = "Detects VEST encryption core accumulator in PE file as used by Lazarus malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ochsenmeier/status/1354737155495649280"
      date = "2021-01-28"
      score = 70
      hash1 = "7cd3ca8bdfb44e98a4b9d0c6ad77546e03d169bda9bdf3d1bcf339f68137af23"
      id = "8343652b-8865-5213-b735-d6d4084e4a84"
   strings:
      $sc1 = { 4F 70 46 DA E1 8D F6 41 59 E8 5D 26 1E CC 2F 89
               26 6D 52 BA BC 11 6B A9 C6 47 E4 9C 1E B6 65 A2
               B6 CD 90 47 1C DF F8 10 4B D2 7C C4 72 25 C6 97
               25 5D C6 1D 4B 36 BC 38 36 33 F8 89 B4 4C 65 A7
               96 CA 1B 63 C3 4B 6A 63 DC 85 4C 57 EE 2A 05 C7
               0C E7 39 35 8A C1 BF 13 D9 52 51 3D 2E 41 F5 72
               85 23 FE A1 AA 53 61 3B 25 5F 62 B4 36 EE 2A 51
               AF 18 8E 9A C6 CF C4 07 4A 9B 25 9B 76 62 0E 3E
               96 3A A7 64 23 6B B6 19 BC 2D 40 D7 36 3E E2 85
               9A D1 22 9F BC 30 15 9F C2 5D F1 23 E6 3A 73 C0 }
   condition:
      uint16(0) == 0x5a4d and
      1 of them
}


rule MAL_MuddyWater_DroppedTask_Jun18_1 {
   meta:
      description = "Detects a dropped Windows task as used by MudyWater in June 2018"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/719c94eb-0a00-47cc-b583-ad4f9e25ebdb"
      date = "2018-06-12"
      hash1 = "7ecc2e1817f655ece2bde39b7d6633f4f586093047ec5697a1fab6adc7e1da54"
      id = "d9ef379d-161f-59f1-873e-3af12b24b76b"
   strings:
      $x1 = "%11%\\scrobj.dll,NI,c:" wide

      $s1 = "AppAct = \"SOFTWARE\\Microsoft\\Connection Manager\"" fullword wide
      $s2 = "[DefenderService]" fullword wide
      $s3 = "UnRegisterOCXs=EventManager" fullword wide
      $s4 = "ShortSvcName=\" \"" fullword wide
   condition:
      uint16(0) == 0xfeff and filesize < 1KB and ( 1 of ($x*) or 3 of them )
}


rule MAL_Backdoor_Naikon_APT_Sample1 {
   meta:
      description = "Detects backdoors related to the Naikon APT"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/7vHyvh"
      date = "2015-05-14"
		modified = "2023-01-06"
      hash = "d5716c80cba8554eb79eecfb4aa3d99faf0435a1833ec5ef51f528146c758eba"
      hash = "f5ab8e49c0778fa208baad660fe4fa40fc8a114f5f71614afbd6dcc09625cb96"
      id = "ba79285b-7c7f-5b19-837e-6696e50a2866"
   strings:
      $x0 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
      $x1 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
      $x2 = "greensky27.vicp.net" fullword ascii
      $x3 = "\\tempvxd.vxd.dll" wide
      $x5 = "otna.vicp.net" fullword ascii

      $s1 = "User-Agent: webclient" fullword ascii
      $s2 = "\\User.ini" ascii
      $s3 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200" ascii
      $s4 = "\\UserProfile.dll" wide
      $s5 = "Connection:Keep-Alive: %d" fullword ascii
      $s6 = "Referer: http://%s:%d/" ascii
      $s7 = "%s %s %s %d %d %d " fullword ascii
      $s8 = "%s--%s" fullword wide
      $s9 = "Run File Success!" fullword wide
      $s10 = "DRIVE_REMOTE" fullword wide
      $s11 = "ProxyEnable" fullword wide
      $s12 = "\\cmd.exe" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      (
         1 of ($x*) or 7 of ($s*)
      )
}

rule MAL_APT_NK_TriFaux_EasyRAT_JUPITER {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the EasyRAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "8bd72287-59da-53cf-9015-66149303e59f"
   strings:
      $InitOnce = "InitOnceExecuteOnce"
      $BREAK = { 0D 00 0A 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 0D 00 0A }
      $Bytes = "4C,$00,$00,$00,$01,$14,$02,$00,$00,$00,$00,$00,$C0,$00,$00,$00,$00,$00,$00," wide
   condition:
      uint16(0) == 0x5a4d
      and all of them
}



rule MAL_APT_NK_Andariel_CutieDrop_MagicRAT {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects the MagicRAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "104244de-83fb-5112-a2b6-e20d38a6ced6"
   strings:
      // I removed the 'wide' from the strings because the samples don't contain the strings
      // UTF-16 formatted and there's no indication that they ever will be, F.R.

      $config_os_w = "os/windows" ascii
      $config_os_l = "os/linux" ascii
      $config_os_m = "os/mac" ascii
      $config_comp_msft = "company/microsoft" ascii
      $config_comp_orcl = "company/oracle" ascii
      $POST_field_1 = "session=" ascii
      $POST_field_2 = "type=" ascii
      // $POST_field_3 = "id=" ascii wide  // disabled this string because it's too short
      $command_misspelled = "renmae" ascii
   condition:
      uint16(0) == 0x5a4d
      and 7 of them
}



rule MAL_APT_NK_Andariel_HHSD_FileTransferTool {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the HHSD File Transfer Tool"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2025-07-09"
      score = 70
      id = "46b6dbaf-1272-5bbd-a586-5e48ba6c5022"
   strings:
      // 30 4D C7                xor     [rbp+buffer_v41+3], cl
      // 81 7D C4 22 C0 78 00    cmp      dword ptr [rbp+buffer_v41], 78C022h
      // 44 88 83 00 01 00 00    mov      [rbx+100h], r8b
      $handshake = { 30 ?? ?? 81 7? ?? 22 C0 78 00 4? 88 }

      // B1 14                   mov     cl, 14h
      // C7 45 F7 14 00 41 00    mov      [rbp+57h+Src], 410014h
      // C7 45 FB 7A 00 7F 00    mov      [rbp+57h+var_5C], 7F007Ah
      // C7 45 FF 7B 00 63 00    mov     [rbp+57h+var_58], 63007Bh
      // C7 45 03 7A 00 34 00    mov      [rbp+57h+var_54], 34007Ah
      // C7 45 07 51 00 66 00    mov      [rbp+57h+var_50], 660051h
      // C7 45 0B 66 00 7B 00    mov      [rbp+57h+var_4C], 7B0066h
      // C7 45 0F 66 00 00 00    mov      [rbp+57h+var_48], 66h ; 'f'
      $err_xor_str = { 14 C7 [2] 14 00 41 00 C7 [2] 7A 00 7F 00 C7 [2] 7B 00 63 00 C7 [2] 7A 00 34 00 }

      // 41 02 D0                add     dl, r8b
      // 44 02 DA                add     r11b, dl
      // 3C 1F                   cmp     al, 1Fh
      // $buf_add_cmp_1f = { 4? 02 ?? 4? 02 ?? 3? 1F }      removed due to 1 byte atom
      // B9 8D 10 B7 F8          mov     ecx, 0F8B7108Dh
      // E8 F1 BA FF FF          call    sub_140001280
      $hash_call_loadlib = { B? 8D 10 B7 F8 E8 }
      $hash_call_unk = { B? 91 B8 F6 88 E8 }
   condition:
      uint16(0) == 0x5a4d
      and 1 of ($handshake, $err_xor_str)
      and 1 of ($hash_call_*)
      or 2 of ($handshake, $err_xor_str)
}



rule MAL_APT_NK_Andariel_Atharvan_3RAT {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the Atharvan 3RAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "9ff6998a-a2dd-5671-bd3f-ee69561f71ef"
   strings:
      $3RAT = "D:\\rang\\TOOL\\3RAT"
      $atharvan = "Atharvan_dll.pdb"
   condition:
      uint16(0) == 0x5a4d
      and 1 of them
}



rule MAL_APT_NK_Andariel_LilithRAT_Variant {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects a variant of the Lilith RAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 80
      id = "916a289b-db7b-5f09-9d3e-589c3f09101d"
   strings:
      // I removed the 'wide' from the strings because the samples don't contain the strings
      // UTF-16 formatted and there's no indication that they ever will be, F.R.

      // The following are strings seen in the open source version of Lilith
      $lilith_1 = "Initiate a CMD session first." ascii
      $lilith_2 = "CMD is not open" ascii
      $lilith_3 = "Couldn't write command" ascii
      $lilith_4 = "Couldn't write to CMD: CMD not open" ascii

      // The following are strings that appear to be unique to the Unnamed Trojan based on Lilith
      $unique_1 = "Upload Error!" ascii
      $unique_2 = "ERROR: Downloading is already running!" ascii
      $unique_3 = "ERROR: Unable to open file:" ascii
      $unique_4 = "General error" ascii
      $unique_5 = "CMD error" ascii
      $unique_6 = "killing self" ascii
   condition:
      // I refactored the condition to make it more generic, F.R.
      uint16(0) == 0x5a4d
      and filesize < 150KB
      and (
         all of ($lilith_*)
         or 4 of ($unique_*)
         or 1 of ($lilith_4, $unique_2)  // both strings are very specific - let's use them as a unique indicator, F.R.
      )
}



rule MAL_APT_NK_Andariel_SocksTroy_Strings_OpCodes {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the SocksTroy malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "9e7fb6ba-771e-5cae-a0d5-c0b95ee6d4e9"
   strings:
      $strHost = "-host" wide
      $strAuth = "-auth" wide
      $SocksTroy = "SocksTroy"
      $cOpCodeCheck = { 81 E? A0 00 00 00 0F 84 ?? ?? ?? ?? 83 E? 03 74 ?? 83 E? 02 74 ?? 83 F? 0B }
   condition:
      uint16(0) == 0x5a4d and (
         1 of ($str*)
         and all of ($c*)
         or all of ($Socks*)
      )
}



rule MAL_APT_NK_Andariel_Agni {
   meta:
      author = "CISA.gov"
      description = "Detects samples of the Agni malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "ffe3f427-c10a-5ad4-ab29-c0d9b576c30f"
   strings:
      $xor = { 34 ?? 88 01 48 8D 49 01 0F B6 01 84 C0 75 F1 }
      $stackstrings = { C7 44 24 [5-10] C7 44 24 [5] C7 44 24 [5-10] C7 44 24 [5-10] C7 44 24 }
   condition:
      uint16(0) == 0x5a4d
      and #xor > 100
      and #stackstrings > 5
}



rule MAL_APT_NK_Andariel_TigerRAT_Crowdsourced_Rule {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects the Tiger RAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 75
      id = "6be65222-7d3c-5ff5-a9c7-d91dcf1deaa6"
   strings:
      $m1 = ".?AVModuleKeyLogger@@" fullword ascii
      $m2 = ".?AVModulePortForwarder@@" fullword ascii
      $m3 = ".?AVModuleScreenCapture@@" fullword ascii
      $m4 = ".?AVModuleShell@@" fullword ascii

      $s1 = "\\x9891-009942-xnopcopie.dat" fullword wide
      $s2 = "(%02d : %02d-%02d %02d:%02d:%02d)--- %s[Clipboard]" fullword ascii
      $s3 = "[%02d : %02d-%02d %02d:%02d:%02d]--- %s[Title]" fullword ascii
      $s4 = "del \"%s\"%s \"%s\" goto " ascii
   // $s5 = "[<<]" fullword ascii  // we don't need that short string and the rule probably doesn't lose anything without it, F.R.
   condition:
      uint16(0) == 0x5a4d and (
         all of ($s*) or (
            all of ($m*) and 1 of ($s*)
         )
         or (
            2 of ($m*) and 2 of ($s*)
         )
      )
}



rule MAL_APT_NK_WIN_Tiger_RAT_Auto {
   meta:
      author = "CISA.gov"
      description = "Detects the Tiger RAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 75
      id = "4579af62-52be-5f5f-a577-16ec50297c05"
   strings:
      $sequence_0 = { 33 c0 89 44 24 38 89 44 24 30 44 8b cf 45 33 c0 }
      // n = 5, score = 200
      //   33c0                 | jmp                 5
      //   89442438             | dec                 eax
      //   89442430             | mov                 eax, ecx
      //   448bcf               | movzx               eax, byte ptr [eax]
      //   4533c0               | dec                 eax

      $sequence_1 = { 41 b9 01 00 00 00 48 8b d6 48 8b cb e8 ?? ?? ?? ?? }
      // n = 4, score = 200
      //   41b901000000         | dec                 eax
      //   488bd6                | mov                 eax, dword ptr [ecx]
      //   488bcb               | jmp                 8
      //   e8????????           |                     

      $sequence_2 = { 48 81 ec 90 05 00 00 8b 01 89 85 c8 04 00 00 8b 41 04 }
      // n = 4, score = 200
      //   4881ec90050000       | test                eax, eax
      //   8b01                 | jns                 0x16
      //   8985c8040000         | dec                 eax
      //   8b4104               | mov                 eax, dword ptr [ecx]

      $sequence_3 = { 48 8b 01 ff 10 48 8b 4f 08 4c 8d 4c 24 30 }
      // n = 4, score = 200
      //   488b01               | mov                 edx, esi
      //   ff10                 | dec                 eax
      //   488b4f08             | mov                 ecx, ebx
      //   4c8d4c2430           | inc                 ecx

      $sequence_4 = { 48 8b 01 ff 10 48 8b 4e 18 48 8b 01 }
      // n = 4, score = 200
      //   488b01               | dec                 eax
      //   ff10                 | cmp                 dword ptr [ecx + 0x18], 0x10
      //   488b4e18             | dec                 eax
      //   488b01               | sub                 esp, 0x590

      $sequence_5 = { 48 81 ec a0 00 00 00 33 c0 48 8b d9 48 8d 4c 24 32 }
      // n = 4, score = 200
      //   4881eca0000000       | mov                 eax, dword ptr [ecx]
      //   33c0                 | mov                 dword ptr [ebp + 0x4c8], eax
      //   488bd9               | mov                 eax, dword ptr [ecx + 4]
      //   488d4c2432           | mov                 dword ptr [ebp + 0x4d0], eax

      $sequence_6 = { 48 8b 01 eb 03 48 8b c1 0f b6 00 }
      // n = 4, score = 200
      //   488b01               | inc                 ecx
      //   eb03                 | mov                 ebx, dword ptr [ebp + ebp]
      //   488bc1               | inc                 ecx
      //   0fb600               | movups              xmmword ptr [edi], xmm0

      $sequence_7 = { 48 8b 01 8b 10 89 51 24 44 8b 41 24 45 85 c0 }
      // n = 5, score = 200
      //   488b01               | sub                 esp, 0x30
      //   8b10                 | dec                 ecx
      //   895124               | mov                 ebx, eax
      //   448b4124             | dec                 eax
      //   4585c0               | mov                 ecx, eax

      $sequence_8 = { 4c 8d 0d 31 eb 00 00 c1 e9 18 c1 e8 08 41 bf 00 00 00 80 }
      // n = 4, score = 100
      //   4c8d0d31eb0000       | jne                 0x1e6
      //   c1e918               | dec                 eax
      //   c1e808               | lea                 ecx, [0xbda0]
      //   41bf00000080         | dec                 esp

      $sequence_9 = { 48 8b d8 48 85 c0 75 2d ff 15 ?? ?? ?? ?? 83 f8 57 0f 85 e0 01 00 00 48 8d 0d a0 bd 00 00 }
      // n = 7, score = 100
      //   488bd8               | dec                 eax
      //   4885c0               | mov                 ebx, eax
      //   752d                 | dec                 eax
      //   ff15????????         |                     
      //   83f857               | test                eax, eax
      //   0f85e0010000         | jne                 0x2f
      //   488d0da0bd0000       | cmp                  eax, 0x57

      $sequence_10 = { 75 d4 48 8d 1d 7f 6c 01 00 48 8b 4b f8 48 85 c9 74 0b }
      // n = 5, score = 100
      //   75d4                 | lea                 ecx, [0xeb31]
      //   488d1d7f6c0100       | shr                 ecx, 0x18
      //   488b4bf8             | shr                 eax, 8
      //   4885c9               | inc                 ecx
      //   740b                 | mov                 edi, 0x80000000

      $sequence_11 = { 0f 85 d9 00 00 00 48 8d 15 d0 c9 00 00 41 b8 10 20 01 00 48 8b cd e8 ?? ?? ?? ?? eb 6b b9 f4 ff ff ff }
      // n = 7, score = 100
      //   0f85d9000000         | jne                 0xffffffd6
      //   488d15d0c90000       | dec                 eax
      //   41b810200100         | lea                 ebx, [0x16c7f]
      //   488bcd               | dec                 eax
      //   e8????????           |                     
      //   eb6b                 | mov                 ecx, dword ptr [ebx - 8]
      //   b9f4ffffff           | dec                 eax

      $sequence_12 = { 48 89 0d ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8d 05 ae 61 00 00 48 89 05 ?? ?? ?? ?? 48 8d 05 a0 55 00 00 48 89 05 ?? ?? ?? ?? }
      // n = 6, score = 100
      //    48890d????????       |                     
      //   488905????????       |                     
      //   488d05ae610000       | test                ecx, ecx
      //   488905????????       |                     
      //   488d05a0550000       | je                  0x10
      //   488905????????       |                     

      $sequence_13 = { 8b cf e8 ?? ?? ?? ?? 48 8b 7c 24 48 85 c0 0f 84 40 03 00 00 48 8d 05 60 25 01 00 }
      // n = 6, score = 100
      //   8bcf                  | mov                 eax, 0x12010
      //   e8????????           |                     
      //   488b7c2448           | dec                 eax
      //   85c0                 | mov                 ecx, ebp
      //   0f8440030000         | jmp                 0x83
      //   488d0560250100       | mov                 ecx, 0xfffffff4

      $sequence_14 = { ff 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 23 05 ?? ?? ?? ?? ba 02 00 00 00 33 c9 89 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? }
      // n = 7, score = 100
      //   ff15????????         |                     
      //   8b05????????         |                     
      //   2305????????         |                     
      //   ba02000000           | dec                 eax
      //   33c9                 | lea                 eax, [0x61ae]
      //   8905????????         |                     
      //   8b05????????         |                     

      $sequence_15 = { 48 83 ec 30 49 8b d8 e8 ?? ?? ?? ?? 48 8b c8 48 85 c0 }
   // n = 5, score = 100
   //   4883ec30             | jne                 0xdf
   //   498bd8               | dec                 eax
   //   e8????????           |                     
   //   488bc8               | lea                 edx, [0xc9d0]
   //   4885c0               | inc                 ecx
   condition:
      filesize < 600KB and 7 of them
}



rule MAL_APT_NK_WIN_DTrack_Auto {
   meta:
      author = "CISA.gov"
      description = "Detects DTrack variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 75
      id = "1b40c685-beba-50fa-b484-c1526577cb23"
   strings:
      $sequence_0 = { 52 8b 45 08 50 e8 ?? ?? ?? ?? 83 c4 14 8b 4d 10 51 }
      // n = 7, score = 400
      //   52                   | push                edx
      //   8b4508               | mov                 eax, dword ptr [ebp + 8]
      //   50                   | push                eax
      //   e8????????           |                     
      //   83c414               | add                 esp, 0x14
      //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
      //   51                   | push                ecx

      $sequence_1 = { 3a 41 01 75 23 83 85 4c f6 ff ff 02 83 85 50 f6 ff ff 02 80 bd 4a f6 ff ff 00 75 ae c7 85 44 f6 ff ff 00 00 00 00 }
      // n = 7, score = 300
      //   3a4101               | cmp                 al, byte ptr [ecx + 1]
      //    7523                 | jne                 0x25
      //   83854cf6ffff02       | add                 dword ptr [ebp - 0x9b4], 2
      //   838550f6ffff02       | add                 dword ptr [ebp - 0x9b0], 2
      //   80bd4af6ffff00       | cmp                 byte ptr [ebp - 0x9b6], 0
      //   75ae                 | jne                 0xffffffb0
      //   c78544f6ffff00000000     | mov     dword ptr [ebp - 0x9bc], 0

      $sequence_2 = { 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 50 }
      // n = 7, score = 300
      //   50                   | push                eax
      //   ff15????????         |                     
      //   a3????????           |                     
      //   68????????           |                     
      //   e8????????           |                     
      //   83c404               | add                 esp, 4
      //   50                   | push                eax

      $sequence_3 = { 8d 8d d4 fa ff ff 51 e8 ?? ?? ?? ?? 83 c4 08 8b 15 ?? ?? ?? ?? }
      // n = 5, score = 300
      //   8d8dd4faffff         | lea                 ecx, [ebp - 0x52c]
      //   51                   | push                ecx
      //   e8????????           |                     
      //   83c408               | add                 esp, 8
      //   8b15????????         |                     

      $sequence_4 = { 88 55 f5 6a 5c 8b 45 0c 50 e8 ?? ?? ?? ?? }
      // n = 5, score = 300
      //   8855f5               | mov                 byte ptr [ebp - 0xb], dl
      //   6a5c                 | push                0x5c
      //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
      //   50                   | push                eax
      //   e8????????           |                     

      $sequence_5 = { 51 e8 ?? ?? ?? ?? 83 c4 10 8b 55 8c 52 }
      // n = 5, score = 300
      //   51                   | push                ecx
      //   e8????????           |                     
      //   83c410               | add                 esp, 0x10
      //   8b558c                | mov                 edx, dword ptr [ebp - 0x74]
      //   52                   | push                edx

      $sequence_6 = { 8b 4d 0c 51 68 ?? ?? ?? ?? 8d 95 60 ea ff ff 52 e8 ?? ?? ?? ?? }
      // n = 6, score = 300
      //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
      //   51                   | push                ecx
      //   68????????           |                     
      //   8d9560eaffff         | lea                 edx, [ebp - 0x15a0]
      //   52                   | push                edx
      //   e8????????           |                     

      $sequence_7 = { 83 c0 01 89 45 f4 83 7d f4 20 7d 2c 8b 4d f8 }
      // n = 5, score = 300
      //   83c001               | add                 eax, 1
      //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
      //   837df420             | cmp                 dword ptr [ebp - 0xc], 0x20
      //   7d2c                 | jge                 0x2e
      //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

      $sequence_8 = { 83 c0 01 89 85 6c f6 ff ff 8b 8d 70 f6 ff ff 8a 11 }
      // n = 4, score = 300
      //   83c001               | add                 eax, 1
      //   89856cf6ffff         | mov                 dword ptr [ebp - 0x994], eax
      //   8b8d70f6ffff         | mov                 ecx, dword ptr [ebp - 0x990]
      //   8a11                 | mov                 dl, byte ptr [ecx]

      $sequence_9 = { 03 55 f0 0f b6 02 0f b6 4d f7 33 c1 0f b6 55 fc 33 c2 }
      // n = 6, score = 200
      //   0355f0               | add                 edx, dword ptr [ebp - 0x10]
      //   0fb602               | movzx               eax, byte ptr [edx]
      //   0fb64df7             | movzx               ecx, byte ptr [ebp - 9]
      //   33c1                 | xor                 eax, ecx
      //    0fb655fc             | movzx               edx, byte ptr [ebp - 4]
      //   33c2                 | xor                 eax, edx

      $sequence_10 = { d1 e9 89 4d f8 8b 55 18 89 55 fc c7 45 f0 00 00 00 00 }
      // n = 5, score = 200
      //   d1e9                 | shr                 ecx, 1
      //   894df8               | mov                 dword ptr [ebp - 8], ecx
      //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
      //   8955fc               | mov                 dword ptr [ebp - 4], edx
      //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0

      $sequence_11 = { 8b 4d f0 3b 4d 10 0f 8d 90 00 00 00 8b 55 08 03 55 f0 0f b6 02 }
      // n = 6, score = 200
      //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
      //   3b4d10               | cmp                 ecx, dword ptr [ebp + 0x10]
      //   0f8d90000000         | jge                 0x96
      //   8b5508               | mov                 edx, dword ptr [ebp + 8]
      //   0355f0               | add                 edx, dword ptr [ebp - 0x10]
      //   0fb602               | movzx               eax, byte ptr [edx]

      $sequence_12 = { 89 4d 14 8b 45 f8 c1 e0 18 8b 4d fc c1 e9 08 0b c1 }
      // n = 6, score = 200
      //   894d14               | mov                 dword ptr [ebp + 0x14], ecx
      //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
      //   c1e018               | shl                 eax, 0x18
      //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
      //   c1e908               | shr                 ecx, 8
      //   0bc1                 | or                  eax, ecx

      $sequence_13 = { 0b c1 89 45 18 8b 55 14 89 55 f8 }
      // n = 4, score = 200
      //   0bc1                 | or                  eax, ecx
      //   894518               | mov                 dword ptr [ebp + 0x18], eax
      //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
      //   8955f8               | mov                 dword ptr [ebp - 8], edx

      $sequence_14 = { 8b 55 14 89 55 f8 8b 45 18 89 45 fc e9 ?? ?? ?? ?? 8b e5 }
   // n = 6, score = 200
   //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
   //   8955f8               | mov                 dword ptr [ebp - 8], edx
   //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
   //   8945fc               | mov                 dword ptr [ebp - 4], eax
   //   e9????????           |                     
   //   8be5                 | mov                 esp, ebp
   condition:
      filesize < 1700KB and 7 of them
}


rule MAL_APT_Operation_ShadowHammer_MalSetup {
   meta:
      description = "Detects a malicious file used by BARIUM group in Operation ShadowHammer"
      date = "2019-03-25"
      author = "Florian Roth (Nextron Systems)"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      score = 80
      hash1 = "ac0711afee5a157d084251f3443a40965fc63c57955e3a241df866cfc7315223"
      hash2 = "9acd43af36f2d38077258cb2ace42d6737b43be499367e90037f4605318325f8"
      hash3 = "bca9583263f92c55ba191140668d8299ef6b760a1e940bddb0a7580ce68fef82"
      hash4 = "c299b6dd210ab5779f3abd9d10544f9cae31cd5c6afc92c0fc16c8f43def7596"
      hash5 = "6aedfef62e7a8ab7b8ab3ff57708a55afa1a2a6765f86d581bc99c738a68fc74"
      hash6 = "cfbec77180bd67cceb2e17e64f8a8beec5e8875f47c41936b67a60093e07fcfd"
      reference = "https://securelist.com/operation-shadowhammer/89992/"
      id = "000f840a-848d-5f82-84bf-70690efbd4de"
   strings:
      $x1 = "\\AsusShellCode\\Release" ascii
      $x2 = "\\AsusShellCode\\Debug"
   condition:
      uint16(0) == 0x5a4d and 1 of them
}


rule MAL_QuasarRAT_May19_1 {
   meta:
      description = "Detects QuasarRAT malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.ensilo.com/uncovering-new-activity-by-apt10"
      date = "2019-05-27"
      modified = "2023-01-06"
      hash1 = "0644e561225ab696a97ba9a77583dcaab4c26ef0379078c65f9ade684406eded"
      id = "a4e82b6a-31f8-59fc-acfa-805c4594680a"
   strings:
      $x1 = "Quasar.Common.Messages" ascii fullword
      $x2 = "Client.MimikatzTools" ascii fullword
      $x3 = "Resources.powerkatz_x86.dll" ascii fullword
      $x4 = "Uninstalling... good bye :-(" wide

      $xc1 = { 41 00 64 00 6D 00 69 00 6E 00 00 11 73 00 63 00
               68 00 74 00 61 00 73 00 6B 00 73 00 00 1B 2F 00
               63 00 72 00 65 00 61 00 74 00 65 00 20 00 2F 00
               74 00 6E 00 20 00 22 00 00 27 22 00 20 00 2F 00
               73 }
      $xc2 = { 00 70 00 69 00 6E 00 67 00 20 00 2D 00 6E 00 20
               00 31 00 30 00 20 00 6C 00 6F 00 63 00 61 00 6C
               00 68 00 6F 00 73 00 74 00 20 00 3E 00 20 00 6E
               00 75 00 6C 00 0D 00 0A 00 64 00 65 00 6C 00 20
               00 2F 00 61 00 20 00 2F 00 71 00 20 00 2F 00 66
               00 20 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and 1 of them
}


rule MAL_RANSOM_DarkBit_Feb23_1 {
   meta:
      description = "Detects indicators found in DarkBit ransomware"
      author = "Florian Roth"
      reference = "https://twitter.com/idonaor1/status/1624703255770005506?s=12&t=mxHaauzwR6YOj5Px8cIeIw"
      date = "2023-02-13"
      score = 75
      id = "d209a0c2-f649-5fb1-9ecd-f1c35caa796f"
   strings:
      $s1 = ".onion" ascii
      $s2 = "GetMOTWHostUrl"

      $x1 = "hus31m7c7ad.onion"
      $x2 = "iw6v2p3cruy"
      $xn1 = "You will receive decrypting key after the payment."
   condition:
      uint16(0) == 0x5a4d and
      filesize < 10MB and (
         1 of ($x*) or 2 of them
      ) or 4 of them
      or ( filesize < 10MB and $xn1 ) // Ransom note
}



rule MAL_RANSOM_DarkBit_Feb23_2 {
   meta:
      description = "Detects Go based DarkBit ransomware (garbled code; could trigger on other obfuscated samples, too)"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff?environmentId=160"
      date = "2023-02-13"
      score = 75
      hash1 = "9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff"
      id = "f530815c-68e7-55f1-8e36-bc74a1059584"
   strings:
      $s1 = "runtime.initLongPathSupport" ascii fullword
      $s2 = "reflect." ascii
      $s3 = "    \"processes\": []," ascii fullword
      $s4 = "^!* %!(!" ascii fullword

      $op1 = { 4d 8b b6 00 00 00 00 48 8b 94 24 40 05 00 00 31 c0 87 82 30 03 00 00 b8 01 00 00 00 f0 0f c1 82 00 03 00 00 48 8b 44 24 48 48 8b 0d ba 1f 32 00 }
      $op2 = { 49 8d 49 01 0f 1f 00 48 39 d9 7c e2 b9 0b 00 00 00 49 89 d8 e9 28 fc ff ff e8 89 6c d7 ff }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 20000KB and all of them
}


rule MAL_Backdoor_DLL_Nov23_1 {
   meta:
      author = "X__Junior"
      description = "Detects a backdoor DLL, that was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "cc21c77e1ee7e916c9c48194fad083b2d4b2023df703e544ffb2d6a0bfc90a63"
      hash2 = "0eb66eebb9b4d671f759fb2e8b239e8a6ab193a732da8583e6e8721a2670a96d"
      score = 80
      id = "3588d437-b561-5380-8dac-73a31f4cdb5a"
   strings:
      $s1 = "ERROR GET INTERVAL" ascii
      $s2 = "OFF HIDDEN MODE" ascii
      $s3 = "commandMod:" ascii
      $s4 = "RESULT:" ascii

      $op1 = { C7 44 24 ?? 01 00 00 00 C7 84 24 ?? ?? ?? ?? FF FF FF FF 83 7C 24 ?? 00 74 ?? 83 BC 24 ?? ?? ?? ?? 00 74 ?? 4C 8D 8C 24 ?? ?? ?? ?? 41 B8 00 04 00 00 48 8D 94 24 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 }
      $op2 = { 48 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 03 00 00 00 48 8D 0D ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8D 0D ?? ?? ?? ?? 44 0F B7 05 ?? ?? ?? ?? 48 8B D0 48 8B 4C 24 ?? FF 15 }
   condition:
      uint16(0) == 0x5a4d
      and ( all of ($s*) or all of ($op*) )
}



rule MAL_Trojan_DLL_Nov23 {
   meta:
      author = "X__Junior"
      description = "Detects a trojan DLL that installs other components - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"
      score = 80
      id = "1dd87d0a-2b8b-5386-8fdd-40d184c731a4"
   strings:
      $op1 = { C7 84 24 ?? ?? ?? ?? 52 70 63 53 C7 84 24 ?? ?? ?? ?? 74 72 69 6E C7 84 24 ?? ?? ?? ?? 67 42 69 6E C7 84 24 ?? ?? ?? ?? 64 69 6E 67 C7 84 24 ?? ?? ?? ?? 43 6F 6D 70 C7 84 24 ?? ?? ?? ?? 6F 73 65 41 C7 84 24 ?? ?? ?? ?? 00 40 01 01 }
      $op2 = { C7 84 24 ?? ?? ?? ?? 6C 73 61 73 C7 84 24 ?? ?? ?? ?? 73 70 69 72 66 C7 84 24 ?? ?? 00 00 70 63 }
      $op3 = { C7 84 24 ?? ?? ?? ?? 4E 64 72 43 C7 84 24 ?? ?? ?? ?? 6C 69 65 6E C7 84 24 ?? ?? ?? ?? 74 43 61 6C C7 84 24 ?? ?? ?? ?? 6C 33 00 8D }
   condition:
      uint16(0) == 0x5a4d and all of them
}



rule MAL_DLL_Stealer_Nov23 {
   meta:
      author = "X__Junior"
      description = "Detects a DLL that steals authentication credentials - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23"
      hash1 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"
      score = 80
      id = "9cfed8ec-1d04-53d7-88ef-2576075cfc33"
   strings:
      $op1 = { C7 45 ?? 4D 69 6E 69 C7 45 ?? 44 75 6D 70 C7 45 ?? 57 72 69 74 C7 45 ?? 65 44 75 6D C7 45 ?? 70 00 27 00 C7 45 ?? 44 00 62 00 C7 45 ?? 67 00 68 00 C7 45 ?? 65 00 6C 00 C7 45 ?? 70 00 2E 00 C7 45 ?? 64 00 6C 00 C7 45 ?? 6C 00 00 00}
   condition:
      uint16(0) == 0x5a4d and all of them
}



rule MAL_Sednit_DelphiDownloader_Apr18_3 {
   meta:
      description = "Detects malware from Sednit Delphi Downloader report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/2018/04/24/sednit-update-analysis-zebrocy/"
      date = "2018-04-24"
      modified = "2023-01-06"
      hash1 = "ecb835d03060db1ea3496ceca2d79d7c4c6c671c9907e0b0e73bf8d3371fa931"
      hash2 = "e355a327479dcc4e71a38f70450af02411125c5f101ba262e8df99f9f0fef7b6"
      id = "2200fbdc-3600-51d4-a273-dc7fd4127c05"
   strings:
      $ = "Processor Level: " fullword ascii
      $ = "CONNECTION ERROR" fullword ascii
      $ = "FILE_EXECUTE_AND_KILL_MYSELF" ascii
      $ = "-KILL_PROCESS-" ascii
      $ = "-FILE_EXECUTE-" ascii
      $ = "-DOWNLOAD_ERROR-" ascii
      $ = "CMD_EXECUTE" fullword ascii
      $ = "\\Interface\\Office\\{31E12FE8-937F-1E32-871D-B1C9AOEF4D4}\\" ascii
      $ = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}


rule MAL_Turla_Agent_BTZ {
   meta:
      description = "Detects Turla Agent.BTZ"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.gdatasoftware.com/blog/2014/11/23937-the-uroburos-case-new-sophisticated-rat-identified"
      date = "2018-04-12"
      modified = "2023-01-06"
      score = 90
      hash1 = "c4a1cd6916646aa502413d42e6e7441c6e7268926484f19d9acbf5113fc52fc8"
      id = "bd642f11-19f6-5178-b978-1215215fea86"
   strings:
      $x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii
      $x3 = "mstotreg.dat" fullword ascii
      $x4 = "Bisuninst.bin" fullword ascii
      $x5 = "mfc42l00.pdb" fullword ascii
      $x6 = "ielocal~f.tmp" fullword ascii

      $s1 = "%s\\1.txt" fullword ascii
      $s2 = "%windows%" fullword ascii
      $s3 = "%s\\system32" fullword ascii
      $s4 = "\\Help\\SYSTEM32\\" ascii
      $s5 = "%windows%\\mfc42l00.pdb" ascii
      $s6 = "Size of log(%dB) is too big, stop write." fullword ascii
      $s7 = "Log: Size of log(%dB) is too big, stop write." fullword ascii
      $s8 = "%02d.%02d.%04d Log begin:" fullword ascii
      $s9 = "\\system32\\win.com" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
         1 of ($x*) or
         4 of them
      )
}



rule MAL_Turla_Sample_May18_1 {
   meta:
      description = "Detects Turla samples"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/omri9741/status/991942007701598208"
      date = "2018-05-03"
      hash1 = "4c49c9d601ebf16534d24d2dd1cab53fde6e03902758ef6cff86be740b720038"
      hash2 = "77cbd7252a20f2d35db4f330b9c4b8aa7501349bc06bbcc8f40ae13d01ae7f8f"
      id = "5052838f-a895-55cb-abcf-813465074127"
   strings:
      $x1 = "sc %s create %s binPath= \"cmd.exe /c start %%SystemRoot%%\\%s\">>%s" fullword ascii
      $x2 = "cmd.exe /c start %%SystemRoot%%\\%s" fullword ascii
      $x3 = "cmd.exe /c %s\\%s -s %s:%s:%s -c \"%s %s /wait 1\">>%s" fullword ascii
      $x4 = "Read InjectLog[%dB]********************************" fullword ascii
      $x5 = "%s\\System32\\011fe-3420f-ff0ea-ff0ea.tmp" fullword ascii
      $x6 = "**************************** Begin ini %s [%d]***********************************************" fullword ascii
      $x7 = "%s -o %s -i %s -d exec2 -f %s" fullword ascii
      $x8 = "Logon to %s failed: code %d(User:%s,Pass:%s)" fullword ascii
      $x9 = "system32\\dxsnd32x.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and 1 of them
}



rule MAL_WIPER_CaddyWiper_Mar22_1 {
   meta:
      description = "Detects CaddyWiper malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ESETresearch/status/1503436420886712321?s=20&t=xh8JK6fEmRIrnqO7Ih_PNg"
      date = "2022-03-15"
      score = 85
      hash1 = "1e87e9b5ee7597bdce796490f3ee09211df48ba1d11f6e2f5b255f05cc0ba176"
      hash2 = "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
      hash3 = "ea6a416b320f32261da8dafcf2faf088924f99a3a84f7b43b964637ea87aef72"
      hash4 = "f1e8844dbfc812d39f369e7670545a29efef6764d673038b1c3edd11561d6902"
      id = "83495a0d-a295-5ec7-9761-ce79918e1034"
   strings:
      $op1 = { ff 55 94 8b 45 fc 50 ff 55 f8 8a 4d ba 88 4d ba 8a 55 ba 80 ea 01 }
      $op2 = { 89 45 f4 83 7d f4 00 74 04 eb 47 eb 45 6a 00 8d 95 1c ff ff ff 52 }
      $op3 = { 6a 20 6a 02 8d 4d b0 51 ff 95 68 ff ff ff 85 c0 75 0a e9 4e 02 00 00 }
      $op4 = { e9 67 01 00 00 83 7d f4 05 74 0a e9 5c 01 00 00 e9 57 01 00 00 8d 45 98 50 6a 20 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 50KB and 3 of them or all of them
}


rule MAL_WIPER_IsaacWiper_Mar22_1 {
   meta:
      description = "Detects IsaacWiper malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/"
      date = "2022-03-03"
      score = 85
      hash1 = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
      hash2 = "7bcd4ec18fc4a56db30e0aaebd44e2988f98f7b5d8c14f6689f650b4f11e16c0"
      id = "97d8d8dd-db65-5156-8f97-56c620cf2d56"
   strings:
      $s1 = "C:\\ProgramData\\log.txt" wide fullword
      $s2 = "Cleaner.dll" ascii fullword
      $s3 = "-- system logical drive: " wide fullword
      $s4 = "-- FAILED" wide fullword

      $op1 = { 8b f1 80 3d b0 66 03 10 00 0f 85 96 00 00 00 33 c0 40 b9 a8 66 03 10 87 01 33 db }
      $op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 74 34 68 a2 c8 01 10 2b c1 6a 04 }
      $op3 = { 8d 4d f4 ff 75 08 e8 12 ff ff ff 68 88 39 03 10 8d 45 f4 50 e8 2d 1d 00 00 cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      (
         pe.imphash() == "a4b162717c197e11b76a4d9bc58ea25d" or
         3 of them
      )
}


rule MAL_OBFUSC_Unknown_Jan22_1 {
   meta:
      description = "Detects samples similar to reversed stage3 found in Ukrainian wiper incident named WhisperGate"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/juanandres_gs/status/1482827018404257792"
      date = "2022-01-16"
      hash1 = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
      id = "647c0092-b03d-5627-8568-ddaa982c73a1"
   strings:
      $xc1 = { 37 00 63 00 38 00 63 00 62 00 35 00 35 00 39 00
               38 00 65 00 37 00 32 00 34 00 64 00 33 00 34 00
               33 00 38 00 34 00 63 00 63 00 65 00 37 00 34 00
               30 00 32 00 62 00 31 00 31 00 66 00 30 00 65 }
      $xc2 = { 4D 61 69 6E 00 43 6C 61 73 73 4C 69 62 72 61 72
               79 31 00 70 63 31 65 }

      $s1 = ".dll" wide
      $s2 = "%&%,%s%" ascii fullword

      $op1 = { a2 87 fa b1 44 a5 f5 12 da a7 49 11 5c 8c 26 d4 75 }
      $op2 = { d7 af 52 38 c7 47 95 c8 0e 88 f3 d5 0b }
      $op3 = { 6c 05 df d6 b8 ac 11 f2 67 16 cb b7 34 4d b6 91 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 1000KB and ( 1 of ($x*) or 3 of them )
}



rule MAL_Unknown_Discord_Characteristics_Jan22_1 {
   meta:
      description = "Detects unknown malware with a few indicators also found in Wiper malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
      date = "2022-01-16"
      score = 75
      hash1 = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
      id = "23ee5319-6a72-517b-8ea0-55063b6b862c"
   strings:
      $x1 = "xownxloxadDxatxxax" wide
      
      $s2 = "https://cdn.discordapp.com/attachments/" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 1000KB and all of them
}


rule MAL_UNC2891_Winghook {
   meta:
      description = "Detects UNC2891 Winghook Keylogger"
      author = "Frank Boldewin (@r3c0nst)"
      date = "2022-03-30"
      reference = "https://github.com/fboldewin/YARA-rules/tree/master"
      hash1 = "d071ee723982cf53e4bce89f3de5a8ef1853457b21bffdae387c4c2bd160a38e"

      id = "e5955fa0-8204-58e3-88a6-de4b47756ede"
   strings:
      $code1 = {01 F9 81 E1 FF 00 00 00 41 89 CA [15] 44 01 CF 81 E7 FF 00 00 00} // crypt log file data
      $code2 = {83 E2 0F 0F B6 14 1? 32 14 01 88 14 0? 48 83 ?? ?? 48 83 ?? ?? 75} // decrypt path+logfile name
      $str1 = "fgets" ascii // hook function name
      $str2 = "read" ascii // hook function name
   condition:
      uint32 (0) ==  0x464c457f and filesize < 100KB and 1 of ($code*) and all of ($str*)
}


rule MAL_WebMonitor_RAT {
   meta:
      description = "Detects WebMonitor RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/04/unit42-say-cheese-webmonitor-rat-comes-c2-service-c2aas/"
      date = "2018-04-13"
      hash1 = "27aaad8a7b3fd53d99077a9202e8bed05696c843ed2485bea6eb9e33a1c273ac"
      hash2 = "05111c305028b5d822ecd12de9879560223c42860cc9d448c47886c236648607"
      id = "5378f22e-4bba-50e7-8374-5135e980e06b"
   strings:
      $x1 = "send_keylog_stream_start" fullword wide
      $x2 = "KEYLOG_STREAM_STOP" fullword wide

      $s1 = "SHELL_EXEC" fullword wide
      $s2 = "send_shell_exec" fullword wide
      $s3 = "send_connections_get" fullword wide

      $a1 = "Select * from Win32_PerfRawData_PerfProc_Process where IDProcess = '" fullword wide
      $a2 = "Select * from Win32_Process WHERE handle =" fullword wide
      $a3 = "Select * from Win32_Process where ProcessId=" fullword wide
      $a4 = "Select * from Win32_ComputerSystem" fullword wide
      $a5 = "The service is in the process of being continued" fullword wide
      $a6 = "tcpdump" fullword wide
      $a7 = "memdump" fullword wide
      $a8 = "<val1>Processor</val1>" fullword wide
      $a9 = "Win32 share process" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         1 of ($x*) or
         ( 2 of ($s*) and 2 of ($a*) ) or
         7 of them
      )
}


rule MAL_Winnti_BR_Report_TwinPeaks {
   meta:
      description = "Detects Winnti samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
      id = "2e4e2b88-fdb4-5adc-8192-a304d71ca851"
   strings:
      $cooper = "Cooper"
      $pattern = { e9 ea eb ec ed ee ef f0}
   condition:
      uint16(0) == 0x5a4d and $cooper and ($pattern in (@cooper[1]..@cooper[1]+100))
}



rule MAL_BR_Report_TheDao {
   meta:
      description = "Detects indicator in malicious UPX packed samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
      id = "5cc932d7-2ec6-5570-af4a-3f64b39e6db5"
  strings:
    $b = { DA A0 }
  condition:
    uint16(0) == 0x5a4d and $b at pe.overlay.offset and pe.overlay.size > 100
}



rule MAL_Winnti_BR_Report_MockingJay {
   meta:
      description = "Detects Winnti samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
      id = "9aff9d65-3827-59de-9dc3-38f227155d3d"
  strings:
    $load_magic = { C7 44 ?? ?? FF D8 FF E0 }
    $iter = { E9 EA EB EC ED EE EF F0 }
    $jpeg = { FF D8 FF E0 00 00 00 00 00 00 }
  condition:
    uint16(0) == 0x5a4d and
      $jpeg and
      ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and
      for any i in (1..#jpeg): ( uint8(@jpeg[i] + 11) != 0 )
}


rule MAL_BurningUmbrella_Sample_1 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fcfe8fcf054bd8b19226d592617425e320e4a5bb4798807d6f067c39dfc6d1ff"
      id = "9f8a6831-172b-5310-9763-43657b79b91d"
   strings:
      $s1 = { 40 00 00 E0 75 68 66 61 6F 68 6C 79 }
      $s2 = { 40 00 00 E0 64 6A 7A 66 63 6D 77 62 }
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and (
         pe.imphash() == "baa93d47220682c04d92f7797d9224ce" and
         $s1 in (0..1024) and
         $s2 in (0..1024)
      )
}



rule MAL_BurningUmbrella_Sample_2 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "801a64a730fc8d80e17e59e93533c1455686ca778e6ba99cf6f1971a935eda4c"
      id = "926b4a29-ce47-559b-94e3-1fabd90f3fbe"
   strings:
      $s1 = { 40 00 00 E0 63 68 72 6F 6D 67 75 78 }
      $s2 = { 40 00 00 E0 77 62 68 75 74 66 6F 61 }
      $s3 = "ActiveX Manager" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      $s1 in (0..1024) and
      $s2 in (0..1024) and
      $s3
}



rule MAL_BurningUmbrella_Sample_3 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "92efbecc24fbb5690708926b6221b241b10bdfe3dd0375d663b051283d0de30f"
      id = "b997822a-3f62-51b4-bd96-e780ffe60812"
   strings:
      $s1 = "HKEY_CLASSES_ROOT\\Word.Document.8\\shell\\Open\\command" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}



rule MAL_BurningUmbrella_Sample_4 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "a1629e8abce9d670fdb66fa1ef73ad4181706eefb8adc8a9fd257b6a21be48c6"
      id = "3489f64b-7ebc-55b8-bd11-afaa719e572b"
   strings:
      $x1 = "dumpodbc.exe" fullword ascii
      $x2 = "photo_Bundle.exe" fullword ascii
      $x3 = "Connect 2 fails : %d,%s:%d" fullword ascii
      $x4 = "Connect fails 1 : %d %s:%d" fullword ascii
      $x5 = "New IP : %s,New Port: %d" fullword ascii
      $x6 = "Micrsoft Corporation. All rights reserved." fullword wide
      $x7 = "New ConFails : %d" fullword ascii

      $s1 = "cmd /c net stop stisvc" fullword ascii
      $s2 = "cmd /c net stop spooler" fullword ascii
      $s3 = "\\temp\\s%d.dat" ascii
      $s4 = "cmd /c net stop wuauserv" fullword ascii
      $s5 = "User-Agent: MyApp/0.1" fullword ascii
      $s6 = "%s->%s Fails : %d" fullword ascii
      $s7 = "Enter WorkThread,Current sock:%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and (
         ( pe.exports("Print32") and 2 of them ) or
         1 of ($x*) or
         4 of them
      )
}



rule MAL_BurningUmbrella_Sample_6 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "49ef2b98b414c321bcdbab107b8fa71a537958fe1e05ae62aaa01fe7773c3b4b"
      id = "7198a734-fd54-5cb5-9966-b91796a415c7"
   strings:
      $s1 = "ExecuteFile=\"hidcon:nowait:\\\"Word\\\\r.bat\\\"\"" fullword ascii
      $s2 = "InstallPath=\"%Appdata%\\\\Microsoft\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}



rule MAL_BurningUmbrella_Sample_7 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "a4ce3a356d61fbbb067e1430b8ceedbe8965e0cfedd8fb43f1f719e2925b094a"
      hash2 = "a8bfc1e013f15bc395aa5c047f22ff2344c343c22d420804b6d2f0a67eb6db64"
      hash3 = "959612f2a9a8ce454c144d6aef10dd326b201336a85e69a604e6b3892892d7ed"
      id = "7e427512-a8ee-53ae-a141-e995e74ca845"
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f5b113d6708a3927b5cc48f2215fcaff"
}



rule MAL_BurningUmbrella_Sample_8 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "73270fe9bca94fead1b5b38ddf69fae6a42e574e3150d3e3ab369f5d37d93d88"
      id = "1b89d5a1-1425-5cb7-b429-563769bc0943"
   strings:
      $s1 = "cmd /c open %s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}



rule MAL_BurningUmbrella_Sample_10 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "70992a72412c5d62d003a29c3967fcb0687189d3290ebbc8671fa630829f6694"
      hash2 = "48f0bbc3b679aac6b1a71c06f19bb182123e74df8bb0b6b04ebe99100c57a41e"
      hash3 = "5475ae24c4eeadcbd49fcd891ce64d0fe5d9738f1c10ba2ac7e6235da97d3926"
      id = "e4cb2211-efbe-55f9-99e3-c01601904509"
   strings:
      $s1 = "revjj.syshell.org" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}



rule MAL_BurningUmbrella_Sample_12 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "b9aba520eeaf6511877c1eec5f7d71e0eea017312a104f30d3b8f17c89db47e8"
      id = "805a00e7-2959-53d8-b769-0f8e54e1bbd5"
   strings:
      $s1 = "%SystemRoot%\\System32\\qmgr.dll" fullword ascii
      $s2 = "rundll32.exe %s,Startup" fullword ascii
      $s3 = "nvsvcs.dll" fullword wide
      $s4 = "SYSTEM\\CurrentControlSet\\services\\BITS\\Parameters" fullword ascii
      $s5 = "http://www.sginternet.net 0" fullword ascii
      $s6 = "Microsoft Corporation. All rights reserved." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and (
         pe.exports("SvcServiceMain") and
         5 of them
      )
}



rule MAL_BurningUmbrella_Sample_13 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "d31374adc0b96a8a8b56438bbbc313061fd305ecee32a12738dd965910c8890f"
      hash2 = "c74a8e6c88f8501fb066ae07753efe8d267afb006f555811083c51c7f546cb67"
      id = "38c73425-bbdd-5b74-8ad4-5e0052039dd8"
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "75f201aa8b18e1c4f826b2fe0963b84f"
}



rule MAL_BurningUmbrella_Sample_14 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "388ef4b4e12a04eab451bd6393860b8d12948f2bce12e5c9022996a9167f4972"
      id = "a2b3a4bb-ca60-5dc2-8124-17e654e326b8"
   strings:
      $s1 = "C:\\tmp\\Google_updata.exe" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}



rule MAL_BurningUmbrella_Sample_15 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "be6bea22e909bd772d21647ffee6d15e208e386e8c3c95fd22816c6b94196ae8"
      hash2 = "72a8fa454f428587d210cba0e74735381cd0332f3bdcbb45eecb7e271e138501"
      hash3 = "9cc38ea106efd5c8e98c2e8faf97c818171c52fa3afa0c4c8f376430fa556066"
      hash4 = "1a4a64f01b101c16e8b5928b52231211e744e695f125e056ef7a9412da04bb91"
      hash5 = "3cd42e665e21ed4815af6f983452cbe7a4f2ac99f9ea71af4480a9ebff5aa048"
      id = "4dc840c1-e6fa-5b21-bfcd-ef07cd85272a"
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and pe.imphash() == "cc33b1500354cf785409a3b428f7cd2a"
}



rule MAL_BurningUmbrella_Sample_16 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "58bb3859e02b8483e9f84cc56fbd964486e056ef28e94dd0027d361383cc4f4a"
      id = "8b1970bd-571e-5c53-9170-1605c69d9d6d"
   strings:
      $s1 = "http://netimo.net 0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and all of them
}



rule MAL_BurningUmbrella_Sample_17 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fa380dac35e16da01242e456f760a0e75c2ce9b68ff18cfc7cfdd16b2f4dec56"
      hash2 = "854b64155f9ceac806b49f3e352949cc292e5bc33f110d965cf81a93f78d2f07"
      hash3 = "1e462d8968e8b6e8784d7ecd1d60249b41cf600975d2a894f15433a7fdf07a0f"
      hash4 = "3cdc149e387ec4a64cce1191fc30b8588df4a2947d54127eae43955ce3d08a01"
      hash5 = "a026b11e15d4a81a449d20baf7cbd7b8602adc2644aa4bea1e55ff1f422c60e3"
      id = "d79d3f65-f27c-582b-9258-7c84dc7682a6"
   strings:
      $s1 = "syshell" fullword wide
      $s2 = "Normal.dotm" fullword ascii
      $s3 = "Microsoft Office Word" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}



rule MAL_BurningUmbrella_Sample_18 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "d8df60524deb6df4f9ddd802037a248f9fbdd532151bb00e647b233e845b1617"
      hash2 = "c55cb6b42cfabf0edf1499d383817164d1b034895e597068e019c19d787ea313"
      hash3 = "32144ba8370826e069e5f1b6745a3625d10f50a809f3f2a72c4c7644ed0cab03"
      hash4 = "ae616003d85a12393783eaff9778aba20189e423c11c852e96c29efa6ecfce81"
      hash5 = "95b6e427883f402db73234b84a84015ad7f3456801cb9bb19df4b11739ea646d"
      hash6 = "1419ba36aae1daecc7a81a2dfb96631537365a5b34247533d59a70c1c9f58da2"
      hash7 = "6a5a9b0ae10ce6a0d5e1f7d21d8ea87894d62d0cda00db005d8d0de17cae7743"
      hash8 = "74e348068f8851fec1b3de54550fe09d07fb85b7481ca6b61404823b473885bb"
      hash9 = "adb9c2fe930fae579ce87059b4b9e15c22b6498c42df01db9760f75d983b93b2"
      hash0 = "23f28b5c4e94d0ad86341c0b9054f197c63389133fcd81dd5e0cf59f774ce54b"
      id = "d08f4676-ff28-59be-9fd4-b5a824e577d9"
   strings:
      $s1 = "c:\\tmp\\tran.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         pe.imphash() == "11675b4db0e7df7b29b1c1ef6f88e2e1" or
         pe.imphash() == "364e1f68e2d412db34715709c68ba467" or
         pe.exports("deKernel") or
         1 of them
      )
}



rule MAL_BurningUmbrella_Sample_19 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "05e2912f2a593ba16a5a094d319d96715cbecf025bf88bb0293caaf6beb8bc20"
      hash2 = "e7bbdb275773f43c8e0610ad75cfe48739e0a2414c948de66ce042016eae0b2e"
      id = "8ab55e80-5d28-5a5f-a1cc-725ba6720e4b"
   strings:
      $s1 = "Cryption.dll" fullword ascii
      $s2 = "tran.exe" fullword ascii
      $s3 = "Kernel.dll" fullword ascii
      $s4 = "Now ready to get the file %s!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}



rule MAL_BurningUmbrella_Sample_20 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      modified = "2023-01-06"
      hash1 = "5c12379cd7ab3cb03dac354d0e850769873d45bb486c266a893c0daa452aa03c"
      hash2 = "172cd90fd9e31ba70e47f0cc76c07d53e512da4cbfd197772c179fe604b75369"
      hash3 = "1ce88e98c8b37ea68466657485f2c01010a4d4a88587ba0ae814f37680a2e7a8"
      id = "1a39a76a-31e2-5d6e-82cb-ea38d503b6a9"
   strings:
      $s1 = "Wordpad.Document.1\\shell\\open\\command\\" wide
      $s2 = "%s\\shell\\Open\\command" fullword wide
      $s3 = "expanding computer" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "bac338bfe2685483c201e15eae4352d5" or
         2 of them
      )
}



rule MAL_BurningUmbrella_Sample_21 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "4b7b9c2a9d5080ccc4e9934f2fd14b9d4e8f6f500889bf9750f1d672c8724438"
      id = "2193e4b6-b71c-5031-8e43-fdd7177ad05c"
   strings:
      $s1 = "c:\\windows\\ime\\setup.exe" fullword ascii
      $s2 = "ws.run \"later.bat /start\",0Cet " fullword ascii
      $s3 = "del later.bat" fullword ascii
      $s4 = "mycrs.xls" fullword ascii

      $a1 = "-el -s2 \"-d%s\" \"-p%s\" \"-sp%s\"" fullword ascii
      $a2 = "<set ws=wscript.createobject(\"wscript.shell\")" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and 2 of them
}



rule MAL_AirdViper_Sample_Apr18_1 {
   meta:
      description = "Detects Arid Viper malware sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-04"
      hash1 = "9f453f1d5088bd17c60e812289b4bb0a734b7ad2ba5a536f5fd6d6ac3b8f3397"
      id = "00f118d1-be1c-5f50-a50f-591f824a1a53"
   strings:
      $x1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" fullword ascii
      $x2 = "daenerys=%s&" ascii
      $x3 = "betriebssystem=%s&anwendung=%s&AV=%s" ascii

      $s1 = "Taskkill /IM  %s /F &  %s" fullword ascii
      $s2 = "/api/primewire/%s/requests/macKenzie/delete" fullword ascii
      $s3 = "\\TaskWindows.exe" ascii
      $s4 = "MicrosoftOneDrives.exe" fullword ascii
      $s5 = "\\SeanSansom.txt" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and (
         1 of ($x*) or
         4 of them
      )
}





rule MAL_Winnti_Sample_May18_1 {
   meta:
      description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"
      id = "c2f3339e-269f-5a51-8db6-06e54a707b3a"
   strings:
      $s1 = "wireshark" fullword wide
      $s2 = "procexp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and all of them
}



rule MAL_Visel_Sample_May18_1 {
   meta:
      description = "Detects Visel malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "35db8e6a2eb5cf09cd98bf5d31f6356d0deaf4951b353fc513ce98918b91439c"
      id = "a244461a-380c-56e6-a891-131f6e13c280"
   strings:
      $s2 = "print32.dll" fullword ascii
      $s3 = "c:\\a\\b.txt" fullword ascii
      $s4 = "\\temp\\s%d.dat" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         pe.exports("szFile") or
         2 of them
      )
}


rule SUSP_Patcher_Keygen_Indicators_Jun15 {
	meta:
		description = "Sample from CN Honker Pentest Toolset"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e32f5de730e324fb386f97b6da9ba500cf3a4f8d"
		id = "4dd65e4b-8178-5576-9740-b3c80a8127e2"
	strings:
		$s0 = "<description>Patch</description>" fullword ascii 
		$s2 = "\\dup2patcher.dll" ascii
		$s3 = "load_patcher" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}



rule MAL_CRIME_CobaltGang_Malware_Oct19_1 {
   meta:
      description = "Detects CobaltGang malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/vxsh4d0w/status/1187353649015611392"
      date = "2019-10-24"
      hash1 = "72125933265f884ceb8ab64ab303ea76aaeb7877faee8976d398acd0d0b7356b"
      hash2 = "893339624602c7b3a6f481aed9509b53e4e995d6771c72d726ba5a6b319608a7"
      hash3 = "3c34bbf641df25f9accd05b27b9058e25554fdfea0e879f5ca21ffa460ad2b01"
      id = "95c16016-b09b-56f3-b5a4-fca18ac70ad5"
   strings:
      $op_a1 = { 0f 44 c2 eb 0a 31 c0 80 fa 20 0f 94 c0 01 c0 5d }

      $op_b1 = { 89 e5 53 8b 55 08 8b 4d 0c 8a 1c 01 88 1c 02 83 }
      $op_b2 = { 89 e5 53 8b 55 08 8b 45 0c 8a 1c 0a 88 1c 08 83 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and (
         pe.imphash() == "d1e3f8d02cce09520379e5c1e72f862f" or
         pe.imphash() == "8e26df99c70f79cb8b1ea2ef6f8e52ac" or
         ( $op_a1 and 1 of ($op_b*) )
      )
}


rule MAL_RANSOM_COVID19_Apr20_1 {
   meta:
      description = "Detects ransomware distributed in COVID-19 theme"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/covid-19-themed-cyber-attacks-target-government-and-medical-organizations/"
      date = "2020-04-15"
      hash1 = "2779863a173ff975148cb3156ee593cb5719a0ab238ea7c9e0b0ca3b5a4a9326"
      id = "fc723d1f-e969-5af6-af57-70d00bf797f4"
   strings:
      $s1 = "/savekey.php" wide

      $op1 = { 3f ff ff ff ff ff 0b b4 }
      $op2 = { 60 2e 2e 2e af 34 34 34 b8 34 34 34 b8 34 34 34 }
      $op3 = { 1f 07 1a 37 85 05 05 36 83 05 05 36 83 05 05 34 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      2 of them
}


rule MAL_RANSOM_Crime_DearCry_Mar2021_1 {
    meta:
        description = "Triggers on strings of known DearCry samples"
        author = "Nils Kuhnert"
        date = "2021-03-12"
        reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
        hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
        hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
        hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
        id = "d9714502-f1ea-5fe8-b0ac-1f7a9a30d8f5"
    strings:
        $x1 = ".TIF .TIFF .PDF .XLS .XLSX .XLTM .PS .PPS .PPT .PPTX .DOC .DOCX .LOG .MSG .RTF .TEX .TXT .CAD .WPS .EML .INI .CSS .HTM .HTML  .XHTML .JS .JSP .PHP .KEYCHAIN .PEM .SQL .APK .APP .BAT .CGI .ASPX .CER .CFM .C .CPP .GO .CONFIG .PL .PY .DWG .XML .JPG .BMP .PNG .EXE .DLL .CAD .AVI .H.CSV .DAT .ISO .PST .PGD  .7Z .RAR .ZIP .ZIPX .TAR .PDB .BIN .DB .MDB .MDF .BAK .LOG .EDB .STM .DBF .ORA .GPG .EDB .MFS" ascii

        $s1 = "create rsa error" ascii fullword
        $s2 = "DEARCRY!" ascii fullword
        $s4 = "/readme.txt" ascii fullword
        $s5 = "msupdate" ascii fullword
        $s6 = "Your file has been encrypted!" ascii fullword
        $s7 = "%c:\\%s" ascii fullword
        $s8 = "C:\\Users\\john\\" ascii
        $s9 = "EncryptFile.exe.pdb" ascii
    condition:
        uint16(0) == 0x5a4d 
        and filesize > 1MB and filesize < 2MB 
        and ( 1 of ($x*) or 3 of them )
        or 5 of them
}



rule MAL_CRIME_RANSOM_DearCry_Mar21_1 {
   meta:
      description = "Detects DearCry Ransomware affecting Exchange servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
      date = "2021-03-12"
      hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
      hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
      hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
      id = "96cd2fe8-8bb9-5a3b-9bf1-c63a1148a817"
   strings:
      $s1 = "dear!!!" ascii fullword
      $s2 = "EncryptFile.exe.pdb" ascii fullword
      $s3 = "/readme.txt" ascii fullword
      $s4 = "C:\\Users\\john\\" ascii
      $s5 = "And please send me the following hash!" ascii fullword

      $op1 = { 68 e0 30 52 00 6a 41 68 a5 00 00 00 6a 22 e8 81 d0 f8 ff 83 c4 14 33 c0 5e }
      $op2 = { 68 78 6a 50 00 6a 65 6a 74 6a 10 e8 d9 20 fd ff 83 c4 14 33 c0 5e }
      $op3 = { 31 40 00 13 31 40 00 a4 31 40 00 41 32 40 00 5f 33 40 00 e5 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 4000KB and
      3 of them or 5 of them
}


rule MAL_Emotet_JS_Dropper_Oct19_1 {
   meta:
      description = "Detects Emotet JS dropper"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/aaa75105-dc85-48ca-9732-085b2ceeb6eb/"
      date = "2019-10-03"
      hash1 = "38295d728522426672b9497f63b72066e811f5b53a14fb4c4ffc23d4efbbca4a"
      hash2 = "9bc004a53816a5b46bfb08e819ac1cf32c3bdc556a87a58cbada416c10423573"
      id = "34605452-8f3d-540a-b66f-4f68d9187003"
   strings:
      $xc1 = { FF FE 76 00 61 00 72 00 20 00 61 00 3D 00 5B 00
               27 00 }
   condition:
      uint32(0) == 0x0076feff and filesize <= 700KB and $xc1 at 0
}

import "pe"



rule MAL_Emotet_Jan20_1 {
   meta:
      description = "Detects Emotet malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/5e81638e-df2e-4a5b-9e45-b07c38d53929/"
      date = "2020-01-29"
      hash1 = "e7c22ccdb1103ee6bd15c528270f56913bb2f47345b360802b74084563f1b73d"
      id = "334ae7e5-0a46-5e95-bf53-0f343db4e4de"
   strings:
      $op0 = { 74 60 8d 34 18 eb 54 03 c3 50 ff 15 18 08 41 00 }
      $op1 = { 03 fe 66 39 07 0f 85 2a ff ff ff 8b 4d f0 6a 20 }
      $op2 = { 8b 7d fc 0f 85 49 ff ff ff 85 db 0f 84 d1 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 200KB and (
         pe.imphash() == "009889c73bd2e55113bf6dfa5f395e0d" or
         1 of them
      )
}



rule MAL_Enfal_Nov22 { 
   meta:
      old_rule_name = "Enfal_Malware"
      description = "Detects a certain type of Enfal Malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enfal"
      date = "2015-02-10"
      modified = "2023-01-06"
      hash2 = "42fa6241ab94c73c7ab386d600fae70da505d752daab2e61819a0142b531078a"
      hash2 = "bf433f4264fa3f15f320b35e773e18ebfe94465d864d3f4b2a963c3e5efd39c2"
      score = 75
      id = "9dcba14e-2175-5da0-8629-5b952c213f6c"
   strings:
      $xop1 = { 00 00 83 c9 ff 33 c0 f2 ae f7 d1 49 b8 ff 8f 01 00 2b c1 }

      $s1 = "POWERPNT.exe" fullword ascii
      $s2 = "%APPDATA%\\Microsoft\\Windows\\" ascii
      $s3 = "%HOMEPATH%" fullword ascii
      $s4 = "Server2008" fullword ascii
      $s5 = "%ComSpec%" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      ( 1 of ($x*) or 3 of ($s*) )
}



rule MAL_Envrial_Jan18_1 {
   meta:
      description = "Detects Encrial credential stealer malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/malwrhunterteam/status/953313514629853184"
      date = "2018-01-21"
      hash1 = "9ae3aa2c61f7895ba6b1a3f85fbe36c8697287dc7477c5a03d32cf994fdbce85"
      hash2 = "9edd8f0e22340ecc45c5f09e449aa85d196f3f506ff3f44275367df924b95c5d"
      id = "8be5f0d8-013f-5070-9e19-9ac522c88693"
   strings:
      $x1 = "/Evrial/master/domen" wide

      $a1 = "\\Opera Software\\Opera Stable\\Login Data" wide
      $a2 = "\\Comodo\\Dragon\\User Data\\Default\\Login Data" wide
      $a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide
      $a4 = "\\Orbitum\\User Data\\Default\\Login Data" wide
      $a5 = "\\Kometa\\User Data\\Default\\Login Data" wide

      $s1 = "dlhosta.exe" fullword wide
      $s2 = "\\passwords.log" wide
      $s3 = "{{ <>h__TransparentIdentifier1 = {0}, Password = {1} }}" fullword wide
      $s4 = "files/upload.php?user={0}&hwid={1}" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and (
        1 of ($x*) or
        3 of them or
        2 of ($s*)
      )
}

rule MAL_Floxif_Generic {
   meta:
      description = "Detects Floxif Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-11"
      score = 80
      hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
      id = "5ddd6a6c-b02a-518b-bbe3-8f528b3d7eae"
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         pe.imphash() == "2f4ddcfebbcad3bacadc879747151f6f" or
         pe.exports("FloodFix") or pe.exports("FloodFix2")
      )
}




rule MAL_CN_FlyStudio_May18_1 {
   meta:
      description = "Detects malware / hacktool detected in May 2018"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-11"
      hash1 = "b85147366890598518d4f277d44506eef871fd7fc6050d8f8e68889cae066d9e"
      id = "b78b9ea0-5eef-5922-b5d7-d3c5ddce7fad"
   strings:
      $s1 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
      $s2 = "www.cfyhack.cn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and (
         pe.imphash() == "65ae5cf17140aeaf91e3e9911da0ee3e" or
         1 of them
      )
}


rule MAL_SUSP_Gamaredon_GetImportByHash {
    meta:
        description = "Detects Gamaredon APIHashing"
        author = "Frank Boldewin (@r3c0nst)"
        date = "2021-05-12"
        reference  = "https://twitter.com/r3c0nst/status/1392405576131436546?s=20"
        hash1 = "2d03a301bae0e95a355acd464afc77fde88dd00232aad6c8580b365f97f67a79"
        hash2 = "43d6e56515cca476f7279c3f276bf848da4bc13fd15fad9663b9e044970253e8"
        hash3 = "5c09f6ebb7243994ddc466058d5dc9920a5fced5e843200b1f057bda087b8ba6"
        id = "8f28273e-e8ca-52cb-8dbc-a235598b1975"
    strings:
        $ParseImgExportDir = { 8B 50 3C 03 D0 8B 52 78 03 D0 8B 4A 1C 03 C8 }
        $djb2Hashing = { 8B 75 08 BA 05 15 00 00 8B C2 C1 E2 05 03 D0 33 DB 8A 1E 03 D3 46 33 DB 8A 1E 85 DB 75 } 
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MAL_crime_win32_loader_guloader_1_experimental {
   meta:
      description = "Detects injected GuLoader shellcode bin"
      author = "@VK_Intel"
      reference = "https://twitter.com/VK_Intel/status/1257206565146370050"
      tlp = "white"
      date = "2020-05-04"
      id = "c37882c6-15dc-54dc-8c10-7e91ea0fc6bd"
   strings:
      $djib2_hash = { f8 8b ?? ?? ?? ba 05 15 00 00 89 d3 39 c0 c1 e2 05 81 ff f6 62 f1 87 01 da 0f ?? ?? d9 d0 01 da 83 c6 02 66 ?? ?? ?? 75 ?? c2 04 00}
      $nt_inject_loader = {8b ?? ?? ba 44 1a 0e 9e 39 d2 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? f8 ba d0 e0 8b 30 e8 ?? ?? ?? ?? d9 d0 89 ?? ?? d9 d0 81 fb 20 af 00 00 8b ?? ?? 39 c9 ba 92 a7 f3 95 e8 ?? ?? ?? ?? 89 ?? ?? 8b ?? ?? 39 d2 ba d0 20 2e d0 e8 ?? ?? ?? ?? 89 ?? ?? f8 8b ?? ?? ba 6a 19 1f 23 d9 d0 e8 ?? ?? ?? ?? d9 d0 89 ?? ?? 81 fb e4 8c 00 00 39 c9 8b ?? ?? ba 19 50 9c c2 e8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 39 d2 8b ?? ?? fc ba 3d 13 8e 8b e8 ?? ?? ?? ?? d9 d0 89 ?? ?? f8 8b ?? ?? ba 30 3d 7b 2c e8 ?? ?? ?? ??}
   condition:
      uint16(0) == 0x5a4d and all of them 
}


rule MAL_IcedID_GZIP_LDR_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-12"
      modified = "2023-01-27"
      description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "fbf578e7-c318-5f67-82df-f93232362a23"
   strings:
      $internal_name = "loader_dll_64.dll" fullword

      $string0 = "_gat=" wide
      $string1 = "_ga=" wide
      $string2 = "_gid=" wide
      $string4 = "_io=" wide
      $string5 = "GetAdaptersInfo" fullword
      $string6 = "WINHTTP.dll" fullword
      $string7 = "DllRegisterServer" fullword
      $string8 = "PluginInit" fullword
      $string9 = "POST" wide fullword
      $string10 = "aws.amazon.com" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name or all of ($s*) )
      or all of them
}



rule MAL_IcedId_Core_LDR_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-13"
      description = "2021 loader for Bokbot / Icedid core (license.dat)"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "f096e18d-3a31-5236-b3c3-0df39b408d9a"
   strings:
      $internal_name = "sadl_64.dll" fullword

      $string0 = "GetCommandLineA" fullword
      $string1 = "LoadLibraryA" fullword
      $string2 = "ProgramData" fullword
      $string3 = "SHLWAPI.dll" fullword
      $string4 = "SHGetFolderPathA" fullword
      $string5 = "DllRegisterServer" fullword
      $string6 = "update" fullword
      $string7 = "SHELL32.dll" fullword
      $string8 = "CreateThread" fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name and 5 of them )
      or all of them
}



rule MAL_IceId_Core_202104 {
   meta:
      author = "Thomas Barabosch, Telekom Security"
      date = "2021-04-12"
      description = "2021 Bokbot / Icedid core"
      reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
      id = "526a73da-415f-58fe-bb5f-4c3df6b2e647"
   strings:
      $internal_name = "fixed_loader64.dll" fullword

      $string0 = "mail_vault" wide fullword
      $string1 = "ie_reg" wide fullword
      $string2 = "outlook" wide fullword
      $string3 = "user_num" wide fullword
      $string4 = "cred" wide fullword
      $string5 = "Authorization: Basic" fullword
      $string6 = "VaultOpenVault" fullword
      $string7 = "sqlite3_free" fullword
      $string8 = "cookie.tar" fullword
      $string9 = "DllRegisterServer" fullword
      $string10 = "PT0S" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 5000KB and 
      ( $internal_name or all of ($s*) )
      or all of them
}


rule MAL_GandCrab_Apr18_1 {
   meta:
      description = "Detects GandCrab malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/MarceloRivero/status/988455516094550017"
      date = "2018-04-23"
      hash1 = "6fafe7bb56fd2696f2243fc305fe0c38f550dffcfc5fca04f70398880570ffff"
      id = "ef7983cd-a7b3-5ce2-8cff-1bcf35bc6140"
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "7936b0e9491fd747bf2675a7ec8af8ba"
}


rule MAL_Nitol_Malware_Jan19_1 {
   meta:
      description = "Detects Nitol Malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/shotgunner101/status/1084602413691166721"
      date = "2019-01-14"
      hash1 = "fe65f6a79528802cb61effc064476f7b48233fb0f245ddb7de5b7cc8bb45362e"
      id = "5b9968a8-31ba-593b-9e01-b69a4e31fe65"
   strings:
      $xc1 = { 00 25 75 20 25 73 00 00 00 30 2E 30 2E 30 2E 30
               00 25 75 20 4D 42 00 00 00 25 64 2A 25 75 25 73
               00 7E 4D 48 7A }
      $xc2 = "GET ^&&%$%$^" ascii

      $n1 = ".htmGET " ascii

      $s1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
      $s2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $s3 = "User-Agent:Mozilla/5.0 (X11; U; Linux i686; en-US; re:1.4.0) Gecko/20080808 Firefox/%d.0" fullword ascii
      $s4 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.imphash() == "286870a926664a5129b8b68ed0d4a8eb" or
         1 of ($x*) or
         #n1 > 4 or
         4 of them
      )
}


rule MAL_Ransomware_Wadhrama {
   meta:
      description = "Detects Wadhrama Ransomware via Imphash"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-04-07"
      hash1 = "557c68e38dce7ea10622763c10a1b9f853c236b3291cd4f9b32723e8714e5576"
      id = "f7de40e9-fe22-5f14-abc6-f6611a4382ac"
   condition:
      uint16(0) == 0x5a4d and pe.imphash() == "f86dec4a80961955a89e7ed62046cc0e"
}


rule MAL_unspecified_Jan18_1 {
   meta:
      description = "Detects unspecified malware sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-01-19"
      hash1 = "f87879b29ff83616e9c9044bd5fb847cf5d2efdd2f01fc284d1a6ce7d464a417"
      id = "f3187c60-8fff-54de-9918-2fb2301f2d92"
   strings:
      $s1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
      $s2 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" fullword ascii
      $s3 = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
      $s4 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" fullword ascii
      $s5 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
      $s6 = "%s\\%s.bat" fullword ascii
      $s7 = "DEL /s \"%s\" >nul 2>&1" fullword ascii
   condition:
      filesize < 300KB and 2 of them
}


rule MAL_XMR_Miner_May19_1 : HIGHVOL {
   meta:
      description = "Detects Monero Crypto Coin Miner"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      score = 85
      hash1 = "d6df423efb576f167bc28b3c08d10c397007ba323a0de92d1e504a3f490752fc"
      id = "233d1d47-de67-55a9-ae7e-46b5dd34e6ce"
   strings:
      $x1 = "donate.ssl.xmrig.com" fullword ascii
      $x2 = "* COMMANDS     'h' hashrate, 'p' pause, 'r' resume" fullword ascii

      $s1 = "[%s] login error code: %d" fullword ascii
      $s2 = "\\\\?\\pipe\\uv\\%p-%lu" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and (
         pe.imphash() == "25d9618d1e16608cd5d14d8ad6e1f98e" or
         1 of ($x*) or
         2 of them
      )
}



rule SUSP_PDB_CN_Threat_Actor_May19_1 {
   meta:
      description = "Detects PDB path user name used by Chinese threat actors"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      score = 65
      hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
      id = "fc6969ed-5fc1-5b3b-9659-c6fc1c9e2f9c"
   strings:
      $x1 = "C:\\Users\\zcg\\Desktop\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}



rule MAL_Ramnit_May19_1 {
   meta:
      description = "Detects Ramnit malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      hash1 = "d7ec3fcd80b3961e5bab97015c91c843803bb915c13a4a35dfb5e9bdf556c6d3"
      id = "f8fa3557-556e-5680-9f1a-2ecf118ade75"
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB
      and pe.imphash() == "500cd02578808f964519eb2c85153046"
}



rule MAL_Parite_Malware_May19_1 {
   meta:
      description = "Detects Parite malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      score = 80
      hash1 = "c9d8852745e81f3bfc09c0a3570d018ae8298af675e3c6ee81ba5b594ff6abb8"
      hash2 = "8d47b08504dcf694928e12a6aa372e7fa65d0d6744429e808ff8e225aefa5af2"
      hash3 = "285e3f21dd1721af2352196628bada81050e4829fb1bb3f8757a45c221737319"
      hash4 = "b987dcc752d9ceb3b0e6cd4370c28567be44b789e8ed8a90c41aa439437321c5"
      id = "f4c9da17-9894-5243-828a-827accb0bac5"
   strings:
      $s1 = "taskkill /im cmd.exe /f" fullword ascii
      $s2 = "LOADERX64.dll" fullword ascii

      $x1 = "\\dllhot.exe" ascii
      $x2 = "dllhot.exe --auto --any --forever --keepalive" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) or 2 of them )
}



rule MAL_Parite_Malware_May19_2 {
   meta:
      description = "Detects Parite malware based on Imphash"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      hash1 = "c9d8852745e81f3bfc09c0a3570d018ae8298af675e3c6ee81ba5b594ff6abb8"
      hash2 = "8d47b08504dcf694928e12a6aa372e7fa65d0d6744429e808ff8e225aefa5af2"
      hash3 = "285e3f21dd1721af2352196628bada81050e4829fb1bb3f8757a45c221737319"
      hash4 = "b987dcc752d9ceb3b0e6cd4370c28567be44b789e8ed8a90c41aa439437321c5"
      id = "33970268-610c-5abf-9e9e-83dae0c81064"
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and (
         pe.imphash() == "b132a2719be01a6ef87d9939d785e19e" or
         pe.imphash() == "78f4f885323ffee9f8fa011455d0523d"
      )
}



rule MAL_RANSOM_Darkside_May21_1 {
   meta:
      description = "Detects Darkside Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/020c1740-717a-4191-8917-5819aa25f385/"
      date = "2021-05-10"
      hash1 = "ec368752c2cf3b23efbfa5705f9e582fc9d6766435a7b8eea8ef045082c6fbce"
      id = "e5592065-591e-597b-bebb-f20bc306fe52"
   strings:
      $op1 = { 85 c9 75 ed ff 75 10 ff b5 d8 fe ff ff ff b5 dc fe ff ff e8 7d fc ff ff ff 8d cc fe ff ff 8b 8d cc fe ff ff }
      $op2 = { 66 0f 6f 06 66 0f 7f 07 83 c6 10 83 c7 10 49 85 c9 75 ed 5f }
      $op3 = { 6a 00 ff 15 72 0d 41 00 ab 46 81 fe 80 00 00 00 75 2e 6a ff 6a 01 }
      $op4 = { 0f b7 0c 5d 88 0f 41 00 03 4c 24 04 89 4c 24 04 83 e1 3f 0f b7 14 4d 88 0f 41 00 03 54 24 08 89 54 24 08 83 e2 3f }

      $s1 = "http://darksid" ascii
      $s2 = "[ Welcome to DarkSide ]" ascii
      $s3 = ".onion/" ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      3 of them or all of ($op*) or all of ($s*)
}



rule MAL_Ransomware_Win_DARKSIDE_v1_1 {
    meta:
        author = "FireEye"
        date = "2021-03-22"
        description = "Detection for early versions of DARKSIDE ransomware samples based on the encryption mode configuration values."
        hash = "1a700f845849e573ab3148daef1a3b0b"
        reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
        id = "322a3de5-a7e5-52b9-8648-6019954e92d7"
    strings:
        $consts = { 80 3D [4] 01 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] 00 00 04 00 [1-10] 00 00 00 00 [1-30] 80 3D [4] 02 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] FF FF FF FF [1-10] FF FF FF FF [1-30] 03 00 00 00 [1-10] 03 00 00 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $consts
}



rule MAL_Dropper_Win_Darkside_1 {
    meta:
        author = "FireEye"
        date_created = "2021-05-11"
        description = "Detection for on the binary that was used as the dropper leading to DARKSIDE."
        reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
        id = "910a581c-25a4-5d5e-acdc-6d87cbedd3cf"
    strings:
        $CommonDLLs1 = "KERNEL32.dll" fullword
        $CommonDLLs2 = "USER32.dll" fullword
        $CommonDLLs3 = "ADVAPI32.dll" fullword
        $CommonDLLs4 = "ole32.dll" fullword
        $KeyString1 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 57 69 6E 64 6F 77 73 2E 43 6F 6D 6D 6F 6E 2D 43 6F 6E 74 72 6F 6C 73 22 20 76 65 72 73 69 6F 6E 3D 22 36 2E 30 2E 30 2E 30 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 22 }
        $KeyString2 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 56 43 39 30 2E 4D 46 43 22 20 76 65 72 73 69 6F 6E 3D 22 39 2E 30 2E 32 31 30 32 32 2E 38 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 31 66 63 38 62 33 62 39 61 31 65 31 38 65 33 62 22 }
        $Slashes = { 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C }
    condition:
        filesize < 2MB and filesize > 500KB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (all of ($CommonDLLs*)) and (all of ($KeyString*)) and $Slashes
}



rule MAL_Backdoor_Win_C3_1 {
    meta:
        author = "FireEye"
        date_created = "2021-05-11"
        description = "Detection to identify the Custom Command and Control (C3) binaries."
        md5 = "7cdac4b82a7573ae825e5edb48f80be5"
        reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
        id = "60eb022e-6f4e-5c7d-9ddf-b458a593071e"
    strings:
        $dropboxAPI = "Dropbox-API-Arg"
        $knownDLLs1 = "WINHTTP.dll" fullword
        $knownDLLs2 = "SHLWAPI.dll" fullword
        $knownDLLs3 = "NETAPI32.dll" fullword
        $knownDLLs4 = "ODBC32.dll" fullword
        $tokenString1 = { 5B 78 5D 20 65 72 72 6F 72 20 73 65 74 74 69 6E 67 20 74 6F 6B 65 6E }
        $tokenString2 = { 5B 78 5D 20 65 72 72 6F 72 20 63 72 65 61 74 69 6E 67 20 54 6F 6B 65 6E }
        $tokenString3 = { 5B 78 5D 20 65 72 72 6F 72 20 64 75 70 6C 69 63 61 74 69 6E 67 20 74 6F 6B 65 6E }
    condition:
        filesize < 5MB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (((all of ($knownDLLs*)) and ($dropboxAPI or (1 of ($tokenString*)))) or (all of ($tokenString*)))
}


rule SUSP_RANSOMWARE_Indicator_Jul20 {
   meta:
      description = "Detects ransomware indicator"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
      date = "2020-07-28"
      score = 60
      hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
      hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
      hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
      id = "6036fdfd-8474-5d79-ac75-137ac2efdc77"
   strings:
      $ = "Decrypt.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "Decrypt-Files.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT.txt" ascii wide 
      $ = "DecryptFiles.txt" ascii wide
      $ = "DECRYPT-FILES.txt" ascii wide
      $ = "DecryptFilesHere.txt" ascii wide
      $ = "DECRYPT_INSTRUCTION.TXT" ascii wide 
      $ = "FILES ENCRYPTED.txt" ascii wide
      $ = "DECRYPT MY FILES" ascii wide 
      $ = "DECRYPT-MY-FILES" ascii wide 
      $ = "DECRYPT_MY_FILES" ascii wide
      $ = "DECRYPT YOUR FILES" ascii wide  
      $ = "DECRYPT-YOUR-FILES" ascii wide 
      $ = "DECRYPT_YOUR_FILES" ascii wide 
      $ = "DECRYPT FILES.txt" ascii wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 1400KB and
      1 of them
}


rule MAL_Ransomware_GermanWiper {
   meta:
      description = "Detects RansomWare GermanWiper in Memory or in unpacked state"
      author = "Frank Boldewin (@r3c0nst), modified by Florian Roth"
      reference = "https://twitter.com/r3c0nst/status/1158326526766657538"
      date = "2019-08-05"
      hash_packed = "41364427dee49bf544dcff61a6899b3b7e59852435e4107931e294079a42de7c"
      hash_unpacked = "708967cad421bb2396017bdd10a42e6799da27e29264f4b5fb095c0e3503e447"

      id = "e7587691-f69a-53e7-bab2-875179fbfa19"
   strings:
      $x_Mutex1 = "HSDFSD-HFSD-3241-91E7-ASDGSDGHH" ascii
      $x_Mutex2 = "cFgxTERNWEVhM2V" ascii

      // code patterns for process kills
      $PurgeCode = { 6a 00 8b 47 08 50 6a 00 6a 01 e8 ?? ?? ?? ??
                     50 e8 ?? ?? ?? ?? 8b f0 8b d7 8b c3 e8 }
      $ProcessKill1 = "sqbcoreservice.exe" ascii
      $ProcessKill2 = "isqlplussvc.exe"  ascii
      $KillShadowCopies = "vssadmin.exe delete shadows" ascii
      $Domain1 = "cdnjs.cloudflare.com" ascii
      $Domain2 = "expandingdelegation.top" ascii
      $RansomNote = "Entschluesselungs_Anleitung.html" ascii
   condition:
      uint16(0) == 0x5A4D and filesize < 1000KB and
      ( 1 of ($x*) or 3 of them )
}


rule MAL_Prolock_Malware {
	meta:
		description = "Detects Prolock malware in encrypted and decrypted mode"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Prolock.Malware.yar"
		date = "2020-05-17"
		hash1 = "a6ded68af5a6e5cc8c1adee029347ec72da3b10a439d98f79f4b15801abd7af0"
		hash2 = "dfbd62a3d1b239601e17a5533e5cef53036647901f3fb72be76d92063e279178"
		
		id = "269bf0c5-8315-5405-8e44-e2cc5507a36a"
	strings:
		$DecryptionRoutine = {01 C2 31 DB B8 ?? ?? ?? ?? 31 04 1A 81 3C 1A}
		$DecryptedString1 = "support981723721@protonmail.com" nocase ascii
		$DecryptedString2 = "Your files have been encrypted by ProLock Ransomware" nocase ascii
		$DecryptedString3 = "msaoyrayohnp32tcgwcanhjouetb5k54aekgnwg7dcvtgtecpumrxpqd.onion" nocase ascii
		$CryptoCode = {B8 63 51 E1 B7 31 D2 8D BE ?? ?? ?? ?? B9 63 51 E1 B7 81 C1 B9 79 37 9E}
		
	condition:
		((uint16(0) == 0x5A4D) or (uint16(0) == 0x4D42)) and filesize < 100KB and (($DecryptionRoutine) or (1 of ($DecryptedString*) and $CryptoCode))
}

rule MAL_RANSOM_Ragna_Locker_Apr20_1 {
   meta:
      description = "Detects Ragna Locker Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://otx.alienvault.com/indicator/file/c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      date = "2020-04-27"
      hash1 = "c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      id = "67164cb4-73b7-5c4e-88f9-42379b88c641"
   strings:
      $x1 = "---RAGNAR SECRET---" ascii
      $xc1 = { 0D 0A 25 73 0D 0A 0D 0A 25 73 0D 0A 25 73 0D 0A
               25 73 0D 0A 0D 0A 25 73 0D 0A 00 00 2E 00 72 00
               61 00 67 00 6E 00 61 00 72 00 5F }
      $xc2 = { 00 2D 00 66 00 6F 00 72 00 63 00 65 00 00 00 00
               00 57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C
               00 44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00
               00 5C 00 6E 00 6F 00 74 00 65 00 70 00 61 00 64
               00 2E 00 65 00 78 00 65 00 }

      $s1 = "bootfont.bin" wide fullword

      $sc2 = { 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 00
               00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2E
               00 6F 00 6C 00 64 00 00 00 54 00 6F 00 72 00 20
               00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 }

      $op1 = { c7 85 58 ff ff ff 55 00 6b 00 c7 85 5c ff ff ff }
      $op2 = { 50 c7 85 7a ff ff ff 5c }
      $op3 = { 8b 75 08 8a 84 0d 20 ff ff ff ff 45 08 32 06 8b }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      1 of ($x*) or 4 of them
}



rule MAL_Ransom_Ragnarlocker_July_2020_1 {
   meta:
      description = "Detects Ragnarlocker by strings (July 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/JAMESWT_MHT/status/1288797666688851969"
      date = "2020-07-30"
      hash1 = "04c9cc0d1577d5ee54a4e2d4dd12f17011d13703cdd0e6efd46718d14fd9aa87"
      id = "60e09057-d9f8-5e89-8f47-c5dda32806c6"
   strings:
      $f1 = "bootfont.bin" fullword wide
      $f2 = "bootmgr.efi" fullword wide
      $f3 = "bootsect.bak" fullword wide
      $r1 = "$!.txt" fullword wide
      $r2 = "---BEGIN KEY R_R---" fullword ascii
      $r3 = "!$R4GN4R_" wide
      $r4 = "RAGNRPW" fullword ascii 
      $r5 = "---END KEY R_R---" fullword ascii
      $a1 = "+RhRR!-uD8'O&Wjq1_P#Rw<9Oy?n^qSP6N{BngxNK!:TG*}\\|W]o?/]H*8z;26X0" fullword ascii    
      $a2 = "\\\\.\\PHYSICALDRIVE%d" fullword wide 
      $a3 = "WinSta0\\Default" fullword wide 
      $a4 = "%s-%s-%s-%s-%s" fullword wide 
      $a5 = "SOFTWARE\\Microsoft\\Cryptography" fullword wide 
      $c1 = "-backup" fullword wide
      $c2 = "-force" fullword wide
      $c3 = "-vmback" fullword wide
      $c4 = "-list" fullword wide
      $s1 = ".ragn@r_" wide 
      $s2 = "\\notepad.exe" wide 
      $s3 = "Opera Software" fullword wide  
      $s4 = "Tor browser" fullword wide 
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and ( pe.imphash() == "2c2aab89a4cba444cf2729e2ed61ed4f" and ( (2 of ($f*)) and (3 of ($r*)) and (4 of ($a*)) and (2 of ($c*)) and (2 of ($s*)) ) )
}

rule MAL_RANSOM_REvil_Oct20_1 {
   meta:
      description = "Detects REvil ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2020-10-13"
      hash1 = "5966c25dc1abcec9d8603b97919db57aac019e5358ee413957927d3c1790b7f4"
      hash2 = "f66027faea8c9e0ff29a31641e186cbed7073b52b43933ba36d61e8f6bce1ab5"
      hash3 = "f6857748c050655fb3c2192b52a3b0915f3f3708cd0a59bbf641d7dd722a804d"
      hash4 = "fc26288df74aa8046b4761f8478c52819e0fca478c1ab674da7e1d24e1cfa501"
      id = "0c85a2cc-3487-577f-bd12-e3effd8fc811"
   strings:
      $op1 = { 0f 8c 74 ff ff ff 33 c0 5f 5e 5b 8b e5 5d c3 8b }
      $op2 = { 8d 85 68 ff ff ff 50 e8 2a fe ff ff 8d 85 68 ff }
      $op3 = { 89 4d f4 8b 4e 0c 33 4e 34 33 4e 5c 33 8e 84 }
      $op4 = { 8d 85 68 ff ff ff 50 e8 05 06 00 00 8d 85 68 ff }
      $op5 = { 8d 85 68 ff ff ff 56 57 ff 75 0c 50 e8 2f }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      2 of them or 4 of them
}


rule MAL_RANSOM_RobinHood_May19_1 {
   meta:
      description = "Detects RobinHood Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/BThurstonCPTECH/status/1128489465327030277"
      date = "2019-05-15"
      hash1 = "21cb84fc7b33e8e31364ff0e58b078db8f47494a239dc3ccbea8017ff60807e3"
      id = "7199c0de-c925-5399-8fa6-852604190a21"
   strings:
      $s1 = ".enc_robbinhood" ascii
      $s2 = "c:\\windows\\temp\\pub.key" ascii fullword
      $s3 = "cmd.exe /c net use * /DELETE /Y" ascii
      $s4 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s5 = "main.EnableShadowFucks" nocase
      $s6 = "main.EnableRecoveryFCK" nocase
      $s7 = "main.EnableLogLaunders" nocase
      $s8 = "main.EnableServiceFuck" nocase
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}


rule MAL_RANSOM_Venus_Nov22_1 {
   meta:
      description = "Detects Venus Ransomware samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/dyngnosis/status/1592588860168421376"
      date = "2022-11-16"
      score = 85
      hash1 = "46f9cbc3795d6be0edd49a2c43efe6e610b82741755c5076a89eeccaf98ee834"
      hash2 = "6d8e2d8f6aeb0f4512a53fe83b2ef7699513ebaff31735675f46d1beea3a8e05"
      hash3 = "931cab7fbc0eb2bbc5768f8abdcc029cef76aff98540d9f5214786dccdb6a224"
      hash4 = "969bfe42819e30e35ca601df443471d677e04c988928b63fccb25bf0531ea2cc"
      hash5 = "db6fcd33dcb3f25890c28e47c440845b17ce2042c34ade6d6508afd461bfa21c"
      hash6 = "ee036f333a0c4a24d9aa09848e635639e481695a9209474900eb71c9e453256b"
      hash7 = "fa7ba459236c7b27a0429f1961b992ab87fc8b3427469fd98bfc272ae6852063"
      id = "0f7e0ca4-c5e2-5557-92de-2e0d73035f12"
   strings:
      $x1 = "<html><head><title>Venus</title><style type = \"text" ascii fullword
      $x2 = "xXBLTZKmAu9pjcfxrIK4gkDp/J9XXATjuysFRXG4rH4=" ascii fullword
      $x3 = "%s%x%x%x%x.goodgame" wide fullword

      $s1 = "/c ping localhost -n 3 > nul & del %s" ascii fullword
      $s2 = "C:\\Windows\\%s.png" wide

      $op1 = { 8b 4c 24 24 46 8b 7c 24 14 41 8b 44 24 30 81 c7 00 04 00 00 81 44 24 10 00 04 00 00 40 }
      $op2 = { 57 c7 45 fc 00 00 00 00 7e 3f 50 33 c0 74 03 9b 6e }
      $op3 = { 66 89 45 d4 0f 11 45 e8 e8 a8 e7 ff ff 83 c4 14 8d 45 e8 50 8d 45 a4 50 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      (
         pe.imphash() == "bb2600e94092da119ee6acbbd047be43" or
         1 of ($x*) or
         2 of them
      ) 
      or 4 of them
}



rule MAL_crime_win32_rat_parallax_shell_bin {
   meta:
      description = "Detects Parallax injected code"
      author = "@VK_Intel"
      reference = "https://twitter.com/VK_Intel/status/1257714191902937088"
      tlp = "white"
      date = "2020-05-05"
      id = "6bb337ef-3156-589a-9b2f-fa1b21699433"
   strings:
      $ntdll_load = {55 8b ec 81 ec d0 08 00 00 53 56 57 e8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 33 c0 b9 18 01 00 00 f3 ?? 68 02 9f e6 6a e8 ?? ?? ?? ?? 8b d8 68 40 5e c0 84 89 ?? ?? e8 ?? ?? ?? ?? 6a 00 8b f0 68 0b 1c 64 72 53 89 ?? ?? e8 ?? ?? ?? ?? 83 c4 14 89 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 68 30 02 00 00 51 ff d0 6a 6e 58 6a 74 66 ?? ?? ?? ?? ?? ?? 58 6a 64 59 6a 6c 66 ?? ?? ?? ?? ?? ?? 58 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 33 c0 6a 2e}
      $call_func = {81 ec bc 00 00 00 8d ?? ?? 56 50 6a 00 6a 01 ff ?? ?? e8 ?? ?? ?? ?? 8b f0 83 c4 10 85 f6 0f ?? ?? ?? ?? ?? 33 c9 89 ?? ?? 39 ?? ?? 0f ?? ?? ?? ?? ?? 8b ?? ?? 53 57 8b ?? ?? 8d ?? ?? 0f ?? ?? ?? 8b ?? ?? 8d ?? ?? 8b ?? ?? 03 fa 8b df 2b da 03 ?? ?? 80 ?? ?? 0f ?? ?? ?? ?? ?? 83 ?? ?? ?? 8b c7 83 ?? ?? ?? 83 ?? ?? ?? 83 ?? ?? ?? 83 ?? ?? ?? 83 ?? ?? ?? 99 89 ?? ?? 8b ca 89 ?? ?? 8d ?? ?? 99 89 ?? ?? 89 ?? ?? 8d ?? ?? 89 ?? ?? 89 ?? ?? 8b ca 99 89 ?? ?? 89 ?? ?? 8b ca 89 ?? ?? 89 ?? ?? 8d ?? ?? 6a 40 89 ?? ??}
      $cryp_hex =  {8b ec 8b ?? ?? 25 55 55 55 55 d1 e0 8b ?? ?? d1 e9 81 e1 55 55 55 55 0b c1 89 ?? ?? 8b ?? ?? 81 e2 33 33 33 33 c1 e2 02 8b ?? ?? c1 e8 02 25 33 33 33 33 0b d0 89 ?? ?? 8b ?? ?? 81 e1 0f 0f 0f 0f c1 e1 04 8b ?? ?? c1 ea 04 81 e2 0f 0f 0f 0f 0b ca 89 ?? ?? 8b ?? ?? c1 e0 18 8b ?? ?? 81 e1 00 ff 00 00 c1 e1 08 0b c1 8b ?? ?? c1 ea 08 81 e2 00 ff 00 00 0b c2 8b ?? ?? c1 e9 18 0b c1 89 ?? ?? 8b ?? ?? 5d c3}
   condition:
      uint16(0) == 0x5a4d and 2 of them or all of them
}


rule MAL_Ryuk_Ransomware {
   meta:
      description = "Detects strings known from Ryuk Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/"
      date = "2018-12-31"
      hash1 = "965884f19026913b2c57b8cd4a86455a61383de01dabb69c557f45bb848f6c26"
      hash2 = "b8fcd4a3902064907fb19e0da3ca7aed72a7e6d1f94d971d1ee7a4d3af6a800d"
      id = "25d40631-4158-5d3d-913e-a2f1233489e0"
   strings:
      $x1 = "/v \"svchos\" /f" fullword wide
      $x2 = "\\Documents and Settings\\Default User\\finish" wide
      $x3 = "\\users\\Public\\finish" wide
      $x4 = "lsaas.exe" fullword wide
      $x5 = "RyukReadMe.txt" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
         pe.imphash() == "4a069c1abe5aca148d5a8fdabc26751e" or
         pe.imphash() == "dc5733c013378fa418d13773f5bfe6f1" or
         1 of them
      )
}


rule MAL_Trickbot_Oct19_1 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
      id = "b428cbf9-0796-5a01-9b98-28e1bc6827cc"
   strings:
      $s1 = "Celestor@hotmail.com" fullword ascii
      $s2 = "\\txtPassword" ascii
      $s14 = "Invalid Password, try again!" fullword wide

      $op1 = { 78 c4 40 00 ff ff ff ff b4 47 41 }
      $op2 = { 9b 68 b2 34 46 00 eb 14 8d 55 e4 8d 45 e8 52 50 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 3 of them
}



rule MAL_Trickbot_Oct19_2 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash2 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
      id = "2ff69a51-d089-53e5-ab19-4fbdf20f90f8"
   strings:
      $x1 = "C:\\Users\\User\\Desktop\\Encrypt\\Math_Cad\\Release\\Math_Cad.pdb" fullword ascii
      $x2 = "AxedWV3OVTFfnGb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 1 of them
}



rule MAL_Trickbot_Oct19_3 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
      hash2 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash3 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
      hash4 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash5 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
      id = "3428b7e3-def9-5574-bbbb-6ba98c134dec"
   strings:
      $s1 = "Decrypt Shell Fail" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and ( 1 of them or pe.imphash() == "4e3fbfbf1fc23f646cd40a6fe09385a7" )
}



rule MAL_Trickbot_Oct19_4 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
      hash2 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
      hash3 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash4 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
      id = "dcadaa50-52ae-5ded-b40e-149f28092093"
   strings:
      $x1 = "c:\\users\\user\\documents\\visual studio 2005\\projects\\adzxser\\release\\ADZXSER.pdb" fullword ascii
      $x2 = "http://root-hack.org" fullword ascii
      $x3 = "http://hax-studios.net" fullword ascii
      $x4 = "5OCFBBKCAZxWUE#$_SVRR[SQJ" fullword ascii
      $x5 = "G*\\AC:\\Users\\911\\Desktop\\cButtonBar\\cButtonBar\\ButtonBar.vbp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 1 of them
}



rule MAL_Trickbot_Oct19_5 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
      hash4 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
      id = "b3034f0c-5fd9-58a2-866f-9100e3a56f39"
   strings:
      $s1 = "LoadShellCode" fullword ascii
      $s2 = "pShellCode" fullword ascii
      $s3 = "InitShellCode" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 2 of them
}



rule MAL_Trickbot_Oct19_6 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
      hash2 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
      id = "5feb8d34-4974-5315-a5f9-79a3fac83d1d"
   strings:
      $x1 = "D:\\MyProjects\\spreader\\Release\\ssExecutor_x86.pdb" fullword ascii

      $s1 = "%s\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%s" fullword ascii
      $s2 = "%s\\appdata\\roaming\\%s" fullword ascii
      $s3 = "WINDOWS\\SYSTEM32\\TASKS" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 400KB and ( 1 of ($x*) or 3 of them )
}


rule SUSP_EXPL_CommVault_CVE_2025_57791_Aug25_1 {
   meta:
      description = "Detects potential exploit for WT-2025-0050, authentication bypass through QCommand argument injection"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      author = "X__Junior"
      date = "2025-08-21"
      score = 60
      id = "e83f8a1f-23cf-5f6d-aea1-414af813ee74"
   strings:
      $sa1 = "_localadmin__"
      $sa2 = "-localadmin"
   condition:
      not uint16(0) == 0x5a4d and
      filesize < 20MB and all of them
}



rule SUSP_MAL_SigningCert_Feb24_1 {
   meta:
      description = "Detects PE files signed with a certificate used to sign malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "37a39fc1feb4b14354c4d4b279ba77ba51e0d413f88e6ab991aad5dd6a9c231b"
      hash2 = "e8c48250cf7293c95d9af1fb830bb8a5aaf9cfb192d8697d2da729867935c793"
      id = "f25ea77a-1b4e-5c13-9117-eedf0c20335a"
   strings:
      $s1 = "Wisdom Promise Security Technology Co." ascii
      $s2 = "Globalsign TSA for CodeSign1" ascii
      $s3 = { 5D AC 0B 6C 02 5A 4B 21 89 4B A3 C2 }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 70000KB
      and all of them
}



rule MAL_CS_Loader_Feb24_1 {
   meta:
      description = "Detects Cobalt Strike malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "0a492d89ea2c05b1724a58dd05b7c4751e1ffdd2eab3a2f6a7ebe65bf3fdd6fe"
      id = "6c9914a4-b079-5a39-9d3b-7b9a2b54dc2b"
   strings:
      $s1 = "Dll_x86.dll" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 1000KB
      and (
         pe.exports("UpdateSystem") and (
            pe.imphash() == "0dc05c4c21a86d29f1c3bf9cc5b712e0"
            or $s1
         )
      )
}



rule MAL_RANSOM_LockBit_Indicators_Feb24 {
   meta:
      description = "Detects Lockbit ransomware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "a50d9954c0a50e5804065a8165b18571048160200249766bfa2f75d03c8cb6d0"
      id = "108430c8-4fe5-58a1-b709-539b257c120c"
   strings:
      $op1 = { 76 c1 95 8b 18 00 93 56 bf 2b 88 71 4c 34 af b1 a5 e9 77 46 c3 13 }
      $op2 = { e0 02 10 f7 ac 75 0e 18 1b c2 c1 98 ac 46 }
      $op3 = { 8b c6 ab 53 ff 15 e4 57 42 00 ff 45 fc eb 92 ff 75 f8 ff 15 f4 57 42 00 }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 500KB
      and (
         pe.imphash() == "914685b69f2ac2ff61b6b0f1883a054d"
         or 2 of them
      ) or all of them
}



rule MAL_Beacon_Unknown_Feb24_1 {
   meta:
      description = "Detects malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709 "
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "6e8f83c88a66116e1a7eb10549542890d1910aee0000e3e70f6307aae21f9090"
      hash2 = "b0adf3d58fa354dbaac6a2047b6e30bc07a5460f71db5f5975ba7b96de986243"
      hash3 = "c0f7970bed203a5f8b2eca8929b4e80ba5c3276206da38c4e0a4445f648f3cec"
      id = "9299fd44-5327-5a73-8299-108b710cb16e"
   strings:
      $s1 = "Driver.dll" wide fullword
      $s2 = "X l.dlT" ascii fullword
      $s3 = "$928c7481-dd27-8e23-f829-4819aefc728c" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 2000KB
      and 3 of ($s*)
}






rule SUSP_ASPX_PossibleDropperArtifact_Aug21 {
   meta:
      description = "Detects an ASPX file with a non-ASCII header, often a result of MS Exchange drop techniques"
      reference = "Internal Research"
      author = "Max Altgelt"
      date = "2021-08-23"
      score = 60
      id = "52016598-74a1-53d6-812a-40b078ba0bb9"
   strings:
      $s1 = "Page Language=" ascii nocase

      $fp1 = "Page Language=\"java\"" ascii nocase
   condition:
      filesize < 500KB
      and not uint16(0) == 0x4B50 and not uint16(0) == 0x6152 and not uint16(0) == 0x8b1f  // Exclude ZIP / RAR / GZIP files (can cause FPs when uncompressed)
      and not uint16(0) == 0x5A4D  // PE
      and not uint16(0) == 0xCFD0  // OLE
      and not uint16(0) == 0xC3D4  // PCAP
      and not uint16(0) == 0x534D  // CAB
      and all of ($s*) and not 1 of ($fp*) and
      (
         ((uint8(0) < 0x20 or uint8(0) > 0x7E   ) and uint8(0) != 0x9   and uint8(0) != 0x0D   and uint8(0) != 0x0A   and uint8(0) != 0xEF   )
         or ((uint8(1) < 0x20 or uint8(1) > 0x7E   ) and uint8(1) != 0x9   and uint8(1) != 0x0D   and uint8(1) != 0x0A   and uint8(1) != 0xBB   )
         or ((uint8(2) < 0x20 or uint8(2) > 0x7E   ) and uint8(2) != 0x9   and uint8(2) != 0x0D   and uint8(2) != 0x0A   and uint8(2) != 0xBF   )
         or ((uint8(3) < 0x20 or uint8(3) > 0x7E   ) and uint8(3) != 0x9   and uint8(3) != 0x0D   and uint8(3) != 0x0A   )
         or ((uint8(4) < 0x20 or uint8(4) > 0x7E   ) and uint8(4) != 0x9   and uint8(4) != 0x0D   and uint8(4) != 0x0A   )
         or ((uint8(5) < 0x20 or uint8(5) > 0x7E   ) and uint8(5) != 0x9   and uint8(5) != 0x0D   and uint8(5) != 0x0A   )
         or ((uint8(6) < 0x20 or uint8(6) > 0x7E   ) and uint8(6) != 0x9   and uint8(6) != 0x0D   and uint8(6) != 0x0A   )
         or ((uint8(7) < 0x20 or uint8(7) > 0x7E   ) and uint8(7) != 0x9   and uint8(7) != 0x0D   and uint8(7) != 0x0A   )
      )
}



rule MAL_Loader_TurtleLoader_Nov23 {
   meta:
      description = "Detects Tutle loader used in attacks against SysAid CVE-2023-47246"
      author = "Florian Roth"
      reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
      date = "2023-11-09"
      score = 85
      hash1 = "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d"
      id = "c7b5d03d-52c4-59b4-ac69-55e532a21340"
   strings:
      $s1 = "No key in args!" ascii fullword
      $s2 = "Bad data file!" ascii fullword
      $s3 = "Data file loaded. Running..." ascii

      $op1 = { 48 8d 55 c8 4c 8d 3d ac 8f 00 00 45 33 c9 45 33 d2 4d 8b e7 44 21 0a 45 33 db 4c 8d 3d 16 ec ff ff }
      $op2 = { 48 d3 e8 0f b6 c8 49 03 cb 49 81 c3 00 01 00 00 45 33 8c 8f a0 e4 00 00 41 83 fa 04 7c c7 41 ff c0 }
      $op3 = { 48 83 c1 04 48 ff ca 89 41 1c 75 ef 03 f6 48 83 c3 20 48 ff cd 0f 85 77 ff ff ff }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 200KB
      and 3 of them
}



rule MAL_EXE_LockBit_v2 {
	meta:
		author = "Silas Cutler, modified by Florian Roth"
		description = "Detection for LockBit version 2.x from 2011"
		date = "2023-01-01"
      modified = "2023-01-06"
		version = "1.0"
      score = 80
		hash = "00260c390ffab5734208a7199df0e4229a76261c3f5b7264c4515acb8eb9c2f8"
		DaysofYARA = "1/100"

		id = "a2c27110-e63b-5f93-88a0-98c12811e8b4"
	strings:
		$s_ransom_note01 = "that is located in every encrypted folder." wide
		$s_ransom_note02 = "Would you like to earn millions of dollars?" wide

		$x_ransom_tox = "3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" wide
		$x_ransom_url = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide

		$s_str1 = "Active:[ %d [                  Completed:[ %d" wide
		$x_str2 = "\\LockBit_Ransomware.hta" wide ascii
      $s_str2 = "Ransomware.hta" wide ascii
	condition:
		uint16(0) == 0x5A4D and ( 1 of ($x*) or 2 of them ) or 3 of them
}



rule MAL_EXE_PrestigeRansomware {
	meta:
		author = "Silas Cutler, modfied by Florian Roth"
		description = "Detection for Prestige Ransomware"
		date = "2023-01-04"
      modified = "2023-01-06"
		version = "1.0"
      score = 80
		reference = "https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/"
		hash = "5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57"
		DaysofYARA = "4/100"

		id = "5ac8033a-8b15-5abe-89d5-018a4fef9ab5"
	strings:
		$x_ransom_email = "Prestige.ranusomeware@Proton.me" wide
		$x_reg_ransom_note = "C:\\Windows\\System32\\reg.exe add HKCR\\enc\\shell\\open\\command /ve /t REG_SZ /d \"C:\\Windows\\Notepad.exe C:\\Users\\Public\\README\" /f" wide

		$ransom_message01 = "To decrypt all the data, you will need to purchase our decryption software." wide
		$ransom_message02 = "Contact us {}. In the letter, type your ID = {:X}." wide
		$ransom_message03 = "- Do not try to decrypt your data using third party software, it may cause permanent data loss." wide
		$ransom_message04 = "- Do not modify or rename encrypted files. You will lose them." wide
	condition:
		uint16(0) == 0x5A4D and 
			(1 of ($x*) or 2 of them or pe.imphash() == "a32bbc5df4195de63ea06feb46cd6b55")
}



rule MAL_EXE_RoyalRansomware {
	meta:
		author = "Silas Cutler, modfied by Florian Roth"
		description = "Detection for Royal Ransomware seen Dec 2022"
		date = "2023-01-03"
		version = "1.0"
		hash = "a8384c9e3689eb72fa737b570dbb53b2c3d103c62d46747a96e1e1becf14dfea"
		DaysofYARA = "3/100"

		id = "f83316f7-b8c4-5907-a38e-80535215e7ef"
	strings:
		$x_ext = ".royal_" wide
		$x_fname = "royal_dll.dll"
		$s_readme = "README.TXT" wide
		$s_cli_flag01 = "-networkonly" wide
		$s_cli_flag02 = "-localonly" wide
		$x_ransom_msg01 = "If you are reading this, it means that your system were hit by Royal ransomware."
		$x_ransom_msg02 = "Try Royal today and enter the new era of data security!"
		$x_onion_site = "http://royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion/"
	condition:
		uint16(0) == 0x5A4D and 
		( 
         2 of ($x*) or
		   5 of them
		)
}



rule SUSP_Excel4Macro_AutoOpen {
    meta:
        description = "Detects Excel4 macro use with auto open / close"
        author = "John Lambert @JohnLaTwC"
        date = "2020-03-26"
        score = 50
        hash="2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f"
        id = "cfed97fe-b330-5528-8402-08c6ba6af04a"
    strings:
        $header_docf = { D0 CF 11 E0 }
        $s1 = "Excel" fullword

        // 2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f
        // ' 0018     23 LABEL : Cell Value, String Constant - build-in-name 1 Auto_Open
        // 00002d80:
        // 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 01 00 16 00 07 00

        // f4c01e26eb88b72d38be3d6331fafe03b1ae53fdbff57d610173ed797fa26e73
        // 00003460: 00 00 18 00 17 00 20 00 00 01 07 00 00 00 00 00  ...... .........
        // 00003470: 00 00 00 00 00 01 3a 00 00 3f 02 8d 00 c1 01 08  ......:..?......

        // ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d
        // ' 0018     23 LABEL : Cell Value, String Constant - build-in-name 1 Auto_Open
        // 00003560: 00 00 00 00 00 18 00 17 00 aa 03 00 01 07 00 00  ................
        // 00003570: 00 00 00 00 00 00 00 00 01 3a 00 00 04 00 65 00  .........:....e.

        $Auto_Open  = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
        $Auto_Close = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }
        $Auto_Open1 = {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
        $Auto_Close1= {18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }

        // some Excel4 files don't have auto_open names e.g.:
        // b8b80e9458ff0276c9a37f5b46646936a08b83ce050a14efb93350f47aa7d269
        // 079be05edcd5793e1e3596cdb5f511324d0bcaf50eb47119236d3cb8defdfa4c


    condition:
        filesize < 3000KB
        and $header_docf at 0
        and $s1
        and any of ($Auto_*)
}


rule SUSP_NullSoftInst_Combo_Oct20_1 {
   meta:
      description = "Detects suspicious NullSoft Installer combination with common Copyright strings"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/malwrhunterteam/status/1313023627177193472"
      date = "2020-10-06"
      score = 65
      hash1 = "686b5240e5e503528cc5ac8d764883413a260716dd290f114a60af873ee6a65f"
      hash2 = "93951379e57e4f159bb62fd7dd563d1ac2f3f23c80ba89f2da2e395b8a647dcf"
      hash3 = "a9ca1d6a981ccc8d8b144f337c259891a67eb6b85ee41b03699baacf4aae9a78"
      id = "380f30a6-df6b-50c6-bb2d-b8785564bbac"
   strings:
      $a1 = "NullsoftInst" ascii 

      $b1 = "Microsoft Corporation" wide fullword
      $b2 = "Apache Software Foundation" ascii wide fullword
      $b3 = "Simon Tatham" wide fullword

      $fp1 = "nsisinstall" fullword ascii
      $fp2 = "\\REGISTRY\\MACHINE\\Software\\" wide
      $fp3 = "Apache Tomcat" wide fullword
      $fp4 = "Bot Framework Emulator" wide fullword
      $fp5 = "Firefox Helper" wide fullword
      $fp6 = "Paint.NET Setup" wide fullword
      $fp7 = "Microsoft .NET Services Installation Utility" wide fullword
      $fp8 = "License: MPL 2" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and
      $a1 and 1 of ($b*) and 
      not 1 of ($fp*)
}


rule SUSP_AnyDesk_Compromised_Certificate_Jan24_1 {
   meta:
      description = "Detects binaries signed with a compromised signing certificate of AnyDesk that aren't AnyDesk itself (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; strict version)"
      date = "2024-02-02"
      author = "Florian Roth"
      reference = "https://anydesk.com/en/public-statement"
      score = 75
      id = "8d172b04-f7f7-54df-b30c-3ee17d3cca12"
   strings:
      $a1 = "AnyDesk Software GmbH" wide
   condition:
      uint16(0) == 0x5a4d 
      and not $a1
      and for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8"
      )
}



rule SUSP_AnyDesk_Compromised_Certificate_Jan24_2 {
   meta:
      description = "Detects binaries signed with a compromised signing certificate of AnyDesk that aren't AnyDesk itself (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; permissive version)"
      date = "2024-02-02"
      author = "Florian Roth"
      reference = "https://anydesk.com/en/public-statement"
      score = 65
      id = "a41af8d8-ebdf-5a2f-8cf5-abd4587bdfc5"
   strings:
      $sc1 = { 0D BF 15 2D EA F0 B9 81 A8 A9 38 D5 3F 76 9D B8 }
      $s2 = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"

      $f1 = "AnyDesk Software GmbH" wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20000KB
      and all of ($s*)
      and not 1 of ($f*)
}



rule SUSP_AnyDesk_Compromised_Certificate_Jan24_3 {
   meta:
      description = "Detects binaries signed with a compromised signing certificate of AnyDesk after it was revoked (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; version that uses dates for validation)"
      date = "2024-02-02"
      author = "Florian Roth"
      reference = "https://anydesk.com/en/public-statement"
      score = 75
      id = "9610e61c-25d7-53e8-ba3f-b78b3d108aa3"
   condition:
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8" and
         // valid after Monday, January 29, 2024 0:00:00
         (
            pe.signatures[i].not_before > 1706486400 // certificate validity starts after it was revoked
            or pe.timestamp > 1706486400 // PE was created after it was revoked
         )
      )
}


rule SUSP_autocad_lsp_malware {
    meta:
        description = "Recognizes malicious autocad files written in LISP"
        author = "John Lambert @JohnLaTwC"
        date = "2019-02-04"
        reference1 = "http://cadablog.blogspot.com/2012/06/acadmedrea-malware-autocad-based-virus.html"
        hash1= "1313398e2f39fcf17225c7e915b92bd74292d427163112d70b82f271359b84d5"
        hash2= "2382e6908e6b44c0676c537cb8caa239c8938cb01e62a45c7247d40ab7dbf0ad"
        hash3= "23cf3e7f41a755a45e396e5caa3e753e64655b91fe665808f71aa68718670dc8"
        hash4= "23f018135afc4890e1e09bef9386e45e2236fc43550383b7888cddbdefbcd950"
        hash5= "4a8da078a02fc49b7f13cd19d10519b1bf31ed0ab04268f018ad4733918e28ff"
        hash6= "4cca7b530213ef71b2e69a5b11178b61044f93dc60f4e8e568ddb3bb06749ba2"
        hash7= "5390271899e1ebf884380f5da7d26dff527d13922d3b3f8a3b5ec9152b9dfa40"
        hash8= "53ef3029f36a3a2b912a722d64eef04f599f6f683c6dcb31a122ab1c98f38700"
        hash9= "7f7d78931370fa693cbfa50aadecc09b4ab93917dcde3a653bd67fa6dc274cdc"
        hash10= "8147cc97b6203c7eccfbd10457eb52527f74180ebae79bf3cb9c9edb582e708c"
        hash11= "8a3113ceb45725539e4ccef5ea1482c29b2bbe0ce7ede72f59f9949a0e04c5cd"
        hash12= "a0c77993f84ca8fb3096579088326bc907b003327f5885660ea5ba47e2cbc6de"
        hash13= "a20ac5e0bfa2ee3cb4092907420c23d1f94a1ed1b59cc3d351e5602d7206178c"
        hash14= "b201969ed7bf782d01011211b48bfccb9dd41a3a5a7456cdff2167f1e4d1b954"
        hash15= "b2bac49288329a777e7aa7001e9383eec75719c08f2aa8c278b44fabeb74844f"
        hash16= "b772dce92319bb48df39db6ab701761bd7645a771fd7f394510d5951695e7e96"
        hash17= "c116cc4db6f77c580c1c4f8acda537ed04e597739bc83011773dbeb77adf93e3"
        hash18= "ca1b9026b5d69c0981ca088330180d4865602fc2b514fd838664d3e11eab4468"
        hash19= "d7a814d677f9f9dd9666dc4f4bb9cca88fa90bdb074e87006e8810eef9a0fb32"
        hash20= "e4acfb69006b8aecf5801e36e2c69ccfeea2e8cbad4ceda9228d2dae2c8fd023"
        hash21= "f9d6b894ca907145464058a4e2c78de84bf592609b46f3573bfd9e0029e1c778"

        id = "3a4ac6e1-d7ea-5b9a-a386-9f881fad073b"
    strings:
        $s1 = /\(chr\s+\d+\)\s*\(chr\s+\d+\)\s*\(chr\s+\d+\)\s*\(chr\s+\d+\)/    //obfuscation
        $s2 = /vl\-list\-\>string\s+\'\(\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+/ //obfucation c116cc4db6f77c580c1c4f8acda537ed04e597739bc83011773dbeb77adf93e3

        $m1 = "strcat" nocase fullword
        $m2 = "write-line" nocase fullword
        $m3 = "open" nocase fullword
        $m4 = /acad\w*\.lsp\"/ nocase fullword


        $n1 = "vl-registry-write" nocase fullword
        $n2 = "NOHIDDEN" nocase fullword
        $n3 = "vlax-create-object " nocase fullword

    condition:
        filesize < 1MB
        and uint8(0) == 0x28 
        and (   
            1 of ($s*)
            or all of ($m*)
            or all of ($n*)
        )
} 


rule SUSP_PS1_Msdt_Execution_May22 {
   meta:
      description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190 / Follina exploitation"
      author = "Nasreddine Bencherchali, Christian Burkard"
      date = "2022-05-31"
      modified = "2025-03-21"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 65
      id = "a1863582-87a2-5d07-a549-ef4a31bf0ed2"
   strings:
      $a = "PCWDiagnostic" ascii wide fullword
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide
      $sa3 = "ms-msdt" ascii wide

      $sb1 = "/af " ascii wide
      $sb2 = "-af " ascii wide
      $sb3 = "IT_BrowseForFile=" ascii wide

      
      $fp1 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00
               46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00
               00 00 70 00 63 00 77 00 72 00 75 00 6E 00 2E 00
               65 00 78 00 65 00 }
      $fp2 = "FilesFullTrust" wide
      $fp3 = "Cisco Spark" ascii wide
      $fp4 = "author: " ascii
   condition:
      filesize < 10MB
      and $a
      and 1 of ($sa*)
      and 1 of ($sb*)
      and not 1 of ($fp*)
      // not JSON
      and not uint8(0) == 0x7B
}



rule SUSP_Fake_AMSI_DLL_Jun23_1 {
   meta:
      description = "Detects an amsi.dll that has the same exports as the legitimate one but very different contents or file sizes"
      author = "Florian Roth"
      reference = "https://twitter.com/eversinc33/status/1666121784192581633?s=20"
      date = "2023-06-07"
      modified = "2023-06-12"
      score = 65
      id = "b12df9de-ecfb-562b-b599-87fa786a33bc"
   strings:
      $a1 = "Microsoft.Antimalware.Scan.Interface" ascii
      $a2 = "Amsi.pdb" ascii fullword
      $a3 = "api-ms-win-core-sysinfo-" ascii
      $a4 = "Software\\Microsoft\\AMSI\\Providers" wide
      $a5 = "AmsiAntimalware@" ascii
      $a6 = "AMSI UAC Scan" ascii

      $fp1 = "Wine builtin DLL"
   condition:
      uint16(0) == 0x5a4d 
      // AMSI.DLL exports
      and (
         pe.exports("AmsiInitialize")
         and pe.exports("AmsiScanString")
      )
      // and now the anomalies
      and (
         filesize > 200KB     // files bigger than 100kB
         or filesize < 35KB   // files smaller than 35kB 
         or not 4 of ($a*)  // files that don't contain the expected strings
      )
      and not 1 of ($fp*)
}





rule SUSP_TINY_PE {
   meta:
      description = "Detects Tiny PE file"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://webserver2.tecgraf.puc-rio.br/~ismael/Cursos/YC++/apostilas/win32_xcoff_pe/tyne-example/Tiny%20PE.htm"
      date = "2019-10-23"
      score = 80
      id = "5081c24e-91d1-5705-9459-f675be4f0e3c"
   strings:
      $header = { 4D 5A 00 00 50 45 00 00 }
   condition:
      uint16(0) == 0x5a4d and uint16(4) == 0x4550 and filesize <= 20KB and $header at 0
}



rule SUSP_HxD_Icon_Anomaly_May23_1 {
   meta:
      description = "Detects suspicious use of the the free hex editor HxD's icon in PE files that don't seem to be a legitimate version of HxD"
      author = "Florian Roth"
      reference = "https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios"
      date = "2023-05-29"
      score = 65
      id = "3ac8cc92-6d76-5787-ada0-cfb6eabb4b20"
   strings:
      
      $ac1 = { 99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D D0 99 98 09
               99 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 09
               99 99 00 0D D0 99 98 0F F9 99 00 0D D0 99 98 09
               9F 99 00 0D D0 99 98 09 FF 99 00 0D D0 99 98 09
               FF 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 0F
               F9 99 00 0D D0 99 98 09 99 99 00 0D 09 99 80 9F
               F9 99 99 00 09 99 80 99 F9 99 99 00 09 99 80 FF }
      $ac2 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF B9 DE
               FA 68 B8 F4 39 A2 F1 39 A2 F1 39 A2 F1 39 A2 F1
               39 A2 F1 39 A2 F1 68 B8 F4 B9 DE FA FF FF FF FF
               FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }

      
      $s1 = { 00 4D 00 61 00 EB 00 6C 00 20 00 48 00 F6 00 72 00 7A } 
      $s2 = "mh-nexus.de" ascii wide

      
      $upx1 = "UPX0" ascii fullword

      
      $xs1 = "terminator" ascii wide fullword // https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios
      $xs2 = "Terminator" ascii wide fullword // https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios
   condition:
      // HxD indicators
      uint16(0) == 0x5a4d 
      and 1 of ($ac*)
      // Anomalies
      and (
         not 1 of ($s*) // not one of the expected strings
         or filesize > 6930000 // no legitimate sample bigger than 6.6MB
         // all legitimate binaries have a known size and shouldn't be smaller than ...
         or ( pe.is_32bit() and filesize < 1540000 and not $upx1 )
         or ( pe.is_32bit() and filesize < 590000 and $upx1 )
         or ( pe.is_64bit() and filesize < 6670000 and not $upx1 )
         or ( pe.is_64bit() and filesize < 1300000 and $upx1 )
         // keywords expected in malicious samples
         or 1 of ($xs*)
      )
}


rule SUSP_Unsigned_GoogleUpdate {
   meta:
      description = "Detects suspicious unsigned GoogleUpdate.exe"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-08-05"
      score = 60
      hash1 = "5aa84aa5c90ec34b7f7d75eb350349ae3aa5060f3ad6dd0520e851626e9f8354"
      id = "2575b882-3526-5c42-9d50-83fb0b7df3f5"
   strings:
      
      $ac1 = { 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C
               00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65
               00 00 00 47 00 6F 00 6F 00 67 00 6C 00 65 00 55
               00 70 00 64 00 61 00 74 00 65 00 2E 00 65 00 78
               00 65 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and $ac1
      and pe.number_of_signatures < 1
}


rule SUSP_AdobePDF_SFX_Bitmap_Combo_Executable {
   meta:
      description = "Detects a suspicious executable that contains both a SFX icon and an Adobe PDF icon"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mp.weixin.qq.com/s/3Pa3hiuZyQBspDzH0kGSHw"
      date = "2020-11-02"
      score = 60
      hash1 = "13655f536fac31e6c2eaa9e6e113ada2a0b5e2b50a93b6bbfc0aaadd670cde9b"
      id = "d2d078c9-fbe5-51f4-8f7e-5d943c5a8197"
   strings:
      
      $sc1 = { FF 00 CC FF FF 00 99 FF FF 00 66 FF FF 00 33 FF
               FF 80 00 FF FF 80 FF CC FF 80 CC CC FF C0 99 CC
               FF 80 66 CC FF 00 33 CC FF 00 00 CC FF 00 FF 99
               FF FF CC 99 FF FF 99 99 FF FF 66 99 FF FF 33 99
               FF 08 00 99 FF 88 FF 66 FF 88 CC 66 FF 88 99 66
               FF 88 66 66 FF 88 33 66 FF 05 00 66 FF 55 FF 33
               FF 55 CC 33 FF 55 99 33 FF 55 66 33 FF 58 33 33
               FF 01 00 33 FF 99 FF 00 FF 99 CC 00 FF 99 99 00
               FF 99 66 00 FF 58 33 00 FF 01 00 00 FF 99 FF FF
               CC 99 CC FF CC 99 99 FF CC 99 66 FF CC 58 33 FF
               CC 01 00 FF CC FF FF CC CC FF CC CC CC FF 99 CC
               CC FF 66 CC CC 58 33 CC CC 01 00 CC CC FF FF 99 }
      
      $sc2 = { 28 66 27 00 60 00 00 00 80 00 00 00 80 80 80 00
               C0 C0 C0 00 FF FF FF 00 FF FF FF 00 FF FF FF 00
               FF FF FF 00 FF FF FF 00 FF FF FF 00 FF FF FF 00
               FF FF FF 00 FF FF FF 00 5D 33 00 00 5D 33 00 00
               5D 33 00 00 5D 33 00 00 5D 33 00 00 5D 33 00 00
               5D 33 00 00 5D 33 00 00 5D 33 00 00 5D 33 00 00 }
   condition:
      uint16(0) == 0x5a4d and
      all of them
      and pe.number_of_signatures < 1
}



rule SUSP_AdobePDF_Bitmap_Executable {
   meta:
      description = "Detects a suspicious executable that contains a Adobe PDF icon and no shows no sign of actual Adobe software"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mp.weixin.qq.com/s/3Pa3hiuZyQBspDzH0kGSHw"
      date = "2020-11-02"
      score = 60
      hash1 = "13655f536fac31e6c2eaa9e6e113ada2a0b5e2b50a93b6bbfc0aaadd670cde9b"
      id = "86ebadd4-64a8-5290-b45e-ac125a10ea66"
   strings:
      
      $sc1 = { FF 00 CC FF FF 00 99 FF FF 00 66 FF FF 00 33 FF
               FF 80 00 FF FF 80 FF CC FF 80 CC CC FF C0 99 CC
               FF 80 66 CC FF 00 33 CC FF 00 00 CC FF 00 FF 99
               FF FF CC 99 FF FF 99 99 FF FF 66 99 FF FF 33 99
               FF 08 00 99 FF 88 FF 66 FF 88 CC 66 FF 88 99 66
               FF 88 66 66 FF 88 33 66 FF 05 00 66 FF 55 FF 33
               FF 55 CC 33 FF 55 99 33 FF 55 66 33 FF 58 33 33
               FF 01 00 33 FF 99 FF 00 FF 99 CC 00 FF 99 99 00
               FF 99 66 00 FF 58 33 00 FF 01 00 00 FF 99 FF FF
               CC 99 CC FF CC 99 99 FF CC 99 66 FF CC 58 33 FF
               CC 01 00 FF CC FF FF CC CC FF CC CC CC FF 99 CC
               CC FF 66 CC CC 58 33 CC CC 01 00 CC CC FF FF 99 }
      
      $fp1 = "Adobe" ascii wide fullword
   condition:
      uint16(0) == 0x5a4d and
      $sc1 and not 1 of ($fp*)
      and pe.number_of_signatures < 1
}


rule MAL_Malware_Imphash_Mar23_1 : HIGHVOL {
    meta:
        description = "Detects malware by known bad imphash or rich_pe_header_hash"
        reference = "https://yaraify.abuse.ch/statistics/"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp"
        date = "2023-03-20"
        modified = "2023-03-22"
        score = 75
        hash = "167dde6bd578cbfcc587d5853e7fc2904cda10e737ca74b31df52ba24db6e7bc"
        hash = "0a25a78c6b9df52e55455f5d52bcb3816460001cae3307b05e76ac70193b0636"
        hash = "d87a35decd0b81382e0c98f83c7f4bf25a2b25baac90c9dcff5b5a147e33bcc8"
        hash = "5783bf969c36f13f4365f4cae3ec4ee5d95694ff181aba74a33f4959f1f19e8b"
        hash = "4ca925b0feec851d787e7ee42d263f4c08b0f73f496049bdb5d967728ff91073"
        hash = "9c2d2fa9c32fdff1828854e8cc39160dae73a4f90fb89b82ef6d853b63035663"
        hash = "2c53d58f30b2ee1a2a7746e20f136c34d25d0214261783fc67e119329d457c2a"
        hash = "5e83747015b0589b4f04b0db981794adf53274076c1b4acf717e3ff45eca0249"
        hash = "ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247"
        hash = "82fb1ba998dfee806a513f125bb64c316989c36c805575914186a6b45da3b132"
        hash = "cb41d2520995abd9ba8ccd42e53d496a66da392007ea6aebd4cbc43f71ad461a"
        hash = "c7bd758506b72ee6db1cc2557baf745bf9e402127d8e49266cc91c90f3cf3ed5"
        hash = "e6e0d60f65a4ea6895ff97df340f6d90942bbfa402c01bf443ff5b4641ff849f"
        hash = "e8ddef9fa689e98ba2d48260aea3eb8fa41922ed718b7b9135df6426b3ddf126"
        hash = "ad57d77aba6f1bf82e0affe4c0ae95964be45fb3b7c2d6a0e08728e425ecd301"
        hash = "483df98eb489899bc89c6a0662ca8166c9b77af2f6bedebd17e61a69211843d9"
        hash = "a65ed85851d8751e6fe6a27ece7b3879b90866a10f272d8af46fb394b46b90a9"
        hash = "09081e04f3228d6ef2efc1108850958ed86026e4dfda199852046481f4711565"
        hash = "1b2c9054f44f7d08cffe7e2d9127dbd96206ab2c15b63ebf6120184950336ae1"
        hash = "257887d1c84eb15abb2c3c0d7eb9b753ca961d905f4979a10a094d0737d97138"
        hash = "1cbad8b58dbd1176e492e11f16954c3c254b5169dde52b5ad6d0d3c51930abf8"
        hash = "a9897fd2d5401071a8219b05a3e9b74b64ad67ab75044b3e41818e6305a8d7b9"
        hash = "aeac45fbc5d2a59c9669b9664400aeaf6699d76a57126d2f437833a3437a693e"
        hash = "7b4c4d4676fab6c009a40d370e6cb53ea4fd73b09c23426fbaccc66d652f2a00"
        hash = "b07f6873726276842686a6a6845b361068c3f5ce086811db05c1dc2250009cd0"
        hash = "d1b3afebcacf9dd87034f83d209b42b0d79e66e08c0a897942fbe5fbd6704a0e"
        hash = "074d52be060751cf213f6d0ead8e9ab1e63f055ae79b5fcbe4dd18469deea12b"
        hash = "84d1fdef484fa9f637ae3d6820c996f6c5cf455470e8717ad348a3d80d2fb8e0"
        hash = "437da123e80cfd10be5f08123cd63cfc0dc561e17b0bef861634d60c8a134eda"
        hash = "f76c36eb22777473b88c6a5fc150fd9d6b5fac5b2db093f0ccd101614c46c7e7"
        hash = "5498b7995669877a410e1c2b68575ca94e79014075ef5f89f0f1840c70ebf942"
        hash = "af4e633acfba903e7c92342b114c4af4e694c5cfaea3d9ea468a4d322b60aa85"
        hash = "d7d870f5afab8d4afa083ea7d7ce6407f88b0f08ca166df1a1d9bdc1a46a41b3"
        hash = "974209d88747fbba77069bb9afa9e8c09ee37ae233d94c82999d88dfcd297117"
        hash = "f2d99e7d3c59adf52afe0302b298c7d8ea023e9338c2870f74f11eaa0a332fc4"
        hash = "b32c93be9320146fc614fafd5e6f1bb8468be83628118a67eb01c878f941ee5d"
        hash = "bbd99acc750e6457e89acbc5da8b2a63b4ef01d4597d160e9cde5dc8bd04cf74"
        hash = "dbff5ca3d1e18902317ab9c50be4e172640a8141e09ec13dcca986f2ec1dc395"
        hash = "3ee1741a649f0b97bbeb05b6f9df97afda22c82e1e870177d8bdd34141ef163c"
        hash = "222096fc800c8ea2b0e530302306898b691858324dbe5b8357f90407e9665b85"
        hash = "b9995d1987c4e8b6fb30d255948322cfad9cc212c7f8f4c5db3ac80e23071533"
        hash = "a6a92ea0f27da1e678c15beb263647de43f68608afe82d6847450f16a11fe6c0"
        hash = "866e3ea86671a62b677214f07890ddf7e8153bec56455ad083c800e6ab51be37"
        id = "fb398c26-e9ac-55f9-b605-6b763021e96a"
    strings:
        $fp1 = "Win32 Cabinet Self-Extractor" wide
        $fp2 = "EXTRACTOPT" ascii fullword
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ (ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247) and the hash is calculated only on the header
            pe.imphash() == "9ee34731129f4801db97fd66adbfeaa0" or
            pe.imphash() == "f9e8597c55008e10a8cdc8a0764d5341" or
            pe.imphash() == "0a76016a514d8ed3124268734a31e2d2" or
            pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" or
            pe.imphash() == "d8b32e731e5438c6329455786e51ab4b" or
            pe.imphash() == "cdf5bbb8693f29ef22aef04d2a161dd7" or
            pe.imphash() == "890e522b31701e079a367b89393329e6" or
            pe.imphash() == "bf5a4aa99e5b160f8521cadd6bfe73b8" or
            pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" or
            pe.imphash() == "9f4693fc0c511135129493f2161d1e86" or
            pe.imphash() == "b4c6fff030479aa3b12625be67bf4914" // or

            // these have lots of hits on abuse.ch but none on VT? (except for my one test upload) honeypot collected samples?
            //pe.imphash() == "2c2ad1dd2c57d1bd5795167a7236b045" or
            //pe.imphash() == "46f03ef2495b21d7ad3e8d36dc03315d" or
            //pe.imphash() == "6db997463de98ce64bf5b6b8b0f77a45" or
            //pe.imphash() == "c9246f292a6fdc22d70e6e581898a026" or
            //pe.imphash() == "c024c5b95884d2fe702af4f8984b369e" or
            //pe.imphash() == "4dcbc0931c6f88874a69f966c86889d9" or
            //pe.imphash() == "48521d8a9924bcb13fd7132e057b48e1" or

            // rich_pe_header_hash:b6321cd8142ea3954c1a27b162787f7d p:2+ has 238k hits on VT including many files without imphash (e.g. e193dadf0405a826b3455185bdd9293657f910e5976c59e960a0809b589ff9dc) due to being corrupted?
            // zero hits with p:0
            // disable bc it's killing performance
            //hash.md5(pe.rich_signature.clear_data) == "b6321cd8142ea3954c1a27b162787f7d"
        )
        and not 1 of ($fp*)
}




rule SUSP_LNX_Linux_Malware_Indicators_Aug20_1 {
   meta:
      description = "Detects indicators often found in linux malware samples. Note: This detection is based on common characteristics typically associated with the mentioned threats, must be considered a clue and does not conclusively prove maliciousness."
      author = "Florian Roth (Nextron Systems)"
      score = 65
      reference = "Internal Research"
      date = "2020-08-03"
      modified = "2026-01-04"
      id = "9a1093a6-0239-5d1c-aa30-1ca725941583"
   strings:
      $s1 = "&& chmod +x" ascii
      $s2 = "|base64 -" ascii
      $s3 = " /tmp" ascii
      $s4 = "|curl " ascii
      $s5 = "whoami" ascii fullword

      $fp1 = "WITHOUT ANY WARRANTY" ascii
      $fp2 = "postinst" ascii fullword
      $fp3 = "THIS SOFTWARE IS PROVIDED" ascii fullword
      $fp4 = "Free Software Foundation" ascii fullword
      $fp5 = "Too many sessions open! Use ssh_channel.close() or 'with'!"
   condition:
      filesize < 400KB and
      3 of ($s*) and not 1 of ($fp*)
}


rule SUSP_3CX_App_Signed_Binary_Mar23_1 {
   meta:
      description = "Detects 3CX application binaries signed with a certificate and created in a time frame in which other known malicious binaries have been created"
      author = "Florian Roth (Nextron Systems)"
      date = "2023-03-29"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      score = 65
      hash1 = "fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405"
      hash2 = "dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc"
      id = "b6ce4c1d-1b7b-5e0c-af4c-05cb3ad0a4e0"
   strings:
      $sa1 = "3CX Ltd1"
      $sa2 = "3CX Desktop App" wide
      $sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 } // Known compromised cert
   condition:
      uint16(0) == 0x5a4d
      and pe.timestamp > 1669680000 // 29.11.2022 earliest known malicious sample 
      and pe.timestamp < 1680108505 // 29.03.2023 date of the report
      and all of ($sa*)
      and $sc1 // serial number of known compromised certificate
}



rule MAL_BackNet_Nov18_1 {
   meta:
      description = "Detects BackNet samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/valsov/BackNet"
      date = "2018-11-02"
      hash1 = "4ce82644eaa1a00cdb6e2f363743553f2e4bd1eddb8bc84e45eda7c0699d9adc"
      id = "f8575c5a-710d-5e97-91c1-5db454c6baf4"
   strings:
      $s1 = "ProcessedByFody" fullword ascii
      $s2 = "SELECT * FROM AntivirusProduct" fullword wide
      $s3 = "/C netsh wlan show profile" wide
      $s4 = "browsertornado" fullword wide
      $s5 = "Current user is administrator" fullword wide
      $s6 = "/C choice /C Y /N /D Y /T 4 & Del" wide
      $s7 = "ThisIsMyMutex-2JUY34DE8E23D7" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them
}


rule SUSP_Doc_WindowsInstaller_Call_Feb22_1 {
    meta:
        author = "Nils Kuhnert"
        date = "2022-02-26"
        description = "Triggers on docfiles executing windows installer. Used for deploying ThinBasic scripts."
        tlp = "white"
        reference = "https://inquest.net/blog/2022/02/24/dangerously-thinbasic"
        reference2 = "https://twitter.com/threatinsight/status/1497355737844133895"
        id = "8f2e8f91-74e0-5574-9c0a-1479d6114212"
    strings:
        $ = "WindowsInstaller.Installer$"
        $ = "CreateObject"
        $ = "InstallProduct"
    condition:
        uint32be(0) == 0xd0cf11e0 and all of them
}


rule MAL_Metasploit_Framework_UA {
   meta:
      description = "Detects User Agent used in Metasploit Framework"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/rapid7/metasploit-framework/commit/12a6d67be48527f5d3987e40cac2a0cbb4ab6ce7"
      date = "2018-08-16"
      score = 65
      hash1 = "1743e1bd4176ffb62a1a0503a0d76033752f8bd34f6f09db85c2979c04bbdd29"
      id = "e5a18456-3a07-5b58-ad95-086152298a1f"
   strings:
      $s3 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}



rule SUSP_NVIDIA_LAPSUS_Leak_Compromised_Cert_Mar22_1 {
   meta:
      description = "Detects a binary signed with the leaked NVIDIA certifcate and compiled after March 1st 2022"
      author = "Florian Roth (Nextron Systems)"
      date = "2022-03-03"
      modified = "2022-03-04"
      score = 70
      reference = "https://twitter.com/cyb3rops/status/1499514240008437762"
      id = "8bc7460f-a1c4-5157-8c2d-34d3a6c9c7e9"
   condition:
      uint16(0) == 0x5a4d and filesize < 100MB and
      pe.timestamp > 1646092800 and  // comment out to find all files signed with that certificate
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and (
            pe.signatures[i].serial == "43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5" or
            pe.signatures[i].serial == "14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18"
         )
   )
}


rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_1 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      modified = "2023-02-27"
      score = 65
      id = "b8ea8c7b-052f-5a97-9577-99903462ea84"
   strings:
      
      $x1 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4d 5a } // PE
      $x2 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 65 63 68 6f } // @echo off
      $x3 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 45 43 48 4f } // @ECHO OFF
      $x4 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 4F 6E 20 45 } // On Error Resume
      $x5 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 6F 6E 20 65 } // on error resume
      $x6 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4c 00 00 00 } // LNK file
      $x7 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 49 54 53 46 } // CHM file
      $x8 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 68 74 61 3A } // hta:
      $x9 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 48 54 41 3A } // HTA:
      $x10 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 6A 6F 62 20 } // WSF file "<job "
   condition:
      filesize < 10MB and 1 of them
}



rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_2 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      score = 65
      id = "0664d202-ab4c-57b6-91ee-ea21ac08909e"
   strings:
      
      $a1 = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      $s1 = "<HTA:APPLICATION "
   condition:
      filesize < 5MB
      and $a1 
      and 1 of ($s*)
}


rule SUSP_Microsoft_7z_SFX_Combo {
   meta:
      description = "Detects a suspicious file that has a Microsoft copyright and is a 7z SFX"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-16"
      hash1 = "cce63f209ee4efb4f0419fb4bbb32326392b5ef85cfba80b5b42b861637f1ff1"
      id = "9163a689-c3ee-59b1-bf58-aef5d3072be6"
   strings:
      $s1 = "7ZSfx%03x.cmd" fullword wide
      $s2 = "7z SFX: error" fullword ascii

      
      $c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
              00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9
              00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
              00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F
              00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20
              00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68
              00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72
              00 76 00 65 00 64 00 2E }
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of ($s*) and $c1
}




rule SUSP_Microsoft_RAR_SFX_Combo {
   meta:
      description = "Detects a suspicious file that has a Microsoft copyright and is a RAR SFX"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-16"
      id = "0fa81a9e-2f41-5783-9786-bb6d33b82bd9"
   strings:
      $s1 = "winrarsfxmappingfile.tmp" fullword wide
      $s2 = "WinRAR self-extracting archive" fullword wide
      $s3 = "WINRAR.SFX" fullword

      
      $c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
              00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9
              00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
              00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F
              00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20
              00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68
              00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72
              00 76 00 65 00 64 00 2E }
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of ($s*) and $c1
}


rule SUSP_Unsigned_OSPPSVC {
   meta:
      description = "Detects a suspicious unsigned office software protection platform service binary"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/2019/09/24/no-summer-vacations-zebrocy/"
      date = "2019-09-26"
      hash1 = "5294a730f1f0a176583b9ca2b988b3f5ec65dad8c6ebe556b5135566f2c16a56"
      id = "0e312237-0c82-59da-b62d-56065c6075f0"
   strings:
      
      $sc1 = { 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63
               00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00 00
               00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
               00 66 00 74 00 20 00 4F 00 66 00 66 00 69 00 63
               00 65 00 20 00 53 00 6F 00 66 00 74 00 77 00 61
               00 72 00 65 00 20 00 50 00 72 00 6F 00 74 00 65
               00 63 00 74 00 69 00 6F 00 6E 00 20 00 50 00 6C
               00 61 00 74 00 66 00 6F 00 72 00 6D 00 20 00 53
               00 65 00 72 00 76 00 69 00 63 00 65 }
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and $sc1 and pe.number_of_signatures < 1
}




rule SUSP_PE_Signed_by_Suspicious_Entitiy_Mar23 {
    meta:
        author = "Arnim Rupp (https://github.com/ruppde)"
        date_created = "2023-03-06"
        description = "Find driver signed by suspicious company (see references)"
        score = 60
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        reference = "https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware"
        reference = "https://news.sophos.com/en-us/2022/12/13/signed-driver-malware-moves-up-the-software-trust-chain/"
        reference = "https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/"
        hash = "2fb7a38e69a88e3da8fece4c6a1a81842c1be6ae9d6ac299afa4aef4eb55fd4b"
        hash = "9a24befcc0c0926abb49d43174fe25c2469cca06d6ab3b5000d7c9d434c42fe9"
        hash = "9ad716f0173489e74fefe086000dfbea9dc093b1c3460bed9cdb82f923073806"
        hash = "a007c8c6c1aecfff1065429fef691e7ae1c0ce20012a113f01ac57c61564a627"
        hash = "fbe82a21939d04735aa3bbf23fbabd45ac491a143396e8e62ee20509c1257918"
        hash = "d12c6ea0a86c58ea2d80d1dc9b793ba28a0db92c72bb5b6f4ee2b800fe42091b"
        hash = "4cf31d000f1542690cbc0ace41e4166651a71747978dc408e3cce32e82713917"
        hash = "e1adaea335b20d4d2e351f7bea496cd40cb379376900434866db342f851d9ddf"
        hash = "031408cf2f2c282bcc05066356fcc2bb862b7e3c504ab7ffb0220bea341404a5"
        hash = "2f13d4e1bd35f6c0ad0978af19006c17193cf3d42b71cba763cca68f7e9d7fca"
        hash = "cb40a5dc4f6a27b1dc50176770026b827f8baa05fa95a98a4e880652f6729d96"
        hash = "a7591b7384bd10eb934f0dac8dcbfdff8c352eba2309f4d75553567fa2376efa"
        hash = "d517ce5f132b3274f0b9783a5b0c37d1d648e6079874960af24ca764b011c042"
        hash = "aeec903013d5b66f0ae1c6fa50bb892759149c1cec86db8089a4e60482e02250"
        hash = "0d22828724cb7fbc6cef7f98665d020867d2eb801cff2c21f2e97e481040499b"
        hash = "4b2e874d51d332fd840dadd463a393f9f019de46e49de73be910b9b1365e4e4e"
        hash = "3839c0925acf836238ba9a0c5798b84b1c089a8353cc27ae7e6b75d273b539e3"
        hash = "c470f519fb0d4a2862035e0d9e105a0a6918adc51842b12ad14b5b5f34879963"
        hash = "cc6d174bc86f84f5a4c516e9c04947e2fecc0509a84748ea80576aeee5950aed"
        hash = "6fe8df70254f9b5f53452815f0163cb2ffb2d7f0f5aefbb9b149ad1be9284e31"
        hash = "4cde473fb68fa9b2709ea8a23349cd2fce8b8b3991b9fea12f95d12292b8aa7a"
        hash = "e2c40c8dd60bb395807c39c76bfdf5cd158ebefd2a47ad3306a96662c50057c0"
        hash = "9c12b09b529fa517eaeb49df22527d7563b5432d62776166048d97f83b2dce5c"
        hash = "5a4e17287f3dceb5bf1ed411e5fdd7e8692aebf2a19b334327733fc1c158b0ba"
        hash = "c42964aa7fa354b1a285bdbcbd9e84b6bdd8813ff9361955e0e455d032803cce"
        hash = "ffd6955bf40957a35901d82fd5b96d0cb191b651d3eca7afa779eebfed0d9f7e"
        hash = "f6874335eb0d611d47b2ec99a6b70f7b373a50d8d1f62d290b06174f42279f36"
        hash = "4e6d7fd70a143f19429fead2c14779aea9d9140e270bb9e91e47fa601643e40e"
        hash = "7b0e4aae37660b1099de69f4c14f5d976f260c64a4af8495ff1415512a6268ba"
        hash = "db45cbfb094f3e1ebf1cb3880087a24d4e771cc43ba48ad373e6283cbe7391da"
        hash = "813edc804f59a97ec9391ea0db4b779443bd8daf1e64c622b5e3c9a22ee9c2e0"
        hash = "8d66a4b7c2ae468390d32e5e70b3f9b7cb796b54b7c404cde038de9786be8d1d"
        hash = "85936141f0f32cf8f3173655e7200236d1fce6ef9c2616fd2b19ae7951c644c5"
        hash = "b5fc0cc9980fc594a18682d2b0d5b0d0f19ba7a35d35106693a78f4aaba346ac"
        hash = "7aae36c5ffa8baaab19724dae051673ddafd36107cb61c505926bfceaadcd516"
        hash = "5d0228a0d321e2ddac5502da04ca7a2b2744f3dc1382daa5f02faa9da5aface1"
        hash = "2af1ac8bc8ae8d7cad703d2695f2f6c6d79b82eebba01253a8ec527e11e83fcd"
        hash = "c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497"
        hash = "0e339c9c8a6702b32ee9f2915512cbeb3391ced74b16c7e0aed9b1a80c9e58c8"
        hash = "80bdeaa4f162c65722b700e4ffba31701d0d634f5533e59bf3885dc67ee92f3f"
        hash = "4570f64f2000bdaf53aec0fc2214c8bd54e0f5cb75987cdf1f8bda6ea5fc4c43"
        hash = "a9c906bde6c8a693d5d46c9922dafa2dfd2dec0fff554f3f6a953c2e36d3f7b7"
        hash = "520df3ddd7c9ecdeecac8e443d75ac258c26b45d37ecec22501afdda797f6a0a"
        hash = "4d3e0f27a7bcfd4b442b489c63641af22285ca41c6d56ac1db734196ab10b315"
        hash = "5000b3b1d593ba40cc10098644af1551259590ac67d3726fab2be87aad460877"
        hash = "7c27bd6104fc67dd16e655f3bf67c2abd8b5bf2a693ba714ac86904c5765b316"
        hash = "34b1234eab7ff10edde9e09ecf73c5e4bfe9ee047ccfdb43de1e1f6155afad0c"
        hash = "f6fe2cc9ea31f85273c26e84422137df21cfce4b9e972b0db94fe3a67b54f6ca"
        hash = "ec4d0828196926bd36325f4b021895d37cfaaa024f754b36618c78b2574f0122"
        hash = "2a89f263d85da8fb0c934d287b5b524744479741491c740aaa46ac9f694f6d1b"
        hash = "c8d0122974fc10a7d82c62f3e6573a94379c026dd741fd73497afdf36d3929be"
        hash = "0345f71876bc4c888deadba7284565a8da112901f343e54b8522279968abd1b2"
        hash = "6c0e10650be9e795dc6adfbe8aad8c1c3a8657e4c45cb82a7d5188ee24021ca0"
        hash = "90b8d9c4ff3e4e0a0342e0d91da3a25be2fead29f3b32888bb35f8575845259d"
        hash = "0310400c9e62c3fe08dc6506313e26f7c5c89035c81b0141ce57543910c1c42e"
        hash = "b0da0316443f878aad0b3d9764b631d5df60e119ab59324c37640da1b431893a"
        hash = "cc4bd06f27a5f266bc8825a08e5f45dcaa4352eb6d69214b5037d28cc8de6908"
        hash = "2d4b7c6931203923db9a07e1ac92124e799f3747ab20e95e191e99c7b98f3fbd"
        hash = "b5965de0d883fd0602037f3dc26fd4461e6328612f1a34798cff0066142e13c4"
        hash = "86ce17183ddf32379db53ecaedefe0811252165b05cd326025bb8eca2e6a25d7"
        hash = "6edca16d5aa751aa4c212e6477121d51e4d9b9432896d25b41938a27a554bbe7"
        hash = "cdd8966e0cf08a6578e34de7498a44413a6adabae04d81ef3129f26305966db2"
        hash = "df890974589ed2435f53b8c8f147a06752f1b37404afd4431362c1938fcb451e"
        hash = "3e05d8abaaa95af359e5b09efb30546d0aa693859ebc8a0970a2641556ea644c"
        hash = "1c8ddf4b9c99c8f1945abf1527c7fa93141430680ac156a405d9a927d32f3b5e"
        hash = "5d2ed5930ab1a650f9fb9293f49a9f35737139fdfa9f14e46a07e5d4d721ae3e"
        hash = "18834de3e4844a418970c2184cc78c2d7cb61d18e9f7c7c0e88e994b4212edc5"
        hash = "a6b6fc94d8e582059af0fe30c2c93c687fccd5a0073a6a26a2cd097ea96adc7c"
        hash = "28b40fa160c915f13f046d36725c055d6c827a4d28674ea33c75a9b410321290"
        hash = "efab0fbf77dc67a792efd1fe2b3f46bbdfdee30a9321acc189c53a6c5e90f05c"
        hash = "348781221d1a2886923de089d1b7b12c32cfdd38628b71203da925b5736561e9"
        hash = "a1a5f410e6eab2445d64bfcd742fe1a802a0a2d9af45c7ab398f84894dd5dc3d"
        hash = "9de05ce0d9e9de05ebdc2859a5156f044f98bb180723f427a779d36b1913e5d3"
        hash = "eeff7e85c50a7f11fc8a99f7048953719fb1d2a6451161a0796eac43119ece21"
        hash = "383cc025800a3b3d089f7697e78fe4d5695a8d1ee26dcad0b0956ad6800ccae4"
        hash = "41be6f393cea4d8d5869fff526c4d75ec66c855f7e9c176042c39b9682ea9c14"
        hash = "71552e65433c8bbf14e5bcbc35a708bc10d6fded740c5f4783edce84aea4aabf"
        hash = "3c1b3e8666b58a78c70f36ed557c7ecc52e84457e87e5884b42e5cd9e8c1a303"
        hash = "4288d7113031151a2636a164c0dc6fce78c86f322271afec9ef2d4b54494c334"
        hash = "f73a39332be393a9bc23ec27ff6d025bc90d7320dde97f37cc585ecf6c0436a2"
        hash = "018f5103635992aa9ddc1c46cafe2b7ba659fcfbc8f8ab29dcea28e155b033ee"
        hash = "fe650fc138dcfbbd4ab6aa5718bf3cd36f50898ae19d3aceaa12f7d4f39d0b43"
        hash = "fa21b39cd5a24ba35433e90cae486454b7400b50e7f7f5c190fdbec6704b4352"
        hash = "3dd36c798cc89bfad7cdbf58d7da90ba113fe043ca46bdbcab7ae7fb9dc2f42b"
        hash = "674f4444f0de5c81c766c376a65fbdf1f7116228a61c71ffb504995c9e160183"
        hash = "cd3d25b2842bb2d6a5580f72e819acd344ce7f3a2478fb6d53ff668ad6531228"
        hash = "1668f4eb8a85914db46ff308b9f8a5040a024acc93259dfc004ea2b80ab6bcf1"
        hash = "4f31cab6c011b79bf862bb6acea3086308b0576afe33affdb09039c97e723beb"
        hash = "6b0ff48b8113076d2875edb7bea7f120b7b9d9a990ae296a5b5a95660ae7edfc"
        hash = "956a00dd6382e83d3f7490378ae98e4fc8d9b8ec2cd549519f007091e3ccce1f"
        hash = "8c7f938cf55728d8d41a7fa6b9953c4f81cf05ed3d7b7435ec8999e130257f7f"
        hash = "427ee4d4d18fc0c1196326215e94947f7d8c03794de36d0127231690bf5bf3c0"
        hash = "b6f3ece5bf7b9f6ecf99104d3c76b9007106fad98d20500956dd1e42d4ec5e8d"
        hash = "47a0ad6150c5a1de4c788827662a9cafbd2816a7d32be2028721e49a464acbed"
        hash = "8743ac81384fd10c0459f3574489d626e13c95dd73274dcf1d872bcd3630b9e8"
        hash = "a1755415a12f85bea3f65807860f902cf41e56b0ab2c155ac742af3166ef1dfd"
        hash = "3f5a91500bfade2d9708e1fbe76ae81dacdb7b0f65f335fee598546ccfc267e3"
        hash = "5be43b773dbde6542d6a0d53cd6616ea95a49dd38659edc6ba0d580a0d9777ab"
        hash = "90e080a63916c768b0b65787fe5695fd903d44e1b0b688d06c14988ba30b5ea7"
        hash = "d1184ee3f26919b8f5a4b1a6d089f14e79e0c89260590156111f72a979c8e446"
        hash = "c13ddd2bafcfdfc00fb5cb87d8eb533ae094b0dd5784df77c98bddeac9d72725"
        hash = "9bb3035610bd09ba769c0335f23f98dd85c2f32351cdd907d4761b41ab5d099c"
        hash = "1703025c4aed71d0ca29a3cd0e15047c24cc9adbb5239765f63e205ef7d65753"
        hash = "948d47b9386b2b3247b7e9796ab2f2078889264559ad04ccd9362b03dbbf8534"
        hash = "edd527d978b591d146d24d075bb4c24177e0eca6a27b5d92f35be68635cc3767"
        hash = "c642dc125fbd83e004d2c527933996589e0fcad06313a5a56679a265b8966529"
        hash = "cfa3a48bf0c683834d1d198a653ebced8a8faae9d0cbb38f3e859b45da81d554"
        hash = "bb8f5d123aebdde5542724db5be8430d62a80f86f590a272aac9087d097f395c"
        hash = "e41e10673db41b13ba17c828beb94fc39e8d3aa43b01f9fe437a2f6e0b8ae443"
        hash = "a132e31db9f9761d6bd2c375415e615bb0a548fb02c4fd6373e9f7d1568de1dc"
        hash = "5084c6e20b88adeea6a28508cf172048d7cf20adeaa52abdd361fc2207411055"
        hash = "525320e3631a23a3286481710533ba15cd6268ee10be98962a55e2afead1ffbf"
        hash = "16c74f288f4f929e74cd8e16443303aec3a64cfef64aabc14553f4c1e58c9ede"
        hash = "4b482ebf88bcb55e7b0769690ccca4d08856c879af82ad7165436b82a315d742"
        hash = "79c9acadd99ab1251dbba3bff7d0b67de4252f913f485465d63f4f0c4d9a6419"
        hash = "9bcc3f36c32e3efbf8bdcba7670658042db65dd617dad0709d92c554ba841b57"
        hash = "5654ed1205de6860e66383a27231e4ac2bb7639b07504121d313a8503ece3305"
        hash = "5d1e3c495d08982459b4bd4fd2ab073ed2078fce9347627718a7c25adee152e9"
        hash = "458702ae1b2ef8a113344be76af185ee137b7aac3646ece626d2eeeadcc9e003"
        hash = "2c703e562a6266175379fa48f06f58aab109dbe56e0cde24b4b0db5f22f810a3"
        hash = "49faf70c0978c21a68bc8395cf326f50c491e379f55b5df7d17f0af953861ece"
        hash = "a2b16bbef0a7cb545597828466cd13225efaba6e7006bfbf59040bbff54c463c"
        hash = "b08449d42f140c7e4d070c5f81ce7509f48282a5bb0e06948b7ed65053696a37"
        hash = "c1633ad8c9e6c2b4cc23578655fc6cf5cd0122cfd24395d1551af1d092f89db2"
        hash = "01f42f949a37d9d479b8021f27dcf0d0e6f0b0b6cd2e0883c6b4b494f0a1d32a"
        hash = "4943d53a38ac123ed7c04ad44742a67ea06bb54ea02fa241d9c4ebadab4cb99a"
        hash = "597ce12c9fbecc71299ba6fc3e4df36cc49222878d0e080c4c35bbfdffd30083"
        hash = "0265fbd9cfc27c26c42374fce7cf0ef11f38e086308d51648b45f040d767c51d"
        hash = "0dc92a1a6fd27144b3e35a9900038653892d25c2db8ede8b9e0aee04839f165a"
        hash = "682582c324cb1eafacf80090f6108c1580fee12dbfdfe8b51771d429fdcce718"
        hash = "e9e6f6e22b5924f80164fbad45be28299e9ec0bd2f404551b6ca772509a7135a"
        hash = "a8db750f82906fb9cf9fb371ec65be76275d9b81b95e351fcb3db4ef345884ab"
        hash = "e900b4016177259d07011139a55c0571c1e824fb7e9dddc11df493b3c8209173"
        hash = "f8a7a26d51a5e938325deee86cbf5aa8263d3a50818c15d5a395b98658630c18"
        hash = "861b87fc6c4758cfe1e26c7a038cffb64054ad633b7ea81319c9a98b7b49df0d"
        hash = "848fdb491307ed7b002dbdf99796df2b286d53b2e0066d78f3554f2f38a2c438"
        hash = "4b0c05bc33c9e7d0ed2d97dbefb6292469b9d74d650d5cfb2691345a11c0f54a"
        hash = "948d47b9386b2b3247b7e9796ab2f2078889264559ad04ccd9362b03dbbf8534"
        hash = "edd527d978b591d146d24d075bb4c24177e0eca6a27b5d92f35be68635cc3767"
        hash = "c642dc125fbd83e004d2c527933996589e0fcad06313a5a56679a265b8966529"
        hash = "cfa3a48bf0c683834d1d198a653ebced8a8faae9d0cbb38f3e859b45da81d554"
        hash = "bb8f5d123aebdde5542724db5be8430d62a80f86f590a272aac9087d097f395c"
        hash = "e41e10673db41b13ba17c828beb94fc39e8d3aa43b01f9fe437a2f6e0b8ae443"
        hash = "a132e31db9f9761d6bd2c375415e615bb0a548fb02c4fd6373e9f7d1568de1dc"
        hash = "5084c6e20b88adeea6a28508cf172048d7cf20adeaa52abdd361fc2207411055"
        hash = "525320e3631a23a3286481710533ba15cd6268ee10be98962a55e2afead1ffbf"
        hash = "16c74f288f4f929e74cd8e16443303aec3a64cfef64aabc14553f4c1e58c9ede"
        hash = "4b482ebf88bcb55e7b0769690ccca4d08856c879af82ad7165436b82a315d742"
        hash = "79c9acadd99ab1251dbba3bff7d0b67de4252f913f485465d63f4f0c4d9a6419"
        hash = "9bcc3f36c32e3efbf8bdcba7670658042db65dd617dad0709d92c554ba841b57"

        id = "13151f9b-22cb-551f-81b4-a60a301f0bfc"
    strings:
        // works well enough with string search so no need to use the pe module
        $cert1 = "91210242MA0YGH36" wide ascii ///serialNumber=91210242MA0YGH36XJ/jurisdictionC=CN/businessCategory=Private Organization/C=CN/ST=\xE8\xBE\xBD\xE5\xAE\x81\xE7\x9C\x81
        $cert2 = "Copyright (C) 2013-2021 QuickZip. All rights reserved." wide ascii 
        $cert3 = "Qi Lijun" wide ascii // short but no fp
        $cert4 = {51 00 69 00 20 00 4c 00 69 00 6a 00 75 00 6e} // string above in hex(utf16-be minus first 00) because of https://github.com/VirusTotal/yara/issues/1891
        $cert5 = "Luck Bigger Technology Co., Ltd" wide ascii
        $cert6 = {4c 00 75 00 63 00 6b 00 20 00 42 00 69 00 67 00 67 00 65 00 72 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 20 00 43 00 6f 00 2e 00 2c 00 20 00 4c 00 74 00 64 } // above in hex
        $cert7 = "XinSing Network Service Co., Ltd" wide ascii
        $cert8 = "Hangzhou Shunwang Technology Co.,Ltd" wide ascii
        $cert9 = "Zhuhai liancheng Technology Co., Ltd." wide ascii
        $cert10 = { e5 a4 a7 e8 bf 9e e7 ba b5 e6 a2 a6 e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert11 = { e5 8c 97 e4 ba ac e5 bc 98 e9 81 93 e9 95 bf e5 85 b4 e5 9b bd e9 99 85 e8 b4 b8 e6 98 93 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert12 = { e7 a6 8f e5 bb ba e5 a5 a5 e5 88 9b e4 ba 92 e5 a8 b1 e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert13 = { e5 8e a6 e9 97 a8 e6 81 92 e4 bf a1 e5 8d 93 e8 b6 8a e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 0a }
        $cert14 = { e5 a4 a7 e8 bf 9e e7 ba b5 e6 a2 a6 e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        filesize < 20MB and
        any of ( $cert* )

}


rule SUSP_BAT2EXE_BDargo_Converted_BAT {
   meta:
      description = "Detects binaries created with BDARGO Advanced BAT to EXE converter"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.majorgeeks.com/files/details/advanced_bat_to_exe_converter.html"
      date = "2018-07-28"
      modified = "2022-06-23"
      score = 45
      hash1 = "d428d79f58425d831c2ee0a73f04749715e8c4dd30ccd81d92fe17485e6dfcda"
      hash1 = "a547a02eb4fcb8f446da9b50838503de0d46f9bb2fd197c9ff63021243ea6d88"
      id = "c9da4184-1530-5525-bdba-2dcc8a221bb1"
   strings:
      $s1 = "Error #bdembed1 -- Quiting" fullword ascii
      $s2 = "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
      $s3 = "\\a.txt" ascii
      $s4 = "command.com" fullword ascii 
      $s6 = "DFDHERGDCV" fullword ascii
      $s7 = "DFDHERGGZV" fullword ascii
      $s8 = "%s%s%s%s%s%s%s%s" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and 5 of them
}


rule SUSP_NET_Msil_Suspicious_Use_StrReverse {
   meta:
      
      description = "Detects mixed use of Microsoft.CSharp and VisualBasic to use StrReverse"
      author = "dr4k0nia, modified by Florian Roth"
      reference = "https://github.com/dr4k0nia/yara-rules"
      version = "1.1"
      date = "01/31/2023"
      modified = "02/22/2023"
      score = 70
      hash = "02ce0980427dea835fc9d9eed025dd26672bf2c15f0b10486ff8107ce3950701"
      id = "830dec40-4412-59c1-8b4d-a237f14acd30"
   strings:
      $a1 = ", PublicKeyToken="
      $a2 = ".NETFramework,Version="

      $csharp = "Microsoft.CSharp"
      $vbnet = "Microsoft.VisualBasic"
      $strreverse = "StrReverse"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 50MB
      and all of ($a*)
      and $csharp
      and $vbnet
      and $strreverse
}


rule SUSP_Reversed_Base64_Encoded_EXE : FILE {
   meta:
      description = "Detects an base64 encoded executable with reversed characters"
      author = "Florian Roth (Nextron Systems)"
      date = "2020-04-06"
      reference = "Internal Research"
      score = 80
      hash1 = "7e6d9a5d3b26fd1af7d58be68f524c4c55285b78304a65ec43073b139c9407a8"
      id = "3b52e59e-7c0a-560f-8123-1099c52e7e3d"
   strings:
      $s1 = "AEAAAAEQATpVT"
      $s2 = "AAAAAAAAAAoVT"
      $s3 = "AEAAAAEAAAqVT"
      $s4 = "AEAAAAIAAQpVT"
      $s5 = "AEAAAAMAAQqVT"

      $sh1 = "SZk9WbgM1TEBibpBib1JHIlJGI09mbuF2Yg0WYyd2byBHIzlGaU" ascii
      $sh2 = "LlR2btByUPREIulGIuVncgUmYgQ3bu5WYjBSbhJ3ZvJHcgMXaoR" ascii
      $sh3 = "uUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGV" ascii
   condition:
      filesize < 10000KB and 1 of them
}



rule SUSP_Office_Dropper_Strings {
   meta:
      description = "Detects Office droppers that include a notice to enable active content"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-13"
      id = "6560fdf7-46e8-5c16-8263-a36f1dec7868"
   strings:
      $a1 = "_VBA_PROJECT" wide

      $s1 = "click enable editing" fullword ascii
      $s2 = "click enable content" fullword ascii
      $s3 = "\"Enable Editing\"" fullword ascii
      $s4 = "\"Enable Content\"" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and $a1 and 1 of ($s*)
}



rule SUSP_SFX_RunProgram_WScript {
   meta:
      description = "Detects suspicious SFX that runs wscript.exe"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-27"
      score = 75
      hash1 = "e3bb02c5985fc64759b9c2d3c5474d46237ce472b4a0101c6313dafa939de5a9"
      hash2 = "0ecf88d4b32895b4819dec3acb62eaaa7035aa6292499d903f76af60fcec0d6a"
      hash3 = "a7a48f5220bd1ebe04de258d71fdd001711c165d162bd45e8cfbe8964eddf01c"
      hash4 = "b6fa4889d8a87d45706d92714d716025bf223c01929755321faac1ab0db94a88"
      hash5 = "7117b39890659c7dd11e15092c5e5ea9495bec0ff2b6e25254f6e343ed6ca33d"
      hash6 = "ec2afb63555986fa55b7f98ae57c57e1138acb404a0dd2fe4f3d315730b9898e"
      id = "e12cea50-a939-5f69-963c-d6d1cb133e92"
   strings:
      $x1 = "RunProgram=\"wscript.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and 1 of them
}


rule MAL_RTF_Embedded_OLE_PE {
   meta:
      description = "Detects a suspicious string often used in PE files in a hex encoded object stream"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.nextron-systems.com/2018/01/22/creating-yara-rules-detect-embedded-exe-files-ole-objects/"
      date = "2018-01-22"
      modified = "2023-11-25"
      score = 65
      id = "20044f08-9574-5baf-b91e-47613e490d62"
   strings:
      
      
      $a1 = "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f6465" ascii
      
      $a2 = "4b45524e454c33322e646c6c" ascii
      
      $a3 = "433a5c66616b65706174685c" ascii
      
      $m3 = "4d5a40000100000006000000ffff"
      $m2 = "4d5a50000200000004000f00ffff"
      $m1 = "4d5a90000300000004000000ffff"
   condition:
      uint32be(0) == 0x7B5C7274 
      and 1 of them
}


rule SUSP_XORed_URL_In_EXE {
   meta:
      description = "Detects an XORed URL in an executable"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
      date = "2020-03-09"
      modified = "2022-09-16"
      score = 50
      id = "f83991c8-f2d9-5583-845a-d105034783ab"
   strings:
      $s1 = "http://" xor
      $s2 = "https://" xor
      $f1 = "http://" ascii
      $f2 = "https://" ascii

      $fp01 = "3Com Corporation" ascii  
      $fp02 = "bootloader.jar" ascii  
      $fp03 = "AVAST Software" ascii wide
      $fp04 = "smartsvn" wide ascii fullword
      $fp05 = "Avira Operations GmbH" wide fullword
      $fp06 = "Perl Dev Kit" wide fullword
      $fp07 = "Digiread" wide fullword
      $fp08 = "Avid Editor" wide fullword
      $fp09 = "Digisign" wide fullword
      $fp10 = "Microsoft Corporation" wide fullword
      $fp11 = "Microsoft Code Signing" ascii wide
      $fp12 = "XtraProxy" wide fullword
      $fp13 = "A Sophos Company" wide
      $fp14 = "http://crl3.digicert.com/" ascii
      $fp15 = "http://crl.sectigo.com/SectigoRSACodeSigningCA.crl" ascii
      $fp16 = "HitmanPro.Alert" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and (
         ( $s1 and #s1 > #f1 ) or
         ( $s2 and #s2 > #f2 )
      )
      and not 1 of ($fp*)
      and not pe.number_of_signatures > 0
}



rule SUSP_PDB_Strings_Keylogger_Backdoor : HIGHVOL {
   meta:
      description = "Detects PDB strings used in backdoors or keyloggers"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-03-23"
      score = 65
      id = "190daadb-0de6-5665-a241-95c374dbda47"
   strings:
      $ = "\\Release\\PrivilegeEscalation"
      $ = "\\Release\\KeyLogger"
      $ = "\\Debug\\PrivilegeEscalation"
      $ = "\\Debug\\KeyLogger"
      $ = "Backdoor\\KeyLogger_"
      $ = "\\ShellCode\\Debug\\"
      $ = "\\ShellCode\\Release\\"
      $ = "\\New Backdoor"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB
      and 1 of them
}



rule SUSP_Microsoft_Copyright_String_Anomaly_2 {
   meta:
      description = "Detects Floxif Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-11"
      score = 60
      hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
      id = "3257aff0-b923-5e56-b67c-fa676341a102"
   strings:
      $s1 = "Microsoft(C) Windows(C) Operating System" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}



rule SUSP_Win32dll_String {
   meta:
      description = "Detects suspicious string in executables"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@Sebdraven/apt-sidewinder-changes-theirs-ttps-to-install-their-backdoor-f92604a2739"
      date = "2018-10-24"
      hash1 = "7bd7cec82ee98feed5872325c2f8fd9f0ea3a2f6cd0cd32bcbe27dbbfd0d7da1"
      id = "b1c78386-c23d-5138-942a-3da90e5802cc"
   strings:
      $s1 = "win32dll.dll" fullword ascii
   condition:
      filesize < 60KB and all of them
}



rule SUSP_Modified_SystemExeFileName_in_File {
   meta:
      description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11"
      score = 65
      hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
      hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"
      id = "97d91e1b-49b8-504e-9e9c-6cfb7c2afe41"
   strings:
      $s1 = "svchosts.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}



rule SUSP_DropperBackdoor_Keywords {
   meta:
      description = "Detects suspicious keywords that indicate a backdoor"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
      date = "2019-04-24"
      hash1 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
      id = "2942ba6d-a533-5954-bfcf-417262e2fac2"
   strings:
      $x4 = "DropperBackdoor" fullword wide ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}



rule SUSP_SFX_cmd {
   meta:
      description = "Detects suspicious SFX as used by Gamaredon group"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-27"
      hash1 = "965129e5d0c439df97624347534bc24168935e7a71b9ff950c86faae3baec403"
      id = "87e75fe6-c2d7-5cb4-9432-7c37dbfe94b8"
   strings:
      $s1 = /RunProgram=\"hidcon:[a-zA-Z0-9]{1,16}.cmd/ fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}



rule SUSP_XMRIG_Reference {
   meta:
      description = "Detects an executable with a suspicious XMRIG crypto miner reference"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/itaitevet/status/1141677424045953024"
      date = "2019-06-20"
      score = 70
      id = "0a7324ce-90dc-5e6a-b22a-c29eccf324e9"
   strings:
      $x1 = "\\xmrig\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}



rule SUSP_PDB_Path_Keywords {
   meta:
      description = "Detects suspicious PDB paths"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1179832666285326337?s=20"
      date = "2019-10-04"
      id = "cbd9b331-58bb-5b29-88a2-5c19f12893a9"
   strings:
      $ = "Debug\\Shellcode" ascii
      $ = "Release\\Shellcode" ascii
      $ = "Debug\\ShellCode" ascii
      $ = "Release\\ShellCode" ascii
      $ = "Debug\\shellcode" ascii
      $ = "Release\\shellcode" ascii
      $ = "shellcode.pdb" nocase ascii
      $ = "\\ShellcodeLauncher" ascii
      $ = "\\ShellCodeLauncher" ascii
      $ = "Fucker.pdb" ascii
      $ = "\\AVFucker\\" ascii
      $ = "ratTest.pdb" ascii
      $ = "Debug\\CVE_" ascii
      $ = "Release\\CVE_" ascii
      $ = "Debug\\cve_" ascii
      $ = "Release\\cve_" ascii
   condition:
      uint16(0) == 0x5a4d and 1 of them
}



rule SUSP_PE_Discord_Attachment_Oct21_1 {
   meta:
      description = "Detects suspicious executable with reference to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-10-12"
      score = 70
      id = "7c217350-4a35-505d-950d-1bc989c14bc2"
   strings:
      $x1 = "https://cdn.discordapp.com/attachments/" ascii wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 5000KB 
      and 1 of them
}



rule SUSP_THOR_Unsigned_Oct23_1 {
   meta:
      description = "Detects unsigned version of THOR scanner, which could be a backdoored / modified version of the scanner"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2023-10-28"
      score = 75
      id = "2ca6a192-675e-5f02-a7b1-40369eeb9904"
   strings:
      $s1 = "THOR APT Scanner" wide fullword
      $s2 = "Nextron Systems GmbH" wide fullword

      
      $sc1 = { 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 68 00 6F 00 72 } 
   condition:
      uint16(0) == 0x5a4d
      and all of them
      and pe.number_of_signatures == 0
}


rule SUSP_VHD_Suspicious_Small_Size {
   meta:
      description = "Detects suspicious VHD files"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/MeltX0R/status/1208095892877774850"
      date = "2019-12-21"
      modified = "2023-01-27"
      score = 50
      hash1 = "3382a75bd959d2194c4b1a8885df93e8770f4ebaeaff441a5180ceadf1656cd9"
      id = "f4a72e7b-ddd3-5038-9440-1e81dc27755d"
   strings:
      
      $hc1 = { 63 6F 6E 65 63 74 69 78 }
      $hc2a = { 49 6E 76 61 6C 69 64 20 70 61 72 74 69 74 69 6F
               6E 20 74 61 62 6C 65 00 45 72 72 6F 72 20 6C 6F
               61 64 69 6E 67 20 6F 70 65 72 61 74 69 6E 67 20
               73 79 73 74 65 6D 00 4D 69 73 73 69 6E 67 20 6F
               70 65 72 61 74 69 6E 67 20 73 79 73 74 65 6D }
      $hc2b = "connectix"
   condition:
      not uint16(0) == 0x5a4d
      and filesize > 1KB and filesize <= 4000KB 
      and (
         $hc1 at 0 
         or all of ($hc2*)
      )
}


rule SUSP_Two_Byte_XOR_PE_And_MZ {
   meta:
      author = "Wesley Shields <wxs@atarininja.org>"
      description = "Look for 2 byte xor of a PE starting at offset 0"
      reference = "https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83"
      score = 60
      date = "2021-10-11"
      id = "ddb87194-bafb-597d-9184-fe4fe3c5ce8d"
   condition:
      uint16(0) != 0x5a4d and
      uint32((uint16(0x3c) ^ (uint16(0) ^ 0x5a4d)) | ((uint16(0x3e) ^ (uint16(0) ^ 0x5a4d)) << 16)) ^ ((uint16(0) ^ 0x5a4d) | ((uint16(0) ^ 0x5a4d) << 16)) == 0x00004550
}



rule SUSP_Four_Byte_XOR_PE_And_MZ {
   meta:
      author = "Wesley Shields <wxs@atarininja.org>"
      description = "Look for 4 byte xor of a PE starting at offset 0"
      reference = "https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83"
      score = 60
      date = "2021-10-11"
      id = "d7b4b462-dfde-5d1f-8039-63522436c15f"
   condition:
      uint16(0) != 0x5a4d and
      uint32(0x28) != 0x00000000 and
      uint32(0x28) == uint32(0x2c) and
      uint32(uint32(0x3c) ^ uint32(0x28)) ^ uint32(0x28) == 0x00004550
}


rule SUSP_Size_of_ASUS_TuningTool {
   meta:
      description = "Detects an ASUS tuning tool with a suspicious size"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      modified = "2022-12-21"
      score = 60
      noarchivescan = 1
      hash1 = "d4e97a18be820a1a3af639c9bca21c5f85a3f49a37275b37fd012faeffcb7c4a"
      id = "d22a1bf9-55d6-5cb4-9537-ad13b23af4d1"
   strings:
      $s1 = "\\Release\\ASGT.pdb" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and filesize > 70KB and all of them
}



rule SUSP_Putty_Unnormal_Size {
   meta:
      description = "Detects a putty version with a size different than the one provided by Simon Tatham (could be caused by an additional signature or malware)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-01-07"
      modified = "2022-06-30"
      score = 50
      hash1 = "e5e89bdff733d6db1cffe8b3527e823c32a78076f8eadc2f9fd486b74a0e9d88"
      hash2 = "ce4c1b718b54973291aefdd63d1cca4e4d8d4f5353a2be7f139a290206d0c170"
      hash3 = "adb72ea4eab7b2efc2da6e72256b5a3bb388e9cdd4da4d3ff42a9fec080aa96f"
      hash4 = "1c0bd6660fa43fa90bd88b56cdd4a4c2ffb4ef9d04e8893109407aa7039277db"
      id = "576b118c-d4be-5ce2-994a-ce3f943dda88"
   strings:
      $s1 = "SSH, Telnet and Rlogin client" fullword wide

      $v1 = "Release 0.6" wide
      $v2 = "Release 0.70" wide

      $fp1 = "KiTTY fork" fullword wide
   condition:
      uint16(0) == 0x5a4d
      and $s1 and 1 of ($v*)
      and not 1 of ($fp*)
      // has offset
      and filesize != 524288
      and filesize != 495616
      and filesize != 483328
      and filesize != 524288
      and filesize != 712176
      and filesize != 828400
      and filesize != 569328
      and filesize != 454656
      and filesize != 531368
      and filesize != 524288
      and filesize != 483328
      and filesize != 713592
      and filesize != 829304
      and filesize != 571256
      and filesize != 774200
      and filesize != 854072
      and filesize != 665144
      and filesize != 774200
      and filesize != 854072
      and filesize != 665144
      and filesize != 640000  
      and filesize != 650720  
      and filesize != 662808  
      and filesize != 651256  
      and filesize != 664432  
}



rule MAL_Chrysalis_DllLoader_Feb26 {
   meta:
      description = "Detects DLL used to load Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      date = "2026-02-02"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      hash = "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad"
      score = 80
      id = "a2bf8cde-36a5-565d-9257-f1a4b2d67adc"
   strings:
      $op1 = { 33 D2 8B C1 F7 F6 0F B6 C1 03 55 ?? 6B C0 ?? 32 02 88 04 0F 41 83 F9 ?? 72 }
      $op2 = { 0F B6 04 31 41 33 C2 69 D0 ?? ?? ?? ?? 3B CB 72 }
   condition:
      uint16(0) == 0x5a4d and all of them
}



rule MAL_CobaltStrike_Beacon_Loader_Feb26 {
   meta:
      description = "Detects Cobalt Strike beacon loader"
      author = "X__Junior"
      date = "2026-02-02"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      hash = "0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd"
      hash = "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3"
      score = 80
      id = "9d6888d0-64c6-5e52-a01a-8bcc51dd16b1"
   strings:
      $opa1 = { 45 33 C9 41 B8 ?? ?? ?? ?? 48 8D 94 24 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 66 89 44 24 ?? 41 B8 ?? ?? ?? ?? 48 8D 94 24 ?? ?? ?? ?? 0F B7 4C 24 ?? FF 15 ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? FF 15 }
      $opa2 = { 4C 8D 4C 24 ?? 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8D 0D ?? ?? ?? ?? 45 33 C0 33 D2 48 8B C8 FF 15 }

      $opb1 = { 48 8D 89 ?? ?? ?? ?? 0F 10 00 0F 10 48 ?? 48 8D 80 ?? ?? ?? ?? 0F 11 41 ?? 0F 10 40 ?? 0F 11 49 ?? 0F 10 48 ?? 0F 11 41 ?? 0F 10 40 ?? 0F 11 49 ?? 0F 10 48 ?? 0F 11 41 ?? 0F 10 40 ?? 0F 11 49 ?? 0F 10 48 ?? 0F 11 41 ?? 0F 11 49 ?? 48 83 EA }
      $opb2 = { 45 33 C9 48 89 84 24 ?? ?? ?? ?? 41 B8 18 00 00 00 C7 84 24 ?? ?? ?? ?? 03 00 00 00 48 8D 94 24 ?? ?? ?? ?? 48 89 BC 24 ?? ?? ?? ?? B9 B9 00 00 00 FF 15 }
   condition:
      uint16(0) == 0x5a4d and
      all of ($opa*)
      or all of ($opb*)
}



rule MAL_POC_Microsoft_Warbird_Loader_Feb26 {
   meta:
      description = "Detects a POC to turn Microsoft Warbird into a shellcode loader"
      author = "X__Junior"
      date = "2026-02-03"
      reference = "https://cirosec.de/en/news/abusing-microsoft-warbird-for-shellcode-execution/"
      hash = "29d0467ee452752286318f350ceb28a2b04ee4c6de550ba0edc34ae0fa7cbb03"
      score = 75
      id = "a07f6d10-c463-56a6-a667-82b1c00760af"
   strings:
      $op = { fe af fe ca ef be ad de }
   condition:
      uint16(0) == 0x5a4d and $op
}


rule MAL_AveMaria_RAT_Jul19 {
   meta:
      description = "Detects AveMaria RAT"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/abuse_ch/status/1145697917161934856"
      date = "2019-07-01"
      hash1 = "5a927db1566468f23803746ba0ccc9235c79ca8672b1444822631ddbf2651a59"
      id = "960048cf-7a56-50cf-8498-549f900770d8"
   strings:
      $a1 = "operator co_await" fullword ascii
      $s1 = "uohlyatqn" fullword ascii
      $s2 = "index = [%d][%d][%d][%d]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}


rule MAL_WIPER_BiBi_Oct23 {
   meta:
      description = "Detects BiBi wiper samples for Windows and Linux"
      author = "Florian Roth"
      reference = "https://x.com/ESETresearch/status/1719437301900595444?s=20"
      date = "2023-11-01"
      hash1 = "23bae09b5699c2d5c4cb1b8aa908a3af898b00f88f06e021edcb16d7d558efad"
      hash2 = "40417e937cd244b2f928150cae6fa0eff5551fdb401ea072f6ecdda67a747e17"
      id = "e1ea8016-e074-5208-8c98-54922bbcc407"
   strings:
      $s1 = "send attempt while closed" ascii fullword
      $s2 = "[+] CPU cores: %d, Threads: %d" ascii fullword
      $s3 = "[+] Stats: %d | %d" ascii fullword

      $opw1 = { 33 c0 88 45 48 b8 01 00 00 00 86 45 48 45 8b f5 48 8d 3d de f5 ff ff 0f 57 c9 f3 0f 7f 4d b8 }
      $opw2 = { 2d ce b5 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 26 b4 00 00 44 8b 05 5f b6 00 00 e8 ca 0d 00 00 }

      $opl1 = { 4c 8d 44 24 08 48 89 f7 48 ff c2 48 83 c6 04 e8 c7 fb ff ff 41 89 c1 0f b6 42 ff 41 0f af c1 }
      $opl2 = { e8 6f fb ff ff 49 8d 78 f8 89 c0 48 01 c2 48 89 15 09 fb 24 00 e8 5a fb ff ff 49 8d 78 fc 6b f0 06 } 
   condition:
      ( uint16(0) == 0x5a4d or uint16(0) == 0x457f )
      and filesize < 4000KB
      and 2 of them
}


rule MAL_CRIME_suspicious_hex_string_Jun21_1 : CRIME PE {
    meta:
        author = "Nils Kuhnert"
        date = "2021-06-04"
        description = "Triggers on parts of a big hex string available in lots of crime'ish PE files."
        hash1 = "37d60eb2daea90a9ba275e16115848c95e6ad87d20e4a94ab21bd5c5875a0a34"
        hash2 = "3380c8c56d1216fe112cbc8f1d329b59e2cd2944575fe403df5e5108ca21fc69"
        hash3 = "cd283d89b1b5e9d2875987025009b5cf6b137e3441d06712f49e22e963e39888"
        hash4 = "404efa6fb5a24cd8f1e88e71a1d89da0aca395f82d8251e7fe7df625cd8e80aa"
        hash5 = "479bf3fb8cff50a5de3d3742ab4b485b563b8faf171583b1015f80522ff4853e"
        id = "2ad208fa-c7a5-5df9-96fe-4a84dc770f0f"
    strings:
        $a1 = "07032114130C0812141104170C0412147F6A6A0C041F321104130C0412141104030C0412141104130C0412141104130C0412141104130C0412141104130C0412141104130C0412141104130C0412141122130C0412146423272A711221112B1C042734170408622513143D20262B0F323038692B312003271C170B3A2F286623340610241F001729210579223202642200087C071C17742417020620141462060F12141104130C0412141214001C0412011100160C0C002D2412130C0412141104130C04121A11041324001F140122130C0134171" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and all of them
}



rule MAL_CRIME_RAT_WIN_PE_GodRat_Aug25: GodRAT {
   meta:
      description = "Detects GodRAT malware targeting Windows systems"
      author = "Arda Buyukkaya"
      date = "2025-08-23"
      family = "GodRAT"
      reference = "https://securelist.com/godrat/117119/"
      tags = "RAT, Windows, GodRAT, Gh0st RAT, GETGOD"
      victims = "Financial services"
      sha256 = "154e800ed1719dbdcb188c00d5822444717c2a89017f2d12b8511eeeda0c2f41"
      id = "e6ec0af5-71d3-520a-a671-8634ac2f926f"
   strings:
      // WinRT version string
      $winrt_txt = "C++/WinRT version" ascii wide nocase

      // API function names blob
      $api_blob = {
         4E 74 43 72 65 61 74 65 53 65 63 74 69 6F 6E 00                          // NtCreateSection
         4E 74 4D 61 70 56 69 65 77 4F 66 53 65 63 74 69 6F 6E 00 00              // NtMapViewOfSection
         4E 74 55 6E 6D 61 70 56 69 65 77 4F 66 53 65 63 74 69 6F 6E 00 00 00 00  // NtUnmapViewOfSection
      }

      // Generic XOR decryption routine pattern using SSE instructions
      // Common characteristics across variants:
      // - Uses SSE instructions (MOVUPS/MOVQ) for efficient XOR operations
      // - Processes ~1900 bytes (0x770/0x76C) of encrypted data
      // - Unrolled loop processing multiple bytes per iteration

      // Load operations - reading XOR key/data into XMM registers
      $ld_movups = { 0F 10 05 ?? ?? ?? ?? }  // movups xmm0, xmmword ptr [address]
      $ld_movq = { F3 0F 7E 05 ?? ?? ?? ?? }  // movq xmm0, qword ptr [address]

      // Store operations - writing XORed data back to memory
      $st_movups = { 0F 11 85 ?? ?? ?? ?? }  // movups xmmword ptr [ebp+offset], xmm0
      $st_movq = { 66 0F D6 85 ?? ?? ?? ?? }  // movq qword ptr [ebp+offset], xmm0

      // String length calculation loop (strlen implementation)
      $scan_loop = { 8A 01 41 84 C0 75 F9 }  // mov al, [ecx]; inc ecx; test al, al; jnz loop

      // Buffer size checks for ~1900 byte decryption
      $cmp_len_770 = { 81 FF 70 07 00 00 0F 82 ?? ?? ?? ?? }  // cmp edi, 0x770 (1904); jb offset
      $cmp_len_76C = { 81 FF 6C 07 00 00 0F 82 ?? ?? ?? ?? }  // cmp edi, 0x76C (1900); jb offset
   condition:
      pe.is_pe and
      filesize <= 10MB and
      (
         // Condition 1: WinRT string with specific PE imphash
         (
            $winrt_txt and
            (
               pe.imphash() == "0f4b0270c84616ce594b6a84c47a7717"
            )
         )
         or
         // Condition 2: Generic XOR decryption pattern (SSE-optimized, ~1900 bytes)
         (
            // Must have SSE load instruction (reading data/key)
            ($ld_movups or $ld_movq) and
            // Must have multiple SSE store instructions (writing XORed data)
            (
               (#st_movups >= 2) or
               (#st_movq >= 2) or
               (#st_movups >= 1 and #st_movq >= 1)
            ) and
            // Must have strlen loop (for key length calculation)
            $scan_loop and
            // Must have NT API names blob (common in this malware family)
            $api_blob and
            // Must check for ~1900 byte buffer size (0x770 or 0x76C)
            ($cmp_len_770 or $cmp_len_76C)
         )
         or
         // Condition 3: Specific import hash for AES Encrypted version
         // sha256: 48d0d162bd408f32f8909d08b8e60a21b49db02380a13d366802d22d4250c4e7
         pe.imphash() == "ee5ea868d8233000216e7b29bc8cb4e2"
      )
}


rule MAL_CrypRAT_Jan19_1 {
   meta:
      description = "Detects CrypRAT"
      author = "Florian Roth (Nextron Systems)"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      reference = "Internal Research"
      score = 90
      date = "2019-01-07"
      id = "f3063a16-8813-5d6c-9807-6a0725907fb5"
   strings:
      $x1 = "Cryp_RAT" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
         pe.imphash() == "2524e5e9fe04d7bfe5efb3a5e400fe4b" or
         1 of them
      )
}


rule MAL_Compromised_Cert_DuckTail_Stealer_Jun23 {
   meta:
      author = "dr4k0nia"
      description = "Detects binaries signed with compromised certificates used by DuckTail stealer - identified in June 2023"
      reference = "Internal Research"
      date = "2023-06-16"
      modified = "2023-08-12"
      hash1 = "17c75f2d14af9f00822fc1dba00ccc9ec71fc50962e196d7e6f193f4b2ee0183"
      hash2 = "b3cfdb442772d07a7f037b0bb093ba315dfd1e79b0e292736c52097355495270"
      hash3 = "9afe013cae0167993a6a7ccd650eb1221a5ec163110565eb3a49a8b57949d4ee"
      score = 80
      id = "b491e1b6-42c4-58e9-8efa-19e697804f96"
   strings:
      $sx1 = "AZM MARKETING COMPANY LIMITED" ascii fullword
      $sx2 = "CONG TY TNHH" ascii
      $sx3 = {43 C3 94 4E 47 20 54 59 20 54 4E 48 48 20}
      $sx4 = "CONG TY TRACH" ascii

      $se1 = {65 78 BE 85 2D 48 E3 3D 4E 48 B8 D4 73 F5 B7 60} // AZM MARKETING COMPANY LIMITED
      $se2 = {1D 53 38 32 74 2B 58 37 87 C0 A2 53 32 F7 FB 06} // AZM MARKETING COMPANY LIMITED
      $se3 = {00 BD 7B 85 B2 6A 69 C9 7D 6D 68 CC 95 67 34 C0 6B} // CONG TY TNHH PDF SOFTWARE
      $se4 = {06 5F 5C 57 0B D6 A7 98 92 FB B0 E6 34 61 3A 4D}
      $se5 = {41 55 3F 07 13 37 11 7A 99 B4 58 57} // CONG TY TNHH CAO SU MINH KHANG
      $se6 = {1E AA E4 CE E7 EE 89 FB 20 32 59 27 88 13 D8 53} // CONG TY TNHH MTV SAN VUON THAI VUONG
      $se7 = {56 DC DB 85 D4 89 F9 87 B2 D6 76 72} // CONG TY TNHH THUONG MAI VA XAY DUNG PHUC NGUYEN
      $se8 = {2D A4 50 57 C2 74 3C 1A 3C A4 93 7A} // CONG TY TNHH DICH VU CAU CHU NHO
      $se9 = {37 AE 95 F5 4C 8E 9B D0 B6 47 68 6A} // CONG TY TNHH THIET KE VA XAY DUNG SAN VUON NON BO SON HAI
      $se10 = {3D C8 F5 3B 62 7A 34 07 AC 7E 01 00 13 87 A3 B3} // CONG TY TNHH GIa I PHA P CCNG NGHE SO VIET
      $se11 = {01 C9 87 5A 5F A8 59 68 6D 34 17 C9} // CONG TY TRACH NHIEM HUU HAN THIET BI NOI THAT TAKASY
      $se12 = {1B 35 19 E1 CD C2 6B 57 DA EE 06 C9} // CONG TY TNHH DUOC PHAM VA THIET BI Y TE BT
      $se13 = {79 7D 0B 5E 22 AA 0F C7 A2 97 E6 48} // CONG TY TNHH THIET BI Y TE QUOC TE VIET AU
      $se14 = {57 9E 5C 89 B0 85 A7 96 B3 3C F3 19} // CONG TY TNHH THUONG MAI DICH VU CO KHI & XAY DUNG SONG NHAT VIET
   condition:
      uint16(0) == 0x5a4d
      and 1 of ($sx*) and 1 of ($se*)
}


rule MAL_Etoroloro_Malicious_NodePackage_Dec25 {
   meta:
      description = "Detects malicious component of node package named Etoroloro"
      reference = "Internal Research"
      author = "Pezier Pierre-Henri"
      date = "2025-12-12"
      score = 80
      hash = "f08c5b748c91dd45fd73c5e85920f656e361d94b869e2147410b2b528c6ae78f"
      id = "4c271502-68c6-5d20-85ea-c7f7628e417a"
   strings:
      $s1 = "DLLSideload."
      $s2 = "Failed to expand path:" wide
      $op1 = {
         41 0f af c0           // imul    eax, r8d
         48 8d 52 01           // lea     rdx, [rdx+1]
         0f b6 c9              // movzx   ecx, cl
         45 69 c0 35 d4 04 00  // imul    r8d, 4D435h
         03 c1                 // add     eax, ecx
         0f b6 0a              // movzx   ecx, byte ptr [rdx]
         84 c9                 // test    cl, cl
         75 e5                 // jnz     short loc_1800022C0
      }
   condition:
      uint16(0) == 0x5a4d
      and (all of ($s*) or $op1)
}



rule MAL_Fake_Document_Software_Indicators_Nov23 {
   meta:
      description = "Detects indicators of fake document/image utility software that acts as a downloader for additional malware"
      author = "Jonathan Peters"
      date = "2023-11-13"
      reference = "https://nochlab.blogspot.com/2023/09/net-in-javascript-fake-pdf-converter.html"
      hash1 = "ac5356ae011effb9d401bf428c92a48cf82c9b61f4c24a29a9718e3379f90f1d"
      hash2 = "d1c29c2243c511ca3264ad568a6be62f374e104b903eca93debce6691e1c5007"
      score = 80
      id = "231474cd-1ec9-5738-bf48-ef707689056d"
   strings:
      $ = "tweakscode.com" wide
      $ = "www.createmygif.com" wide
      $ = "www.videownload.com" wide
      $ = "www.pdfconverterz.com" wide
      $ = "www.pdfconvertercompare.com" wide
   condition:
      uint16(0) == 0x5a4d
      and 1 of them
}


rule MAL_Katz_Stealer_May25 {
   meta:
      description = "Detects Katz stealer"
      author = "MalGamy (Nextron Systems)"
      date = "2025-05-16"
      reference = "Internal Research"
      hash = "fdc86a5b3d7df37a72c3272836f743747c47bfbc538f05af9ecf78547fa2e789"
      hash = "d92bb6e47cb0a0bdbb51403528ccfe643a9329476af53b5a729f04a4d2139647"
      score = 80
      id = "ef84df99-3c1a-56b6-a0fd-39876982d0c3"
   strings:
      $s1 = "Motherboard Product: %s" ascii
      $s2 = "cmd.exe /c %s" ascii
      $s3 = "reg export \"%s\" \"%s\" /y" ascii
      $s4 = ").request({ hostname: '" ascii
      $s5 = "Type: Removable"
      $s6 = "%s\\Microsoft\\Windows Live Mail" ascii
   condition:
      uint16(0) == 0x5a4d
      and filesize < 300KB
      and 4 of them
}



rule MAL_DLL_Chrome_App_Bound_Encryption_Decryption_May25 {
   meta:
      description = "Detects a DLL used to decrypt App-Bound Encrypted (ABE) cookies, passwords and payment methods from Chromium-based browsers. Seen being used by Katz stealer"
      author = "MAlGamy"
      date = "2025-05-19"
      reference = "Internal Research"
      hash = "6dc8e99da68b703e86fa90a8794add87614f254f804a8d5d65927e0676107a9d"
      score = 80
      id = "ee1e2584-7104-506f-93a9-89e97cf39a93"
   strings:
      $s1 = "Failed to set proxy blanket." ascii
      $s2 = "Decryption failed. Last error:" ascii
      $s3 = "\\Google\\Chrome\\User Data\\Local State" ascii

      $op1 = {48 39 F3 74 ?? 4C 89 E2 48 89 E9 E8 ?? ?? ?? ?? 48 89 C1 48 8B 00 B2 ?? 48 8B 40 ?? 48 C7 44 01 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 13 48 89 C1 E8 ?? ?? ?? ?? 48 FF C3 EB ?? 48 8D 54 24 ?? 48 89 F9 E8 ?? ?? ?? ?? 48 89 E9 E8 ?? ?? ?? ?? 48 89 F8 48 81 C4}
   condition:
      uint16(0) == 0x5a4d
      and filesize < 2MB
      and $op1 and 1 of ($s*)
}



rule MAL_NET_UAC_Bypass_May25 {
   meta:
      description = "Detects .NET based tool abusing legitimate Windows utility cmstp.exe to bypass UAC (User-Admin-Controls)"
      author = "Jonathan Peters (cod3nym)"
      date = "2025-05-21"
      reference = "Internal Research"
      hash = "4f12c5dca2099492d0c0cd22edef841cbe8360af9be2d8e9b57c2f83d401c1a7"
      hash = "fcad234dc2ad5e2d8215bcf6caac29aef62666c34564e723fa6d2eee8b6468ed"
      score = 80
      id = "bf14177f-be55-5bb1-8218-a4a734532ea4"
   strings:
      $x1 = "CmstpBypass" ascii
      $x2 = { 52 00 45 00 50 00 4C 00 41 00 43 00 45 00 5F 00 43 00 4F 00 4D 00 4D 00 41 00 4E 00 44 00 5F 00 4C 00 49 00 4E 00 45 00 00 13 63 00 6D 00 73 00 74 00 70 00 2E 00 65 00 78 00 65 00 00 33 63 00 6D 00 73 00 74 00 70 00 2E 00 65 00 78 00 65 }
      $x3 = { 52 00 45 00 50 00 4C 00 41 00 43 00 45 00 5F 00 43 00 4F 00 4D 00 4D 00 41 00 4E 00 44 00 5F 00 4C 00 49 00 4E 00 45 00 0D 00 0A 00 74 00 61 00 73 00 6B 00 6B 00 69 00 6C 00 6C 00 20 00 2F 00 49 00 4D 00 20 00 63 00 6D 00 73 00 74 00 70 00 2E 00 65 00 78 00 65 }
   condition:
      uint16(0) == 0x5a4d
      and $x1
      or 1 of ($x2,$x3)
}


rule MAL_Kernel_RegPhantom_Mar26 {
   meta:
      description = "Detects RegPhantom, a kernel-mode rootkit that allow attacker to inject arbitrary code from unprivileged user-mode into kernel-mode and execute it."
      author = "Pezier Pierre-Henri (Nextron Systems)"
      date = "2026-03-19"
      reference = "Internal Research"
      hash = "006e08f1b8cad821f7849c282dc11d317e76ce66a5bcd84053dd5e7752e0606f"
      score = 80
      id = "aa8963b5-3053-52a4-a84f-2fc02d03275e"
   strings:
      $s1 = "CmRegisterCallback" fullword
      $s2 = "PsSetCreateThreadNotifyRoutine" fullword

      $o1 = {
         // xor decrypt
         48 8b 09     // mov     rcx, [rcx]
         0f b6 14 08  // movzx   edx, byte ptr [rax+rcx]
         4c 31 c2     // xor     rdx, r8
         88 14 08     // mov     [rax+rcx], dl
      }
      $o2 = {
         // Command selector
         c6 01 01     // mov     byte ptr [rcx], 1
         48 83 38 77  // cmp     qword ptr [rax], 77h
         0f 94 c0     // setz    al
         24 01        // and     al, 1
      }
   condition:
      uint16(0) == 0x5a4d
      and all of them
}



rule MAL_Neshta_Generic : HIGHVOL {
   meta:
      description = "Detects Neshta malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-01-15"
      modified = "2021-04-14"
      hash1 = "27c67eb1378c2fd054c6649f92ec8ee9bfcb6f790224036c974f6c883c46f586"
      hash1 = "0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e"
      hash2 = "b7f8233dafab45e3abbbb4f3cc76e6860fae8d5337fb0b750ea20058b56b0efb"
      hash3 = "1954e06fc952a5a0328774aaf07c23970efd16834654793076c061dffb09a7eb"
      id = "9a3b8369-7e19-5c21-9eba-0bb81507696a"
   strings:
      $x1 = "the best. Fuck off all the rest."
      $x2 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" fullword ascii

      $s1 = "Neshta" ascii fullword
      $s2 = "Made in Belarus. " ascii fullword

      $op1 = { 85 c0 93 0f 85 62 ff ff ff 5e 5b 89 ec 5d c2 04 }
      $op2 = { e8 e5 f1 ff ff 8b c3 e8 c6 ff ff ff 85 c0 75 0c }
      $op3 = { eb 02 33 db 8b c3 5b c3 53 85 c0 74 15 ff 15 34 }

      $sop1 = { e8 3c 2a ff ff b8 ff ff ff 7f eb 3e 83 7d 0c 00 }
      $sop2 = { 2b c7 50 e8 a4 40 ff ff ff b6 88 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and (
         1 of ($x*) or 
         all of ($s*) or 
         3 of them or 
         pe.imphash() == "9f4693fc0c511135129493f2161d1e86"
      )
}


rule SUSP_JS_Dropper_Mar26 {
   meta:
      description = "Detects suspicious JavaScript dropper used in plain-crypto-js supply chain attacks"
      author = "Marius Benthin"
      date = "2026-03-31"
      reference = "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
      hash = "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09"
      score = 70
      id = "456a52c2-9cbf-572f-9a5b-b8d74183e3f4"
   strings:
      $sa1 = "Buffer.from("
      $sa2 = "FileSync("
      $sa3 = ".replaceAll("

      $sb1 = ".arch()"
      $sb2 = ".platform()"
      $sb3 = ".release()"
      $sb4 = ".type()"
   condition:
      filesize < 10KB
      and all of ($sa*)
      and 2 of ($sb*)
}


rule MAL_Passwordstate_Moserware_Backdoor_Apr21_1 {
   meta:
      description = "Detects backdoor used in Passwordstate incident"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://thehackernews.com/2021/04/passwordstate-password-manager-update.html"
      date = "2021-04-25"
      hash1 = "c2169ab4a39220d21709964d57e2eafe4b68c115061cbb64507cfbbddbe635c6"
      hash2 = "f23f9c2aaf94147b2c5d4b39b56514cd67102d3293bdef85101e2c05ee1c3bf9"
      id = "061de3ae-c404-5e4a-a16b-b3b208b1ae7f"
   strings:
      $x1 = "https://passwordstate-18ed2.kxcdn.com" wide

      $s1 = " ProxyUserName, ProxyPassword FROM [SystemSettings]" wide fullword
      $s2 = "PasswordstateService.Passwordstate.Crypto" wide
      $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari" wide fullword

      $op1 = { 00 4c 00 4e 00 43 00 4c 00 49 00 31 00 31 00 3b 00 00 17 }
      $op2 = { 4c 00 49 00 31 00 31 00 3b 00 00 17 50 00 72 00 }
      $op3 = { 61 00 74 00 65 00 2d 00 31 00 38 00 65 00 64 00 32 00 2e 00 6b 00 78 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 200KB and
      1 of ($x*) or 3 of them
}


rule MAL_EXPL_Perfctl_Oct24 {
   meta:
      description = "Detects exploits used in relation with Perfctl malware campaigns"
      author = "Florian Roth"
      reference = "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/"
      date = "2024-10-09"
      score = 80
      hash1 = "22e4a57ac560ebe1eff8957906589f4dd5934ee555ebcc0f7ba613b07fad2c13"
      id = "1f525eaf-445c-592e-bfa4-e9846390dd1d"
   strings:
      $s1 = "Exploit failed. Target is most likely patched." ascii fullword
      $s2 = "SHELL=pkexec" ascii fullword
      $s3 = "/dump_" ascii fullword
      $s4 = ".EYE$" ascii
   condition:
      uint16(0) == 0x457f
      and filesize < 30000KB
      and 2 of them
      or all of them
}



rule MAL_LNX_Perfctl_Oct24 {
   meta:
      description = "Detects Perfctl malware samples"
      author = "Florian Roth"
      reference = "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/"
      date = "2024-10-09"
      score = 75
      hash1 = "a6d3c6b6359ae660d855f978057aab1115b418ed277bb9047cd488f9c7850747"
      hash2 = "ca3f246d635bfa560f6c839111be554a14735513e90b3e6784bedfe1930bdfd6"
      id = "391513ae-3348-5297-a22a-6f06e50f06d2"
   strings:
      $op1 = { 83 45 f8 01 8b 45 f8 48 3b 45 98 0f 82 1b ff ff ff 90 c9 c3 55 }
      $op2 = { 48 8b 55 a0 48 01 ca 0f b6 0a 48 8b 55 a8 89 c0 88 4c 02 18 8b 45 fc 83 e0 3f }
      $op3 = { 88 4c 10 58 83 45 f8 01 83 7d f8 03 0f 86 68 ff ff ff 90 c9 c3 55 }
      $op4 = { 48 83 ec 68 48 89 7d a8 48 89 75 a0 48 89 55 98 48 8b 45 a8 48 8b 00 83 e0 3f 89 45 fc }
   condition:
      uint16(0) == 0x457f
      and filesize < 300KB
      and 2 of them
}


rule MAL_PHISH_ShellCode_Enc_Payload_Feb25 {
   meta:
      author = "X__Junior"
      description = "Detects unknown of phishing-delivered malware"
      reference = "https://x.com/dtcert/status/1890384162818802135"
      hash = "247e6a648bb22d35095ba02ef4af8cfe0a4cdfa25271117414ff2e3a21021886"
      date = "2025-02-14"
      score = 80
      id = "8459c5ba-37ec-59bd-8d4a-5ab7b6bb4553"
   strings:
     $op1 = { 48 89 EA FF D0 48 89 E9 4C 8D 4C 24 ?? 41 B8 ?? ?? ?? ?? 48 89 C7 48 89 C3 48 89 EA F3 A4 48 89 C1 41 FF D4 31 C9 FF D3}
   condition:
      uint16(0) == 0x5a4d and $op1
}



rule SUSP_Sysinternals_Desktops_Anomaly_Feb25 {
   meta:
      description = "Detects anomalies in Sysinternals Desktops binaries"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-02-14"
      score = 70
      hash = "5b8f64e090c7c9012e656c222682dfae7910669c7b7afaca35829cd1cc2eac17"
      hash = "d0f7f3f58e0dfcfd81235379bb5a236f40be490207d3bf45f190a264879090db"
      hash = "a83dc4d69a3de72aed4d1933db2ca120657f06adc6683346afbd267b8b7d27d0"
      hash = "9ebfe694914d337304edded8b6406bd3fbff1d4ee110ef3a8bf95c3fb5de7c38"
      hash = "9a5b9d89686de129a7b1970d5804f0f174156143ccfcd2cf669451c1ad4ab97e"
      hash = "ff82c4c679c5486aed2d66a802682245a1e9cd7d6ceb65fa0e7b222f902998e8"
      hash = "1da91d2570329f9e214f51bc633283f10bd55a145b7b3d254e03175fd86292d9"
      id = "5a586222-9263-5079-be48-9cfa464440d4"
   strings:
      $s1 = "Software\\Sysinternals\\Desktops" wide fullword
      $s2 = "Sysinternals Desktops" wide fullword
      $s3 = "http://www.sysinternals.com" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize > 350KB
      and all of them
}



rule SUSP_PE_Compromised_Certificate_Feb25 {
   meta:
      description = "Detects suspicious PE files signed with a certificate used in a widespread phishing attack in February 2025"
      author = "Jonathan Peters"
      reference = "https://x.com/DTCERT/status/1890384162818802135"
      date = "2025-02-14"
      score = 60
      hash = "5b8f64e090c7c9012e656c222682dfae7910669c7b7afaca35829cd1cc2eac17"
      hash = "d0f7f3f58e0dfcfd81235379bb5a236f40be490207d3bf45f190a264879090db"
      hash = "a83dc4d69a3de72aed4d1933db2ca120657f06adc6683346afbd267b8b7d27d0"
      hash = "9ebfe694914d337304edded8b6406bd3fbff1d4ee110ef3a8bf95c3fb5de7c38"
      hash = "9a5b9d89686de129a7b1970d5804f0f174156143ccfcd2cf669451c1ad4ab97e"
      hash = "ff82c4c679c5486aed2d66a802682245a1e9cd7d6ceb65fa0e7b222f902998e8"
      hash = "1da91d2570329f9e214f51bc633283f10bd55a145b7b3d254e03175fd86292d9"
      id = "2e6ad630-b24e-53b2-8ffe-622c51914568"
   strings:
      $sb1 = { 44 B8 66 73 57 BB 95 65 1D 61 D0 61 } // compromised certificate serial
      $sb2 = { 4F 23 43 D9 61 54 B9 41 DB 0A 26 B2 } // compromised certificate serial
      $sb3 = { 40 A3 62 E3 50 68 91 19 F5 2E C3 4C } // compromised certificate serial
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20MB
      and 1 of them
}


rule MAL_WIN_Ralordv1_Apr25 {
    meta:
        description = "This ISH Tecnologia Yara rule, detects the main components of the first version of RALord Ransomware"
        author = "0x0d4y-Icaro Cesar"
        date = "2025-04-01"
        score = 80
        reference = "https://ish.com.br/wp-content/uploads/2025/04/RALord-Novo-grupo-de-Ransomware-as-a-Service-1.pdf"
        hash = "BE15F62D14D1CBE2AECCE8396F4C6289"
        id = "67254633-3597-4770-9806-8b2e26c8f66a"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        rule_matching_tlp = "TLP:WHITE"
        rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.ralord"

    strings:
        $code_pattern_quarterround = { 4? 31 ?? 48 8b ?? ?? ?? 4? 31 ?? 48 8b ?? ?? ?? 31 e8 4? 31 ?? 41 c1 ?? 0c c1 ?? 0c c1 ?? 0c 48 89 c2 c1 ?? 0c }
        $code_pattern_custom_alg = { 0f 57 ?? 0f 10 ?? c5 ?? ?? ?? ?? 0f 57 ?? 0f 10 ?? c5 ?? ?? ?? ?? 0f 57 ?? 0f 10 ?? c5 ?? ?? ?? ?? 0f 57 ?? 0f 11 ?? c5 ?? ?? ?? ?? 0f 11 ?? c5 ?? ?? ?? ?? 0f 11 ?? c5 ?? ?? ?? ?? 0f 11 ?? c5 ?? ?? ?? ?? 48 83 c0 08 48 3d 8? }
        $ralord_str_I = "chacha" ascii
        $ralord_str_II = "scorp" ascii
        $ralord_str_III = "RALord" ascii
        $ralord_str_IV = "onion" ascii
        $ralord_str_V = "/rust" ascii
        $ralord_str_VI = "BCryptGenRandom" ascii

    condition:
        uint16(0) == 0x5a4d and
        all of ($code_pattern_*) and
        4 of ($ralord_str_*)
}


rule MAL_RANSOM_Lorenz_May21_1 {
   meta:
      description = "Detects Lorenz Ransomware samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - DACH TE"
      date = "2021-05-04"
      hash1 = "4b1170f7774acfdc5517fbe1c911f2bd9f1af498f3c3d25078f05c95701cc999"
      hash2 = "8258c53a44012f6911281a6331c3ecbd834b6698b7d2dbf4b1828540793340d1"
      hash3 = "c0c99b141b014c8e2a5c586586ae9dc01fd634ea977e2714fbef62d7626eb3fb"
      id = "0b18a4a3-82da-574b-8d10-daf2176448b9"
   strings:
      $x1 = "process call create \"cmd.exe /c schtasks /Create /F /RU System /SC ONLOGON " ascii fullword
      $x2 = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCn7fL/1qsWkJkUtXKZIJNqYfnVByVhK" ascii fullword
      
      $s1 = "process call create \"cmd.exe /c schtasks /Create /F " ascii fullword
      $s2 = "twr.ini" ascii fullword
      $s3 = "/c wmic /node:'" ascii fullword

      $op1 = { 0f 4f d9 81 ff dc 0f 00 00 5f 8d 4b 0? 0f 4e cb 83 fe 3c 5e 5b }
      $op2 = { 6a 02 e8 ?? ?? 0? 00 83 c4 18 83 f8 01 75 01 cc 6a 00 68 ?? ?? 00 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 4000KB and (
         1 of ($x*) or 
         all of ($op*) 
         or 3 of them
      ) 
}

rule MAL_PeerBlight_Dec25 {
   meta:
      description = "Detects PeerBlight Linux backdoor with systemd persistence artifacts and user-mode masquerading strings, linked to React2Shell exploitation"
      author = "RussianPanda"
      date = "2025-12-07"
      score = 85
      reference = "https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell"
      hash = "a605a70d031577c83c093803d11ec7c1e29d2ad530f8e95d9a729c3818c7050d"
      id = "23e6d040-00cb-5ad4-9f9b-bdbabeabd7ab"
   strings:
      $s1 = "/bin/systemd-daemon"
      $s2 = "/lib/systemd/system/systemd-agent.service"
      $s3 = "group"
      $s4 = "tag"
      $s5 = "arch"
      $s6 = "softirq"
   condition:
      uint32(0) == 0x464c457f and 5 of them
}


rule MAL_WIN_Akira_Apr25 {
    meta:
        description = "This Yara rule from ISH Tecnologia's Heimdall Security Research Team detects key components of Akira Ransomware"
        author = "0x0d4y-Icaro Cesar"
        date = "2025-04-11"
        score = 90
        reference = "https://ish.com.br/wp-content/uploads/2025/04/A-Anatomia-do-Ransomware-Akira-e-sua-expansao-multiplataforma.pdf"
        hash = "205589629EAD5D3C1D9E914B49C08589"
        id = "76722cb6-70be-465f-9ef1-afd78f694289"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        rule_matching_tlp = "TLP:WHITE"
        rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.akira"

    strings:
        $code_custom_algorithm = { 44 8B CF 90 42 0F B6 4C 0D ?? 83 E9 4E 44 8D 04 89 45 03 C0 B8 09 04 02 81 41 F7 E8 41 03 D0 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 44 2B C0 41 83 C0 7F B8 09 04 02 81 41 F7 E8 41 03 D0 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 44 2B C0 46 88 44 0D ?? 49 FF C1 }
        $code_aes_key_expansion = { 41 8D 41 FF 33 D2 8B 0C ?? 41 8B C1 41 F7 F2 85 D2 75 ?? 44 8B C1 0F B6 C1 0F B6 0C ?? 41 8B C0 48 C1 E8 ?? C1 E1 ?? 0F B6 04 ?? 0B C8 41 8B C0 48 C1 E8 ?? C1 E1 ?? 0F B6 D0 49 C1 E8 ?? 0F B6 04 ?? 0B C8 41 0F B6 C0 C1 E1 ?? 0F B6 14 ?? 0F B6 45 00 0B CA 33 C8 48 FF C5 }
        $akira_str_I = "akira" ascii
        $akira_str_II = "onion" ascii
        $akira_str_III = "powershell" ascii
        $akira_str_IV = "akira_readme.txt" ascii


    condition:
        uint16(0) == 0x5a4d and
        all of ($code_*) and
        all of ($akira_str_*)
}


rule MAL_Win_Amadey_Jun25 {
   meta:
      author = "0x0d4y"
      description = "This rule detects intrinsic patterns of Amadey version 5.34"
      date = "2025-06-18"
      score = 80
      reference = "https://0x0d4y.blog/amadey-targeted-analysis/"
      yarahub_reference_md5 = "1db72c5832fb71b29863ccc3125137a0"
      id = "853111b8-e548-46a9-8f5a-ec8621343e0d"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      malpedia_family = "win.amadey"

   strings:
      $rc4_algorithm = { 8a 96 ?? ?? ?? ?? 0f b6 86 ?? ?? ?? ?? 03 f8 0f b6 ca 03 f9 81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47 8a 87 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 46 88 97 ?? ?? ?? ?? 81 fe 00 01 00 00 7c }
      $s_MZ_PE_validation = { b8 4d 5a ?? ?? 66 39 06 0f 85 a8 01 ?? ?? 8b 7e 3c 03 fe 81 3f 50 45 00 00  }
      $s_loop_through_pe_section = { 8b 4c 24 0c 03 ce 03 4e 3c 6a ?? ff b1 08 01 ?? ?? 8b 81 0c 01 00 00 03 c6 50 8b 81 04 01 ?? ?? 03 44 24 20 50 ff 74 24 30 ff 15 f4 f0 44 00 8b 4c 24 10 0f b7 47 06 41 83 44 24 0c 28 89 4c 24 10 3b c8 }
      $s_str_decryption_algorithm = { 8b cb 0f 43 35 ?? ?? ?? ?? 2b c8 8d 04 0a 33 d2 f7 f3 }

    condition:
      uint16(0) == 0x5a4d 
      and $rc4_algorithm 
      and 2 of ($s*)
}


rule MAL_BACKORDER_LOADER_WIN_Go_Jan23 {
   meta:
      description = "Detects the BACKORDER loader compiled in GO which download and executes a second stage payload from a remote server."
      author = "Arda Buyukkaya (modified by Florian Roth)"
      date = "2025-01-23"
      reference = "EclecticIQ"
      score = 80
      tags = "loader, golang, BACKORDER, malware, windows"
      hash = "70c91ffdc866920a634b31bf4a070fb3c3f947fc9de22b783d6f47a097fec2d8"
      id = "90a82f2c-be92-5d0b-b47e-f47db2b15867"
   strings:
      $GoBuildId = "Go build" ascii
      // Debug symbols commonly seen in BACKORDER loader
      $x_DebugSymbol_1 = "C:/updatescheck/main.go"
      $x_DebugSymbol_2 = "C:/Users/IEUser/Desktop/Majestic/"
      // Function name patterns observed in BACKORDER loader
      $s_FunctionName_1 = "main.getUpdates.func"
      $s_FunctionName_2 = "main.obt_zip"
      $s_FunctionName_3 = "main.obtener_zip"
      $s_FunctionName_4 = "main.get_zip"
      $s_FunctionName_5 = "main.show_pr0gressbar"
      $s_FunctionName_6 = "main.pr0cess"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 10MB
      and $GoBuildId
      and (
         1 of ($x*)
         or 3 of them
      )
}


rule MAL_WIN_Megazord_Apr25 {
    meta:
        description = "This Yara rule from ISH Tecnologia's Heimdall Security Research Team, detects the main components of the Megazord Ransomware"
        author = "0x0d4y-Icaro Cesar"
        date = "2025-04-11"
        score = 80
        reference = "https://ish.com.br/wp-content/uploads/2025/04/A-Anatomia-do-Ransomware-Akira-e-sua-expansao-multiplataforma.pdf"
        hash = "FD380DB23531BB7BB610A7B32FC2A6D5"
        id = "6225a690-8f54-4a50-a19a-8f7523537228"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        rule_matching_tlp = "TLP:WHITE"
        rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.akira"

    strings:
        $code_custom_algorithm = { 89 c1 45 31 e6 31 e8 44 31 f0 35 ?? ?? ?? ?? c1 c0 0b 44 31 ff 44 31 ef 31 c7 81 f7 ?? ?? ?? ?? c1 c7 0b 44 31 e3 31 cb 31 fb 81 f3 ?? ?? ?? ?? c1 c3 0b 89 da 31 c2 89 84 24 ?? ?? ?? ?? 44 31 ed 31 d5 89 94 24 ?? ?? ?? ?? 81 f5 ?? ?? ?? ?? c1 c5 0b 41 89 e8 41 31 f8 89 bc 24 ?? ?? ?? ?? 41 31 cf 45 31 c7 44 89 84 24 ?? ?? ?? ?? 41 81 f7 ?? ?? ?? ?? 41 c1 c7 0b 41 31 d4 45 31 fc 41 81 f4 ?? ?? ?? ?? 41 c1 c4 0b 45 31 c5 45 31 e5 41 81 f5 ?? ?? ?? ?? 41 c1 c5 0b 89 9c 24 ?? ?? ?? ?? 31 d9 44 31 f9 44 31 e9 81 f1 ?? ?? ?? ?? c1 c1 0b 41 89 c8 45 31 e0 44 89 a4 24 ?? ?? ?? ?? 89 ac 24 ?? ?? ?? ?? 31 e8 44 31 c0 35 ?? ?? ?? ?? c1 c0 0b 44 89 fa 44 89 bc 24 ?? ?? ?? ?? 31 fa 44 31 ea 31 c2 41 89 c1 81 f2 ?? ?? ?? ?? c1 c2 0b 41 31 d8 41 31 d0 41 81 f0 ?? ?? ?? ?? 41 c1 c0 0b 44 89 e8 44 89 ac 24 ?? ?? ?? ?? 31 e8 44 31 c8 44 31 c0 45 89 c3 35 }
        $megazord_str_I = "powerranges" ascii
        $megazord_str_II = "onion" ascii
        $megazord_str_III = "powershell" ascii
        $megazord_str_IV = "taskkill" ascii
        $megazord_str_V = "mal_public_key_bytes" ascii
        $megazord_str_VI = "runneradmin" ascii
        $megazord_str_VII = "//rustc" ascii


    condition:
        uint16(0) == 0x5a4d and
        $code_custom_algorithm and
        5 of ($megazord_str_*)
}


rule MAL_WIPER_Unknown_Jun25 {
   meta:
      description = "Detects unknown disk wiper first spotted in June 2025 and uploaded from Israel"
      author = "Florian Roth"
      reference = "https://x.com/cyb3rops/status/1935707307805134975"
      date = "2025-06-19"
      score = 75
      hash1 = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
      id = "ceb2b80f-6bc3-555a-b1c8-003f380533e5"
   strings:
      $x1 = "\\CWipeNew\\Release\\" ascii fullword

      $s1 = "Failed to get disk geometry: " wide fullword
      $s2 = "--- Working on " wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 200KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
}


rule SUSP_LNX_SH_Disk_Wiper_Script_Jun25 {
   meta:
      description = "Detects unknown disk wiper script for Linux systems"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-06-19"
      score = 65
      hash1 = "f662f69fc7f4240cd8c00661db9484e76b5d02f903590140b4086fefcf9d9331"
      id = "aad68277-4889-512d-b8b3-a4c4706fbc9e"
   strings:
      $s1 = "THIS SCRIPT IS LIVE AND ARMED!" ascii fullword
      $s2 = "FAIR WARNING!" ascii fullword
      $s3 = "lists devices" ascii fullword
   condition:
      uint16(0) == 0x2123
      and filesize < 2KB
      and all of them
}



rule SUSP_PY_PYInstaller_Swiper_Jun25 {
   meta:
      description = "Detects suspicious Python based executable with similarities to a known disk wiper"
      author = "Florian Roth"
      reference = "https://x.com/cyb3rops/status/1935707307805134975"
      date = "2025-06-19"
      score = 65
      hash1 = "4f669ecbe12e95d51f37be76933de4c2626d20bb01729086ce2efc603c4ffdf3"
      id = "049587a8-275d-59a6-bfbd-b72173d21a73"
   strings:
      $a1 = "bzlib1.dll" ascii fullword
      $a2 = "VCRUNTIME140_1.dll" wide fullword
      $a3 = "%s%c%s.exe" ascii fullword

      $sc1 = { 73 77 69 70 65 72 00 00 00 } // "swiper\0\0\0"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 40000KB
      and all of them
}



rule SUSP_XMRIG_String {
   meta:
      description = "Detects a suspicious XMRIG crypto miner executable string in filr"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-12-28"
      hash1 = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"
      id = "8c6f3e6e-df2a-51b7-81b8-21cd33b3c603"
   strings:
      $x1 = "xmrig.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}


rule SUSP_LNX_ARCH_PKGBUILD_NPM_Dependency_Jun26 {
   meta:
      description = "Detects suspicious PKGBUILD with NPM dependency and install script"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      reference2 = "https://aur.archlinux.org/cgit/aur.git/commit/?h=python-django-js-asset&id=af09b1cf1b59"
      hash = "56bed7736d44219215fd912b229c7f765b737db4f6cde256ce264e795310c648"
      hash = "1359814fda7f5ef63f04348439bfb011d7abc0381be6fbb404b04b359d63b61b"
      hash = "3e1f297ab4d261fcad14a865a54d049d75d897d549d03371a5c4bbbc6e10e5cd"
      score = 60
   strings:
      // depends=('npm' or 'bun'
      $sa1 = { (0A | 20) 64 65 70 65 6E 64 73 3D 28 [0-15] (6E 70 6D | 62 75 6E) }

      // install -Dm644 "../*.hook"
      $sb1 = { 69 6E 73 74 61 6C 6C 20 2D 44 6D 36 34 34 20 (22 | 27) [0-100] 2E 68 6F 6F 6B (22 | 27) 0A }
      // install=oracle-bin-deps.install
      $sb2 = { 69 6E 73 74 61 6C 6C 3D [1-50] 2E 69 6E 73 74 61 6C 6C }
   condition:
      filesize < 100KB
      and $sa1
      and 1 of ($sb*)
}



rule SUSP_LNX_ARCH_SRCINFO_NPM_Dependency_Jun26 {
   meta:
      description = "Detects suspicious .SRCINFO with NPM dependency and install script"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      hash = "2ee28d5866fdb46e439678ad92729b1cd71d2d871135d8d56a27cf6a6b49e649"
      score = 60
   strings:
      $s1 = "depends = npm\n"
      // install = python-pymilvus-deps.install
      $s2 = { 69 6E 73 74 61 6C 6C 20 3D 20 [1-50] 2E 69 6E 73 74 61 6C 6C }
   condition:
      filesize < 5KB
      and all of them
}



rule SUSP_AppDomainInjection_Keyword_May26 {
   meta:
      description = "Detects link files, archives and binaries that contain keywords related to AppDomain hijacking/injection a technique used by malware to sideload payloads."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-27"
      reference = "https://attack.mitre.org/techniques/T1574/014/"
      hash = "eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71"
      score = 70
   strings:
      $x1 = "AppDomainInjection" ascii wide fullword
      $x2 = "AppDomainHijack" ascii wide fullword
   condition:
      (
         uint16(0) == 0x5a4d // PE
         or uint16(0) == 0x4b50 // ZIP
         or uint32(0x8000) == 0x30444301 // ISO
         or uint16(0) == 0x004c and uint32(4) == 0x00021401 // LNK
      )
      and 1 of ($x*)
}



rule SUSP_PE_Contains_Encrypted_Executable_May26 {
   meta:
      description = "Detects executables containing an encrypted embedded payload using parameters commonly observed in malware, suggesting obfuscation or staged execution."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-20"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      hash = "eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71"
      score = 70
   strings:
      // MZ header AES encrypted with key: 1234567890123456 and IV: abcdefghijklmnop
      $op = { ae b6 8d 86 71 f0 a9 c8 90 66 53 31 ef 7f 1f d2 b4 a8 21 bc 39 77 c2 c2 60 db 24 4a 12 32 f9 69 09 09 46 22 a6 d1 0a 5e a7 dc 62 fa 96 56 ad dd }
   condition:
      uint16(0) == 0x5a4d
      and 1 of them
}


rule SUSP_VulnDriver_HP_Hardware_Diagnostics_Etdsupp_May23 {
   meta:
      description = "Detects vulnerable versions of the HP Hardware Diagnostics driver (etdsupp.sys) based on PE metadata info"
      author = "X__Junior (Nextron Systems)"
      date = "2023-05-12"
      reference = "https://github.com/alfarom256/HPHardwareDiagnostics-PoC/tree/main/"
      hash = "f744abb99c97d98e4cd08072a897107829d6d8481aee96c22443f626d00f4145"
      score = 65
      id = "8f838e4f-3e3e-5131-9d67-e49f6848bb37"
    strings:
        $s1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 65 00 74 00 64 00 73 00 75 00 70 00 70 00 2e 00 73 00 79 00 73 00} 
        $s2 = "etdsupp.pdb"
        $s3 = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff]{2}[\x00-\x11]\x00[\x00-\xff]{4}|\x00\x00\x12\x00\x00\x00\x00\x00)/  
    condition:
        uint16(0) == 0x5a4d and int16(uint32(0x3C) + 0x5c) == 0x0001 and filesize < 100KB and all of them
}


rule SUSP_Imphash_PassRevealer_PY_EXE {
   meta:
      description = "Detects an imphash used by password revealer and hack tools (some false positives with hardware driver installers)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-04-06"
      modified = "2021-11-09"
      score = 40
      hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"
      id = "9462dfc4-2feb-591d-ac0c-ba02f093c216"
   strings:
      $fp1 = "Assmann Electronic GmbH" ascii wide
      $fp2 = "Oculus VR" ascii wide
      $fp3 = "efm8load" ascii  
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB
      and pe.imphash() == "ed61beebc8d019dd9bec823e2d694afd"
      and not 1 of ($fp*)
}



rule MAL_Unknown_PWDumper_Apr18_3 {
   meta:
      description = "Detects sample from unknown sample set - IL origin"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-04-06"
      hash1 = "d435e7b6f040a186efeadb87dd6d9a14e038921dc8b8658026a90ae94b4c8b05"
      hash2 = "8c35c71838f34f7f7a40bf06e1d2e14d58d9106e6d4e6f6e9af732511a126276"
      id = "2431d562-dcd8-5d21-8406-7d2567b6eca9"
   strings:
      $s1 = "loaderx86.dll" fullword ascii
      $s2 = "tcpsvcs.exe" fullword wide
      $s3 = "%Program Files, Common FOLDER%" fullword wide
      $s4 = "%AllUsers, ApplicationData FOLDER%" fullword wide
      $s5 = "loaderx86" fullword ascii
      $s6 = "TNtDllHook$" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}



rule SUSP_Katz_PDB {
   meta:
      description = "Detects suspicious PDB in file"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-02-04"
      hash1 = "6888ce8116c721e7b2fc3d7d594666784cf38a942808f35e309a48e536d8e305"
      id = "79f4f07c-b234-5203-a2ab-aba4a9cb9f8d"
   strings:
      $s1 = /\\Release\\[a-z]{0,8}katz.pdb/
      $s2 = /\\Debug\\[a-z]{0,8}katz.pdb/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}



rule SUSP_VULN_DRV_PROCEXP152_May23 {
   meta:
      description = "Detects vulnerable process explorer driver (original file name: PROCEXP152.SYS), often used by attackers to elevate privileges (false positives are possible in cases in which old versions of process explorer are still present on the system)"
      author = "Florian Roth"
      reference = "https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/"
      date = "2023-05-05"
		modified = "2023-07-28"
      score = 50
      hash1 = "cdfbe62ef515546f1728189260d0bdf77167063b6dbb77f1db6ed8b61145a2bc"
      id = "748eb390-f320-5045-bed2-24ae70471f43"
   strings:
      $a1 = "\\ProcExpDriver.pdb" ascii
      $a2 = "\\Device\\PROCEXP152" wide fullword
      $a3 = "procexp.Sys" wide fullword
   condition:
      uint16(0) == 0x5a4d 
      and filesize < 200KB 
      and all of them
}



rule MAL_Information_Collector_May26 {
   meta:
      description = "Detects reconaissance payload used in the DAEMON Tools supplychain compromise. The tools collects detailed information about the infected system like hardware, installed software, running processes etc. all data is exfilled to an attacker controlled server."
      author = "MalGamy, Jonathan Peters (cod3nym)"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "a916e56121212613d17932e124b68752c9312e73bde8f2351054bd64394257df"
      score = 80
      id = "97bfe7ef-ba23-550c-a6bf-412c759eec91"
   strings:
      $x1 = ": InfoCollector.exe <" wide

      $s1 = "CollectInstalledSoftwareSemicolon" ascii
      $s2 = "GetRc4KeyFromUrl" ascii
      $s3 = "InfoGatherer" ascii

      $op1 = { 09 7E ?? ?? ?? 04 28 ?? ?? ?? 0A 28 ?? ?? ?? 0A 13 ?? 11 ?? 16 36 3A 11 ?? 1E 35 ?? 1E 8D ?? ?? ?? 01 13 ?? 09 7E ?? ?? ?? 04 28 ?? ?? ?? 0A 11 ?? 16 11 ?? 28 ?? ?? ?? 0A }
      $op2 = { 02 73 ?? ?? ?? 0A 6F ?? ?? ?? 0A 0A 06 2D ?? 72 ?? ?? ?? 70 0B DE ?? 06 6F ?? ?? ?? 0A 0A 06 72 ?? ?? ?? 70 7E ?? ?? ?? 0A 6F ?? ?? ?? 0A 0A 06 6F ?? ?? ?? 0A 2D ?? 72 ?? ?? ?? 70 0B DE ?? 06 0B DE }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 50KB
      and (
         $x1
         or all of ($op*)
         or all of ($s*)
      )
}



rule MAL_DAEMON_Tools_Lite_Compromised_May26 {
   meta:
      description = "Detects compromised DAEMON Tools Lite versions deployed in a supplychain compromise campaign affected versions include: 12.5.0.2421 up to 12.5.0.2434 The infected binaries drop Quic RAT and various custom data exfiltration payloads."
      author = "Jonathan Peters (cod3nym)"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "12edcaafab7703d0819b1395f45c35e3083dd83fb8b128292cb11033453fb6e8"
      hash = "0066ed9b9de2b8e251f7bcf73edcb549218179398cf90124a221958fedce6212"
      hash = "d2a5c9cbb73849cc0667987c33a9bf3822718e1528faef005f1628de3348ffb0"
      score = 80
      id = "68b6838a-6075-576b-af90-77c244d4d7a0"
   strings:
      $sa1 = { 31 03 35 55 e4 c4 32 2d a9 e0 b3 81 6d 14 38 4e }  // certificate serial number
      $sa2 = "AVB Disc Soft, SIA" ascii
      $sa3 = "DAEMON Tools Lite" ascii wide

      $re = /12\.5\.0\.24(21|22|23|24|25|26|27|28|29|30|31|33|34)/ ascii wide
   condition:
      uint16(0) == 0x5a4d
      and all of ($sa*)
      and $re
}



rule MAL_Minimalistic_Backdoor_May26 {
   meta:
      description = "Detects minimalistic backdoor deployment where a shellcode loader downloads an encrypted payload and executes it in memory after RC4 decryption using a command-line provided key"
      author = "MalGamy"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "395ec7acd475a8acd358adc75c4615cf41737aed8a96c4f2dd792c8a6af4140c"
      score = 80
      id = "8292161d-8b20-51e0-987a-dd0f4c1cf3e8"
   strings:
      $x1 = "Note: if multiple processes load the DLL," wide
      $x2 = "Inject (shellcode file is RC4 ciphertext; key is a UTF-8 string" wide

      $s1 = "Error: VirtualAllocEx failed, Win" wide
      $s2 = "Try running as administrator; " wide
      $s3 = ", shellcode size: " wide
      $s4 = "input file path cannot be empty." wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 50KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
}


rule SUSP_LNX_Base64_Download_Exec_Apr24 : SCRIPT {
   meta:
      description = "Detects suspicious base64 encoded shell commands used for downloading and executing further stages"
      author = "Paul Hager"
      date = "2024-04-18"
      reference = "Internal Research"
      score = 75
      id = "df8dddef-3c49-500c-abc8-7f7de5aa69ae"
   strings:
      $sa1 = "curl http" base64
      $sa2 = "wget http" base64
      
      $sb1 = "chmod 777 " base64
      $sb2 = "/tmp/" base64
   condition:
      1 of ($sa*)
      and all of ($sb*)
}



rule SUSP_LNX_Base64_Exec_Apr24 : SCRIPT {
   meta:
      description = "Detects suspicious base64 encoded shell commands (as seen in Palo Alto CVE-2024-3400 exploitation)"
      author = "Christian Burkard"
      date = "2024-04-18"
      modified = "2025-03-21"
      reference = "Internal Research"
      score = 75
      id = "2da3d050-86b0-5903-97eb-c5f39ce4f3a3"
   strings:
      $s1 = "curl http://" base64
      $s2 = "wget http://" base64
      $s3 = ";chmod 777 " base64
      // $s4 = "/tmp/" base64 // prone to FPs
      
      $mirai = "country="

      $fp1 = "<html"
      $fp2 = "<?xml"
   condition:
      filesize < 800KB
      and 1 of ($s*) 
      and not $mirai
      and not 1 of ($fp*)
}


rule MAL_Driver_Microsoftcorporation_Windbgsys_Microsoftwindowsoperatingsystem_6994 {
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - windbg.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "6994b32e3f3357f4a1d0abe81e8b62dd54e36b17816f2f1a80018584200a1b77"
		hash = "5b932eab6c67f62f097a3249477ac46d80ddccdc52654f8674060b4ddf638e5d"
		hash = "ea50f22daade04d3ca06dedb497b905215cba31aae7b4cab4b533fda0c5be620"
		hash = "f936ec4c8164cbd31add659b61c16cb3a717eac90e74d89c47afb96b60120280"
		hash = "32882949ea084434a376451ff8364243a50485a3b4af2f2240bb5f20c164543d"
		hash = "6661320f779337b95bbbe1943ee64afb2101c92f92f3d1571c1bf4201c38c724"
		hash = "86047bb1969d1db455493955fd450d18c62a3f36294d0a6c3732c88dfbcc4f62"
		hash = "06c5ebd0371342d18bc81a96f5e5ce28de64101e3c2fd0161d0b54d8368d2f1f"
		hash = "4734a0a5d88f44a4939b8d812364cab6ca5f611b9b8ceebe27df6c1ed3a6d8a4"
		hash = "770f33259d6fb10f4a32d8a57d0d12953e8455c72bb7b60cb39ce505c507013a"
		hash = "50819a1add4c81c0d53203592d6803f022443440935ff8260ff3b6d5253c0c76"
		hash = "f9f2091fccb289bcf6a945f6b38676ec71dedb32f3674262928ccaf840ca131a"
		hash = "fa9abb3e7e06f857be191a1e049dd37642ec41fb2520c105df2227fcac3de5d5"
		hash = "139f8412a7c6fdc43dcfbbcdba256ee55654eb36a40f338249d5162a1f69b988"
		hash = "e1cb86386757b947b39086cc8639da988f6e8018ca9995dd669bdc03c8d39d7d"
		hash = "e6f764c3b5580cd1675cbf184938ad5a201a8c096607857869bd7c3399df0d12"
		hash = "bb2422e96ea993007f25c71d55b2eddfa1e940c89e895abb50dd07d7c17ca1df"
		date = "2024-08-07"
		score = 70
		id = "05060e37-3c01-5b86-a3ee-6e141399164a"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00570069006e0064006f007700730020004700550049002000730079006d0062006f006c00690063002000640065006200750067006700650072 } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e } 
		$ = { 00460069006c006500560065007200730069006f006e[1-8]00310030002e0030002e00310039003000340031002e0036003800350020002800570069006e004200750069006c0064002e003100360030003100300031002e00300038003000300029 } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]00310030002e0030002e00310039003000340031002e003600380035 } 
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00770069006e006400620067002e007300790073 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d006900630072006f0073006f00660074003f002000570069006e0064006f00770073003f0020004f007000650072006100740069006e0067002000530079007300740065006d } 
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00770069006e006400620067002e007300790073 } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]003f0020004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } 
	condition:
		all of them
}




rule MAL_Driver_Microsoftcorporation_Ntbiosys_Microsoftrwindowsrntoperatingsystem_C0D8 {
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - ntbios_2.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "c0d88db11d0f529754d290ed5f4c34b4dba8c4f2e5c4148866daabeab0d25f9c"
		hash = "96bf3ee7c6673b69c6aa173bb44e21fa636b1c2c73f4356a7599c121284a51cc"
		date = "2024-08-07"
		score = 70
		id = "f16b4b22-985a-5d39-ae51-709aa9a69d8d"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]006e007400620069006f00730020006400720069007600650072 } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e } 
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0035002c00200030002c00200032002c00200031 } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0035002c00200030002c00200032002c00200031 } 
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006e007400620069006f002e007300790073 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0020004d006900630072006f0073006f00660074002800520029002000570069006e0064006f0077007300200028005200290020004e00540020004f007000650072006100740069006e0067002000530079007300740065006d } 
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006e007400620069006f0073002e007300790073 } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]7248674362406709002000280043002900200032003000300033 } 
	condition:
		all of them
}




rule MAL_Driver_Microsoftcorporation_Wintapixsys_Microsoftwindowsoperatingsystem_8578 {
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - WinTapix.sys, SRVNET2.SYS"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "8578bff36e3b02cc71495b647db88c67c3c5ca710b5a2bd539148550595d0330"
		hash = "1485c0ed3e875cbdfc6786a5bd26d18ea9d31727deb8df290a1c00c780419a4e"
		date = "2024-08-07"
		score = 70
		id = "0bb182e8-e64b-5b01-9ca5-105212ebeb51"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00570069006e0064006f007700730020004b00650072006e0065006c00200045007800650063007500740069007600650020004d006f00640075006c0065 } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e } 
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002e0033002e0039003600300030002e003100360033003800340020002800770069006e0062006c00750065005f00720074006d002e003100330030003800320031002d00310036003200330029 } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002e0033002e0039003600300030002e00310036003300380034 } 
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00570069006e00540061007000690078002e007300790073 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d006900630072006f0073006f0066007400ae002000570069006e0064006f0077007300ae0020004f007000650072006100740069006e0067002000530079007300740065006d } 
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00570069006e00540061007000690078002e007300790073 } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a90020004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } 
	condition:
		all of them
}




rule MAL_Driver_Microsoftcorporation_Wantdsys_Microsoftwindowsoperatingsystem_E7AF {
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - wantd_6.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e"
		hash = "b9dad0131c51e2645e761b74a71ebad2bf175645fa9f42a4ab0e6921b83306e3"
		hash = "8d9a2363b757d3f127b9c6ed8f7b8b018e652369bc070aa3500b3a978feaa6ce"
		hash = "06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4"
		date = "2024-08-07"
		score = 70
		id = "5f883209-6887-5cb4-96bb-988898d47c09"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00570041004e0020005400720061006e00730070006f007200740020004400720069007600650072 } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e } 
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e0031003100370032 } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e0031003100370032 } 
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00770061006e00740064002e007300790073 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d006900630072006f0073006f00660074002000570069006e0064006f007700730020004f007000650072006100740069006e0067002000530079007300740065006d } 
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00770061006e00740064002e007300790073 } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } 
	condition:
		all of them
}




rule MAL_Driver_Microsoftcorporation_Wantdsys_Microsoftwindowsoperatingsystem_6908 {
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - wantd_2.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f"
		date = "2024-08-07"
		score = 70
		id = "3bd8b888-8170-5da6-ba1c-f13c1ca27e6f"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00570041004e0020005400720061006e00730070006f007200740020004400720069007600650072 } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e } 
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e003900330038 } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e003900330038 } 
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00770061006e00740064002e007300790073 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d006900630072006f0073006f00660074002000570069006e0064006f007700730020004f007000650072006100740069006e0067002000530079007300740065006d } 
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00770061006e00740064002e007300790073 } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } 
	condition:
		all of them
}




rule MAL_Driver_Microsoftcorporation_Srvnetsys_Microsoftwindowsoperatingsystem_F6C3 {
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - WinTapix.sys, SRVNET2.SYS"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "f6c316e2385f2694d47e936b0ac4bc9b55e279d530dd5e805f0d963cb47c3c0d"
		date = "2024-08-07"
		score = 70
		id = "3559718f-59d7-5bff-860c-6a073f4c05d9"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0053006500720076006500720020004e006500740077006f0072006b0020006400720069007600650072 } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e } 
		$ = { 00460069006c006500560065007200730069006f006e[1-8]00310030002e0030002e00310038003300360032002e0036003900330020002800570069006e004200750069006c0064002e003100360030003100300031002e00300038003000300029 } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]00310030002e0030002e00310038003300360032002e003600390033 } 
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]005300520056004e004500540032002e005300590053 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d006900630072006f0073006f0066007400ae002000570069006e0064006f0077007300ae0020004f007000650072006100740069006e0067002000530079007300740065006d } 
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]005300520056004e004500540032002e005300590053 } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a90020004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } 
	condition:
		all of them
}




rule MAL_Driver_Microsoftcorporation_Wantdsys_Microsoftwindowsoperatingsystem_81C7 {
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - wantd_3.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1"
		date = "2024-08-07"
		score = 70
		id = "43ae822a-c4c4-5525-bfd3-a05d1ec50bd0"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00570041004e0020005400720061006e00730070006f007200740020004400720069007600650072 } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e } 
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0035002e0032002e0033003700390030002e003900330038 } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0035002e0032002e0033003700390030002e003900330038 } 
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00770061006e00740064002e007300790073 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d006900630072006f0073006f00660074002000570069006e0064006f007700730020004f007000650072006100740069006e0067002000530079007300740065006d } 
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00770061006e00740064002e007300790073 } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } 
	condition:
		all of them
}




rule MAL_Driver_Microsoftcorporation_Ndislansys_Microsoftwindowsoperatingsystem_B0EB {
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - ndislan.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "b0eb4d999e4e0e7c2e33ff081e847c87b49940eb24a9e0794c6aa9516832c427"
		date = "2024-08-07"
		score = 70
		id = "c94adcf3-2ea6-5856-9327-2e5ed1c49b22"
	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004d00530020004c0041004e0020004400720069007600650072 } 
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e } 
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e0031003400320031 } 
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e0031003400320031 } 
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006e006400690073006c0061006e002e007300790073 } 
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d006900630072006f0073006f0066007400ae002000570069006e0064006f0077007300ae0020004f007000650072006100740069006e0067002000530079007300740065006d } 
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006e006400690073006c0061006e002e007300790073 } 
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a90020004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e } 
	condition:
		all of them
}
