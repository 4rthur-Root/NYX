# simulate_employee.ps1 -- Scenario S3, etape 2-3 : Compromission de poste
# employe (NyxSOC)
#
# Simule l'employe (dir1) qui, apres avoir vu le fichier depose sur le
# partage commun, le copie sur son poste puis l'execute -- sans interaction
# humaine manuelle, conformement a Topologie.pdf 4.4.2.
#
# Declenche :
#   - Sysmon EventID 11 (file_create) lors de la copie locale
#   - Sysmon EventID 1 (process_exec) lors de l'execution
#
# Ces deux evenements + samba_write (deja journalise lors du depot cote
# Debian Server) forment la sequence a 3 etapes attendue par la regle
# MALICIOUS_FILE_EXEC_001 (Type 2, fenetre 4h, correlation par actor_user).
#
# Prerequis :
#   - Session PowerShell ouverte en tant que dir1 sur NYX-PME
#   - Partage \\10.0.1.20\commun accessible (credentials dir1 deja utilises
#     pour la session, ou fournis explicitement)
#   - ATTENTION : Windows Defender actif peut supprimer le fichier avant
#     execution. Etape 1 (EICAR) sert justement a valider ce point sans
#     risque avant de passer a un vrai payload.
#
# Usage :
#   .\simulate_employee.ps1 -ShareHost 10.0.1.20 -ShareName commun -FileName eicar_test.txt
#
# Exemple :
#   .\simulate_employee.ps1 -ShareHost 10.0.1.20 -ShareName commun -FileName eicar_test.txt -LocalDir "$env:USERPROFILE\Downloads"

param(
    [Parameter(Mandatory=$false)]
    [string]$ShareHost = "10.0.1.20",

    [Parameter(Mandatory=$false)]
    [string]$ShareName = "commun",

    [Parameter(Mandatory=$true)]
    [string]$FileName,

    [Parameter(Mandatory=$false)]
    [string]$LocalDir = "$env:USERPROFILE\Downloads",

    [Parameter(Mandatory=$false)]
    [switch]$Execute = $true,

    [Parameter(Mandatory=$false)]
    [string]$ShareUser = "",

    [Parameter(Mandatory=$false)]
    [string]$SharePassword = ""
)

$ErrorActionPreference = "Stop"

$SharePath = "\\$ShareHost\$ShareName\$FileName"
$ShareRoot = "\\$ShareHost\$ShareName"
$LocalPath = Join-Path $LocalDir $FileName

$RunId = "s3_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$LogDir = ".\logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$MetaFile = Join-Path $LogDir "$RunId.meta.json"

$tsStart = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

Write-Host "=================================================="
Write-Host " NyxSOC -- Scenario S3 : Compromission poste employe"
Write-Host "=================================================="
Write-Host " Partage source : $SharePath"
Write-Host " Destination    : $LocalPath"
Write-Host " Utilisateur    : $env:USERNAME"
Write-Host " Run ID         : $RunId"
Write-Host " Debut (UTC)    : $tsStart"
Write-Host "=================================================="

# --- Authentification SMB explicite (evite l'echec silencieux de la ---
# --- session locale Windows face au domaine NYX.TG) --------------------
if ($ShareUser -ne "") {
    Write-Host ""
    Write-Host "[0/2] Authentification explicite sur $ShareRoot en tant que $ShareUser ..."

    # Nettoyage prealable d'une eventuelle connexion existante (evite
    # l'erreur "multiple connections... not allowed" si une session
    # anonyme/differente est deja active vers ce partage).
    net use $ShareRoot /delete /y 2>&1 | Out-Null

    $netUseResult = net use $ShareRoot /user:$ShareUser $SharePassword 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Echec de l'authentification SMB : $netUseResult"
        Write-Host "    Verifie ShareUser (format NYX\user ou user@NYX.TG) et SharePassword."
        exit 1
    }
    Write-Host "[+] Authentifie avec succes sur $ShareRoot"
}

$tsCopyStart = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$copySucceeded = $false

Write-Host ""
Write-Host "[1/2] Copie du fichier depuis le partage vers $LocalDir ..."

try {
    Copy-Item -Path $SharePath -Destination $LocalPath -Force
    $copySucceeded = Test-Path $LocalPath
} catch {
    Write-Host "[!] Echec de la copie : $($_.Exception.Message)"
}

$tsCopyEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

if (-not $copySucceeded) {
    Write-Host "[!] Fichier absent apres copie -- probablement mis en quarantaine par Windows Defender."
    Write-Host "    Verifie : Get-MpThreatDetection"
    $tsEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    $failResult = [ordered]@{
        scenario            = "S3_MALICIOUS_FILE_EXEC"
        run_id              = $RunId
        actor_user          = $env:USERNAME
        share_path          = $SharePath
        local_path          = $LocalPath
        copy_succeeded      = $false
        execution_attempted = $false
        ts_start_utc        = $tsStart
        ts_copy_start       = $tsCopyStart
        ts_copy_end         = $tsCopyEnd
        ts_end_utc          = $tsEnd
        note                = "Copie echouee - probable blocage Defender. Verifier quarantaine."
        expected_rule       = "MALICIOUS_FILE_EXEC_001"
        mitre               = "T1204.002"
    }
    $failResult | ConvertTo-Json | Out-File -FilePath $MetaFile -Encoding utf8

    Write-Host "[!] Metadonnees (echec) ecrites dans $MetaFile"

    if ($ShareUser -ne "") {
        net use $ShareRoot /delete /y 2>&1 | Out-Null
    }
    exit 1
}

Write-Host "[+] Fichier copie avec succes : $LocalPath"

$executionAttempted = $false
$tsExecStart = $null
$tsExecEnd = $null

if ($Execute) {
    Write-Host ""
    Write-Host "[2/2] Execution du fichier (simulation double-clic employe)..."
    $tsExecStart = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $executionAttempted = $true

    try {
        if ($FileName -match '\.exe$') {
            Start-Process -FilePath $LocalPath
            Write-Host "[+] Processus lance : $LocalPath"
        } else {
            Write-Host "[i] Fichier non-executable ($FileName) -- etape d'execution simulee par lecture seule."
            Write-Host "    (Normal en phase de validation EICAR ; le vrai test process_exec"
            Write-Host "     interviendra avec le payload .exe.)"
            Get-Content -Path $LocalPath | Out-Null
        }
    } catch {
        Write-Host "[!] Echec de l'execution : $($_.Exception.Message)"
    }

    $tsExecEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

$tsEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

$result = [ordered]@{
    scenario            = "S3_MALICIOUS_FILE_EXEC"
    run_id              = $RunId
    actor_user          = $env:USERNAME
    share_path          = $SharePath
    local_path          = $LocalPath
    copy_succeeded      = $true
    execution_attempted = $executionAttempted
    ts_start_utc        = $tsStart
    ts_copy_start       = $tsCopyStart
    ts_copy_end         = $tsCopyEnd
    ts_exec_start       = $tsExecStart
    ts_exec_end         = $tsExecEnd
    ts_end_utc          = $tsEnd
    expected_rule       = "MALICIOUS_FILE_EXEC_001"
    mitre               = "T1204.002"
}
$result | ConvertTo-Json | Out-File -FilePath $MetaFile -Encoding utf8

Write-Host "=================================================="
Write-Host " Fin (UTC)   : $tsEnd"
Write-Host " Metadonnees : $MetaFile"
Write-Host "=================================================="
Write-Host "[+] Termine. Verifie les EventID 11 et 1 dans l'Observateur d'evenements."
Write-Host "    Chemin : Applications and Services Logs / Microsoft / Windows / Sysmon / Operational"

if ($ShareUser -ne "") {
    net use $ShareRoot /delete /y 2>&1 | Out-Null
    Write-Host "[+] Connexion SMB explicite fermee."
}
