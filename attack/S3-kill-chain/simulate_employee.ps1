# simulate_employee.ps1 — Scénario S3, étape 2-3 : Compromission de poste
# employé (NyxSOC)
#
# Simule l'employé (dir1) qui, après avoir vu le fichier déposé sur le
# partage commun, le copie sur son poste puis l'exécute — sans interaction
# humaine manuelle, conformément à Topologie.pdf §4.4.2.
#
# Déclenche :
#   - Sysmon EventID 11 (file_create) lors de la copie locale
#   - Sysmon EventID 1 (process_exec) lors de l'exécution
#
# Ces deux événements + samba_write (déjà journalisé lors du dépôt côté
# Debian Server) forment la séquence à 3 étapes attendue par la règle
# MALICIOUS_FILE_EXEC_001 (Type 2, fenêtre 4h, corrélation par actor_user).
#
# Prérequis :
#   - Session PowerShell ouverte en tant que dir1 sur NYX-PME
#   - Partage \\10.0.1.20\commun accessible (credentials dir1 déjà utilisés
#     pour la session, ou fournis explicitement)
#   - ATTENTION : Windows Defender actif peut supprimer le fichier avant
#     exécution. Étape 1 (EICAR) sert justement à valider ce point sans
#     risque avant de passer à un vrai payload.
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
    [switch]$Execute = $true
)

$ErrorActionPreference = "Stop"

$SharePath = "\\$ShareHost\$ShareName\$FileName"
$LocalPath = Join-Path $LocalDir $FileName

$RunId = "s3_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$LogDir = ".\logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$MetaFile = Join-Path $LogDir "$RunId.meta.json"

$tsStart = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

Write-Host "=================================================="
Write-Host " NyxSOC — Scénario S3 : Compromission poste employé"
Write-Host "=================================================="
Write-Host " Partage source : $SharePath"
Write-Host " Destination    : $LocalPath"
Write-Host " Utilisateur    : $env:USERNAME"
Write-Host " Run ID         : $RunId"
Write-Host " Début (UTC)    : $tsStart"
Write-Host "=================================================="

# --- Étape 2 : copie du fichier (déclenche Sysmon EventID 11 - file_create) ---
Write-Host ""
Write-Host "[1/2] Copie du fichier depuis le partage vers $LocalDir ..."

$tsCopyStart = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$copySucceeded = $false

try {
    Copy-Item -Path $SharePath -Destination $LocalPath -Force
    $copySucceeded = Test-Path $LocalPath
} catch {
    Write-Host "[!] Échec de la copie : $($_.Exception.Message)"
}

$tsCopyEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

if (-not $copySucceeded) {
    Write-Host "[!] Fichier absent après copie — probablement mis en quarantaine par Windows Defender."
    Write-Host "    Vérifie : Get-MpThreatDetection"
    $tsEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    @{
        scenario         = "S3_MALICIOUS_FILE_EXEC"
        run_id           = $RunId
        actor_user       = $env:USERNAME
        share_path       = $SharePath
        local_path       = $LocalPath
        copy_succeeded   = $false
        execution_attempted = $false
        ts_start_utc     = $tsStart
        ts_copy_start    = $tsCopyStart
        ts_copy_end      = $tsCopyEnd
        ts_end_utc       = $tsEnd
        note             = "Copie échouée - probable blocage Defender. Vérifier quarantaine."
        expected_rule    = "MALICIOUS_FILE_EXEC_001"
        mitre            = "T1204.002"
    } | ConvertTo-Json | Out-File -FilePath $MetaFile -Encoding utf8

    Write-Host "[!] Métadonnées (échec) écrites dans $MetaFile"
    exit 1
}

Write-Host "[+] Fichier copié avec succès : $LocalPath"

# --- Étape 3 : exécution (déclenche Sysmon EventID 1 - process_exec) ---
$executionAttempted = $false
$tsExecStart = $null
$tsExecEnd = $null

if ($Execute) {
    Write-Host ""
    Write-Host "[2/2] Exécution du fichier (simulation double-clic employé)..."
    $tsExecStart = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $executionAttempted = $true

    try {
        # Pour un .txt (EICAR) : pas d'exécution binaire réelle possible.
        # Pour un .exe (Meterpreter, phase suivante) : Start-Process direct.
        if ($FileName -match '\.exe$') {
            Start-Process -FilePath $LocalPath
            Write-Host "[+] Processus lancé : $LocalPath"
        } else {
            Write-Host "[i] Fichier non-exécutable ($FileName) — étape d'exécution simulée par lecture seule."
            Write-Host "    (Normal en phase de validation EICAR ; le vrai test process_exec"
            Write-Host "     interviendra avec le payload .exe.)"
            Get-Content -Path $LocalPath | Out-Null
        }
    } catch {
        Write-Host "[!] Échec de l'exécution : $($_.Exception.Message)"
    }

    $tsExecEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

$tsEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

@{
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
} | ConvertTo-Json | Out-File -FilePath $MetaFile -Encoding utf8

Write-Host "=================================================="
Write-Host " Fin (UTC)   : $tsEnd"
Write-Host " Métadonnées : $MetaFile"
Write-Host "=================================================="
Write-Host "[+] Terminé. Vérifie les EventID 11 et 1 dans l'Observateur d'événements > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational."
