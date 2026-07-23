# ============================================================
# sysmon_install.ps1 - Installation et configuration de Sysmon
# NyxSOC - Windows 10 (NYX-PME)
# Usage : à exécuter en tant qu'Administrateur, via SSH
#   powershell -ExecutionPolicy Bypass -File sysmon_install.ps1
# ============================================================

$ErrorActionPreference = "Stop"

$SysmonDir  = "C:\NyxSOC\Sysmon"
$SysmonExe  = "$SysmonDir\Sysmon64.exe"
$ConfigFile = "$SysmonDir\sysmonconfig-nyxsoc.xml"
$ZipUrl     = "https://download.sysinternals.com/files/Sysmon.zip"
$ZipPath    = "$SysmonDir\Sysmon.zip"

Write-Host "=== Installation de Sysmon (NyxSOC) ===" -ForegroundColor Cyan

# 1. Préparer le répertoire de travail
if (-not (Test-Path $SysmonDir)) {
    New-Item -ItemType Directory -Path $SysmonDir -Force | Out-Null
    Write-Host "→ Répertoire créé : $SysmonDir"
}

# 2. Vérifier que le fichier de config est présent (copié au préalable via scp)
if (-not (Test-Path "$SysmonDir\sysmonconfig-nyxsoc.xml")) {
    Write-Host "ERREUR : sysmonconfig-nyxsoc.xml absent de $SysmonDir" -ForegroundColor Red
    Write-Host "Copie-le d'abord avec : scp sysmonconfig-nyxsoc.xml <user>@10.0.1.30:'C:\NyxSOC\Sysmon\'"
    exit 1
}

# 3. Télécharger Sysmon si absent
if (-not (Test-Path $SysmonExe)) {
    Write-Host "→ Téléchargement de Sysmon depuis Sysinternals..."
    Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath -UseBasicParsing
    Expand-Archive -Path $ZipPath -DestinationPath $SysmonDir -Force
    Remove-Item $ZipPath
    Write-Host "→ Sysmon téléchargé et extrait."
} else {
    Write-Host "→ Sysmon64.exe déjà présent, pas de re-téléchargement."
}

# 4. Installer ou reconfigurer Sysmon
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonService) {
    Write-Host "→ Installation du service Sysmon avec la config NyxSOC..."
    & $SysmonExe -accepteula -i $ConfigFile
} else {
    Write-Host "→ Service Sysmon déjà installé, mise à jour de la config..."
    & $SysmonExe -accepteula -c $ConfigFile
}

# 5. Vérifications
Write-Host ""
Write-Host "=== Vérifications ===" -ForegroundColor Cyan

$service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "✅ Service Sysmon64 actif" -ForegroundColor Green
} else {
    Write-Host "❌ Service Sysmon64 non actif" -ForegroundColor Red
    exit 1
}

# Vérifie qu'au moins un événement Sysmon a été journalisé
$recentEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue
if ($recentEvents) {
    Write-Host "✅ Journal Sysmon accessible, événements présents :" -ForegroundColor Green
    $recentEvents | Select-Object TimeCreated, Id, Message -First 3 | Format-Table -Wrap
} else {
    Write-Host "⚠️  Journal Sysmon vide ou inaccessible pour le moment (normal juste après l'installation)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Installation Sysmon terminée ===" -ForegroundColor Cyan
Write-Host "Event IDs actifs : 1 (ProcessCreate), 2 (FileCreateTime), 3 (NetworkConnect), 11 (FileCreate)"
