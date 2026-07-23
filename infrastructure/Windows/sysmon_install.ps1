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

Write-Host "=== Installation de Sysmon (NyxSOC) ==="

# 1. Preparer le repertoire de travail
if (-not (Test-Path $SysmonDir)) {
    New-Item -ItemType Directory -Path $SysmonDir -Force | Out-Null
    Write-Host "-> Repertoire cree : $SysmonDir"
}

# 2. Verifier que le fichier de config est present (copie au prealable via scp)
if (-not (Test-Path "$SysmonDir\sysmonconfig-nyxsoc.xml")) {
    Write-Host "ERREUR : sysmonconfig-nyxsoc.xml absent de $SysmonDir"
    Write-Host "Copie-le d'abord avec : scp sysmonconfig-nyxsoc.xml <user>@10.0.1.30:'C:\NyxSOC\Sysmon\'"
    exit 1
}

# 3. Telecharger Sysmon si absent
# NOTE : download.sysinternals.com est generalement accessible directement
# (contrairement a nxlog.co), mais si le telechargement echoue ici aussi,
# telecharge Sysmon.zip manuellement depuis https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
# et pousse-le via scp dans C:\NyxSOC\Sysmon\Sysmon.zip avant de relancer.
if (-not (Test-Path $SysmonExe)) {
    if (Test-Path $ZipPath) {
        Write-Host "-> Sysmon.zip deja present localement, extraction directe."
    } else {
        Write-Host "-> Telechargement de Sysmon depuis Sysinternals..."
        try {
            Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath -UseBasicParsing
        } catch {
            Write-Host "ERREUR : le telechargement a echoue ($($_.Exception.Message))"
            Write-Host "Telecharge Sysmon.zip manuellement depuis https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
            Write-Host "puis pousse-le avec : scp Sysmon.zip <user>@10.0.1.30:'C:\NyxSOC\Sysmon\Sysmon.zip'"
            exit 1
        }
    }

    $zipSize = (Get-Item $ZipPath).Length
    if ($zipSize -lt 100KB) {
        Write-Host "ERREUR : Sysmon.zip fait seulement $zipSize octets, ce n'est probablement pas le vrai fichier."
        exit 1
    }

    Expand-Archive -Path $ZipPath -DestinationPath $SysmonDir -Force
    Remove-Item $ZipPath
    Write-Host "-> Sysmon extrait avec succes."
} else {
    Write-Host "-> Sysmon64.exe deja present, pas de re-telechargement."
}

# 4. Installer ou reconfigurer Sysmon
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonService) {
    Write-Host "-> Installation du service Sysmon avec la config NyxSOC..."
    & $SysmonExe -accepteula -i $ConfigFile
} else {
    Write-Host "-> Service Sysmon deja installe, mise a jour de la config..."
    & $SysmonExe -accepteula -c $ConfigFile
}

# 5. Verifications
Write-Host ""
Write-Host "=== Verifications ==="

$service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "OK - Service Sysmon64 actif"
} else {
    Write-Host "ECHEC - Service Sysmon64 non actif"
    exit 1
}

# Verifie qu'au moins un evenement Sysmon a ete journalise
$recentEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue
if ($recentEvents) {
    Write-Host "OK - Journal Sysmon accessible, evenements presents :"
    $recentEvents | Select-Object TimeCreated, Id, Message -First 3 | Format-Table -Wrap
} else {
    Write-Host "ATTENTION - Journal Sysmon vide ou inaccessible pour le moment (normal juste apres l'installation)"
}

Write-Host ""
Write-Host "=== Installation Sysmon terminee ==="
Write-Host "Event IDs actifs : 1 (ProcessCreate), 2 (FileCreateTime), 3 (NetworkConnect), 11 (FileCreate)"
