# ============================================================
# nxlog_install.ps1 - Installation et configuration de NXLog CE
# NyxSOC - Windows 10 (NYX-PME)
# Usage : a executer en tant qu'Administrateur, via SSH
#   powershell -ExecutionPolicy Bypass -File nxlog_install.ps1
#
# PREREQUIS : le fichier nxlog-ce.msi doit deja etre present dans
# C:\NyxSOC\NXLog\ (le site nxlog.co ne fournit pas de lien de
# telechargement direct stable - telecharger manuellement depuis
# https://nxlog.co/products/nxlog-community-edition/download puis
# le pousser via scp) :
#   scp nxlog-ce-3.2.2329.msi user@10.0.1.30:'C:\NyxSOC\NXLog\nxlog-ce.msi'
# ============================================================

$ErrorActionPreference = "Stop"

$NxlogDir     = "C:\Program Files\nxlog"
$ConfigTarget = "$NxlogDir\conf\nxlog.conf"
$WorkDir      = "C:\NyxSOC\NXLog"
$MsiPath      = "$WorkDir\nxlog-ce.msi"

Write-Host "=== Installation de NXLog CE (NyxSOC) ==="

# 1. Verifier que le MSI est present et de taille raisonnable
if (-not (Test-Path $MsiPath)) {
    Write-Host "ERREUR : $MsiPath introuvable."
    Write-Host "Telecharge le MSI depuis https://nxlog.co/products/nxlog-community-edition/download"
    Write-Host "puis pousse-le avec : scp nxlog-ce-3.2.2329.msi <user>@10.0.1.30:'C:\NyxSOC\NXLog\nxlog-ce.msi'"
    exit 1
}

$msiSize = (Get-Item $MsiPath).Length
if ($msiSize -lt 1MB) {
    Write-Host "ERREUR : le fichier MSI fait seulement $($msiSize) octets - ce n'est probablement pas le vrai installeur."
    Write-Host "Verifie le telechargement (le site nxlog.co peut avoir servi une page d'erreur au lieu du .msi)."
    exit 1
}
Write-Host "-> MSI present, taille : $([math]::Round($msiSize/1MB, 1)) MB"

# 2. Verifier que la config est deja copiee (via scp au prealable)
if (-not (Test-Path "$WorkDir\nxlog.conf")) {
    Write-Host "ERREUR : nxlog.conf absent de $WorkDir"
    Write-Host "Copie-le d'abord avec : scp nxlog.conf <user>@10.0.1.30:'C:\NyxSOC\NXLog\'"
    exit 1
}

# 3. Installer NXLog si absent
if (-not (Test-Path $NxlogDir)) {
    Write-Host "-> Installation silencieuse de NXLog CE..."
    $proc = Start-Process msiexec.exe -ArgumentList "/i `"$MsiPath`" /quiet /norestart /l*v `"$WorkDir\install.log`"" -Wait -PassThru
    Start-Sleep -Seconds 5

    if ($proc.ExitCode -ne 0) {
        Write-Host "ERREUR : msiexec a echoue avec le code $($proc.ExitCode)"
        Write-Host "Voir le log detaille : Get-Content '$WorkDir\install.log' -Tail 40"
        exit 1
    }

    if (-not (Test-Path $NxlogDir)) {
        Write-Host "ERREUR : msiexec a rendu le code 0 mais $NxlogDir n'existe toujours pas."
        Write-Host "Voir le log detaille : Get-Content '$WorkDir\install.log' -Tail 40"
        exit 1
    }

    Write-Host "-> NXLog installe avec succes dans $NxlogDir"
} else {
    Write-Host "-> NXLog deja installe, mise a jour de la config uniquement."
}

# 4. Deployer la configuration
Write-Host "-> Deploiement de nxlog.conf..."
if (-not (Test-Path "$NxlogDir\conf")) {
    Write-Host "ERREUR : $NxlogDir\conf n'existe pas - l'installation semble incomplete."
    exit 1
}
Copy-Item -Path "$WorkDir\nxlog.conf" -Destination $ConfigTarget -Force

# 5. Demarrer/redemarrer le service
$service = Get-Service -Name "nxlog" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "-> Redemarrage du service nxlog..."
    Restart-Service nxlog
    Set-Service -Name nxlog -StartupType Automatic
} else {
    Write-Host "ERREUR : service nxlog introuvable apres installation."
    exit 1
}

Start-Sleep -Seconds 3

# 6. Verifications
Write-Host ""
Write-Host "=== Verifications ==="

$service = Get-Service -Name "nxlog"
if ($service.Status -eq "Running") {
    Write-Host "OK - Service nxlog actif"
} else {
    Write-Host "ECHEC - Service nxlog non actif (status: $($service.Status))"
    Write-Host "-> Verifier les logs : Get-Content '$NxlogDir\data\nxlog.log' -Tail 30"
    exit 1
}

Write-Host ""
Write-Host "-> Dernieres lignes du log nxlog :"
Get-Content "$NxlogDir\data\nxlog.log" -Tail 10 -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Installation NXLog terminee ==="
Write-Host "Verifie cote SOC : sudo tail -f /var/log/remote/NYX-PME.log"
