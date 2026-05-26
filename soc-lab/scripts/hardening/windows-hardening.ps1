# =============================================================================
# windows-hardening.ps1
# Automação de hardening CIS Benchmark + DISA STIG — Windows Server 2022
# Uso: PowerShell como Administrador
#   .\windows-hardening.ps1           (aplica hardening)
#   .\windows-hardening.ps1 -DryRun   (simula sem aplicar)
# =============================================================================

param(
    [switch]$DryRun
)

#region ── Setup ────────────────────────────────────────────────────────────────

$ErrorActionPreference = "SilentlyContinue"
$LogFile = "C:\Windows\Logs\cis-hardening-$(Get-Date -Format 'yyyy-MM-dd_HHmm').log"
New-Item -Path "C:\Windows\Logs" -ItemType Directory -Force | Out-Null

$PassCount = 0
$FailCount = 0
$SkipCount = 0

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $line = "[$timestamp][$Level] $Message"
    Add-Content -Path $LogFile -Value $line
    switch ($Level) {
        "PASS" { Write-Host "[PASS] $Message" -ForegroundColor Green }
        "FAIL" { Write-Host "[FAIL] $Message" -ForegroundColor Red }
        "INFO" { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
        "WARN" { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
    }
}

function Invoke-Control {
    param([string]$Description, [scriptblock]$Action)
    if ($DryRun) {
        Write-Log "[DRY-RUN] $Description" "WARN"
        $script:SkipCount++
        return
    }
    try {
        & $Action
        Write-Log $Description "PASS"
        $script:PassCount++
    } catch {
        Write-Log "$Description — ERRO: $_" "FAIL"
        $script:FailCount++
    }
}

# Verificar se está rodando como Administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Execute como Administrador: PowerShell (Admin) > .\windows-hardening.ps1" -ForegroundColor Red
    exit 1
}

Write-Log "============================================================"
Write-Log " CIS Windows Server 2022 Hardening — $(Get-Date)"
Write-Log " Modo: $(if ($DryRun) { 'DRY-RUN' } else { 'LIVE' })"
Write-Log "============================================================"

#endregion

#region ── 1. ATUALIZAÇÕES ──────────────────────────────────────────────────────

Write-Log "=== 1. Atualizações do Sistema ===" "INFO"

Invoke-Control "Configurar Windows Update automático" {
    $wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    New-Item -Path $wuKey -Force | Out-Null
    Set-ItemProperty -Path $wuKey -Name "NoAutoUpdate"          -Value 0
    Set-ItemProperty -Path $wuKey -Name "AUOptions"             -Value 4  # Auto download and install
    Set-ItemProperty -Path $wuKey -Name "AutoInstallMinorUpdates" -Value 1
    Set-ItemProperty -Path $wuKey -Name "ScheduledInstallDay"   -Value 0  # Every day
    Set-ItemProperty -Path $wuKey -Name "ScheduledInstallTime"  -Value 3  # 3 AM
}

#endregion

#region ── 2. CONTAS DE USUÁRIO ─────────────────────────────────────────────────

Write-Log "=== 2. Contas de Usuário ===" "INFO"

Invoke-Control "Renomear conta Administrator para nome não padrão" {
    Rename-LocalUser -Name "Administrator" -NewName "LabAdmin"
}

Invoke-Control "Desabilitar conta Guest" {
    Disable-LocalUser -Name "Guest"
}

Invoke-Control "Definir descrição falsa na conta LabAdmin (decoy)" {
    Set-LocalUser -Name "LabAdmin" -Description "Managed Service Account"
}

#endregion

#region ── 3. POLÍTICA DE SENHAS ────────────────────────────────────────────────

Write-Log "=== 3. Política de Senhas ===" "INFO"

Invoke-Control "Aplicar política de senhas via secedit (CIS)" {
    $infContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
    $infPath = "C:\Windows\Temp\cis-password-policy.inf"
    $infContent | Out-File -FilePath $infPath -Encoding Unicode
    secedit /configure /db "C:\Windows\Temp\cis-hardening.sdb" `
            /cfg $infPath /quiet
    Remove-Item $infPath -Force
}

#endregion

#region ── 4. AUDITORIA ─────────────────────────────────────────────────────────

Write-Log "=== 4. Auditoria Avançada ===" "INFO"

$auditPolicies = @{
    # Logon
    "Logon"                        = @("enable", "enable")
    "Logoff"                       = @("enable", "disable")
    "Account Lockout"              = @("disable", "enable")
    "Special Logon"                = @("enable", "disable")
    # Account Management
    "User Account Management"      = @("enable", "enable")
    "Computer Account Management"  = @("enable", "enable")
    "Security Group Management"    = @("enable", "enable")
    # Privilege Use
    "Sensitive Privilege Use"      = @("enable", "enable")
    # Process Tracking
    "Process Creation"             = @("enable", "disable")
    "Process Termination"          = @("enable", "disable")
    # Policy Change
    "Audit Policy Change"          = @("enable", "enable")
    "Authentication Policy Change" = @("enable", "disable")
    # System
    "Security System Extension"    = @("enable", "enable")
    "System Integrity"             = @("enable", "enable")
    # Object Access
    "File System"                  = @("disable", "enable")
    "Registry"                     = @("disable", "enable")
    # DS Access
    "Directory Service Access"     = @("disable", "enable")
    "Directory Service Changes"    = @("enable", "disable")
}

foreach ($policy in $auditPolicies.GetEnumerator()) {
    Invoke-Control "Auditoria: $($policy.Key)" {
        $success = $policy.Value[0]
        $failure = $policy.Value[1]
        auditpol /set /subcategory:"$($policy.Key)" `
            /success:$success /failure:$failure | Out-Null
    }
}

Invoke-Control "Habilitar log de linha de comando em Process Creation" {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath `
        -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
}

Invoke-Control "Aumentar tamanho dos logs de eventos para 1 GB" {
    foreach ($log in @("Security", "Application", "System")) {
        wevtutil sl $log /ms:1073741824
    }
}

#endregion

#region ── 5. WINDOWS DEFENDER ──────────────────────────────────────────────────

Write-Log "=== 5. Windows Defender ===" "INFO"

Invoke-Control "Habilitar proteção em tempo real" {
    Set-MpPreference -DisableRealtimeMonitoring $false
}

Invoke-Control "Habilitar monitoramento de comportamento" {
    Set-MpPreference -DisableBehaviorMonitoring $false
}

Invoke-Control "Habilitar proteção de rede" {
    Set-MpPreference -EnableNetworkProtection Enabled
}

Invoke-Control "Habilitar proteção contra PUA (Potentially Unwanted Apps)" {
    Set-MpPreference -PUAProtection Enabled
}

Invoke-Control "Habilitar Controlled Folder Access" {
    Set-MpPreference -EnableControlledFolderAccess Enabled
}

Invoke-Control "Habilitar varredura de scripts" {
    Set-MpPreference -DisableScriptScanning $false
}

Invoke-Control "Atualizar assinaturas do Defender" {
    Update-MpSignature
}

#endregion

#region ── 6. FIREWALL ──────────────────────────────────────────────────────────

Write-Log "=== 6. Windows Firewall ===" "INFO"

Invoke-Control "Habilitar firewall em todos os perfis com default deny inbound" {
    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogAllowed True `
        -LogBlocked True `
        -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" `
        -LogMaxSizeKilobytes 16384
}

Invoke-Control "Permitir RDP apenas da rede do lab (192.168.100.0/24)" {
    # Remover regras RDP existentes abertas para qualquer origem
    Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Remove-NetFirewallRule

    New-NetFirewallRule `
        -DisplayName "RDP - LabNetwork Only" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 3389 `
        -RemoteAddress "192.168.100.0/24" `
        -Action Allow `
        -Profile Any
}

Invoke-Control "Permitir Wazuh Agent comunicação com SIEM" {
    New-NetFirewallRule `
        -DisplayName "Wazuh Agent - Outbound" `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort 1514,1515,55000 `
        -RemoteAddress "192.168.100.10" `
        -Action Allow `
        -Profile Any
}

#endregion

#region ── 7. SERVIÇOS ──────────────────────────────────────────────────────────

Write-Log "=== 7. Serviços Desnecessários ===" "INFO"

$servicesToDisable = @(
    @{ Name = "Telnet";           Desc = "Protocolo inseguro" },
    @{ Name = "RemoteRegistry";   Desc = "CIS: desabilitar" },
    @{ Name = "Fax";              Desc = "Não utilizado" },
    @{ Name = "XblAuthManager";   Desc = "Xbox — não utilizado" },
    @{ Name = "XblGameSave";      Desc = "Xbox — não utilizado" },
    @{ Name = "XboxNetApiSvc";    Desc = "Xbox — não utilizado" },
    @{ Name = "WSearch";          Desc = "Windows Search — não necessário em server" },
    @{ Name = "SCardSvr";         Desc = "Smart Card — não utilizado" }
)

foreach ($svc in $servicesToDisable) {
    Invoke-Control "Desabilitar serviço: $($svc.Name) ($($svc.Desc))" {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc.Name -Force
            Set-Service  -Name $svc.Name -StartupType Disabled
        }
    }
}

Invoke-Control "Desabilitar SMBv1 (previne EternalBlue / WannaCry)" {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
}

Invoke-Control "Habilitar SMB Signing (previne relay attacks)" {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
}

#endregion

#region ── 8. CONFIGURAÇÕES DE SISTEMA ──────────────────────────────────────────

Write-Log "=== 8. Configurações de Sistema ===" "INFO"

Invoke-Control "Configurar UAC no nível máximo (Secure Desktop)" {
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $uacPath -Name "EnableLUA"                     -Value 1
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin"    -Value 2
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser"     -Value 0
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop"         -Value 1
}

Invoke-Control "Proteger LSASS (previne Mimikatz / credential dumping)" {
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $lsaPath -Name "RunAsPPL"              -Value 1
    Set-ItemProperty -Path $lsaPath -Name "DisableRestrictedAdmin" -Value 0
    Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel"  -Value 5  # NTLMv2 only
    Set-ItemProperty -Path $lsaPath -Name "NoLMHash"              -Value 1
}

Invoke-Control "Desabilitar AutoPlay e AutoRun" {
    $explorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    New-Item -Path $explorerPath -Force | Out-Null
    Set-ItemProperty -Path $explorerPath -Name "NoDriveTypeAutoRun" -Value 255
    Set-ItemProperty -Path $explorerPath -Name "NoAutorun"          -Value 1
}

Invoke-Control "Configurar NTP para servidor confiável" {
    w32tm /config /manualpeerlist:"pool.ntp.br" /syncfromflags:manual /reliable:YES /update | Out-Null
    Restart-Service w32tm
}

Invoke-Control "Desabilitar WDigest (previne senha em texto claro na memória)" {
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    New-Item -Path $wdigestPath -Force | Out-Null
    Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0
}

Invoke-Control "Habilitar proteção contra Pass-the-Hash (RestrictedAdmin)" {
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $lsaPath -Name "DisableRestrictedAdmin" -Value 0
}

#endregion

#region ── 9. POWERSHELL LOGGING ────────────────────────────────────────────────

Write-Log "=== 9. PowerShell Logging ===" "INFO"

Invoke-Control "Habilitar Script Block Logging" {
    $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $psPath -Force | Out-Null
    Set-ItemProperty -Path $psPath -Name "EnableScriptBlockLogging"         -Value 1
    Set-ItemProperty -Path $psPath -Name "EnableScriptBlockInvocationLogging" -Value 1
}

Invoke-Control "Habilitar Module Logging" {
    $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    New-Item -Path $psPath -Force | Out-Null
    Set-ItemProperty -Path $psPath -Name "EnableModuleLogging" -Value 1

    $modulePath = "$psPath\ModuleNames"
    New-Item -Path $modulePath -Force | Out-Null
    Set-ItemProperty -Path $modulePath -Name "*" -Value "*"
}

Invoke-Control "Habilitar PowerShell Transcription" {
    $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $outputDir = "C:\Windows\Logs\PowerShell"
    New-Item -Path $psPath     -Force | Out-Null
    New-Item -Path $outputDir  -ItemType Directory -Force | Out-Null
    Set-ItemProperty -Path $psPath -Name "EnableTranscripting"    -Value 1
    Set-ItemProperty -Path $psPath -Name "EnableInvocationHeader" -Value 1
    Set-ItemProperty -Path $psPath -Name "OutputDirectory"        -Value $outputDir
}

Invoke-Control "Definir PowerShell execution policy como RemoteSigned" {
    Set-ExecutionPolicy RemoteSigned -Force -Scope LocalMachine
}

#endregion

#region ── 10. RELATÓRIO FINAL ──────────────────────────────────────────────────

Write-Log "============================================================" "INFO"
Write-Log " RELATÓRIO DE HARDENING — $(Get-Date)" "INFO"
Write-Log "============================================================" "INFO"
Write-Log " PASS: $PassCount" "INFO"
Write-Log " FAIL: $FailCount" "INFO"
Write-Log " SKIP: $SkipCount" "INFO"
Write-Log " Log completo: $LogFile" "INFO"
Write-Log "============================================================" "INFO"

Write-Host ""
Write-Host "=== VERIFICAÇÃO PÓS-HARDENING ===" -ForegroundColor Cyan

Write-Host "`n[1] Contas locais:"
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize

Write-Host "[2] SMBv1:"
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | Format-Table -AutoSize

Write-Host "[3] Windows Defender:"
Get-MpComputerStatus | Select-Object `
    AntivirusEnabled, RealTimeProtectionEnabled, `
    NISEnabled, IoavProtectionEnabled | Format-List

Write-Host "[4] Firewall:"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | Format-Table -AutoSize

Write-Host "[5] LSASS RunAsPPL:"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL |
    Select-Object RunAsPPL | Format-Table -AutoSize

Write-Host "[6] WDigest (deve ser 0):"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name UseLogonCredential | Select-Object UseLogonCredential | Format-Table -AutoSize

Write-Host "[7] PowerShell Script Block Logging:"
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name EnableScriptBlockLogging | Select-Object EnableScriptBlockLogging | Format-Table -AutoSize

if ($FailCount -gt 0) {
    Write-Host "`nExistem $FailCount falhas. Revisar log: $LogFile" -ForegroundColor Red
    exit 1
}

Write-Host "`n✅ Hardening concluído com sucesso." -ForegroundColor Green

#endregion
