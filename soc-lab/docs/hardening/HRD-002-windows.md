# HRD-002 — Hardening Windows Server 2022 (CIS + STIG)

**Framework:** CIS Microsoft Windows Server 2022 Benchmark v1.0 + DISA STIG  
**Ambiente:** VM Windows Server 2022 no lab  
**Ferramenta:** PowerShell (Administrador) + GPO  

---

## Pré-requisitos

```powershell
# Executar como Administrador
# Verificar versão do OS
Get-ComputerInfo | Select-Object OsName, OsVersion, WindowsVersion

# Criar snapshot ANTES do hardening no VMware/VirtualBox

# Habilitar execução de scripts
Set-ExecutionPolicy RemoteSigned -Force
```

---

## 1. ATUALIZAÇÕES DO WINDOWS

```powershell
# 1.1 - Verificar e instalar atualizações pendentes
Install-Module PSWindowsUpdate -Force -Confirm:$false
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot

# 1.2 - Configurar Windows Update automático
$wuSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
$wuSettings.NotificationLevel = 4  # Auto download and install
$wuSettings.Save()
Write-Host "✅ Windows Update configurado"
```

---

## 2. CONTA ADMINISTRATOR LOCAL

```powershell
# 2.1 - Renomear conta Administrator (CIS 2.2.1)
Rename-LocalUser -Name "Administrator" -NewName "LabAdmin"

# 2.2 - Desabilitar conta Guest
Disable-LocalUser -Name "Guest"
Get-LocalUser | Select-Object Name, Enabled, LastLogon

# 2.3 - Configurar senha forte para LabAdmin
$secPwd = ConvertTo-SecureString "S3cur3P@ssw0rd!Lab" -AsPlainText -Force
Set-LocalUser -Name "LabAdmin" -Password $secPwd
```

---

## 3. POLÍTICA DE SENHAS E CONTA (GPO LOCAL)

```powershell
# Configurar via secedit (equivalente a GPO local)
$seceditTemplate = @"
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
signature="$CHICAGO$"
Revision=1
"@

$seceditTemplate | Out-File -FilePath "C:\Windows\Temp\password-policy.inf" -Encoding Unicode
secedit /configure /db "C:\Windows\Temp\hardening.sdb" `
  /cfg "C:\Windows\Temp\password-policy.inf" /quiet

Write-Host "✅ Política de senhas aplicada"
```

---

## 4. AUDITORIA (EVENT LOGS)

```powershell
# 4.1 - Configurar políticas de auditoria avançadas (CIS)
$auditPolicies = @{
  # Logon/Logoff
  "Logon"                     = "Success,Failure"
  "Logoff"                    = "Success"
  "Account Lockout"           = "Failure"
  # Account Management
  "User Account Management"   = "Success,Failure"
  "Computer Account Management" = "Success,Failure"
  "Security Group Management" = "Success,Failure"
  # Privilege Use
  "Sensitive Privilege Use"   = "Success,Failure"
  # Process Tracking
  "Process Creation"          = "Success"
  # Policy Change
  "Audit Policy Change"       = "Success,Failure"
  "Authentication Policy Change" = "Success"
  # System
  "Security System Extension" = "Success,Failure"
  "System Integrity"          = "Success,Failure"
}

foreach ($policy in $auditPolicies.GetEnumerator()) {
  $args = "/set /subcategory:`"$($policy.Key)`""
  $args += if ($policy.Value -match "Success") { " /success:enable" } else { " /success:disable" }
  $args += if ($policy.Value -match "Failure") { " /failure:enable" } else { " /failure:disable" }
  Start-Process auditpol -ArgumentList $args -NoNewWindow -Wait
  Write-Host "Auditoria configurada: $($policy.Key)"
}

# 4.2 - Aumentar tamanho dos logs de eventos
$eventLogs = @("Security", "Application", "System")
foreach ($log in $eventLogs) {
  wevtutil sl $log /ms:1073741824  # 1 GB
  Write-Host "Log aumentado: $log"
}

# 4.3 - Habilitar log de linha de comando em Process Creation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

Write-Host "✅ Auditoria configurada"
```

---

## 5. WINDOWS DEFENDER E ANTIVIRUS

```powershell
# 5.1 - Verificar status do Windows Defender
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, `
  BehaviorMonitorEnabled, IoavProtectionEnabled

# 5.2 - Configurar proteção em tempo real
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -PUAProtection Enabled

# 5.3 - Atualizar assinaturas
Update-MpSignature
Write-Host "✅ Windows Defender configurado"
```

---

## 6. WINDOWS FIREWALL

```powershell
# 6.1 - Garantir firewall ativo em todos os perfis
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block
Set-NetFirewallProfile -DefaultOutboundAction Allow
Set-NetFirewallProfile -LogAllowed True
Set-NetFirewallProfile -LogBlocked True

# 6.2 - Regras de entrada mínimas
# Bloquear SMBv1 (EternalBlue)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# RDP apenas da rede do lab
New-NetFirewallRule -DisplayName "RDP-LabOnly" `
  -Direction Inbound -Protocol TCP -LocalPort 3389 `
  -RemoteAddress 192.168.100.0/24 -Action Allow

# Bloquear acesso RDP externo
New-NetFirewallRule -DisplayName "Block-RDP-External" `
  -Direction Inbound -Protocol TCP -LocalPort 3389 `
  -RemoteAddress Any -Action Block -Priority 100

Write-Host "✅ Firewall configurado"
```

---

## 7. SERVIÇOS DESNECESSÁRIOS

```powershell
# 7.1 - Desabilitar serviços de risco
$servicesToDisable = @(
  "Telnet",           # Protocolo inseguro
  "SNMP",             # Se não utilizado
  "RemoteRegistry",   # CIS: desabilitar
  "Spooler",          # Se não for servidor de impressão
  "Fax",
  "XblAuthManager",
  "XblGameSave",
  "XboxNetApiSvc"
)

foreach ($svc in $servicesToDisable) {
  $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($service) {
    Set-Service -Name $svc -StartupType Disabled
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Write-Host "Desabilitado: $svc"
  }
}

# 7.2 - Desabilitar SMBv1 (crítico — previne WannaCry/EternalBlue)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Write-Host "✅ SMBv1 desabilitado"
```

---

## 8. CONFIGURAÇÕES DE SEGURANÇA DO SISTEMA

```powershell
# 8.1 - Configurar UAC (máximo)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "EnableLUA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "ConsentPromptBehaviorAdmin" -Value 2  # Prompt no Secure Desktop

# 8.2 - Configurar NTP para servidor de tempo confiável
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:YES /update
Restart-Service w32tm

# 8.3 - Desabilitar AutoPlay/AutoRun
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -Name "NoDriveTypeAutoRun" -Value 255
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -Name "NoAutorun" -Value 1

# 8.4 - Configurar LSASS protegido (Credential Guard)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RunAsPPL" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "DisableRestrictedAdmin" -Value 0

Write-Host "✅ Configurações de sistema aplicadas"
```

---

## 9. POWERSHELL LOGGING

```powershell
# 9.1 - Habilitar PowerShell logging completo
$psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
New-Item -Path $psLoggingPath -Force | Out-Null

# Script Block Logging
New-Item -Path "$psLoggingPath\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLoggingPath\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1

# Module Logging
New-Item -Path "$psLoggingPath\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLoggingPath\ModuleLogging" `
  -Name "EnableModuleLogging" -Value 1

# Transcription (salvar em arquivo)
New-Item -Path "$psLoggingPath\Transcription" -Force | Out-Null
Set-ItemProperty -Path "$psLoggingPath\Transcription" `
  -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "$psLoggingPath\Transcription" `
  -Name "OutputDirectory" -Value "C:\Windows\Logs\PowerShell"

New-Item -Path "C:\Windows\Logs\PowerShell" -ItemType Directory -Force | Out-Null

Write-Host "✅ PowerShell logging habilitado"
```

---

## 10. VERIFICAÇÃO FINAL

```powershell
Write-Host "=== RELATÓRIO DE HARDENING ===" -ForegroundColor Cyan

Write-Host "`n[1] Usuários locais:"
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table

Write-Host "`n[2] Serviços críticos:"
Get-Service -Name "WinDefend","MpsSvc","EventLog","Audiosrv" | `
  Select-Object Name, Status | Format-Table

Write-Host "`n[3] SMBv1:"
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

Write-Host "`n[4] Windows Defender:"
Get-MpComputerStatus | Select-Object `
  AntivirusEnabled, RealTimeProtectionEnabled, `
  NISEnabled, IoavProtectionEnabled | Format-List

Write-Host "`n[5] Firewall:"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | Format-Table

Write-Host "`n[6] Auditoria ativa:"
auditpol /get /category:* | Select-String "Success|Failure" | Select-Object -First 10

Write-Host "`n✅ Hardening Windows Server concluído" -ForegroundColor Green
```

---

## Checklist

- [ ] Windows atualizado
- [ ] Conta Administrator renomeada
- [ ] Guest desabilitado
- [ ] Política de senhas (14 chars, lockout 5 tentativas)
- [ ] Auditoria de segurança configurada (todos os eventos críticos)
- [ ] Windows Defender com proteção em tempo real
- [ ] Firewall ativo (default deny inbound)
- [ ] SMBv1 desabilitado
- [ ] RemoteRegistry desabilitado
- [ ] UAC no nível máximo
- [ ] LSASS protegido (RunAsPPL)
- [ ] PowerShell Script Block Logging ativo
- [ ] Snapshot "pós-hardening" criado

---

## Referências
- [CIS Windows Server 2022 Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [DISA STIG Windows Server 2022](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Security Baseline](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
