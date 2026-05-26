# PB-001 — SSH Brute Force Attack

**Classificação:** Alto (P2)  
**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing), T1021.004 (Remote Services: SSH)  
**SLA:** Detecção < 30min | Contenção < 4h | Recuperação < 24h  

---

## 1. DETECÇÃO

### Indicadores de Comprometimento (IoC)
- Múltiplas tentativas de login SSH falhadas (> 10 em 1 min) do mesmo IP
- Alert no Security Onion / Wazuh: `rule.id:5712` ou similar
- Log: `/var/log/auth.log` com entradas `Failed password for`

### Como Reproduzir no Lab (Kali → Ubuntu Server)

```bash
# Na VM Kali Linux
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://192.168.100.20 -t 4 -V
```

### Regra de Detecção (Wazuh)

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<rule id="100001" level="10">
  <if_matched_sid>5712</if_matched_sid>
  <same_source_ip/>
  <description>SSH Brute Force: multiple failed logins from same IP</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

### ✅ Checkpoint de Detecção
- [ ] Alerta disparado no SIEM (registrar timestamp)
- [ ] IP de origem identificado
- [ ] Número de tentativas documentado
- [ ] Verificado se houve login bem-sucedido

**⏱️ Timestamp Detecção:** `____:____`

---

## 2. CONTENÇÃO

### Ações Imediatas

```bash
# No Ubuntu Server (alvo) — bloquear IP atacante
sudo ufw deny from 192.168.100.50 to any port 22
sudo ufw reload

# OU via iptables
sudo iptables -A INPUT -s 192.168.100.50 -j DROP

# Verificar se há sessão ativa do IP
who
last | grep 192.168.100.50
ss -tnp | grep :22
```

```bash
# Se houve login bem-sucedido — encerrar sessão imediatamente
sudo pkill -u <usuario_comprometido>
sudo passwd -l <usuario_comprometido>  # Bloquear senha
```

```bash
# No pfSense — bloquear no firewall perimetral
# Firewall > Rules > LAN > Adicionar regra de bloqueio para o IP
```

### Isolamento (se necessário)
```bash
# Script de isolamento completo
# Ver scripts/incident-response/isolate-host.sh
```

### ✅ Checkpoint de Contenção
- [ ] IP bloqueado em firewall (host e/ou perímetro)
- [ ] Sessões ativas encerradas
- [ ] Conta comprometida bloqueada (se aplicável)
- [ ] Time notificado

**⏱️ Timestamp Contenção:** `____:____`

---

## 3. ERRADICAÇÃO

### Verificar Persistência

```bash
# Checar usuários criados recentemente
awk -F: '$3 >= 1000' /etc/passwd
lastlog | grep -v "Never"

# Checar chaves SSH não autorizadas
cat /root/.ssh/authorized_keys
cat /home/*/.ssh/authorized_keys

# Checar crontabs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*

# Checar serviços novos
systemctl list-units --type=service --state=running \
  --no-pager | sort

# Checar SUID/SGID anômalos
find / -perm -4000 -o -perm -2000 2>/dev/null \
  | grep -v -f /etc/find.whitelist
```

### Remover Persistência (se encontrada)

```bash
# Remover chave SSH não autorizada
sed -i '/CHAVE_MALICIOSA/d' /root/.ssh/authorized_keys

# Remover usuário criado pelo atacante
userdel -r <usuario_malicioso>

# Remover crontab malicioso
crontab -r -u <usuario>
```

### ✅ Checkpoint de Erradicação
- [ ] Nenhum usuário não autorizado no sistema
- [ ] Nenhuma chave SSH não autorizada
- [ ] Nenhum crontab ou serviço persistente encontrado
- [ ] Hash de arquivos críticos verificado

**⏱️ Timestamp Erradicação:** `____:____`

---

## 4. RECUPERAÇÃO

```bash
# Restaurar configurações de firewall padrão
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.100.0/24 to any port 22
sudo ufw enable

# Hardening SSH pós-incidente
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no
# MaxAuthTries 3
# AllowUsers seu_usuario

sudo systemctl restart sshd

# Instalar/reconfigurar fail2ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
```

### Validação Pós-Recuperação

```bash
# Testar que SSH com senha está bloqueado
ssh -o PasswordAuthentication=yes root@192.168.100.20

# Confirmar que fail2ban está ativo
sudo fail2ban-client status sshd

# Verificar logs limpos
sudo grep "Failed password" /var/log/auth.log | tail -20
```

### ✅ Checkpoint de Recuperação
- [ ] Serviço SSH operacional com hardening aplicado
- [ ] fail2ban ativo e configurado
- [ ] Acesso via chave SSH funcionando normalmente
- [ ] Monitoramento ativo no SIEM para recorrência

**⏱️ Timestamp Recuperação:** `____:____`

---

## 5. PÓS-INCIDENTE / LIÇÕES APRENDIDAS

```markdown
## Post-Mortem — INC-XXX

**Data:** dd/mm/aaaa  
**Duração total:** XX minutos  

### Timeline
| Hora | Evento |
|---|---|
| HH:MM | Primeiro login falhado detectado no SIEM |
| HH:MM | Alerta P2 disparado |
| HH:MM | IP bloqueado (contenção) |
| HH:MM | Verificação de persistência concluída |
| HH:MM | SSH hardening aplicado (recuperação) |

### SLA Atingido?
- Detecção: XX min (SLA: < 30 min) ✅/❌
- Contenção: XX min (SLA: < 4h)   ✅/❌
- Recuperação: XX min (SLA: < 24h) ✅/❌

### O que funcionou bem
- ...

### O que pode melhorar
- ...

### Ação corretiva
- [ ] Implementar MFA para SSH
- [ ] Adicionar regra de detecção para X IPs em < 5 min
```

---

## Referências
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [CIS Controls v8 — Control 13 (Network Monitoring)](https://www.cisecurity.org/controls/v8)
- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
