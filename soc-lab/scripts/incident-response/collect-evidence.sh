#!/usr/bin/env bash
# =============================================================================
# collect-evidence.sh
# Coleta forense inicial para resposta a incidentes (Linux)
# Uso: sudo bash collect-evidence.sh [INCIDENT_ID]
# =============================================================================

set -euo pipefail

INCIDENT_ID="${1:-INC-$(date +%Y%m%d-%H%M)}"
EVIDENCE_DIR="/tmp/evidence-${INCIDENT_ID}"
ARCHIVE="/var/log/evidence-${INCIDENT_ID}.tar.gz"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLUE}[$(date +%T)]${NC} $1" | tee -a "$EVIDENCE_DIR/collection.log"; }
done_() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$EVIDENCE_DIR/collection.log"; }

[[ $EUID -ne 0 ]] && { echo "Execute como root: sudo $0 $1"; exit 1; }

mkdir -p "$EVIDENCE_DIR"/{network,processes,users,files,logs,system}

log "==================================================="
log " COLETA DE EVIDÊNCIAS — Incidente: $INCIDENT_ID"
log " Host: $(hostname) | IP: $(hostname -I | awk '{print $1}')"
log " Analista: $(logname 2>/dev/null || echo 'root')"
log " Início: $(date)"
log "==================================================="

# Preservar timestamp de início
date -u > "$EVIDENCE_DIR/collection-timestamp.txt"

# ─────────────────────────────────────────────
# SISTEMA
# ─────────────────────────────────────────────
log "Coletando informações do sistema..."
uname -a                          > "$EVIDENCE_DIR/system/uname.txt"
uptime                            > "$EVIDENCE_DIR/system/uptime.txt"
date                              > "$EVIDENCE_DIR/system/date.txt"
hostname -f                       > "$EVIDENCE_DIR/system/hostname.txt"
cat /etc/os-release               > "$EVIDENCE_DIR/system/os-release.txt"
dmesg | tail -200                 > "$EVIDENCE_DIR/system/dmesg-tail.txt"
last -n 100                       > "$EVIDENCE_DIR/system/last-logins.txt"
lastb -n 100 2>/dev/null          > "$EVIDENCE_DIR/system/failed-logins.txt" || true
journalctl -n 500 --no-pager      > "$EVIDENCE_DIR/system/journal-recent.txt"
done_ "Sistema coletado"

# ─────────────────────────────────────────────
# REDE
# ─────────────────────────────────────────────
log "Coletando estado de rede..."
ss -tulpn 2>/dev/null             > "$EVIDENCE_DIR/network/listening-ports.txt"
ss -tnp 2>/dev/null               > "$EVIDENCE_DIR/network/active-connections.txt"
ip addr show                      > "$EVIDENCE_DIR/network/ip-addresses.txt"
ip route show                     > "$EVIDENCE_DIR/network/routes.txt"
ip neigh show                     > "$EVIDENCE_DIR/network/arp-cache.txt"
cat /etc/hosts                    > "$EVIDENCE_DIR/network/etc-hosts.txt"
cat /etc/resolv.conf              > "$EVIDENCE_DIR/network/resolv-conf.txt"
iptables -L -n -v 2>/dev/null     > "$EVIDENCE_DIR/network/iptables.txt" || true
nft list ruleset 2>/dev/null      > "$EVIDENCE_DIR/network/nftables.txt" || true
done_ "Rede coletada"

# ─────────────────────────────────────────────
# PROCESSOS
# ─────────────────────────────────────────────
log "Coletando processos em execução..."
ps auxwwef                        > "$EVIDENCE_DIR/processes/ps-full.txt"
ps -eo pid,ppid,user,args --sort=start_time > "$EVIDENCE_DIR/processes/ps-sorted.txt"

# Processos com conexões de rede abertas
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  if [[ -d "/proc/$pid/net" ]]; then
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
    echo "$pid $exe" >> "$EVIDENCE_DIR/processes/pids-with-net.txt"
  fi
done

# Listar todos os descritores de arquivo de processos suspeitos
lsof -i 2>/dev/null               > "$EVIDENCE_DIR/processes/lsof-network.txt" || true
done_ "Processos coletados"

# ─────────────────────────────────────────────
# USUÁRIOS E CREDENCIAIS
# ─────────────────────────────────────────────
log "Coletando usuários e sessões..."
cat /etc/passwd                   > "$EVIDENCE_DIR/users/passwd.txt"
cat /etc/group                    > "$EVIDENCE_DIR/users/group.txt"
who -a                            > "$EVIDENCE_DIR/users/who.txt"
w                                 > "$EVIDENCE_DIR/users/w.txt"
id                                > "$EVIDENCE_DIR/users/current-user.txt"

# Listar chaves SSH autorizadas
find /home /root -name "authorized_keys" 2>/dev/null \
  -exec echo "=== {} ===" \; -exec cat {} \; \
  > "$EVIDENCE_DIR/users/authorized-keys.txt"

# Usuários com shell válido
grep -E "bash|sh|zsh" /etc/passwd > "$EVIDENCE_DIR/users/shell-users.txt"

# Usuários com UID 0 além do root
awk -F: '($3 == 0) {print}' /etc/passwd > "$EVIDENCE_DIR/users/uid0-users.txt"

# Sudo
cat /etc/sudoers 2>/dev/null      > "$EVIDENCE_DIR/users/sudoers.txt" || true
ls /etc/sudoers.d/ 2>/dev/null    >> "$EVIDENCE_DIR/users/sudoers.txt"
done_ "Usuários coletados"

# ─────────────────────────────────────────────
# PERSISTÊNCIA (CRÍTICO)
# ─────────────────────────────────────────────
log "Verificando mecanismos de persistência..."

# Crontabs
crontab -l -u root 2>/dev/null    > "$EVIDENCE_DIR/files/crontab-root.txt" || true
cat /etc/crontab                  > "$EVIDENCE_DIR/files/etc-crontab.txt"
ls -la /etc/cron.*                > "$EVIDENCE_DIR/files/cron-dirs.txt"

# Systemd services e timers
systemctl list-units --type=service --state=running --no-pager \
  > "$EVIDENCE_DIR/files/systemd-services.txt"
systemctl list-timers --no-pager \
  > "$EVIDENCE_DIR/files/systemd-timers.txt"

# Serviços instalados recentemente
find /etc/systemd/system -name "*.service" -newer /etc/passwd 2>/dev/null \
  > "$EVIDENCE_DIR/files/new-services.txt"

# Arquivos SUID/SGID
find / -perm -4000 -o -perm -2000 2>/dev/null | sort \
  > "$EVIDENCE_DIR/files/suid-sgid.txt"

# .bashrc e .profile com modificações suspeitas
find /home /root -name ".bashrc" -o -name ".profile" -o -name ".bash_profile" 2>/dev/null \
  -exec echo "=== {} ===" \; -exec cat {} \; \
  > "$EVIDENCE_DIR/files/shell-profiles.txt"

done_ "Persistência verificada"

# ─────────────────────────────────────────────
# LOGS DO SISTEMA
# ─────────────────────────────────────────────
log "Copiando logs relevantes..."
cp /var/log/auth.log* "$EVIDENCE_DIR/logs/" 2>/dev/null || true
cp /var/log/syslog* "$EVIDENCE_DIR/logs/" 2>/dev/null || true
cp /var/log/kern.log* "$EVIDENCE_DIR/logs/" 2>/dev/null || true
cp /var/log/audit/audit.log* "$EVIDENCE_DIR/logs/" 2>/dev/null || true
done_ "Logs copiados"

# ─────────────────────────────────────────────
# HASHES DE INTEGRIDADE
# ─────────────────────────────────────────────
log "Calculando hashes de integridade das evidências..."
find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/HASHES-SHA256.txt"
done_ "Hashes calculados"

# ─────────────────────────────────────────────
# EMPACOTAR EVIDÊNCIAS
# ─────────────────────────────────────────────
log "Empacotando evidências..."
tar -czf "$ARCHIVE" -C /tmp "evidence-${INCIDENT_ID}/"
sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"

log "==================================================="
log " COLETA CONCLUÍDA"
log " Arquivo: $ARCHIVE"
log " Hash: $(cat ${ARCHIVE}.sha256 | awk '{print $1}')"
log " Fim: $(date)"
log "==================================================="
