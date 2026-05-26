# HRD-004 — Hardening AWS (CIS AWS Foundations Benchmark v1.5)

**Framework:** CIS Amazon Web Services Foundations Benchmark v1.5  
**Escopo:** IAM, S3, CloudTrail, EC2, VPC, GuardDuty, Security Hub  
**Ferramenta:** AWS CLI + Console  

---

## Pré-requisitos

```bash
# Instalar AWS CLI
sudo apt install awscli -y
aws configure  # Access Key, Secret, Region

# Verificar acesso
aws sts get-caller-identity
```

---

## 1. IDENTITY AND ACCESS MANAGEMENT (IAM)

### 1.1 — Conta Root
```bash
# Verificar se MFA está ativo na conta root
aws iam get-account-summary \
  --query 'SummaryMap.AccountMFAEnabled'
# Esperado: 1 (ativo)

# Verificar access keys da root (deve ser 0)
aws iam list-access-keys --user-name root \
  --query 'AccessKeyMetadata[*].AccessKeyId'
# Esperado: lista vazia

# ✅ Ação: Ativar MFA virtual na root via Console > IAM > Dashboard
```

### 1.2 — Password Policy
```bash
# Aplicar política de senhas forte
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --hard-expiry

# Verificar
aws iam get-account-password-policy
```

### 1.3 — Usuários com Access Keys Antigas
```bash
# Listar usuários com access keys
aws iam generate-credential-report
sleep 5
aws iam get-credential-report \
  --query 'Content' --output text | base64 -d | \
  awk -F, '$10 == "true" {print $1, "Key1 last used:", $11}' | \
  head -20

# Keys com mais de 90 dias devem ser rotacionadas
```

### 1.4 — MFA para Todos os Usuários IAM
```bash
# Listar usuários SEM MFA
aws iam list-users --query 'Users[*].UserName' --output text | \
  tr '\t' '\n' | while read user; do
    mfa=$(aws iam list-mfa-devices --user-name "$user" \
      --query 'MFADevices' --output text)
    [[ -z "$mfa" ]] && echo "SEM MFA: $user"
  done
```

### 1.5 — Política de Least Privilege
```bash
# Identificar usuários com AdministratorAccess
aws iam list-users --query 'Users[*].UserName' --output text | \
  tr '\t' '\n' | while read user; do
    policies=$(aws iam list-attached-user-policies \
      --user-name "$user" \
      --query 'AttachedPolicies[*].PolicyName' --output text)
    echo "$policies" | grep -q "AdministratorAccess" && \
      echo "⚠️  Admin direto no usuário: $user"
  done

# Exemplo: remover AdministratorAccess de usuário comum
# aws iam detach-user-policy \
#   --user-name USERNAME \
#   --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

---

## 2. CLOUDTRAIL (LOGGING)

```bash
# 2.1 - Verificar trilhas ativas em todas as regiões
aws cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[*].{Name:Name,MultiRegion:IsMultiRegionTrail,LogStatus:HasCustomEventSelectors}'

# 2.2 - Criar trilha multi-região com log de gestão
BUCKET_NAME="cloudtrail-lab-$(aws sts get-caller-identity --query Account --output text)"

# Criar bucket S3 para logs
aws s3 mb "s3://$BUCKET_NAME" --region us-east-1

# Política do bucket (bloquear acesso público)
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Criar trilha
aws cloudtrail create-trail \
  --name "cis-multi-region-trail" \
  --s3-bucket-name "$BUCKET_NAME" \
  --is-multi-region-trail \
  --include-global-service-events \
  --enable-log-file-validation

aws cloudtrail start-logging --name "cis-multi-region-trail"

# 2.3 - Habilitar log de Data Events (S3 e Lambda)
aws cloudtrail put-event-selectors \
  --trail-name "cis-multi-region-trail" \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {"Type":"AWS::S3::Object","Values":["arn:aws:s3:::"]},
        {"Type":"AWS::Lambda::Function","Values":["arn:aws:lambda"]}
      ]
    }
  ]'
```

---

## 3. S3 — HARDENING DE BUCKETS

```bash
# 3.1 - Bloquear acesso público em TODOS os buckets da conta
aws s3control put-public-access-block \
  --account-id "$(aws sts get-caller-identity --query Account --output text)" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 3.2 - Auditar buckets com acesso público
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read bucket; do
    status=$(aws s3api get-public-access-block \
      --bucket "$bucket" \
      --query 'PublicAccessBlockConfiguration.BlockPublicAcls' \
      --output text 2>/dev/null || echo "ERROR")
    [[ "$status" != "True" ]] && echo "⚠️  Bucket SEM bloqueio público: $bucket"
  done

# 3.3 - Habilitar versionamento e MFA Delete
aws s3api put-bucket-versioning \
  --bucket "$BUCKET_NAME" \
  --versioning-configuration Status=Enabled

# 3.4 - Habilitar criptografia padrão (SSE-KMS)
aws s3api put-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms"
      }
    }]
  }'
```

---

## 4. VPC — SEGURANÇA DE REDE

```bash
# 4.1 - Verificar VPC padrão (deve ser deletada ou não usada em produção)
DEFAULT_VPC=$(aws ec2 describe-vpcs \
  --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)
echo "VPC padrão: $DEFAULT_VPC"

# 4.2 - Security Groups — verificar regras permissivas demais
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{
    ID:GroupId,
    Name:GroupName,
    Ports:IpPermissions[*].FromPort
  }' \
  --output table

# 4.3 - Verificar Security Group com SSH aberto para 0.0.0.0/0
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.from-port,Values=22" \
            "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName}' \
  --output table

# 4.4 - VPC Flow Logs (obrigatório CIS)
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids "$DEFAULT_VPC" \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name "/aws/vpc/flow-logs" \
  --deliver-logs-permission-arn "arn:aws:iam::ACCOUNT:role/VPCFlowLogsRole"
```

---

## 5. EC2 — HARDENING

```bash
# 5.1 - Verificar instâncias com IP público e portas abertas
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].{
    ID:InstanceId,
    State:State.Name,
    PublicIP:PublicIpAddress,
    IMDSv2:MetadataOptions.HttpTokens
  }' --output table

# 5.2 - Forçar IMDSv2 em todas as instâncias (evitar SSRF)
for instance in $(aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].InstanceId' --output text); do
  aws ec2 modify-instance-metadata-options \
    --instance-id "$instance" \
    --http-tokens required \
    --http-endpoint enabled
  echo "IMDSv2 obrigatório: $instance"
done

# 5.3 - Verificar EBS volumes não criptografados
aws ec2 describe-volumes \
  --query 'Volumes[?Encrypted==`false`].{ID:VolumeId,Size:Size,State:State}' \
  --output table

# 5.4 - Habilitar criptografia padrão de EBS na região
aws ec2 enable-ebs-encryption-by-default
aws ec2 get-ebs-encryption-by-default
```

---

## 6. GUARDDUTY E SECURITY HUB

```bash
# 6.1 - Habilitar GuardDuty
aws guardduty create-detector --enable \
  --data-sources '{"S3Logs":{"Enable":true},"Kubernetes":{"AuditLogs":{"Enable":true}}}'

DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
echo "GuardDuty Detector ID: $DETECTOR_ID"

# 6.2 - Habilitar Security Hub com padrões CIS
aws securityhub enable-security-hub \
  --enable-default-standards

# Habilitar CIS AWS Foundations
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
  '[{"StandardsArn":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"}]'

# 6.3 - Verificar findings do Security Hub
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}' \
  --query 'Findings[*].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id}' \
  --output table | head -30
```

---

## 7. CLOUDWATCH — ALARMES DE SEGURANÇA (CIS)

```bash
# Criar alarmes para atividades críticas (CIS 4.x)
ALARM_SNS="arn:aws:sns:REGION:ACCOUNT:security-alerts"
LOGS_GROUP="CloudTrail/DefaultLogGroup"

create_alarm() {
  local name="$1" pattern="$2" desc="$3"
  
  # Criar filtro de métrica
  aws logs put-metric-filter \
    --log-group-name "$LOGS_GROUP" \
    --filter-name "$name" \
    --filter-pattern "$pattern" \
    --metric-transformations \
    "metricName=$name,metricNamespace=CISAlarms,metricValue=1"
  
  # Criar alarme CloudWatch
  aws cloudwatch put-metric-alarm \
    --alarm-name "$name" \
    --alarm-description "$desc" \
    --metric-name "$name" \
    --namespace "CISAlarms" \
    --statistic Sum \
    --period 300 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --evaluation-periods 1 \
    --alarm-actions "$ALARM_SNS"
}

# CIS 4.1 - Uso da conta root
create_alarm "CIS-4.1-RootAccountUsage" \
  '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent"}' \
  "Alerta: Uso da conta root detectado"

# CIS 4.2 - Mudanças no IAM
create_alarm "CIS-4.2-IAMChanges" \
  '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=SetDefaultPolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}' \
  "Alerta: Mudança em políticas IAM"

# CIS 4.4 - Mudanças no Security Group
create_alarm "CIS-4.4-SecurityGroupChanges" \
  '{($.eventName=AuthorizeSecurityGroupIngress)||($.eventName=AuthorizeSecurityGroupEgress)||($.eventName=RevokeSecurityGroupIngress)||($.eventName=RevokeSecurityGroupEgress)||($.eventName=CreateSecurityGroup)||($.eventName=DeleteSecurityGroup)}' \
  "Alerta: Mudança em Security Group"

echo "✅ Alarmes CIS criados"
```

---

## Verificação de Conformidade

```bash
# Relatório rápido de conformidade
echo "=== RELATÓRIO CIS AWS ==="

echo "1. MFA na root:"
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'

echo "2. CloudTrail ativo:"
aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,MultiRegion:IsMultiRegionTrail}'

echo "3. GuardDuty ativo:"
aws guardduty list-detectors --query 'DetectorIds'

echo "4. Security Hub:"
aws securityhub describe-hub --query 'HubArn' 2>/dev/null || echo "Não ativo"

echo "5. EBS encryption padrão:"
aws ec2 get-ebs-encryption-by-default

echo "6. S3 Block Public Access (conta):"
aws s3control get-public-access-block \
  --account-id "$(aws sts get-caller-identity --query Account --output text)" \
  --query 'PublicAccessBlockConfiguration'
```

---

## Checklist Final

- [ ] MFA ativo na conta root
- [ ] Nenhuma access key na conta root
- [ ] Política de senhas IAM configurada (>14 chars, complexidade, 90 dias)
- [ ] MFA para todos os usuários IAM com acesso ao console
- [ ] CloudTrail multi-região com validação de log ativa
- [ ] S3 Block Public Access ativo na conta
- [ ] VPC Flow Logs ativados
- [ ] IMDSv2 obrigatório em todas as EC2
- [ ] EBS encryption padrão ativado
- [ ] GuardDuty ativo
- [ ] Security Hub com CIS benchmark ativo
- [ ] Alarmes CloudWatch para atividades críticas (CIS 4.x)

---

## Referências
- [CIS AWS Foundations Benchmark v1.5](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Hub — CIS Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-cis.html)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
