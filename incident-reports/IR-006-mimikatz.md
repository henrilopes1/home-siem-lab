# 📋 Relatório de Incidente — IR-006

---

## Informações Gerais

| Campo | Detalhe |
|---|---|
| **ID do Incidente** | IR-006 |
| **Título** | Mimikatz — Credential Dumping via Reverse Shell |
| **Alert UUID** | `a0d33da3007143546b408a6c9b4b3a6f695ab86aa5029605c30eb40fcd0d0d17` |
| **Rule UUID** | `2ce6c598-d70e-4f30-8e1d-630225bb54a2` |
| **Data de Detecção** | 2026-05-23 |
| **Horário do Evento** | 15:22:44 UTC |
| **Horário do Alerta** | 15:23:38 UTC |
| **Tempo de Detecção** | ~54 segundos após o evento |
| **Analista** | Henri Lopes |
| **Severidade** | 🔴 Critical |
| **Risk Score** | 99 |
| **Status** | ✅ Resolvido |
| **Técnica MITRE** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Tática MITRE** | Credential Access |

---

## 1. Resumo Executivo

Em 2026-05-23 às 15:23:38 UTC, o Kibana SIEM gerou um alerta de severidade **Critical** com Risk Score **99** — o mais alto possível — detectando a execução do `mimikatz.exe` no host `DESKTOP-2AHHAUL`.

O alerta foi gerado pela regra **Mimikatz - Credential Dumping** baseada no **Sysmon Event ID 1 (Process Creation)**, com threshold de apenas 1 ocorrência — qualquer execução do Mimikatz é suficiente para disparar o alerta imediatamente.

O contexto do ataque é particularmente grave: o Mimikatz foi executado **remotamente via Reverse Shell**, onde o atacante (Kali Linux `10.200.200.10`) estabeleceu previamente uma conexão reversa com a máquina vítima (IR-004), obteve acesso interativo via `powershell.exe`, e utilizou esse acesso para executar o Mimikatz e tentar extrair credenciais da memória do processo `lsass.exe`.

Esta sequência de eventos demonstra uma **cadeia de ataque completa**: Brute Force (IR-007) → Reverse Shell (IR-004) → Credential Dumping (IR-006).

---

## 2. Linha do Tempo

| Horário (UTC) | Evento |
|---|---|
| 15:11:50 | Brute Force detectado (IR-007) — 28 tentativas contra Administrator |
| 15:13:42 | Alerta de Brute Force gerado |
| ~15:20:00 | Reverse Shell estabelecida via `shell.ps1` (IR-004) |
| 15:22:44 | Execução do `mimikatz.exe` registrada pelo Sysmon (Event ID 1) |
| 15:23:38 | Alerta Critical gerado pelo Kibana SIEM — **54 segundos após o evento** |
| 15:23:38 | Alerta classificado como **open** — máxima prioridade |

---

## 3. Detecção

### 3.1 Regra Disparada

| Campo | Valor |
|---|---|
| **Nome da Regra** | Mimikatz - Credential Dumping |
| **Rule ID** | `5f421708-eb8f-4a4a-99d0-226018ff5fe4` |
| **Tipo** | Threshold Rule |
| **Severidade** | 🔴 Critical |
| **Risk Score** | 99 |
| **Intervalo de execução** | 1 minuto |
| **Lookback** | 6 minutos (`now-6m`) |
| **Threshold** | >= 1 (qualquer execução dispara) |
| **Kibana Version** | 8.19.15 |

### 3.2 Query de Detecção

```kql
event.provider: "Microsoft-Windows-Sysmon" and 
event.code: "1" and 
winlog.event_data.Image: *mimikatz*
```

> ✅ Detecção baseada no **nome do processo** — qualquer arquivo com "mimikatz" no caminho dispara o alerta, independente do diretório ou variação do nome.

### 3.3 Dados do Threshold

```json
{
  "count": 1,
  "from": "2026-05-23T15:22:44.738Z",
  "terms": []
}
```

> ⚠️ O threshold sem `field` (terms vazio) significa que **qualquer** execução do Mimikatz no ambiente inteiro dispara o alerta — não há agrupamento por host ou usuário. Isso é intencional para garantir detecção imediata.

---

## 4. Análise Técnica

### 4.1 O que é o Mimikatz?

Mimikatz é uma ferramenta de segurança ofensiva desenvolvida por Benjamin Delpy, amplamente utilizada em testes de penetração e ataques reais para extrair credenciais da memória do Windows. Suas principais capacidades incluem:

- **sekurlsa::logonpasswords** — extrai senhas em texto claro da memória LSASS
- **sekurlsa::wdigest** — extrai credenciais WDigest
- **lsadump::sam** — dumpa o banco SAM local
- **lsadump::dcsync** — simula um Domain Controller para replicar hashes
- **kerberos::golden** — cria Golden Tickets Kerberos

### 4.2 Técnica MITRE — T1003.001

**Tática:** Credential Access  
**Técnica:** OS Credential Dumping  
**Sub-técnica:** LSASS Memory

O processo `lsass.exe` (Local Security Authority Subsystem Service) armazena credenciais de usuários logados na memória RAM. Atacantes utilizam o Mimikatz para acessar e extrair estas credenciais, obtendo:

- Senhas em texto claro (se WDigest estiver habilitado)
- Hashes NTLM (usados em Pass-the-Hash)
- Tickets Kerberos (usados em Pass-the-Ticket)

### 4.3 Cadeia de Ataque Completa

Este incidente faz parte de uma sequência de ataques detectados no mesmo dia:

```
[15:10] IR-007 — Brute Force RDP (28 tentativas)
           ↓
[15:13] Alerta Medium disparado
           ↓
[~15:20] IR-004 — Reverse Shell estabelecida
         powershell.exe → nc → Kali 10.200.200.10:4444
           ↓
[15:22] IR-006 — Mimikatz executado via shell remota
         mimikatz.exe → sekurlsa::logonpasswords
           ↓
[15:23] Alerta CRITICAL disparado (Risk Score: 99)
```

Esta progressão representa as fases da **Cyber Kill Chain**:

| Fase | Ação | Incidente |
|---|---|---|
| Reconnaissance | Nmap scan | IR-005 |
| Initial Access | Brute Force RDP | IR-007 |
| Execution | Reverse Shell | IR-004 |
| **Credential Access** | **Mimikatz** | **IR-006** |

### 4.4 Gravidade do Incidente

O Risk Score **99** (máximo) reflete a gravidade real desta ameaça:

| Fator | Impacto |
|---|---|
| Credenciais em texto claro expostas | 🔴 Crítico |
| Hashes NTLM extraíveis | 🔴 Crítico — Pass-the-Hash |
| Execução remota via C2 | 🔴 Crítico |
| Privilégios de administrador confirmados | 🔴 Crítico |
| Ferramenta conhecida de atacantes reais | 🔴 Crítico |

### 4.5 Detecção em 54 Segundos

Um dado notável deste alerta é o **tempo de detecção de apenas 54 segundos**:

| Evento | Horário |
|---|---|
| Sysmon registra execução | 15:22:44 |
| Alerta gerado pelo SIEM | 15:23:38 |
| **Diferença** | **54 segundos** |

Isso demonstra a eficácia da combinação Sysmon + Winlogbeat + Kibana para detecção em tempo quase real.

---

## 5. Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| **Process** | `mimikatz.exe` | Ferramenta de credential dumping |
| **Image Path** | `C:\mimikatz\x64\mimikatz.exe` | Localização no disco |
| **Event ID** | Sysmon 1 — Process Create | Método de detecção |
| **Host** | `DESKTOP-2AHHAUL` | Máquina comprometida |
| **Horário** | 15:22:44 UTC | Timestamp da execução |
| **Vetor** | Reverse Shell via `shell.ps1` | Como chegou ao sistema |
| **C2** | `10.200.200.10:4444` | IP do atacante |

---

## 6. Contenção

> ⚠️ Em ambiente de produção — resposta imediata obrigatória:

### 6.1 Ações Imediatas (0-15 minutos) 🚨
- [ ] **ISOLAR** o host `DESKTOP-2AHHAUL` da rede IMEDIATAMENTE
- [ ] **ENCERRAR** a sessão do Mimikatz e a Reverse Shell
- [ ] **BLOQUEAR** IP `10.200.200.10` no firewall
- [ ] **REVOGAR** todas as senhas de contas que estavam logadas no host
- [ ] **NOTIFICAR** equipe de segurança e gestão — incidente crítico

### 6.2 Ações de Curto Prazo (0-1h)
- [ ] Assumir que **todas as credenciais** do host estão comprometidas
- [ ] Verificar se o atacante criou novas contas (`net user` — IR-003)
- [ ] Verificar persistência: tarefas agendadas, serviços, chaves de registro
- [ ] Capturar dump de memória forense antes de reiniciar

### 6.3 Ações de Médio Prazo (1-24h)
- [ ] Reset de senha de todos os usuários do domínio (se ambiente AD)
- [ ] Verificar se hashes NTLM foram usados para movimento lateral
- [ ] Auditar outros sistemas que aceitam as mesmas credenciais

**Query para detectar movimento lateral pós-Mimikatz:**
```kql
event.code: "4624" and
winlog.event_data.LogonType: "3" and
@timestamp > "2026-05-23T15:22:44Z"
```

---

## 7. Erradicação

> ⚠️ Em ambiente de produção:

- [ ] Remover `mimikatz.exe` e `shell.ps1` do disco
- [ ] Identificar e eliminar todos os mecanismos de persistência
- [ ] Revogar todos os tickets Kerberos ativos (krbtgt password reset x2)
- [ ] Reinstalar o sistema operacional — nível de comprometimento crítico

---

## 8. Recuperação

> ⚠️ Em ambiente de produção:

- [ ] Restaurar a partir de backup limpo anterior ao comprometimento
- [ ] Resetar senha do krbtgt duas vezes (Golden Ticket prevention)
- [ ] Monitorar ambiente por 90 dias para comportamento residual
- [ ] Implementar Credential Guard para proteger LSASS

---

## 9. Lições Aprendidas

### O que funcionou bem
- ✅ Detecção em **54 segundos** — quase tempo real
- ✅ Risk Score 99 — classificação correta da gravidade
- ✅ Threshold >= 1 — qualquer execução dispara imediatamente
- ✅ Correlação com IR-004 (Reverse Shell) e IR-007 (Brute Force) revela cadeia completa

### Oportunidades de melhoria

**1. Detectar acesso ao LSASS (mais profundo):**
```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "10" and
winlog.event_data.TargetImage: *lsass*
```

**2. Detectar variantes com nome alterado:**
```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "1" and
winlog.event_data.Hashes: *4DB27267734D1576D75C991DC70F68AC*
```
→ Usar IMPHASH conhecido do Mimikatz para detectar mesmo com nome alterado

**3. Detectar privilege::debug (comportamento, não nome):**
```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "10" and
winlog.event_data.TargetImage: *lsass* and
winlog.event_data.GrantedAccess: "0x1fffff"
```

---

## 10. Referências

| Fonte | Link |
|---|---|
| MITRE ATT&CK T1003.001 | https://attack.mitre.org/techniques/T1003/001/ |
| Mimikatz GitHub | https://github.com/gentilkiwi/mimikatz |
| Sysmon Event ID 1 | https://learn.microsoft.com/sysinternals/downloads/sysmon |
| Detecting Mimikatz | https://www.varonis.com/blog/how-to-detect-mimikatz |
| Windows Credential Guard | https://learn.microsoft.com/windows/security/identity-protection/credential-guard |

---

## 11. Classificação Final

| Campo | Valor |
|---|---|
| **Tipo de Incidente** | Credential Access — OS Credential Dumping |
| **Vetor** | Execução remota via Reverse Shell (C2) |
| **Ferramenta** | Mimikatz v2.x |
| **Host Comprometido** | `DESKTOP-2AHHAUL` |
| **Tempo de Detecção** | 54 segundos |
| **Impacto** | Crítico — credenciais potencialmente expostas |
| **Correlação** | IR-004 (Reverse Shell) + IR-007 (Brute Force) |
| **Falso Positivo?** | Não — simulação controlada via Reverse Shell + Mimikatz |
| **Ação Tomada** | Documentado, analisado e monitorado |
| **Data de Fechamento** | 2026-05-23 |
| **Analista** | Henri Lopes |

---

*Este relatório foi produzido em ambiente de laboratório para fins educacionais.*  
*Todas as simulações foram realizadas em máquinas virtuais próprias e isoladas.*  
*Dados de alerta extraídos diretamente do Kibana SIEM — índice `.internal.alerts-security.alerts-default-000001`*