# 📋 Relatório de Incidente — IR-007

---

## Informações Gerais

| Campo | Detalhe |
|---|---|
| **ID do Incidente** | IR-007 |
| **Título** | Brute Force RDP — Múltiplos Logins Falhados via Network Logon |
| **Alert UUID** | `6befad88e76e3cfdb5748d0225d3b3ad88790510bcdb295a823c3aee5a708c09` |
| **Rule UUID** | `3cd3caca-6f08-4e02-b698-4867d7120c05` |
| **Data de Detecção** | 2026-05-23 |
| **Horário do Evento** | 15:11:50 UTC |
| **Horário do Alerta** | 15:13:42 UTC |
| **Tempo de Detecção** | ~2 minutos após o threshold ser atingido |
| **Analista** | Henri Lopes |
| **Severidade** | 🟡 Medium |
| **Risk Score** | 47 |
| **Status** | ✅ Resolvido |
| **Técnica MITRE** | T1110.001 — Brute Force: Password Guessing |
| **Tática MITRE** | Credential Access |

---

## 1. Resumo Executivo

Em 2026-05-23 às 15:13:42 UTC, o Kibana SIEM gerou um alerta de severidade **Medium** detectando uma campanha de Brute Force contra a conta `Administrator` no host `DESKTOP-2AHHAUL`.

A regra **Threshold** identificou **28 tentativas de login falhado** (Event ID 4625, LogonType 3 — Network Logon) originadas do IP `10.200.200.10` (Kali Linux) em uma janela de apenas **2 minutos** (15:10:51 a 15:13:42 UTC), ultrapassando o threshold configurado de 10 tentativas.

O LogonType 3 confirma que as tentativas foram realizadas via protocolo de rede (RDP/SMB), caracterizando um ataque de força bruta remoto. A ferramenta utilizada foi o **Hydra** em ambiente controlado de laboratório.

---

## 2. Linha do Tempo

| Horário (UTC) | Evento |
|---|---|
| 15:10:51 | Primeira tentativa de login falhado registrada (início da janela de detecção) |
| 15:11:50 | Threshold de 10 tentativas atingido — evento original registrado |
| 15:12:00 | Hydra continua enviando tentativas — total acumulado de 28 |
| 15:13:42 | Alerta gerado pelo Kibana SIEM — `kibana.alert.start` |
| 15:13:42 | Alerta classificado como **open** e disponível para triagem |

---

## 3. Detecção

### 3.1 Regra Disparada

| Campo | Valor |
|---|---|
| **Nome da Regra** | Brute Force - Failed Logon Detection |
| **Rule ID** | `c791d8b2-3a98-44a1-88d7-82d681c055e1` |
| **Tipo** | Threshold Rule |
| **Severidade** | Medium |
| **Risk Score** | 47 |
| **Intervalo de execução** | 5 minutos |
| **Lookback** | 10 minutos (`now-10m`) |
| **Kibana Version** | 8.19.15 |
| **Rule Revision** | 3 (regra foi atualizada 3 vezes) |

### 3.2 Query e Threshold

```kql
event.code: "4625" and winlog.event_data.LogonType: "3"
```

| Campo | Valor |
|---|---|
| **Threshold** | >= 10 |
| **Group by** | `winlog.event_data.IpAddress` + `winlog.event_data.TargetUserName` |
| **Contagem real** | **28 tentativas** na janela de detecção |
| **Janela de tempo** | 15:10:51 → 15:13:42 UTC (~2 minutos) |

### 3.3 Dados do Threshold

```json
{
  "count": 28,
  "from": "2026-05-23T15:10:51.688Z",
  "terms": [
    { "field": "winlog.event_data.IpAddress", "value": "10.200.200.10" },
    { "field": "winlog.event_data.TargetUserName", "value": "Administrator" }
  ]
}
```

---

## 4. Análise Técnica

### 4.1 O que é Brute Force — T1110.001?

**Tática:** Credential Access  
**Técnica:** Brute Force  
**Sub-técnica:** Password Guessing

Atacantes tentam sistematicamente adivinhar credenciais de acesso utilizando listas de senhas comuns (wordlists) ou gerando combinações automaticamente. O objetivo é obter acesso legítimo a sistemas sem precisar explorar vulnerabilidades técnicas.

### 4.2 Análise do LogonType 3

O **LogonType 3 (Network Logon)** é o tipo de logon utilizado em conexões remotas via:
- RDP (Remote Desktop Protocol — porta 3389)
- SMB (porta 445)
- Net Use / mapeamento de drives remotos

| LogonType | Tipo | Contexto |
|---|---|---|
| 2 | Interactive | Login local no teclado |
| 3 | **Network** | **Login remoto via rede** ← Este alerta |
| 10 | RemoteInteractive | RDP com sessão gráfica |

A combinação de `Event ID 4625 + LogonType 3` é a assinatura clássica de um ataque de brute force remoto.

### 4.3 Velocidade do Ataque

| Métrica | Valor |
|---|---|
| Total de tentativas detectadas | 28 |
| Janela de tempo | ~2 minutos |
| Taxa aproximada | ~14 tentativas/minuto |
| IP de origem | `10.200.200.10` (Kali Linux) |
| Conta alvo | `Administrator` |

Uma taxa de 14 tentativas/minuto é característica do Hydra com `-t 1` (1 thread) contra RDP — protocolo que não suporta paralelismo.

### 4.4 Análise do Alvo

A conta `Administrator` é o principal alvo de ataques de brute force porque:
- É a conta administrativa padrão do Windows
- Existe em praticamente todas as instalações Windows
- Tem privilégios máximos no sistema local
- Muitos sistemas têm essa conta habilitada por padrão

### 4.5 Índice de Suspeição

| Fator | Avaliação | Peso |
|---|---|---|
| 28 tentativas falhadas em 2 minutos | 🔴 Altamente Suspeito | Alto |
| IP de origem externo à rede confiável | 🔴 Altamente Suspeito | Alto |
| Conta alvo: Administrator | 🔴 Alto valor | Alto |
| LogonType 3 — acesso remoto | ⚠️ Suspeito | Médio |
| Sem logon bem-sucedido detectado | ✅ Ataque não efetivo | — |
| Confirmado via Hydra (Laboratório) | ✅ Simulação | — |

**Conclusão:** Padrão inequívoco de ataque de brute force remoto. Em ambiente de produção, este alerta exigiria resposta imediata.

### 4.6 Diferença para a Versão Anterior da Regra

A versão original da regra usava apenas `event.code: 4625` sem filtragem por LogonType, o que gerava muitos falsos positivos (logins locais falhados, tentativas de serviços, etc.).

| Campo | Versão Anterior | Versão Atual |
|---|---|---|
| **Query** | `event.code: 4625` | `event.code: "4625" and LogonType: "3"` |
| **Threshold** | Sem agrupamento | Group by IP + Username |
| **Precisão** | Baixa | Alta |
| **Falsos positivos** | Muitos | Reduzidos |

---

## 5. Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| **Source IP** | `10.200.200.10` | IP do atacante (Kali Linux) |
| **Target Host** | `DESKTOP-2AHHAUL` | Máquina alvo |
| **Target Account** | `Administrator` | Conta sob ataque |
| **Event ID** | `4625` | Logon falhado |
| **LogonType** | `3` | Network Logon (remoto) |
| **Contagem** | 28 tentativas | Volume do ataque |
| **Janela** | 15:10:51 → 15:13:42 | Período do ataque |

---

## 6. Contenção

> ⚠️ Em ambiente de produção:

### 6.1 Ações Imediatas (0-1h)
- [ ] Bloquear o IP `10.200.200.10` no firewall de borda imediatamente
- [ ] Verificar se houve algum login bem-sucedido (Event ID 4624) do mesmo IP
- [ ] Ativar bloqueio de conta após N tentativas falhadas (Account Lockout Policy)
- [ ] Verificar se a porta RDP/SMB está exposta para a internet

### 6.2 Ações de Curto Prazo (1-24h)
- [ ] Verificar outros IPs realizando o mesmo padrão contra outros hosts
- [ ] Revisar política de senha da conta Administrator
- [ ] Considerar desabilitar a conta Administrator local e usar conta nomeada
- [ ] Implementar MFA para acesso RDP

**Query para verificar se o ataque foi bem-sucedido:**
```kql
event.code: "4624" and
winlog.event_data.LogonType: "3" and
winlog.event_data.IpAddress: "10.200.200.10" and
winlog.event_data.TargetUserName: "Administrator"
```

**Query para busca lateral — outros hosts atacados:**
```kql
event.code: "4625" and
winlog.event_data.LogonType: "3" and
winlog.event_data.IpAddress: "10.200.200.10"
```

---

## 7. Erradicação

> ⚠️ Em ambiente de produção:

- [ ] Bloquear permanentemente o IP de origem no firewall
- [ ] Revisar e fortalecer a política de senhas
- [ ] Habilitar Account Lockout Policy (bloqueio após 5 tentativas)
- [ ] Restringir acesso RDP apenas a IPs autorizados via VPN

---

## 8. Recuperação

> ⚠️ Em ambiente de produção:

- [ ] Confirmar que não houve acesso bem-sucedido
- [ ] Monitorar o host por 30 dias para comportamento anômalo
- [ ] Revisar todos os logs de autenticação do período
- [ ] Validar integridade da conta Administrator

---

## 9. Lições Aprendidas

### O que funcionou bem
- ✅ Regra Threshold agrupando por IP + Username — muito mais precisa que a versão anterior
- ✅ LogonType 3 filtrou apenas logins remotos — reduziu falsos positivos
- ✅ 28 tentativas detectadas em janela de 2 minutos — detecção rápida
- ✅ Dados de threshold com contagem exata disponíveis no alerta

### Oportunidades de melhoria

**1. Detectar brute force bem-sucedido (crítico):**
```kql
# Criar regra separada — Event Correlation
# 4625 seguido de 4624 do mesmo IP em menos de 5 minutos
event.code: ("4625" or "4624") and
winlog.event_data.LogonType: "3" and
winlog.event_data.IpAddress: *
```

**2. Aumentar severidade para High se conta for Administrator:**
```kql
event.code: "4625" and
winlog.event_data.LogonType: "3" and
winlog.event_data.TargetUserName: "Administrator"
```
→ Severidade: **High** | Risk Score: **73**

**3. Detectar password spray (1 senha, muitos usuários):**
```kql
event.code: "4625" and
winlog.event_data.LogonType: "3"
```
→ Threshold: Group by `IpAddress` apenas (não por username) >= 5 usernames diferentes

---

## 10. Referências

| Fonte | Link |
|---|---|
| MITRE ATT&CK T1110.001 | https://attack.mitre.org/techniques/T1110/001/ |
| Windows Event ID 4625 | https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625 |
| Windows Logon Types | https://learn.microsoft.com/windows-server/identity/securing-privileged-access/reference-tools-logon-types |
| Hydra — THC | https://github.com/vanhauser-thc/thc-hydra |
| CIS Benchmark — Account Lockout | https://www.cisecurity.org/cis-benchmarks |

---

## 11. Classificação Final

| Campo | Valor |
|---|---|
| **Tipo de Incidente** | Credential Access — Brute Force Password Guessing |
| **Vetor** | Hydra via protocolo RDP/Network Logon |
| **IP de Origem** | `10.200.200.10` (Kali Linux) |
| **Conta Alvo** | `Administrator` |
| **Total de Tentativas** | 28 em ~2 minutos |
| **Acesso Obtido?** | Não — ataque não bem-sucedido |
| **Falso Positivo?** | Não — simulação confirmada via Hydra |
| **Ação Tomada** | Documentado, analisado e monitorado |
| **Data de Fechamento** | 2026-05-23 |
| **Analista** | Henri Lopes |

---

*Este relatório foi produzido em ambiente de laboratório para fins educacionais.*  
*Todas as simulações foram realizadas em máquinas virtuais próprias e isoladas.*  
*Dados de alerta extraídos diretamente do Kibana SIEM — índice `.internal.alerts-security.alerts-default-000001`*