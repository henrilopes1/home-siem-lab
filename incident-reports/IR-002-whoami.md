# 📋 Relatório de Incidente — IR-002

---

## Informações Gerais

| Campo | Detalhe |
|---|---|
| **ID do Incidente** | IR-002 |
| **Título** | System Owner Discovery via Whoami.exe |
| **Alert UUID** | `350c6e4b8385aefcc69dfafebff0bf7fdfc5aa526449de216079cfe256041827` |
| **Rule UUID** | `03ebe476-041c-4412-8b20-7ec7fcf103ab` |
| **Data de Detecção** | 2026-05-23 |
| **Horário do Evento** | 01:55:58 UTC |
| **Horário do Alerta** | 01:57:03 UTC |
| **Tempo de Detecção** | ~1 minuto após o evento |
| **Analista** | Henri Lopes |
| **Severidade** | 🟢 Low |
| **Risk Score** | 21 |
| **Status** | ✅ Resolvido |
| **Técnica MITRE** | T1033 — System Owner/User Discovery |
| **Tática MITRE** | Discovery |

---

## 1. Resumo Executivo

Em 2026-05-23 às 01:57:03 UTC, o Kibana SIEM gerou um alerta de severidade **Low** identificando a execução de `whoami.exe` no host `DESKTOP-2AHHAUL`, sob o usuário `DESKTOP-2AHHAUL\VM`.

O detalhe mais relevante deste alerta é o **IntegrityLevel High** combinado com o processo pai sendo `powershell.exe` — indicando que o `whoami.exe` foi executado a partir de uma sessão PowerShell elevada. Em cenários reais, atacantes executam `whoami` logo após obter acesso inicial ou escalar privilégios para confirmar o contexto de execução.

A simulação foi realizada via **Atomic Red Team (T1033)** em ambiente controlado de laboratório.

---

## 2. Linha do Tempo

| Horário (UTC) | Evento |
|---|---|
| 01:54:58 | Detection rule criada no Kibana |
| 01:55:58 | Execução de `whoami.exe` registrada pelo Sysmon (Event ID 1) |
| 01:55:59 | Winlogbeat processa e envia o evento ao Elasticsearch |
| 01:57:03 | Alerta gerado automaticamente pelo Kibana SIEM |
| 01:57:03 | Alerta classificado como **open** e disponível para triagem |

---

## 3. Detecção

### 3.1 Regra Disparada

| Campo | Valor |
|---|---|
| **Nome da Regra** | System Owner Discovery - Whoami Execution - T1033 |
| **Rule ID** | `4f729659-ce72-4770-af0a-32cc46410cbe` |
| **Tipo** | Custom Query Rule |
| **Severidade** | Low |
| **Risk Score** | 21 |
| **Intervalo de execução** | 1 minuto |
| **Lookback** | 6 minutos (`now-6m`) |
| **Query KQL** | `event.provider: "Microsoft-Windows-Sysmon" and event.code: "1" and winlog.event_data.Image: *whoami*` |

### 3.2 Evento Original (Sysmon)

| Campo | Valor |
|---|---|
| **Event ID** | 1 — Process Create |
| **Provider** | Microsoft-Windows-Sysmon |
| **Canal** | Microsoft-Windows-Sysmon/Operational |
| **Record ID** | 5658 |
| **UtcTime** | 2026-05-23 01:55:58.479 |
| **Host** | DESKTOP-2AHHAUL |
| **Agent ID** | `7c57b5e5-794f-4640-9c9a-d0408c59c3e3` |
| **Agent Version** | Winlogbeat 9.4.1 |

### 3.3 Detalhes do Processo

| Campo | Valor |
|---|---|
| **Image** | `C:\Windows\System32\whoami.exe` |
| **OriginalFileName** | `whoami.exe` |
| **CommandLine** | `"C:\Windows\system32\whoami.exe"` |
| **ProcessId** | 4200 |
| **ProcessGuid** | `{4429F9B4-092E-6A11-D501-000000000800}` |
| **CurrentDirectory** | `C:\Windows\system32\` |
| **IntegrityLevel** | ⚠️ **High** |
| **TerminalSessionId** | 1 |
| **User** | `DESKTOP-2AHHAUL\VM` |
| **LogonId** | `0x1f405` |

### 3.4 Processo Pai — ⚠️ Ponto de Atenção

| Campo | Valor |
|---|---|
| **ParentImage** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **ParentCommandLine** | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"` |
| **ParentProcessId** | 4732 |
| **ParentProcessGuid** | `{4429F9B4-0038-6A11-AE00-000000000800}` |
| **ParentUser** | `DESKTOP-2AHHAUL\VM` |

### 3.5 Hashes do Binário

| Algoritmo | Hash |
|---|---|
| **MD5** | `A4A6924F3EAF97981323703D38FD99C4` |
| **SHA256** | `1D4902A04D99E8CCBFE7085E63155955FEE397449D386453F6C452AE407B8743` |
| **IMPHASH** | `7FF0758B766F747CE57DFAC70743FB88` |

> ✅ Hashes correspondem ao binário legítimo da Microsoft (`FileVersion: 10.0.19041.1`, `Company: Microsoft Corporation`).

---

## 4. Análise Técnica

### 4.1 O que é o Whoami?

`whoami.exe` é um binário nativo do Windows que exibe informações sobre o usuário logado, incluindo nome de usuário, grupos e privilégios. É uma ferramenta legítima de administração, mas frequentemente abusada por atacantes para:

- Confirmar o contexto de execução após acesso inicial
- Verificar se obtiveram privilégios elevados após escalonamento
- Enumerar grupos e permissões da conta comprometida

### 4.2 Técnica MITRE — T1033

**Tática:** Discovery  
**Técnica:** System Owner/User Discovery

Atacantes utilizam `whoami` para coletar informações sobre o sistema comprometido, geralmente como um dos primeiros comandos executados após ganhar acesso:

```cmd
whoami                    # usuário atual
whoami /priv              # privilégios da conta
whoami /groups            # grupos do usuário
whoami /all               # todas as informações
```

### 4.3 Ponto Crítico — IntegrityLevel High ⚠️

O dado mais relevante deste alerta é o **IntegrityLevel: High**, diferente do IR-001 onde era Medium.

| IntegrityLevel | Significado |
|---|---|
| Low | Processo sandboxed (ex: browser) |
| Medium | Usuário padrão |
| **High** | **Administrador / Processo elevado** |
| System | Nível de sistema operacional |

`whoami.exe` rodando com **IntegrityLevel High** a partir de `powershell.exe` indica que:
- O PowerShell estava rodando como Administrador
- O atacante já possui privilégios elevados no sistema
- Este é um indicador forte de escalonamento de privilégios bem-sucedido

### 4.4 Cadeia de Execução

```
powershell.exe (PID: 4732) [IntegrityLevel: High]
└── whoami.exe (PID: 4200) [IntegrityLevel: High]
```

Em um ataque real, esta cadeia sugere que o atacante:
1. Obteve acesso ao sistema
2. Escalou para uma sessão PowerShell elevada
3. Executou `whoami` para confirmar os privilégios obtidos

### 4.5 Correlação com Outros Eventos

Em um ambiente real, este alerta deveria ser correlacionado com:

```kql
# Verificar eventos anteriores no mesmo LogonId (0x1f405)
winlog.event_data.LogonId: "0x1f405"

# Verificar outros processos filhos do mesmo PowerShell (PID 4732)
winlog.event_data.ParentProcessId: "4732"

# Verificar Event ID 4672 - Logon com privilégios especiais
event.code: "4672" and winlog.event_data.SubjectLogonId: "0x1f405"
```

---

## 5. Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| **Process** | `C:\Windows\System32\whoami.exe` | Binário executado |
| **CommandLine** | `"C:\Windows\system32\whoami.exe"` | Linha de comando |
| **MD5** | `A4A6924F3EAF97981323703D38FD99C4` | Hash do binário |
| **SHA256** | `1D4902A04D99E8CCBFE7085E63155955FEE397449D386453F6C452AE407B8743` | Hash do binário |
| **Host** | `DESKTOP-2AHHAUL` | Máquina afetada |
| **Usuário** | `DESKTOP-2AHHAUL\VM` | Conta executora |
| **Parent Process** | `powershell.exe` (PID 4732) | Processo pai |
| **IntegrityLevel** | High | ⚠️ Indica elevação |
| **LogonId** | `0x1f405` | Sessão de logon |

---

## 6. Contenção

> ⚠️ Em ambiente de produção:

### 6.1 Ações Imediatas (0-1h)
- [ ] Identificar a origem da sessão PowerShell elevada (PID 4732)
- [ ] Verificar como o usuário obteve privilégios de administrador
- [ ] Investigar eventos anteriores no mesmo LogonId `0x1f405`
- [ ] Verificar outros comandos executados na mesma sessão

### 6.2 Ações de Curto Prazo (1-24h)
- [ ] Buscar execuções de `whoami` em outros hosts
- [ ] Correlacionar com alertas de brute force ou phishing anteriores
- [ ] Revisar logs de escalonamento de privilégios (Event ID 4672, 4728)

**Query de investigação:**
```kql
winlog.event_data.ParentProcessGuid: "{4429F9B4-0038-6A11-AE00-000000000800}"
```

---

## 7. Lições Aprendidas

### O que funcionou bem
- ✅ Sysmon capturou IntegrityLevel — dado crucial para a análise
- ✅ Processo pai identificado — permite rastrear a cadeia de execução
- ✅ Alerta gerado em ~1 minuto após o evento
- ✅ LogonId disponível para correlação com outros eventos

### Oportunidades de melhoria

**Regra mais específica — whoami com IntegrityLevel High:**
```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "1" and
winlog.event_data.Image: *whoami* and
winlog.event_data.IntegrityLevel: "High"
```

**Aumentar severidade quando executado por PowerShell:**
```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "1" and
winlog.event_data.Image: *whoami* and
winlog.event_data.ParentImage: *powershell*
```

---

## 8. Referências

| Fonte | Link |
|---|---|
| MITRE ATT&CK T1033 | https://attack.mitre.org/techniques/T1033/ |
| Atomic Red Team T1033 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md |
| Sysmon Event ID 1 | https://learn.microsoft.com/sysinternals/downloads/sysmon |
| Windows Integrity Levels | https://learn.microsoft.com/windows/win32/secauthz/mandatory-integrity-control |

---

## 9. Classificação Final

| Campo | Valor |
|---|---|
| **Tipo de Incidente** | Discovery — System Owner/User Discovery |
| **Vetor** | Execução local via PowerShell elevado |
| **Impacto** | Baixo (ambiente controlado de laboratório) |
| **Ponto de Atenção** | IntegrityLevel High indica sessão elevada |
| **Falso Positivo?** | Não — comportamento confirmado via Atomic Red Team T1033 |
| **Ação Tomada** | Documentado, analisado e monitorado |
| **Data de Fechamento** | 2026-05-23 |
| **Analista** | Henri Lopes |

---

*Este relatório foi produzido em ambiente de laboratório para fins educacionais.*  
*Todas as simulações foram realizadas em máquinas virtuais próprias e isoladas.*  
*Dados de alerta extraídos diretamente do Kibana SIEM — índice `.internal.alerts-security.alerts-default-000001`*
