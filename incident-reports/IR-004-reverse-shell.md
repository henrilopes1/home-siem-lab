# 📋 Relatório de Incidente — IR-004

---

## Informações Gerais

| Campo | Detalhe |
| --- | --- |
| **ID do Incidente** | IR-004 |
| **Título** | Reverse Shell — Conexão Suspeita de Saída (Porta 4444) |
| **Alert UUID** | `0dcae7b41b9d9e1fcd31c62efb2c2e602d5e6fd663f175dc41241e4b9b710d58` |
| **Rule UUID** | `03168606-6021-4952-85f4-7dec236c0e32` |
| **Data de Detecção** | 2026-05-22 |
| **Horário do Evento** | 03:47:48 UTC |
| **Horário do Alerta** | 03:49:34 UTC |
| **Tempo de Detecção** | ~2 minutos após o evento |
| **Analista** | Henri Lopes |
| **Severidade** | 🔴 High |
| **Risk Score** | 73 |
| **Status** | ✅ Resolvido |
| **Técnica MITRE** | T1059 — Command and Scripting Interpreter / T1071 — Application Layer Protocol |
| **Tática MITRE** | Execution / Command and Control (C2) |

---

## 1. Resumo Executivo

Em 2026-05-22 às 03:49:34 UTC, o Kibana SIEM gerou um alerta de severidade **High** identificando uma conexão de rede de saída direcionada à porta `4444`. A porta 4444 é historicamente conhecida por ser a porta *default* de escuta para payloads do Metasploit Framework e conexões de Netcat.

O alerta foi disparado por uma regra do tipo **Threshold** baseada no **Sysmon (Event ID 3 — Network Connection)**. A investigação subsequente dos logs originais (drill-down) confirmou que a conexão foi originada pelo processo `powershell.exe` na máquina Windows (`10.200.200.20`) em direção à máquina atacante Kali Linux (`10.200.200.10`), caracterizando o estabelecimento de uma *Reverse Shell*.

A atividade foi confirmada como uma simulação laboratorial, demonstrando com sucesso a capacidade de detecção de canais de Comando e Controle (C2) não criptografados e em portas suspeitas.

---

## 2. Linha do Tempo

| Horário (UTC) | Evento |
| --- | --- |
| 03:23:45 | Detection rule criada no Kibana |
| 03:47:48 | Conexão de rede estabelecida na porta 4444 (Capturada pelo Sysmon Event ID 3) |
| 03:48:06 | Winlogbeat processa e envia o evento ao Elasticsearch |
| 03:49:34 | Alerta Threshold gerado (`kibana.alert.start`) |
| 03:49:34 | Alerta classificado como **open** e disponível para triagem |

---

## 3. Detecção

### 3.1 Regra Disparada

| Campo | Valor |
| --- | --- |
| **Nome da Regra** | Reverse Shell - Suspicious Outbound Connection |
| **Rule ID** | `2ec64e91-1562-4bc5-a200-8cd07ad274fa` |
| **Tipo** | Threshold Rule |
| **Severidade** | High |
| **Risk Score** | 73 |
| **Intervalo de execução** | 1 minuto |
| **Lookback** | 6 minutos (`now-6m`) |
| **Threshold** | > 1 ocorrência |
| **Query KQL** | `event.provider: "Microsoft-Windows-Sysmon" and event.code: "3" and winlog.event_data.DestinationPort: 4444` |

> ℹ️ **Nota:** O uso de uma regra *Threshold* aqui é interessante porque garante que o SIEM não crie centenas de alertas se a shell gerar múltiplos eventos de conexão. O analista recebe um alerta consolidado.

---

## 4. Análise Técnica

### 4.1 Ameaça de Reverse Shell

Uma *Reverse Shell* ocorre quando o alvo comprometido (neste caso, a máquina Windows) inicia uma conexão de volta para a máquina do atacante (Kali Linux). Isto é feito para contornar regras de firewall de entrada (Inbound), uma vez que a maioria das redes corporativas permite tráfego de saída (Outbound).

### 4.2 Análise do Comportamento (Drill-down do Event ID 3)

A partir do alerta agregado pelo Kibana, o analista realizou a busca pelos eventos puros do Sysmon (`event.code: 3`) para aquele `timestamp`. A investigação revelou a seguinte cadeia:

1. **Processo Origem:** `powershell.exe`
2. **Linha de Comando (Event ID 1 anterior):** `powershell -ExecutionPolicy Bypass -File C:\shell.ps1`
3. **Conexão:** Abertura de socket TCP saindo do IP da vítima (`10.200.200.20`) para o IP do atacante (`10.200.200.10`) na porta `4444`.

### 4.3 Índice de Suspeição

| Fator | Avaliação | Peso |
| --- | --- | --- |
| Porta de Destino 4444 | 🔴 Altamente Suspeito | Alto (Assinatura comum Metasploit/NC) |
| Processo Origem PowerShell | 🔴 Altamente Suspeito | Alto |
| Conexão não-padrão de saída | ⚠️ Suspeito | Médio |
| Confirmado no Lab | ✅ Simulação | — |

**Conclusão:** O padrão é indicativo claro de um comprometimento ativo. O atacante tem execução interativa (Command & Control) na máquina afetada.

---

## 5. Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Contexto |
| --- | --- | --- |
| **Destination Port** | `4444` | Porta de escuta do atacante |
| **Destination IP** | `10.200.200.10` | IP do C2 (Kali Linux) |
| **Process** | `powershell.exe` | Interpretador abusado para estabelecer a conexão |
| **Command Line** | `powershell -ExecutionPolicy Bypass -File C:\shell.ps1` | Execução do payload malicioso |
| **File Path** | `C:\shell.ps1` | Artefato no disco do host |
| **Host** | `DESKTOP-2AHHAUL` | Máquina comprometida |

---

## 6. Contenção

> ⚠️ Em ambiente de produção:

### 6.1 Ações Imediatas (0-1h)

* [ ] **Isolamento de Rede:** Cortar IMEDIATAMENTE a comunicação da máquina `DESKTOP-2AHHAUL` com o resto da rede e com a internet, mantendo apenas a porta do agente EDR/SIEM ativa para contenção.
* [ ] Bloquear o IP de destino (`10.200.200.10`) no Firewall de borda/Proxy corporativo para evitar que outras máquinas comprometidas consigam "telefonar para casa".
* [ ] Terminar (Kill) o processo do PowerShell que está a manter a conexão aberta (Event ID 3).

### 6.2 Ações de Curto Prazo (1-24h)

* [ ] Investigar como o ficheiro `shell.ps1` chegou à máquina (Event ID 11 - File Create ou logs de navegação Web/Email).
* [ ] Verificar eventos pós-conexão (Quais comandos foram executados após a shell abrir? Consultar logs de PowerShell Script Block Logging - Event ID 4104).

---

## 7. Erradicação e Recuperação

> ⚠️ Em ambiente de produção:

* Remover o artefato `C:\shell.ps1`.
* Identificar e eliminar mecanismos de persistência que o atacante possa ter criado enquanto teve acesso remoto (chaves de Run registry, Scheduled Tasks, utilizadores criados).
* Refazer a máquina a partir de uma imagem limpa (recomendado para incidentes que envolvem C2 interativo, pois a confiança no sistema operacional é perdida).
* Reset global de senhas do utilizador da máquina afetada.

---

## 8. Lições Aprendidas e Tuning de Regras

### O que funcionou bem

* ✅ A regra de *Threshold* evitou o inundamento do painel de alertas, entregando um único evento consolidado para a porta 4444.
* ✅ O Sysmon Event ID 3 permitiu correlacionar rapidamente a porta de rede ao executável que a originou.

### Oportunidades de melhoria

**1. Expandir a regra para outras portas padrão de C2:**
Atacantes frequentemente alteram portas para evadir detecção. Podemos criar uma regra para processos do sistema (`powershell.exe`, `cmd.exe`, `rundll32.exe`) estabelecendo qualquer conexão externa:

```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "3" and
winlog.event_data.Image: (*powershell.exe or *cmd.exe or *wscript.exe) and
NOT winlog.event_data.DestinationPort: (80 or 443)

```

---

## 9. Referências

| Fonte | Link |
| --- | --- |
| MITRE ATT&CK T1059.001 | [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE ATT&CK T1071.001 | [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/) |
| Sysmon Event ID 3 | [https://learn.microsoft.com/sysinternals/downloads/sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) |
| Reverse Shell Cheat Sheet | [https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/) |

---

## 10. Classificação Final

| Campo | Valor |
| --- | --- |
| **Tipo de Incidente** | Command and Control — Reverse Shell |
| **Vetor** | Script PowerShell local conectando via TCP |
| **Impacto** | Crítico (Comprometimento Interativo em Lab) |
| **Falso Positivo?** | Não — simulação controlada entre VM Vítima e Kali |
| **Ação Tomada** | Documentado, analisado e bloqueado hipoteticamente |
| **Data de Fechamento** | 2026-05-22 |
| **Analista** | Henri Lopes |