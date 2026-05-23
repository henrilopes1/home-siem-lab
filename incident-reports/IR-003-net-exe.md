# 📋 Relatório de Incidente — IR-003

---

## Informações Gerais

| Campo | Detalhe |
| --- | --- |
| **ID do Incidente** | IR-003 |
| **Título** | Account Discovery via Net.exe — Enumeração de Contas Locais |
| **Alert UUID** | `a522690979c341610a584f64b721e3410f031bd35914029db86e6ed4724bec89` |
| **Rule UUID** | `5dc812b4-9100-44c9-9087-2ef683aaf951` |
| **Data de Detecção** | 2026-05-23 |
| **Horário do Evento** | 02:01:36 UTC |
| **Horário do Alerta** | 02:03:13 UTC |
| **Tempo de Detecção** | ~2 minutos após o evento |
| **Analista** | Henri Lopes |
| **Severidade** | 🟡 Medium |
| **Risk Score** | 47 |
| **Status** | ✅ Resolvido |
| **Técnica MITRE** | T1087.001 — Account Discovery: Local Account |
| **Tática MITRE** | Discovery |

---

## 1. Resumo Executivo

Em 2026-05-23 às 02:03:13 UTC, o Kibana SIEM gerou um alerta de severidade **Medium** identificando a execução do utilitário `net.exe` com o argumento `users` no host `DESKTOP-2AHHAUL`, sob a conta de utilizador `DESKTOP-2AHHAUL\VM`.

O aspeto mais crítico deste alerta é o processo pai (`cmd.exe`), que orquestrou uma cadeia de comandos automatizada para extrair o domínio, o utilizador atual, enumerar todas as contas locais e sessões ativas no sistema, redirecionando o output (stdout) de todos estes comandos para um ficheiro temporário na diretoria `AppData\Local\Temp`. Este comportamento é altamente indicativo da fase de reconhecimento de um atacante (ou script malicioso) a preparar dados para exfiltração.

A detecção foi realizada pelo **Sysmon (Event ID 1 — Process Creation)** e o alerta foi gerado pela regra **Account Discovery - Net.exe Execution - T1087**. A atividade foi confirmada como uma simulação laboratorial executada através do **Atomic Red Team (T1087)**.

---

## 2. Linha do Tempo

| Horário (UTC) | Evento |
| --- | --- |
| 01:53:06 | Detection rule criada/atualizada no Kibana |
| 02:01:36 | Execução do `net.exe` registada pelo Sysmon (Event ID 1) |
| 02:01:38 | Winlogbeat processa e envia o evento ao Elasticsearch |
| 02:03:13 | Alerta gerado automaticamente pelo Kibana SIEM |
| 02:03:13 | Alerta classificado como **open** e disponível para triagem |

---

## 3. Detecção

### 3.1 Regra Disparada

| Campo | Valor |
| --- | --- |
| **Nome da Regra** | Account Discovery - Net.exe Execution - T1087 |
| **Rule ID** | `e47b3895-a6b2-4ab8-8a6e-61d7024376ae` |
| **Tipo** | Custom Query Rule |
| **Severidade** | Medium |
| **Risk Score** | 47 |
| **Intervalo de execução** | 1 minuto |
| **Lookback** | 6 minutos (`now-6m`) |
| **Query KQL** | `event.provider: "Microsoft-Windows-Sysmon" and event.code: "1" and winlog.event_data.Image: *net.exe*` |

### 3.2 Evento Original (Sysmon)

| Campo | Valor |
| --- | --- |
| **Event ID** | 1 — Process Create |
| **Provider** | Microsoft-Windows-Sysmon |
| **Canal** | Microsoft-Windows-Sysmon/Operational |
| **Record ID** | 5811 |
| **UtcTime** | 2026-05-23 02:01:36.432 |
| **Host** | DESKTOP-2AHHAUL |
| **Agent ID** | `7c57b5e5-794f-4640-9c9a-d0408c59c3e3` |

### 3.3 Detalhes do Processo (Filho)

| Campo | Valor |
| --- | --- |
| **Image** | `C:\Windows\System32\net.exe` |
| **CommandLine** | `net users` |
| **ProcessId** | 1752 |
| **ProcessGuid** | `{4429F9B4-0A80-6A11-4502-000000000800}` |
| **CurrentDirectory** | `C:\Users\VM\AppData\Local\Temp\` |
| **IntegrityLevel** | High |
| **User** | `DESKTOP-2AHHAUL\VM` |

### 3.4 Processo Pai — 🚨 Indicador de Comprometimento Crítico

| Campo | Valor |
| --- | --- |
| **ParentImage** | `C:\Windows\System32\cmd.exe` |
| **ParentCommandLine** | `"cmd.exe" /c set file=$env:temp\user_info_%random%.tmp & echo Username: %USERNAME% > %file% & echo User Domain: %USERDOMAIN% >> %file% & net users >> %file% & query user >> %file%` |
| **ParentProcessId** | 3712 |
| **ParentUser** | `DESKTOP-2AHHAUL\VM` |

### 3.5 Hashes do Binário

| Algoritmo | Hash |
| --- | --- |
| **MD5** | `0BD94A338EEA5A4E1F2830AE326E6D19` |
| **SHA256** | `9F376759BCBCD705F726460FC4A7E2B07F310F52BAA73CAAAAA124FDDBDF993E` |

> ✅ Os hashes correspondem ao binário legítimo do Windows OS. O alerta não se baseia na presença de malware, mas sim no **abuso de ferramentas nativas** (Living off the Land).

---

## 4. Análise Técnica

### 4.1 O que é a ferramenta Net.exe?

O `net.exe` é um utilitário nativo de linha de comandos do Windows utilizado para gerir utilizadores de rede, serviços e partilhas. No contexto de segurança, os comandos `net user` e `net localgroup` são frequentemente abusados por adversários nas fases iniciais de um comprometimento para enumerar alvos e mapear as contas existentes na máquina afetada ou no domínio.

### 4.2 Técnica MITRE — T1087.001

**Tática:** Discovery

**Técnica:** Account Discovery: Local Account

Os atacantes utilizam esta técnica para identificar quais as contas que existem no sistema operativo local. Esta informação ajuda o adversário a decidir que contas tentar comprometer a seguir (para escalonamento de privilégios ou movimento lateral) e a compreender o nível de acesso que já obtiveram.

### 4.3 Análise do Comportamento do Processo Pai

A verdadeira "arma fumegante" deste alerta não é apenas a execução do `net users`, mas a forma como foi orquestrada pela linha de comandos do processo pai. A cadeia de execução (encadeada pelo operador `&`) realiza os seguintes passos:

1. `set file=$env:temp\user_info_%random%.tmp` ➔ Define uma variável para criar um ficheiro temporário e furtivo na pasta de ficheiros temporários do utilizador.
2. `echo Username: %USERNAME% > %file%` ➔ Escreve o nome do utilizador atual no ficheiro.
3. `echo User Domain: %USERDOMAIN% >> %file%` ➔ Anexa (`>>`) o domínio da máquina/utilizador.
4. `net users >> %file%` ➔ Anexa a lista completa de utilizadores locais do sistema.
5. `query user >> %file%` ➔ Anexa informações sobre sessões ativas (quem está ligado no momento).

**Avaliação:** Este é um comportamento de script de recolha (collection) automatizada, perfeitamente alinhado com o que faria um implante C2 (Command and Control) como o Cobalt Strike, ou um script .bat largado na máquina.

### 4.4 Índice de Suspeição

| Fator | Avaliação | Peso |
| --- | --- | --- |
| `net users` isolado | ⚠️ Suspeito | Baixo (Pode ser um Sysadmin) |
| Redirecionamento de output (>>) | 🔴 Altamente Suspeito | Alto |
| Encadeamento de comandos CMD (&) | 🔴 Altamente Suspeito | Alto |
| Criação de ficheiro .tmp oculto | 🔴 Altamente Suspeito | Alto |
| IntegrityLevel High | ⚠️ Permite ler ficheiros do sistema | Médio |
| Confirmado via Atomic Red Team | ✅ Simulação | — |

**Conclusão:** O padrão é claramente malicioso. Se isto fosse detetado num ambiente de produção corporativo fora de uma janela de testes/Pentest, seria declarado de imediato um incidente de segurança.

---

## 5. Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Contexto |
| --- | --- | --- |
| **Process** | `C:\Windows\System32\net.exe` | Ferramenta abusada |
| **Process** | `C:\Windows\System32\cmd.exe` | Processo orquestrador |
| **Command Line (CMD)** | `"cmd.exe" /c set file=$env:temp\user_info_%random%.tmp & ...` | Script de enumeração |
| **File Path (Regex)** | `C:\Users\VM\AppData\Local\Temp\user_info_*.tmp` | Ficheiro de staging de exfiltração |
| **Host** | `DESKTOP-2AHHAUL` | Máquina comprometida |
| **Usuário** | `DESKTOP-2AHHAUL\VM` | Conta sob ataque |
| **SHA256 (net.exe)** | `9F376759BCBCD705F726460FC4A7E2B07F310F52BAA73CAAAAA124FDDBDF993E` | Hash Legítimo |

---

## 6. Contenção

> ⚠️ Em ambiente de produção:

### 6.1 Ações Imediatas (0-1h)

* [ ] Isolar logicamente a máquina `DESKTOP-2AHHAUL` da rede corporativa.
* [ ] Preservar o estado da máquina para recolher o ficheiro `user_info_*.tmp` criado na pasta `AppData\Local\Temp\` para perícia forense.
* [ ] Investigar o que originou o processo `cmd.exe` (PID 3712). Identificar o "Avô" do processo (ex: Word.exe, PowerShell.exe, serviço web compromissado).
* [ ] Bloquear a conta `VM` temporariamente no Ative Directory/Local, uma vez que a mesma está a ser usada para o reconhecimento local.

### 6.2 Ações de Curto Prazo (1-24h)

* [ ] Correlacionar logs para verificar se ocorreram ligações de rede suspeitas (Sysmon Event ID 3) subsequentes a este evento (possível exfiltração do ficheiro `.tmp`).
* [ ] Procurar o mesmo padrão de linha de comandos (Query KQL) no restante parque informático.

**Query de investigação para Movimento Lateral:**

```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "1" and
winlog.event_data.ParentCommandLine: *user_info_%random%.tmp*

```

---

## 7. Erradicação e 8. Recuperação

> ⚠️ Em ambiente de produção:

* Remover o processo/artefato que originou a shell inicial e o `cmd.exe`.
* Apagar os ficheiros de staging de dados (o ficheiro `.tmp`).
* Rodar (reset) as credenciais da conta `DESKTOP-2AHHAUL\VM` e das contas locais com privilégios.
* Reconectar a máquina após atestar que a shell reversa ou backdoor inicial foi eliminada.

---

## 9. Lições Aprendidas

### O que funcionou bem

* ✅ O Winlogbeat enviou os logs quase em tempo real (2 segundos).
* ✅ O Sysmon registou a linha de comandos do processo Pai de forma intacta, o que foi essencial para confirmar a natureza maliciosa (sem a visualização do ParentCommandLine, pareceria apenas uma execução simples de `net users`).

### Oportunidades de melhoria

**Melhorar a Severidade Dinâmica da Regra:**
A regra atual gerou severidade **Medium**. Podemos criar uma regra paralela de severidade **Critical** se detetar enumeração combinada com redirecionamento de ficheiros na pasta Temp:

```kql
event.provider: "Microsoft-Windows-Sysmon" and
event.code: "1" and
winlog.event_data.Image: *net.exe* and
winlog.event_data.ParentCommandLine: (*> * or *>> *) and
winlog.event_data.ParentCommandLine: (*temp* or *tmp*)

```

---

## 10. Referências

| Fonte | Link |
| --- | --- |
| MITRE ATT&CK T1087.001 | [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/) |
| Atomic Red Team T1087.001 | [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) |
| Elastic Security Rule - Net.exe | [https://www.elastic.co/guide/en/security/current/account-discovery-command-line.html](https://www.google.com/search?q=https://www.elastic.co/guide/en/security/current/account-discovery-command-line.html) |

---

## 11. Classificação Final

| Campo | Valor |
| --- | --- |
| **Tipo de Incidente** | Discovery — Local Account Discovery |
| **Vetor** | Scripting/Automatização Local em CMD |
| **Impacto** | Baixo (ambiente controlado de laboratório) |
| **Ponto de Atenção** | A Linha de Comandos do Processo Pai denota recolha clara de dados (Staging) |
| **Falso Positivo?** | Não — comportamento confirmado via Atomic Red Team T1087 |
| **Ação Tomada** | Documentado, analisado e monitorado |
| **Data de Fechamento** | 2026-05-23 |
| **Analista** | Henri Lopes |

---

*Este relatório foi produzido em ambiente de laboratório para fins educacionais.* *Todas as simulações foram realizadas em máquinas virtuais próprias e isoladas.* *Dados de alerta extraídos diretamente do Kibana SIEM — índice `.internal.alerts-security.alerts-default-000001*`