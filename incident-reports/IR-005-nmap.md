# 📋 Relatório de Incidente — IR-005

---

## Informações Gerais

| Campo | Detalhe |
| --- | --- |
| **ID do Incidente** | IR-005 |
| **Título** | Nmap Scan — Reconhecimento de Rede e Port Scan |
| **Alert UUID** | `4220bf58ca8e263e17a7b816b924d0d709ad116125dfcdaed5da288d2c1e999d` |
| **Rule UUID** | `a2cbbb70-c8f2-4a6f-91c8-60953e71e6dc` |
| **Data de Detecção** | 2026-05-22 |
| **Horário do Evento** | 03:52:20 UTC (Início do Scan) |
| **Horário do Alerta** | 03:57:54 UTC |
| **Tempo de Detecção** | ~5 minutos (agregado na janela de lookback) |
| **Analista** | Henri Lopes |
| **Severidade** | 🟡 Medium |
| **Risk Score** | 47 |
| **Status** | ✅ Resolvido |
| **Técnica MITRE** | T1046 — Network Service Discovery |
| **Tática MITRE** | Discovery |

---

## 1. Resumo Executivo

Em 2026-05-22 às 03:57:54 UTC, o Kibana SIEM gerou um alerta de severidade **Medium** identificando um comportamento anómalo de rede indicativo de um *Port Scan* (Varrimento de Portas).

O alerta foi disparado por uma regra **Threshold** focada em eventos do **Sysmon (Event ID 3 — Network Connection)**. A regra monitoriza múltiplas conexões de rede originadas de um único endereço IP suspeito num curto espaço de tempo. A análise revelou que **14 conexões distintas** foram estabelecidas a partir do IP `10.200.200.10` (identificado na arquitetura como a máquina atacante Kali Linux) em direção à máquina local.

A atividade foi confirmada como uma simulação laboratorial de reconhecimento utilizando a ferramenta **Nmap**, demonstrando a eficácia do SIEM em detetar as fases iniciais da *Kill Chain* de um ataque.

---

## 2. Linha do Tempo

| Horário (UTC) | Evento |
| --- | --- |
| 03:52:20 | Primeiro evento de conexão capturado pelo Sysmon (Event ID 3) |
| 03:55:51 | Criação/Atualização da regra de detecção no SIEM |
| 03:56:30 | Múltiplas conexões subsequentes continuam a ser registadas |
| 03:57:54 | O limite (threshold) de 10 conexões é ultrapassado (total de 14) |
| 03:57:54 | Alerta gerado e classificado como **open** para triagem |

---

## 3. Detecção

### 3.1 Regra Disparada

| Campo | Valor |
| --- | --- |
| **Nome da Regra** | Nmap Scan - Network Reconnaissance |
| **Rule ID** | `718fa31a-fa25-420c-be45-959c7667fafd` |
| **Tipo** | Threshold Rule |
| **Severidade** | Medium |
| **Risk Score** | 47 |
| **Lookback** | 6 minutos (`now-6m`) |
| **Threshold (Limite)** | > 10 ocorrências |
| **Contagem Real** | 14 ocorrências no período |
| **Query KQL** | `event.provider: "Microsoft-Windows-Sysmon" and event.code: "3" and winlog.event_data.SourceIp: "10.200.200.10"` |

---

## 4. Análise Técnica

### 4.1 A Ameaça do Reconhecimento de Rede

O reconhecimento de rede (Network Service Discovery) é frequentemente a primeira fase ativa de um ataque. Adversários utilizam ferramentas como o **Nmap** para interrogar ativamente uma máquina ou rede, enviando pacotes (TCP SYN, UDP, etc.) para milhares de portas com o objetivo de descobrir quais os serviços que estão à escuta (ex: RDP, SMB, HTTP), os respetivos números de versão e potenciais vulnerabilidades.

### 4.2 Análise do Comportamento (Event ID 3)

Num cenário normal, o tráfego de rede corporativo costuma apresentar ligações pontuais e direcionadas a portas específicas conhecidas. No entanto, o log agregado pelo SIEM mostrou o IP `10.200.200.10` a iniciar rapidamente um volume elevado de conexões de entrada (*Inbound*) contra o host vítima num espaço de poucos minutos.

O Sysmon regista cada uma destas tentativas através do **Event ID 3**. Como a regra foi configurada como *Threshold* (Limite > 10), o analista não foi inundado com 14 alertas separados, mas recebeu um único incidente acionável que resume o comportamento da máquina atacante.

### 4.3 Índice de Suspeição

| Fator | Avaliação | Peso |
| --- | --- | --- |
| > 10 conexões do mesmo Source IP num curto período | 🔴 Altamente Suspeito | Alto |
| Source IP pertencente a rede/segmento não confiável | ⚠️ Suspeito | Médio |
| Volume e rapidez das conexões (Varrimento) | 🔴 Altamente Suspeito | Alto |
| Simulação via Nmap (Laboratório) | ✅ Confirmado | — |

**Conclusão:** O padrão de tráfego é a assinatura clássica de um Port Scan agressivo.

---

## 5. Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Contexto |
| --- | --- | --- |
| **Source IP** | `10.200.200.10` | IP da máquina que originou o varrimento (Kali Linux) |
| **Target Host** | `DESKTOP-2AHHAUL` | Máquina alvo do reconhecimento |
| **Target IP** | `10.200.200.20` | IP da máquina vítima |
| **Event Type** | `Sysmon Event ID 3` | Conexão de Rede Detectada |

---

## 6. Contenção

> ⚠️ Em ambiente de produção:

### 6.1 Ações Imediatas (0-1h)

* [ ] **Bloqueio no Firewall:** Adicionar o IP de origem (`10.200.200.10`) à lista de bloqueio (Blocklist) do Firewall de borda ou do IPS/IDS da rede para interromper o reconhecimento em curso.
* [ ] Analisar os logs para verificar quais portas específicas foram atingidas pelo scan (para entender o foco do atacante).

### 6.2 Ações de Curto Prazo (1-24h)

* [ ] **Análise Pós-Scan:** O port scan em si não é um comprometimento, mas sim o precursor de um. O passo crítico seguinte é **cruzar dados**: verificar se houve algum log de exploração de vulnerabilidade, tentativas de login falhadas (brute-force) ou tráfego invulgar com origem no IP do atacante *após* a janela do scan.
* [ ] Identificar a quem pertence o IP (externo ou movimento lateral de outra máquina interna comprometida?).

---

## 7. Lições Aprendidas e Tuning de Regras

### O que funcionou bem

* ✅ A utilização da lógica de **Threshold** funcionou perfeitamente para detetar um evento volumétrico (como um scan) sem causar "fadiga de alertas" (*alert fatigue*) ao analista SOC.
* ✅ O período de observação de 6 minutos (`now-6m`) foi suficiente para captar o comportamento de scan rápido.

### Oportunidades de melhoria

**1. Generalizar a Regra (Agnóstica de IP):**
Atualmente a regra está com um "hardcode" para o IP do Kali (`10.200.200.10`). Num cenário de SOC real, a regra deve ser agnóstica em relação ao IP de origem e deve alertar sobre *qualquer* IP externo ou de VPN que atinja este volume de conexões.

*Sugestão de KQL para ambiente corporativo:*

```kql
event.provider: "Microsoft-Windows-Sysmon" and 
event.code: "3" and 
network.direction: ("inbound" or "ingress")

```

*Configuração do Threshold:* Agrupar por `source.ip` e acionar se Count > 50 em 5 minutos.

---

## 8. Referências

| Fonte | Link |
| --- | --- |
| MITRE ATT&CK T1046 | [https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/) |
| Nmap Reference Guide | [https://nmap.org/book/man.html](https://nmap.org/book/man.html) |
| Elastic Security - Port Scan Rule | [https://www.elastic.co/guide/en/security/current/network-port-scanning.html](https://www.google.com/search?q=https://www.elastic.co/guide/en/security/current/network-port-scanning.html) |

---

## 9. Classificação Final

| Campo | Valor |
| --- | --- |
| **Tipo de Incidente** | Discovery — Network Service Scanning |
| **Vetor** | Varrimento de rede via ferramenta Nmap |
| **Impacto** | Informativo / Pré-Comprometimento |
| **Falso Positivo?** | Não — Simulação controlada de scan originada do Kali Linux |
| **Ação Tomada** | Documentado e monitorizado para possíveis ataques subsequentes |
| **Data de Fechamento** | 2026-05-22 |
| **Analista** | Henri Lopes |