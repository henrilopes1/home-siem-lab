# 🔵 Home SIEM Lab — Elastic Stack

![SIEM](https://img.shields.io/badge/SIEM-Elastic%20Stack-blue)
![Status](https://img.shields.io/badge/Status-Ativo-green)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC-informational)

## 📌 Objetivo

Construir um ambiente SOC doméstico funcional para detecção de ameaças em tempo real, simulando ataques reais e desenvolvendo habilidades de Blue Team. O projeto cobre desde a infraestrutura até a criação de regras de detecção mapeadas ao framework MITRE ATT&CK.

---

## 🏗️ Arquitetura

> 📷 _Diagrama será adicionado em breve_

```
┌──────────────────────────────────────────────────┐
│              Rede Interna VirtualBox             │
│              10.200.200.0/24                     │
│                                                  │
│  ┌───────────────┐       ┌───────────────────┐   │
│  │   Kali Linux  │──────▶│   Windows 10      │   │
│  │   Atacante    │       │   Vítima          │   │
│  │ 10.200.200.10 │       │  10.200.200.20    │   │
│  └───────────────┘       │  + Sysmon         │   │
│                          │  + Winlogbeat     │   │
│                          └────────┬──────────┘   │
│                                   │              │
│                          ┌────────▼──────────┐   │
│                          │  Ubuntu Server    │   │
│                          │  ELK Stack        │   │
│                          │  10.200.200.30    │   │
│                          │  Elasticsearch    │   │
│                          │  Kibana           │   │
│                          └───────────────────┘   │
└──────────────────────────────────────────────────┘
```

---

## 🛠️ Ferramentas Utilizadas

| Ferramenta | Versão | Função |
|---|---|---|
| Elasticsearch | 8.x | Armazenamento e indexação de logs |
| Kibana | 8.x | Visualização, dashboards e alertas |
| Winlogbeat | 9.x | Coleta de logs do Windows |
| Sysmon | Latest | Telemetria avançada do Windows |
| Atomic Red Team | Latest | Simulação de ataques MITRE ATT&CK |
| Hydra | 9.x | Simulação de brute force |
| Nmap | Latest | Simulação de reconhecimento de rede |
| Mimikatz | 2.x | Simulação de dump de credenciais |
| VirtualBox | Latest | Virtualização do ambiente |

---

## 🎯 Detection Rules Criadas

| # | Regra | Técnica MITRE | Severidade | Evento |
|---|---|---|---|---|
| 1 | Brute Force - Failed Logon Detection | T1110 | 🟡 Medium | Event ID 4625 |
| 2 | Reverse Shell - Suspicious Outbound Connection | T1059 | 🔴 High | Sysmon ID 3, porta 4444 |
| 3 | Nmap Scan - Network Reconnaissance | T1046 | 🟡 Medium | Sysmon ID 3, source Kali |
| 4 | Mimikatz - Credential Dumping | T1003 | 🔴 Critical | Sysmon ID 1, mimikatz.exe |
| 5 | Suspicious Rundll32 Execution | T1218.011 | 🟡 Medium | Sysmon ID 1, rundll32.exe |
| 6 | System Owner Discovery - Whoami | T1033 | 🟢 Low | Sysmon ID 1, whoami.exe |
| 7 | Account Discovery - Net.exe | T1087 | 🟡 Medium | Sysmon ID 1, net.exe |

---

## ⚔️ Ataques Simulados

### 1. Brute Force RDP — T1110

**Ferramenta:** Hydra  
**Origem:** Kali Linux  
**Detecção:** Event ID 4625 — múltiplos logins falhados

```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://10.200.200.20
```

> 📷 _Screenshot do ataque será adicionado em breve_

---

### 2. Reverse Shell — T1059

**Ferramenta:** Netcat + PowerShell  
**Origem:** Kali Linux  
**Detecção:** Sysmon Event ID 3 — conexão de saída na porta 4444

```bash
# Kali - Listener
nc -lvnp 4444
```

```powershell
# Windows - Reverse Shell
powershell -ExecutionPolicy Bypass -File C:\shell.ps1
```

> 📷 _Screenshot do ataque será adicionado em breve_

---

### 3. Reconhecimento de Rede — T1046

**Ferramenta:** Nmap  
**Origem:** Kali Linux  
**Detecção:** Sysmon Event ID 3 — múltiplas conexões do IP do Kali

```bash
nmap -sS -A 10.200.200.20
```

> 📷 _Screenshot do ataque será adicionado em breve_

---

### 4. Dump de Credenciais — T1003

**Ferramenta:** Mimikatz  
**Origem:** Windows (local)  
**Detecção:** Sysmon Event ID 1 — execução do mimikatz.exe

```
privilege::debug
sekurlsa::logonpasswords
```

> 📷 _Screenshot do ataque será adicionado em breve_

---

### 5. Simulações com Atomic Red Team — T1033, T1087, T1218

**Ferramenta:** Atomic Red Team  
**Origem:** Windows (local)  
**Detecção:** Sysmon Event ID 1 — processos suspeitos

```powershell
Invoke-AtomicTest T1033    # System Owner Discovery
Invoke-AtomicTest T1087    # Account Discovery
Invoke-AtomicTest T1218.011 # Signed Binary Proxy Execution
Invoke-AtomicTest T1059.001 # PowerShell
```

> 📷 _Screenshot do ataque será adicionado em breve_

---

## 📊 Dashboards Kibana

> 📷 _Screenshots dos dashboards serão adicionados em breve_

### Visualizações criadas:
- **Alertas por Severidade** — Gráfico de pizza (Critical / High / Medium / Low)
- **Alertas por Regra** — Gráfico de barras com todas as detection rules
- **Timeline de Ataques** — Gráfico de área com linha do tempo
- **Top Eventos Sysmon** — Distribuição dos Event IDs capturados

---

## 📈 Resultados Obtidos

| Métrica | Resultado |
|---|---|
| Detection Rules criadas | 7 |
| Alertas gerados em simulações | 43+ |
| Técnicas MITRE cobertas | 7 |
| Fontes de log | Windows Event Log + Sysmon |
| Campos indexados | 354 |

---

## 🗂️ Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Regra de Detecção |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | Brute Force - Failed Logon |
| Execution | Command & Scripting | T1059 | Reverse Shell Detection |
| Discovery | Network Service Scan | T1046 | Nmap Scan Detection |
| Credential Access | OS Credential Dumping | T1003 | Mimikatz Execution |
| Defense Evasion | Signed Binary Proxy | T1218.011 | Suspicious Rundll32 |
| Discovery | System Owner/User | T1033 | Whoami Execution |
| Discovery | Account Discovery | T1087 | Net.exe Discovery |

---

## 📁 Estrutura do Repositório

```
home-siem-lab/
├── README.md
├── configs/
│   ├── winlogbeat.yml          # Configuração do Winlogbeat
│   └── kibana.yml              # Configuração do Kibana
├── rules/
│   ├── brute-force.json        # Detection rule exportada
│   ├── reverse-shell.json
│   ├── nmap-scan.json
│   ├── mimikatz.json
│   ├── rundll32.json
│   ├── whoami.json
│   └── net-discovery.json
├── incident-reports/
│   └── IR-001-brute-force.md   # Relatório de incidente formal
└── screenshots/
    ├── 01-elk-running.png
    ├── 02-kibana-discover.png
    ├── 03-event-4625.png
    ├── 04-hydra-attack.png
    ├── 05-reverse-shell.png
    ├── 06-mimikatz.png
    ├── 07-alerts-dashboard.png
    └── 08-kibana-dashboard.png
```

---

## 🚀 Como Reproduzir

### Pré-requisitos
- VirtualBox instalado
- 16GB RAM no host
- ISOs: Ubuntu Server 22.04, Windows 10, Kali Linux

### Passo a passo

**1. Configurar as VMs**
```
Ubuntu Server → 3GB RAM → Rede Interna + NAT
Windows 10   → 2GB RAM → Rede Interna + NAT
Kali Linux   → 1.5GB RAM → Rede Interna + NAT
```

**2. Instalar Elastic Stack (Ubuntu Server)**
```bash
# Adicionar repositório
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update

# Instalar
sudo apt install elasticsearch kibana -y
sudo systemctl enable --now elasticsearch kibana
```

**3. Instalar Sysmon (Windows)**
- Baixar Sysmon em: https://learn.microsoft.com/sysinternals/downloads/sysmon
- Baixar config SwiftOnSecurity
```powershell
.\Sysmon64.exe -accepteula -i C:\sysmonconfig.xml
```

**4. Instalar Winlogbeat (Windows)**
- Baixar em: https://www.elastic.co/downloads/beats/winlogbeat
- Configurar `winlogbeat.yml` com o IP do ELK
- Instalar e iniciar o serviço

**5. Simular ataques e monitorar alertas**
- Acessar Kibana: `http://IP_ELK:5601`
- Importar detection rules
- Executar simulações

---

## 📝 Incident Reports

| ID | Incidente | Data | Status |
|---|---|---|---|
| IR-001 | Brute Force RDP | 2026-05-21 | ✅ Documentado |

---

## 👤 Autor

**Henri Lopes**  
Cybersecurity — Blue Team | SOC Analyst  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Conectar-blue?logo=linkedin)](https://www.linkedin.com/in/henri-de-oliveira-lopes/)

---

## ⚠️ Aviso Legal

Este projeto foi desenvolvido exclusivamente para fins educacionais em ambiente isolado e controlado. Todas as simulações de ataque foram realizadas em máquinas virtuais próprias. Nunca utilize estas técnicas em sistemas sem autorização explícita.
