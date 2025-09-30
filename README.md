<div align="center" style="background-color:black; padding: 20px 0;">
  <img src="https://i.ibb.co/0jCTqKkj/upscalemedia-transformed.png" alt="PADOCCA Security Framework v2.0" width="600"/>
</div>

# PADOCCA Security Framework v2.0

![Version](https://img.shields.io/badge/version-2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

## Elite • Stealth • Undetectable

PADOCCA é uma framework de segurança ofensiva de última geração que combina reconhecimento avançado, detecção de vulnerabilidades e modo stealth adaptativo para testes de penetração profissionais.

## 🚀 O que há de novo:

### ✨ Novos Módulos Principais
- **🔍 Subdomain Discovery Avançado**: 20+ fontes de dados com validação inteligente
- **🕰️ Wayback Machine Integration**: Descoberta de URLs históricas com validação
- **📝 Template-based Scanning**: Sistema estilo Nuclei para detecção de vulnerabilidades
- **🔄 Pipeline Orchestration**: Execução declarativa de ataques via YAML
- **🥷 Stealth Mode v2.0**: Sistema completo de evasão com 5 níveis adaptáveis
- **🛡️ WAF Detection & Bypass**: Detecção e bypass automático de WAF/IPS
- **💾 Cache Inteligente**: Sistema de cache com TTL configurável

## 📦 Instalação Rápida

```bash
git clone https://github.com/DonatoReis/padocca.git
cd padocca
./install.sh
```

## 🎯 Uso Básico

### Scan Completo (14 módulos)
```bash
# Scan básico
./padocca.sh --scan example.com

# Scan em modo stealth
./padocca.sh --scan example.com --stealth

# Scan + pipeline de ataque completo
./padocca.sh --scan example.com --full

# Ultimate stealth attack
./padocca.sh --scan example.com --stealth --full
```

## 🛠️ Módulos Disponíveis

### Core (Básicos)
- `--scan` - Scan completo com 14 módulos
- `--dns` - Enumeração DNS
- `--ports` - Scan de portas
- `--crawl` - Web crawler
- `--fuzzer` - Directory fuzzing
- `--ssl` - Análise SSL/TLS
- `--email` - Análise de segurança de email

### Avançados
- `--xss-sqli` - Scanner XSS/SQLi com bypass WAF
- `--osint` - Inteligência OSINT profunda
- `--bruteforce` - Bruteforce inteligente
- `--subdiscover` - Descoberta de subdomínios (20+ fontes)
- `--wayback` - URLs históricas
- `--template-scan` - Scan baseado em templates
- `--pipeline` - Execução de pipeline YAML

### Stealth Mode
- `--stealth scan` - Scan ultra-silencioso
- `--stealth config` - Ver configuração
- `--stealth proxy` - Gerenciar proxies
- `--stealth test` - Testar capacidades

## 🥷 Stealth Mode - Níveis

| Nível | Nome | Descrição |
|-------|------|-----------|
| 0 | Disabled | Sem stealth |
| 1 | Low | Randomização básica |
| 2 | Medium | Proxies + timing |
| 3 | High | Fragmentação + adaptativo |
| 4 | Paranoid | Todas técnicas + decoys |

### Técnicas de Evasão Implementadas
- ✅ Randomização de User-Agent (50+ agents)
- ✅ Headers dinâmicos rotativos
- ✅ Timing adaptativo gaussiano
- ✅ Suporte a proxies residenciais
- ✅ Fragmentação de pacotes
- ✅ Tráfego decoy para camuflagem
- ✅ Encoding multi-camada
- ✅ Session management
- ✅ Anti-forensics automático

## 📋 Pipelines Declarativas

### Exemplo de Pipeline YAML
```yaml
name: "Web Pentest Complete"
stages:
  - name: reconnaissance
    steps:
      - module: subdiscovery
        config:
          target: "{{.target}}"
          sources: ["all"]
      
  - name: scanning
    parallel: true
    steps:
      - module: portscan
      - module: wayback
      
  - name: exploitation
    manual_approval: true
    steps:
      - module: template_scan
        config:
          templates: ["critical", "high"]
```

### Executar Pipeline
```bash
# Pipeline padrão
./padocca.sh --pipeline pipelines/pentest-web.yaml -t example.com

# Pipeline stealth
./padocca.sh --pipeline pipelines/stealth-web-pentest.yaml -t example.com
```

## 🎯 O que o Full Scan faz?

O comando `--scan` agora executa **14 módulos** organizados em 4 fases:

### FASE 1: Reconhecimento Passivo
1. **Subdomain Discovery** - 20+ fontes de dados
2. **Wayback URLs** - URLs históricas
3. **DNS Enumeration** - Zone transfer, registros
4. **OSINT Intelligence** - Coleta de inteligência

### FASE 2: Reconhecimento Ativo
5. **WAF Detection** - Detecta e prepara bypass
6. **Port Scanning** - Scan adaptativo
7. **Web Crawling** - Spider profundo
8. **SSL Analysis** - Análise TLS/SSL

### FASE 3: Avaliação de Vulnerabilidades
9. **Template Scanning** - Detecção via templates
10. **XSS/SQLi Scanner** - Com bypass WAF
11. **Directory Fuzzing** - Descoberta de diretórios

### FASE 4: Análise Avançada
12. **Email Security** - SPF/DMARC/DKIM
13. **Tech Fingerprinting** - Stack tecnológico
14. **API Discovery** - Endpoints de API

## 📊 Estatísticas e Performance

| Módulo | Performance | Concorrência |
|--------|------------|--------------|
| Subdomain Discovery | ~1000/min | 20 workers |
| Wayback URLs | ~1000/sec | 10 workers |
| Port Scanning | 65K ports/30s | 100 workers |
| Template Scan | 100 templates/min | 20 workers |

## 🔧 Configuração

### Proxies (config/proxies.txt)
```
socks5://127.0.0.1:9050  # Tor
http://proxy.com:8080
https://user:pass@proxy2.com:3128
```

### Templates (templates/)
- SQL Injection templates
- XSS templates  
- XXE templates
- RCE templates
- Custom YAML templates

## 🏗️ Arquitetura

```
Padocca/
├── bin/                # Binários compilados
├── pipelines/         # Pipelines YAML
├── templates/         # Templates de vulnerabilidades
├── config/            # Configurações
├── results/           # Resultados dos scans
├── tools-go/          # Módulos em Go (70%)
├── core-rust/         # Core em Rust (25%)
└── docs/              # Documentação
```

## 🔒 Segurança

- **False Positive Reduction**: Validação comportamental
- **WAF Evasion**: Bypass automático
- **Stealth Operations**: 5 níveis de discrição
- **Cache Intelligence**: Evita re-scans desnecessários
- **Adaptive Timing**: Ajusta baseado em respostas

## 📈 Roadmap

- [ ] Execução distribuída (cluster mode)
- [ ] Plugin marketplace
- [ ] GUI web interface
- [ ] Integration with Metasploit
- [ ] AI-powered exploitation
- [ ] Zero-day discovery engine

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:
1. Fork o projeto
2. Crie sua feature branch
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## ⚠️ Aviso Legal

Esta ferramenta é destinada apenas para testes autorizados de segurança. O uso não autorizado é ilegal e antiético.

## 📜 Licença

MIT License - veja LICENSE para detalhes

## 🙏 Créditos

Desenvolvido com ❤️ pela PADOCCA Security Team

---

**Para suporte**: security@padocca.com  
**Documentação completa**: [docs/FEATURES.md](docs/FEATURES.md)
