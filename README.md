# MTScan - Linux Vulnerability Analysis Toolkit

**[English](#english) | [Português Brasileiro](#português-brasileiro)**

---

## English

A comprehensive security toolkit for automated vulnerability scanning and analysis, designed **exclusively for Linux systems**.

### Recent Enhancements

**LATEST UPDATE: Internet Connectivity Check Fixed**
- **Internet Connectivity Check**: Fixed and re-enabled in setup.py for Linux systems
- **Network Validation**: Multi-method connectivity testing (DNS, Socket, Ping, HTTP)
- **Linux VM Optimized**: Tested and working on Linux virtual machines
- **No Emoji Output**: Clean, professional text-only output formatting

**Previous Updates:**
- **Interactive Menu Interface**: User-friendly `mtscan.py` interface for guided scanning
- **Network Connectivity Enforcement**: Automatic scan termination on network failure (no user prompts)
- **Port Information Display**: Real-time port range information during scans
- **Tool Path Resolution**: Fixed executable path detection for reliable tool execution
- **Output Formatting**: Clean, consistent output formatting across all interfaces
- **Enhanced Installation**: Master installer with comprehensive validation
- **Multi-Mode Support**: Interactive menu and direct command-line workflows

### Overview

This toolkit integrates powerful security tools (naabu, httpx, nuclei) into a streamlined workflow for vulnerability scanning. It automates the entire process from port scanning to vulnerability detection and report generation.

**IMPORTANT: This toolkit only works on Linux systems due to the security tools' dependencies on Linux kernel features and libraries.**

### Features

- **Comprehensive Scanning**: Automated port scanning, HTTP service detection, and vulnerability discovery
- **Enhanced Real-time Output**: Live port range information and scan progress display
- **Network Connectivity Enforcement**: Automatic scan termination if network connectivity fails
- **Zero-Configuration**: Just provide a target and the toolkit does the rest
- **Auto-Installation**: Automatically installs and configures all necessary tools
- **Report Generation**: Creates detailed vulnerability reports in multiple formats
- **Linux-Optimized**: Built specifically for Linux security environments
- **Multi-Distro Support**: Works on Debian, Ubuntu, Kali Linux, Arch Linux, and more
- **Clean Output Formatting**: Consistent, professional output across all scan types
- **Internet Connectivity Check**: Robust multi-method network validation
- **Interactive Menu System**: User-friendly interface with guided scanning options
- **Flexible Execution Modes**: Command-line, interactive menu, or workflow-based scanning
- **Real-time Progress Tracking**: Live updates during scanning operations
- **Comprehensive Error Handling**: Graceful failure management with detailed error reporting

### Supported Linux Distributions

- **Kali Linux** (Recommended for security testing)
- **Debian**
- **Ubuntu**
- **Arch Linux**
- **Fedora/CentOS/RHEL** (Basic support)

### System Requirements

- **Operating System**: Linux (64-bit)
- **Python**: 3.8 or higher
- **Memory**: Minimum 2GB RAM (4GB+ recommended)
- **Storage**: 1GB free space for tools and results
- **Network**: Internet connection required for installation and updates
- **Privileges**: Root/sudo access required for installation
- **Go Language**: Automatically installed by the master installer

### Quick Start

1. **Clone and Install** (5 minutes):
   ```bash
   git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
   cd linux-vulnerability-toolkit
   sudo python3 install/setup.py
   ```

2. **Verify Installation**:
   ```bash
   python3 tests/validate_installation.py
   ```

3. **Run Your First Scan**:
   ```bash
   python3 run.py example.com
   ```

## Installation

### Master Installation Orchestrator (Recommended)

The toolkit now features a comprehensive **single-point master installer** that handles everything automatically:

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Run the master installation orchestrator (requires root privileges)
sudo python3 install/setup.py
```


The master installer performs:
- Linux platform verification and distribution detection
- Root/sudo permission enforcement 
- **NEW**: Anti-hang timeout protection for all operations
- **NEW**: Package manager lock file cleanup and repair
- System package installation with individual package tracking
- **NEW**: VM-optimized installation process (Kali Linux tested)
- Go programming environment setup with PATH management
- Security tools installation with timeout protection (naabu, httpx, nuclei)
- Python dependencies and virtual environment setup
- Configuration optimization and bash aliases creation
- Complete system verification with functionality testing

### Alternative Installation Methods

#### Option 1: Python Environment Setup Only

```bash
# For Python environment setup and validation only
python3 scripts/autoinstall.py
```


**Note:** Legacy shell scripts have been integrated into the master installer for a streamlined experience.

### Post-Installation Verification

After installation, verify everything is working:

```bash
# Comprehensive installation validation (Recommended)
python3 tests/validate_installation.py

# Python environment validation
python3 scripts/autoinstall.py

# Legacy tool validation
python3 tests/verify_installation.py
```

## Architecture

### Enhanced Master Installer Architecture

The toolkit features a **streamlined single-point master installer** architecture with integrated functionality:

```
Linux Vulnerability Analysis Toolkit/
├── install/
│   ├── setup.py                    # ENHANCED MASTER INSTALLER (All-in-One)
│   └── setup_backup_original.py   # Original backup
├── scripts/
│   ├── autoinstall.py             # Python environment setup & validation
│   └── run_toolkit.sh             # Main toolkit launcher
├── src/
│   ├── workflow.py                # Main scanning workflow
│   ├── utils.py                   # Core utilities
│   ├── reporter.py                # Report generation
│   ├── config_manager.py          # Configuration management
│   └── code_scanner.py            # Code scanning capabilities
├── commands/
│   ├── naabu.py                   # Port scanning commands
│   ├── httpx.py                   # HTTP service detection
│   └── nuclei.py                  # Vulnerability scanning
├── config/
│   └── requirements.txt           # Python dependencies
├── output/                        # Scan results output
├── reports/                       # Generated reports
└── tests/                         # Testing and validation
    ├── validate_installation.py   # Comprehensive validation script
    └── verify_installation.py     # Tool verification script
```

### Key Architecture Improvements

- **Integrated Functionality**: Legacy shell scripts consolidated into master installer
- **Enhanced Error Handling**: Robust UTF-8 encoding and dependency management
- **Comprehensive Validation**: Advanced installation verification system
- **Streamlined Workflow**: Simplified installation and usage process

### Installation Flow

1. **install/setup.py** (Enhanced Master Installer)
   - Platform verification & distribution detection
   - Root permission enforcement  
   - System package management
   - Go environment setup and PATH configuration
   - Security tools installation (naabu, httpx, nuclei)
   - Configuration generation and optimization
   - Integrated functionality from legacy scripts

2. **scripts/autoinstall.py** (Python Environment Manager)
   - Python dependencies validation
   - Virtual environment setup
   - Tool availability checking
   - Configuration file creation

3. **tests/validate_installation.py** (Comprehensive Validator)
   - Installation integrity verification
   - Tool functionality testing
   - Configuration validation
   - System compatibility checking

## Usage

### How to Run the Project

#### **Step 1: Installation (Linux Only)**

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Install everything with one command (requires root privileges)
sudo python3 install/setup.py
```

#### **Step 2: Validation (Recommended)**

```bash
# Verify installation is working correctly
python3 tests/validate_installation.py
```

#### **Step 3: Run Vulnerability Scans**

**Basic Scan:**

```bash
# Simple scan
python3 run.py <target>

# Example
python3 run.py example.com
```

**Using Shell Script:**

```bash
# Alternative launcher
bash scripts/run_toolkit.sh <target>
```

### Advanced Usage Options

```bash
# Specify custom ports
python3 run.py --target example.com --ports 80,443,8080-8090

# Use specific nuclei templates
python3 run.py --target example.com --templates cves,exposures

# Comprehensive scan with filtering
python3 run.py --target example.com --ports top-1000 --tags cve,exposure --severity critical,high

# Verbose output for debugging
python3 run.py --target example.com --verbose
```

### Additional Options

- `--verbose`: Display more detailed output
- `--timeout`: Set maximum scan timeout in seconds
- `--scan-code`: Enable code scanning for web applications
- `--auto-config`: Automatically configure tools based on system capabilities

### Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `python3 run.py <target>` | Basic vulnerability scan | `python3 run.py example.com` |
| `python3 mtscan.py` | Interactive menu interface | Launch guided scanning |
| `bash scripts/run_toolkit.sh <target>` | Alternative launcher | `bash scripts/run_toolkit.sh example.com` |
| `python3 tests/validate_installation.py` | Validate installation | Check system status |
| `python3 scripts/autoinstall.py` | Python environment setup | Setup dependencies |
| `sudo python3 install/setup.py` | Master installer | Complete system setup |

### Interactive Menu System

The toolkit includes an intuitive interactive menu system via `mtscan.py`:

```bash
# Launch interactive menu
python3 mtscan.py
```

**Menu Features:**
- **Guided Target Selection**: Step-by-step target input with validation
- **Scan Type Selection**: Choose between quick, comprehensive, or custom scans
- **Real-time Progress**: Live updates and status information
- **Result Management**: Easy access to scan results and reports
- **Tool Configuration**: Interactive tool setup and verification

### Scan Types and Modes

#### 1. Quick Scan (Recommended for beginners)
```bash
python3 run.py --quick <target>
```
- Top 1000 ports
- Basic vulnerability templates
- Fast execution time

#### 2. Comprehensive Scan (Recommended for thorough analysis)
```bash
python3 run.py --comprehensive <target>
```
- All ports (1-65535)
- Complete vulnerability template set
- Detailed service enumeration

#### 3. Custom Scan (Advanced users)
```bash
python3 run.py --target <target> --ports <ports> --templates <templates>
```
- User-defined port ranges
- Specific vulnerability templates
- Custom timeout and threading options

**For detailed usage instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md)**

## Output

Results are saved in a timestamped directory (e.g., `results_example.com_20250603_120101/`) including:

- `ports.txt`: Discovered open ports
- `http_services.txt`: Discovered HTTP services
- `vulnerabilities.txt`: Discovered vulnerabilities
- `report.html`: Comprehensive HTML report
- `report.json`: JSON data for further processing

## Validation & Troubleshooting

### Installation Validation

Always validate your installation after setup:

```bash
# Comprehensive installation validation
python3 tests/validate_installation.py

# Python environment validation
python3 scripts/autoinstall.py

# Legacy tool validation
python3 tests/verify_installation.py
```


### Common Issues & Solutions

#### 1. **Master Installer Issues**

```bash
# Problem: Permission denied during installation
sudo python3 install/setup.py

# Problem: Platform not supported
# Solution: Use Linux (Debian/Ubuntu/Kali/Arch only)
```

#### 2. **Security Tools Missing**

```bash
# Check tool availability
which naabu httpx nuclei

# Reinstall tools (master installer handles Go PATH automatically)
sudo python3 install/setup.py

# Manual tool installation if needed
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

#### 3. **Python Environment Issues**

```bash
# Validate Python setup
python3 scripts/autoinstall.py

# Check Python version (3.8+ required)
python3 --version

# Install missing Python packages
pip3 install -r config/requirements.txt
```

#### 4. **Configuration Problems**

```bash
# Regenerate configuration and validate installation
python3 scripts/autoinstall.py

# Run comprehensive validation
python3 tests/validate_installation.py

# Fix permissions
chmod +x scripts/*.sh
```


### Linux Distribution-Specific Issues

#### **Debian/Ubuntu/Kali**

```bash
# The master installer now handles all repository and package issues automatically
sudo python3 install/setup.py

# Manual fixes if needed:
sudo apt update && sudo apt upgrade
sudo apt install build-essential curl wget git python3-pip
```

#### **Arch Linux**

```bash
# Update system first
sudo pacman -Syu

# Install base development tools (handled by master installer)
sudo pacman -S base-devel go git curl wget python3-pip
```

#### **Fedora/CentOS/RHEL**

```bash
# Install development tools (handled by master installer)
sudo dnf groupinstall "Development Tools"
sudo dnf install golang git curl wget python3-pip
```


### Performance Optimization

#### **System Tuning for Better Performance**

```bash
# Increase file descriptor limits (temporary)
ulimit -n 65536

# Optimize network parameters (requires root)
echo 'net.core.rmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p
```

#### **Scan Optimization Options**

```bash
# Fast scan with optimized settings
python3 run.py --target example.com --threads 50 --timeout 5

# Conservative scan for unstable networks
python3 run.py --target example.com --threads 10 --timeout 10 --delay 100ms

# Maximum performance scan (use with caution)
python3 run.py --target example.com --threads 100 --timeout 3 --rate 1000
```

### Advanced Troubleshooting

#### **Complete Reset & Reinstall**

```bash
# 1. Clean previous installation
rm -rf ~/go/bin/{naabu,httpx,nuclei}

# 2. Run enhanced master installer
sudo python3 install/setup.py

# 3. Validate installation
python3 tests/validate_installation.py
```

#### **Manual Tool Installation**

```bash
# Install Go manually
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install tools manually
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

#### **Debug Mode**

```bash
# Run with verbose output
python3 run.py --target example.com --verbose

# Check tool versions
naabu -version && httpx -version && nuclei -version

# Test individual tools
echo "example.com" | naabu -top-ports 10
echo "http://example.com" | httpx -title
nuclei -target example.com -t cves/
```


## Security Considerations

### Legal and Ethical Guidelines

- **Authorization Required**: Always obtain explicit written permission before scanning any targets
- **Scope Limitations**: Only scan systems you own or have explicit authorization to test
- **Responsible Disclosure**: Report discovered vulnerabilities through proper channels
- **Data Protection**: Handle scan results and sensitive information according to applicable laws

### Best Practices

- **Isolated Environment**: Use dedicated security testing environments when possible
- **Rate Limiting**: Use appropriate scan speeds to avoid overwhelming target systems
- **Log Management**: Maintain detailed logs of all scanning activities
- **Result Security**: Encrypt and securely store scan results containing sensitive information

### Recommended Testing Environment

```bash
# Example: Setting up a controlled testing environment
# Use VirtualBox/VMware with isolated network segments
# Deploy intentionally vulnerable applications (DVWA, WebGoat, etc.)
python3 run.py 192.168.56.101  # VMware/VirtualBox host-only network
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Usage Modes

### Individual Tool Mode
Perfect for targeted assessments or when you only need specific functionality:

- **Port Scanning Only**: `-naabu -host <target>`
- **HTTP Service Discovery**: `-httpx -host <target>`
- **Vulnerability Assessment**: `-nuclei -host <target>`

### Combined Tool Mode
Run multiple tools in sequence with automatic result chaining:

- **naabu → nuclei**: Port scan followed by vulnerability assessment
- **httpx → nuclei**: HTTP discovery followed by vulnerability scanning
- **naabu → httpx → nuclei**: Complete chain with all tools

### Full Workflow Mode
Traditional mode that runs all tools automatically:

```bash
sudo python src/workflow.py <target>
```

## Tool Configuration

The toolkit automatically detects tool installations in common locations:

### naabu
- `/usr/bin/naabu`
- `/usr/local/bin/naabu`
- `/root/go/bin/naabu`
- `~/go/bin/naabu`

### httpx
- `/usr/bin/httpx` (Kali Linux system package)
- `/usr/local/bin/httpx`
- `/root/go/bin/httpx`
- `~/go/bin/httpx`

### nuclei
- `/usr/bin/nuclei`
- `/usr/local/bin/nuclei`
- `/root/go/bin/nuclei`
- `~/go/bin/nuclei`

## Output Structure

Results are organized in timestamped directories:

### Individual Tool Mode

```
results_<target>_<tools>_<timestamp>/
├── ports.txt              # naabu results (if used)
├── ports.json              # naabu JSON output
├── http_services.txt       # httpx results (if used)
├── http_services.json      # httpx JSON output
├── vulnerabilities.txt     # nuclei results (if used)
├── vulnerabilities.jsonl   # nuclei JSONL output
├── nuclei_responses/       # HTTP responses (if nuclei used)
└── summary.txt            # Executive summary
```

### Full Workflow Mode

```
results_<target>_<timestamp>/
├── ports.txt
├── ports.json
├── http_services.txt
├── http_services.json
├── vulnerabilities.txt
├── vulnerabilities.jsonl
├── nuclei_responses/
├── code_vulnerabilities.md (if --scan-code used)
└── summary.txt
```

## Examples

### Basic Port Scanning

```bash
# Quick port scan
sudo python src/workflow.py -naabu -host 192.168.1.1

# Custom ports
sudo python src/workflow.py -naabu -host 192.168.1.1 -p "22,80,443,8080"

# Top 100 ports only
sudo python src/workflow.py -naabu -host 192.168.1.1 -p "top-100"
```

### HTTP Service Discovery

```bash
# Basic HTTP enumeration
sudo python src/workflow.py -httpx -host example.com

# From previous port scan results
sudo python src/workflow.py -naabu -httpx -host 192.168.1.1
```

### Vulnerability Assessment

```bash
# Target-based scanning
sudo python src/workflow.py -nuclei -host https://example.com

# Chain with service discovery
sudo python src/workflow.py -httpx -nuclei -host 192.168.1.1

# Custom severity levels
sudo python src/workflow.py -nuclei -host example.com --severity "critical,high"
```

### Complete Assessments

```bash
# Full automated scan
sudo python src/workflow.py 192.168.1.1

# Full scan with stealth mode
sudo python src/workflow.py 192.168.1.1 -s

# Comprehensive assessment with all options
sudo python src/workflow.py -naabu -httpx -nuclei -host 192.168.1.1 -s -v --json-output
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test on multiple Linux distributions
4. Submit a pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Disclaimer

This toolkit is designed for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any targets. The authors are not responsible for any misuse or damage caused by this software.

---

## Português Brasileiro

Um kit de ferramentas de segurança abrangente para varredura automatizada de vulnerabilidades e análise, projetado **exclusivamente para sistemas Linux**.

### Melhorias Recentes

**ATUALIZAÇÃO MAIS RECENTE: Verificação de Conectividade com a Internet Corrigida**
- **Verificação de Conectividade com Internet**: Corrigida e reabilitada no setup.py para sistemas Linux
- **Validação de Rede**: Testes de conectividade multi-método (DNS, Socket, Ping, HTTP)
- **Otimizado para VM Linux**: Testado e funcionando em máquinas virtuais Linux
- **Saída Sem Emoji**: Formatação de saída limpa e profissional apenas com texto

**Atualizações Anteriores:**
- **Interface de Menu Interativo**: Interface `mtscan.py` amigável para varredura guiada
- **Aplicação de Conectividade de Rede**: Término automático de varredura em falha de rede (sem prompts do usuário)
- **Exibição de Informações de Porta**: Informações de faixa de porta em tempo real durante varreduras
- **Resolução de Caminho de Ferramenta**: Detecção fixa de caminho executável para execução confiável de ferramenta
- **Formatação de Saída**: Formatação de saída limpa e consistente em todas as interfaces
- **Instalação Aprimorada**: Instalador mestre com validação abrangente
- **Suporte Multi-Modo**: Menu interativo e fluxos de trabalho de linha de comando diretos

### Visão Geral

Este kit de ferramentas integra ferramentas de segurança poderosas (naabu, httpx, nuclei) em um fluxo de trabalho simplificado para varredura de vulnerabilidades. Automatiza todo o processo desde varredura de portas até detecção de vulnerabilidades e geração de relatórios.

**IMPORTANTE: Este kit de ferramentas funciona apenas em sistemas Linux devido às dependências das ferramentas de segurança em recursos e bibliotecas do kernel Linux.**

### Características

- **Varredura Abrangente**: Varredura automatizada de portas, detecção de serviços HTTP e descoberta de vulnerabilidades
- **Saída Aprimorada em Tempo Real**: Informações de faixa de porta ao vivo e exibição de progresso de varredura
- **Aplicação de Conectividade de Rede**: Término automático de varredura se a conectividade de rede falhar
- **Configuração Zero**: Apenas forneça um alvo e o kit de ferramentas faz o resto
- **Auto-Instalação**: Instala e configura automaticamente todas as ferramentas necessárias
- **Geração de Relatórios**: Cria relatórios detalhados de vulnerabilidades em múltiplos formatos
- **Otimizado para Linux**: Construído especificamente para ambientes de segurança Linux
- **Suporte Multi-Distro**: Funciona em Debian, Ubuntu, Kali Linux, Arch Linux e mais
- **Formatação de Saída Limpa**: Saída profissional e consistente em todos os tipos de varredura
- **Verificação de Conectividade com Internet**: Validação de rede robusta multi-método
- **Sistema de Menu Interativo**: Interface amigável com opções de varredura guiada
- **Modos de Execução Flexíveis**: Varredura por linha de comando, menu interativo ou baseada em fluxo de trabalho
- **Rastreamento de Progresso em Tempo Real**: Atualizações ao vivo durante operações de varredura
- **Tratamento Abrangente de Erros**: Gerenciamento gracioso de falhas com relatórios detalhados de erro

### Distribuições Linux Suportadas

- **Kali Linux** (Recomendado para testes de segurança)
- **Debian**
- **Ubuntu**
- **Arch Linux**
- **Fedora/CentOS/RHEL** (Suporte básico)

### Requisitos do Sistema

- **Sistema Operacional**: Linux (64-bit)
- **Python**: 3.8 ou superior
- **Memória**: Mínimo 2GB RAM (4GB+ recomendado)
- **Armazenamento**: 1GB de espaço livre para ferramentas e resultados
- **Rede**: Conexão com internet necessária para instalação e atualizações
- **Privilégios**: Acesso root/sudo necessário para instalação
- **Linguagem Go**: Instalada automaticamente pelo instalador mestre

### Início Rápido

1. **Clone e Instale** (5 minutos):
   ```bash
   git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
   cd linux-vulnerability-toolkit
   sudo python3 install/setup.py
   ```

2. **Verifique a Instalação**:
   ```bash
   python3 tests/validate_installation.py
   ```

3. **Execute Sua Primeira Varredura**:
   ```bash
   python3 run.py example.com
   ```

## Instalação

### Orquestrador de Instalação Mestre (Recomendado)

O kit de ferramentas agora possui um **instalador mestre de ponto único** abrangente que lida com tudo automaticamente:

```bash
# Clone o repositório
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Execute o orquestrador de instalação mestre (requer privilégios de root)
sudo python3 install/setup.py
```

O instalador mestre executa:
- Verificação de plataforma Linux e detecção de distribuição
- Aplicação de permissão root/sudo 
- **NOVO**: Proteção de timeout anti-travamento para todas as operações
- **NOVO**: Limpeza e reparo de arquivos de bloqueio do gerenciador de pacotes
- Instalação de pacotes do sistema com rastreamento de pacotes individuais
- **NOVO**: Processo de instalação otimizado para VM (Kali Linux testado)
- Configuração de ambiente Go com gerenciamento de PATH
- Instalação de ferramentas de segurança com proteção de timeout (naabu, httpx, nuclei)
- Configuração de dependências Python e ambiente virtual
- Otimização de configuração e criação de aliases bash
- Verificação completa do sistema com testes de funcionalidade

### Métodos de Instalação Alternativos

#### Opção 1: Configuração de Ambiente Python Apenas

```bash
# Para configuração de ambiente Python e validação apenas
python3 scripts/autoinstall.py
```

**Nota:** Scripts shell legados foram integrados no instalador mestre para uma experiência simplificada.

### Verificação Pós-Instalação

Após a instalação, verifique se tudo está funcionando:

```bash
# Validação de instalação abrangente (Recomendado)
python3 tests/validate_installation.py

# Validação de ambiente Python
python3 scripts/autoinstall.py

# Validação de ferramenta legada
python3 tests/verify_installation.py
```

## Uso

### Como Executar o Projeto

#### **Passo 1: Instalação (Apenas Linux)**

```bash
# Clone o repositório
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Instale tudo com um comando (requer privilégios de root)
sudo python3 install/setup.py
```

#### **Passo 2: Validação (Recomendado)**

```bash
# Verifique se a instalação está funcionando corretamente
python3 tests/validate_installation.py
```

#### **Passo 3: Execute Varreduras de Vulnerabilidade**

**Varredura Básica:**

```bash
# Varredura simples
python3 run.py <alvo>

# Exemplo
python3 run.py example.com
```

**Usando Script Shell:**

```bash
# Lançador alternativo
bash scripts/run_toolkit.sh <alvo>
```

### Opções de Uso Avançado

```bash
# Especifique portas personalizadas
python3 run.py --target example.com --ports 80,443,8080-8090

# Use templates nuclei específicos
python3 run.py --target example.com --templates cves,exposures

# Varredura abrangente com filtragem
python3 run.py --target example.com --ports top-1000 --tags cve,exposure --severity critical,high

# Saída verbosa para debug
python3 run.py --target example.com --verbose
```

### Referência de Comandos

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `python3 run.py <alvo>` | Varredura básica de vulnerabilidade | `python3 run.py example.com` |
| `python3 mtscan.py` | Interface de menu interativo | Lançar varredura guiada |
| `bash scripts/run_toolkit.sh <alvo>` | Lançador alternativo | `bash scripts/run_toolkit.sh example.com` |
| `python3 tests/validate_installation.py` | Validar instalação | Verificar status do sistema |
| `python3 scripts/autoinstall.py` | Configuração de ambiente Python | Configurar dependências |
| `sudo python3 install/setup.py` | Instalador mestre | Configuração completa do sistema |

### Sistema de Menu Interativo

O kit de ferramentas inclui um sistema de menu interativo intuitivo via `mtscan.py`:

```bash
# Lançar menu interativo
python3 mtscan.py
```

**Recursos do Menu:**
- **Seleção de Alvo Guiada**: Entrada de alvo passo a passo com validação
- **Seleção de Tipo de Varredura**: Escolha entre varreduras rápidas, abrangentes ou personalizadas
- **Progresso em Tempo Real**: Atualizações ao vivo e informações de status
- **Gerenciamento de Resultados**: Acesso fácil a resultados de varredura e relatórios
- **Configuração de Ferramentas**: Configuração e verificação interativa de ferramentas

### Tipos e Modos de Varredura

#### 1. Varredura Rápida (Recomendado para iniciantes)
```bash
python3 run.py --quick <alvo>
```
- Top 1000 portas
- Templates básicos de vulnerabilidade
- Tempo de execução rápido

#### 2. Varredura Abrangente (Recomendado para análise completa)
```bash
python3 run.py --comprehensive <alvo>
```
- Todas as portas (1-65535)
- Conjunto completo de templates de vulnerabilidade
- Enumeração detalhada de serviços

#### 3. Varredura Personalizada (Usuários avançados)
```bash
python3 run.py --target <alvo> --ports <portas> --templates <templates>
```
### Opções Adicionais

- `--verbose`: Exibir saída mais detalhada
- `--timeout`: Definir timeout máximo de varredura em segundos
- `--scan-code`: Habilitar varredura de código para aplicações web
- `--auto-config`: Configurar automaticamente ferramentas baseado nas capacidades do sistema

## Saída e Relatórios

### Estrutura de Resultados

Resultados são salvos em um diretório com timestamp (ex: `results_example.com_20250603_120101/`) incluindo:

- `ports.txt`: Portas abertas descobertas
- `ports.json`: Dados JSON de portas para processamento
- `http_services.txt`: Serviços HTTP descobertos
- `http_services.json`: Dados JSON de serviços HTTP
- `vulnerabilities.txt`: Vulnerabilidades descobertas
- `vulnerabilities.jsonl`: Dados JSONL de vulnerabilidades
- `report.html`: Relatório HTML abrangente com visualizações
- `report.json`: Dados JSON estruturados para processamento adicional
- `summary.txt`: Resumo executivo dos achados

### Formatos de Relatório

- **HTML**: Relatórios visuais com gráficos e tabelas interativas
- **JSON**: Dados estruturados para integração com outras ferramentas
- **TXT**: Formato legível para revisão rápida
- **JSONL**: Formato de linha JSON para processamento em lote

## Considerações de Segurança

### Diretrizes Legais e Éticas

- **Autorização Necessária**: Sempre obtenha permissão explícita por escrito antes de varrer qualquer alvo
- **Limitações de Escopo**: Apenas varre sistemas que você possui ou tem autorização explícita para testar
- **Divulgação Responsável**: Relate vulnerabilidades descobertas através de canais apropriados
- **Proteção de Dados**: Manuseie resultados de varredura e informações sensíveis de acordo com leis aplicáveis

### Melhores Práticas

- **Ambiente Isolado**: Use ambientes dedicados de teste de segurança quando possível
- **Limitação de Taxa**: Use velocidades de varredura apropriadas para evitar sobrecarregar sistemas alvo
- **Gerenciamento de Logs**: Mantenha logs detalhados de todas as atividades de varredura
- **Segurança de Resultados**: Criptografe e armazene com segurança resultados de varredura contendo informações sensíveis

### Ambiente de Teste Recomendado

```bash
# Exemplo: Configurando um ambiente de teste controlado
# Use VirtualBox/VMware com segmentos de rede isolados
# Implante aplicações intencionalmente vulneráveis (DVWA, WebGoat, etc.)
python3 run.py 192.168.56.101  # Rede host-only VMware/VirtualBox
```

## Validação e Solução de Problemas

### Validação de Instalação

Sempre valide sua instalação após a configuração:

```bash
# Validação de instalação abrangente
python3 tests/validate_installation.py

# Validação de ambiente Python
python3 scripts/autoinstall.py

# Validação de ferramenta legada
python3 tests/verify_installation.py
```

### Problemas Comuns e Soluções

#### 1. **Problemas do Instalador Mestre**

```bash
# Problema: Permissão negada durante instalação
sudo python3 install/setup.py

# Problema: Plataforma não suportada
# Solução: Use Linux (apenas Debian/Ubuntu/Kali/Arch)
```

#### 2. **Ferramentas de Segurança Ausentes**

```bash
# Verificar disponibilidade de ferramentas
which naabu httpx nuclei

# Reinstalar ferramentas (instalador mestre lida com PATH do Go automaticamente)
sudo python3 install/setup.py

# Instalação manual de ferramentas se necessário
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

#### 3. **Problemas de Ambiente Python**

```bash
# Validar configuração Python
python3 scripts/autoinstall.py

# Verificar versão Python (3.8+ necessário)
python3 --version

# Instalar pacotes Python ausentes
pip3 install -r config/requirements.txt
```

### Otimização de Performance

#### **Ajuste do Sistema para Melhor Performance**

```bash
# Aumentar limites de descritores de arquivo (temporário)
ulimit -n 65536

# Otimizar parâmetros de rede (requer root)
echo 'net.core.rmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p
```

#### **Opções de Otimização de Varredura**

```bash
# Varredura rápida com configurações otimizadas
python3 run.py --target example.com --threads 50 --timeout 5

# Varredura conservadora para redes instáveis
python3 run.py --target example.com --threads 10 --timeout 10 --delay 100ms

# Varredura de performance máxima (use com cuidado)
python3 run.py --target example.com --threads 100 --timeout 3 --rate 1000
```

### Solução Avançada de Problemas

#### **Reset Completo e Reinstalação**

```bash
# 1. Limpar instalação anterior
rm -rf ~/go/bin/{naabu,httpx,nuclei}

# 2. Executar instalador mestre aprimorado
sudo python3 install/setup.py

# 3. Validar instalação
python3 tests/validate_installation.py
```

## Contribuindo

1. Faça um fork do repositório
2. Crie uma branch de feature
3. Teste em múltiplas distribuições Linux
4. Envie um pull request

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para detalhes.

## Aviso Legal

Este kit de ferramentas é projetado apenas para testes de segurança autorizados e propósitos de pesquisa. Os usuários são responsáveis por garantir que tenham autorização adequada antes de varrer qualquer alvo. Os autores não são responsáveis por qualquer uso indevido ou dano causado por este software.

---

**Suporte de Plataforma**: Apenas Linux | **Versão**: 2.0 | **Última Atualização**: Junho 2025

**Para citações de código, veja:** [docs/documentacao/CODE_CITATIONS.md](docs/documentacao/CODE_CITATIONS.md)
