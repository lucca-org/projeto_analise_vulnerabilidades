# Code Citations - MTScan Linux Vulnerability Analysis Toolkit

This document contains all third-party code citations, licenses, and acknowledgments for code snippets, patterns, or concepts used in the MTScan toolkit.

## Overview

MTScan integrates various security tools and includes networking utilities, regular expressions, and system detection code. This document provides proper attribution for any third-party code or patterns that have been adapted or referenced.

## Python Standard Library and Built-in Modules

MTScan extensively uses Python's standard library modules which are part of the Python Software Foundation License:

### Core Standard Library Usage
- **subprocess**: Process execution and command-line tool integration
- **socket**: Network connectivity testing and DNS resolution
- **platform**: System detection (platform.system(), platform.release())
- **os**: File system operations, environment variables, and path management
- **sys**: System-specific parameters and functions
- **json**: JSON parsing for tool outputs (naabu, httpx, nuclei)
- **re**: Regular expression processing for pattern matching
- **urllib**: HTTP connectivity testing and URL handling
- **time**: Timeout and delay operations
- **shutil**: File operations and executable path detection
- **pathlib**: Modern path handling
- **datetime**: Timestamp generation and formatting
- **logging**: Application logging and debugging
- **tempfile**: Temporary file and directory management
- **getpass**: User information retrieval
- **signal**: Process signal handling
- **argparse**: Command-line argument parsing
- **threading**: Concurrent operations
- **traceback**: Error debugging and stack traces

**License**: Python Software Foundation License
**Usage**: Core functionality across all modules in MTScan

## Third-Party Python Libraries

### External Dependencies
All external Python dependencies are managed through `config/requirements.txt`:

#### Core Dependencies
- **requests==2.32.2**: HTTP library for connectivity testing
- **colorama==0.4.6**: Cross-platform colored terminal text output

#### Reporting Dependencies  
- **jinja2==3.1.2**: Template engine for HTML report generation
- **rich==13.3.5**: Advanced terminal formatting and progress displays
- **markdown==3.4.3**: Markdown processing for documentation

#### Utility Libraries
- **tqdm==4.65.0**: Progress bars for long-running operations
- **pathlib==1.0.1**: Enhanced path handling
- **jsonschema==4.19.0**: JSON validation and schema checking
- **pyyaml==6.0.1**: YAML configuration file processing

#### Testing Dependencies
- **pytest-httpx==0.24.0**: HTTP testing utilities

**Licenses**: Various (MIT, Apache 2.0, BSD)
**Usage**: Enhanced functionality and user interface improvements

## Security Tool Integration

### ProjectDiscovery Tools
MTScan integrates three main security tools from ProjectDiscovery:

#### Naabu (Port Scanner)
- **Repository**: github.com/projectdiscovery/naabu
- **Version**: v2.1.8
- **License**: MIT License
- **Usage**: Port scanning and service discovery

#### HTTPX (HTTP Toolkit)
- **Repository**: github.com/projectdiscovery/httpx  
- **Version**: v1.3.7
- **License**: MIT License
- **Usage**: HTTP service enumeration and analysis

#### Nuclei (Vulnerability Scanner)
- **Repository**: github.com/projectdiscovery/nuclei
- **Version**: Latest
- **License**: MIT License
- **Usage**: Template-based vulnerability scanning

**Attribution**: All ProjectDiscovery tools are properly attributed and installed via their official repositories.

## Code Scanning Patterns

### Security Vulnerability Detection
The `src/code_scanner.py` module includes vulnerability patterns for multiple languages:

#### Python Security Patterns
- SQL Injection detection via string formatting
- OS Command Injection in subprocess calls  
- Insecure deserialization (pickle.loads)
- Weak cryptographic algorithms (MD5, SHA1)
- Hard-coded credentials detection
- Debug feature detection

#### JavaScript Security Patterns
- DOM-based XSS vulnerabilities
- eval() usage detection
- Insecure local storage usage
- Hard-coded credentials in JS

#### Bash Security Patterns
- Shell injection vulnerabilities
- Insecure temporary file usage

**Source**: Industry-standard security patterns and OWASP guidelines
**License**: Public domain security knowledge

## External Scanner Integration

### Bandit Support
Integration with Bandit security scanner for Python code analysis:
- **Repository**: github.com/PyCQA/bandit
- **License**: Apache 2.0
- **Usage**: External Python security scanning when available

## Network Connectivity Testing

### Multi-Method Connectivity Validation
The internet connectivity check in `install/setup.py` implements multiple validation methods:

1. **DNS Resolution Testing**: Tests resolution of google.com, github.com, cloudflare.com
2. **Direct Socket Connections**: Tests connectivity to DNS servers (8.8.8.8, 1.1.1.1, 9.9.9.9)
3. **Ping Testing**: ICMP connectivity tests with Linux-specific parameters
4. **HTTP Connectivity**: HTTPS requests to reliable endpoints

**Source**: Standard network programming practices
**License**: Public domain networking concepts

## System Detection and Platform Support

### Linux Distribution Detection
Support for multiple Linux distributions with specific package management:

#### Supported Distributions
- **Debian**: APT package manager, libpcap-dev, build-essential
- **Ubuntu**: APT package manager with universe repository support
- **Kali Linux**: APT with special repository handling
- **Arch Linux**: Pacman package manager, AUR support

**Source**: Distribution-specific package management standards
**License**: Public domain system administration knowledge

## Go Environment Management

### Go Installation and PATH Management
Automated Go environment setup with:
- GOPATH and GOBIN configuration
- PATH environment variable updates
- Go module cache management
- Cross-platform binary installation

**Source**: Official Go installation and configuration documentation
**License**: BSD-style license (Go programming language)

## Regular Expression Patterns

### IP Address Validation Patterns

The following IPv4 address validation regular expressions are sourced from various open-source projects:

#### Standard IPv4 Regex Pattern
**License**: Unknown  
**Source**: https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```regex
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
```

**Usage in MTScan**: Used in network validation and target parsing functions.


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9
```


## License: GPL-2.0
https://github.com/jab/melk.util/blob/6652694b91b7651e2fcc8b6abaa327a5839e6f2b/melk/util/urlnorm.py

```
a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]
```


## License: unknown
https://github.com/naryga/alm-familyfellowship-com/blob/0db47e969caca4951e4d44de45fd04912df6c3dc/webroot/modules/modules/Gecko/Gecko.js

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-
```


## License: BSD-2-Clause
https://github.com/groovy-sky/vnt/blob/888b6745966ea937f3ea12d88207d71600c94f9d/split.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-
```


## License: MIT
https://github.com/bangrezz/mikfiles/blob/d8b55be91cccb3e7bc7ae1d3e911622c3e293796/modules/cronjob.py

```
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform_release': platform.
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform_release': platform.release(),
        '
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform_release': platform.release(),
        'platform_version': platform
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'hostname
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'hostname': platform.node(),
        
```


## License: unknown
https://github.com/zimNMM/SimpleOoobaDiscordBot/blob/36de75ee0ca7d461a0001bd5adbb2c67fa1ab960/main.py

```
.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'hostname': platform.node(),        'processor': platform.processor(),
```

## Package Manager Integration

### APT (Advanced Package Tool)
The installation system includes comprehensive APT package management for Debian-based systems:

#### Package Lock Management
- Lock file cleanup and recovery mechanisms
- Process termination for hanging package operations
- Non-interactive installation environment setup

#### Package Installation Strategies
- Individual package tracking and verification
- Alternative installation methods for problematic packages
- Repository source management and updating

**Source**: Debian and Ubuntu package management best practices
**License**: GPL-compatible (Debian packaging standards)

### Pacman Package Manager
Support for Arch Linux package management:
- System update procedures
- Development tool installation
- AUR (Arch User Repository) compatibility

**Source**: Arch Linux packaging guidelines
**License**: GPL-compatible

## Error Handling and Timeout Management

### Anti-Hang Protection System
Comprehensive timeout protection for:
- Package manager operations (300-1800 second timeouts)
- Network connectivity tests (5-10 second timeouts)  
- Tool compilation processes (600-900 second timeouts)
- Repository update operations (300 second timeout)

#### Process Management
- Graceful process termination with SIGTERM
- Forceful termination with SIGKILL as fallback
- Background process monitoring and cleanup

**Source**: Standard Unix process management practices
**License**: Public domain system programming concepts

## Logging and User Experience

### Logging Infrastructure
Multi-level logging system with:
- User-specific log directories in `/tmp/vulnerability_scan_{user}/`
- Appropriate file permissions (Linux stat.S_IRWXU)
- Fallback mechanisms for permission issues
- Structured log formatting

#### Color-Coded Output
Professional terminal output with ANSI color codes:
- Success messages in green
- Warning messages in yellow  
- Error messages in red
- Informational messages in white/blue

**Source**: ANSI color standard and Unix terminal conventions
**License**: Public domain terminal programming practices

## JSON and Data Processing

### Multi-Format Output Parsing
Support for various data formats from security tools:

#### JSON Processing
- Standard JSON array parsing
- JSONL (JSON Lines) format support
- Error-tolerant parsing with line-by-line fallback
- Schema validation for tool outputs

#### Report Generation
- HTML report templates using Jinja2
- Markdown report generation
- CSV export functionality
- XML structure support via ElementTree

**Source**: Standard data interchange formats
**License**: Public domain data processing patterns

## Regular Expression Patterns and Network Validation

### Domain and IP Address Validation
MTScan includes various regex patterns for network address validation. Some patterns may be derived from public sources:

## MTScan Original Code

### Core Architecture and Design
The following components are original contributions of the MTScan project:

#### Master Installation System (`install/setup.py`)
- **Author**: MTScan Development Team
- **License**: MIT License
- **Description**: Comprehensive Linux security toolkit installer with multi-distribution support, anti-hang protection, and automated dependency management

#### Interactive Menu Interface (`mtscan.py`)
- **Author**: MTScan Development Team  
- **License**: MIT License
- **Description**: User-friendly terminal interface for guided vulnerability scanning

#### Workflow Orchestration (`src/workflow.py`)
- **Author**: MTScan Development Team
- **License**: MIT License
- **Description**: Automated multi-tool scanning workflow with network validation and real-time output

#### Security Tool Wrappers (`commands/`)
- **Files**: `naabu.py`, `httpx.py`, `nuclei.py`
- **Author**: MTScan Development Team
- **License**: MIT License
- **Description**: Python wrappers for ProjectDiscovery tools with enhanced error handling and output processing

#### Advanced Reporting System (`src/reporter.py`)
- **Author**: MTScan Development Team
- **License**: MIT License
- **Description**: Multi-format report generation with vulnerability analysis and compliance checking

#### Configuration Management (`src/config_manager.py`)
- **Author**: MTScan Development Team
- **License**: MIT License
- **Description**: Automated tool configuration and system optimization

#### Code Security Scanner (`src/code_scanner.py`)
- **Author**: MTScan Development Team
- **License**: MIT License
- **Description**: Multi-language source code vulnerability detection

#### Network Testing Utilities (`src/network_test.py`)
- **Author**: MTScan Development Team
- **License**: MIT License
- **Description**: Comprehensive network connectivity validation

#### Utility Functions (`src/utils.py`)
- **Author**: MTScan Development Team
- **License**: MIT License
- **Description**: Core utility functions for command execution, file operations, and system management

### Project Innovation

#### Anti-Hang Installation Protection
Original contribution: Timeout-protected package installation system that prevents hanging on virtual machines and slow networks.

#### Multi-Method Connectivity Validation
Original contribution: Redundant network connectivity testing using DNS, socket, ping, and HTTP methods for reliable internet validation.

#### Integrated Security Tool Management
Original contribution: Seamless integration of multiple security tools with automatic installation, configuration, and PATH management.

#### Professional Linux-Only Focus
Original contribution: Deliberate Linux-exclusive design optimized for security testing environments with comprehensive distribution support.

## Acknowledgments

### Community Contributions
- ProjectDiscovery team for excellent security tools (naabu, httpx, nuclei)
- Python Software Foundation for robust standard library
- Linux distribution maintainers for reliable package management
- Open source security community for vulnerability patterns and best practices

### Educational Resources
- OWASP (Open Web Application Security Project) for security guidelines
- CVE (Common Vulnerabilities and Exposures) database for vulnerability information
- Linux documentation projects for system administration practices
- Go community for installation and management procedures

## Compliance Statement

This project complies with:
- MIT License terms for all original code
- Attribution requirements for third-party libraries
- Proper citation of security patterns and methodologies
- Acknowledgment of integrated tool licenses

All external dependencies are properly declared in `config/requirements.txt` and installed through official channels. Security tools are installed from their official repositories with proper version pinning.

## Contact and Updates

For questions about code citations or licensing:
- Check the main project README.md for current information
- Review individual file headers for specific attributions
- Consult dependency documentation for third-party library licenses

**Document Version**: 2.0  
**Last Updated**: June 2025  
**Project License**: MIT License

