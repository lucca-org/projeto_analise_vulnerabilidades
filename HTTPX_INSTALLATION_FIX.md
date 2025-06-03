# httpx Installation Fix

## Issue
The httpx installation was failing with the error: `No such file or directory: 'go'` even though Go was installed at `/usr/local/go/bin/go`.

## Root Cause
The Python script was trying to execute `go` command directly without specifying the full path, but Go wasn't in the system PATH when the script was running.

## Solution Applied

### 1. Improved Go Binary Detection
Modified the installation script to check multiple possible Go installation locations:
- `/usr/local/go/bin/go` (manual installation)
- `shutil.which("go")` (system PATH)
- `~/go/bin/go` (user installation)

### 2. Enhanced PATH Setup
Updated `setup_go_env()` function to:
- Detect existing Go installations in multiple locations
- Properly add Go directories to PATH
- Set GOPATH and GOROOT environment variables
- Create missing directories as needed

### 3. Fixed httpx Installation
Updated `install_httpx()` function to:
- Use the detected Go binary path instead of assuming `go` is in PATH
- Implement multiple fallback installation methods
- Better error handling and reporting

### 4. Improved httpx Detection
Enhanced `commands/httpx.py` to:
- Check multiple common installation locations
- Provide better error messages when httpx is not found
- Automatically add Go bin directory to PATH if needed

## Files Modified

1. **index.py**
   - Fixed Go binary path detection
   - Improved `check_and_install_go()` function
   - Enhanced `setup_go_env()` function
   - Updated `install_httpx()` function

2. **commands/httpx.py**
   - Added better executable path detection
   - Improved error messages
   - Enhanced `check_httpx()` function

3. **test_installation.py** (new)
   - Test script to verify installations work correctly

## Usage

### Run Installation
```bash
python3 index.py
```

### Test Installation
```bash
python3 test_installation.py
```

### Manual httpx Installation (if needed)
```bash
# Find Go binary
which go
# OR
/usr/local/go/bin/go version

# Install httpx using full Go path
/usr/local/go/bin/go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add to PATH
export PATH=$PATH:$HOME/go/bin
```

## Verification

After running the fixes:
1. Go should be properly detected at `/usr/local/go/bin/go`
2. httpx should install successfully to `~/go/bin/httpx`
3. Both tools should be available in PATH for subsequent use

The installation script now handles cases where:
- Go is installed but not in PATH
- Multiple Go installations exist
- User doesn't have write permissions to system directories
- Network issues during download

## Notes

- **Linux Only**: This toolkit is designed exclusively for Linux systems (Debian/Kali Linux)
- **No Windows Support**: Windows is intentionally not supported
- All changes maintain backward compatibility
- Added comprehensive error handling and user feedback

## Troubleshooting

### If httpx still fails to install:
1. Check Go installation: `/usr/local/go/bin/go version`
2. Manually install: `/usr/local/go/bin/go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
3. Verify: `~/go/bin/httpx -version`
4. Add to PATH: `export PATH=$PATH:$HOME/go/bin`

### If PATH issues persist:
```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## Technical Details

The key fix was updating the Go binary detection logic to handle cases where:
- Go is installed in `/usr/local/go/bin/` but not added to system PATH
- Multiple Go installations exist on the system
- The installation script runs in an environment without proper PATH setup

The solution ensures the full path to the Go binary is used for all operations, eliminating the "command not found" errors.

## Next Steps & Ideas for Future Work

### Immediate Tasks (Priority 1)
1. **Complete Shell Script Verification**
   - Verify all `.sh` scripts have correct permissions (`chmod +x`)
   - Test `setup_tools.sh` orchestration on actual Linux system
   - Ensure `fix_repo_keys.sh` properly handles Kali Linux repositories
   - Validate `fix_dpkg.sh` resolves package manager interruptions

2. **Master Orchestration Testing**
   - Test the `orchestrate_installation()` function in `index.py`
   - Verify installation state management (`.installation_completed` file)
   - Ensure proper error handling and fallback mechanisms
   - Test skip logic for already-installed components

3. **httpx Installation Verification**
   - Run comprehensive tests with `test_installation.py`
   - Verify httpx works with different Go installation paths
   - Test fallback installation methods
   - Ensure symbolic links are created properly in `/usr/local/bin/`

### Medium Priority Tasks
4. **Dependency Chain Verification**
   - Test nuclei and naabu installation after httpx fixes
   - Verify all Go tools install to `~/go/bin/` consistently
   - Test PATH updates persist across shell sessions
   - Validate Python dependencies install correctly

5. **Error Handling Improvements**
   - Add more specific error messages for common failure scenarios
   - Implement retry logic for network-dependent operations
   - Add timeout handling for long-running installations
   - Create recovery procedures for partial installations

6. **Documentation & User Experience**
   - Create troubleshooting guide for common issues
   - Add verbose mode for debugging installation problems
   - Document manual installation procedures as fallbacks
   - Create quick verification scripts for post-installation

### Advanced Features (Future)
7. **Installation Optimization**
   - Add parallel installation for independent tools
   - Implement caching for downloaded packages
   - Add offline installation support
   - Create minimal vs full installation options

8. **System Integration**
   - Add support for other Linux distributions (Ubuntu, CentOS)
   - Create automated testing on different Linux environments
   - Add integration with package managers (snap, flatpak)
   - Implement version management for tools

9. **Security & Maintenance**
   - Add checksum verification for downloaded binaries
   - Implement automatic updates for security tools
   - Add tool version consistency checks
   - Create backup/restore functionality for configurations

### Technical Debt & Code Quality
10. **Code Improvements**
    - Refactor large functions into smaller, testable units
    - Add comprehensive logging throughout installation process
    - Implement configuration file for customizing installation
    - Add unit tests for critical installation functions

11. **Linux-Only Optimization**
    - Remove any remaining Windows compatibility code
    - Optimize for Debian/Kali Linux package management
    - Add Kali Linux specific optimizations
    - Leverage Linux-specific features for better performance

### Testing & Validation
12. **Comprehensive Testing**
    - Test on fresh Kali Linux installations
    - Test on Debian-based systems
    - Create automated CI/CD testing pipeline
    - Add performance benchmarks for installation time

**Current State**: Linux-only vulnerability analysis toolkit with robust Go/httpx installation. Ready for comprehensive testing and deployment on target systems.

**Next Session Focus**: Test shell script orchestration, verify complete installation flow, and validate all security tools work correctly after the PATH fixes.
