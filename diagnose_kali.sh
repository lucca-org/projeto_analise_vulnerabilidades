#!/bin/bash
# Kali Linux VM Diagnostics Script
# Run this to diagnose why Phase 1 hangs

echo "🔍 Kali Linux VM Installation Diagnostics"
echo "=========================================="

# Check 1: Network connectivity
echo "1. Testing network connectivity..."
if ping -c 3 google.com &> /dev/null; then
    echo "✅ Internet connection working"
else
    echo "❌ No internet connection - this will cause hangs!"
    echo "💡 Fix: Check VM network settings"
fi

# Check 2: Repository accessibility  
echo "2. Testing Kali repositories..."
if curl -s --connect-timeout 10 http://http.kali.org/kali/ &> /dev/null; then
    echo "✅ Kali repositories accessible"
else
    echo "❌ Kali repositories unreachable"
    echo "💡 Fix: Repository issues detected"
fi

# Check 3: Package manager status
echo "3. Checking package manager locks..."
if [[ -f /var/lib/dpkg/lock ]] || [[ -f /var/lib/dpkg/lock-frontend ]]; then
    echo "⚠️ Package manager is locked"
    echo "💡 Run: sudo rm /var/lib/dpkg/lock*"
else
    echo "✅ Package manager unlocked"
fi

# Check 4: Available disk space
echo "4. Checking disk space..."
AVAILABLE=$(df / | tail -1 | awk '{print $4}')
if [[ $AVAILABLE -lt 2000000 ]]; then
    echo "⚠️ Low disk space: ${AVAILABLE}K available"
    echo "💡 Need at least 2GB for installation"
else
    echo "✅ Sufficient disk space: ${AVAILABLE}K available"
fi

# Check 5: System resources
echo "5. Checking system resources..."
MEM_TOTAL=$(free -m | awk 'NR==2{print $2}')
if [[ $MEM_TOTAL -lt 1024 ]]; then
    echo "⚠️ Low memory: ${MEM_TOTAL}MB"
    echo "💡 Consider increasing VM RAM"
else
    echo "✅ Sufficient memory: ${MEM_TOTAL}MB"
fi

# Check 6: Repository configuration
echo "6. Checking repository configuration..."
if grep -q "deb http://http.kali.org/kali kali-rolling main" /etc/apt/sources.list 2>/dev/null; then
    echo "✅ Kali repositories configured"
else
    echo "⚠️ Repository configuration issues"
    echo "💡 Fix: Check /etc/apt/sources.list"
fi

echo ""
echo "🎯 Diagnostics complete!"
echo "If you see any ❌ or ⚠️ above, fix those issues first."
echo "Then run: sudo python3 setup_kali_safe.py"
