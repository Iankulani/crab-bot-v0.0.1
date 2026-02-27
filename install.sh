#!/bin/bash
# Crab-Bot Installation Script

echo "🦀 Installing Crab-Bot Cybersecurity Tool..."

# Check Python version
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
required_version="3.7"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.7 or higher required. Found: $python_version"
    exit 1
fi

# Create virtual environment (optional)
read -p "Create virtual environment? (y/n): " create_venv
if [ "$create_venv" = "y" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv crab-env
    source crab-env/bin/activate
    echo "✅ Virtual environment created and activated"
fi

# Install Python packages
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install system dependencies based on OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🐧 Detected Linux - Installing system dependencies..."
    
    # Check distribution
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            nmap \
            nikto \
            traceroute \
            whois \
            dnsutils \
            curl \
            wget \
            netcat \
            openssh-client \
            iptables \
            chromium-browser \
            signal-cli || true
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Fedora
        sudo dnf install -y \
            nmap \
            nikto \
            traceroute \
            bind-utils \
            curl \
            wget \
            nc \
            openssh-clients \
            iptables \
            chromium || true
    fi

elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 Detected macOS - Installing dependencies with Homebrew..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "⚠️ Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install \
        nmap \
        nikto \
        traceroute \
        whois \
        bind \
        curl \
        wget \
        netcat \
        openssh \
        iptables \
        chromium \
        signal-cli || true

elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    echo "🪟 Detected Windows - Please install manually:"
    echo "  - Download and install Python 3.7+ from python.org"
    echo "  - Install Nmap from https://nmap.org/download.html"
    echo "  - Install Nikto from https://github.com/sullo/nikto"
    echo "  - Install Chrome browser for WhatsApp integration"
fi

# Create configuration directories
echo "📁 Creating configuration directories..."
mkdir -p ~/.crab_bot
mkdir -p ~/.crab_bot/ssh_keys
mkdir -p ~/.crab_bot/nikto_results
mkdir -p ~/.crab_bot/traffic_logs
mkdir -p ~/.crab_bot/phishing_pages
mkdir -p ~/.crab_bot/phishing_templates
mkdir -p ~/.crab_bot/phishing_logs
mkdir -p ~/.crab_bot/captured_credentials
mkdir -p ~/.crab_bot/whatsapp_session
mkdir -p ~/.crab_bot/ssh_logs
mkdir -p ~/.crab_bot/time_history

mkdir -p reports
mkdir -p scan_results
mkdir -p alerts
mkdir -p monitoring
mkdir -p backups
mkdir -p temp
mkdir -p scripts

# Set proper permissions
chmod 700 ~/.crab_bot

# Check for root/admin privileges for firewall features
if [[ "$EUID" -ne 0 ]] && [[ "$OSTYPE" != "msys"* ]]; then
    echo ""
    echo "⚠️  Warning: Running without root/admin privileges"
    echo "   Firewall operations (block_ip/unblock_ip) will not work"
    echo "   Advanced traffic generation will be limited"
    echo ""
    echo "   To run with root privileges, use: sudo $(which python3) crab_bot.py"
fi

# Create desktop shortcut (optional)
read -p "Create desktop shortcut? (y/n): " create_shortcut
if [ "$create_shortcut" = "y" ]; then
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        cat > ~/.local/share/applications/crab-bot.desktop << EOF
[Desktop Entry]
Name=Crab-Bot
Comment=Cybersecurity Tool
Exec=$(which python3) $(pwd)/crab_bot.py
Icon=$(pwd)/icon.png
Terminal=true
Type=Application
Categories=Security;
EOF
        chmod +x ~/.local/share/applications/crab-bot.desktop
        echo "✅ Desktop shortcut created"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "📱 Create shortcut manually on macOS"
    fi
fi

echo ""
echo "🦀 Crab-Bot installation complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Run the tool: python3 crab_bot.py"
echo "  2. Configure messaging platforms during setup"
echo "  3. For Telegram: get API credentials from my.telegram.org"
echo "  4. For Discord: create bot at https://discord.com/developers/applications"
echo "  5. For Signal: install signal-cli separately"
echo "  6. For WhatsApp: ensure Chrome is installed"
echo ""
echo "📁 Configuration files are stored in: ~/.crab_bot/"
echo ""
echo "🔧 Optional installations:"
echo "  - Install Nikto: https://github.com/sullo/nikto"
echo "  - Install signal-cli: https://github.com/AsamK/signal-cli"
echo "  - For advanced traffic: run with sudo"
echo ""
echo "🎉 Installation successful! Run: python3 crab_bot.py"