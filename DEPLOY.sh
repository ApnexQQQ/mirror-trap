# LIAR'S ECHO — DEPLOYMENT GUIDE
# For someone with zero Linux experience
# Follow every step exactly

# ============================================
# STEP 1 — GET YOUR VPS
# ============================================
# Go to: https://www.hetzner.com/cloud
# Create account
# Create new server:
#   - Location: any
#   - Image: Ubuntu 22.04
#   - Type: CX21 (2 vCPU, 4GB RAM) = ~6 euros/month
#   - Add your SSH key OR use root password
# Click Create & Buy
# You will get an IP address — save it

# ============================================
# STEP 2 — CONNECT TO YOUR VPS
# ============================================
# On Windows: download PuTTY from https://putty.org
# On Mac/Linux: open Terminal
#
# Connect with:
ssh root@YOUR_VPS_IP
# Type yes when asked
# Enter your password

# ============================================
# STEP 3 — INSTALL REQUIREMENTS
# ============================================
apt update && apt upgrade -y
apt install python3 python3-pip git -y
pip3 install scapy requests

# ============================================
# STEP 4 — UPLOAD LIAR'S ECHO
# ============================================
# From your computer, upload the liars_echo folder:
# On Windows use WinSCP (free): https://winscp.net
# On Mac/Linux run this in Terminal (not on VPS):
scp -r liars_echo/ root@YOUR_VPS_IP:/root/

# ============================================
# STEP 5 — GET YOUR API KEYS
# ============================================

# --- DeepSeek API Key ---
# Go to: https://platform.deepseek.com
# Create account (free — you get 5M tokens free)
# Go to API Keys section
# Create new key — copy it

# --- Telegram Bot ---
# Open Telegram, search for @BotFather
# Send: /newbot
# Follow instructions, copy the token it gives you
# Then message @userinfobot to get your chat ID

# ============================================
# STEP 6 — CONFIGURE LIAR'S ECHO
# ============================================
nano /root/liars_echo/config/settings.py
# Edit these 3 lines with your real keys:
#   DEEPSEEK_API_KEY = "your_key_here"
#   TELEGRAM_BOT_TOKEN = "your_token_here"
#   TELEGRAM_CHAT_ID = "your_chat_id_here"
# Save: Ctrl+X then Y then Enter

# ============================================
# STEP 7 — TEST IT WORKS
# ============================================
cd /root/liars_echo
python3 main.py
# You should see logs in terminal
# And receive a Telegram message within 30 seconds

# ============================================
# STEP 8 — RUN AS BACKGROUND SERVICE
# ============================================
# So it keeps running even after you close terminal:

cat > /etc/systemd/system/liarsecho.service << EOF
[Unit]
Description=Liar's Echo Security System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/liars_echo
ExecStart=/usr/bin/python3 /root/liars_echo/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable liarsecho
systemctl start liarsecho

# Check it's running:
systemctl status liarsecho

# View live logs:
journalctl -u liarsecho -f

# ============================================
# TROUBLESHOOTING
# ============================================
# If python3 main.py gives errors:
#   pip3 install scapy requests
#
# If Telegram alerts not arriving:
#   Check your bot token and chat ID are correct
#   Make sure you messaged your bot first on Telegram
#
# If DeepSeek errors:
#   Check your API key
#   System works without it — just no AI classification
