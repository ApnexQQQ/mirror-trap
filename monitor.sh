#!/bin/bash
# Mirror Trap health monitor — runs every 5 minutes via cron
TELEGRAM_TOKEN="8897487308:AAF2U7ivi3LUFHPS8pAx9P6yymHTr-f30n0"
CHAT_ID="5837857821"

alert() {
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}&text=⚠️ Mirror Trap ALERT: $1" > /dev/null
}

# Check honeypot
if ! systemctl is-active --quiet mirrortrap-honeypot; then
    alert "Honeypot service is DOWN - restarting"
    systemctl restart mirrortrap-honeypot
fi

# Check dashboard
if ! systemctl is-active --quiet mirrortrap-dashboard; then
    alert "Dashboard service is DOWN - restarting"
    systemctl restart mirrortrap-dashboard
fi

# Check nginx
if ! systemctl is-active --quiet nginx; then
    alert "Nginx is DOWN - restarting"
    systemctl restart nginx
fi

# Check if dashboard responds
HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:5000/login)
if [ "$HTTP" != "200" ]; then
    alert "Dashboard not responding (HTTP $HTTP) - restarting"
    systemctl restart mirrortrap-dashboard
fi
