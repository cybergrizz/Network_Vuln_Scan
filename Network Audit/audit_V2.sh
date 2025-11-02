#!/bin/bash

INPUT="domains.txt"
REPORT_DIR="audit_reports"
mkdir -p "$REPORT_DIR"

# Function: Clean up domain name and create its report folder
clean_domain() {
  echo "$1" | tr -d '\r\n' | xargs
}

# Loop through each domain
while read -r domain_raw; do
  domain=$(clean_domain "$domain_raw")
  if [ -z "$domain" ]; then
    echo "⚠️  Skipping blank domain"
    continue
  fi

  DOMAIN_DIR="$REPORT_DIR/$domain"
  mkdir -p "$DOMAIN_DIR"
  START_TIME=$(date +%s)

  echo "\n🧪 Auditing $domain..."

  # WHOIS Lookup
  echo "[*] WHOIS"
  timeout 20s whois "$domain" > "$DOMAIN_DIR/whois.txt" || echo "WHOIS failed." > "$DOMAIN_DIR/whois.txt"

  # DNS Records
  echo "[*] DNS"
  {
    echo "A Record:"; timeout 5s dig +short A "$domain"
    echo "MX Record:"; timeout 5s dig +short MX "$domain"
    echo "TXT Record:"; timeout 5s dig +short TXT "$domain"
  } > "$DOMAIN_DIR/dns.txt"

  # Basic Nmap
  echo "[*] Nmap (basic)"
  timeout 60s nmap -sT -Pn -T4 -F "$domain" > "$DOMAIN_DIR/nmap.txt" || echo "Nmap basic failed." > "$DOMAIN_DIR/nmap.txt"

  # Nmap Vuln Scripts
  echo "[*] Nmap (vuln)"
  timeout 90s nmap -sV --script vuln "$domain" > "$DOMAIN_DIR/nmap_vuln.txt" || echo "Nmap vuln scan failed." > "$DOMAIN_DIR/nmap_vuln.txt"

  # SSL Scan
  echo "[*] SSL scan"
  timeout 90s ./testssl.sh/testssl.sh --quiet --color 0 "$domain" > "$DOMAIN_DIR/ssl.txt" || echo "SSL scan failed." > "$DOMAIN_DIR/ssl.txt"

  # HTTP Headers
  echo "[*] HTTP headers"
  timeout 15s curl -I -s "https://$domain" > "$DOMAIN_DIR/headers.txt" || echo "Curl failed." > "$DOMAIN_DIR/headers.txt"

  # Subdomain Enumeration
  echo "[*] Subfinder"
  if command -v subfinder >/dev/null 2>&1; then
    timeout 60s subfinder -d "$domain" -silent > "$DOMAIN_DIR/subdomains.txt" || echo "Subfinder failed." > "$DOMAIN_DIR/subdomains.txt"
  else
    echo "Subfinder not found" > "$DOMAIN_DIR/subdomains.txt"
  fi

  # Dalfox XSS Scan
  echo "[*] Dalfox XSS"
  if command -v dalfox >/dev/null 2>&1; then
    timeout 60s dalfox url "https://$domain" > "$DOMAIN_DIR/xss.txt" || echo "Dalfox failed." > "$DOMAIN_DIR/xss.txt"
  else
    echo "Dalfox not found" > "$DOMAIN_DIR/xss.txt"
  fi

  # Nuclei Scan
  echo "[*] Nuclei"
  if command -v nuclei >/dev/null 2>&1; then
    timeout 90s nuclei -u "https://$domain" -o "$DOMAIN_DIR/nuclei.txt" || echo "Nuclei failed." > "$DOMAIN_DIR/nuclei.txt"
  else
    echo "Nuclei not found" > "$DOMAIN_DIR/nuclei.txt"
  fi

  # AI Summary Request (assumes OPENAI_API_KEY is exported)
  echo "[*] Generating AI summary"
  COMBINED_REPORT=$(cat "$DOMAIN_DIR"/*.txt | head -c 12000)
  JSON_PAYLOAD=$(jq -n \
    --arg content "$COMBINED_REPORT" \
    --arg domain "$domain" \
    '{
      model: "gpt-4",
      messages: [
        {role: "system", content: "You are a cybersecurity auditor."},
        {role: "user", content: "Generate a Markdown-formatted summary of scan results for domain \($domain). Include: Overall posture, Findings grouped by severity (Critical/High/Medium/Low), and remediation steps.\n\nScan Results:\n\n\($content)"}
      ],
      temperature: 0.3
    }')

  RESPONSE=$(curl -s https://api.openai.com/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -d "$JSON_PAYLOAD")

  echo "$RESPONSE" | jq -r '.choices[0].message.content' > "$DOMAIN_DIR/${domain}_summary.txt"
  echo "[✔] Summary saved"

  END_TIME=$(date +%s)
  echo "[✔] Finished $domain in $((END_TIME - START_TIME))s"

done < "$INPUT"

# Finalize master summary
echo "[*] Creating master summary"
MASTER="audit_reports/_master_summary.md"
echo "# 🧾 Domain Security Master Summary" > "$MASTER"
echo "Generated: $(date)" >> "$MASTER"
echo -e "\n| Domain | Summary |
|--------|---------|" >> "$MASTER"

for d in "$REPORT_DIR"/*/; do
  base=$(basename "$d")
  summary_file="$d/${base}_summary.txt"
  if [ -f "$summary_file" ]; then
    short=$(head -n 5 "$summary_file" | tr '\n' ' ' | cut -c1-200)
    echo "| $base | $short... |" >> "$MASTER"
  fi
done

echo "[✔] Master report created: $MASTER"