apt update && apt upgrade -y
apt install -y python3 python3-pip gowitness

mkdir /home/ail-typo-squatting
chmod 777 /home/ail-typo-squatting

# Define the script path
SCRIPT_PATH="/home/ail-typo-squatting/automate.sh"
touch "$SCRIPT_PATH"

# Use printf to create the script content and write it to the target file
printf '%s\n' "#!/bin/bash" \
    "# Input arguments" \
    "DOMAIN_LIST=\"$1\"" \
    "OUTPUT_FOLDER=\"$2\"" \
    "BACKUP_FOLDER=\"$OUTPUT_FOLDER/backups\"" \
    "TYPO_SCRIPT=\"ail-typo-squatting/ail_typo_squatting/typo.py\"" \
    "RESOLVERS_FILE=\"resolvers.txt\"" \
    "REPORT_GENERATOR_SCRIPT=\"report2.py\"" \
    "TIMESTAMP=\$(date +\"%Y-%m-%d_%H-%M-%S\")" \
    "mkdir -p \"$OUTPUT_FOLDER\" \"$BACKUP_FOLDER\"" \
    "if [ \"\$(ls -A \"$OUTPUT_FOLDER\" 2>/dev/null | grep -v \"backups\")\" ]; then" \
    "    RUN_BACKUP_FOLDER=\"$BACKUP_FOLDER/\$TIMESTAMP\"" \
    "    mkdir -p \"\$RUN_BACKUP_FOLDER\"" \
    "    echo \"[*] Backing up existing output files to \$RUN_BACKUP_FOLDER\"" \
    "    find \"$OUTPUT_FOLDER\" -mindepth 1 -maxdepth 1 -not -name 'backups' -exec mv {} \"\$RUN_BACKUP_FOLDER\" \;" \
    "fi" \
    "SUBDOMAINS_FILE=\"$OUTPUT_FOLDER/discovered_subdomains.txt\"" \
    "TYPO_OUTPUT_FOLDER=\"$OUTPUT_FOLDER/domains\"" \
    "DEDUPLICATED_FILE=\"$OUTPUT_FOLDER/deduplicated_domains.txt\"" \
    "RESOLVED_OUTPUT=\"$OUTPUT_FOLDER/resolved.txt\"" \
    "CHECKED_DOMAINS=\"$OUTPUT_FOLDER/checked_domains.txt\"" \
    "SCREENSHOTS_FOLDER=\"$OUTPUT_FOLDER/screenshots\"" \
    "GOWITNESS_LOG=\"$OUTPUT_FOLDER/gowitness.log\"" \
    "FINAL_REPORT=\"$OUTPUT_FOLDER/Security_Report.xlsx\"" \
    "while IFS= read -r root_domain; do" \
    "    echo \"[*] Finding subdomains for \$root_domain\"" \
    "    subfinder -d \"\$root_domain\" -silent >> \"\$SUBDOMAINS_FILE\"" \
    "done < \"$DOMAIN_LIST\"" \
    "cat \"$DOMAIN_LIST\" \"$SUBDOMAINS_FILE\" | sort -u > \"$OUTPUT_FOLDER/combined_domains.txt\"" \
    "python3 \"$TYPO_SCRIPT\" -fdn \"$OUTPUT_FOLDER/combined_domains.txt\" -a -ko --fo text -o \"$TYPO_OUTPUT_FOLDER\" -v" \
    "for file in \"$TYPO_OUTPUT_FOLDER\"/*; do" \
    "    sort -u \"\$file\" -o \"\$file\"" \
    "done" \
    "find \"$TYPO_OUTPUT_FOLDER\" -type f -exec cat {} + | sort -u > \"$DEDUPLICATED_FILE\"" \
    "massdns -r \"$RESOLVERS_FILE\" -o S -q \"$DEDUPLICATED_FILE\" -w \"$RESOLVED_OUTPUT\"" \
    "grep \" A \" \"$RESOLVED_OUTPUT\" | awk '{print \$1}' | sed 's/\\.\$//' > \"$CHECKED_DOMAINS\"" \
    "mkdir -p \"$SCREENSHOTS_FOLDER\"" \
    "gowitness scan file -f \"$CHECKED_DOMAINS\" --screenshot-path \"$SCREENSHOTS_FOLDER\" &> \"$GOWITNESS_LOG\"" \
    "python3 \"$REPORT_GENERATOR_SCRIPT\" \"$OUTPUT_FOLDER\" \"$FINAL_REPORT\"" \
    "echo \"[*] Scan and report generation completed. Report saved as \$FINAL_REPORT.\"" \
    "echo \"[*] gowitness log stored at \$GOWITNESS_LOG\"" \
    | sudo tee "$SCRIPT_PATH" > /dev/null

# Make the generated script executable
sudo chmod +x "$SCRIPT_PATH"

echo "[*] Created new automation script at $SCRIPT_PATH"



