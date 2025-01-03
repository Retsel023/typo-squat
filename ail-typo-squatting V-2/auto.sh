#!/bin/bash

# Lock file
LOCKFILE="/tmp/automate.lock"
QUEUE_FILE="/tmp/cron_queue"

# Ensure the cron_queue file exists and has the correct permissions
touch "$QUEUE_FILE"
chmod 666 "$QUEUE_FILE"

# Check if the lock file exists
if [ -e "$LOCKFILE" ]; then
    echo "[*] Another instance is running. Adding to queue."
    echo "/home/ail-typo-squatting/auto.sh $1 $2" >> "$QUEUE_FILE"
    echo "[*] Job added to queue: /home/ail-typo-squatting/auto.sh $1 $2"
    exit 1
fi

# Create the lock file
touch "$LOCKFILE"

# Ensure the lock file is removed on exit
trap "rm -f $LOCKFILE" EXIT

# Input arguments
DOMAIN_LIST="$1"
OUTPUT_FOLDER="$2"
BACKUP_FOLDER="$OUTPUT_FOLDER/backups"

# Debug statements to confirm input arguments
echo "[*] DOMAIN_LIST: $DOMAIN_LIST"
echo "[*] OUTPUT_FOLDER: $OUTPUT_FOLDER"

# Paths for required tools and files
TYPO_SCRIPT="/home/ail-typo-squatting/ail-typo-squatting/ail_typo_squatting/typo.py"
RESOLVERS_FILE="/home/ail-typo-squatting/resolvers.txt"
REPORT_GENERATOR_SCRIPT="/home/ail-typo-squatting/report2.py"

# Timestamp for backups (format: YYYY-MM-DD_HH-MM-SS)
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# Create necessary directories
mkdir -p "$OUTPUT_FOLDER" "$BACKUP_FOLDER"

# Check for existing output files in OUTPUT_FOLDER and back them up if present
if [ "$(ls -A "$OUTPUT_FOLDER" 2>/dev/null | grep -v "backups")" ]; then
    RUN_BACKUP_FOLDER="$BACKUP_FOLDER/$TIMESTAMP"
    mkdir -p "$RUN_BACKUP_FOLDER"

    echo "[*] Backing up existing output files to $RUN_BACKUP_FOLDER"
    find "$OUTPUT_FOLDER" -mindepth 1 -maxdepth 1 -not -name "backups" -exec mv {} "$RUN_BACKUP_FOLDER" \;
fi

# Define file paths for processing and results
SUBDOMAINS_FILE="$OUTPUT_FOLDER/discovered_subdomains.txt"
TYPO_OUTPUT_FOLDER="$OUTPUT_FOLDER/domains"
DEDUPLICATED_FILE="$OUTPUT_FOLDER/deduplicated_domains.txt"
RESOLVED_OUTPUT="$OUTPUT_FOLDER/resolved.txt"
CHECKED_DOMAINS="$OUTPUT_FOLDER/checked_domains.txt"
SCREENSHOTS_FOLDER="$OUTPUT_FOLDER/screenshots"
GOWITNESS_LOG="$OUTPUT_FOLDER/gowitness.log"
FINAL_REPORT="$OUTPUT_FOLDER/Security_Report.xlsx"

# Step 1: Discover subdomains for each domain and append to subdomain list
echo "[*] Discovering subdomains for each domain in $DOMAIN_LIST"
while IFS= read -r root_domain; do
    echo "[*] Finding subdomains for $root_domain"
    subfinder -d "$root_domain" -silent >> "$SUBDOMAINS_FILE"
done < "$DOMAIN_LIST"

# Combine main domains and discovered subdomains
cat "$DOMAIN_LIST" "$SUBDOMAINS_FILE" | sort -u > "$OUTPUT_FOLDER/combined_domains.txt"

# Step 2: Run typo-squatting generation on the combined domain list
echo "[*] Generating typo-squatting domains"
python3 "$TYPO_SCRIPT" -fdn "$OUTPUT_FOLDER/combined_domains.txt" -a -ko --fo text -o "$TYPO_OUTPUT_FOLDER" -v

# Step 3: Deduplicate typo domain files
echo "[*] Deduplicating typo domain files"
for file in "$TYPO_OUTPUT_FOLDER"/*; do
    sort -u "$file" -o "$file"
done

# Step 4: Combine and deduplicate all generated typo domains
echo "[*] Combining and deduplicating generated typo domains"
find "$TYPO_OUTPUT_FOLDER" -type f -exec cat {} + | sort -u > "$DEDUPLICATED_FILE"

# Step 5: Use massdns to check which domains are registered
echo "[*] Running massdns to resolve domains"
massdns -r "$RESOLVERS_FILE" -o S -q "$DEDUPLICATED_FILE" -w "$RESOLVED_OUTPUT"

# Step 6: Parse massdns output for resolved domains in CHECKED_DOMAINS
echo "[*] Parsing massdns output for resolved domains"
grep " A " "$RESOLVED_OUTPUT" | awk "{print \$1}" | sed "s/\.$//" > "$CHECKED_DOMAINS"

# Step 7: Capture screenshots of resolved domains using gowitness and log the output
echo "[*] Capturing screenshots of resolved domains and logging output"
mkdir -p "$SCREENSHOTS_FOLDER"
gowitness scan file -f "$CHECKED_DOMAINS" --screenshot-path "$SCREENSHOTS_FOLDER" &> "$GOWITNESS_LOG"

# Step 8: Run the Python script to generate the final report
echo "[*] Generating the final security report"
python3 "$REPORT_GENERATOR_SCRIPT" "$OUTPUT_FOLDER" "$FINAL_REPORT" >> "$OUTPUT_FOLDER/report2.log" 2>&1

echo "[*] Scan and report generation completed. Report saved as $FINAL_REPORT."
echo "[*] gowitness log stored at $GOWITNESS_LOG"
