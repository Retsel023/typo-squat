#!/bin/bash

# Check if correct number of arguments are passed
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <company name> <path to subdomain list>"
    exit 1
fi

# Assign arguments to variables
COMPANY_NAME="$1"
DOMAIN_LIST="$2"

# Check if the specified subdomain list file exists
if [ ! -f "$DOMAIN_LIST" ]; then
    echo "Error: Subdomain list file not found at $DOMAIN_LIST"
    exit 1
fi

# Define output directories and files
COMPANY_OUTPUT_DIR="dnstwist_outputs/$COMPANY_NAME"
BACKUP_DIR="$COMPANY_OUTPUT_DIR/backups"
SCREENSHOT_DIR="$COMPANY_OUTPUT_DIR/screenshots"
DNSTWIST_OUTPUT="$COMPANY_OUTPUT_DIR/dnstwist_output.csv"
ERROR_LOG="$COMPANY_OUTPUT_DIR/dnstwist_errors.log"

# Create backups directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Backup old output if it exists
if [ -d "$COMPANY_OUTPUT_DIR/screenshots" ] || [ -f "$DNSTWIST_OUTPUT" ] || [ -f "$ERROR_LOG" ]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    COMPANY_BACKUP="$BACKUP_DIR/backup_$TIMESTAMP"
    echo "[*] Found previous output for $COMPANY_NAME. Creating backup at $COMPANY_BACKUP"
    mkdir -p "$COMPANY_BACKUP"
    
    # Move previous outputs to the backup folder
    [ -f "$DNSTWIST_OUTPUT" ] && mv "$DNSTWIST_OUTPUT" "$COMPANY_BACKUP"
    [ -f "$ERROR_LOG" ] && mv "$ERROR_LOG" "$COMPANY_BACKUP"
    [ -d "$SCREENSHOT_DIR" ] && mv "$SCREENSHOT_DIR" "$COMPANY_BACKUP"
fi

# Create new output directories
mkdir -p "$SCREENSHOT_DIR"

# Clear previous output files if they exist
> "$DNSTWIST_OUTPUT"
> "$ERROR_LOG"

# Process each domain in the provided domain list file
while IFS= read -r domain; do
    echo "[*] Finding subdomains for $domain..."
    
    # Run subfinder to find subdomains and store in a temporary file
    SUBDOMAINS_FILE=$(mktemp)
    subfinder -d "$domain" -silent >> "$SUBDOMAINS_FILE"
    
    # Check if subdomains were found
    if [ ! -s "$SUBDOMAINS_FILE" ]; then
        echo "[!] No subdomains found for $domain."
        continue
    fi

    echo "[*] Running dnstwist on discovered subdomains and the main domain for $domain..."
    
    # Run dnstwist for the main domain and capture output and errors
    {
        dnstwist -r -f csv --phash --screenshot "$SCREENSHOT_DIR" "$domain" 2>> "$ERROR_LOG"
    } >> "$DNSTWIST_OUTPUT"

    # Also run dnstwist for each subdomain
    while IFS= read -r subdomain; do
        {
            dnstwist -r -f csv --phash --screenshot "$SCREENSHOT_DIR" "$subdomain" 2>> "$ERROR_LOG"
        } >> "$DNSTWIST_OUTPUT"
    done < "$SUBDOMAINS_FILE"

    # Clean up temporary subdomains file
    rm "$SUBDOMAINS_FILE"

done < "$DOMAIN_LIST"

echo "[*] Output saved to $DNSTWIST_OUTPUT"
echo "[*] Screenshots saved in $SCREENSHOT_DIR"
echo "[*] Errors logged to $ERROR_LOG"
