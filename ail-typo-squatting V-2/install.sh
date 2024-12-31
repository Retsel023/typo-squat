apt update && apt upgrade -y
apt install -y python3 python3-pip gowitness git subfinder massdns

mkdir /home/ail-typo-squatting
mkdir /home/ail-typo-squatting/output
chmod 777 /home/ail-typo-squatting

# Define the script path
SCRIPT_PATH="/home/ail-typo-squatting/automate.sh"
REPORT_SCRIPT="/home/ail-typo-squatting/report2.py"
touch "$SCRIPT_PATH"
touch "$REPORT_SCRIPT"
# Use printf to create the script content and write it to the target file
printf '%s\n' '#!/bin/bash' \
'' \
'# Input arguments' \
'DOMAIN_LIST="$1"                       # Path to the domain list file' \
'OUTPUT_FOLDER="$2"                     # Main output directory for this company' \
'BACKUP_FOLDER="$OUTPUT_FOLDER/backups" # Directory to store backups' \
'' \
'# Paths for required tools and files' \
'TYPO_SCRIPT="ail-typo-squatting/ail_typo_squatting/typo.py" # Path to typo.py for typo generation' \
'RESOLVERS_FILE="resolvers.txt"               # Path to resolvers file for massdns' \
'REPORT_GENERATOR_SCRIPT="report2.py" # Python script for generating the report' \
'' \
'# Timestamp for backups (format: YYYY-MM-DD_HH-MM-SS)' \
'TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")' \
'' \
'# Create necessary directories' \
'mkdir -p "$OUTPUT_FOLDER" "$BACKUP_FOLDER"' \
'' \
'# Check for existing output files in OUTPUT_FOLDER and back them up if present' \
'if [ "$(ls -A "$OUTPUT_FOLDER" 2>/dev/null | grep -v "backups")" ]; then' \
'    RUN_BACKUP_FOLDER="$BACKUP_FOLDER/$TIMESTAMP"' \
'    mkdir -p "$RUN_BACKUP_FOLDER"' \
'' \
'    echo "[*] Backing up existing output files to $RUN_BACKUP_FOLDER"' \
'    find "$OUTPUT_FOLDER" -mindepth 1 -maxdepth 1 -not -name "backups" -exec mv {} "$RUN_BACKUP_FOLDER" \;' \
'fi' \
'' \
'# Define file paths for processing and results' \
'SUBDOMAINS_FILE="$OUTPUT_FOLDER/discovered_subdomains.txt"' \
'TYPO_OUTPUT_FOLDER="$OUTPUT_FOLDER/domains"' \
'DEDUPLICATED_FILE="$OUTPUT_FOLDER/deduplicated_domains.txt"' \
'RESOLVED_OUTPUT="$OUTPUT_FOLDER/resolved.txt"' \
'CHECKED_DOMAINS="$OUTPUT_FOLDER/checked_domains.txt"' \
'SCREENSHOTS_FOLDER="$OUTPUT_FOLDER/screenshots"' \
'GOWITNESS_LOG="$OUTPUT_FOLDER/gowitness.log"  # Log file for gowitness' \
'FINAL_REPORT="$OUTPUT_FOLDER/Security_Report.xlsx" # Path for final report' \
'' \
'# Step 1: Discover subdomains for each domain and append to subdomain list' \
'echo "[*] Discovering subdomains for each domain in $DOMAIN_LIST"' \
'while IFS= read -r root_domain; do' \
'    echo "[*] Finding subdomains for $root_domain"' \
'    subfinder -d "$root_domain" -silent >> "$SUBDOMAINS_FILE"' \
'done < "$DOMAIN_LIST"' \
'' \
'# Combine main domains and discovered subdomains' \
'cat "$DOMAIN_LIST" "$SUBDOMAINS_FILE" | sort -u > "$OUTPUT_FOLDER/combined_domains.txt"' \
'' \
'# Step 2: Run typo-squatting generation on the combined domain list' \
'echo "[*] Generating typo-squatting domains"' \
'python3 "$TYPO_SCRIPT" -fdn "$OUTPUT_FOLDER/combined_domains.txt" -a -ko --fo text -o "$TYPO_OUTPUT_FOLDER" -v' \
'' \
'# Step 3: Deduplicate typo domain files' \
'echo "[*] Deduplicating typo domain files"' \
'for file in "$TYPO_OUTPUT_FOLDER"/*; do' \
'    sort -u "$file" -o "$file" # Sort and remove duplicates in-place' \
'done' \
'' \
'# Step 4: Combine and deduplicate all generated typo domains' \
'echo "[*] Combining and deduplicating generated typo domains"' \
'find "$TYPO_OUTPUT_FOLDER" -type f -exec cat {} + | sort -u > "$DEDUPLICATED_FILE"' \
'' \
'# Step 5: Use massdns to check which domains are registered' \
'echo "[*] Running massdns to resolve domains"' \
'massdns -r "$RESOLVERS_FILE" -o S -q "$DEDUPLICATED_FILE" -w "$RESOLVED_OUTPUT"' \
'' \
'# Step 6: Parse massdns output for resolved domains in CHECKED_DOMAINS' \
'echo "[*] Parsing massdns output for resolved domains"' \
'grep " A " "$RESOLVED_OUTPUT" | awk "{print \$1}" | sed "s/\.$//" > "$CHECKED_DOMAINS"' \
'' \
'# Step 7: Capture screenshots of resolved domains using gowitness and log the output' \
'echo "[*] Capturing screenshots of resolved domains and logging output"' \
'mkdir -p "$SCREENSHOTS_FOLDER"' \
'gowitness scan file -f "$CHECKED_DOMAINS" --screenshot-path "$SCREENSHOTS_FOLDER" &> "$GOWITNESS_LOG"' \
'' \
'# Step 8: Run the Python script to generate the final report' \
'echo "[*] Generating the final security report"' \
'python3 "$REPORT_GENERATOR_SCRIPT" "$OUTPUT_FOLDER" "$FINAL_REPORT"' \
'' \
'echo "[*] Scan and report generation completed. Report saved as $FINAL_REPORT."' \
'echo "[*] gowitness log stored at $GOWITNESS_LOG"' | tee /home/ail-typo-squatting/automate.sh > /dev/null


# Make the generated script executable
chmod +x "$SCRIPT_PATH"
touch /home/ail-typo-squatting/resolvers.txt
printf '%s\n' '1.1.1.1' \
'1.0.0.1' \
'9.9.9.9' \
'8.8.8.8' \
'208.67.222.222' \
| tee /home/ail-typo-squatting/resolvers.txt > /dev/null

# Use printf to write the Python script content to the target file
printf '%s\n' 'import openpyxl' \
'from openpyxl.drawing.image import Image' \
'from openpyxl.styles import Font, Alignment' \
'import os' \
'import sys' \
'import glob' \
'' \
'# Check for correct number of arguments' \
'if len(sys.argv) != 3:' \
'    print("Usage: python generate_report.py <output_folder> <report_output_path>")' \
'    sys.exit(1)' \
'' \
'# Command-line arguments' \
'output_folder = sys.argv[1]' \
'output_report = sys.argv[2]' \
'' \
'# Define file paths based on the output folder' \
'resolved_domains_file = os.path.join(output_folder, "resolved.txt")' \
'screenshots_folder = os.path.join(output_folder, "screenshots")' \
'' \
'# Validate input paths' \
'if not os.path.exists(output_folder):' \
'    print(f"Output folder not found: {output_folder}")' \
'    sys.exit(1)' \
'' \
'if not os.path.exists(resolved_domains_file):' \
'    print(f"Resolved domains file not found: {resolved_domains_file}")' \
'    sys.exit(1)' \
'' \
'if not os.path.exists(screenshots_folder):' \
'    print(f"Screenshots folder not found: {screenshots_folder}")' \
'    sys.exit(1)' \
'' \
'# Initialize workbook and active sheet' \
'wb = openpyxl.Workbook()' \
'ws = wb.active' \
'ws.title = "Resolved Domains Report"' \
'' \
'# Define column headers' \
'headers = ["Domain", "Record Type", "IP/CNAME", "HTTP Screenshot", "HTTPS Screenshot"]' \
'for col, header in enumerate(headers, 1):' \
'    ws.cell(row=1, column=col, value=header)' \
'    ws.cell(row=1, column=col).font = Font(bold=True)' \
'    ws.cell(row=1, column=col).alignment = Alignment(horizontal="center")' \
'' \
'# Read resolved domains' \
'with open(resolved_domains_file, "r") as f:' \
'    resolved_domains = [line.strip() for line in f if line.strip()]' \
'' \
'# Set initial row height to allow room for screenshots' \
'for row in range(2, len(resolved_domains) + 2):' \
'    ws.row_dimensions[row].height = 110' \
'' \
'# Define a helper function to find a screenshot file matching the domain' \
'def find_screenshot(domain, protocol, folder):' \
'    pattern = os.path.join(folder, f"{protocol}---{domain}-*.jpeg")' \
'    matching_files = glob.glob(pattern)' \
'    return matching_files[0] if matching_files else None' \
'' \
'# Populate the worksheet with domain data' \
'row = 2' \
'for domain_entry in resolved_domains:' \
'    parts = domain_entry.split()' \
'    if len(parts) >= 3:' \
'        domain = parts[0].rstrip(".")' \
'        record_type = parts[1]' \
'        ip_or_cname = parts[2]' \
'' \
'        ws.cell(row=row, column=1, value=domain)' \
'        ws.cell(row=row, column=2, value=record_type)' \
'        ws.cell(row=row, column=3, value=ip_or_cname)' \
'' \
'        http_screenshot_path = find_screenshot(domain, "http", screenshots_folder)' \
'        https_screenshot_path = find_screenshot(domain, "https", screenshots_folder)' \
'' \
'        http_img = None' \
'        https_img = None' \
'' \
'        if http_screenshot_path and os.path.exists(http_screenshot_path):' \
'            http_img = Image(http_screenshot_path)' \
'            http_img.width, http_img.height = 200, 150' \
'' \
'        if https_screenshot_path and os.path.exists(https_screenshot_path):' \
'            https_img = Image(https_screenshot_path)' \
'            https_img.width, https_img.height = 200, 150' \
'' \
'        if http_img:' \
'            ws.add_image(http_img, f"D{row}")' \
'        else:' \
'            ws.cell(row=row, column=4, value="No HTTP screenshot")' \
'' \
'        if https_img:' \
'            ws.add_image(https_img, f"E{row}")' \
'        else:' \
'            ws.cell(row=row, column=5, value="No HTTPS screenshot")' \
'' \
'        row += 1' \
'' \
'ws.column_dimensions["A"].width = 30' \
'ws.column_dimensions["B"].width = 15' \
'ws.column_dimensions["C"].width = 25' \
'ws.column_dimensions["D"].width = 60' \
'ws.column_dimensions["E"].width = 60' \
'' \
'wb.save(output_report)' \
'print(f"Security report saved as {output_report}")' \
| tee "$REPORT_SCRIPT" > /dev/null

git clone https://github.com/typosquatter/ail-typo-squatting.git /home/ail-typo-squatting/ail-typo-squatting
pip install -r /home/ail-typo-squatting/ail-typo-squatting/requirements.txt --break-system-packages
pip install openpyxl retrie requests tldextract --break-system-packages

touch /home/ail-typo-squatting/usage.txt
printf '%s\n' './automate.sh <domainlist> <company name>' | tee /home/ail-typo-squatting/usage.txt

#if urlib3 keeps failing
#apt remove python3-urllib3
#pip install urllib3 --break-system-packages

