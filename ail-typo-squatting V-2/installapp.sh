pip install flask werkzeug

APP="/home/ail-typo-squatting/app.py"
TEMPLATES="/home/ail-typo-squatting/templates"
INDEX="/home/ail-typo-squatting/templates/index.html"
UPLOAD="/home/ail-typo-squatting/templates/upload_domain_list.html"
COMPANY="/home/ail-typo-squatting/templates/company_files.html"

touch "$APP"
mkdir "$TEMPLATES"
touch "$INDEX"
touch "$UPLOAD"
touch "$COMPANY"
