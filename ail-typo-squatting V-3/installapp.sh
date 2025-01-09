pip install flask werkzeug --break-system-packages

APP="/home/ail-typo-squatting/app.py"
TEMPLATES="/home/ail-typo-squatting/templates"
INDEX="/home/ail-typo-squatting/templates/index.html"
UPLOAD="/home/ail-typo-squatting/templates/upload_domain_list.html"
COMPANY="/home/ail-typo-squatting/templates/company_files.html"
EDIT_CRONTAB="/home/ail-typo-squatting/templates/edit_crontab.html"
REPORTS="/home/ail-typo-squatting/templates/reports.html"

touch "$APP"
mkdir "$TEMPLATES"
touch "$INDEX"
touch "$UPLOAD"
touch "$COMPANY"
touch "$EDIT_CRONTAB"
touch "$REPORTS"

printf '%s\n' "from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
import subprocess
import pandas as pd
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flash messages

OUTPUT_BASE_FOLDER = 'output'
DOMAIN_LIST_FOLDER = 'domain_lists'
os.makedirs(DOMAIN_LIST_FOLDER, exist_ok=True)

@app.route('/')
def index():
    company_folders = [d for d in os.listdir(OUTPUT_BASE_FOLDER) if os.path.isdir(os.path.join(OUTPUT_BASE_FOLDER, d))]
    return render_template('index.html', company_folders=company_folders)

@app.route('/files/<company_name>/', strict_slashes=False)
def view_company_files(company_name):
    company_path = os.path.join(OUTPUT_BASE_FOLDER, company_name)
    if not os.path.exists(company_path):
        return 'Company folder not found', 404
    folder_structure = get_folder_structure(company_path)
    return render_template('company_files.html', company_name=company_name, folder_structure=folder_structure)

@app.route('/upload_domain_list', methods=['GET', 'POST'])
def upload_domain_list():
    if request.method == 'POST':
        file = request.files['domain_list']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(DOMAIN_LIST_FOLDER, filename))
            return redirect(url_for('index'))
    return render_template('upload_domain_list.html')

@app.route('/run_automation', methods=['POST'])
def run_automation():
    domain_list_filename = request.form.get('domain_list')
    company_name = request.form.get('company_name')
    if not domain_list_filename or not company_name:
        return 'Missing domain list or company name', 400
    domain_list_path = os.path.join(DOMAIN_LIST_FOLDER, domain_list_filename)
    output_folder = os.path.join(OUTPUT_BASE_FOLDER, company_name)
    os.makedirs(output_folder, exist_ok=True)
    script_path = './auto.sh'
    command = f'bash {script_path} {domain_list_path} {output_folder}'
    try:
        subprocess.run(command, shell=True, check=True)
        return redirect(url_for('view_company_files', company_name=company_name))
    except subprocess.CalledProcessError as e:
        return f'Error running script: {e}', 500

@app.route('/edit_crontab', methods=['GET', 'POST'])
def edit_crontab():
    if request.method == 'POST':
        new_content = request.form['crontab_content']
        # Ensure the new content ends with a newline character
        if not new_content.endswith('\n'):
            new_content += '\n'
        with open('my-crontab.txt', 'w') as file:
            file.write(new_content)
        # Apply the updated crontab file
        subprocess.run(['crontab', 'my-crontab.txt'])
        flash('Crontab updated successfully!')
        return redirect(url_for('edit_crontab'))
    with open('my-crontab.txt', 'r') as file:
        crontab_content = file.read()
    return render_template('edit_crontab.html', crontab_content=crontab_content)

@app.route('/reports/<company_name>')
def reports(company_name):
    try:
        report_path = os.path.join(OUTPUT_BASE_FOLDER, company_name, 'Security_Report.xlsx')
        df = pd.read_excel(report_path)
        df['HTTP Screenshot'] = df['HTTP Screenshot'].apply(lambda x: f'<img src=\"{x}\" alt=\"HTTP Screenshot\" width=\"200\">' if pd.notna(x) else 'No HTTP screenshot')
        df['HTTPS Screenshot'] = df['HTTPS Screenshot'].apply(lambda x: f'<img src=\"{x}\" alt=\"HTTPS Screenshot\" width=\"200\">' if pd.notna(x) else 'No HTTPS screenshot')
        report_html = df.to_html(escape=False, classes='dataframe', border=1)
        return render_template('reports.html', report_content=report_html)
    except Exception as e:
        return f'Error reading report: {e}', 500

@app.route('/compare_reports/<company_name>')
def compare_reports(company_name):
    try:
        current_report_path = os.path.join(OUTPUT_BASE_FOLDER, company_name, 'Security_Report.xlsx')
        backup_folder = os.path.join(OUTPUT_BASE_FOLDER, company_name)
        backup_dates = [d for d in os.listdir(backup_folder) if os.path.isdir(os.path.join(backup_folder, d))]
        latest_backup_date = max(backup_dates)
        backup_report_path = os.path.join(backup_folder, latest_backup_date, 'Security_Report.xlsx')

        current_report = pd.read_excel(current_report_path)
        backup_report = pd.read_excel(backup_report_path)
        new_data = current_report[~current_report.isin(backup_report)].dropna()
        new_data['HTTP Screenshot'] = new_data['HTTP Screenshot'].apply(lambda x: f'<img src=\"{x}\" alt=\"HTTP Screenshot\" width=\"200\">' if pd.notna(x) else 'No HTTP screenshot')
        new_data['HTTPS Screenshot'] = new_data['HTTPS Screenshot'].apply(lambda x: f'<img src=\"{x}\" alt=\"HTTPS Screenshot\" width=\"200\">' if pd.notna(x) else 'No HTTPS screenshot')
        new_data_html = new_data.to_html(escape=False, classes='dataframe', border=1)
        return render_template('compare_reports.html', new_data_html=new_data_html)
    except Exception as e:
        return f'Error comparing reports: {e}', 500

@app.route('/download/<company_name>/<path:file_path>')
def download_file(company_name, file_path):
    file_full_path = os.path.join(OUTPUT_BASE_FOLDER, company_name, file_path)
    if not os.path.exists(file_full_path):
        return 'File not found', 404
    directory = os.path.dirname(file_full_path)
    filename = os.path.basename(file_full_path)
    return send_from_directory(directory, filename, as_attachment=True)

def get_folder_structure(company_path):
    folder_structure = {'Root': {'files': [], 'subfolders': {}}}
    for root, dirs, files in os.walk(company_path):
        relative_path = os.path.relpath(root, company_path)
        parts = relative_path.split(os.sep)
        current_level = folder_structure['Root']
        for part in parts:
            if part == '.':
                continue
            if part not in current_level['subfolders']:
                current_level['subfolders'][part] = {'files': [], 'subfolders': {}}
            current_level = current_level['subfolders'][part]
        current_level['files'].extend(files)
    return folder_structure

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
" | tee "$APP" > /dev/null

printf '%s\n' "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Dashboard</title>
</head>
<body>
    <h1>Company Folders</h1>
    <ul>
        {% for company in company_folders %}
        <li><a href=\"/files/{{ company }}\">{{ company }}</a></li>
        {% endfor %}
    </ul>
    <h2>Upload Domain List</h2>
    <form action=\"/upload_domain_list\" method=\"post\" enctype=\"multipart/form-data\">
        <input type=\"file\" name=\"domain_list\" required>
        <button type=\"submit\">Upload</button>
    </form>
    <h2>Run Automation</h2>
    <form action=\"/run_automation\" method=\"post\">
        <label for=\"domain_list\">Domain List:</label>
        <input type=\"text\" name=\"domain_list\" required>
        <br>
        <label for=\"company_name\">Company Name:</label>
        <input type=\"text\" name=\"company_name\" required>
        <br>
        <button type=\"submit\">Run Automation</button>
    </form>
    <h2>Additional Features</h2>
    <ul>
        <li><a href=\"/edit_crontab\">Edit Crontab</a></li>
        <li><a href=\"/reports\">View Reports</a></li>
        <li><a href=\"/compare_reports\">Compare Reports</a></li>
    </ul>
</body>
</html>
" | tee "$INDEX" > /dev/null

printf '%s\n' "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Upload Domain List</title>
</head>
<body>
    <h1>Upload Domain List</h1>
    <form action=\"/upload_domain_list\" method=\"post\" enctype=\"multipart/form-data\">
        <input type=\"file\" name=\"domain_list\" required>
        <button type=\"submit\">Upload</button>
    </form>
    <a href=\"/\">Back to dashboard</a>
</body>
</html>
" | tee "$UPLOAD" > /dev/null

printf '%s\n' "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <title>Files for {{ company_name }}</title>
    <style>
        .folder {
            cursor: pointer;
            margin-left: 20px;
        }
        .files {
            display: none;
            margin-left: 20px;
        }
    </style>
    <script>
        function toggleFolder(folderId) {
            var files = document.getElementById(folderId);
            if (files.style.display === \"none\") {
                files.style.display = \"block\";
            } else {
                files.style.display = \"none\";
            }
        }
    </script>
</head>
<body>
    <h1>Files for {{ company_name }}</h1>

    <h2>Root Folder</h2>
    <ul>
        {% for file in folder_structure.Root.files %}
            <li><a href=\"{{ url_for('download_file', company_name=company_name, file_path=file) }}\">{{ file }}</a></li>
        {% endfor %}
    </ul>

    {% macro render_folder(folder, folder_id) %}
        <div class=\"folder\" onclick=\"toggleFolder('{{ folder_id }}')\">
            {{ folder_id }}
        </div>
        <div class=\"files\" id=\"{{ folder_id }}\">
            <ul>
                {% for file in folder.files %}
                    <li><a href=\"{{ url_for('download_file', company_name=company_name, file_path=folder_id + '/' + file) }}\">{{ file }}</a></li>
                {% endfor %}
            </ul>
            {% for subfolder, subcontent in folder.subfolders.items() %}
                {{ render_folder(subcontent, folder_id + '/' + subfolder) }}
            {% endfor %}
        </div>
    {% endmacro %}

    {% for subfolder, subcontent in folder_structure.Root.subfolders.items() %}
        {{ render_folder(subcontent, subfolder) }}
    {% endfor %}
</body>
</html>
" | tee "$COMPANY" > /dev/null

printf '%s\n' "<!DOCTYPE html>
<html>
<head>
    <title>Edit Crontab</title>
</head>
<body>
    <h1>Edit Crontab</h1>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>
            {% for message in messages %}
                <li>{{ message }}</li>
            {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}
    <form action=\"/edit_crontab\" method=\"post\">
        <textarea name=\"crontab_content\" rows=\"20\" cols=\"80\">{{ crontab_content }}</textarea><br>
        <input type=\"submit\" value=\"Update Crontab\">
    </form>
    <a href=\"/\">Back to dashboard</a>
</body>
</html>
" | tee "$EDIT_CRONTAB" > /dev/null

printf '%s\n' "<!DOCTYPE html>
<html>
<head>
    <title>Reports</title>
    <style>
        table.dataframe {
            border-collapse: collapse;
            width: 100%;
        }
        table.dataframe, table.dataframe th, table.dataframe td {
            border: 1px solid black;
        }
        table.dataframe th, table.dataframe td {
            padding: 8px;
            text-align: left;
        }
        table.dataframe th {
            background-color: #f2f2f2;
        }
        img {
            max-width: 200px;
            height: auto;
        }
    </style>
</head>
<body>
    <h1>Reports</h1>
    {{ report_content | safe }}
    <a href=\"/\">Back to dashboard</a>
</body>
</html>
" | tee "$REPORTS" > /dev/null
