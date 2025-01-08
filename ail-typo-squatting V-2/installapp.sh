pip install flask werkzeug --break-system-packages

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

printf '%s\n' "import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import subprocess

app = Flask(__name__)

# Define the base path for the output directory (where company-specific folders are stored)
OUTPUT_BASE_FOLDER = 'output'  # Base folder where company folders are
DOMAIN_LIST_FOLDER = 'domain_lists'  # Folder where domain lists are stored

# Ensure the domain list folder exists
os.makedirs(DOMAIN_LIST_FOLDER, exist_ok=True)

@app.route('/')
def index():
    # Get all company folders in the output base directory
    company_folders = [d for d in os.listdir(OUTPUT_BASE_FOLDER) if os.path.isdir(os.path.join(OUTPUT_BASE_FOLDER, d))]
    return render_template('index.html', company_folders=company_folders)

@app.route('/files/<company_name>/', strict_slashes=False)
def view_company_files(company_name):
    print(f'Requested company: {company_name}')  # This will print to the console
    company_path = os.path.join(OUTPUT_BASE_FOLDER, company_name)

    if not os.path.exists(company_path):
        print(f'Folder does not exist: {company_path}')  # This helps to debug
        return 'Company folder not found', 404

    folder_structure = get_folder_structure(company_path)
    return render_template('company_files.html', company_name=company_name, folder_structure=folder_structure)

@app.route('/upload_domain_list', methods=['GET', 'POST'])
def upload_domain_list():
    if request.method == 'POST':
        file = request.files['domain_list']
        if file:
            # Save the uploaded file to the domain_lists folder
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

    # Create the output folder if it does not exist
    os.makedirs(output_folder, exist_ok=True)

    # Execute the shell script (automate.sh)
    script_path = './automate.sh'  # Ensure automate.sh is in the correct path
    command = f'bash {script_path} {domain_list_path} {output_folder}'

    # Run the command as a subprocess
    try:
        subprocess.run(command, shell=True, check=True)
        return redirect(url_for('view_company_files', company_name=company_name))
    except subprocess.CalledProcessError as e:
        return f'Error running script: {e}', 500

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

    # Check if the structure was found properly
    print(f'Folder structure for {company_path}: {folder_structure}')
    return folder_structure

@app.route('/download/<company_name>/<path:file_path>')
def download_file(company_name, file_path):
    file_full_path = os.path.join(OUTPUT_BASE_FOLDER, company_name, file_path)
    if not os.path.exists(file_full_path):
        return 'File not found', 404
    directory = os.path.dirname(file_full_path)
    filename = os.path.basename(file_full_path)
    print(f'Downloading file: {file_full_path}')
    return send_from_directory(directory, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
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

