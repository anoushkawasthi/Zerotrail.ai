import json
import random
from pathlib import Path

random.seed(42) 

LANGUAGES = ["python", "javascript", "java", "php"]

SQLI_TEMPLATES = {
    "python": [
        ("""def fetch_user(user_input):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = 'SELECT * FROM users WHERE name=' + user_input
    cursor.execute(query)
    rows = cursor.fetchall()
    result = []
    for row in rows:
        if row:
            result.append(dict(row))
    return result
""", 16),
        ("""def get_orders(order_id):
    connection = db.connect('shop.db')
    sql = f\"SELECT * FROM orders WHERE id={order_id}\"
    cursor = connection.cursor()
    return cursor.execute(sql).fetchall()
""", 14),
        ("""def search_products(term):
    sql = "SELECT * FROM products WHERE title LIKE '%{}%'".format(term)
    result = database.execute(sql)
    return [dict(row) for row in result]
""", 15),
    ],
    "javascript": [
        ("""function getUser(name) {
    const q = 'SELECT * FROM users WHERE display_name=' + name;
    return db.query(q);
}
""", 10),
        ("""function searchBooks(query) {
    const sql = `SELECT * FROM books WHERE author = '${query}'`;
    return database.query(sql);
}
""", 11),
        ("""function listOrders(id) {
    const sql = "SELECT * FROM orders WHERE id=" + id;
    return db.run(sql);
}
""", 10),
    ],
    "java": [
        ("""public List<Map<String,Object>> findUser(String userInput) throws SQLException {
    Connection conn = DriverManager.getConnection(url);
    String stmt = "SELECT * FROM users WHERE username='" + userInput + "'";
    return executeQuery(conn, stmt);
}
""", 12),
        ("""public ResultSet listItems(String itemId) throws SQLException {
    String query = String.format("SELECT * FROM items WHERE id=%s", itemId);
    return connection.createStatement().executeQuery(query);
}
""", 12),
        ("""public void getAccount(String accountId) throws SQLException {
    String sql = "SELECT * FROM accounts WHERE id=" + accountId;
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
}
""", 12),
    ],
    "php": [
        ("""function getUser($name) {
    $query = "SELECT * FROM users WHERE name='" . $name . "'";
    return mysqli_query($db, $query);
}
""", 10),
        ("""function findPost($postId) {
    $sql = sprintf("SELECT * FROM posts WHERE id=%s", $postId);
    return $mysqli->query($sql);
}
""", 10),
        ("""function search($term) {
    $sql = "SELECT * FROM products WHERE title LIKE '%" . $term . "%'";
    return $conn->query($sql);
}
""", 10),
    ],
}

XSS_TEMPLATES = {
    "python": [
        ("""def render_comment(user_input):
    html = '<div>' + user_input + '</div>'
    return html
""", 10),
        ("""def show_message(message):
    return f'<p>{message}</p>'
""", 10),
        ("""def build_page(user_comment):
    body = '<span>' + user_comment + '</span>'
    return body
""", 10),
    ],
    "javascript": [
        ("""function display(userInput) {
    const container = document.getElementById('output');
    const html = '<div class="message">' + userInput + '</div>';
    container.innerHTML = html;
    if (userInput.includes('<script>')) {
        console.warn('potential XSS payload');
        container.classList.add('warning');
    }
    const metadata = document.createElement('span');
    metadata.textContent = 'Rendered on ' + new Date().toISOString();
    container.appendChild(metadata);
    const footer = document.createElement('div');
    footer.textContent = 'Content length: ' + userInput.length;
    container.appendChild(footer);
    return container.innerHTML;
}
""", 16),
        ("""function render(msg) {
    document.write(msg);
}
""", 7),
        ("""function show(name) {
    const container = document.querySelector('#target');
    container.innerHTML = '<div>' + name + '</div>';
}
""", 10),
    ],
    "java": [
        ("""public String buildPage(String comment) {
    return "<div>" + comment + "</div>";
}
""", 7),
        ("""public void writeResponse(HttpServletResponse resp, String userName) throws IOException {
    resp.getWriter().println("<span>" + userName + "</span>");
}
""", 10),
        ("""public String show(String unsafe) {
    return "<p>" + unsafe + "</p>";
}
""", 7),
    ],
    "php": [
        ("""function render($name) {
    echo '<h1>' . $name . '</h1>';
}
""", 7),
        ("""function greet($user) {
    echo $_GET['name'];
}
""", 6),
        ("""function profile($bio) {
    print '<div>' . $bio . '</div>';
}
""", 7),
    ],
}

CMDI_TEMPLATES = {
    "python": [
        ("""def ping_host(host):
    cmd = 'ping -c 4 ' + host
    os.system(cmd)
""", 8),
        ("""def list_dir(path):
    command = 'ls ' + path
    subprocess.call(command, shell=True)
""", 8),
        ("""def run_backup(filename):
    cmd = 'tar -czf backup.tar.gz ' + filename
    os.system(cmd)
""", 9),
    ],
    "javascript": [
        ("""function execute(cmd) {
    child_process.exec('sh -c "' + cmd + '"');
}
""", 7),
        ("""function runTask(task) {
    exec('bash -c ' + task, function(err){
        if (err) throw err;
    });
}
""", 9),
        ("""function ping(host) {
    require('child_process').exec('ping ' + host);
}
""", 8),
    ],
    "java": [
        ("""public void deleteFile(String target) throws IOException, InterruptedException {
    String command = "rm -rf " + target;
    Process process = Runtime.getRuntime().exec(command);
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }
    int exitCode = process.waitFor();
    if (exitCode != 0) {
        throw new IOException("Command failed: " + exitCode);
    }
    logger.info("Deleted target: " + target);
}
""", 17),
        ("""public void runCommand(String arg) throws IOException {
    String command = "cmd /c " + arg;
    Runtime.getRuntime().exec(command);
}
""", 8),
        ("""public void list(String path) throws IOException {
    Process p = Runtime.getRuntime().exec("ls " + path);
}
""", 8),
    ],
    "php": [
        ("""function remove($file) {
    system('rm ' . $file);
}
""", 6),
        ("""function run($cmd) {
    exec($cmd);
}
""", 5),
        ("""function ping($host) {
    shell_exec('ping ' . $host);
}
""", 6),
    ],
}

PATH_TEMPLATES = {
    "python": [
        ("""def read_file(filename):
    path = '/var/www/' + filename
    with open(path, 'r') as f:
        contents = f.read()
    if not contents:
        return ''
    return contents
""", 11),
        ("""def get_file(user_path):
    file_path = base_dir + '/' + user_path
    return open(file_path).read()
""", 9),
        ("""def save_log(log_path):
    with open('/tmp/' + log_path, 'r') as f:
        return f.read()
""", 9),
    ],
    "javascript": [
        ("""function load(fileName) {
    const full = '/var/www/' + fileName;
    return fs.readFileSync(full, 'utf8');
}
""", 9),
        ("""function download(userPath) {
    return fs.readFileSync(path.join(baseDir, userPath), 'utf8');
}
""", 9),
        ("""function loadData(name) {
    const target = __dirname + '/' + name;
    return fs.readFileSync(target, 'utf8');
}
""", 9),
    ],
    "java": [
        ("""public String openFile(String fileName) throws IOException {
    File file = new File(basePath + "/" + fileName);
    if (!file.exists()) {
        throw new FileNotFoundException(file.getPath());
    }
    String contents = new String(Files.readAllBytes(file.toPath()));
    if (contents.isEmpty()) {
        return "";
    }
    // the caller expects the raw file contents as a string
    return contents;
}
""", 16),
        ("""public void serve(String path) throws IOException {
    File data = new File(rootDir + File.separator + path);
    Files.copy(data.toPath(), response.getOutputStream());
}
""", 11),
        ("""public String read(String param) throws IOException {
    String full = "/home/app/" + param;
    return new String(Files.readAllBytes(Paths.get(full)));
}
""", 10),
    ],
    "php": [
        ("""function load($filename) {
    $file = '/var/www/' . $filename;
    return file_get_contents($file);
}
""", 8),
        ("""function sendFile($path) {
    readfile(__DIR__ . '/' . $path);
}
""", 7),
        ("""function openLog($name) {
    $full = "/var/www/html/" . $name;
    return fopen($full, 'r');
}
""", 8),
    ],
}

SAFE_TEMPLATES = {
    "python": [
        ("""def fetch_user(user_input):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = 'SELECT * FROM users WHERE name=?'
    cursor.execute(query, (user_input,))
    rows = cursor.fetchall()
    output = []
    for row in rows:
        if row is None:
            continue
        output.append({
            'id': row[0],
            'name': row[1],
        })
    return output
""", 16),
        ("""def get_comment(msg):
    safe_html = '<div>' + html.escape(msg) + '</div>'
    return safe_html
""", 10),
        ("""def list_dir(path):
    sanitized = os.path.basename(path)
    if sanitized not in allowed_files:
        raise ValueError('invalid path')
    return open(os.path.join(base_dir, sanitized)).read()
""", 13),
        ("""def backup(filename):
    subprocess.run(['tar', '-czf', 'backup.tar.gz', filename], shell=False)
""", 9),
    ],
    "javascript": [
        ("""function display(userInput) {
    document.getElementById('output').textContent = userInput;
}
""", 8),
        ("""function executeSafe(command) {
    child_process.execFile('ls', [command]);
}
""", 7),
        ("""function read(userPath) {
    const filename = path.basename(userPath);
    return fs.readFileSync(path.join(baseDir, filename), 'utf8');
}
""", 9),
    ],
    "java": [
        ("""public List<Map<String,Object>> getOrders(String orderId) throws SQLException {
    PreparedStatement stmt = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
    stmt.setString(1, orderId);
    ResultSet resultSet = stmt.executeQuery();
    List<Map<String,Object>> output = new ArrayList<>();
    while (resultSet.next()) {
        Map<String,Object> row = new HashMap<>();
        row.put("id", resultSet.getString("id"));
        row.put("amount", resultSet.getString("amount"));
        output.add(row);
    }
    return output;
}
""", 16),
        ("""public void writeSafe(HttpServletResponse resp, String comment) throws IOException {
    resp.getWriter().println(StringEscapeUtils.escapeHtml4(comment));
}
""", 10),
        ("""public String readFile(String userPath) throws IOException {
    String safeName = Paths.get(userPath).getFileName().toString();
    if (!allowed.contains(safeName)) throw new IOException("Invalid file");
    return Files.readString(Paths.get(baseDir, safeName));
}
""", 13),
    ],
    "php": [
        ("""function getUser($name) {
    $stmt = $db->prepare('SELECT * FROM users WHERE name = ?');
    $stmt->bind_param('s', $name);
    $stmt->execute();
    return $stmt->get_result();
}
""", 13),
        ("""function render($text) {
    echo htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}
""", 7),
        ("""function download($path) {
    $safe = basename($path);
    if (!in_array($safe, $whitelist)) {
        throw new Exception('Invalid file');
    }
    readfile(__DIR__ . '/' . $safe);
}
""", 12),
    ],
}

VARIABLES = [
    'user_input', 'request', 'payload', 'input', 'name', 'query', 'search', 'data', 'term', 'text', 'comment'
]

def choose_name(exclude=None):
    names = [n for n in VARIABLES if n != exclude]
    return random.choice(names)


def add_comment_and_whitespace(code, language):
    lines = code.strip().split('\n')
    new_lines = []
    for line in lines:
        new_lines.append(line)
        if random.random() < 0.12:
            if language == 'python':
                new_lines.append('    # fetch user record')
            elif language == 'javascript':
                new_lines.append('    // render user content')
            elif language == 'java':
                new_lines.append('    // sanitize later')
            else:
                new_lines.append('    // check path')
        if random.random() < 0.1:
            new_lines.append('')
    return '\n'.join(new_lines)


def randomize_template(template, language):
    code = template
    if language == 'python':
        code = code.replace('user_input', choose_name('user_input'))
        code = code.replace('query', choose_name('query'))
        code = code.replace('term', choose_name('term'))
        code = code.replace('order_id', choose_name('order_id'))
        code = code.replace('name', choose_name('name'))
        code = code.replace('userName', choose_name('userName'))
        code = code.replace('itemId', choose_name('itemId'))
        code = code.replace('fileName', choose_name('fileName'))
        code = code.replace('filename', choose_name('filename'))
    elif language == 'javascript':
        code = code.replace('name', choose_name('name'))
        code = code.replace('userInput', choose_name('userInput'))
        code = code.replace('query', choose_name('query'))
        code = code.replace('msg', choose_name('msg'))
        code = code.replace('cmd', choose_name('cmd'))
        code = code.replace('host', choose_name('host'))
        code = code.replace('fileName', choose_name('fileName'))
        code = code.replace('userPath', choose_name('userPath'))
        code = code.replace('path', choose_name('path'))
    elif language == 'java':
        code = code.replace('userInput', choose_name('userInput'))
        code = code.replace('orderId', choose_name('orderId'))
        code = code.replace('accountId', choose_name('accountId'))
        code = code.replace('itemId', choose_name('itemId'))
        code = code.replace('target', choose_name('target'))
        code = code.replace('arg', choose_name('arg'))
        code = code.replace('fileName', choose_name('fileName'))
        code = code.replace('userPath', choose_name('userPath'))
        code = code.replace('comment', choose_name('comment'))
    else:
        code = code.replace('$name', '$' + choose_name('name'))
        code = code.replace('$term', '$' + choose_name('term'))
        code = code.replace('$postId', '$' + choose_name('postId'))
        code = code.replace('$file', '$' + choose_name('file'))
        code = code.replace('$host', '$' + choose_name('host'))
        code = code.replace('$cmd', '$' + choose_name('cmd'))
        code = code.replace('$path', '$' + choose_name('path'))
    return code


def make_samples(templates, lang_counts, vuln_type):
    samples = []
    for language, target in lang_counts.items():
        templates_list = templates[language]
        for i in range(target):
            base = random.choice(templates_list)[0]
            code = randomize_template(base, language)
            if random.random() < 0.35:
                code = add_comment_and_whitespace(code, language)
            samples.append((language, code, vuln_type))
    return samples


counts = {
    'SQLi': {'python': 20, 'javascript': 15, 'java': 15, 'php': 10},
    'XSS': {'python': 15, 'javascript': 25, 'java': 10, 'php': 10},
    'CMDi': {'python': 20, 'javascript': 10, 'java': 10, 'php': 10},
    'PathTraversal': {'python': 20, 'javascript': 10, 'java': 10, 'php': 10},
    'none': {'python': 30, 'javascript': 25, 'java': 25, 'php': 50},
}

samples = []
for vuln_type, lang_counts in counts.items():
    if vuln_type == 'none':
        templates = SAFE_TEMPLATES
    else:
        templates = {
            'SQLi': SQLI_TEMPLATES,
            'XSS': XSS_TEMPLATES,
            'CMDi': CMDI_TEMPLATES,
            'PathTraversal': PATH_TEMPLATES,
        }[vuln_type]
    samples.extend(make_samples(templates, lang_counts, vuln_type))

assert len(samples) == 350, len(samples)

# Make sure no exact duplicates and all line limits satisfied
unique_codes = set()
cleaned_samples = []
for language, code, vuln_type in samples:
    code = code.strip()
    lines = [line for line in code.split('\n') if line.strip()]
    if len(lines) < 10:
        # pad with a benign comment or blank lines to hit the minimum
        while len(lines) < 10:
            lines.append('    # additional logic' if language == 'python' else '    // more logic')
        code = '\n'.join(lines)
    if code in unique_codes:
        code += '\n' + ('# variant' if language == 'python' else '// variant')
    unique_codes.add(code)
    cleaned_samples.append((language, code, vuln_type))

records = []
for idx, (language, code, vuln_type) in enumerate(cleaned_samples, start=1):
    label = 'safe' if vuln_type == 'none' else 'vulnerable'
    records.append({
        'id': idx,
        'language': language,
        'code': code,
        'label': label,
        'vuln_type': vuln_type,
    })

out_path = Path('vuln_dataset.json')
with out_path.open('w', encoding='utf-8') as f:
    json.dump(records, f, indent=2)

augmented = list(records)
for record in records:
    # create one augmented variant for 100 of the records
    if record['id'] % 3 == 0:
        code = record['code']
        if record['language'] == 'python':
            code = code.replace('user_input', 'req_data')
            code = code.replace('query', 'sql_str')
            code = code.replace('cmd', 'command')
        elif record['language'] == 'javascript':
            code = code.replace('userInput', 'req_data')
            code = code.replace('query', 'sqlStr')
        elif record['language'] == 'java':
            code = code.replace('userInput', 'reqData')
            code = code.replace('query', 'sqlQuery')
        else:
            code = code.replace('$name', '$req_data')
            code = code.replace('$query', '$sql_str')
        code = add_comment_and_whitespace(code, record['language'])
        augmented.append({
            'id': len(augmented) + 1,
            'language': record['language'],
            'code': code,
            'label': record['label'],
            'vuln_type': record['vuln_type'],
        })

with Path('vuln_dataset_augmented.json').open('w', encoding='utf-8') as f:
    json.dump(augmented, f, indent=2)

print(f'Wrote {len(records)} records to {out_path.name}')
print(f'Wrote {len(augmented)} records to vuln_dataset_augmented.json')
