<?php
header('Content-Type: application/json');

if (!file_exists(__DIR__ . '/config.php')) {
    echo json_encode(['error' => 'Not configured — run install.php first']);
    exit;
}
require __DIR__ . '/config.php';

function run_analyser(string $filepath): array {
    $python = escapeshellarg(PYTHON_PATH);
    $script = escapeshellarg(SCRIPT_PATH);
    $file   = escapeshellarg($filepath);
    $cmd    = "$python $script $file --format json 2>&1";
    $output = shell_exec($cmd);
    if (!$output) {
        return ['error' => 'No output from analyser — check Python is installed and analyser.py exists'];
    }
    $data = json_decode($output, true);
    if (!$data) {
        return ['error' => 'Could not parse analyser output: ' . substr($output, 0, 200)];
    }
    return $data;
}

// Sample mode
if (isset($_GET['sample'])) {
    $samplePath = realpath(__DIR__ . '/../sample.log');
    if (!$samplePath || !file_exists($samplePath)) {
        echo json_encode(['error' => 'sample.log not found']);
        exit;
    }
    echo json_encode(run_analyser($samplePath));
    exit;
}

// File upload mode
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_FILES['logfile'])) {
    echo json_encode(['error' => 'No file uploaded']);
    exit;
}

$file = $_FILES['logfile'];

if ($file['error'] !== UPLOAD_ERR_OK) {
    echo json_encode(['error' => 'Upload error code: ' . $file['error']]);
    exit;
}

// Validate extension
$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
if (!in_array($ext, ['log', 'gz', 'txt'])) {
    echo json_encode(['error' => 'Invalid file type — upload a .log, .log.gz or .txt file']);
    exit;
}

// Max 50MB
if ($file['size'] > 52428800) {
    echo json_encode(['error' => 'File too large — max 50MB']);
    exit;
}

$uploadPath = UPLOAD_DIR . 'upload_' . uniqid() . '.' . $ext;
if (!move_uploaded_file($file['tmp_name'], $uploadPath)) {
    echo json_encode(['error' => 'Could not save uploaded file']);
    exit;
}

$result = run_analyser($uploadPath);

// Clean up temp file
@unlink($uploadPath);

echo json_encode($result);
