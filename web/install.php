<?php
/**
 * Apache Log Analyser — Setup
 * Run this once to verify your server is ready.
 * Then visit index.php to use the tool.
 */

$checks = [];

// 1. PHP version
$phpOk = version_compare(PHP_VERSION, '7.4.0', '>=');
$checks[] = [
    'label' => 'PHP ' . PHP_VERSION,
    'ok'    => $phpOk,
    'note'  => $phpOk ? 'Good to go.' : 'Need PHP 7.4 or higher.',
];

// 2. Python3
$pythonPath = trim(shell_exec('which python3 2>/dev/null') ?: '');
$pythonVersion = $pythonPath ? trim(shell_exec('python3 --version 2>&1')) : '';
$pythonOk = !empty($pythonPath);
$checks[] = [
    'label' => 'Python 3',
    'ok'    => $pythonOk,
    'note'  => $pythonOk ? $pythonVersion . ' found at ' . $pythonPath : 'Python 3 not found. Install it from python.org',
];

// 3. analyser.py exists
$scriptPath = realpath(__DIR__ . '/../analyser.py');
$scriptOk = $scriptPath && file_exists($scriptPath);
$checks[] = [
    'label' => 'analyser.py',
    'ok'    => $scriptOk,
    'note'  => $scriptOk ? 'Found at ' . $scriptPath : 'Cannot find analyser.py — make sure web/ is inside the apache_log_analyser folder.',
];

// 4. colorama installed
$coloramaOk = false;
if ($pythonOk) {
    $out = shell_exec('python3 -c "import colorama; print(\'ok\')" 2>/dev/null');
    $coloramaOk = trim($out ?? '') === 'ok';
}
$checks[] = [
    'label' => 'Python: colorama',
    'ok'    => $coloramaOk,
    'note'  => $coloramaOk ? 'Installed.' : 'Run: pip3 install colorama',
];

// 5. uploads directory writable
$uploadDir = __DIR__ . '/uploads/';
if (!is_dir($uploadDir)) {
    @mkdir($uploadDir, 0755, true);
}
$uploadOk = is_writable($uploadDir);
$checks[] = [
    'label' => 'Uploads folder',
    'ok'    => $uploadOk,
    'note'  => $uploadOk ? 'Writable.' : 'Cannot write to uploads/ — check folder permissions (chmod 755 web/uploads)',
];

// 6. shell_exec enabled
$shellOk = function_exists('shell_exec') && !in_array('shell_exec', array_map('trim', explode(',', ini_get('disable_functions'))));
$checks[] = [
    'label' => 'shell_exec',
    'ok'    => $shellOk,
    'note'  => $shellOk ? 'Enabled.' : 'shell_exec is disabled in php.ini — this tool needs it to call Python.',
];

$allOk = array_reduce($checks, fn($c, $i) => $c && $i['ok'], true);

// Write config
if ($allOk) {
    $config = "<?php\ndefine('PYTHON_PATH', " . var_export($pythonPath, true) . ");\ndefine('SCRIPT_PATH', " . var_export($scriptPath, true) . ");\ndefine('UPLOAD_DIR', " . var_export($uploadDir, true) . ");\n";
    file_put_contents(__DIR__ . '/config.php', $config);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Apache Log Analyser — Setup</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>

<div class="topbar">
  <div>
    <h1>Apache Log Analyser — Setup</h1>
    <div class="sub">Run this once to verify everything is ready</div>
  </div>
</div>

<div class="container" style="max-width:680px">

  <div class="card">
    <h2>System Check</h2>

    <?php foreach ($checks as $i => $c): ?>
    <div class="install-step">
      <div class="step-num <?= $c['ok'] ? 'done' : 'fail' ?>"><?= $c['ok'] ? '✓' : '✗' ?></div>
      <div class="step-content">
        <div class="step-title"><?= htmlspecialchars($c['label']) ?></div>
        <div class="step-desc"><?= htmlspecialchars($c['note']) ?></div>
      </div>
    </div>
    <?php endforeach; ?>

    <?php if ($allOk): ?>
    <div class="alert alert-ok" style="margin-top:16px">
      ✓ All checks passed. config.php written. <a href="index.php">→ Open the tool</a>
    </div>
    <?php else: ?>
    <div class="alert alert-warn" style="margin-top:16px">
      Fix the issues above then refresh this page.
    </div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2>Quick Start Guide</h2>
    <ol style="padding-left:18px; color:#94a3b8; font-size:13px; line-height:2">
      <li>Make sure you have PHP and Python 3 installed</li>
      <li>Run <code style="background:#23263a;padding:1px 6px;border-radius:3px">pip3 install colorama</code> if needed</li>
      <li>Put this <code style="background:#23263a;padding:1px 6px;border-radius:3px">web/</code> folder inside your Apache or Nginx web root, or run <code style="background:#23263a;padding:1px 6px;border-radius:3px">php -S localhost:8080</code> from the <code style="background:#23263a;padding:1px 6px;border-radius:3px">web/</code> folder</li>
      <li>Visit this page — all ticks = ready</li>
      <li>Go to <a href="index.php">index.php</a> and upload a log file</li>
    </ol>
  </div>

</div>
</body>
</html>
