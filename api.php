<?php
/**
 * Network Security - PHP REST API
 * 
 * Replaces the FastAPI app (app.py) with a PHP implementation.
 * 
 * Endpoints:
 *   GET  /            → Redirect to /api/info
 *   GET  /api/info    → API documentation / overview (JSON)
 *   GET  /api/train   → Trigger the ML training pipeline
 *   POST /api/predict → Upload a CSV file, run predictions, return HTML table
 */

// ─── Configuration ───────────────────────────────────────────────────────────
define('BASE_DIR', __DIR__);
define('PYTHON_BIN', BASE_DIR . '/venv/bin/python');   // virtualenv python
define('FINAL_MODEL_DIR', BASE_DIR . '/final_model');
define('PREDICTION_OUTPUT_DIR', BASE_DIR . '/prediction_output');
define('UPLOAD_TMP_DIR', BASE_DIR . '/upload_tmp');
define('PREDICT_BRIDGE', BASE_DIR . '/predict_bridge.py');
define('TEMPLATES_DIR', BASE_DIR . '/templates ');       // note: original folder has trailing space

// ─── CORS ────────────────────────────────────────────────────────────────────
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Credentials: true');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ─── Routing ─────────────────────────────────────────────────────────────────
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method     = $_SERVER['REQUEST_METHOD'];

// Strip trailing slash for consistency (but not for root "/")
if ($requestUri !== '/' && str_ends_with($requestUri, '/')) {
    $requestUri = rtrim($requestUri, '/');
}

try {
    switch (true) {
        // GET / → redirect to API info
        case ($method === 'GET' && $requestUri === '/'):
            header('Location: /api/info');
            http_response_code(302);
            break;

        // GET /api/info → show available endpoints
        case ($method === 'GET' && $requestUri === '/api/info'):
            handleInfo();
            break;

        // GET /api/train → run training pipeline
        case ($method === 'GET' && $requestUri === '/api/train'):
            handleTrain();
            break;

        // POST /api/predict → upload CSV & get predictions
        case ($method === 'POST' && $requestUri === '/api/predict'):
            handlePredict();
            break;

        default:
            sendJson(['error' => 'Not Found', 'message' => "No route matches $method $requestUri"], 404);
    }
} catch (Throwable $e) {
    error_log('NetworkSecurity API Error: ' . $e->getMessage());
    sendJson([
        'error'   => 'Internal Server Error',
        'message' => $e->getMessage(),
    ], 500);
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/**
 * GET /api/info
 * Return a JSON overview of all available endpoints.
 */
function handleInfo(): void
{
    sendJson([
        'application' => 'Network Security Phishing Detection API',
        'version'     => '1.0.0',
        'endpoints'   => [
            [
                'method'      => 'GET',
                'path'        => '/api/info',
                'description' => 'API documentation (this page)',
            ],
            [
                'method'      => 'GET',
                'path'        => '/api/train',
                'description' => 'Trigger the full ML training pipeline',
            ],
            [
                'method'      => 'POST',
                'path'        => '/api/predict',
                'description' => 'Upload a CSV file and receive phishing predictions',
                'parameters'  => [
                    'file' => '(multipart/form-data) CSV file to classify',
                ],
            ],
        ],
    ]);
}

/**
 * GET /api/train
 * Execute the Python training pipeline and return the result.
 */
function handleTrain(): void
{
    // Run the training pipeline through Python
    $cmd = escapeshellcmd(PYTHON_BIN) . ' -c '
         . escapeshellarg(
             'import sys; sys.path.insert(0, "' . BASE_DIR . '"); '
           . 'from networksecurity.pipeline.training_pipeline import TrainingPipeline; '
           . 'tp = TrainingPipeline(); tp.run_pipeline(); '
           . 'print("Training is successful")'
         )
         . ' 2>&1';

    $output = [];
    $exitCode = 0;
    exec($cmd, $output, $exitCode);

    $outputStr = implode("\n", $output);

    if ($exitCode !== 0) {
        sendJson([
            'success' => false,
            'message' => 'Training pipeline failed',
            'details' => $outputStr,
        ], 500);
        return;
    }

    sendJson([
        'success' => true,
        'message' => 'Training is successful',
        'output'  => $outputStr,
    ]);
}

/**
 * POST /api/predict
 * Accept a CSV upload, run predictions via Python, return an HTML table.
 */
function handlePredict(): void
{
    // ── 1. Validate upload ───────────────────────────────────────────────
    if (!isset($_FILES['file'])) {
        sendJson(['error' => 'Bad Request', 'message' => 'No file uploaded. Send a CSV file as "file".'], 400);
        return;
    }

    $file = $_FILES['file'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        sendJson(['error' => 'Upload Error', 'message' => 'File upload failed with code ' . $file['error']], 400);
        return;
    }

    // ── 2. Save uploaded file to a temp location ─────────────────────────
    if (!is_dir(UPLOAD_TMP_DIR)) {
        mkdir(UPLOAD_TMP_DIR, 0755, true);
    }

    $tmpCsv = UPLOAD_TMP_DIR . '/' . uniqid('upload_', true) . '.csv';
    move_uploaded_file($file['tmp_name'], $tmpCsv);

    // ── 3. Call the Python prediction bridge ─────────────────────────────
    $cmd = escapeshellcmd(PYTHON_BIN) . ' '
         . escapeshellarg(PREDICT_BRIDGE) . ' '
         . escapeshellarg($tmpCsv)
         . ' 2>&1';

    $output = [];
    $exitCode = 0;
    exec($cmd, $output, $exitCode);

    $outputStr = implode("\n", $output);

    // Clean up temp upload
    @unlink($tmpCsv);

    if ($exitCode !== 0) {
        sendJson([
            'success' => false,
            'message' => 'Prediction failed',
            'details' => $outputStr,
        ], 500);
        return;
    }

    // ── 4. Read the prediction output CSV ────────────────────────────────
    $outputCsv = PREDICTION_OUTPUT_DIR . '/output.csv';

    if (!file_exists($outputCsv)) {
        sendJson(['error' => 'Prediction output not found'], 500);
        return;
    }

    // ── 5. Convert CSV to HTML table ─────────────────────────────────────
    $tableHtml = csvToHtmlTable($outputCsv);

    // ── 6. Render the full HTML page ─────────────────────────────────────
    $html = renderTemplate($tableHtml);

    header('Content-Type: text/html; charset=UTF-8');
    echo $html;
}

// ─── Utility Functions ───────────────────────────────────────────────────────

/**
 * Send a JSON response with the given HTTP status code.
 */
function sendJson(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

/**
 * Parse a CSV file and build an HTML <table>.
 */
function csvToHtmlTable(string $csvPath): string
{
    $rows = [];
    if (($handle = fopen($csvPath, 'r')) !== false) {
        while (($row = fgetcsv($handle)) !== false) {
            $rows[] = $row;
        }
        fclose($handle);
    }

    if (empty($rows)) {
        return '<p>No data available.</p>';
    }

    $html = '<table class="table table-striped">' . "\n";

    // Header row
    $html .= '<thead><tr>';
    foreach ($rows[0] as $header) {
        $html .= '<th>' . htmlspecialchars($header) . '</th>';
    }
    $html .= '</tr></thead>' . "\n";

    // Data rows
    $html .= '<tbody>';
    for ($i = 1, $count = count($rows); $i < $count; $i++) {
        $html .= '<tr>';
        foreach ($rows[$i] as $cell) {
            $html .= '<td>' . htmlspecialchars($cell) . '</td>';
        }
        $html .= '</tr>' . "\n";
    }
    $html .= '</tbody></table>';

    return $html;
}

/**
 * Render the HTML page template with the prediction table.
 */
function renderTemplate(string $tableHtml): string
{
    return <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>Predicted Data</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <h2>Predicted Data</h2>
    {$tableHtml}
</body>
</html>
HTML;
}
