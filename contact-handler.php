<?php
/**
 * B_LineGraphix Contact Form Handler
 * Adaptiert von CITECH Contact Handler v3
 *
 * Sicherheitsfeatures:
 * - CSRF-Schutz via Origin-Check
 * - Rate Limiting (3 Anfragen pro Stunde)
 * - Honeypot-Feld Pruefung
 * - Input-Sanitierung
 * - E-Mail-Validierung
 */

// ============================================
// KONFIGURATION
// ============================================
$config = [
    'email_to' => 'info@blinegraphix.de',
    'from_email' => 'noreply@blinegraphix.de',

    'allowed_origins' => [
        'https://blinegraphix.de',
        'https://www.blinegraphix.de',
        'http://blinegraphix.de',
        'http://www.blinegraphix.de',
        'http://localhost:5173',
        'http://localhost:5174',
    ],

    'max_submissions_per_hour' => 3,
    'debug' => false
];

// ============================================
// CORS & JSON Response Setup
// ============================================
header('Content-Type: application/json; charset=utf-8');

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $config['allowed_origins'])) {
    header("Access-Control-Allow-Origin: $origin");
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ============================================
// HILFSFUNKTIONEN
// ============================================

function sendResponse($success, $message = '', $code = 200) {
    http_response_code($code);
    echo json_encode([
        'success' => $success,
        'error' => $success ? null : $message,
        'message' => $success ? $message : null
    ], JSON_UNESCAPED_UNICODE);
    exit();
}

function sanitizeInput($input, $maxLength = 1000) {
    if (empty($input)) return '';
    $input = trim($input);
    $input = strip_tags($input);
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    return mb_substr($input, 0, $maxLength);
}

function isValidEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

// ============================================
// SICHERHEITSPRUEFUNGEN
// ============================================

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse(false, 'Method not allowed', 405);
}

if (!empty($origin) && !in_array($origin, $config['allowed_origins'])) {
    sendResponse(false, 'Forbidden', 403);
}

// ============================================
// RATE LIMITING
// ============================================
session_start();

$rate_key = 'contact_rate_limit';
$current_time = time();
$time_window = 3600;

if (!isset($_SESSION[$rate_key])) {
    $_SESSION[$rate_key] = ['count' => 0, 'window_start' => $current_time];
}

if ($current_time - $_SESSION[$rate_key]['window_start'] > $time_window) {
    $_SESSION[$rate_key] = ['count' => 0, 'window_start' => $current_time];
}

if ($_SESSION[$rate_key]['count'] >= $config['max_submissions_per_hour']) {
    sendResponse(false, 'Zu viele Anfragen. Bitte versuchen Sie es spaeter erneut.', 429);
}

// ============================================
// HONEYPOT (Bot-Schutz)
// ============================================
$honeypot = $_POST['website'] ?? '';
if (!empty($honeypot)) {
    sendResponse(true, 'Nachricht gesendet');
}

// ============================================
// FORMULARDATEN VERARBEITEN
// ============================================

$name = sanitizeInput($_POST['name'] ?? '', 100);
$email = sanitizeInput($_POST['email'] ?? '', 254);
$message = sanitizeInput($_POST['message'] ?? '', 5000);

// Pflichtfelder
if (empty($name)) {
    sendResponse(false, 'Bitte geben Sie Ihren Namen ein.', 400);
}
if (empty($email) || !isValidEmail($email)) {
    sendResponse(false, 'Bitte geben Sie eine gueltige E-Mail-Adresse ein.', 400);
}

// ============================================
// E-MAIL ERSTELLEN UND SENDEN
// ============================================

$subject = "=?UTF-8?B?" . base64_encode("[B_LineGraphix] Kontaktanfrage von $name") . "?=";

$email_body = "Neue Kontaktanfrage ueber die B_LineGraphix Website\n";
$email_body .= "====================================================\n\n";

$email_body .= "KONTAKTDATEN\n";
$email_body .= "------------\n";
$email_body .= "Name: $name\n";
$email_body .= "E-Mail: $email\n";

$email_body .= "\nNACHRICHT\n";
$email_body .= "---------\n";
$email_body .= !empty($message) ? $message : '(Keine Nachricht eingegeben)';

$email_body .= "\n\n====================================================\n";
$email_body .= "Gesendet am: " . date('d.m.Y H:i:s') . "\n";
$email_body .= "IP-Adresse: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unbekannt') . "\n";

$headers = [];
$headers[] = "From: B_LineGraphix Website <{$config['from_email']}>";
$headers[] = "Reply-To: $name <$email>";
$headers[] = "Content-Type: text/plain; charset=UTF-8";
$headers[] = "X-Mailer: BLineGraphix Contact Form v1";

$mail_sent = mail($config['email_to'], $subject, $email_body, implode("\r\n", $headers));

if ($mail_sent) {
    $_SESSION[$rate_key]['count']++;
    sendResponse(true, 'Ihre Nachricht wurde erfolgreich gesendet. Wir melden uns zeitnah bei Ihnen.');
} else {
    sendResponse(false, 'Die Nachricht konnte nicht gesendet werden. Bitte versuchen Sie es spaeter erneut.', 500);
}
