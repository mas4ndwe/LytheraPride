<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Database configuration
$db_host = 'localhost';
$db_user = 'root'; // Ganti dengan username database Anda
$db_pass = ''; // Ganti dengan password database Anda
$db_name = 'LytheraOpenMP'; // Ganti dengan nama database Anda

// Create connection
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check connection
if ($conn->connect_error) {
    echo json_encode([
        'success' => false,
        'message' => 'Koneksi database gagal!'
    ]);
    exit;
}

// Get JSON input
$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (!$data) {
    echo json_encode([
        'success' => false,
        'message' => 'Data tidak valid!'
    ]);
    exit;
}

$username = trim($data['username']);
$ip = $data['ip'];
$verifycode = $data['verifycode'];

// Validate username
if (strlen($username) < 3 || strlen($username) > 25) {
    echo json_encode([
        'success' => false,
        'message' => 'Username harus antara 3-25 karakter!'
    ]);
    exit;
}

if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    echo json_encode([
        'success' => false,
        'message' => 'Username hanya boleh mengandung huruf, angka, dan underscore!'
    ]);
    exit;
}

// Check if username already exists
$stmt = $conn->prepare("SELECT id FROM ucp WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo json_encode([
        'success' => false,
        'message' => 'Username sudah digunakan! Silakan pilih username lain.'
    ]);
    $stmt->close();
    exit;
}
$stmt->close();

// Check if IP already has an account
$stmt = $conn->prepare("SELECT id FROM ucp WHERE ip = ?");
$stmt->bind_param("s", $ip);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo json_encode([
        'success' => false,
        'message' => 'IP Address Anda sudah terdaftar! Satu IP hanya dapat membuat 1 akun UCP.'
    ]);
    $stmt->close();
    exit;
}
$stmt->close();

// Generate secure password with SHA256 and salt
$salt = bin2hex(random_bytes(32)); // Generate 64 character salt
$password = hash('sha256', $username . time() . $salt); // Generate unique password
$hashed_password = hash('sha256', $password . $salt); // Hash password with salt

// Get current timestamp
$registerdate = time();

// Insert new user
$stmt = $conn->prepare("INSERT INTO ucp (username, verifycode, password, salt, ip, admin, registerdate, extrac, security) VALUES (?, ?, ?, ?, ?, 0, ?, 0, 0)");
$stmt->bind_param("sisssi", $username, $verifycode, $hashed_password, $salt, $ip, $registerdate);

if ($stmt->execute()) {
    echo json_encode([
        'success' => true,
        'message' => 'Registrasi berhasil!',
        'data' => [
            'username' => $username,
            'verifycode' => $verifycode,
            'registerdate' => date('Y-m-d H:i:s', $registerdate)
        ]
    ]);
} else {
    echo json_encode([
        'success' => false,
        'message' => 'Gagal menyimpan data! Error: ' . $stmt->error
    ]);
}

$stmt->close();
$conn->close();
?>
