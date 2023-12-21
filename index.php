<?php

// index.php

// Basic routing logic
$request_uri = $_SERVER['REQUEST_URI'];

// Split the request URI to get the endpoint
$uri_parts = explode('/', $request_uri);

// Extract the endpoint from the URI
$endpoint = isset($uri_parts[2]) ? $uri_parts[2] : null;

// Include api.php to access API functions
include 'api.php';

// Route requests to API functions based on the endpoint
if ($endpoint === 'register') {
    // Call the login function from api.php
    register();
} elseif ($endpoint === 'verify') {
    // Call the verifyAccount function from api.php
    verifyAccount();
} elseif ($endpoint === 'login') {
    // Call the login function from api.php
    login();
} elseif ($endpoint === 'forgot-password') {
    // Call the forgotPassword function from api.php
    forgotPassword();
} elseif (strpos($endpoint, 'reset-password') !== false) {
    // Extract tokenNumber from the endpoint
    $tokenNumber = end($uri_parts);
    
    // Call the resetPassword function from api.php
    resetPassword($tokenNumber);
} elseif ($endpoint === 'user') {
    // Call the user function from api.php
    user();
} else {
    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode(http_response_code(404));
}
?>
