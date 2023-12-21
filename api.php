<?php
require 'vendor/autoload.php'; // Include Composer autoloader

// Include configuration
include 'config.php';

// Function to sanitize input
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Function to send verification email
function sendmail($firstname, $to, $subject, $verificationCode) {
    // Create the Transport
    $transport = (new Swift_SmtpTransport('smtp.gmail.com', 587, 'tls'))
        ->setUsername('razonmarknicholas.cdlb@gmail.com')
        ->setPassword('yrib suvl noam edsc');

    // Create the Mailer using your created Transport
    $mailer = new Swift_Mailer($transport);

    // Create a message
    $message = (new Swift_Message($subject))
        ->setFrom(['razonmarknicholas.cdlb@gmail.com' => 'APIForm'])
        ->setTo([$to])
        ->setBody(
            '<html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        margin: 0;
                        padding: 20px;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 5px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }
                    h1 {
                        color: #333;
                    }
                    p {
                        color: #555;
                    }
                    .verification-code {
                        font-size: 24px;
                        font-weight: bold;
                        color: #3498db;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Account Verification Code</h1>
                    <p>Dear ' . $firstname . ',</p>
                    <p>Your verification code is: <span class="verification-code">' . $verificationCode . '</span></p>
                    <p>Thank you for registering!</p>
                </div>
            </body>
            </html>',
            'text/html'
        );

    // Send the message
    $result = $mailer->send($message);

    // Check if the email was sent successfully
    if ($result > 0) {
        // Email sent successfully
        return true;
    } else {
        // Email not sent
        return false;
    }
}

// Function to handle registration API
function register() {
    global $pdo;  // Make $pdo variable available in this function
    $subject = "APIForm Account Verification";

    // Assuming you receive registration data in the POST request
    $firstname = isset($_POST['firstname']) ? sanitizeInput($_POST['firstname']) : null;
    $lastname = isset($_POST['lastname']) ? sanitizeInput($_POST['lastname']) : null;
    $email = isset($_POST['email']) ? sanitizeInput($_POST['email']) : null;
    $password = isset($_POST['password']) ? sanitizeInput($_POST['password']) : null;
    $confirmPassword = isset($_POST['confirm_password']) ? sanitizeInput($_POST['confirm_password']) : null;

    // Check if all required fields are provided
    if ($firstname && $lastname && $email && $password && $confirmPassword) {
        // Check if passwords match
        if ($password === $confirmPassword) {
            // Check if the email already exists in the database
            $stmtCheckEmail = $pdo->prepare('SELECT COUNT(*) FROM accounts WHERE email = ?');
            $stmtCheckEmail->execute([$email]);
            $emailExists = (bool)$stmtCheckEmail->fetchColumn();

            if (!$emailExists) {
                // Generate a unique user token using uniqid
                $userToken = uniqid('token_', true);

                // Generate a 6-digit code
                $verificationCode = sprintf('%06d', mt_rand(0, 999999));

                // Hash the password for security
                $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

                try {
                    // Send verification email
                    $emailSent = sendmail($firstname, $email, $subject, $verificationCode);

                    if ($emailSent) {
                        // Insert data into the accounts table using a prepared statement
                        $stmt = $pdo->prepare('INSERT INTO accounts (userToken, firstname, lastname, email, password, creationDate, code) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)');
                        $stmt->execute([$userToken, $firstname, $lastname, $email, $hashedPassword, $verificationCode]);

                        // Respond with a success message
                        $response = array('success' => true, 'message' => 'Registration successful');
                    } else {
                        $response = array('success' => false, 'message' => 'Error sending verification email');
                    }
                } catch (PDOException $e) {
                    $response = array('success' => false, 'message' => 'Error inserting data into the database');
                }
            } else {
                $response = array('success' => false, 'message' => 'Email already exists. Please use a different email address.');
            }
        } else {
            $response = array('success' => false, 'message' => 'Passwords do not match');
        }
    } else {
        $response = array('success' => false, 'message' => 'All fields are required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to handle account verification API
function verifyAccount() {
    global $pdo;  // Make $pdo variable available in this function

    // Assuming you receive verification code in the POST request
    $verificationCode = isset($_POST['verification_code']) ? sanitizeInput($_POST['verification_code']) : null;

    // Check if the verification code is provided
    if ($verificationCode) {
        try {
            // Verify the account based on the provided verification code
            $stmt = $pdo->prepare('SELECT id, userToken, email FROM accounts WHERE code = ?');
            $stmt->execute([$verificationCode]);
            $account = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($account) {
                // Update the account as verified
                $stmtUpdate = $pdo->prepare('UPDATE accounts SET status = "verified" WHERE id = ?');
                $stmtUpdate->execute([$account['id']]);

                // Respond with a success message
                $response = array('success' => true, 'message' => 'Account verification successful');
            } else {
                $response = array('success' => false, 'message' => 'Invalid verification code or account already verified');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error verifying account');
        }
    } else {
        $response = array('success' => false, 'message' => 'Verification code is required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to handle login API
function login() {
    global $pdo;  // Make $pdo variable available in this function

    // Assuming you receive email and password in the POST request
    $email = isset($_POST['email']) ? $_POST['email'] : null;
    $password = isset($_POST['password']) ? $_POST['password'] : null;

    // Check if both email and password are provided
    if ($email && $password) {
        try {
            // Fetch user information from the database based on the provided email
            $stmt = $pdo->prepare('SELECT id, userToken, firstname, lastname, email, creationDate, password, status, code FROM accounts WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the user exists
            if ($user) {
                // Check if the user is verified
                if ($user['status'] == 'verified') {
                    // Verify the provided password against the hashed password stored in the database
                    if (password_verify($password, $user['password'])) {
                        // Generate a new 6-digit code
                        $newVerificationCode = sprintf('%06d', mt_rand(0, 999999));

                        // Update the code in the database
                        $updateCodeStmt = $pdo->prepare('UPDATE accounts SET code = ? WHERE email = ?');
                        $updateCodeStmt->execute([$newVerificationCode, $email]);

                        // User logged in successfully
                        $response = array(
                            'success' => true,
                            'message' => 'Login successful',
                            'user' => array(
                                'id' => $user['id'],
                                'userToken' => $user['userToken'],
                                'firstname' => $user['firstname'],
                                'lastname' => $user['lastname'],
                                'email' => $user['email'],
                                'creationDate' => $user['creationDate']
                            )
                        );
                    } else {
                        $response = array('success' => false, 'message' => 'Invalid credentials');
                    }
                } else {
                    $response = array('success' => false, 'message' => 'Account not verified. Please check your email for verification instructions.');
                }
            } else {
                $response = array('success' => false, 'message' => 'Invalid credentials. User not found');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error retrieving user information');
        }
    } else {
        $response = array('success' => false, 'message' => 'Email and password are required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to handle forgot password API
function forgotPassword() {
    global $pdo;  // Make $pdo variable available in this function

    // Assuming you receive email in the POST request
    $email = isset($_POST['email']) ? $_POST['email'] : null;

    // Check if email is provided
    if ($email) {
        try {
            // Fetch user information from the database based on the provided email
            $stmt = $pdo->prepare('SELECT id, userToken, firstname, lastname, email FROM accounts WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the user exists
            if ($user) {
                // Generate a unique reset token using userToken
                $resetToken = $user['userToken'];

                // Send reset password email with a link containing the reset token
                $resetLink = 'http://localhost/resetpassword?token=' . $resetToken; // Update with your domain
                $subject = "APIForm Reset Password";
                $emailSent = sendResetPasswordEmail($email, $subject, $resetLink);

                if ($emailSent) {
                    // Respond with a success message
                    $response = array('success' => true, 'message' => 'Reset password instructions sent to your email');
                } else {
                    $response = array('success' => false, 'message' => 'Error sending reset password instructions');
                }
            } else {
                $response = array('success' => false, 'message' => 'Email not found');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error retrieving user information');
        }
    } else {
        $response = array('success' => false, 'message' => 'Email is required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}

// Function to send reset password email
function sendResetPasswordEmail($to, $subject, $resetLink) {
    // Create the Transport
    $transport = (new Swift_SmtpTransport('smtp.gmail.com', 587, 'tls'))
        ->setUsername('razonmarknicholas.cdlb@gmail.com')
        ->setPassword('yrib suvl noam edsc');

    // Create the Mailer using your created Transport
    $mailer = new Swift_Mailer($transport);

    // Create a message
    $message = (new Swift_Message($subject))
        ->setFrom(['razonmarknicholas.cdlb@gmail.com' => 'APIForm'])
        ->setTo([$to])
        ->setBody(
            'Click the following link to reset your password: <a href="' . $resetLink . '">Click here</a>',
            'text/html'
        );

    // Send the message
    $result = $mailer->send($message);

    // Check if the email was sent successfully
    return $result > 0;
}

// Function to handle resetting the password based on the tokenNumber
function resetPassword($tokenNumber) {
    global $pdo;  // Make $pdo variable available in this function

    // Check if the tokenNumber is provided
    if ($tokenNumber) {
        try {
            // Fetch user information from the database based on the provided tokenNumber
            $stmt = $pdo->prepare('SELECT id, userToken, firstname, lastname, email FROM accounts WHERE userToken = ?');
            $stmt->execute([$tokenNumber]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // Check if the user exists
            if ($user) {
                // TODO: Implement the logic to check if the token is still valid (e.g., not expired)

                // Check if the new password and confirm password are provided and match
                $newPassword = isset($_POST['new_password']) ? $_POST['new_password'] : null;
                $confirmPassword = isset($_POST['confirm_password']) ? $_POST['confirm_password'] : null;

                if ($newPassword && $confirmPassword && $newPassword === $confirmPassword) {
                    // Hash the new password
                    $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);

                    // Update the user's password in the database
                    $updatePasswordStmt = $pdo->prepare('UPDATE accounts SET password = ? WHERE userToken = ?');
                    $updatePasswordStmt->execute([$hashedPassword, $tokenNumber]);

                    // Respond with a success message
                    $response = array('success' => true, 'message' => 'Password reset successful');
                } else {
                    $response = array('success' => false, 'message' => 'New password and confirm password do not match');
                }
            } else {
                $response = array('success' => false, 'message' => 'Invalid or expired token');
            }
        } catch (PDOException $e) {
            $response = array('success' => false, 'message' => 'Error retrieving user information');
        }
    } else {
        $response = array('success' => false, 'message' => 'Token number is required');
    }

    // Send JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
}
?>
