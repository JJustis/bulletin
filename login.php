<?php
require_once 'config.php';

// Check if user is already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Verify CSRF token
        Security::verifyCSRFToken($_POST['csrf_token']);
        
        $username = Security::sanitizeInput($_POST['username']);
        $password = $_POST['password'];

        // Prepare query to get user data
        $stmt = $conn->prepare("SELECT id, password, username, directory_name, status FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($user = $result->fetch_assoc()) {
            if ($user['status'] !== 'active') {
                throw new Exception('This account has been ' . $user['status']);
            }
            
            if (password_verify($password, $user['password'])) {
                // Update last login timestamp
                $update_stmt = $conn->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
                $update_stmt->bind_param("i", $user['id']);
                $update_stmt->execute();

                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['directory'] = $user['directory_name'];

                // Regenerate session ID for security
                session_regenerate_id(true);

                // Redirect to home page
                header('Location: index.php');
                exit;
            } else {
                throw new Exception('Invalid username or password');
            }
        } else {
            throw new Exception('Invalid username or password');
        }
    } catch (Exception $e) {
        $error_message = $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo Config::SITE_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .card-header {
            background-color: #fff;
            border-bottom: 1px solid #eee;
            padding: 1.5rem;
            border-radius: 10px 10px 0 0 !important;
        }
        .card-body {
            padding: 2rem;
        }
        .form-control {
            padding: 0.75rem;
            border-radius: 7px;
        }
        .site-name {
            color: #333;
            font-size: 2rem;
            font-weight: bold;
            text-align: center;
            margin-bottom: 2rem;
        }
        .btn-primary {
            padding: 0.75rem;
            font-weight: 500;
        }
        .register-link {
            text-align: center;
            margin-top: 1.5rem;
        }
        .alert {
            border-radius: 7px;
        }
        .back-to-home {
            position: absolute;
            top: 1rem;
            left: 1rem;
        }
    </style>
</head>
<body>
    <a href="index.php" class="btn btn-outline-primary back-to-home">
        <i class="fas fa-home"></i> Back to Home
    </a>

    <div class="login-container">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-5">
                    <div class="site-name">
                        <?php echo Config::SITE_NAME; ?>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <h3 class="mb-0 text-center">Welcome Back</h3>
                        </div>
                        <div class="card-body">
                            <?php if ($error_message): ?>
                                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                    <?php echo $error_message; ?>
                                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                </div>
                            <?php endif; ?>

                            <form method="POST" action="login.php">
                                <?php $csrf_token = Security::generateCSRFToken(); ?>
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                                <div class="mb-4">
                                    <label for="username" class="form-label">Username</label>
                                    <div class="input-group">
                                        <span class="input-group-text">
                                            <i class="fas fa-user"></i>
                                        </span>
                                        <input type="text" class="form-control" id="username" name="username" 
                                               required autofocus
                                               value="<?php echo isset($_POST['username']) ? Security::sanitizeInput($_POST['username']) : ''; ?>">
                                    </div>
                                </div>

                                <div class="mb-4">
                                    <label for="password" class="form-label">Password</label>
                                    <div class="input-group">
                                        <span class="input-group-text">
                                            <i class="fas fa-lock"></i>
                                        </span>
                                        <input type="password" class="form-control" id="password" name="password" required>
                                    </div>
                                </div>

                                <div class="d-grid">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-sign-in-alt me-2"></i>Log In
                                    </button>
                                </div>
                            </form>

                            <div class="register-link">
                                <p class="mb-0">Don't have an account? 
                                    <a href="register.php" class="text-decoration-none">Register here</a>
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://kit.fontawesome.com/your-font-awesome-kit.js"></script>
</head>
</body>
</html>