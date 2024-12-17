<?php
require_once 'config.php';
require_once 'templates.php'; // Make sure this is the file containing TemplateGenerator class

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Use Security class methods for sanitization
        $username = Security::sanitizeInput($_POST['username']);
        $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
        $email = Security::sanitizeInput($_POST['email']);
        $directory = Security::sanitizeInput($_POST['directory']);

        // Validate directory name
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $directory)) {
            throw new Exception('Invalid directory name. Use only letters, numbers, underscores, and hyphens.');
        }

        // Check if directory exists
        if (is_dir($directory)) {
            throw new Exception('Directory already exists.');
        }

        // Check if username exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) {
            throw new Exception('Username already exists.');
        }

        // Check if email exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) {
            throw new Exception('Email already exists.');
        }

        // Begin transaction
        $conn->begin_transaction();

        try {
            // Insert user
            $stmt = $conn->prepare("INSERT INTO users (username, password, email, directory_name, status) VALUES (?, ?, ?, ?, 'active')");
            $stmt->bind_param("ssss", $username, $password, $email, $directory);

            if (!$stmt->execute()) {
                throw new Exception("Error creating user: " . $stmt->error);
            }

            // Create directory structure
            if (!mkdir($directory, 0777, true)) {
                throw new Exception('Failed to create directory');
            }

            if (!mkdir($directory . '/uploads', 0777, true)) {
                throw new Exception('Failed to create uploads directory');
            }

            // Generate and save user files using TemplateGenerator
            TemplateGenerator::createUserFiles($username, $directory);

            // If everything is successful, commit the transaction
            $conn->commit();

            // Redirect to login
            header('Location: login.php?registered=1');
            exit;

        } catch (Exception $e) {
            // If any error occurs, rollback the transaction
            $conn->rollback();
            
            // Clean up any created directories
            if (is_dir($directory)) {
                $this->removeDirectory($directory);
            }
            
            throw $e;
        }

    } catch (Exception $e) {
        $error_message = $e->getMessage();
    }
}

// Helper function to remove directory and its contents
function removeDirectory($dir) {
    if (is_dir($dir)) {
        $objects = scandir($dir);
        foreach ($objects as $object) {
            if ($object != "." && $object != "..") {
                if (is_dir($dir . "/" . $object))
                    removeDirectory($dir . "/" . $object);
                else
                    unlink($dir . "/" . $object);
            }
        }
        rmdir($dir);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - <?php echo Config::SITE_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
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
        .form-control {
            padding: 0.75rem;
            border-radius: 7px;
        }
        .btn-primary {
            padding: 0.75rem;
        }
        .validation-hint {
            font-size: 0.8rem;
            color: #6c757d;
            margin-top: 0.25rem;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="text-center mb-4">
                    <h2><?php echo Config::SITE_NAME; ?></h2>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h3 class="mb-0">Create Your Account</h3>
                    </div>
                    <div class="card-body">
                        <?php if (isset($error_message)): ?>
                            <div class="alert alert-danger alert-dismissible fade show">
                                <?php echo $error_message; ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        <?php endif; ?>

                        <form method="POST" action="register.php" class="needs-validation" novalidate>
                            <?php $csrf_token = Security::generateCSRFToken(); ?>
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username" required
                                    pattern="[a-zA-Z0-9_-]+" 
                                    value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
                                <div class="validation-hint">Letters, numbers, underscore, and hyphen only</div>
                            </div>

                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" name="email" required
                                    value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                            </div>

                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required
                                    minlength="8">
                                <div class="validation-hint">Minimum 8 characters</div>
                            </div>

                            <div class="mb-4">
                                <label for="directory" class="form-label">Directory Name</label>
                                <input type="text" class="form-control" id="directory" name="directory" required
                                    pattern="[a-zA-Z0-9_-]+"
                                    value="<?php echo isset($_POST['directory']) ? htmlspecialchars($_POST['directory']) : ''; ?>">
                                <div class="validation-hint">
                                    This will be your unique directory and cannot be changed later.<br>
                                    Use only letters, numbers, underscore, and hyphen.
                                </div>
                            </div>

                            <button type="submit" class="btn btn-primary w-100">Create Account</button>
                        </form>

                        <div class="mt-3 text-center">
                            <a href="login.php" class="text-decoration-none">Already have an account? Login here</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Form validation
    (function () {
        'use strict'
        var forms = document.querySelectorAll('.needs-validation')
        Array.prototype.slice.call(forms).forEach(function (form) {
            form.addEventListener('submit', function (event) {
                if (!form.checkValidity()) {
                    event.preventDefault()
                    event.stopPropagation()
                }
                form.classList.add('was-validated')
            }, false)
        })
    })()
    </script>
</body>
</html>