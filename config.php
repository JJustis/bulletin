<?php
/**
 * Main configuration file for the bulletin board system
 */

// Basic error handling and reporting
if (defined('ENVIRONMENT') && ENVIRONMENT === 'production') {
    error_reporting(0);
    ini_set('display_errors', 0);
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}

// Core configuration
class Config {
    // Database settings
    const DB_HOST = 'localhost';
    const DB_USER = 'root';
    const DB_PASS = '';
    const DB_NAME = 'news_site';

    // Site settings
    const SITE_NAME = 'Bulletin News Site';
    const SITE_URL = 'http://jcmc.serveminecraft.net';
    const ADMIN_EMAIL = 'admin@yoursite.com';

    // Pagination
    const ITEMS_PER_PAGE = 10;

    // Upload limits
    const MAX_FILE_SIZE = 5242880; // 5MB in bytes
    const ALLOWED_FILE_TYPES = ['image/jpeg', 'image/png', 'image/gif'];
}

// Initialize database connection
class Database {
    private static $instance = null;
    private $connection;

    private function __construct() {
        try {
            $this->connection = new mysqli(
                Config::DB_HOST,
                Config::DB_USER,
                Config::DB_PASS,
                Config::DB_NAME
            );

            if ($this->connection->connect_error) {
                throw new Exception("Database connection failed: " . $this->connection->connect_error);
            }

            $this->connection->set_charset("utf8mb4");
            $this->initializeTables();

        } catch (Exception $e) {
            ErrorHandler::logError($e->getMessage());
            die("Database connection error. Please try again later.");
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->connection;
    }

    private function initializeTables() {
        $tables = [
            "CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                directory_name VARCHAR(50) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                status ENUM('active', 'suspended', 'banned') DEFAULT 'active'
            )",
            "CREATE TABLE IF NOT EXISTS articles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                preview TEXT NOT NULL,
                word_count INT NOT NULL,
                votes INT DEFAULT 0,
                views INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
                status ENUM('draft', 'published', 'archived') DEFAULT 'published',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",
            "CREATE TABLE IF NOT EXISTS votes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                article_id INT NOT NULL,
                user_id INT NOT NULL,
                vote_value INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE KEY unique_vote (article_id, user_id)
            )",
            "CREATE TABLE IF NOT EXISTS tags (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(50) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            "CREATE TABLE IF NOT EXISTS article_tags (
                article_id INT NOT NULL,
                tag_id INT NOT NULL,
                FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE,
                PRIMARY KEY (article_id, tag_id)
            )"
        ];

        foreach ($tables as $table_sql) {
            if (!$this->connection->query($table_sql)) {
                throw new Exception("Table creation failed: " . $this->connection->error);
            }
        }
    }
}

// Error handling
class ErrorHandler {
    public static function logError($message, $severity = 'ERROR') {
        $logDir = __DIR__ . '/logs';
        $logFile = $logDir . '/error.log';
        
        if (!file_exists($logDir)) {
            mkdir($logDir, 0777, true);
        }
        
        $timestamp = date('Y-m-d H:i:s');
        $logMessage = "[$timestamp] $severity: $message" . PHP_EOL;
        error_log($logMessage, 3, $logFile);
    }
}

// Security class
class Security {
    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
    }

    public static function generateCSRFToken() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function verifyCSRFToken($token) {
        if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
            throw new Exception('CSRF token validation failed');
        }
        return true;
    }

    public static function checkAuth() {
        if (!isset($_SESSION['user_id'])) {
            header('Location: ' . Config::SITE_URL . '/login.php');
            exit;
        }
    }
}

// Utility functions
class Utilities {
    public static function getWordCount($content) {
        return str_word_count(strip_tags($content));
    }

    public static function formatDate($date) {
        return date('F j, Y g:i A', strtotime($date));
    }

    public static function validateFileUpload($file) {
        $errors = [];
        
        if ($file['size'] > Config::MAX_FILE_SIZE) {
            $errors[] = 'File size exceeds limit of ' . (Config::MAX_FILE_SIZE / 1024 / 1024) . 'MB';
        }
        
        if (!in_array($file['type'], Config::ALLOWED_FILE_TYPES)) {
            $errors[] = 'File type not allowed';
        }
        
        return $errors;
    }

    public static function getPaginationLinks($total_items, $current_page, $base_url) {
        $total_pages = ceil($total_items / Config::ITEMS_PER_PAGE);
        $links = [];
        
        if ($current_page > 1) {
            $links[] = "<a href='{$base_url}?page=" . ($current_page - 1) . "' class='page-link'>Previous</a>";
        }
        
        for ($i = 1; $i <= $total_pages; $i++) {
            if ($i == $current_page) {
                $links[] = "<span class='page-link active'>$i</span>";
            } else {
                $links[] = "<a href='{$base_url}?page=$i' class='page-link'>$i</a>";
            }
        }
        
        if ($current_page < $total_pages) {
            $links[] = "<a href='{$base_url}?page=" . ($current_page + 1) . "' class='page-link'>Next</a>";
        }
        
        return implode('', $links);
    }
}

// Initialize session
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 1);
session_start();

// Create database connection
$conn = Database::getInstance()->getConnection();

// Set default timezone
date_default_timezone_set('UTC');
?>