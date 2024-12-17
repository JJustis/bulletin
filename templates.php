<?php
class TemplateGenerator {
    private static function getIndexTemplate($username, $directory) {
        return <<<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$username}'s Board</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .user-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            object-fit: cover;
            margin: 20px auto;
            display: block;
        }
        .article-images {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .article-image {
            width: 100%;
            aspect-ratio: 16/9;
            object-fit: cover;
            border-radius: 8px;
        }
        .pinned-article {
            border-left: 4px solid #0d6efd;
            padding-left: 15px;
            margin: 20px 0;
        }
        .site-motto {
            text-align: center;
            font-style: italic;
            color: #666;
            margin: 10px 0;
        }
        #articles-container {
            margin-top: 30px;
        }
        .article {
            margin-bottom: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 20px;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container">
            <a class="navbar-brand" href="../index.php">
                <i class="fas fa-arrow-left"></i> Main Board
            </a>
            <div class="navbar-text">
                {$username}'s Board
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <img src="avatar.jpg" alt="Avatar" class="user-avatar" id="userAvatar">
        <div class="site-motto" id="siteMotto">Welcome to my board</div>
        <div id="pinnedArticle"></div>
        <div id="articles-container"></div>
    </div>

    <script>
    document.addEventListener('DOMContentLoaded', function() {
        fetch('articles.php')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.error) {
                    throw new Error(data.message);
                }

                // Update profile info
                if (data.profile) {
                    document.getElementById('userAvatar').src = data.profile.avatar_url || 'avatar.jpg';
                    document.getElementById('siteMotto').textContent = data.profile.site_motto || 'Welcome to my board';
                    document.title = data.profile.site_motto || "{$username}'s Board";
                }

                // Display pinned article
                if (data.pinnedArticle) {
                    document.getElementById('pinnedArticle').innerHTML = createArticleHTML(data.pinnedArticle, true);
                }

                // Display other articles
                if (Array.isArray(data.articles)) {
                    const articlesHTML = data.articles.map(article => createArticleHTML(article, false)).join('');
                    document.getElementById('articles-container').innerHTML = articlesHTML;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                document.getElementById('articles-container').innerHTML = `
                    <div class="alert alert-danger">
                        Failed to load articles. Please try again later.
                    </div>
                `;
            });
    });

    function createArticleHTML(article, isPinned) {
        const articleClass = isPinned ? 'pinned-article' : 'article';
        
        let imagesHTML = '';
        if (article.images && Array.isArray(article.images)) {
            imagesHTML = '<div class="article-images">';
            for (let i = 0; i < 3; i++) {
                const imgSrc = article.images[i] || 'default-article-image.jpg';
                imagesHTML += `<img src="${imgSrc}" class="article-image" alt="Article image">`;
            }
            imagesHTML += '</div>';
        }

        return `
            <div class="${articleClass}">
                <h2>${article.title}</h2>
                ${imagesHTML}
                <div class="article-content">${article.content}</div>
                <div class="text-muted mt-3">
                    <small>
                        Published ${article.created_at} | 
                        ${article.word_count} words | 
                        ${article.views} views
                    </small>
                </div>
            </div>
        `;
    }
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
HTML;
    }

    private static function getArticlesTemplate() {
        return <<<'PHP'
<?php
require_once '../config.php';

// Set headers
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

try {
    // Get current directory
    $directory = basename(__DIR__);

    // First get user info
    $user_query = "SELECT id, username, site_motto FROM users WHERE directory_name = ? AND status = 'active'";
    $stmt = $conn->prepare($user_query);
    if (!$stmt) {
        throw new Exception("Failed to prepare user query");
    }

    $stmt->bind_param("s", $directory);
    if (!$stmt->execute()) {
        throw new Exception("Failed to execute user query");
    }

    $user_result = $stmt->get_result();
    if ($user_result->num_rows === 0) {
        throw new Exception("User not found");
    }

    $user = $user_result->fetch_assoc();
    $stmt->close();

    // Initialize response array
    $response = [
        'profile' => [
            'username' => $user['username'],
            'site_motto' => $user['site_motto'],
            'avatar_url' => file_exists('avatar.jpg') ? 'avatar.jpg' : null
        ],
        'pinnedArticle' => null,
        'articles' => []
    ];

    // Get pinned article
    $pinned_query = "
        SELECT id, title, content, preview, images, word_count, views, created_at
        FROM articles 
        WHERE user_id = ? AND is_pinned = 1 AND status = 'published'
        LIMIT 1
    ";
    
    $stmt = $conn->prepare($pinned_query);
    if ($stmt) {
        $stmt->bind_param("i", $user['id']);
        $stmt->execute();
        $pinned_result = $stmt->get_result();
        if ($pinned_result->num_rows > 0) {
            $pinned = $pinned_result->fetch_assoc();
            $pinned['images'] = json_decode($pinned['images'], true);
            $response['pinnedArticle'] = $pinned;
        }
        $stmt->close();
    }

    // Get regular articles
    $articles_query = "
        SELECT id, title, content, preview, images, word_count, views, created_at
        FROM articles 
        WHERE user_id = ? 
        AND (is_pinned = 0 OR is_pinned IS NULL)
        AND status = 'published'
        ORDER BY created_at DESC
    ";
    
    $stmt = $conn->prepare($articles_query);
    if ($stmt) {
        $stmt->bind_param("i", $user['id']);
        $stmt->execute();
        $articles_result = $stmt->get_result();
        
        while ($article = $articles_result->fetch_assoc()) {
            $article['images'] = json_decode($article['images'], true);
            $response['articles'][] = $article;
        }
        $stmt->close();
    }

    echo json_encode($response);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'error' => true,
        'message' => $e->getMessage()
    ]);
}
PHP;
    }

    private static function getAdminTemplate($username, $directory) {
        return <<<'PHP'
<?php
require_once '../config.php';

// Verify user is logged in and has access to this directory
Security::checkAuth();
$current_directory = basename(__DIR__);

if ($_SESSION['directory'] !== $current_directory) {
    header('Location: ../index.php');
    exit;
}

$error_message = '';
$success_message = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    try {
        // Verify CSRF token
        Security::verifyCSRFToken($_POST['csrf_token']);

        switch ($_POST['action']) {
            case 'update_profile':
                $motto = Security::sanitizeInput($_POST['site_motto']);
                
                // Handle avatar upload
                if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === 0) {
                    $upload_errors = Utilities::validateFileUpload($_FILES['avatar']);
                    
                    if (empty($upload_errors)) {
                        move_uploaded_file($_FILES['avatar']['tmp_name'], 'avatar.jpg');
                    } else {
                        throw new Exception('Avatar upload error: ' . implode(', ', $upload_errors));
                    }
                }

                // Update profile
                $stmt = $conn->prepare("UPDATE users SET site_motto = ? WHERE id = ?");
                if ($stmt === false) {
                    throw new Exception('Failed to prepare profile update query: ' . $conn->error);
                }
                $stmt->bind_param("si", $motto, $_SESSION['user_id']);
                $stmt->execute();
                $success_message = "Profile updated successfully!";
                break;

            case 'create_article':
                // Validate required fields
                if (empty($_POST['title']) || empty($_POST['content'])) {
                    throw new Exception('Title and content are required');
                }

                $title = Security::sanitizeInput($_POST['title']);
                $content = $_POST['content'];
                $preview = substr(strip_tags($content), 0, 200) . '...';
                $is_pinned = isset($_POST['is_pinned']) ? 1 : 0;
                $images = [];

                // Handle image uploads
                for ($i = 1; $i <= 3; $i++) {
                    if (isset($_FILES["image$i"]) && $_FILES["image$i"]['error'] === 0) {
                        $upload_errors = Utilities::validateFileUpload($_FILES["image$i"]);
                        
                        if (empty($upload_errors)) {
                            $filename = uniqid() . '_' . basename($_FILES["image$i"]['name']);
                            move_uploaded_file($_FILES["image$i"]['tmp_name'], 'uploads/' . $filename);
                            $images[] = 'uploads/' . $filename;
                        }
                    }
                }

                // If this is a pinned article, unpin others first
                if ($is_pinned) {
                    $stmt = $conn->prepare("UPDATE articles SET is_pinned = 0 WHERE user_id = ?");
                    if ($stmt === false) {
                        throw new Exception('Failed to prepare unpin query: ' . $conn->error);
                    }
                    $stmt->bind_param("i", $_SESSION['user_id']);
                    $stmt->execute();
                }

                // Insert the new article
                $stmt = $conn->prepare("
                    INSERT INTO articles 
                    (user_id, title, content, preview, images, is_pinned, word_count, status) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'published')
                ");
                if ($stmt === false) {
                    throw new Exception('Failed to prepare article insert query: ' . $conn->error);
                }

                $images_json = json_encode($images);
                $word_count = Utilities::getWordCount($content);
                
                $stmt->bind_param(
                    "issssii", 
                    $_SESSION['user_id'], 
                    $title, 
                    $content,
                    $preview, 
                    $images_json, 
                    $is_pinned, 
                    $word_count
                );
                
                $stmt->execute();
                $success_message = "Article created successfully!";
                break;
        }
    } catch (Exception $e) {
        $error_message = $e->getMessage();
    }
}

// Get user info
$stmt = $conn->prepare("SELECT username, site_motto FROM users WHERE id = ?");
if ($stmt === false) {
    die('Failed to prepare user query: ' . $conn->error);
}

$stmt->bind_param("i", $_SESSION['user_id']);
$stmt->execute();
$user_info = $stmt->get_result()->fetch_assoc();

// Get all articles by this user
$stmt = $conn->prepare("
    SELECT * FROM articles 
    WHERE user_id = ? 
    ORDER BY is_pinned DESC, created_at DESC
");
if ($stmt === false) {
    die('Failed to prepare articles query: ' . $conn->error);
}

$stmt->bind_param("i", $_SESSION['user_id']);
$stmt->execute();
$articles = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - <?= htmlspecialchars($user_info['username']); ?>'s Board</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/summernote@0.8.18/dist/summernote-bs4.min.css" rel="stylesheet">
    <style>
        .preview-image {
            max-width: 150px;
            height: auto;
            border-radius: 8px;
            margin: 10px 0;
        }
        .article-preview {
            border-left: 3px solid #dee2e6;
            padding-left: 15px;
        }
        .article-preview.pinned {
            border-left-color: #0d6efd;
        }
        .image-preview-container {
            display: flex;
            gap: 10px;
            margin: 10px 0;
        }
        .image-preview-container img {
            max-width: 100px;
            height: auto;
border-radius: 4px;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container">
            <a class="navbar-brand" href="../index.php">
                <i class="fas fa-arrow-left"></i> Back to Main Board
            </a>
            <div class="navbar-text">
                Admin Panel - <?= htmlspecialchars($user_info['username']); ?>'s Board
            </div>
        </div>
    </nav>

    <div class="container my-4">
        <?php if ($error_message): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($error_message); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if ($success_message): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <i class="fas fa-check-circle"></i> <?= htmlspecialchars($success_message); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <!-- Profile Settings -->
        <div class="card mb-4">
            <div class="card-header">
                <i class="fas fa-user"></i> Profile Settings
            </div>
            <div class="card-body">
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?= Security::generateCSRFToken(); ?>">
                    <input type="hidden" name="action" value="update_profile">
                    
                    <div class="row">
                        <div class="col-md-4">
                            <div class="mb-3">
                                <label class="form-label">Avatar</label>
                                <input type="file" name="avatar" class="form-control" accept="image/*">
                                <?php if (file_exists('avatar.jpg')): ?>
                                    <img src="avatar.jpg?v=<?= time(); ?>" class="preview-image mt-2">
                                <?php endif; ?>
                            </div>
                        </div>
                        <div class="col-md-8">
                            <div class="mb-3">
                                <label class="form-label">Site Motto</label>
                                <input type="text" name="site_motto" class="form-control" 
                                       value="<?= htmlspecialchars($user_info['site_motto'] ?? ''); ?>"
                                       placeholder="Enter your site motto">
                                <div class="form-text">This will appear on your board's homepage.</div>
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Update Profile
                    </button>
                </form>
            </div>
        </div>
        
        <!-- New Article -->
        <div class="card mb-4">
            <div class="card-header">
                <i class="fas fa-pen"></i> Create New Article
            </div>
            <div class="card-body">
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?= Security::generateCSRFToken(); ?>">
                    <input type="hidden" name="action" value="create_article">
                    
                    <div class="mb-3">
                        <label class="form-label">Title</label>
                        <input type="text" name="title" class="form-control" required
                               placeholder="Enter article title">
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Images (up to 3)</label>
                        <div class="row">
                            <?php for ($i = 1; $i <= 3; $i++): ?>
                                <div class="col-md-4">
                                    <input type="file" name="image<?= $i; ?>" 
                                           class="form-control" accept="image/*">
                                </div>
                            <?php endfor; ?>
                        </div>
                        <div class="form-text">Supported formats: JPG, PNG, GIF</div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Content</label>
                        <textarea name="content" id="content" required></textarea>
                    </div>
                    
                    <div class="mb-3">
                        <div class="form-check">
                            <input type="checkbox" name="is_pinned" class="form-check-input" id="isPinned">
                            <label class="form-check-label" for="isPinned">
                                Pin this article to the top of your board
                            </label>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-plus"></i> Create Article
                    </button>
                </form>
            </div>
        </div>

        <!-- Article List -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-list"></i> Your Articles
            </div>
            <div class="card-body">
                <?php if ($articles->num_rows > 0): ?>
                    <?php while ($article = $articles->fetch_assoc()): ?>
                        <div class="article-preview mb-4 <?= $article['is_pinned'] ? 'pinned' : ''; ?>">
                            <h4><?= htmlspecialchars($article['title']); ?></h4>
                            <div class="image-preview-container">
                                <?php 
                                $images = json_decode($article['images'], true);
                                if ($images): 
                                    foreach ($images as $image): ?>
                                        <img src="<?= htmlspecialchars($image); ?>" alt="Article image">
                                    <?php endforeach;
                                endif; ?>
                            </div>
                            <div class="text-muted">
                                <small>
                                    Created: <?= Utilities::formatDate($article['created_at']); ?> |
                                    Words: <?= $article['word_count']; ?> |
                                    Status: <?= ucfirst($article['status']); ?> |
                                    <?= $article['is_pinned'] ? '<span class="badge bg-primary">Pinned</span>' : ''; ?>
                                </small>
                            </div>
                        </div>
                    <?php endwhile; ?>
                <?php else: ?>
                    <div class="text-center text-muted py-4">
                        <i class="fas fa-pen-alt fa-3x mb-3"></i>
                        <p>You haven't created any articles yet.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/summernote@0.8.18/dist/summernote-bs4.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#content').summernote({
                height: 300,
                toolbar: [
                    ['style', ['style']],
                    ['font', ['bold', 'underline', 'clear']],
                    ['color', ['color']],
                    ['para', ['ul', 'ol', 'paragraph']],
                    ['insert', ['link']],
                    ['view', ['fullscreen', 'codeview']]
                ],
                placeholder: 'Write your article content here...'
            });
        });
    </script>
</body>
</html>
PHP;
    }

    public static function createUserFiles($username, $directory) {
        if (!is_dir($directory)) {
            mkdir($directory, 0777, true);
            mkdir($directory . '/uploads', 0777, true);
        }

        // Create index.html
        file_put_contents(
            $directory . '/index.html', 
            self::getIndexTemplate($username, $directory)
        );

        // Create admin.php
        file_put_contents(
            $directory . '/admin.php',
            self::getAdminTemplate($username, $directory)
        );

        // Create articles.php
        file_put_contents(
            $directory . '/articles.php',
            self::getArticlesTemplate()
        );

        // Create default avatar
        copy('default-avatar.jpg', $directory . '/avatar.jpg');
        
        // Create .htaccess for security
        file_put_contents($directory . '/.htaccess', <<<HTACCESS
Options -Indexes
<FilesMatch "^articles\.php$">
    Order Allow,Deny
    Allow from all
</FilesMatch>
HTACCESS
        );

        // Create an empty index.php to prevent directory listing
        file_put_contents($directory . '/uploads/index.php', '<?php header("Location: ../index.html"); ?>');

        // Set proper permissions
        chmod($directory . '/uploads', 0777);
        chmod($directory . '/.htaccess', 0644);
        chmod($directory . '/admin.php', 0644);
        chmod($directory . '/index.html', 0644);
        chmod($directory . '/articles.php', 0644);
    }
}
?>