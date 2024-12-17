<?php
// admin.php
session_start();
require_once '../config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['directory'] !== basename(__DIR__)) {
    header('Location: ../index.php');
    exit;
}

// Handle article submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = sanitize_input($_POST['title']);
    $content = $_POST['content']; // Allow HTML content
    $preview = sanitize_input(substr(strip_tags($_POST['content']), 0, 200) . '...');
    $word_count = get_word_count($_POST['content']);

    if (isset($_POST['article_id'])) {
        // Update existing article
        $stmt = $conn->prepare("UPDATE articles SET title = ?, content = ?, preview = ?, word_count = ? WHERE id = ? AND user_id = ?");
        $stmt->bind_param("sssiii", $title, $content, $preview, $word_count, $_POST['article_id'], $_SESSION['user_id']);
    } else {
        // Create new article
        $stmt = $conn->prepare("INSERT INTO articles (user_id, title, content, preview, word_count) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("isssi", $_SESSION['user_id'], $title, $content, $preview, $word_count);
    }

    if ($stmt->execute()) {
        header('Location: index.php');
        exit;
    } else {
        $error = "Error saving article: " . $stmt->error;
    }
}

// Get article for editing if specified
$article = null;
if (isset($_GET['edit'])) {
    $stmt = $conn->prepare("SELECT * FROM articles WHERE id = ? AND user_id = ?");
    $stmt->bind_param("ii", $_GET['edit'], $_SESSION['user_id']);
    $stmt->execute();
    $article = $stmt->get_result()->fetch_assoc();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - News Site</title>
    <script src="https://cdn.tiny.cloud/1/no-api-key/tinymce/5/tinymce.min.js"></script>
    <script>
        tinymce.init({
            selector: '#content',
            plugins: 'link image code',
            toolbar: 'undo redo | formatselect | bold italic | alignleft aligncenter alignright | link image | code',
            height: 400
        });
    </script>
    <style>
        .admin-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        .article-form {
            margin-bottom: 2rem;
        }
        .article-form input[type="text"],
        .article-form textarea {
            width: 100%;
            margin-bottom: 1rem;
        }
        .article-list {
            border-top: 1px solid #ddd;
            padding-top: 2rem;
        }
        .article-item {
            border-bottom: 1px solid #eee;
            padding: 1rem 0;
        }
    </style>
</head>
<body>
    <div class="admin-container">
        <nav>
            <a href="index.php">View Site</a>
            <a href="../index.php">Home</a>
        </nav>

        <h1>Admin Panel</h1>

        <?php if (isset($error)): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>

        <form class="article-form" method="POST">
            <?php if ($article): ?>
                <input type="hidden" name="article_id" value="<?php echo $article['id']; ?>">
            <?php endif; ?>

            <div>
                <label for="title">Title:</label>
                <input type="text" id="title" name="title" required
                    value="<?php echo $article ? $article['title'] : ''; ?>">
            </div>

            <div>
                <label for="content">Content:</label>
                <textarea id="content" name="content" required>
                    <?php echo $article ? $article['content'] : ''; ?>
                </textarea>
            </div>

            <button type="submit">
                <?php echo $article ? 'Update' : 'Create'; ?> Article
            </button>
        </form>

        <div class="article-list">
            <h2>Your Articles</h2>
            <?php
            $stmt = $conn->prepare("SELECT * FROM articles WHERE user_id = ? ORDER BY created_at DESC");
            $stmt->bind_param("i", $_SESSION['user_id']);
            $stmt->execute();
            $result = $stmt->get_result();

            while ($row = $result->fetch_assoc()):
            ?>
                <div class="article-item">
                    <h3><?php echo $row['title']; ?></h3>
                    <div class="meta">
                        Created: <?php echo date('M j, Y', strtotime($row['created_at'])); ?> |
                        Words: <?php echo $row['word_count']; ?> |
                        Votes: <?php echo $row['votes']; ?>
                    </div>
                    <div class="actions">
                        <a href="?edit=<?php echo $row['id']; ?>">Edit</a> |
                        <a href="index.php?article=<?php echo $row['id']; ?>" target="_blank">View</a>
                    </div>
                </div>
            <?php endwhile; ?>
        </div>
    </div>
</body>
</html>
