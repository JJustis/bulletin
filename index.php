<?php
require_once 'config.php';

// Get current page number for pagination
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$items_per_page = Config::ITEMS_PER_PAGE;
$offset = ($page - 1) * $items_per_page;

// Get total articles for pagination
$total_result = $conn->query("SELECT COUNT(*) as count FROM articles WHERE status = 'published'");
$total_articles = $total_result->fetch_assoc()['count'];

// Get latest articles with pagination
$sql = "SELECT a.*, u.username, u.directory_name, 
        (SELECT COUNT(*) FROM votes WHERE article_id = a.id) as vote_count 
        FROM articles a 
        JOIN users u ON a.user_id = u.id 
        WHERE a.status = 'published' 
        ORDER BY a.created_at DESC 
        LIMIT ?, ?";

$stmt = $conn->prepare($sql);
$limit = $items_per_page;
$stmt->bind_param("ii", $offset, $limit);
$stmt->execute();
$articles = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo Config::SITE_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .article-preview {
            transition: transform 0.2s;
        }
        .article-preview:hover {
            transform: translateY(-2px);
        }
        .vote-button {
            cursor: pointer;
            transition: color 0.2s;
        }
        .vote-button:hover {
            color: #0d6efd;
        }
        .sidebar {
            position: sticky;
            top: 1rem;
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-top">
        <div class="container">
            <a class="navbar-brand" href="index.php"><?php echo Config::SITE_NAME; ?></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="index.php">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#directoryModal">Directories</a>
                    </li>
                </ul>
                
                <?php if (isset($_SESSION['user_id'])): ?>
                    <div class="dropdown">
                        <button class="btn btn-light dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="<?php echo $_SESSION['directory']; ?>/admin.php">My Admin</a></li>
                            <li><a class="dropdown-item" href="<?php echo $_SESSION['directory']; ?>">My Directory</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php">Logout</a></li>
                        </ul>
                    </div>
                <?php else: ?>
                    <div class="d-flex">
                        <a href="login.php" class="btn btn-light me-2">Login</a>
                        <a href="register.php" class="btn btn-outline-light">Register</a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container my-4">
        <div class="row">
            <!-- Articles Column -->
            <div class="col-lg-8">
                <div class="card mb-4">
                    <div class="card-header bg-white">
                        <h4 class="mb-0">Latest Articles</h4>
                    </div>
                    <div class="card-body">
                        <?php if ($articles->num_rows > 0): ?>
                            <?php while ($article = $articles->fetch_assoc()): ?>
                                <div class="article-preview card mb-3">
                                    <div class="card-body">
                                        <h5 class="card-title">
                                            <a href="<?php echo htmlspecialchars($article['directory_name']); ?>/index.html?article=<?php echo $article['id']; ?>" 
                                               class="text-decoration-none">
                                                <?php echo htmlspecialchars($article['title']); ?>
                                            </a>
                                        </h5>
                                        <p class="card-text"><?php echo htmlspecialchars($article['preview']); ?></p>
                                        <div class="d-flex justify-content-between align-items-center">
                                            <small class="text-muted">
                                                By <a href="<?php echo htmlspecialchars($article['directory_name']); ?>" 
                                                     class="text-decoration-none">
                                                    <?php echo htmlspecialchars($article['username']); ?>
                                                </a> | 
                                                <?php echo Utilities::formatDate($article['created_at']); ?> | 
                                                <?php echo $article['word_count']; ?> words
                                            </small>
                                            <div class="vote-controls">
                                                <span class="me-2"><?php echo $article['vote_count']; ?> votes</span>
                                                <?php if (isset($_SESSION['user_id'])): ?>
                                                    <i class="fas fa-thumbs-up vote-button" onclick="vote(<?php echo $article['id']; ?>, 1)"></i>
                                                    <i class="fas fa-thumbs-down vote-button" onclick="vote(<?php echo $article['id']; ?>, -1)"></i>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endwhile; ?>

                            <?php if ($total_articles > 0): ?>
                                <!-- Pagination -->
                                <nav aria-label="Page navigation">
                                    <ul class="pagination justify-content-center">
                                        <?php
                                        $total_pages = ceil($total_articles / $items_per_page);
                                        if ($page > 1): ?>
                                            <li class="page-item">
                                                <a class="page-link" href="?page=<?php echo $page - 1; ?>">Previous</a>
                                            </li>
                                        <?php endif; ?>
                                        
                                        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                            <li class="page-item <?php echo $i === $page ? 'active' : ''; ?>">
                                                <a class="page-link" href="?page=<?php echo $i; ?>"><?php echo $i; ?></a>
                                            </li>
                                        <?php endfor; ?>
                                        
                                        <?php if ($page < $total_pages): ?>
                                            <li class="page-item">
                                                <a class="page-link" href="?page=<?php echo $page + 1; ?>">Next</a>
                                            </li>
                                        <?php endif; ?>
                                    </ul>
                                </nav>
                            <?php endif; ?>
                        <?php else: ?>
                            <div class="alert alert-info">
                                No articles have been published yet.
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Sidebar -->
            <div class="col-lg-4">
                <div class="sidebar">
                    <!-- Popular Directories -->
                    <div class="card mb-4">
                        <div class="card-header bg-white">
                            <h5 class="mb-0">Popular Directories</h5>
                        </div>
                        <div class="card-body">
                            <?php
                            $top_dirs = $conn->query("
                                SELECT u.directory_name, u.username, COUNT(a.id) as article_count 
                                FROM users u 
                                LEFT JOIN articles a ON u.id = a.user_id 
                                GROUP BY u.id 
                                ORDER BY article_count DESC 
                                LIMIT 5
                            ");
                            if ($top_dirs->num_rows > 0):
                                while ($dir = $top_dirs->fetch_assoc()): ?>
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <a href="<?php echo htmlspecialchars($dir['directory_name']); ?>" class="text-decoration-none">
                                            <?php echo htmlspecialchars($dir['username']); ?>
                                        </a>
                                        <span class="badge bg-primary"><?php echo $dir['article_count']; ?> articles</span>
                                    </div>
                                <?php endwhile;
                            else: ?>
                                <div class="text-muted">No directories yet.</div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Advertisement Space -->
                    <div class="card mb-4">
                        <div class="card-body text-center">
                            <div class="bg-light p-4">
                                <h6 class="text-muted">Advertisement Space</h6>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    function vote(articleId, value) {
        fetch('vote.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                article_id: articleId,
                vote_value: value
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert(data.message);
            }
        });
    }
    </script>
</body>
</html>