<?php
// vote.php

require_once 'config.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Please login to vote']);
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);
$article_id = $data['article_id'];
$vote_value = $data['vote_value'];
$user_id = $_SESSION['user_id'];

// Check if user has already voted
$stmt = $conn->prepare("SELECT id FROM votes WHERE article_id = ? AND user_id = ?");
$stmt->bind_param("ii", $article_id, $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo json_encode(['success' => false, 'message' => 'You have already voted']);
    exit;
}

// Add vote
$stmt = $conn->prepare("INSERT INTO votes (article_id, user_id, vote_value) VALUES (?, ?, ?)");
$stmt->bind_param("iii", $article_id, $user_id, $vote_value);

if ($stmt->execute()) {
    // Update article votes
    $stmt = $conn->prepare("UPDATE articles SET votes = votes + ? WHERE id = ?");
    $stmt->bind_param("ii", $vote_value, $article_id);
    $stmt->execute();
    
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['success' => false, 'message' => 'Error processing vote']);
}
?>
