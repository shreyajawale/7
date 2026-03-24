CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    password VARCHAR(255),
    remember_token VARCHAR(255)
);
<?php
$conn = new mysqli("localhost", "root", "", "test_db");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
<?php
include 'db.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $password);

    if ($stmt->execute()) {
        echo "User registered! <a href='login.php'>Login</a>";
    } else {
        echo "Error: Username may already exist";
    }
}
?>

<form method="POST">
    <input type="text" name="username" placeholder="Username" required><br><br>
    <input type="password" name="password" placeholder="Password" required><br><br>
    <button type="submit">Register</button>
</form>
<form method="POST" action="authenticate.php">
    <input type="text" name="username" placeholder="Username" required><br><br>
    <input type="password" name="password" placeholder="Password" required><br><br>

    <label>
        <input type="checkbox" name="remember"> Remember Me
    </label><br><br>

    <button type="submit">Login</button>
</form>
<?php
session_start();
include 'db.php';

$username = $_POST['username'];
$password = $_POST['password'];

$stmt = $conn->prepare("SELECT id, password FROM users WHERE username=?");
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    $stmt->bind_result($id, $hashedPassword);
    $stmt->fetch();

    if (password_verify($password, $hashedPassword)) {

        session_regenerate_id(true);

        $_SESSION['user_id'] = $id;
        $_SESSION['username'] = $username;

        // Remember me
        if (isset($_POST['remember'])) {
            $token = bin2hex(random_bytes(32));

            $stmt2 = $conn->prepare("UPDATE users SET remember_token=? WHERE id=?");
            $stmt2->bind_param("si", $token, $id);
            $stmt2->execute();

            setcookie("remember_token", $token, time() + (86400 * 30), "/", "", false, true);
        }

        header("Location: dashboard.php");
        exit();
    }
}

echo "Invalid credentials!";
?>
<?php
session_start();
include 'db.php';

// If session exists
if (isset($_SESSION['user_id'])) {
    return;
}

// Check cookie
if (isset($_COOKIE['remember_token'])) {

    $token = $_COOKIE['remember_token'];

    $stmt = $conn->prepare("SELECT id, username FROM users WHERE remember_token=?");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $username);
        $stmt->fetch();

        $_SESSION['user_id'] = $id;
        $_SESSION['username'] = $username;

        return;
    }
}

// Not logged in
header("Location: login.php");
exit();
?>
<?php
include 'auth_check.php';
?>

<h2>Welcome <?php echo $_SESSION['username']; ?></h2>

<a href="logout.php">Logout</a>
<?php
session_start();
include 'db.php';

// Remove token from DB (optional but recommended)
if (isset($_SESSION['user_id'])) {
    $stmt = $conn->prepare("UPDATE users SET remember_token=NULL WHERE id=?");
    $stmt->bind_param("i", $_SESSION['user_id']);
    $stmt->execute();
}

// Destroy session
session_unset();
session_destroy();

// Delete cookie
setcookie("remember_token", "", time() - 3600, "/");

header("Location: login.php");
exit();
?>


