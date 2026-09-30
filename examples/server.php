<?php

declare(strict_types=1);

/**
 * Minimal integration, for the built-in server: php -S 127.0.0.1:8081 examples/server.php
 *
 *   GET  /captcha/challenge   the challenge for the widget
 *   POST /login               checks the "kncaptcha" field of the form
 *
 * The used challenges go to a SQLite table in the temporary directory: the built-in server forgets the memory of
 * PHP between requests.
 */

use Karewan\KnCaptcha\Difficulty;
use Karewan\KnCaptcha\KnCaptcha;
use Karewan\KnCaptcha\Store;

if (is_file(__DIR__ . '/../vendor/autoload.php')) {
	require __DIR__ . '/../vendor/autoload.php';
} else {
	spl_autoload_register(static function (string $class): void {
		$prefix = 'Karewan\\KnCaptcha\\';
		if (str_starts_with($class, $prefix)) {
			require __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
		}
	});
}

$pdo = new PDO('sqlite:' . sys_get_temp_dir() . '/kncaptcha-example.sqlite');
$pdo->exec('CREATE TABLE IF NOT EXISTS kncaptcha_used (id TEXT NOT NULL PRIMARY KEY, expires_at INTEGER NOT NULL)');

$captcha = new KnCaptcha(
	secret: getenv('KNCAPTCHA_SECRET') ?: 'example-secret-change-me-example-secret-0123',
	markUsed: Store::pdo($pdo),
);

header('Content-Type: application/json');
header('Cache-Control: no-store');

switch (parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH)) {
	case '/captcha/challenge':
		// The demo page picks the difficulty; a real application sets it, e.g. from the failed attempts of the IP
		$bits = max(0, min(12, (int) ($_GET['bits'] ?? 5)));
		echo json_encode(['challenge' => $captcha->createChallenge('login', new Difficulty($bits))]);
		break;

	case '/login':
		$result = $captcha->check((string) ($_POST['kncaptcha'] ?? ''), 'login');
		echo json_encode(['result' => $result->value]);
		break;

	default:
		http_response_code(404);
		echo json_encode(['error' => 'not_found']);
}
