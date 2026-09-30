<?php

declare(strict_types=1);

// Every notice, warning or deprecation fails the tests: KnCaptcha must never raise one, whatever it is given
set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
	if ((error_reporting() & $severity) === 0) {
		return false;
	}
	throw new ErrorException($message, 0, $severity, $file, $line);
});

spl_autoload_register(static function (string $class): void {
	foreach (['Karewan\\KnCaptcha\\Tests\\' => __DIR__ . '/', 'Karewan\\KnCaptcha\\' => __DIR__ . '/../src/'] as $prefix => $dir) {
		if (str_starts_with($class, $prefix)) {
			$file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
			if (is_file($file)) {
				require $file;
			}
			return;
		}
	}
});
