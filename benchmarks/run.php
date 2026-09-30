<?php

declare(strict_types=1);

/**
 * Server cost of KnCaptcha: composer bench
 * Checks the solutions of tests/Fixtures/vectors.json again and again, with a store that accepts everything.
 */

use Karewan\KnCaptcha\Difficulty;
use Karewan\KnCaptcha\KnCaptcha;

require __DIR__ . '/../tests/bootstrap.php';

/**
 * @param callable(): mixed $callback
 * @return float microseconds per call
 */
function measure(callable $callback, int $iterations): float
{
	for ($i = 0; $i < 1000; $i++) {
		$callback();
	}
	$start = hrtime(true);
	for ($i = 0; $i < $iterations; $i++) {
		$callback();
	}
	return (hrtime(true) - $start) / $iterations / 1000;
}

$vectors = json_decode((string) file_get_contents(__DIR__ . '/../tests/Fixtures/vectors.json'), true, flags: JSON_THROW_ON_ERROR);
$byName = array_column($vectors, null, 'name');

printf("PHP %s, OPcache %s, JIT %s\n\n", PHP_VERSION, ini_get('opcache.enable_cli') ? 'on' : 'off', ini_get('opcache.jit') ?: 'off');

$captcha = new KnCaptcha(str_repeat('s', 32), static fn (string $id, int $ttl): bool => true);
printf("%-52s %8.2f µs\n", 'createChallenge()', measure(static fn () => $captcha->createChallenge('login'), 20000));

foreach ([
	'Equihash(96,5), 2 proofs of 5 bits' => 'check(), default difficulty: 2 proofs of Equihash(96,5)',
	'Scoped challenge' => 'check(), 1 proof of Equihash(96,5)',
	'Equihash(80,4), 8 proofs without difficulty' => 'check(), 8 proofs of Equihash(80,4)',
	'Index changed' => 'check(), wrong proof (refused at the last level)',
	'Other scope' => 'check(), bad signature',
	'Padded base64' => 'check(), malformed',
] as $name => $label) {
	$vector = $byName[$name];
	$checker = new KnCaptcha($vector['secret'], static fn (string $id, int $ttl): bool => true, clock: static fn (): int => $vector['now']);
	$result = $checker->check($vector['solution'], $vector['scope']);
	$micros = measure(static fn () => $checker->check($vector['solution'], $vector['scope']), 5000);
	printf("%-52s %8.2f µs  (%s)\n", $label, $micros, $result->value);
}

printf("\nDefault difficulty: %.0f Equihash runs on average for the browser\n", (new Difficulty())->expectedRuns());
