<?php

declare(strict_types=1);

/**
 * Test runner: php tests/run.php [filter]
 * Runs the public test* methods of the classes of tests/Unit, once per data provider case.
 */

use Karewan\KnCaptcha\Tests\AssertionFailed;
use Karewan\KnCaptcha\Tests\DataProvider;
use Karewan\KnCaptcha\Tests\Skipped;
use Karewan\KnCaptcha\Tests\TestCase;

require __DIR__ . '/bootstrap.php';

$filter = $argv[1] ?? null;
$started = hrtime(true);
$passed = $failed = $skipped = $assertions = 0;
$failures = [];

$files = glob(__DIR__ . '/Unit/*Test.php') ?: [];
sort($files);

foreach ($files as $file) {
	$class = 'Karewan\\KnCaptcha\\Tests\\Unit\\' . basename($file, '.php');
	$reflection = new ReflectionClass($class);
	if ($reflection->isAbstract() || !$reflection->isSubclassOf(TestCase::class)) {
		continue;
	}

	foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
		if (!str_starts_with($method->getName(), 'test')) {
			continue;
		}

		$cases = [[]];
		$provider = $method->getAttributes(DataProvider::class)[0] ?? null;
		if (!is_null($provider)) {
			$providerName = $provider->newInstance()->method;
			$cases = $class::$providerName();
		}

		foreach ($cases as $caseName => $arguments) {
			$name = $reflection->getShortName() . '::' . $method->getName() . (is_null($provider) ? '' : ' [' . $caseName . ']');
			if (!is_null($filter) && !str_contains($name, $filter)) {
				continue;
			}

			/** @var TestCase $test */
			$test = new $class();
			try {
				$method->invokeArgs($test, $arguments);
				$passed++;
				echo '.';
			} catch (Skipped $e) {
				$skipped++;
				echo 'S';
				$failures[] = "SKIPPED {$name}: " . $e->getMessage();
			} catch (Throwable $e) {
				$failed++;
				echo 'F';
				$failures[] = "FAILED {$name}\n  " . ($e instanceof AssertionFailed ? '' : $e::class . ': ') . $e->getMessage()
					. "\n  at " . $e->getFile() . ':' . $e->getLine()
					. ($e instanceof AssertionFailed ? "\n  " . self_trace($e) : "\n" . preg_replace('/^/m', '    ', $e->getTraceAsString()));
			} finally {
				$assertions += $test->assertions;
			}
			if (($passed + $failed + $skipped) % 80 === 0) {
				echo "\n";
			}
		}
	}
}

/**
 * Line of the test that failed
 * @param Throwable $e
 * @return string
 */
function self_trace(Throwable $e): string
{
	foreach ($e->getTrace() as $frame) {
		if (isset($frame['file']) && str_contains($frame['file'], '/tests/Unit/')) {
			return 'in ' . basename($frame['file']) . ':' . $frame['line'];
		}
	}
	return '';
}

echo "\n\n" . implode("\n\n", $failures) . ($failures ? "\n\n" : '');
printf("%d passed, %d failed, %d skipped, %d assertions, %.2f s\n", $passed, $failed, $skipped, $assertions, (hrtime(true) - $started) / 1e9);
exit($failed > 0 ? 1 : 0);
