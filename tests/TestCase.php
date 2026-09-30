<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Tests;

use Throwable;

/**
 * Base of the tests: assertions
 */
abstract class TestCase
{
	public int $assertions = 0;

	protected function assertTrue(mixed $value, string $message = ''): void
	{
		$this->assertSame(true, $value, $message);
	}

	protected function assertFalse(mixed $value, string $message = ''): void
	{
		$this->assertSame(false, $value, $message);
	}

	protected function assertSame(mixed $expected, mixed $actual, string $message = ''): void
	{
		$this->assertions++;
		if ($expected !== $actual) {
			throw new AssertionFailed(($message !== '' ? $message . ': ' : '') . 'expected ' . self::export($expected) . ', got ' . self::export($actual));
		}
	}

	protected function assertMatches(string $pattern, string $value, string $message = ''): void
	{
		$this->assertions++;
		if (preg_match($pattern, $value) !== 1) {
			throw new AssertionFailed(($message !== '' ? $message . ': ' : '') . self::export($value) . ' does not match ' . $pattern);
		}
	}

	protected function assertLessThan(float|int $limit, float|int $value, string $message = ''): void
	{
		$this->assertions++;
		if ($value >= $limit) {
			throw new AssertionFailed(($message !== '' ? $message . ': ' : '') . "expected less than {$limit}, got {$value}");
		}
	}

	/**
	 * @template T of Throwable
	 * @param class-string<T> $class
	 * @param callable(): mixed $callback
	 * @param string|null $messageContains
	 * @return T
	 */
	protected function assertThrows(string $class, callable $callback, ?string $messageContains = null): Throwable
	{
		$this->assertions++;
		try {
			$callback();
		} catch (Throwable $e) {
			if (!$e instanceof $class) {
				throw new AssertionFailed("expected {$class}, got " . $e::class . ': ' . $e->getMessage());
			}
			if ($messageContains !== null && !str_contains($e->getMessage(), $messageContains)) {
				throw new AssertionFailed("expected a message containing '{$messageContains}', got '{$e->getMessage()}'");
			}
			return $e;
		}
		throw new AssertionFailed("expected {$class}, nothing was thrown");
	}

	protected function skip(string $reason): never
	{
		throw new Skipped($reason);
	}

	private static function export(mixed $value): string
	{
		if ($value instanceof \UnitEnum) {
			return $value::class . '::' . $value->name;
		}
		$export = var_export($value, true);
		return strlen($export) > 300 ? substr($export, 0, 300) . '...' : $export;
	}
}
