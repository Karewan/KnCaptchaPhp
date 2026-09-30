<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Tests\Unit;

use Karewan\KnCaptcha\Internal\Base64Url;
use Karewan\KnCaptcha\Internal\Equihash;
use Karewan\KnCaptcha\Tests\DataProvider;
use Karewan\KnCaptcha\Tests\Support\Solver;
use Karewan\KnCaptcha\Tests\TestCase;

final class EquihashTest extends TestCase
{
	/**
	 * @return array{string, list<int>} a seed and a solution of Equihash(48, 3)
	 */
	private static function solution(int $n = 48, int $k = 3): array
	{
		for ($s = 0; ; $s++) {
			$seed = hash('sha256', "seed {$s}", true);
			$indices = Solver::equihash($seed, $n, $k, static fn (): bool => true);
			if ($indices !== null) {
				return [$seed, $indices];
			}
		}
	}

	/**
	 * @return array<string, array{int, int}>
	 */
	public static function parameters(): array
	{
		return ['48, 3' => [48, 3], '54, 5 (unaligned)' => [54, 5], '60, 4' => [60, 4]];
	}

	#[DataProvider('parameters')]
	public function testSolutionsOfThePhpSolverPass(int $n, int $k): void
	{
		[$seed, $indices] = self::solution($n, $k);
		$this->assertTrue(Equihash::verify($seed, $n, $k, $indices));
	}

	public function testAnotherSeedFails(): void
	{
		[, $indices] = self::solution();
		$this->assertFalse(Equihash::verify(hash('sha256', 'other', true), 48, 3, $indices));
	}

	public function testChangedIndexFails(): void
	{
		[$seed, $indices] = self::solution();
		foreach ([0, 3, 7] as $position) {
			$changed = $indices;
			$changed[$position] = ($changed[$position] + 1) % 8192;
			$this->assertFalse(Equihash::verify($seed, 48, 3, $changed));
		}
	}

	public function testOrderIsCanonical(): void
	{
		[$seed, $indices] = self::solution();
		$swapped = $indices;
		[$swapped[0], $swapped[1]] = [$swapped[1], $swapped[0]];
		$this->assertFalse(Equihash::verify($seed, 48, 3, $swapped));
		$this->assertFalse(Equihash::verify($seed, 48, 3, [...array_slice($indices, 4), ...array_slice($indices, 0, 4)]));
	}

	public function testBadIndicesFail(): void
	{
		[$seed, $indices] = self::solution();
		$this->assertFalse(Equihash::verify($seed, 48, 3, array_fill(0, 8, 5)));
		$this->assertFalse(Equihash::verify($seed, 48, 3, [...array_slice($indices, 0, 7), 8192]));
		$this->assertFalse(Equihash::verify($seed, 48, 3, [...array_slice($indices, 0, 7), -1]));
		$this->assertFalse(Equihash::verify($seed, 48, 3, array_slice($indices, 0, 4)));
		// A leaf paired with itself XORs to zero everywhere: only the distinct check stops it
		$this->assertFalse(Equihash::verify($seed, 48, 3, [0, 0, 1, 1, 2, 2, 3, 3]));
	}

	public function testUnsupportedParametersFail(): void
	{
		[$seed, $indices] = self::solution();
		$this->assertFalse(Equihash::verify($seed, 48, 1, array_slice($indices, 0, 2)));
		$this->assertFalse(Equihash::verify($seed, 49, 3, $indices));
		$this->assertFalse(Equihash::verify($seed, 24, 3, $indices));
	}

	public function testLeadingZeroBits(): void
	{
		$this->assertTrue(Equihash::leadingZeroBits("\x00\x00\x0f", 20));
		$this->assertFalse(Equihash::leadingZeroBits("\x00\x00\x0f", 21));
		$this->assertTrue(Equihash::leadingZeroBits("\x00\x00", 16));
		$this->assertFalse(Equihash::leadingZeroBits("\x00\x01", 16));
		$this->assertTrue(Equihash::leadingZeroBits("\xff", 0));
		$this->assertFalse(Equihash::leadingZeroBits("\x80", 1));
	}

	public function testBase64Url(): void
	{
		$this->assertSame('', Base64Url::decode(''));
		for ($length = 1; $length < 40; $length++) {
			$bytes = random_bytes($length);
			$text = Base64Url::encode($bytes);
			$this->assertMatches('/^[A-Za-z0-9_-]*$/', $text);
			$this->assertSame($bytes, Base64Url::decode($text));
		}
		foreach (['AAE=', 'a+b/', 'AAAAA', 'AB', 'QR', 'AA AA', "AA\n", 'AAé'] as $text) {
			$this->assertSame(null, Base64Url::decode($text), $text);
		}
	}
}
