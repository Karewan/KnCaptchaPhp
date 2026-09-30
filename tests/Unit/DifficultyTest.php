<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Tests\Unit;

use InvalidArgumentException;
use Karewan\KnCaptcha\Difficulty;
use Karewan\KnCaptcha\Tests\DataProvider;
use Karewan\KnCaptcha\Tests\TestCase;

final class DifficultyTest extends TestCase
{
	public function testDefaults(): void
	{
		$difficulty = new Difficulty();
		$this->assertSame([5, 2, 96, 5], [$difficulty->bits, $difficulty->proofs, $difficulty->n, $difficulty->k]);
		$this->assertSame(32.0, $difficulty->expectedRuns());
	}

	public function testPresets(): void
	{
		$this->assertSame(8.0, Difficulty::low()->expectedRuns());
		$this->assertSame(32.0, Difficulty::medium()->expectedRuns());
		$this->assertSame(128.0, Difficulty::high()->expectedRuns());
	}

	/**
	 * @return array<string, array{int, int, int, int}>
	 */
	public static function invalid(): array
	{
		return [
			'negative bits' => [-1, 2, 96, 5],
			'too many bits' => [25, 2, 96, 5],
			'no proof' => [5, 0, 96, 5],
			'too many proofs' => [5, 9, 96, 5],
			'k too small' => [5, 2, 96, 1],
			'k too large' => [5, 2, 144, 8],
			'n not a multiple of k + 1' => [5, 2, 97, 5],
			'c too small' => [5, 2, 42, 5],
			'c too large' => [5, 2, 126, 5],
		];
	}

	#[DataProvider('invalid')]
	public function testInvalid(int $bits, int $proofs, int $n, int $k): void
	{
		$this->assertThrows(InvalidArgumentException::class, fn () => new Difficulty($bits, $proofs, $n, $k));
	}
}
