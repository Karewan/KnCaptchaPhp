<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha;

use InvalidArgumentException;

/**
 * Cost of a challenge for the browser. It does not change the cost of the verification much: 2^k hashes per proof.
 *
 * The browser runs Equihash(n, k) until it finds, for each of the `proofs` proofs, a solution whose hash starts with
 * `bits` zero bits. A run of Equihash(96, 5) takes about 40 ms on a desktop core and 150 to 250 ms on a phone core,
 * holds about 10 MB and gives about 2 solutions; the widget uses up to 8 cores.
 */
final readonly class Difficulty
{
	/** Limits shared with the JavaScript solver: its memory grows with 2^c (c = n / (k + 1)), the verification with 2^k */
	public const int MIN_K = 2;
	public const int MAX_K = 7;
	public const int MIN_C = 8;
	public const int MAX_C = 20;
	public const int MAX_BITS = 24;
	public const int MAX_PROOFS = 8;

	/** Average number of Equihash solutions per run */
	private const float SOLUTIONS_PER_RUN = 2.0;

	/**
	 * @param int $bits leading zero bits required on the hash of each solution: each bit doubles the work
	 * @param int $proofs solutions to find: more proofs make the solving time more regular, and cost 2^k hashes each to
	 * check
	 * @param int $n Equihash hash length in bits
	 * @param int $k Equihash rounds
	 * @throws InvalidArgumentException when a parameter is outside the supported range
	 */
	public function __construct(
		public int $bits = 5,
		public int $proofs = 2,
		public int $n = 96,
		public int $k = 5,
	) {
		if ($bits < 0 || $bits > self::MAX_BITS) {
			throw new InvalidArgumentException('bits must be between 0 and ' . self::MAX_BITS);
		}
		if ($proofs < 1 || $proofs > self::MAX_PROOFS) {
			throw new InvalidArgumentException('proofs must be between 1 and ' . self::MAX_PROOFS);
		}
		if ($k < self::MIN_K || $k > self::MAX_K || $n % ($k + 1) !== 0) {
			throw new InvalidArgumentException('k must be between ' . self::MIN_K . ' and ' . self::MAX_K . ', and n a multiple of k + 1');
		}
		$c = intdiv($n, $k + 1);
		if ($c < self::MIN_C || $c > self::MAX_C) {
			throw new InvalidArgumentException('n / (k + 1) must be between ' . self::MIN_C . ' and ' . self::MAX_C);
		}
	}

	/** About 8 runs: a fraction of a second everywhere */
	public static function low(): self
	{
		return new self(3);
	}

	/** About 32 runs: under half a second on a desktop, 1 to 2 s on a phone */
	public static function medium(): self
	{
		return new self(5);
	}

	/** About 128 runs: 1 s on a desktop, 4 to 8 s on a phone */
	public static function high(): self
	{
		return new self(7);
	}

	/**
	 * @return float average number of Equihash runs the browser needs
	 */
	public function expectedRuns(): float
	{
		return $this->proofs * (2 ** $this->bits) / self::SOLUTIONS_PER_RUN;
	}
}
