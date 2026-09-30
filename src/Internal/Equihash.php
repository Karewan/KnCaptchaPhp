<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Internal;

use Karewan\KnCaptcha\Difficulty;

/**
 * Checks Equihash solutions (Biryukov & Khovratovich, NDSS 2016): 2^k distinct leaves whose n-bit hashes XOR to
 * zero, each aligned group of 2^l leaves XORing to zero on its first l·c bits (c = n / (k + 1)), and the first leaf
 * of each left half lower than the first leaf of its right half.
 *
 * Leaf i is the slice (i mod perHash) of SHA-256(seed || LE32(i div perHash)), perHash being the number of whole
 * ceil(n/8)-byte slices in a digest; only its first n bits count. See PROTOCOL.md.
 * @internal
 */
final class Equihash
{
	/**
	 * @param string $seed 32 bytes
	 * @param int $n
	 * @param int $k
	 * @param list<int> $indices
	 * @return bool
	 */
	public static function verify(string $seed, int $n, int $k, array $indices): bool
	{
		// The parameters come from a signed challenge: checked again all the same, they bound the work
		if ($k < Difficulty::MIN_K || $k > Difficulty::MAX_K || $n % ($k + 1) !== 0) {
			return false;
		}
		$c = intdiv($n, $k + 1);
		if ($c < Difficulty::MIN_C || $c > Difficulty::MAX_C || count($indices) !== 1 << $k) {
			return false;
		}
		$leaves = 1 << ($c + 1);
		$leafBytes = ($n + 7) >> 3;
		$perHash = intdiv(32, $leafBytes);

		$hashes = [];
		$digests = [];
		$seen = [];
		foreach ($indices as $position => $index) {
			if ($index < 0 || $index >= $leaves || isset($seen[$index])) {
				return false;
			}
			$seen[$index] = true;
			$group = intdiv($index, $perHash);
			$digest = $digests[$group] ??= hash('sha256', $seed . pack('V', $group), true);
			$hashes[$position] = substr($digest, ($index % $perHash) * $leafBytes, $leafBytes);
		}

		// Level by level: the XOR of two siblings, known by the first leaf of the left one
		$first = $indices;
		for ($level = 1; $level <= $k; $level++) {
			$zeroBits = $level === $k ? $n : $level * $c;
			$nextHashes = [];
			$nextFirst = [];
			for ($m = 0, $count = count($hashes); $m < $count; $m += 2) {
				if ($first[$m] >= $first[$m + 1]) {
					return false;
				}
				$xor = $hashes[$m] ^ $hashes[$m + 1];
				if (!self::leadingZeroBits($xor, $zeroBits)) {
					return false;
				}
				$nextHashes[] = $xor;
				$nextFirst[] = $first[$m];
			}
			$hashes = $nextHashes;
			$first = $nextFirst;
		}
		return true;
	}

	/**
	 * @param string $bytes
	 * @param int $bits at most 8 × strlen($bytes)
	 * @return bool whether the first $bits bits are zero
	 */
	public static function leadingZeroBits(string $bytes, int $bits): bool
	{
		$full = $bits >> 3;
		if ($full > 0 && strspn($bytes, "\0", 0, $full) !== $full) {
			return false;
		}
		$rest = $bits & 7;
		return $rest === 0 || ord($bytes[$full]) >> (8 - $rest) === 0;
	}
}
