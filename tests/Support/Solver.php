<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Tests\Support;

use Karewan\KnCaptcha\Internal\Base64Url;
use Karewan\KnCaptcha\Internal\Equihash;
use RuntimeException;

/**
 * Plain PHP solver, for the round trips of the tests with small parameters (Equihash(48, 3): 8192 leaves). The browser
 * uses the optimized JavaScript one.
 */
final class Solver
{
	/**
	 * Solves every proof of a challenge
	 * @param string $challenge
	 * @return string the solution to give to KnCaptcha::check()
	 */
	public static function solve(string $challenge): string
	{
		[$payloadText, $macText] = explode('.', $challenge);
		$payload = Base64Url::decode($payloadText) ?? throw new RuntimeException('Malformed challenge');
		$mac = Base64Url::decode($macText) ?? throw new RuntimeException('Malformed challenge');
		/** @var array{n: int, k: int, bits: int, proofs: int} $fields */
		$fields = unpack('Cversion/Cn/Ck/Cbits/Cproofs', $payload);

		$proofs = '';
		for ($proof = 0; $proof < $fields['proofs']; $proof++) {
			for ($nonce = 0; ; $nonce++) {
				$seed = hash('sha256', 'kncaptcha/v2' . $payload . $mac . chr($proof) . pack('V', $nonce), true);
				$indices = self::equihash(
					$seed,
					$fields['n'],
					$fields['k'],
					static fn (array $indices): bool => Equihash::leadingZeroBits(hash('sha256', $seed . pack('V*', ...$indices), true), $fields['bits']),
				);
				if ($indices !== null) {
					$proofs .= pack('V*', $nonce, ...$indices);
					break;
				}
			}
		}
		return $challenge . '.' . Base64Url::encode($proofs);
	}

	/**
	 * Wagner's algorithm on lists of [hash, leaves], merged in canonical order
	 * @param string $seed
	 * @param int $n
	 * @param int $k
	 * @param callable(list<int>): bool $accept
	 * @return list<int>|null the first accepted solution
	 */
	public static function equihash(string $seed, int $n, int $k, callable $accept): ?array
	{
		$c = intdiv($n, $k + 1);
		$leafBytes = ($n + 7) >> 3;
		$perHash = intdiv(32, $leafBytes);

		$list = [];
		for ($i = 0, $leaves = 1 << ($c + 1); $i < $leaves; $i++) {
			if ($i % $perHash === 0) {
				$digest = hash('sha256', $seed . pack('V', intdiv($i, $perHash)), true);
			}
			$list[] = [substr($digest, ($i % $perHash) * $leafBytes, $leafBytes), [$i]];
		}

		for ($round = 1; $round <= $k; $round++) {
			$buckets = [];
			foreach ($list as $entry) {
				$buckets[self::bits($entry[0], ($round - 1) * $c, $c)][] = $entry;
			}
			$next = [];
			foreach ($buckets as $bucket) {
				for ($x = 0, $size = count($bucket); $x < $size - 1; $x++) {
					for ($y = $x + 1; $y < $size; $y++) {
						[$a, $b] = $bucket[$x][1][0] < $bucket[$y][1][0] ? [$bucket[$x], $bucket[$y]] : [$bucket[$y], $bucket[$x]];
						$xor = $a[0] ^ $b[0];
						$indices = [...$a[1], ...$b[1]];
						if ($round < $k) {
							if (trim($xor, "\0") !== '') {
								$next[] = [$xor, $indices];
							}
						} elseif (self::bits($xor, $k * $c, $c) === 0 && count(array_unique($indices)) === count($indices) && $accept($indices)) {
							return $indices;
						}
					}
				}
			}
			$list = $next;
		}
		return null;
	}

	/**
	 * @param string $bytes
	 * @param int $offset
	 * @param int $count at most 25
	 * @return int the $count bits at bit $offset
	 */
	private static function bits(string $bytes, int $offset, int $count): int
	{
		$chunk = str_pad(substr($bytes, $offset >> 3, 4), 4, "\0");
		return (unpack('N', $chunk)[1] >> (32 - ($offset & 7) - $count)) & ((1 << $count) - 1);
	}
}
