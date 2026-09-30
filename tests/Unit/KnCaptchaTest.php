<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Tests\Unit;

use InvalidArgumentException;
use Karewan\KnCaptcha\Difficulty;
use Karewan\KnCaptcha\Internal\Base64Url;
use Karewan\KnCaptcha\KnCaptcha;
use Karewan\KnCaptcha\Result;
use Karewan\KnCaptcha\Store;
use Karewan\KnCaptcha\Tests\Support\Solver;
use Karewan\KnCaptcha\Tests\TestCase;
use UnexpectedValueException;

final class KnCaptchaTest extends TestCase
{
	private const string SECRET = 'php-tests-secret-php-tests-secret-0123';
	private const int NOW = 1_790_000_000;

	private int $now = self::NOW;

	/** @var list<array{string, int}> calls of the store */
	private array $marked = [];

	private function captcha(?Difficulty $difficulty = null, int $ttl = 300): KnCaptcha
	{
		$store = Store::memory(fn (): int => $this->now);
		return new KnCaptcha(
			self::SECRET,
			function (string $id, int $ttl) use ($store): bool {
				$this->marked[] = [$id, $ttl];
				return $store($id, $ttl);
			},
			$difficulty ?? new Difficulty(bits: 2, proofs: 2, n: 48, k: 3),
			$ttl,
			fn (): int => $this->now,
		);
	}

	public function testChallengeFormat(): void
	{
		$challenge = $this->captcha(new Difficulty(bits: 7, proofs: 3), 120)->createChallenge();
		$this->assertMatches('/^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/', $challenge);

		$payload = Base64Url::decode(explode('.', $challenge)[0]);
		$fields = unpack('Cversion/Cn/Ck/Cbits/Cproofs/C3reserved/Nissued/Nexpires', (string) $payload);
		$this->assertSame(
			['version' => 2, 'n' => 96, 'k' => 5, 'bits' => 7, 'proofs' => 3, 'reserved1' => 0, 'reserved2' => 0, 'reserved3' => 0, 'issued' => self::NOW, 'expires' => self::NOW + 120],
			$fields,
		);
	}

	public function testEachChallengeIsUnique(): void
	{
		$captcha = $this->captcha();
		$this->assertSame(false, $captcha->createChallenge() === $captcha->createChallenge());
	}

	public function testRoundTrip(): void
	{
		$captcha = $this->captcha();
		$solution = Solver::solve($captcha->createChallenge('login'));
		$this->now += 5;

		$this->assertSame(Result::Valid, $captcha->check($solution, 'login'));
		$this->assertSame(1, count($this->marked));
		$this->assertMatches('/^[0-9a-f]{32}$/', $this->marked[0][0]);
		// Remembered until the expiry of the challenge, not longer
		$this->assertSame(295, $this->marked[0][1]);

		$this->assertSame(Result::Replayed, $captcha->check($solution, 'login'));
		$this->assertFalse($captcha->verify($solution, 'login'));
	}

	public function testVerifyGivesABoolean(): void
	{
		$captcha = $this->captcha();
		$this->assertTrue($captcha->verify(Solver::solve($captcha->createChallenge())));
		$this->assertFalse($captcha->verify('garbage'));
	}

	public function testScopeMustMatch(): void
	{
		$captcha = $this->captcha();
		$solution = Solver::solve($captcha->createChallenge('login'));
		$this->assertSame(Result::BadSignature, $captcha->check($solution));
		$this->assertSame(Result::BadSignature, $captcha->check($solution, 'register'));
		$this->assertSame(Result::Valid, $captcha->check($solution, 'login'));
	}

	public function testExpiry(): void
	{
		$captcha = $this->captcha(ttl: 60);
		$solution = Solver::solve($captcha->createChallenge());
		$this->now += 60;
		$this->assertSame(Result::Expired, $captcha->check($solution));
		$this->now -= 1;
		$this->assertSame(Result::Valid, $captcha->check($solution));
		$this->assertSame(1, $this->marked[0][1]);
	}

	public function testOtherSecret(): void
	{
		$solution = Solver::solve($this->captcha()->createChallenge());
		$other = new KnCaptcha(str_repeat('x', 32), Store::memory(), clock: fn (): int => $this->now);
		$this->assertSame(Result::BadSignature, $other->check($solution));
	}

	public function testDifficultyAndTtlPerChallenge(): void
	{
		$captcha = $this->captcha();
		$challenge = $captcha->createChallenge(difficulty: new Difficulty(bits: 0, proofs: 1, n: 48, k: 3), ttl: 30);
		$fields = unpack('x3/Cbits/Cproofs/x3/Nissued/Nexpires', (string) Base64Url::decode(explode('.', $challenge)[0]));
		$this->assertSame(['bits' => 0, 'proofs' => 1, 'issued' => self::NOW, 'expires' => self::NOW + 30], $fields);
		$this->assertSame(Result::Valid, $captcha->check(Solver::solve($challenge)));
	}

	public function testInvalidSolutionsNeverReachTheStore(): void
	{
		$captcha = $this->captcha();
		$solution = Solver::solve($captcha->createChallenge());
		[$payload, $mac, $proofs] = explode('.', $solution);
		$bytes = (string) Base64Url::decode($proofs);
		$bytes[4] = chr(ord($bytes[4]) ^ 1);

		$this->assertSame(Result::InvalidProof, $captcha->check("{$payload}.{$mac}." . Base64Url::encode($bytes)));
		$this->assertSame(Result::BadSignature, $captcha->check($solution, 'other'));
		$this->assertSame(Result::Malformed, $captcha->check("{$payload}.{$mac}"));
		$this->assertSame(0, count($this->marked));
	}

	public function testMalformedInputs(): void
	{
		$captcha = $this->captcha();
		$solution = Solver::solve($captcha->createChallenge());
		foreach (['', '.', '..', 'a.b.c', $solution . '.', $solution . '=', str_repeat('A', 7000), "{$solution}\n", "é.{$solution}"] as $input) {
			$this->assertSame(Result::Malformed, $captcha->check($input), var_export(substr($input, 0, 20), true));
		}
	}

	public function testStoreMustAnswerABoolean(): void
	{
		$captcha = new KnCaptcha(self::SECRET, static fn (string $id, int $ttl): int => 1, new Difficulty(bits: 0, proofs: 1, n: 48, k: 3));
		$this->assertThrows(UnexpectedValueException::class, fn () => $captcha->check(Solver::solve($captcha->createChallenge())), 'must return a bool, it returned int');
	}

	public function testStoreFailuresGoUp(): void
	{
		$captcha = new KnCaptcha(self::SECRET, static fn (string $id, int $ttl): bool => throw new \RuntimeException('Redis down'), new Difficulty(bits: 0, proofs: 1, n: 48, k: 3));
		$this->assertThrows(\RuntimeException::class, fn () => $captcha->check(Solver::solve($captcha->createChallenge())), 'Redis down');
	}

	public function testConfigurationErrors(): void
	{
		$this->assertThrows(InvalidArgumentException::class, fn () => new KnCaptcha(str_repeat('x', 31), Store::memory()), '32 bytes');
		$this->assertThrows(InvalidArgumentException::class, fn () => new KnCaptcha(self::SECRET, Store::memory(), ttl: 0));
		$this->assertThrows(InvalidArgumentException::class, fn () => $this->captcha()->createChallenge(ttl: KnCaptcha::MAX_TTL + 1));
	}

	public function testSecretStaysOutOfDumps(): void
	{
		$dump = print_r($this->captcha(), true);
		$this->assertSame(false, str_contains($dump, self::SECRET));
		$this->assertSame(true, str_contains($dump, '[hidden]'));
	}

	public function testDefaultClock(): void
	{
		$captcha = new KnCaptcha(self::SECRET, Store::memory(), new Difficulty(bits: 0, proofs: 1, n: 48, k: 3));
		$fields = unpack('x8/Nissued', (string) Base64Url::decode(explode('.', $captcha->createChallenge())[0]));
		$this->assertLessThan(3, abs($fields['issued'] - time()));
		$this->assertSame(Result::Valid, $captcha->check(Solver::solve($captcha->createChallenge())));
	}
}
