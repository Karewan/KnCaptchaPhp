<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha;

use Closure;
use InvalidArgumentException;
use Karewan\KnCaptcha\Internal\Base64Url;
use Karewan\KnCaptcha\Internal\Equihash;
use SensitiveParameter;
use UnexpectedValueException;

/**
 * Server side of KnCaptcha: issues the challenges solved by the widget and checks their solutions
 *
 *     $captcha = new KnCaptcha($secret, Store::redis($redis));
 *     echo json_encode(['challenge' => $captcha->createChallenge('login')]);   // GET /captcha/challenge
 *     if (!$captcha->verify($_POST['kncaptcha'] ?? '', 'login')) { ... }        // POST /login
 *
 * Issuing a challenge costs a random draw and an HMAC, and stores nothing. Checking a solution costs an HMAC, 2^k + 2
 * SHA-256 per proof (66 with the default difficulty, a few tens of microseconds), then one call to $markUsed: only
 * valid solutions reach the store.
 */
final class KnCaptcha
{
	public const string VERSION = '2.0.0';

	/** First byte of the challenges */
	public const int PROTOCOL_VERSION = 2;

	public const int MIN_SECRET_BYTES = 32;

	/** Longest lifetime of a challenge (s) */
	public const int MAX_TTL = 86400;

	private const string DOMAIN = 'kncaptcha/v2';
	private const int PAYLOAD_BYTES = 32;
	private const int MAC_BYTES = 32;
	private const int SALT_OFFSET = 16;

	/** 8 proofs of Equihash(n, 7) in base64url, with the challenge */
	private const int MAX_SOLUTION_LENGTH = 6000;

	private readonly string $secret;

	/** @var Closure(): int */
	private readonly Closure $clock;

	/**
	 * @param string $secret at least 32 bytes, e.g. bin2hex(random_bytes(32)), kept out of the code. Changing it
	 * invalidates the pending challenges.
	 * @param Closure(string, int): bool $markUsed remembers the id of a solved challenge (32 hexadecimal characters) for
	 * the given number of seconds, and returns true only if it was not known yet. It must be atomic: Redis
	 * SET NX EX, apcu_add(), Memcached::add(), a primary key... Store has ready-made ones.
	 * @param Difficulty $difficulty default difficulty of createChallenge()
	 * @param int $ttl default lifetime of a challenge (s): time to solve it, then to submit the form
	 * @param (Closure(): int)|null $clock current Unix time, time() by default
	 * @throws InvalidArgumentException
	 */
	public function __construct(
		#[SensitiveParameter] string $secret,
		private readonly Closure $markUsed,
		private readonly Difficulty $difficulty = new Difficulty(),
		private readonly int $ttl = 600,
		?Closure $clock = null,
	) {
		if (strlen($secret) < self::MIN_SECRET_BYTES) {
			throw new InvalidArgumentException('The secret must be at least ' . self::MIN_SECRET_BYTES . ' bytes long');
		}
		self::checkTtl($ttl);
		$this->secret = $secret;
		$this->clock = $clock ?? time(...);
	}

	/**
	 * @param string $scope what the challenge is for (form name, IP address...): verify() must be given the same scope
	 * @param Difficulty|null $difficulty the default difficulty when null
	 * @param int|null $ttl lifetime in seconds, the default one when null
	 * @return string the challenge for the widget, 87 characters
	 * @throws InvalidArgumentException
	 */
	public function createChallenge(string $scope = '', ?Difficulty $difficulty = null, ?int $ttl = null): string
	{
		$difficulty ??= $this->difficulty;
		$ttl ??= $this->ttl;
		self::checkTtl($ttl);
		$now = $this->now();

		$payload = pack(
			'CCCCCx3NN',
			self::PROTOCOL_VERSION,
			$difficulty->n,
			$difficulty->k,
			$difficulty->bits,
			$difficulty->proofs,
			$now,
			$now + $ttl,
		) . random_bytes(self::PAYLOAD_BYTES - self::SALT_OFFSET);

		return Base64Url::encode($payload) . '.' . Base64Url::encode($this->sign($payload, $scope));
	}

	/**
	 * Checks a solution and marks its challenge as used: a solution passes once
	 * @param string $solution sent by the widget (hidden input "kncaptcha" by default)
	 * @param string $scope the scope given to createChallenge()
	 * @return bool
	 * @throws UnexpectedValueException when $markUsed does not return a bool
	 */
	public function verify(string $solution, string $scope = ''): bool
	{
		return $this->check($solution, $scope) === Result::Valid;
	}

	/**
	 * Same as verify(), with the reason of a refusal
	 * @param string $solution
	 * @param string $scope
	 * @return Result
	 * @throws UnexpectedValueException when $markUsed does not return a bool
	 */
	public function check(string $solution, string $scope = ''): Result
	{
		// Cheapest checks first: an HMAC, then the proofs, and the store only for a valid solution
		if (strlen($solution) > self::MAX_SOLUTION_LENGTH) {
			return Result::Malformed;
		}
		$parts = explode('.', $solution);
		if (count($parts) !== 3) {
			return Result::Malformed;
		}
		$payload = Base64Url::decode($parts[0]);
		$mac = Base64Url::decode($parts[1]);
		$proofs = Base64Url::decode($parts[2]);
		if ($payload === null || $mac === null || $proofs === null || strlen($payload) !== self::PAYLOAD_BYTES || strlen($mac) !== self::MAC_BYTES) {
			return Result::Malformed;
		}
		if (!hash_equals($this->sign($payload, $scope), $mac)) {
			return Result::BadSignature;
		}

		/** @var array{version: int, n: int, k: int, bits: int, proofs: int, expires: int} $fields */
		$fields = unpack('Cversion/Cn/Ck/Cbits/Cproofs/x3/Nissued/Nexpires', $payload);
		if ($fields['version'] !== self::PROTOCOL_VERSION) {
			return Result::Malformed;
		}
		$now = $this->now();
		if ($now >= $fields['expires']) {
			return Result::Expired;
		}

		$k = $fields['k'];
		$size = ((1 << $k) + 1) * 4;
		if (strlen($proofs) !== $fields['proofs'] * $size) {
			return Result::Malformed;
		}
		for ($proof = 0; $proof < $fields['proofs']; $proof++) {
			/** @var list<int> $indices */
			$indices = array_values(unpack('V*', substr($proofs, $proof * $size, $size)));
			$nonce = array_shift($indices);
			$seed = hash('sha256', self::DOMAIN . $payload . $mac . chr($proof) . pack('V', $nonce), true);
			if (
				!Equihash::verify($seed, $fields['n'], $k, $indices)
				|| !Equihash::leadingZeroBits(hash('sha256', $seed . pack('V*', ...$indices), true), $fields['bits'])
			) {
				return Result::InvalidProof;
			}
		}

		$fresh = ($this->markUsed)(bin2hex(substr($payload, self::SALT_OFFSET)), $fields['expires'] - $now);
		if (!is_bool($fresh)) {
			throw new UnexpectedValueException('The markUsed closure of KnCaptcha must return a bool, it returned ' . get_debug_type($fresh));
		}
		return $fresh ? Result::Valid : Result::Replayed;
	}

	/**
	 * Keeps the secret out of var_dump() and print_r()
	 * @return array<string, mixed>
	 */
	public function __debugInfo(): array
	{
		return ['secret' => '[hidden]', 'difficulty' => $this->difficulty, 'ttl' => $this->ttl];
	}

	private function sign(string $payload, string $scope): string
	{
		// The payload has a fixed length: nothing can move from the scope to the payload
		return hash_hmac('sha256', self::DOMAIN . $payload . $scope, $this->secret, true);
	}

	private function now(): int
	{
		return ($this->clock)();
	}

	private static function checkTtl(int $ttl): void
	{
		if ($ttl < 1 || $ttl > self::MAX_TTL) {
			throw new InvalidArgumentException('The lifetime of a challenge must be between 1 and ' . self::MAX_TTL . ' seconds');
		}
	}
}
