<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha;

use Closure;
use InvalidArgumentException;
use Memcached;
use PDO;
use PDOException;
use Predis\ClientInterface;
use Redis;

/**
 * Ready-made $markUsed closures of KnCaptcha. Each one remembers an id for $ttl seconds, atomically, and returns true
 * only for an id it did not know. Any exception of the store goes up to the caller: a store down refuses nothing
 * silently.
 */
final class Store
{
	/**
	 * phpredis (or a compatible client such as Relay): SET key 1 NX EX ttl
	 * @param Redis $redis
	 * @param string $prefix
	 * @return Closure(string, int): bool
	 */
	public static function redis(Redis $redis, string $prefix = 'kncaptcha:'): Closure
	{
		return static fn (string $id, int $ttl): bool => $redis->set($prefix . $id, 1, ['nx', 'ex' => $ttl]) === true;
	}

	/**
	 * Predis: SET key 1 EX ttl NX
	 * @param ClientInterface $predis
	 * @param string $prefix
	 * @return Closure(string, int): bool
	 */
	public static function predis(ClientInterface $predis, string $prefix = 'kncaptcha:'): Closure
	{
		return static fn (string $id, int $ttl): bool => $predis->set($prefix . $id, 1, 'EX', $ttl, 'NX') !== null;
	}

	/**
	 * APCu: memory of one server, not shared by several web servers
	 * @param string $prefix
	 * @return Closure(string, int): bool
	 */
	public static function apcu(string $prefix = 'kncaptcha:'): Closure
	{
		return static fn (string $id, int $ttl): bool => apcu_add($prefix . $id, 1, $ttl);
	}

	/**
	 * @param Memcached $memcached
	 * @param string $prefix
	 * @return Closure(string, int): bool
	 */
	public static function memcached(Memcached $memcached, string $prefix = 'kncaptcha:'): Closure
	{
		return static fn (string $id, int $ttl): bool => $memcached->add($prefix . $id, 1, $ttl);
	}

	/**
	 * Database table with the id as primary key (MySQL/MariaDB, PostgreSQL, SQLite...), see the README for its
	 * creation. The expired rows are deleted from time to time, on one call in 100.
	 * @param PDO $pdo in ERRMODE_EXCEPTION, the default since PHP 8.0
	 * @param string $table
	 * @return Closure(string, int): bool
	 * @throws InvalidArgumentException when the table name is not a plain identifier
	 */
	public static function pdo(PDO $pdo, string $table = 'kncaptcha_used'): Closure
	{
		if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $table) !== 1) {
			throw new InvalidArgumentException('The table name must be a plain identifier');
		}
		return static function (string $id, int $ttl) use ($pdo, $table): bool {
			$now = time();
			if (random_int(1, 100) === 1) {
				$pdo->prepare("DELETE FROM {$table} WHERE expires_at < ?")->execute([$now]);
			}
			try {
				$pdo->prepare("INSERT INTO {$table} (id, expires_at) VALUES (?, ?)")->execute([$id, $now + $ttl]);
				return true;
			} catch (PDOException $e) {
				// Integrity constraint violation (SQLSTATE class 23): the id is already there
				if (str_starts_with((string) ($e->errorInfo[0] ?? $e->getCode()), '23')) {
					return false;
				}
				throw $e;
			}
		};
	}

	/**
	 * Memory of the PHP process: for the tests and long-running processes only, PHP-FPM forgets it at the end of each
	 * request
	 * @param (Closure(): int)|null $clock current Unix time, time() by default
	 * @return Closure(string, int): bool
	 */
	public static function memory(?Closure $clock = null): Closure
	{
		$clock ??= time(...);
		/** @var array<string, int> $expiries */
		$expiries = [];
		return static function (string $id, int $ttl) use (&$expiries, $clock): bool {
			$now = $clock();
			$expiries = array_filter($expiries, static fn (int $expiry): bool => $expiry > $now);
			if (isset($expiries[$id])) {
				return false;
			}
			$expiries[$id] = $now + $ttl;
			return true;
		};
	}
}
