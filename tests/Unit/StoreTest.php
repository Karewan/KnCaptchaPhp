<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Tests\Unit;

use Closure;
use InvalidArgumentException;
use Karewan\KnCaptcha\Store;
use Karewan\KnCaptcha\Tests\TestCase;
use PDO;
use PDOException;

final class StoreTest extends TestCase
{
	/**
	 * The contract of every store: true the first time, false while the id is remembered
	 * @param Closure(string, int): bool $store
	 */
	private function assertRemembersOnce(Closure $store): void
	{
		$id = bin2hex(random_bytes(16));
		$this->assertTrue($store($id, 60));
		$this->assertFalse($store($id, 60));
		$this->assertTrue($store(bin2hex(random_bytes(16)), 60));
	}

	public function testMemory(): void
	{
		$now = 1000;
		$store = Store::memory(static function () use (&$now): int {
			return $now;
		});
		$this->assertRemembersOnce($store);
		$this->assertTrue($store('a', 10));
		$now += 9;
		$this->assertFalse($store('a', 10));
		$now += 1;
		$this->assertTrue($store('a', 10));
	}

	public function testPdo(): void
	{
		if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
			$this->skip('pdo_sqlite is not installed');
		}
		$pdo = new PDO('sqlite::memory:');
		$pdo->exec('CREATE TABLE kncaptcha_used (id TEXT NOT NULL PRIMARY KEY, expires_at INTEGER NOT NULL)');
		$store = Store::pdo($pdo);
		$this->assertRemembersOnce($store);

		$store('ttl', 60);
		$expiry = (int) $pdo->query("SELECT expires_at FROM kncaptcha_used WHERE id = 'ttl'")->fetchColumn();
		$this->assertLessThan(3, abs($expiry - (time() + 60)));
	}

	public function testPdoLetsOtherErrorsGoUp(): void
	{
		if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
			$this->skip('pdo_sqlite is not installed');
		}
		$this->assertThrows(PDOException::class, fn () => Store::pdo(new PDO('sqlite::memory:'), 'missing_table')('id', 60));
	}

	public function testPdoRefusesOddTableNames(): void
	{
		if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
			$this->skip('pdo_sqlite is not installed');
		}
		$this->assertThrows(InvalidArgumentException::class, fn () => Store::pdo(new PDO('sqlite::memory:'), 'used; DROP TABLE users'));
	}

	public function testApcu(): void
	{
		if (!function_exists('apcu_add') || !apcu_enabled()) {
			$this->skip('APCu is not enabled (apc.enable_cli=1)');
		}
		$this->assertRemembersOnce(Store::apcu('kncaptcha-test:'));
	}

	public function testRedis(): void
	{
		if (!class_exists(\Redis::class) || getenv('REDIS_HOST') === false) {
			$this->skip('phpredis and REDIS_HOST are needed');
		}
		$redis = new \Redis();
		$redis->connect((string) getenv('REDIS_HOST'));
		$this->assertRemembersOnce(Store::redis($redis, 'kncaptcha-test:'));
	}

	public function testMemcached(): void
	{
		if (!class_exists(\Memcached::class) || getenv('MEMCACHED_HOST') === false) {
			$this->skip('ext-memcached and MEMCACHED_HOST are needed');
		}
		$memcached = new \Memcached();
		$memcached->addServer((string) getenv('MEMCACHED_HOST'), 11211);
		$this->assertRemembersOnce(Store::memcached($memcached, 'kncaptcha-test:'));
	}
}
