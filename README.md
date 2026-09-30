# KnCaptchaPhp

Server side of [KnCaptcha](https://github.com/Karewan/KnCaptcha) for PHP 8.3+: issues the challenges of the "I'm not a
robot" widget and checks their solutions, memory-hard Equihash proofs of work.

- **Stateless challenges**: an HMAC over a random salt, the difficulty and the expiry. About 1 µs, nothing stored.
- **Cheap verification**: an HMAC and 2^k + 2 SHA-256 per proof, about 25 µs with the default difficulty.
- **Your store, as a closure**: the only state is the list of used challenges, kept by a `fn (string $id, int $ttl): bool`
  of yours (Redis, APCu, Memcached, a table...). Only valid solutions reach it.
- **No dependency**: `ext-hash` only, any framework or none.

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [The store closure](#the-store-closure)
- [Difficulty](#difficulty)
- [Scope](#scope)
- [Results](#results)
- [Performance](#performance)
- [Security notes](#security-notes)
- [Protocol](#protocol)
- [Tests](#tests)
- [License](#license)

## Installation

PHP 8.3+, 64-bit.

```shell
composer require karewan/kncaptcha
```

## Quick start

```php
use Karewan\KnCaptcha\KnCaptcha;
use Karewan\KnCaptcha\Store;

$captcha = new KnCaptcha(
	secret: $config['captcha_secret'], // at least 32 bytes: bin2hex(random_bytes(32))
	markUsed: Store::redis($redis),
);

// GET /captcha/challenge: what the widget fetches
header('Content-Type: application/json');
header('Cache-Control: no-store');
echo json_encode(['challenge' => $captcha->createChallenge('login')]);

// POST /login: the widget put the solution in the "kncaptcha" field
if (!$captcha->verify($_POST['kncaptcha'] ?? '', 'login')) {
	http_response_code(422);
	exit;
}
```

On the page, `new KnCaptcha('#captcha', { challenge: '/captcha/challenge' })` (see the
[widget documentation](https://github.com/Karewan/KnCaptcha)). A solution passes once: after a refused login, the page
calls `captcha.reset()` to get a new one.

[`examples/server.php`](examples/server.php) is a complete endpoint for the built-in server:
`php -S 127.0.0.1:8081 examples/server.php`.

Constructor:

| Parameter    | Type                          | Default            | Description                                                          |
|--------------|-------------------------------|--------------------|----------------------------------------------------------------------|
| `secret`     | `string`                      | required           | HMAC key, 32 bytes at least. Changing it invalidates pending challenges |
| `markUsed`   | `Closure(string, int): bool`  | required           | See [The store closure](#the-store-closure)                         |
| `difficulty` | `Difficulty`                  | `new Difficulty()` | Default difficulty of `createChallenge()`                            |
| `ttl`        | `int`                         | `600`              | Default lifetime of a challenge (s): time to solve it and submit the form |
| `clock`      | `?Closure(): int`             | `time(...)`        | Current Unix time, for the tests                                     |

Methods:

| Method                                                           | Returns  | Description                                          |
|------------------------------------------------------------------|----------|------------------------------------------------------|
| `createChallenge(string $scope = '', ?Difficulty $difficulty = null, ?int $ttl = null)` | `string` | Challenge for the widget, 87 characters |
| `verify(string $solution, string $scope = '')`                   | `bool`   | Checks the solution and marks it as used             |
| `check(string $solution, string $scope = '')`                    | `Result` | Same, with the reason of a refusal                   |

## The store closure

`markUsed` receives the id of a challenge whose solution is valid (32 hexadecimal characters) and the seconds until its
expiry. It must remember the id for that time and return `true` only if it did not know it yet, **atomically**: two
requests with the same solution at the same time must not both get `true`.

```php
// phpredis
markUsed: fn (string $id, int $ttl): bool => $redis->set("kncaptcha:{$id}", 1, ['nx', 'ex' => $ttl]) === true,

// Laravel
markUsed: fn (string $id, int $ttl): bool => Cache::add("kncaptcha:{$id}", 1, $ttl),

// Symfony cache: not atomic, use a lock or one of the stores below
```

`Store` has ready-made closures:

| Factory                                              | Store                                                             |
|------------------------------------------------------|-------------------------------------------------------------------|
| `Store::redis(\Redis $redis, string $prefix)`        | phpredis or Relay: `SET key 1 NX EX ttl`                          |
| `Store::predis(ClientInterface $predis, string $prefix)` | Predis                                                        |
| `Store::apcu(string $prefix)`                        | APCu: one server only                                             |
| `Store::memcached(\Memcached $memcached, string $prefix)` | `Memcached::add()`                                           |
| `Store::pdo(\PDO $pdo, string $table)`               | A table with the id as primary key, expired rows deleted on 1 call in 100 |
| `Store::memory()`                                    | Process memory: tests and long-running processes only             |

Table of `Store::pdo()`:

```sql
-- MySQL / MariaDB
CREATE TABLE kncaptcha_used (id CHAR(32) NOT NULL PRIMARY KEY, expires_at INT UNSIGNED NOT NULL, KEY (expires_at));
-- PostgreSQL / SQLite
CREATE TABLE kncaptcha_used (id CHAR(32) NOT NULL PRIMARY KEY, expires_at INTEGER NOT NULL);
```

The exceptions of the store go up to the caller: a store that is down makes the verification fail loudly, it never
lets solutions through twice. A closure that returns something else than a bool throws an `UnexpectedValueException`.

## Difficulty

The browser runs Equihash(n, k) until it finds, for each of the `proofs` proofs, a solution whose hash starts with
`bits` zero bits. A run of Equihash(96, 5) takes about 40 ms on a desktop core, 150 to 250 ms on a phone core, holds
about 10 MB, and gives about 2 solutions; the widget uses up to 8 cores.

| Difficulty                          | Runs | Desktop, 8 cores | Phone (estimate) |
|-------------------------------------|-----:|-----------------:|-----------------:|
| `Difficulty::low()`                 |   ~8 |          < 0.1 s |           ~0.5 s |
| `Difficulty::medium()`, the default |  ~32 |           ~0.2 s |            1–2 s |
| `Difficulty::high()`                | ~128 |           ~0.5 s |            4–8 s |
| `new Difficulty(bits: 9)`           | ~512 |           ~1.3 s |          15–30 s |

Each bit doubles the work. `proofs` (2 by default) makes the solving time more regular, each proof adds 34 hashes to the
verification. `n` and `k` change the puzzle itself (memory `2^(n/(k+1)+1)` hashes, verification `2^k` hashes); keep
the default unless you measured something else. The difficulty is chosen per challenge, for example from the failed
attempts:

```php
$failures = $attempts->count($ip);
$difficulty = match (true) {
	$failures < 5 => Difficulty::low(),
	$failures < 10 => Difficulty::medium(),
	default => Difficulty::high(),
};
echo json_encode(['challenge' => $captcha->createChallenge('login', $difficulty)]);
```

## Scope

The scope binds a challenge to its use: `createChallenge('login')` and `verify($solution, 'login')`. A solution of the
contact form does not open the login. It is part of the HMAC, never sent. Adding the IP address
(`'login:' . $ip`) also stops solutions computed elsewhere, but refuses a user whose address changes between the
challenge and the submission (mobile networks).

## Results

`check()` tells why a solution is refused, for the logs and the statistics. Never show the detail to the user.

| `Result`       | Meaning                                                  |
|----------------|----------------------------------------------------------|
| `Valid`        | Accepted, now used                                       |
| `Malformed`    | Not a solution: format, part missing, too long           |
| `BadSignature` | Not issued by this server, with this secret and scope    |
| `Expired`      | The lifetime of the challenge is over                    |
| `InvalidProof` | A proof of work is wrong                                 |
| `Replayed`     | Already used                                             |

## Performance

`composer bench`, PHP 8.5, OPcache:

| Operation                                        | Time     |
|--------------------------------------------------|----------|
| `createChallenge()`                              |  ~1 µs   |
| `check()`, default difficulty (2 proofs)         |  ~25 µs  |
| `check()`, bad signature                         |  ~2 µs   |
| `check()`, malformed                             |  ~1 µs   |

Wrong solutions are refused before the store: an attacker can neither make the server work nor fill the store without
solving the puzzles.

## Security notes

- Keep the secret out of the code and of the repository. `var_dump($captcha)` does not show it.
- The difficulty, the expiry and the parameters are signed: the browser cannot change them.
- A solution passes once, until the expiry of its challenge (then it is refused as expired).
- A proof of work does not tell a human from a bot, it makes each attempt cost CPU time and memory. Keep the rate limits
  and the account lockouts.

## Protocol

[PROTOCOL.md](PROTOCOL.md) describes the challenge, the solution and the verification byte by byte, for a server in
another language.

## Tests

```shell
composer test    # custom runner, no dependency: php tests/run.php [filter]
composer bench
```

`tests/Fixtures/vectors.json` holds solutions computed by the JavaScript solver (`pnpm vectors` in the KnCaptcha
repository): both libraries check the same cases. `tests/Support/Solver.php` is a plain PHP solver, for round trips
with small parameters. The Redis and Memcached stores are tested when `REDIS_HOST` or `MEMCACHED_HOST` is set, APCu with
`apc.enable_cli=1`.

## License

MIT, see [LICENSE.txt](LICENSE.txt).
