<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Tests\Unit;

use Karewan\KnCaptcha\KnCaptcha;
use Karewan\KnCaptcha\Result;
use Karewan\KnCaptcha\Store;
use Karewan\KnCaptcha\Tests\DataProvider;
use Karewan\KnCaptcha\Tests\TestCase;

/**
 * Solutions computed by the JavaScript solver (tests/vectors.json of the KnCaptcha repository, `pnpm vectors`)
 */
final class VectorsTest extends TestCase
{
	/**
	 * @return array<string, array{array{name: string, secret: string, scope: string, now: int, solution: string, expected: string}}>
	 */
	public static function vectors(): array
	{
		$vectors = json_decode((string) file_get_contents(__DIR__ . '/../Fixtures/vectors.json'), true, flags: JSON_THROW_ON_ERROR);
		$cases = [];
		foreach ($vectors as $vector) {
			$cases[$vector['name']] = [$vector];
		}
		return $cases;
	}

	/**
	 * @param array{name: string, secret: string, scope: string, now: int, solution: string, expected: string} $vector
	 */
	#[DataProvider('vectors')]
	public function testVector(array $vector): void
	{
		$captcha = new KnCaptcha($vector['secret'], Store::memory(), clock: static fn (): int => $vector['now']);
		$this->assertSame(Result::from($vector['expected']), $captcha->check($vector['solution'], $vector['scope']));
	}
}
