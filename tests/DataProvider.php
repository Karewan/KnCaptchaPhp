<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Tests;

use Attribute;

/**
 * The test method runs once per case returned by the named static method: [name => [args...]]
 */
#[Attribute(Attribute::TARGET_METHOD)]
final readonly class DataProvider
{
	public function __construct(public string $method)
	{
	}
}
