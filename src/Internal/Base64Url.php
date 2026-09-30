<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha\Internal;

/**
 * Base64url without padding (RFC 4648 §5)
 * @internal
 */
final class Base64Url
{
	private const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

	public static function encode(string $bytes): string
	{
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}

	/**
	 * @param string $text
	 * @return string|null null unless the text is the canonical encoding of some bytes: no padding, no other character,
	 * unused trailing bits set to zero
	 */
	public static function decode(string $text): ?string
	{
		if (strspn($text, self::ALPHABET) !== strlen($text) || strlen($text) % 4 === 1) {
			return null;
		}
		$bytes = base64_decode(strtr($text, '-_', '+/'), true);
		// base64_decode() also accepts "QR" for "A": only the canonical form gives back the same text
		if ($bytes === false || self::encode($bytes) !== $text) {
			return null;
		}
		return $bytes;
	}
}
