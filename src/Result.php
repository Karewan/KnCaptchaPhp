<?php

declare(strict_types=1);

namespace Karewan\KnCaptcha;

/**
 * Outcome of KnCaptcha::check(). Only Valid lets the request through: the other cases are for the logs and the
 * statistics, never shown to the user.
 */
enum Result: string
{
	case Valid = 'valid';

	/** Not a solution: wrong format, part missing, too long */
	case Malformed = 'malformed';

	/** Not issued by this server, with this secret and this scope */
	case BadSignature = 'bad_signature';

	/** The challenge lifetime is over */
	case Expired = 'expired';

	/** A proof of work is wrong */
	case InvalidProof = 'invalid_proof';

	/** The challenge was already used */
	case Replayed = 'replayed';
}
