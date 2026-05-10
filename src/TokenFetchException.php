<?php

declare(strict_types=1);

namespace Cbox\CboxIdTokens;

use RuntimeException;

/**
 * Thrown when CboxIdTokens cannot mint or refresh a service token.
 * Wraps the underlying HTTP / network error with enough context
 * for the caller to log and decide whether to retry.
 */
final class TokenFetchException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?int $httpStatus = null,
        public readonly ?string $upstreamError = null,
        public readonly ?string $audience = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
