<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Contract;

use Sopsy\WebPush\Exception\SignerException;

interface Jwt
{
    /**
     * Returns a signed Jwt string.
     *
     * @return string Encoded and signed Jwt
     * @throws SignerException if signing the Jwt fails
     */
    public function signedJwt(): string;
}