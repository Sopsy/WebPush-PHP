<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Contract;

use Sopsy\WebPush\Exception\SignerException;

interface Jwt
{
    /**
     * Returns a signed JWT string.
     *
     * @return string Encoded and signed JWT
     * @throws SignerException if signing the JWT fails
     */
    public function signedJwt(): string;
}