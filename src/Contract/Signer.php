<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Contract;

use Sopsy\WebPush\Exception\SignerException;

interface Signer
{
    /**
     * Signer constructor.
     *
     * @param string $privateKey Server private key in PEM format
     */
    public function __construct(string $privateKey);

    /**
     * Returns the algorithm name used by the signer to be used in the JWT header.
     *
     * @return string
     */
    public function algorithmName(): string;

    /**
     * Signs the JWT header and payload with a supported algorithm and
     * returns the signature part of the JWT.
     *
     * @param string $jwtHeader JSON-encoded header of the JWT
     * @param string $jwtPayload JSON-encoded payload of the JWT
     * @return string JWT signature
     * @throws SignerException if an error occurs while signing the JWT
     */
    public function signature(string $jwtHeader, string $jwtPayload): string;
}