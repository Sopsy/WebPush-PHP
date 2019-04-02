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
     * Returns the algorithm name used by the signer to be used in the Jwt header.
     *
     * @return string
     */
    public function algorithmName(): string;

    /**
     * Signs the Jwt header and payload with a supported algorithm and
     * returns the signature part of the Jwt.
     *
     * @param string $jwtHeader JSON-encoded header of the Jwt
     * @param string $jwtPayload JSON-encoded payload of the Jwt
     * @return string Jwt signature
     * @throws SignerException if an error occurs while signing the Jwt
     */
    public function signature(string $jwtHeader, string $jwtPayload): string;
}