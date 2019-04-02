<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Contract;

use Sopsy\WebPush\Exception\KeyCreateException;

interface KeyFactory
{
    /**
     * Get the private key for the newly created key.
     *
     * @return string Private key in PEM format
     * @throws KeyCreateException if the key creation fails
     */
    public function privateKey(): string;

    /**
     * Get the public key for the newly created key.
     *
     * @return string Public key in PEM format
     * @throws KeyCreateException if the key creation fails
     */
    public function publicKey(): string;
}