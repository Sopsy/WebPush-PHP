<?php
declare(strict_types=1);

namespace Sopsy\WebPush;

use Sopsy\WebPush\Exception\KeyCreateException;

interface KeyFactory
{
    /**
     * Set parameters for the new key pair, e.g. key type.
     *
     * @param int $keyType Key type, implementation specific
     * @param int $params Implementation specific key parameters, usually bitwise flags
     * @throws KeyCreateException For invalid keyType or params
     */
    public function setParameters(int $keyType, int $params = 0): void;

    /**
     * Create a new key pair.
     *
     * @throws KeyCreateException If creation of the key fails
     */
    public function createKey(): void;

    /**
     * Get the private key for the newly created key.
     *
     * @return string Private key in PEM format
     */
    public function getPrivateKey(): string;

    /**
     * Get the public key for the newly created key.
     *
     * @return string Public key in PEM format
     */
    public function getPublicKey(): string;
}