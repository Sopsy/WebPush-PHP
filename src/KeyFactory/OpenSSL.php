<?php
declare(strict_types=1);

namespace Sopsy\WebPush\KeyFactory;

use Sopsy\WebPush\Exception\KeyCreateException;
use Sopsy\WebPush\Contract\KeyFactory;

final class OpenSSL implements KeyFactory
{
    // Key types
    public const KEYTYPE_EC = 1;

    // Curve types
    public const CURVE_P256 = 1;

    /* @var int */
    private $keyType;
    /* @var string */
    private $curve;
    /* @var string */
    private $privateKey;
    /* @var string */
    private $publicKey;

    /**
     * Check that the openssl PHP extension is loaded and set parameters for the new key pair, e.g. key type.
     *
     * @param int $keyType Key type, implementation specific
     * @param int $params Implementation specific key parameters, usually bitwise flags
     * @throws KeyCreateException For invalid keyType or params
     */
    public function __construct(int $keyType, int $params = 0)
    {
        if (!extension_loaded('openssl')) {
            throw new KeyCreateException('OpenSSL extension is not loaded');
        }

        if ($keyType === static::KEYTYPE_EC) {
            $this->keyType = OPENSSL_KEYTYPE_EC;
        } else {
            throw new KeyCreateException('Unsupported key type: ' . $keyType);
        }

        $this->curve = 'prime256v1';
        if ($params & static::CURVE_P256) {
            $this->curve = 'prime256v1';
        }
    }

    public function privateKey(): string
    {
        $this->createKey();

        return $this->privateKey;
    }

    public function publicKey(): string
    {
        $this->createKey();

        return $this->publicKey;
    }

    /**
     * @throws KeyCreateException if the key creation fails
     */
    private function createKey(): void
    {
        if (!empty($this->privateKey)) {
            return;
        }

        $key = openssl_pkey_new([
            'curve_name' => $this->curve,
            'private_key_type' => $this->keyType,
        ]);
        if (!$key) {
            throw new KeyCreateException('Could not create a key');
        }

        $details = openssl_pkey_get_details($key);
        if (!$details) {
            throw new KeyCreateException('Could not get details for the new key');
        }

        $private = openssl_pkey_export($key, $privateKey);
        if (!$private) {
            throw new KeyCreateException('Could not export the private key');
        }

        openssl_pkey_free($key);

        $this->privateKey = $privateKey;
        $this->publicKey = $details['key'];
    }
}