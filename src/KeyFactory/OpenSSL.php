<?php
declare(strict_types=1);

namespace Sopsy\WebPush\KeyFactory;

use Sopsy\WebPush\Exception\KeyCreateException;
use Sopsy\WebPush\KeyFactory;
use RuntimeException;
use InvalidArgumentException;

class OpenSSL implements KeyFactory
{
    // Define key types
    public const KEYTYPE_EC = 1;

    // Curve types
    public const CURVE_P256 = 1;

    protected $keyType;
    protected $curve;
    protected $privateKey;
    protected $publicKey;

    /**
     * Only function of this is to check that the openssl PHP extension is loaded.
     */
    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('OpenSSL extension is not loaded');
        }
    }

    public function setParameters(int $keyType, int $params = 0): void
    {
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

    public function createKey(): void
    {
        $key = openssl_pkey_new([
            'curve_name' => $this->curve,
            'private_key_type' => $this->keyType,
        ]);
        if (!$key) {
            throw new KeyCreateException('Could not create a key');
        }

        $details = openssl_pkey_get_details($key);
        if (!$details) {
            throw new RuntimeException('Could not get details for the new key');
        }

        $private = openssl_pkey_export($key, $privateKey);
        if (!$private) {
            throw new RuntimeException('Could not export the private key');
        }

        openssl_pkey_free($key);

        $this->privateKey = $privateKey;
        $this->publicKey = $details['key'];
    }

    public function getPrivateKey(): string
    {
        if (empty($this->privateKey)) {
            throw new InvalidArgumentException('Key not created');
        }

        return $this->privateKey;
    }

    public function getPublicKey(): string
    {
        if (empty($this->publicKey)) {
            throw new InvalidArgumentException('Key not created');
        }

        return $this->publicKey;
    }
}