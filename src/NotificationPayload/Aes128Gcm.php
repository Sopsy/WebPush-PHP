<?php
declare(strict_types=1);

namespace Sopsy\WebPush\NotificationPayload;

use RuntimeException;
use InvalidArgumentException;
use Sopsy\WebPush\Exception\KeyCreateException;
use Sopsy\WebPush\Exception\KeyFileException;
use Sopsy\WebPush\KeyConverter;
use Sopsy\WebPush\KeyFactory;
use Sopsy\WebPush\NotificationPayload;

class Aes128Gcm implements NotificationPayload
{
    protected $payload;
    protected $receiverPublicKey;
    protected $authKey;
    protected $privateKey;
    protected $publicKey;

    protected $encryptedPayload;
    protected $contentHeader;
    protected $encryptionSalt;

    // 4096 bytes - content header (86 bytes) - AEAD authentication tag (16 bytes) - padding delimiter (1 byte)
    protected const PAYLOAD_MAX_LENGTH = 3993;

    /**
     * Aes128Gcm constructor.
     *
     * @param KeyFactory $keyFactory
     * @param string $authKey Auth key from the push subscription, Base64Url decoded
     * @param string $receiverPublicKey Public key from the push subscription in PEM format
     * @throws KeyCreateException
     */
    public function __construct(
        KeyFactory $keyFactory,
        string $authKey,
        string $receiverPublicKey
    )
    {
        $this->authKey = $authKey;
        $this->receiverPublicKey = $receiverPublicKey;

        // Create a new ECDH key pair
        $keyFactory->setParameters(KeyFactory\OpenSSL::KEYTYPE_EC, KeyFactory\OpenSSL::CURVE_P256);
        $keyFactory->createKey();
        $this->privateKey = $keyFactory->getPrivateKey();
        $this->publicKey = $keyFactory->getPublicKey();

        // Polyfill for PHP7.2 (this new function in PHP7.3 is exactly what we need)
        if (!function_exists('openssl_pkey_derive')) {
            function openssl_pkey_derive($peer_pub_key, $priv_key, $keylen = null) {

                if ($keylen !== null) {
                    throw new RuntimeException('Key length attribute is not supported');
                }

                $result = shell_exec('/bin/bash -c "/usr/bin/openssl pkeyutl -derive -inkey <(echo -n ' . escapeshellarg($priv_key) . ') '
                    . '-peerkey <(echo -n ' . escapeshellarg($peer_pub_key) . ')"');

                if ($result === null) {
                    return false;
                }

                return $result;
            }
        }
    }

    public function set(string $payload): void
    {
        if (strlen($payload) > static::PAYLOAD_MAX_LENGTH) {
            throw new InvalidArgumentException(sprintf('Payload too large for Web Push, max size is %d bytes', static::PAYLOAD_MAX_LENGTH));
        }

        $this->payload = $payload;
    }

    public function getContentType(): string
    {
        return 'application/octet-stream';
    }

    public function getContentEncoding(): string
    {
        return 'aes128gcm';
    }

    public function getContentLength(): int
    {
        return mb_strlen($this->encryptedPayload, '8bit');
    }

    /**
     * Get the encrypted payload, returns the encrypted payload
     *
     * @return string aes-128-gcm encrypted payload with padding
     * @throws RuntimeException in case aes-128-gcm is not supported on this install
     * @throws KeyFileException
     */
    public function get(): string
    {
        if (!empty($this->encryptedPayload)) {
            return $this->encryptedPayload;
        }

        return $this->encrypt();
    }

    /**
     * Encrypt the payload with AES-128-GCM
     *
     * @return string encrypted payload
     * @throws RuntimeException in case aes-128-gcm is not supported on this install
     * @throws KeyFileException
     */
    protected function encrypt(): string
    {
        $cipher = 'aes-128-gcm';

        if (!in_array($cipher, openssl_get_cipher_methods(), true)) {
            throw new RuntimeException($cipher . ' is not supported by this OpenSSL install.');
        }

        // Derive all needed parameters for AES-128-GCM encryption
        try {
            $this->encryptionSalt = random_bytes(16);
        } catch (\Exception $e) {
            throw new RuntimeException('Could not generate a cryptographically secure salt.');
        }
        $ikm = $this->getIkm();
        $nonce = hash_hkdf('sha256', $ikm, 12, 'Content-Encoding: nonce' . "\x00", $this->encryptionSalt);
        $contentEncryptionKey = hash_hkdf('sha256', $ikm, 16, 'Content-Encoding: aes128gcm' . "\x00", $this->encryptionSalt);

        // Add padding to prevent figuring out the content by its size
        $this->payload .= $this->getPadding(static::PAYLOAD_MAX_LENGTH - mb_strlen($this->payload, '8bit'));

        // Encrypt
        $encrypted = openssl_encrypt($this->payload, $cipher, $contentEncryptionKey, OPENSSL_RAW_DATA, $nonce, $tag);

        // Payload = Header + encrypted content + AEAD authentication tag
        $this->encryptedPayload = $this->getContentHeader() . $encrypted . $tag;

        return $this->encryptedPayload;
    }

    /**
     * Get padding for plaintext payload.
     * The separator (0x02) is always needed in the payload. The number of NULL bytes can vary.
     *
     * @param int $length Padding length, payload usually padded to max size for security
     * @return string Padding string which should be concatenated to the plaintext payload
     */
    protected function getPadding(int $length): string
    {
        return "\x02" . str_repeat("\x00", $length);
    }

    /**
     * Get the Input Keying Material (IKM) used when deriving the content encryption key.
     * See RFC 8291, section 3.3 for details
     *
     * @return string HKDF derived key
     * @throws KeyFileException if the conversion of a PEM key to DER fails - should never happen
     */
    protected function getIkm(): string
    {
        $sharedSecret = openssl_pkey_derive($this->receiverPublicKey, $this->privateKey);
        $publicKey = KeyConverter::unserializePublic($this->publicKey);
        $receiverPublicKey = KeyConverter::unserializePublic($this->receiverPublicKey);
        $info = 'WebPush: info' . "\x00" . $receiverPublicKey . $publicKey;

        return hash_hkdf('sha256', $sharedSecret, 32, $info, $this->authKey);
    }

    /**
     * Get the AES-128-GCM header, which includes necessary data for the receiver to decrypt the payload.
     * See RFC 8188, section 2.1 for details
     *
     * @return string Content header string in binary format, prepended to the encrypted payload
     * @throws KeyFileException if the conversion of a PEM key to DER fails - should never happen
     */
    protected function getContentHeader(): string
    {
        $publicKey = KeyConverter::unserializePublic($this->publicKey);

        $this->contentHeader = $this->encryptionSalt . pack('N', 4096)
            . chr(mb_strlen($publicKey, '8bit')) . $publicKey;

        return $this->contentHeader;
    }
}