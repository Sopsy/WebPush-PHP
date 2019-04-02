<?php
declare(strict_types=1);

namespace Sopsy\WebPush\MessagePayload;

use RuntimeException;
use Sopsy\WebPush\Exception\KeyCreateException;
use Sopsy\WebPush\Exception\KeyFileException;
use Sopsy\WebPush\Exception\PayloadException;
use Sopsy\WebPush\KeyConverter;
use Sopsy\WebPush\Contract\KeyFactory;
use Sopsy\WebPush\Contract\MessagePayload;

final class Aes128Gcm implements MessagePayload
{
    /* @var string */
    private $payload;
    /* @var string */
    private $receiverPublicKey;
    /* @var string */
    private $authKey;
    /* @var string */
    private $privateKey;
    /* @var string */
    private $publicKey;

    /* @var string */
    private $encryptedPayload;
    /* @var string */
    private $contentHeader;
    /* @var string */
    private $encryptionSalt;

    // 4096 bytes - content header (86 bytes) - AEAD authentication tag (16 bytes) - padding delimiter (1 byte)
    private const PAYLOAD_MAX_LENGTH = 3993;

    /**
     * Aes128Gcm constructor.
     *
     * @param \Sopsy\WebPush\Contract\KeyFactory $keyFactory
     * @param string $authKey Auth key from the push subscription, Base64Url decoded
     * @param string $receiverPublicKey Public key from the push subscription in PEM format
     * @param string $payload Payload to be encrypted
     * @throws KeyCreateException
     * @throws PayloadException
     */
    public function __construct(
        KeyFactory $keyFactory,
        string $authKey,
        string $receiverPublicKey,
        string $payload
    )
    {
        if (strlen($payload) > static::PAYLOAD_MAX_LENGTH) {
            throw new PayloadException(sprintf('Payload too large for Web Push, max size is %d bytes', static::PAYLOAD_MAX_LENGTH));
        }

        $this->payload = $payload;
        $this->authKey = $authKey;
        $this->receiverPublicKey = $receiverPublicKey;

        // Create a new ECDH key pair
        $this->privateKey = $keyFactory->privateKey();
        $this->publicKey = $keyFactory->publicKey();
    }

    public function contentType(): string
    {
        return 'application/octet-stream';
    }

    public function contentEncoding(): string
    {
        return 'aes128gcm';
    }

    public function contentLength(): int
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
    public function payload(): string
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
    private function encrypt(): string
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
        $ikm = $this->ikm();
        $nonce = hash_hkdf('sha256', $ikm, 12, 'Content-Encoding: nonce' . "\x00", $this->encryptionSalt);
        $contentEncryptionKey = hash_hkdf('sha256', $ikm, 16, 'Content-Encoding: aes128gcm' . "\x00", $this->encryptionSalt);

        // Add padding to prevent figuring out the content by its size
        $this->payload .= $this->padding(static::PAYLOAD_MAX_LENGTH - mb_strlen($this->payload, '8bit'));

        // Encrypt
        $encrypted = openssl_encrypt($this->payload, $cipher, $contentEncryptionKey, OPENSSL_RAW_DATA, $nonce, $tag);

        // Payload = Header + encrypted content + AEAD authentication tag
        $this->encryptedPayload = $this->contentHeader() . $encrypted . $tag;

        return $this->encryptedPayload;
    }

    /**
     * Get padding for plaintext payload.
     * The separator (0x02) is always needed in the payload. The number of NULL bytes can vary.
     *
     * @param int $length Padding length, payload usually padded to max size for security
     * @return string Padding string which should be concatenated to the plaintext payload
     */
    private function padding(int $length): string
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
    private function ikm(): string
    {
        $sharedSecret = openssl_pkey_derive($this->receiverPublicKey, $this->privateKey);
        $publicKey = KeyConverter::unserializePublicPem($this->publicKey);
        $receiverPublicKey = KeyConverter::unserializePublicPem($this->receiverPublicKey);
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
    private function contentHeader(): string
    {
        $publicKey = KeyConverter::unserializePublicPem($this->publicKey);

        return $this->encryptionSalt . pack('N', 4096)
            . chr(mb_strlen($publicKey, '8bit')) . $publicKey;
    }
}