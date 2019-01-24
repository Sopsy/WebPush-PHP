<?php
declare(strict_types=1);

namespace Sopsy\WebPush;

use InvalidArgumentException;
use Sopsy\WebPush\Exception\KeyFileException;

class KeyConverter
{
    // DER header - for secp256r1 it's always this and we don't need anything else for Web Push
    protected static $derHeader = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";

    /**
     * OpenSSL requires a header for the key to be usable, the header contains e.g. the curve used.
     * Note: NIST P-256, secp256r1 and prime256v1 are all the same curve.
     * secp256k1 on the other hand is a different beast. Do not confuse.
     *
     * @param string $key 65 byte long public key
     * @return string PEM formatted secp256r1 public key for OpenSSL
     */
    public static function p256PublicKeyToPem(string $key): string
    {
        if (mb_strpos($key, "\x04", 0,  '8bit') !== 0) {
            throw new InvalidArgumentException('Only uncompressed keys are supported (starting with 0x04)');
        }

        $dataLength = mb_strlen($key, '8bit');

        // secp256r1 should always be 64 bytes of data + 1 byte of header
        if ($dataLength !== 65) {
            throw new InvalidArgumentException('Invalid key, wrong length');
        }

        $key = static::$derHeader . $key;

        $key = chunk_split(base64_encode($key), 64, "\n");
        $key = "-----BEGIN PUBLIC KEY-----\n" . $key . "-----END PUBLIC KEY-----\n";

        return $key;
    }

    /**
     * Gets the public key from a private key in PEM format
     *
     * @param string $privateKey PEM private key
     * @return string PEM public key
     */
    public static function getPublicFromPrivate(string $privateKey): string
    {
        $key = openssl_pkey_get_private($privateKey);
        $publicKey = false;
        if ($key) {
            $publicKey = openssl_pkey_get_details($key);
        }

        if (!$publicKey || empty($publicKey['key'])) {
            throw new InvalidArgumentException('Invalid private key, maybe not in PEM format');
        }

        return $publicKey['key'];
    }

    /**
     * Gets the public key from a private key in PEM format and returns it serialized to bytes
     *
     * @param string $privateKey PEM private key
     * @return string PEM public key
     * @throws KeyFileException if the conversion of PEM to DER fails
     */
    public static function unserializePublicFromPrivate(string $privateKey): string
    {
        $publicKey = static::getPublicFromPrivate($privateKey);
        return static::unserializePublic($publicKey);
    }

    /**
     * Returns the public key serialized to bytes
     *
     * @param string $publicKey PEM public key
     * @return string PEM public key
     * @throws KeyFileException if the conversion of PEM to DER fails
     */
    public static function unserializePublic(string $publicKey): string
    {
        $publicKey = static::pem2der($publicKey);
        return static::stripDerHeader($publicKey);
    }

    /**
     * Strips the DER header from a key string
     *
     * @param string $key DER formatted secp256r1 key
     * @return string Key without the DER header
     */
    public static function stripDerHeader(string $key): string
    {
        $headerLength = mb_strlen(static::$derHeader, '8bit');

        if (mb_strpos($key, static::$derHeader, 0, '8bit') !== 0) {
            throw new InvalidArgumentException('Invalid DER file, not secp256r1 header.');
        }

        return mb_substr($key, $headerLength, null, '8bit');
    }

    /**
     * A stupid function which handles only P256 DER signature file conversion to a plain 64 byte signature
     * to be used when signing a JWT.
     *
     * @param string $key
     * @return string signature in binary format
     */
    public static function stripDerSignatureHeaders(string $key): string
    {
        // We have no interest in the first 2 bytes (ASN.1 tag id and sequence length)
        $key = mb_substr($key, 2, null, '8bit');

        // Get R length from its header (second byte)
        $rLen = ord(mb_substr($key, 1, 1, '8bit'));

        // Get R from the signature (start = from end of R header)
        $start = 2;
        if ($rLen === 33) {
            // If length is 33, the first data byte is just a 0x00 padding, ignore it
            ++$start;
        }
        $r = mb_substr($key, $start, 32, '8bit');

        // Get S length from its header (second byte, R header + R + S header first byte)
        $sLen = ord(mb_substr($key, 2 + $rLen + 1, 1, '8bit'));

        // Get S from the signature (R header + R + S header)
        $start = 2 + $rLen + 2;
        if ($sLen === 33) {
            // If length is 33, the first data byte is just a 0x00 padding, ignore it
            ++$start;
        }

        $s = mb_substr($key, $start, null, '8bit');

        return $r . $s;
    }

    /**
     * Converts a PEM key to a DER key.
     *
     * @param string $pem key in PEM format
     * @return string key in DER format
     * @throws KeyFileException if the conversion fails
     */
    public static function pem2der(string $pem): string
    {
        $begin = 'KEY-----';
        $end = '-----END';

        $pem = mb_substr($pem, mb_strpos($pem, $begin, 0, '8bit') + mb_strlen($begin, '8bit'), null, '8bit');
        $pem = mb_substr($pem, 0, mb_strpos($pem, $end, 0, '8bit'), '8bit');
        $der = base64_decode($pem);

        if (!$der) {
            throw new KeyFileException('Could not convert PEM to DER. Possibly invalid key.');
        }

        return $der;
    }
}