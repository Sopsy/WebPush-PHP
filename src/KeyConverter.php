<?php
declare(strict_types=1);

namespace Sopsy\WebPush;

use function base64_decode;
use function base64_encode;
use function chunk_split;
use InvalidArgumentException;
use function ltrim;
use function mb_strlen;
use function mb_strpos;
use function mb_substr;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function ord;
use Sopsy\WebPush\Exception\KeyFileException;
use function str_pad;
use const STR_PAD_LEFT;

final class KeyConverter
{
    // DER header - for secp256r1 it's always this and we don't need anything else for Web Push
    private static $derHeader = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";

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
            throw new InvalidArgumentException('Invalid private key, maybe not in PEM format (' . openssl_error_string() . ')');
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
        return static::unserializePublicPem($publicKey);
    }

    /**
     * Returns the public key serialized to bytes from a PEM key
     *
     * @param string $publicKey PEM public key
     * @return string raw public key in binary format
     * @throws KeyFileException if the conversion of PEM to DER fails
     * @throws InvalidArgumentException if the string does not contain a valid secp256r1 key
     */
    public static function unserializePublicPem(string $publicKey): string
    {
        $publicKey = static::pem2der($publicKey);
        return static::unserializePublicDer($publicKey);
    }

    /**
     * Returns the public key serialized to bytes from a DER key
     *
     * @param string $publicKey DER public key
     * @return string raw public key in binary format
     * @throws InvalidArgumentException if the string is not a valid DER secp256r1 key
     */
    public static function unserializePublicDer(string $publicKey): string
    {
        return static::stripDerHeader($publicKey);
    }

    /**
     * Returns the public key serialized to bytes from a base64 encoded DER key
     *
     * @param string $publicKey base64 encoded DER public key
     * @return string raw public key in binary format
     * @throws InvalidArgumentException if the string is not a valid DER secp256r1 key
     */
    public static function unserializePublicBase64(string $publicKey): string
    {
        $publicKey = base64_decode($publicKey);
        return static::unserializePublicDer($publicKey);
    }

    /**
     * Strips the DER header from a key string
     *
     * @param string $key DER formatted secp256r1 key
     * @return string Key without the DER header
     * @throws InvalidArgumentException if the string is not a valid DER secp256r1 key
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
     * A stupid function which handles only P256 DER signature file conversion to a raw 64 byte signature
     * to be used when signing a JWT.
     *
     * @param string $signature DER encoded P256 signature
     * @return string signature in binary format
     */
    public static function derP256SignatureToRaw(string $signature): string
    {
        // Needs to be a DER with compound structure (first byte needs to be 0x02)
        if ($signature[0] !== "\x30") {
            throw new InvalidArgumentException('Invalid DER signature, not a compound structure (0x30).');
        }

        // Sequence for P256 signature should be between 4 and 70 bytes
        $sequenceLength = ord($signature[1]);
        if ($sequenceLength < 4 || $sequenceLength > 70) {
            throw new InvalidArgumentException('Invalid DER signature, sequence length is not 4-70 bytes.');
        }

        // ---- Get R ----
        // R needs to be integer (third byte needs to be 0x02)
        if ($signature[2] !== "\x02") {
            throw new InvalidArgumentException('Invalid DER signature, R is not an integer (0x02).');
        }

        // Get R length from its header (fourth byte)
        $rLen = ord($signature[3]);

        // If length is 33, the first data byte should be 0x00 to indicate an unsigned int
        if ($rLen === 33 && $signature[4] !== "\x00") {
            throw new InvalidArgumentException('Invalid DER signature, R length is 33 bytes and its first byte is not 0x00.');
        }

        // Get R from the signature
        $r = static::getSignaturePart($signature, 4, $rLen);

        // ---- Get S ----
        // S needs to be integer
        if ($signature[4 + $rLen] !== "\x02") {
            throw new InvalidArgumentException('Invalid DER signature, S is not an integer (0x02).');
        }

        // Get S length from its header (skip DER and R header + R + S header first byte)
        $sLen = ord(mb_substr($signature, 4 + $rLen + 1, 1, '8bit'));

        // Get S from the signature (skip R header + R + S header)
        $sFirstByte = 4 + $rLen + 2;
        if ($sLen === 33 && $signature[$sFirstByte] !== "\x00") {
            throw new InvalidArgumentException('Invalid DER signature, S length is 33 bytes and its first byte is not 0x00.');
        }

        // Get S from the signature
        $s = static::getSignaturePart($signature, $sFirstByte, $sLen);

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

    /**
     * Returns a signature part (R or S) from a full DER encoded P256 signature
     *
     * @param string $signature Full DER encoded P256 signature
     * @param int $firstByte First byte of the signature part to get
     * @param int $partLength Length of the signature part to get in bytes
     * @return string Signature part (R or S)
     */
    private static function getSignaturePart(string $signature, int $firstByte, int $partLength): string
    {
        // Get part from the signature
        $part = mb_substr($signature, $firstByte, $partLength, '8bit');

        // Remove possible unsigned int indicator
        $part = ltrim($part, "\x00");

        // DER left trims 0x00 from signature values, restore it
        return str_pad($part, 32, "\x00", STR_PAD_LEFT);
    }
}