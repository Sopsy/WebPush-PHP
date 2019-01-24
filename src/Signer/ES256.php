<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Signer;

use Sopsy\WebPush\KeyConverter;
use Sopsy\WebPush\Signer;
use Sopsy\WebPush\Exception\SignerException;
use Sopsy\WebPush\Exception\KeyFileException;

class ES256 implements Signer
{
    protected $privateKey;

    /**
     * ES256 constructor.
     *
     * @param string $privateKey Server private key in PEM format
     * @throws KeyFileException if the key file is in invalid format
     */
    public function __construct(string $privateKey)
    {
        if (strpos($privateKey, '-----') === 0) {
            // Assume string
            $this->privateKey = $privateKey;
        } elseif (strpos($privateKey, "\n") === false) {
            // Assume file
            $this->setPrivateKeyFromFile($privateKey);
        } else {
            throw new KeyFileException('Invalid key file format');
        }
    }

    public function getAlgorithmName(): string
    {
        return 'ES256';
    }

    public function getSignature(string $jwtHeader, string $jwtPayload): string
    {
        $unsignedToken = $jwtHeader . '.' . $jwtPayload;

        openssl_sign($unsignedToken, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        // SHA256 DER signature is always 70-72 bytes:
        // 2 byte DER header + 2 byte R header (+ 1 byte R padding if first R byte is >0x7F) + 32 byte R data
        // + 2 byte S header (+ 1 byte S padding if first S byte is >0x7F) + 32 byte S data
        $signatureLength = mb_strlen($signature, '8bit');
        if ($signatureLength < 70 || $signatureLength > 72) {
            throw new SignerException('Invalid signature response from OpenSSL');
        }

        $signature = KeyConverter::stripDerSignatureHeaders($signature);

        if (empty($signature) || mb_strlen($signature, '8bit') !== 64) {
            throw new SignerException('Signing the JWT failed for an unknown reason');
        }

        return $signature;
    }

    /**
     * Sets the private key to be used when signing the JWT from $keyFile
     * or throws a FileNotFoundException if the file does not exist.
     *
     * @param string $keyFile The file to read, an EC private key in PEM format
     * @throws KeyFileException if the requested key file does not exist or is in invalid format
     */
    protected function setPrivateKeyFromFile(string $keyFile): void
    {
        $f = fopen($keyFile, 'rb');
        if (!$f) {
            throw new KeyFileException('Could not open key file "' . $keyFile . '".');
        }

        // Get the first key from the file
        $key = '';
        $lineNum = 0;
        while (($line = fgets($f)) !== false) {
            ++$lineNum;
            $line = trim($line);

            if ($lineNum === 1) {
                if ($line !== '-----BEGIN EC PRIVATE KEY-----') {
                    throw new KeyFileException('Invalid key file "' . $keyFile . '", expecting a singular Base64 encoded PEM EC private key file.');
                }
                continue;
            }

            if (strpos($line, '-----') === 0) {
                break;
            }

            $key .= $line;
        }

        // Test for validity
        if (base64_decode($key) === false) {
            throw new KeyFileException('Invalid key file "' . $keyFile . '", probably not a Base64 encoded PEM file.');
        }

        $key = "-----BEGIN EC PRIVATE KEY-----\n"
            . chunk_split($key, 64, "\n")
            . '-----END EC PRIVATE KEY-----';

        $this->privateKey = $key;
    }
}