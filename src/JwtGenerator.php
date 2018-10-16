<?php
declare(strict_types=1);

namespace Sopsy\WebPush;

use Sopsy\Base64Url\Base64Url;
use Sopsy\WebPush\Exception\SignerException;

class JwtGenerator
{
    protected $signer;
    protected $header;
    protected $payload = [];

    /**
     * JwtGenerator constructor.
     * @param Signer $signer Signer used to sign the signature
     */
    public function __construct(Signer $signer)
    {
        $this->signer = $signer;
        $this->header = [
            'typ' => 'JWT',
            'alg' => $signer->getAlgorithmName(),
        ];
    }

    /**
     * Sets the JWT payload
     *
     * @param array $payload
     */
    public function setPayload(array $payload): void
    {
        $this->payload = $payload;
    }

    /**
     * Returns a signed JWT string.
     *
     * @return string path to the file
     * @throws SignerException if signing the JWT fails
     */
    public function getSignedJwt(): string
    {
        $header = Base64Url::encode(json_encode($this->header));
        $payload = Base64Url::encode(json_encode($this->payload));

        $signature = $this->signer->getSignature($header, $payload);
        $signature = Base64Url::encode($signature);

        return $header . '.' . $payload . '.' . $signature;
    }
}