<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Jwt;

use const FILTER_VALIDATE_URL;
use function filter_var;
use function json_encode;
use Sopsy\Base64Url\Base64Url;
use Sopsy\WebPush\Contract\Jwt;
use Sopsy\WebPush\Contract\Signer;
use Sopsy\WebPush\Exception\JwtException;
use function time;

final class WebPushJwt implements Jwt
{
    private $signer;
    private $header;
    private $payload;

    /**
     * JwtGenerator constructor.
     *
     * @param string $audience Audience for the JWT. Usually the push service origin
     * @param int $ttl TTL for the JWT in seconds, max is a day
     * @param string $subject Sender contact info for the push message, our "mailto:email" or a full URL
     * @param Signer $signer Signer used to sign the signature
     * @throws JwtException if invalid parameters are supplied
     */
    public function __construct(Signer $signer, string $audience, int $ttl, string $subject)
    {
        /** @noinspection BypassedUrlValidationInspection
         *  Not going to create any security issues.
         */
        if (!filter_var($audience, FILTER_VALIDATE_URL)) {
            throw new JwtException('Invalid audience "' . $audience . '": Not a valid URL');
        }

        if ($ttl < 0 || $ttl > 86400) {
            throw new JwtException('Invalid TTL "' . $ttl . '": value should be between 0 and 86400');
        }

        /** @noinspection BypassedUrlValidationInspection
         *  Not going to create any security issues.
         */
        if (!filter_var($subject, FILTER_VALIDATE_URL)) {
            throw new JwtException('Invalid subject "' . $subject . '": Not a valid http- or mailto-link');
        }

        $this->payload = [
            'aud' => $audience,
            'exp' => time() + $ttl,
            'sub' => $subject,
        ];

        $this->signer = $signer;
        $this->header = [
            'typ' => 'JWT',
            'alg' => $signer->algorithmName(),
        ];
    }

    public function signedJwt(): string
    {
        $header = Base64Url::encode(json_encode($this->header));
        $payload = Base64Url::encode(json_encode($this->payload));

        $signature = $this->signer->signature($header, $payload);
        $signature = Base64Url::encode($signature);

        return $header . '.' . $payload . '.' . $signature;
    }
}