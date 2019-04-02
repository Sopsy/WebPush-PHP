<?php
declare(strict_types=1);

namespace Sopsy\WebPush;

use InvalidArgumentException;
use Sopsy\Base64Url\Base64Url;
use Sopsy\WebPush\Contract\Jwt;
use Sopsy\WebPush\Contract\MessagePayload;
use Sopsy\WebPush\Contract\MessageUrgency;
use Sopsy\WebPush\Exception\KeyFileException;
use Sopsy\WebPush\Exception\NotificationException;
use Sopsy\WebPush\Exception\SignerException;

final class Push
{
    private $jwt;
    private $endpoint;
    private $serverPublicKey;
    private $payload;
    private $ttl;
    private $urgency;
    private $topic;

    /**
     * @var $responseCode string Response text from the endpoint after the notification is sent
     */
    private $response;

    /**
     * @var $responseCode int HTTP response code from the endpoint after the notification is sent
     */
    private $responseCode;

    /**
     * Notification constructor.
     *
     * @param Jwt $jwt
     * @param string $endpoint Full endpoint URL from the browser
     * @param string $serverKey The server private key in PEM format
     * @param int $ttl TTL value in seconds - How long should the push service try to deliver the message. A value of 0 will try to deliver it once immediately and gives up if it fails.
     * @throws KeyFileException if the conversion of a PEM key to DER fails, maybe due to an invalid key supplied
     */
    public function __construct(Jwt $jwt, string $endpoint, string $serverKey, int $ttl = 2419200)
    {
        if (strpos($endpoint, 'https://') !== 0) {
            throw new InvalidArgumentException('Invalid endpoint URL');
        }

        if (!$this->validateEndpointUrl($endpoint)) {
            throw new InvalidArgumentException('Invalid endpoint URL');
        }

        if ($ttl < 0) {
            throw new InvalidArgumentException('TTL cannot be negative.');
        }

        $this->jwt = $jwt;
        $this->endpoint = $endpoint;
        $this->serverPublicKey = KeyConverter::unserializePublicFromPrivate($serverKey);
        $this->ttl = $ttl;
    }

    /**
     * Set the notification urgency, use reasonable values to save users' battery.
     *
     * @param MessageUrgency $urgency very-low, low, normal or high
     */
    public function setUrgency(MessageUrgency $urgency): void
    {
        $this->urgency = $urgency;
    }

    /**
     * Set the topic of the push notification. If the push service supports it, only the last notification
     * with the same topic is shown to the user if there is multiple undelivered notifications in queue
     * e.g. due to user being offline.
     *
     * @param string $topic
     * @throws InvalidArgumentException if the topic length exceeds 32 bytes or contains invalid characters
     */
    public function setTopic(string $topic): void
    {
        if (mb_strlen($topic, '8bit') > 32) {
            throw new InvalidArgumentException('Topic too long');
        }

        if (!preg_match('/^[A-Za-z0-9\-_]$/', $topic)) {
            throw new InvalidArgumentException('Topic contains characters that are not URL-safe');
        }

        $this->topic = $topic;
    }

    /**
     * Send the Push Notification to the specified endpoint
     *
     * @param MessagePayload $payload
     * @return bool
     * @throws SignerException if signing the Jwt fails
     */
    public function send(MessagePayload $payload): bool
    {
        $ch = curl_init();

        $headers = [
            'Authorization: vapid t=' . $this->jwt->signedJwt() . ', k=' . Base64Url::encode($this->serverPublicKey),
            'TTL: ' . $this->ttl,
        ];

        if (!empty($this->topic)) {
            $headers[] = 'Topic: ' . $this->topic;
        }

        if ($this->urgency instanceof MessageUrgency) {
            $headers[] = 'Urgency: ' . $this->urgency->name();
        }

        $headers[] = 'Content-Type: ' . $payload->contentType();
        $headers[] = 'Content-Encoding: ' . $payload->contentEncoding();
        $headers[] = 'Content-Length: ' . $payload->contentLength();
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload->payload());
        curl_setopt($ch, CURLOPT_URL, $this->endpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $this->response = curl_exec($ch);
        $this->responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        curl_close($ch);

        // If response code is between 200 - 299, sending probably succeeded. Otherwise we assume it failed.
        return $this->responseCode >= 200 && $this->responseCode <= 299;
    }

    /**
     * @return int
     * @throws NotificationException
     */
    public function responseCode(): int
    {
        if (!$this->responseCode) {
            throw new NotificationException('This notification is not sent, so we do not have a response code.');
        }

        return $this->responseCode;
    }

    /**
     * @return string
     * @throws NotificationException
     */
    public function response(): string
    {
        if (!$this->responseCode) {
            throw new NotificationException('This notification is not sent, so we do not have a response.');
        }

        return $this->response;
    }

    private function validateEndpointUrl($url): bool
    {
        $url = trim($url);

        // All endpoints should always use HTTPS
        if (strpos($url, 'https://') !== 0) {
            return false;
        }

        /**
         * @noinspection BypassedUrlValidationInspection
         * Prior strpos validation of protocol should make us safe already
         */
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
}