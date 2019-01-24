<?php
declare(strict_types=1);

namespace Sopsy\WebPush;

use InvalidArgumentException;
use Sopsy\Base64Url\Base64Url;
use Sopsy\WebPush\Exception\KeyFileException;
use Sopsy\WebPush\Exception\SignerException;

class Notification
{
    protected $jwt;
    protected $endpoint;
    protected $serverPublicKey;
    protected $payload;
    protected $ttl;
    protected $urgency;
    protected $topic;

    /**
     * Notification constructor.
     *
     * @param JwtGenerator $jwt
     * @param string $endpoint Full endpoint URL from the browser
     * @param string $serverKey The server private key in PEM format
     * @param int $ttl TTL value in seconds - How long should the push service try to deliver the message. A value of 0 will try to deliver it once immediately and gives up if it fails.
     * @throws KeyFileException if the conversion of a PEM key to DER fails, maybe due to an invalid key supplied
     */
    public function __construct(JwtGenerator $jwt, string $endpoint, string $serverKey, int $ttl = 2419200)
    {
        if (strpos($endpoint, 'https://') !== 0) {
            return false;
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
     * Set the notification payload.
     *
     * @param NotificationPayload $payload null for no payload
     */
    public function setPayload(NotificationPayload $payload): void
    {
        $this->payload = $payload;
    }

    /**
     * Set the notification urgency, use reasonable values to save users' battery.
     *
     * @param NotificationUrgency $urgency very-low, low, normal or high, null for default
     */
    public function setUrgency(NotificationUrgency $urgency): void
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
     * @return bool
     * @throws SignerException if signing the JWT fails
     */
    public function send(): bool
    {
        $ch = curl_init();

        $headers = [
            'Authorization: vapid t=' . $this->jwt->getSignedJwt() . ', k=' . Base64Url::encode($this->serverPublicKey),
            'TTL: ' . $this->ttl,
        ];

        if (!empty($this->topic)) {
            $headers[] = 'Topic: ' . $this->topic;
        }

        if ($this->urgency instanceof NotificationUrgency) {
            $headers[] = 'Urgency: ' . $this->urgency->getValue();
        }

        if ($this->payload instanceof NotificationPayload) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $this->payload->get());

            $headers[] = 'Content-Type: ' . $this->payload->getContentType();
            $headers[] = 'Content-Encoding: ' . $this->payload->getContentEncoding();
            $headers[] = 'Content-Length: ' . $this->payload->getContentLength();
        }

        curl_setopt($ch, CURLOPT_URL, $this->endpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $result = curl_exec($ch);
        $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        echo 'Response code: ' . $responseCode . "\n";
        if ($responseCode >= 200 && $responseCode <= 299) {
            // Assume the notification was sent, no logging here
            echo "Notification sent!\n";
        }

        curl_close($ch);

        return $result !== false;
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