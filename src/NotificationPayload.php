<?php
declare(strict_types=1);

namespace Sopsy\WebPush;

use InvalidArgumentException;

interface NotificationPayload
{
    /**
     * Set the Push Notification payload (a.k.a. content or data).
     * Max size is 4KB minus encryption header, so 4078 bytes.
     *
     * @param string $payload The service worker should know how to handle this, passed there as is
     * @throws InvalidArgumentException when the payload is too large
     */
    public function set(string $payload): void;

    /**
     * Get the Content-Type for data returned with get(), used as a POST header.
     * Example: application/octet-stream
     *
     * @return string
     */
    public function getContentType(): string;

    /**
     * Get the Content-Encoding for data returned with get(), used as a POST header.
     * Example: aesgcm
     *
     * @return string
     */
    public function getContentEncoding(): string;

    /**
     * Get the Content-Length for data returned with get(), used as a POST header.
     *
     * @return int unsigned
     */
    public function getContentLength(): int;

    /**
     * Get the payload to be used in a Push Notification POST data as is.
     *
     * @return string
     */
    public function get(): string;
}