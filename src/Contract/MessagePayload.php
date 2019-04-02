<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Contract;

interface MessagePayload
{
    /**
     * Get the Content-Type for data returned with get(), used as a POST header.
     * Example: application/octet-stream
     *
     * @return string
     */
    public function contentType(): string;

    /**
     * Get the Content-Encoding for data returned with get(), used as a POST header.
     * Example: aesgcm
     *
     * @return string
     */
    public function contentEncoding(): string;

    /**
     * Get the Content-Length for data returned with get(), used as a POST header.
     *
     * @return int unsigned
     */
    public function contentLength(): int;

    /**
     * Get the payload to be used in a Push Message POST data as is.
     *
     * @return string
     */
    public function payload(): string;
}