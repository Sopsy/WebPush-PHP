<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Contract;

interface Response
{
    /**
     * Returns the HTTP response code from the push service
     *
     * @return int
     */
    public function code(): int;

    /**
     * Returns the full response body from the push service
     *
     * @return string
     */
    public function message(): string;

    /**
     * Did sending the message to the push service succeed?
     *
     * @return bool
     */
    public function success(): bool;
}