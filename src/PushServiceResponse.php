<?php
declare(strict_types=1);

namespace Sopsy\WebPush;

use Sopsy\WebPush\Contract\Response;

final class PushServiceResponse implements Response
{
    private $responseCode;
    private $response;

    public function __construct(int $responseCode, string $response)
    {
        $this->responseCode = $responseCode;
        $this->response = $response;
    }

    public function code(): int
    {
        return $this->responseCode;
    }

    public function message(): string
    {
        return $this->response;
    }

    public function success(): bool
    {
        // If response code is between 200 - 299, sending probably succeeded. Otherwise we assume it failed.
        return $this->responseCode >= 200 && $this->responseCode <= 299;
    }
}