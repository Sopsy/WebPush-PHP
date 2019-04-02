<?php
declare(strict_types=1);

namespace Sopsy\WebPush\Contract;

Interface MessageUrgency
{
    /**
     * Returns the urgency name as a string
     * Supported values for WebPush are very-low, low, normal and high
     *
     * @return string
     */
    public function name(): string;
}