<?php
declare(strict_types=1);

namespace Sopsy\WebPush\MessageUrgency;

use Sopsy\WebPush\Contract\MessageUrgency;

final class Normal implements MessageUrgency
{
    public function name(): string
    {
        return 'normal';
    }
}