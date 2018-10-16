<?php
declare(strict_types=1);

namespace Sopsy\WebPush\NotificationUrgency;

use Sopsy\WebPush\NotificationUrgency;

class VeryLow implements NotificationUrgency
{
    public function getValue(): string
    {
        return 'very-low';
    }
}