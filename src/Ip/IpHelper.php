<?php
/*
 * Part of the "charcoal-dev/networking" package.
 * @link https://github.com/charcoal-dev/networking
 */

declare(strict_types=1);

namespace Charcoal\Net\Ip;

/**
 * A utility class for handling IP address-related operations.
 */
abstract readonly class IpHelper
{
    /**
     * Checks if the given IP address is valid and returns its version.
     */
    public static function isValidIp(string $ip): int|false
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }

        return strlen($bin) === 4 ? 4 : 6;
    }
}