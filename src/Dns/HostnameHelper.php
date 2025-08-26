<?php
/*
 * Part of the "charcoal-dev/networking" package.
 * @link https://github.com/charcoal-dev/networking
 */

declare(strict_types=1);

namespace Charcoal\Net\Dns;

use Charcoal\Net\Ip\IpHelper;

/**
 * Provides utility methods for working with hostnames, including normalization,
 * validation, and reconstruction. Can handle both regular hostnames and special
 * cases such as IP addresses or bracketed IPv6 addresses.
 */
abstract readonly class HostnameHelper
{

    /**
     * Checks if the given hostname is valid.
     * @param bool $allowIpAddr Whether to allow IP addresses as valid hostnames.
     * @param bool $allowNonTld Whether to allow non-top-level domains as valid hostnames.
     */
    public static function isValidHostname(
        string $hostname,
        bool   $allowIpAddr = false,
        bool   $allowNonTld = false
    ): bool
    {
        if (!$hostname) {
            return false;
        }

        $label = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
        $fqdn = "/\A(?=.{1,253}\z)(?:" . $label . "\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})\.?\z/";
        if (preg_match($fqdn, $hostname)) {
            return true;
        }

        return match (true) {
            $allowNonTld && preg_match("/\A" . $label . "\z/", $hostname) => true,
            $allowIpAddr && IpHelper::isValidIp($hostname) !== false => true,
            default => false,
        };
    }

    /**
     * Normalizes a hostname by removing any trailing slashes and converting it to lowercase.
     * Returns validated hostname at index 0, and port if found at index 1, otherwise returns false.
     * If the hostname is a bracketed IPv6 address, expect boolean true at index 2.
     * @param string $hostname
     * @return array<string,int|null>|false
     */
    public static function normalizeHostnamePort(string $hostname): array|false
    {
        $hostname = trim($hostname);
        if ($hostname === "") {
            return false;
        }

        // Bracketed IPv6 addresses
        if (str_starts_with($hostname, "[")) {
            $brackets = strpos($hostname, "]");
            if (!$brackets) {
                return false;
            }

            $baggage = substr($hostname, $brackets + 1);
            $hostname = substr($hostname, 1, $brackets - 1);
            if ($baggage) {
                if ($baggage[0] !== ":") {
                    return false;
                }

                $port = substr($baggage, 1);
                if (ctype_digit($port)) {
                    $port = (int)$port;
                }
            }
        }

        // Suffixed Port
        if (str_contains($hostname, ":") && !isset($brackets)) {
            $parts = explode(":", $hostname);
            if (count($parts) !== 2 || !ctype_digit($parts[1])) {
                return false;
            }

            $hostname = $parts[0];
            $port = (int)$parts[1];
        }

        // Validate Hostname
        $hostname = strtolower(trim($hostname, "."));
        if (!self::isValidHostname($hostname, allowIpAddr: true, allowNonTld: true)) {
            return false;
        }

        return [$hostname, match (true) {
            isset($port) && $port >= 1 && $port <= 65535 => $port,
            default => null,
        }, isset($brackets)];
    }

    /**
     * Reconstructs a hostname and optional port from the provided parts.
     * Returns the reassembled string or false on failure.
     */
    public static function rejoinValidatedParts(null|false|array $parts): string|false
    {
        if (!is_array($parts) || !$parts) {
            return false;
        }

        return match (true) {
            count($parts) === 1 => $parts[0],
            count($parts) === 3 && $parts[1] && !$parts[2] => $parts[0] . ":" . $parts[1],
            $parts[2] === true => "[" . $parts[0] . "]:" . $parts[1],
            default => false,
        };
    }
}