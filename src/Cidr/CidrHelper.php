<?php
declare(strict_types=1);

namespace Charcoal\Net\Cidr;

/**
 * CidrHelper provides helper methods for handling CIDR (Classless Inter-Domain Routing)
 * notations and determining whether an IP address falls within specified CIDR ranges.
 *
 * The class focuses on parsing CIDR notations into binary format, matching IP addresses
 * against CIDR ranges, and generating binary masks for CIDR computations.
 */
abstract readonly class CidrHelper
{
    /**
     * Matches a given IP address against a list of CIDR notations to determine
     * if the IP falls within any of the specified ranges.
     * IP address in non-binary format is converted to binary format before matching.
     * CIDR notations are parsed into binary format before matching.
     */
    final public static function ipInCidr(string $ip, array $cidrList): bool
    {
        $ipBin = @inet_pton($ip);
        if (!$ipBin) {
            return false;
        }

        foreach ($cidrList as $cidr) {
            $cidrBinary = self::parseCidrToBinary($cidr);
            if (!$cidrBinary) {
                continue;
            }

            if (self::ipInCidrBinary($ipBin, true, $cidrBinary[0], $cidrBinary[1])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if the given IP address falls within the specified CIDR range.
     * IP address in non-binary format is converted to binary format before matching.
     * CIDR range is parsed into binary format before matching.
     */
    final public static function ipInCidrBinary(
        string $ip,
        bool   $ipIsBinary,
        string $cidrNetwork,
        string $cidrMask,
    ): bool
    {
        if (!$cidrNetwork || !$cidrMask) {
            return false;
        }

        $ipBin = $ipIsBinary ? $ip : @inet_pton($ip);
        if (!$ipBin) {
            return false;
        }

        return strlen($ipBin) === strlen($cidrMask) &&
            ($ipBin & $cidrMask) === ($cidrNetwork & $cidrMask);
    }

    /**
     * Parses a CIDR notation into binary format.
     * @return array{string,string}|false
     */
    final public static function parseCidrToBinary(string $cidr): array|false
    {
        [$net, $prefix] = array_pad(explode("/", $cidr, 2), 2, null);
        $netBin = @inet_pton($net ?? "");
        if ($netBin === false) {
            return false;
        }

        $bits = strlen($netBin) * 8;
        $pfx = is_numeric($prefix) ? max(0, min((int)$prefix, $bits)) : $bits;
        $mask = self::mask(strlen($netBin), $pfx);
        $network = $netBin & $mask;
        return [$network, $mask];
    }

    /**
     * Parses a list of CIDR notations into binary format.
     * @param array $cidrList
     * @return array<string,array{string,string}>
     * @api
     */
    final public static function parseCidrListToBinary(array $cidrList): array
    {
        $parsed = [];
        foreach ($cidrList as $cidr) {
            $cidrBinary = self::parseCidrToBinary($cidr);
            if ($cidrBinary) {
                $parsed[$cidr] = $cidrBinary;
            }
        }

        return $parsed;
    }

    /**
     * Generates a binary mask for the specified number of bytes and bits.
     */
    private static function mask(int $bytes, int $bits): string
    {
        $full = intdiv($bits, 8);
        $rem = $bits % 8;
        $s = str_repeat("\xFF", $full);
        if ($bits % 8) {
            $s .= chr(0xFF << (8 - $rem) & 0xFF);
        }

        return str_pad($s, $bytes, "\x00", STR_PAD_RIGHT);
    }
}