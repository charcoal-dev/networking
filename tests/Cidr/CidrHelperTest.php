<?php
/*
 * Part of the "charcoal-dev/networking" package.
 * @link https://github.com/charcoal-dev/networking
 */

declare(strict_types=1);

namespace Charcoal\Net\Tests\Cidr;

use Charcoal\Net\Cidr\CidrHelper;
use PHPUnit\Framework\TestCase;

/**
 * Unit test class for the CidrHelper utility.
 *
 * This class contains various test cases for verifying the behavior of the
 * `CidrHelper::ipInCidr` method. It tests the method's functionality using
 * different scenarios involving both IPv4 and IPv6 addresses and CIDR notations.
 *
 * The following scenarios are tested:
 * - Invalid IP address inputs.
 * - Empty CIDR list handling.
 * - Exact host matches for IPv4 and IPv6.
 * - Non-matching cases for out-of-range IPs.
 * - Mixed family inputs (IPv4 and IPv6) with appropriate matching logic.
 * - Zero-prefix CIDRs that match all addresses.
 * - Handling of invalid CIDR entries, including ignoring such entries and continuing to parse valid ones.
 * - Partial-byte prefix matching for IPv4.
 * - Partial-bit prefix matching for IPv6, including complex bit-lengths like 65 bits.
 * - Handling of whitespace in CIDR entries and IP addresses.
 * - Handling of out-of-range prefix values, ensuring invalid prefixes are skipped.
 */
final class CidrHelperTest extends TestCase
{
    public function testIpInCidr_returnsFalseForInvalidIpInput(): void
    {
        $this->assertFalse(CidrHelper::ipInCidr("not.an.ip", ["192.168.0.0/16"]));
        $this->assertFalse(CidrHelper::ipInCidr(" 192.168.1.1", ["192.168.0.0/16"]));
    }

    public function testIpInCidr_returnsFalseForEmptyCidrList(): void
    {
        $this->assertFalse(CidrHelper::ipInCidr("192.0.2.1", []));
        $this->assertFalse(CidrHelper::ipInCidr("2001:db8::1", []));
    }

    public function testIpInCidr_matchesIPv4ExactHost(): void
    {
        $this->assertTrue(CidrHelper::ipInCidr("203.0.113.5", ["203.0.113.5/32"]));
    }

    public function testIpInCidr_doesNotMatchIPv4OutsideRange(): void
    {
        $this->assertFalse(CidrHelper::ipInCidr("203.0.113.5", ["203.0.114.0/24"]));
    }

    public function testIpInCidr_matchesIPv6ExactHost(): void
    {
        $this->assertTrue(CidrHelper::ipInCidr("2001:db8::1234", ["2001:db8::1234/128"]));
    }

    public function testIpInCidr_doesNotMatchIPv6OutsideRange(): void
    {
        $this->assertFalse(CidrHelper::ipInCidr("2001:db8::1234", ["2001:db8:1::/48"]));
    }

    public function testIpInCidr_mixedFamilyListMatchesOnlySameFamily(): void
    {
        // IPv4 IP should match IPv4 CIDR even if IPv6 CIDRs are present
        $this->assertTrue(CidrHelper::ipInCidr(
            "192.0.2.1",
            ["2001:db8::/32", "192.0.2.0/24"]
        ));

        // IPv4 IP should not match if only IPv6 CIDRs are provided
        $this->assertFalse(CidrHelper::ipInCidr(
            "192.0.2.1",
            ["2001:db8::/32"]
        ));
    }

    public function testIpInCidr_zeroPrefixMatchesAll(): void
    {
        $this->assertTrue(CidrHelper::ipInCidr("203.0.113.5", ["0.0.0.0/0"]));
        $this->assertTrue(CidrHelper::ipInCidr("2001:db8::1234", ["::/0"]));
    }

    public function testIpInCidr_ignoresInvalidCidrEntriesAndStillMatchesValidOne(): void
    {
        $cidrs = [
            "bad",
            "192.168.1.0",          // missing prefix
            "10.0.0.0/33",          // prefix too large
            "172.16.0.0/abc",       // non-numeric prefix
            " 192.168.1.0/24",      // leading space in net, will be invalid
            "172.16.0.0/12",        // valid, should cause match
        ];

        $this->assertTrue(CidrHelper::ipInCidr("172.16.5.10", $cidrs));
    }

    public function testIpInCidr_partialBytePrefixIPv4(): void
    {
        // /9: 10.128.0.0 - 10.255.255.255
        $this->assertTrue(CidrHelper::ipInCidr("10.128.0.1", ["10.128.0.0/9"]));
        $this->assertFalse(CidrHelper::ipInCidr("10.127.255.255", ["10.128.0.0/9"]));

        // /13: 172.16.0.0 - 172.23.255.255
        $this->assertTrue(CidrHelper::ipInCidr("172.20.10.5", ["172.16.0.0/13"]));
        $this->assertFalse(CidrHelper::ipInCidr("172.24.0.1", ["172.16.0.0/13"]));
    }

    public function testIpInCidr_partialBitPrefixIPv6_65Bit(): void
    {
        // /65: first 65 bits fixed; 2001:db8:: has 65th bit = 0
        $this->assertTrue(CidrHelper::ipInCidr("2001:db8:0:0:7fff::1", ["2001:db8::/65"]));
        $this->assertFalse(CidrHelper::ipInCidr("2001:db8:0:0:8000::1", ["2001:db8::/65"]));
    }

    public function testIpInCidr_whitespaceInCidrEntriesMakesThemInvalid(): void
    {
        // Entry with spaces should be ignored (no implicit trimming)
        $this->assertFalse(CidrHelper::ipInCidr("192.168.1.10", [" 192.168.1.0/24 "]));

        // A valid, trimmed entry should match
        $this->assertTrue(CidrHelper::ipInCidr("192.168.1.10", [" 192.168.1.0/24 ", "192.168.1.0/24"]));
    }

    public function testIpInCidr_ipWithWhitespaceIsInvalid(): void
    {
        $this->assertFalse(CidrHelper::ipInCidr(" 203.0.113.5", ["203.0.113.0/24"]));
        $this->assertFalse(CidrHelper::ipInCidr("2001:db8::1234 ", ["2001:db8::/32"]));
    }

    public function testIpInCidr_ignoresOutOfRangePrefixValues(): void
    {
        // IPv4: /33 invalid and ignored
        $this->assertFalse(CidrHelper::ipInCidr("10.0.0.1", ["10.0.0.0/33"]));

        // IPv6: /129 invalid and ignored
        $this->assertFalse(CidrHelper::ipInCidr("2001:db8::1", ["2001:db8::/129"]));

        // Mixed with a valid entry should still match
        $this->assertTrue(CidrHelper::ipInCidr("10.0.0.1", ["10.0.0.0/33", "10.0.0.0/8"]));
    }
}