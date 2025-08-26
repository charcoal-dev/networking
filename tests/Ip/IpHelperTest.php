<?php
/*
 * Part of the "charcoal-dev/networking" package.
 * @link https://github.com/charcoal-dev/networking
 */

declare(strict_types=1);

namespace Charcoal\Net\Tests\Ip;

use Charcoal\Net\Ip\IpHelper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Contains test cases for the IpHelper class to validate IP addresses.
 * Provides unit tests for verifying IP validity, checking IPv4, IPv6,
 * IPv4-mapped IPv6, and invalid IP addresses using data providers.
 */
final class IpHelperTest extends TestCase
{
    public function testIsValidIp_returns4ForValidIPv4(): void
    {
        $this->assertSame(4, IpHelper::isValidIp("127.0.0.1"));
        $this->assertSame(4, IpHelper::isValidIp("255.255.255.255"));
        $this->assertSame(4, IpHelper::isValidIp("0.0.0.0"));
    }

    public function testIsValidIp_returns6ForValidIPv6(): void
    {
        $this->assertSame(6, IpHelper::isValidIp("::1"));
        $this->assertSame(6, IpHelper::isValidIp("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        $this->assertSame(6, IpHelper::isValidIp("2001:db8::1"));
    }

    public function testIsValidIp_returns6ForIPv4MappedIPv6(): void
    {
        $this->assertSame(6, IpHelper::isValidIp("::ffff:192.0.2.128"));
    }

    public static function invalidIpProvider(): array
    {
        return [
            [""],
            ["abc"],
            ["256.0.0.1"],
            ["1.2.3.4.5"],
            ["1.2.3"],
            [":::1"],
            ["::gggg"],
            [" 127.0.0.1"],
            ["127.0.0.1 "],
            ["2001:db8::zzzz"],
        ];
    }

    #[dataProvider("invalidIpProvider")]
    public function testIsValidIp_returnsFalseForInvalidInputs(string $ip): void
    {
        $this->assertFalse(IpHelper::isValidIp($ip));
    }

    #[dataProvider("invalidIpProvider")]
    public function testIsValidIp_invalidDataProviderWrapped(string $ip): void
    {
        $this->assertFalse(IpHelper::isValidIp($ip));
    }

}