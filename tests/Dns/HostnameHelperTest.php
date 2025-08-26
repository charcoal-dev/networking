<?php
/*
 * Part of the "charcoal-dev/networking" package.
 * @link https://github.com/charcoal-dev/networking
 */

declare(strict_types=1);

namespace Charcoal\Net\Tests\Dns;

use Charcoal\Net\Dns\HostnameHelper;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for validating hostnames using the HostnameHelper class.
 */
final class HostnameHelperTest extends TestCase
{
    public function testValidHostnameBasic(): void
    {
        self::assertTrue(HostnameHelper::isValidHostname("example.com"));
        self::assertTrue(HostnameHelper::isValidHostname("sub.example.co"));
        self::assertTrue(HostnameHelper::isValidHostname("a-b.example.com"));
        self::assertTrue(HostnameHelper::isValidHostname("123.com"));
    }

    public function testValidHostnameWithTrailingDot(): void
    {
        self::assertTrue(HostnameHelper::isValidHostname("example.com."));
    }

    public function testValidHostnameWithPunycodeTld(): void
    {
        self::assertTrue(HostnameHelper::isValidHostname("example.xn--p1ai"));
    }

    public function testSingleLabelNotAllowedByDefault(): void
    {
        self::assertFalse(HostnameHelper::isValidHostname("localhost"));
        self::assertFalse(HostnameHelper::isValidHostname("my-host"));
    }

    public function testSingleLabelAllowedWhenFlagSet(): void
    {
        self::assertTrue(HostnameHelper::isValidHostname("localhost", false, true));
        self::assertTrue(HostnameHelper::isValidHostname("my-host", false, true));
    }

    public function testIpNotAllowedByDefault(): void
    {
        self::assertFalse(HostnameHelper::isValidHostname("127.0.0.1"));
        self::assertFalse(HostnameHelper::isValidHostname("2001:db8::1"));
    }

    public function testIpAllowedWhenFlagSet(): void
    {
        self::assertTrue(HostnameHelper::isValidHostname("127.0.0.1", true));
        self::assertTrue(HostnameHelper::isValidHostname("2001:db8::1", true));
    }

    public function testInvalidWhenLabelStartsOrEndsWithHyphen(): void
    {
        self::assertFalse(HostnameHelper::isValidHostname("-example.com"));
        self::assertFalse(HostnameHelper::isValidHostname("example-.com"));
        self::assertFalse(HostnameHelper::isValidHostname("sub.-host.example"));
        self::assertFalse(HostnameHelper::isValidHostname("sub.host-.example"));
    }

    public function testInvalidWhenLabelContainsUnderscore(): void
    {
        self::assertFalse(HostnameHelper::isValidHostname("ex_ample.com"));
        self::assertFalse(HostnameHelper::isValidHostname("sub._srv.example"));
    }

    public function testLabelLengthBoundaries(): void
    {
        $label63 = str_repeat("a", 63);
        $label64 = str_repeat("a", 64);

        self::assertTrue(HostnameHelper::isValidHostname($label63 . ".com"));
        self::assertFalse(HostnameHelper::isValidHostname($label64 . ".com"));
    }

    public function testHostnameTotalLengthBoundary(): void
    {
        // Build a hostname longer than 253 chars to ensure it fails.
        // "a." repeated 127 times is 254 chars, plus "a" makes 255.
        $tooLong = str_repeat("a.", 127) . "a";
        self::assertFalse(HostnameHelper::isValidHostname($tooLong));
    }

    public function testEmptyAndWhitespace(): void
    {
        self::assertFalse(HostnameHelper::isValidHostname(""));
        self::assertFalse(HostnameHelper::isValidHostname(" "));
    }


    /**
     * @return void
     */
    public function testMustAccept(): void
    {
        $this->assertSame(["www.example.com", null, false], HostnameHelper::normalizeHostnamePort("www.Example.COM"), "FQDN");
        $this->assertSame(["example.com", 443, false], HostnameHelper::normalizeHostnamePort("example.com:443"), "FQDN + port");
        $this->assertSame(["example.com", 65535, false], HostnameHelper::normalizeHostnamePort("example.com:65535"), "Max port");
        $this->assertSame(["example.com", null, false], HostnameHelper::normalizeHostnamePort("EXAMPLE.COM."), "Trailing dot");
        $this->assertSame(["example.com", null, false], HostnameHelper::normalizeHostnamePort("   example.com   "), "Whitespace trimmed");
        $this->assertSame(["203.0.113.7", null, false], HostnameHelper::normalizeHostnamePort("203.0.113.7"), "IPv4");
        $this->assertSame(["203.0.113.7", 1234, false], HostnameHelper::normalizeHostnamePort("203.0.113.7:1234"), "IPv4 + port");
        $this->assertSame(["2001:db8::1", null, true], HostnameHelper::normalizeHostnamePort("[2001:db8::1]"), "Bracketed IPv6");
        $this->assertSame(["2001:db8::1", 8080, true], HostnameHelper::normalizeHostnamePort("[2001:db8::1]:8080"), "Bracketed IPv6 + port");
        $this->assertSame(["localhost", null, false], HostnameHelper::normalizeHostnamePort("Localhost"), "Single-label host");
        $this->assertSame(["xn--d1acufc.xn--p1ai", null, false], HostnameHelper::normalizeHostnamePort("xn--d1acufc.xn--p1ai"), "Punycode TLD");
        $this->assertSame(["example.com", 443, false], HostnameHelper::normalizeHostnamePort("example.com.:443"), "Trailing dot + port");
        $this->assertSame(["2001:db8::a", null, true], HostnameHelper::normalizeHostnamePort("[2001:DB8::A]"), "Bracketed IPv6 upper → lower");
        $this->assertSame(["2001:db8::1", 443, true], HostnameHelper::normalizeHostnamePort(" [2001:db8::1]:443 "), "Trim + bracketed IPv6 + port");
        $this->assertSame(["example.com", 80, false], HostnameHelper::normalizeHostnamePort("EXAMPLE.com:080"), "Leading zeros in port");
        $this->assertSame(["www.example.com", null, false], HostnameHelper::normalizeHostnamePort("www.example.com."), "www + trailing dot");
        $this->assertSame(["example.com", 1, false], HostnameHelper::normalizeHostnamePort("example.com:01"), "Leading zero → numeric port");
    }

    /**
     * @return void
     */
    public function testMustReject(): void
    {
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("2001:db8::1"), "Unbracketed IPv6");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("example.com:"), "Empty port");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("example.com:abc"), "Non-numeric port");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("foo:bar:443"), "Extra colon junk");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("[2001:db8::1"), "Missing closing bracket");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("example..com"), "Double dot label");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("-bad.com"), "Leading hyphen label");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("*.example.com"), "Wildcard not allowed");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("exa mple.com"), "Space in host");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("[fe80::1%25eth0]"), "IPv6 zone id not allowed");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("[2001:db8::1]443"), "Missing colon after bracket");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("[]:443"), "Empty bracketed host");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort(":"), "Colon only");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort(""), "Empty string");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("exámple.com"), "Non-ASCII label");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("bad-.com"), "Trailing hyphen in label");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("exa_mple.com"), "Underscore not allowed");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("example .com"), "Internal space in host");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("[FE80::1%25ETH0]"), "IPv6 zone id not allowed");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("example.com:+80"), "Plus sign in port");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("example.com:-1"), "Negative port");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("[2001:db8::1] :443"), "Space between ] and :");
        $this->assertFalse(HostnameHelper::normalizeHostnamePort("[2001:db8::1]junk"), "Garbage after bracket");
    }

    /**
     * @return void
     */
    public function testHostnamePassPortRejects():void
    {
        $this->assertSame(["2001:db8::1", null, true], HostnameHelper::normalizeHostnamePort("[2001:db8::1]:"), "Empty port after bracket");
        $this->assertSame(["localhost", null, false], HostnameHelper::normalizeHostnamePort("localhost:70000"), "Port too high");
        $this->assertSame(["example.com", null, false], HostnameHelper::normalizeHostnamePort("example.com:70000"), "Port out of range");
        $this->assertSame(["example.com", null, false], HostnameHelper::normalizeHostnamePort("example.com:0"), "Port zero → treated as absent");
        $this->assertSame(["2001:db8::1", null, true], HostnameHelper::normalizeHostnamePort("[2001:db8::1]:abc"), "IPv6 with non-numeric port");
    }
}