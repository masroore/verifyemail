<?php

namespace VerifyEmail;

class Utils
{
    public const CHARSET_ISO88591 = 'iso-8859-1';
    public const CHARSET_UTF8     = 'utf-8';

    private static $idnSupported;
    private static $dnsSupported;

    /**
     * E-mail address validation.
     *
     * @param string $email Email address
     * @param boolean $checkDns check DNS records
     *
     * @return boolean True if email address is valid
     */
    public static function checkEmail($email, $checkDns): bool
    {
        $email = trim($email);

        // check for length limit specified by RFC 5321
        if (empty($email) || strlen($email) > 254) {
            return false;
        }

        // check for invalid (control) characters
        if (preg_match('/\p{Cc}/u', $email)) {
            return false;
        }

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return false;
        }

        $pos = strrpos($email, '@');

        if ($pos === false) {
            return false;
        }

        $localPart  = substr($email, 0, $pos);
        $domainPart = substr($email, $pos + 1);

        // validate local part
        if (strpos($localPart, '"') === 0) {
            // quoted-string, make sure all backslashes and quotes are escaped
            $localQuoted = preg_replace(
                '/\\\\(\\\\|\")/',
                '',
                substr($localPart, 1, -1)
            );

            if (preg_match('/\\\\|"/', $localQuoted)) {
                return false;
            }
        } elseif (preg_match('/(^\.|\.\.|\.$)/', $localPart)
            || preg_match('/[\\ ",:;<>@]/', $localPart)) {
            // dot-atom portion, make sure there's no prohibited characters
            return false;
        }

        // validate domain part
        if (preg_match('/^\[((IPv6:[0-9a-f:.]+)|([0-9.]+))\]$/i', $domainPart, $matches)) {
            // valid IPv4 or IPv6 email
            return self::checkIp(preg_replace('/^IPv6:/i', '', $matches[1]));
        }

        // if not an IP email
        $domainParts = explode('.', $domainPart);

        // not enough parts to be a valid domain
        if (count($domainParts) < 2) {
            return false;
        }

        foreach ($domainParts as $part) {
            if (!preg_match('/^((xn--)?([A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9])|([A-Za-z0-9]))$/', $part)) {
                return false;
            }
        }

        // validate last domain part
        $lastPart = array_pop($domainParts);
        if (strpos($lastPart, 'xn--') !== 0 && preg_match('/[^a-zA-Z]/', $lastPart)) {
            return false;
        }

        if (!$checkDns || !self::dnsSupported()) {
            return true;
        }

        // check DNS record(s)
        foreach (['MX', 'A', 'CNAME', 'AAAA'] as $type) {
            if (checkdnsrr($domainPart, $type)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validates IPv4 or IPv6 address
     *
     * @param string $_address IP address in v4 or v6 format
     *
     * @return bool True if the address is valid
     */
    public static function checkIp($_address): bool
    {
        #return self::isIPv4($_address) || self::isIPv6($_address);
        return filter_var($_address, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Tells whether DNS functions are supported or not.
     *
     * @return bool
     */
    public static function dnsSupported(): bool
    {
        if (self::$dnsSupported === null) {
            self::$dnsSupported = function_exists('checkdnsrr') && function_exists('getmxrr');
        }
        return self::$dnsSupported;
    }

    /**
     * Parse and extract the domain name from an email address
     *
     * @param string $address
     * @param string $charset
     *
     * @return string|null
     */
    public static function extractDomainFromEmail($address, $charset = self::CHARSET_ISO88591): ?string
    {
        $address = trim($address);
        $pos     = strrpos($address, '@');

        if (false !== $pos) {
            $domain = substr($address, ++$pos);

            if (static::idnSupported()
                && static::has8bitChars($domain)
                && @mb_check_encoding($domain, $charset)) {
                // verify charSet string is a valid one, and domain properly encoded in this charSet.
                $domain   = mb_convert_encoding($domain, 'UTF-8', $charset);
                $punycode = self::idnToAscii($domain);
                if (!empty($punycode)) {
                    $domain = $punycode;
                }
            }

            return $domain;
        }

        return null;
    }

    /**
     * Tells whether IDNs (Internationalized Domain Names) are supported or not. This requires the
     * `intl` and `mbstring` PHP extensions.
     *
     * @return bool `true` if required functions for IDN support are present
     */
    public static function idnSupported(): bool
    {
        if (self::$idnSupported === null) {
            self::$idnSupported = function_exists('idn_to_ascii') && function_exists('mb_convert_encoding');
        }
        return self::$idnSupported;
    }

    /**
     * Does a string contain any 8-bit chars (in any charset)?
     *
     * @param string $text
     *
     * @return bool
     */
    public static function has8bitChars($text): bool
    {
        return (bool)preg_match('/[\x80-\xFF]/', $text);
    }

    /**
     * Wrapper for idn_to_ascii with support for e-mail address.
     *
     * Warning: Domain names may be lowercase'd.
     * Warning: An empty string may be returned on invalid domain.
     *
     * @param string $str Decoded e-mail address
     *
     * @return string Encoded e-mail address
     */
    public static function idnToAscii($str): string
    {
        return self::idnConvert($str, true);
    }

    /**
     * Convert a string to ascii or utf8 (using IDNA standard)
     *
     * @param string $email Decoded e-mail address
     * @param boolean $toAscii Convert by idn_to_ascii if true and idn_to_utf8 if false
     *
     * @return string Encoded e-mail address
     */
    public static function idnConvert($email, $toAscii): string
    {
        if (!static::idnSupported()) {
            return $email;
        }

        if ($at = strrpos($email, '@')) {
            $user   = substr($email, 0, $at);
            $domain = substr($email, $at + 1);
        } else {
            $user   = '';
            $domain = $email;
        }

        // Note that in PHP 7.2/7.3 calling idn_to_* functions with default arguments
        // throws a warning, so we have to set the variant explicitly
        $variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : null;
        $options = 0;

        // Because php-intl extension lowercases domains and return false
        // on invalid email, we skip conversion when not needed

        if ($toAscii) {
            if (preg_match('/[^\x20-\x7E]/', $domain)) {
                $domain = idn_to_ascii($domain, $options, $variant);
            }
        } elseif (preg_match('/(^|\.)xn--/i', $domain)) {
            $domain = idn_to_utf8($domain, $options, $variant);
        }

        if ($domain === false) {
            return '';
        }

        return $at ? $user . '@' . $domain : $domain;
    }

    /**
     * Get MX hostnames for the given domain
     *
     * @param string $domain
     * @return array
     */
    public static function getMxHosts($domain): array
    {
        if (!self::dnsSupported()) {
            return [];
        }

        if (checkdnsrr($domain, 'MX') === false) {
            return [];
        }

        $mx_hosts = $mx_weights = [];
        getmxrr($domain, $mx_hosts, $mx_weights);

        // put the records together in an associative array we can sort
        $mx_records = array_combine($mx_hosts, $mx_weights);

        // sort them
        asort($mx_records);

        return array_keys($mx_records);
    }

    /**
     * Wrapper for idn_to_utf8 with support for e-mail address
     *
     * @param string $str Decoded e-mail address
     *
     * @return string Encoded e-mail address
     */
    public static function idnToUtf8($str)
    {
        return self::idnConvert($str, false);
    }

    /**
     * returns true/false if the given address is a valid IPv4 address
     *
     * @param string $_address the IPv4 address to check
     *
     * @return boolean returns true/false if the address is IPv4 address
     */
    public static function isIPv4($_address): bool
    {
        return filter_var($_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * returns true/false if the given address is a valid IPv6 address
     *
     * @param string $_address the IPv6 address to check
     *
     * @return boolean returns true/false if the address is IPv6 address
     */
    public static function isIPv6($_address): bool
    {
        return filter_var($_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }
}
