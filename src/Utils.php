<?php

namespace VerifyEmail;

class Utils
{
    public const IPV4 = 4;
    public const IPV6 = 6;

    public const CHARSET_ISO88591 = 'iso-8859-1';
    public const CHARSET_UTF8 = 'utf-8';

    private static $idnSupported;
    private static $dnsSupported;

    /**
     * Tells whether IDNs (Internationalized Domain Names) are supported or not. This requires the
     * `intl` and `mbstring` PHP extensions.
     *
     * @return bool `true` if required functions for IDN support are present
     */
    public static function idnSupported()
    {
        if (self::$idnSupported === null) {
            self::$idnSupported = function_exists('idn_to_ascii') && function_exists('mb_convert_encoding');
        }
        return self::$idnSupported;
    }

    /**
     * Tells whether DNS functions are supported or not.
     *
     * @return bool
     */
    public static function dnsSupported()
    {
        if (self::$dnsSupported === null) {
            self::$dnsSupported = function_exists('checkdnsrr') && function_exists('getmxrr');
        }
        return self::$dnsSupported;
    }

    /**
     * Does a string contain any 8-bit chars (in any charset)?
     *
     * @param string $text
     *
     * @return bool
     */
    public static function has8bitChars($text)
    {
        return (bool)preg_match('/[\x80-\xFF]/', $text);
    }

    /**
     * E-mail address validation.
     *
     * @param string $email Email address
     * @param boolean $checkDns check DNS records
     *
     * @return boolean True if email address is valid
     */
    public static function checkEmail(string $email, bool $checkDns): bool
    {
        $email = trim($email);

        // check for length limit specified by RFC 5321
        if (empty($email) || strlen($email) <= 3 || strlen($email) > 254) {
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

        $localPart = substr($email, 0, $pos);
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
    public static function checkIp(string $_address)
    {
        #return self::isIPv4($_address) || self::isIPv6($_address);
        return filter_var($_address, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Parse and extract the domain name from an email address
     *
     * @param string $address
     * @param string $charset
     *
     * @return string|null
     */
    public static function extractDomainFromEmail(string $address, string $charset = self::CHARSET_ISO88591)
    {
        $address = trim($address);
        $pos = strrpos($address, '@');

        if (false !== $pos) {
            $domain = substr($address, ++$pos);

            if (static::idnSupported()
                && static::has8bitChars($domain)
                && @mb_check_encoding($domain, $charset)) {
                // verify charSet string is a valid one, and domain properly encoded in this charSet.
                $domain = mb_convert_encoding($domain, 'UTF-8', $charset);
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
     * Get MX hostnames for the given domain
     *
     * @param string $domain
     * @return array
     */
    public static function getMxHosts($domain)
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
     * Wrapper for idn_to_ascii with support for e-mail address.
     *
     * Warning: Domain names may be lowercase'd.
     * Warning: An empty string may be returned on invalid domain.
     *
     * @param string $str Decoded e-mail address
     *
     * @return string Encoded e-mail address
     */
    public static function idnToAscii($str)
    {
        return self::idnConvert($str, true);
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
     * Convert a string to ascii or utf8 (using IDNA standard)
     *
     * @param string $email Decoded e-mail address
     * @param boolean $toAscii Convert by idn_to_ascii if true and idn_to_utf8 if false
     *
     * @return string Encoded e-mail address
     */
    public static function idnConvert($email, $toAscii)
    {
        if (!static::idnSupported()) {
            return $email;
        }

        if ($at = strrpos($email, '@')) {
            $user = substr($email, 0, $at);
            $domain = substr($email, $at + 1);
        } else {
            $user = '';
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
     * returns true/false if the given address is a valid IPv4 address
     *
     * @param string $_address the IPv4 address to check
     *
     * @return boolean returns true/false if the address is IPv4 address
     */
    public static function isIPv4($_address)
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
    public static function isIPv6($_address)
    {
        return filter_var($_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }


    /**
     * Wrapper for php's checkdnsrr function.
     *
     * @param string $host Fully-Qualified Domain Name
     * @param string $type Resource record type to lookup
     *                        Supported types are: MX (default), A, AAAA, NS, TXT, CNAME
     *                        Other types may work or may not work
     *
     * @return mixed        true if entry found,
     *                    false if entry not found,
     *                    null if this function is not supported by this environment
     *
     * Since null can also be returned, you probably want to compare the result
     * with === true or === false,
     */
    public static function checkDnsRecords($host, $type = 'MX')
    {
        // The dot indicates to search the DNS root (helps those having DNS prefixes on the same domain)
        if (substr($host, -1) === '.') {
            $host_fqdn = $host;
            $host = substr($host, 0, -1);
        } else {
            $host_fqdn = $host . '.';
        }
        // $host		has format	some.host.example.com
        // $host_fqdn	has format	some.host.example.com.

        // If we're looking for an A record we can use gethostbyname()
        if ($type === 'A' && function_exists('gethostbyname')) {
            return (@gethostbyname($host_fqdn) != $host_fqdn);
        }

        if (function_exists('checkdnsrr')) {
            return checkdnsrr($host_fqdn, $type);
        }

        if (function_exists('dns_get_record')) {
            // dns_get_record() expects an integer as second parameter
            // We have to convert the string $type to the corresponding integer constant.
            $type_name = 'DNS_' . strtoupper($type);
            $resource_type = defined($type_name) ? constant($type_name) : DNS_ANY;

            // dns_get_record() might throw E_WARNING and return false for records that do not exist
            $result_set = @dns_get_record($host_fqdn, $resource_type);

            if (empty($result_set) || !is_array($result_set)) {
                return false;
            }

            if ($resource_type === DNS_ANY) {
                // $result_set is a non-empty array
                return true;
            }

            foreach ($result_set as $result) {
                if (
                    isset($result['host'])
                    && $result['host'] == $host
                    && isset($result['type'])
                    && $result['type'] == $type
                ) {
                    return true;
                }
            }

            return false;
        }

        return null;
    }

    /**
     * Gets the IP version. Does not perform IP address validation.
     *
     * @param string $ip the valid IPv4 or IPv6 address.
     * @return int [[IPV4]] or [[IPV6]]
     */
    public static function getIpVersion($ip)
    {
        return strpos($ip, ':') === false ? self::IPV4 : self::IPV6;
    }
}
