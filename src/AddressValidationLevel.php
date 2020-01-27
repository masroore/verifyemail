<?php


namespace VerifyEmail;

use InvalidArgumentException;

/**
 * Class AddressValidationLevel
 *
 * The values of this type can be used as both input parameters (when they define how deeply the e-mail address
 * check should go) and return values (when they show at which stage the verification procedure failed).
 * For instance, if you set the desired level of verification to, let's say, DnsQuery, it means EmailAddressValidator
 * will do syntax check and DNS MX query check. If both checks are OK, the return value will be OK.
 * Otherwise, the return value will be the level at which the verification failed. For instance, if it
 * failed at syntax check, the return value will be SyntaxCheck.
 *
 * @package VerifyEmail
 */
final class AddressValidationLevel
{
    /*
     * Check e-mail address syntax only, via PHP filter_validate() function. Very fast and does not make any
     * network queries.
     */
    public const SyntaxCheck = 1;

    /**
     * In addition to syntax check, do DNS MX query against the domain name part of the e-mail address to
     * determine which SMTP MX server is responsible for delivering e-mail to the given domain. Slower than
     * just syntax check but more accurate as invalid domains are filtered out.
     */
    public const DnsQuery = 2;

    /**
     * In addition to the previous option, make an attempt to connect to the SMTP MX server determined at
     * the previous stage. If multiple MX servers have been detected and the server having the highest priority
     * is not responding, will also try other MXes of this domain, in accordance with their priorities.
     * Slower than just a DNS MX check but more accurate as it filters out the domains with dead SMTP MX servers.
     */
    public const SmtpConnection = 3;

    /**
     * This method not just connects to SMTP MX server but also submits the sender and recipient (where the
     * recipients is the e-mail address being examined) to that MX server. The slowest and the most
     * accurate method.
     */
    public const SendAttempt = 4;

    /**
     * Verify() method returns this value when the e-mail address check passed successfully.
     * @see EmailAddressValidator::verify()
     */
    public const OK = 5;

    public static function check($value): void
    {
        if ($value < self::SyntaxCheck || $value >= self::OK) {
            throw new InvalidArgumentException('Invalid validation level');
        }
    }

    /**
     * @param int $level
     * @return int
     */
    public static function nextLevel($level): int
    {
        if (++$level > self::OK) {
            $level = self::OK;
        }
        return $level;
    }
}
