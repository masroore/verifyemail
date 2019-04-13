<?php declare(strict_types=1);

namespace VerifyEmail;

use Exception;
use InvalidArgumentException;

/**
 * Class EmailAddressVerifier
 *
 * Provides means for verification of e-mail addresses.
 *
 * There are several levels of verification: syntax check with by means of PHP filter_var(), DNS MX lookup of the
 * domain part of the address, test connection to the SMTP MX server responsible for delivering e-mail to
 * the given domain, and test send attempt (which means not only the connection is made but also the sender and
 * the recipient are submitted to the server). Even in "send attempt" mode, the class does not actually send
 * any e-mails, it stops at the point where the server accepted the given e-mail address as the valid recipient's
 * address. How deep the verification will be is controlled with EmailAddressVerifier::validationLevel property.
 *
 * @package VerifyEmail
 */
final class EmailAddressVerifier
{
    /**
     * The level of deepness of e-mail address verification.
     *
     * @var int
     */
    private $validationLevel;

    /**
     * @var DebugLogger
     */
    private $logger;

    /**
     * The domain string to use as an argument of HELO or EHLO commands when making test connections to SMTP servers.
     *
     * The EHLO/HELO argument which should be the public host name of the machine making connection to the SMTP server,
     * or an empty string which tells EmailAddressValidator to use the local IP address or the host name of that
     * machine.
     *
     * The default value is an empty string.
     *
     * This property is only used if EmailAddressValidator::validationLevel is AddressValidationLevel::SmtpConnection
     * or AddressValidationLevel::SendAttempt.
     *
     * @var string
     */
    private $helloDomain;

    /**
     * The string to be used as sender when making test connections to SMTP MX servers.
     *
     * The string EmailAddressValidator will use as MAIL FROM command argument. The default value is "user@domain.com".
     *
     * This property is only used if EmailAddressValidator::validationLevel is AddressValidationLevel::SendAttempt.
     *
     * @var string
     */
    private $mailFrom;

    /**
     * Current validation level
     *
     * @var int
     */
    private $currentLevel;

    /**
     * @var array
     */
    private $mxTransferLogs = [];

    /**
     * Gets the level of deepness of e-mail address verification.
     *
     * @return int
     *
     * @see AddressValidationLevel
     */
    public function getValidationLevel()
    {
        return $this->validationLevel;
    }

    /**
     * Sets the level of deepness of e-mail address verification.
     *
     * @param int $validationLevel The value which tells EmailAddressValidator which checks to do in order to
     *                              validate an e-mail address.
     *
     * @see AddressValidationLevel
     */
    public function setValidationLevel($validationLevel)
    {
        AddressValidationLevel::boundsCheck($validationLevel);
        $this->validationLevel = $validationLevel;
    }

    /**
     * The amount of time (in seconds) to wait for a response from the SMTP server.
     *
     * @var int
     */
    private $timeout;

    /**
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * @param int $timeout
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    public function __construct()
    {
        // The default validation level is SendAttempt (maximum level of verification)
        $this->validationLevel = AddressValidationLevel::SendAttempt;
        $this->timeout = 30;
    }

    /**
     * Gets the domain string to use as an argument of HELO/EHLO command when making test connections to SMTP servers
     *
     * @return string
     */
    public function getHelloDomain()
    {
        return $this->helloDomain;
    }

    /**
     * Sets the domain string to use as an argument of HELO/EHLO command when making test connections to SMTP servers
     *
     * @param string $helloDomain
     */
    public function setHelloDomain($helloDomain)
    {
        if (is_string($helloDomain) && !empty($helloDomain)) {
            $this->helloDomain = $helloDomain;
        }
    }

    /**
     * Gets the string to be used as sender when making test connections to SMTP servers.
     *
     * @return string
     */
    public function getMailFrom()
    {
        return $this->mailFrom;
    }

    /**
     * Sets the string to be used as sender when making test connections to SMTP servers.
     *
     * @param string $mailFrom
     */
    public function setMailFrom($mailFrom)
    {
        if (is_string($mailFrom) && !empty($mailFrom)) {
            $this->mailFrom = $mailFrom;
        }
    }

    /**
     * Checks if required level of verification has been achieved.
     *
     * @return bool TRUE if validation is complete.
     */
    private function validationLevelComplete()
    {
        $this->currentLevel = $this->validationLevel === $this->currentLevel
            ? AddressValidationLevel::OK
            : AddressValidationLevel::nextLevel($this->currentLevel);
        return ($this->currentLevel === AddressValidationLevel::OK);
    }

    /**
     * Verifies a single e-mail email for correct syntax and, optionally, checks it for existence.
     *
     * @param string $email The e-mail email to check. Must be somewhat like "user@domain.tld".
     * @return int          AddressValidationLevel::OK if the validation succeeded, or the particular
     *                      validation level at which the verification failed.
     *
     * @throws Exception
     * @see AddressValidationLevel
     */
    public function verify($email)
    {
        $this->currentLevel = AddressValidationLevel::SyntaxCheck;

        if (!is_string($email) || empty($email)) {
            throw new InvalidArgumentException('Email must be a valid email address');
        }

        if (Utils::checkEmail($email, false)) {
            if ($this->validationLevelComplete()) {
                return AddressValidationLevel::OK;
            }

            $domain = Utils::extractDomainFromEmail($email);
            $mxHosts = Utils::getMxHosts($domain);
            if (empty($mxHosts)) {
                return $this->currentLevel;
            }

            if ($this->validationLevelComplete()) {
                return AddressValidationLevel::OK;
            }

            foreach ($mxHosts as $host) {
                if ($this->verifyMxHost($host, $domain, $email)) {
                    return AddressValidationLevel::OK;
                }
            }
        }

        return $this->currentLevel;
    }

    /**
     * Output debugging
     *
     * @param string $msg Debug string to output
     * @param int $level The debug level of this message.
     */
    protected function log($msg, $level)
    {
        if ($this->logger !== null) {
            $this->logger->log($msg, $level);
        }
    }

    /**
     * @return DebugLogger
     */
    public function getLogger()
    {
        return $this->logger;
    }

    /**
     * @param DebugLogger $logger
     */
    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    /**
     * Convenience method for email verification.
     *
     * @param string $email The email address to verify
     * @param int $levelValidated AddressValidationLevel::OK if succeeded, or the particular
     *                                  validation level at which the verification failed.
     * @param null $mailFrom Sender for making test connections to SMTP MX servers
     * @param null $helloDomain Domain for making test connections to SMTP MX servers
     * @param int $timeout Socket timeout in seconds (default 30)
     * @param int $validationRequired Level of verification required (default AddressValidationLevel::SendAttempt)
     * @return bool                     TRUE if validation succeeded
     * @throws Exception
     */
    public static function validate(
        $email,
        &$levelValidated,
        $validationRequired = AddressValidationLevel::SendAttempt,
        $mailFrom = null,
        $helloDomain = null,
        $timeout = 30
    ) {
        $verifier = new self();
        $verifier->setMailFrom($mailFrom);
        $verifier->setHelloDomain($helloDomain);
        $verifier->setTimeout($timeout);
        $verifier->setValidationLevel($validationRequired);
        $levelValidated = $verifier->verify($email);
        return ($levelValidated === AddressValidationLevel::OK);
    }

    /**
     * @param string $mx_host
     * @param string $domain
     * @param string $email
     * @return bool
     * @throws Exception
     */
    private function verifyMxHost($mx_host, $domain, $email)
    {
        $domain = $this->helloDomain ?? $domain;
        $mailFrom = $this->mailFrom ?? 'user@' . $domain;

        $smtp = new SmtpConnection();
        $smtp->setDebugLevel(5);
        $smtp->connect($mx_host, 25, $this->timeout);

        if (!$smtp->connected()) {
            return false;
        }

        if ($this->validationLevelComplete()) {
            // AddressValidationLevel::SmtpConnection completed
            $this->mxTransferLogs[$mx_host] = $smtp->transferLogs;
            $smtp->close();
            return true;
        }

        $success = ($smtp->hello($domain) && $smtp->mail($mailFrom) && $smtp->recipient($email));
        $smtp->quit(true);
        $this->mxTransferLogs[$mx_host] = $smtp->transferLogs;
        return $success;
    }
}
