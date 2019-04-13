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

    public const MAX_RECIPIENTS_PER_CONNECTION = 50;

    public const DEFAULT_TIMEOUT = 30;

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
     * Maximum number of recipients per SMTP connection
     *
     * @var int
     */
    private $maxRecipientsPerConnection;

    /**
     * The amount of time (in seconds) to wait for a response from the SMTP server.
     *
     * @var int
     */
    private $timeout;

    /**
     * Gets the level of deepness of e-mail address verification.
     *
     * @return int
     *
     * @see AddressValidationLevel
     */
    public function getValidationLevel(): int
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
    public function setValidationLevel($validationLevel): void
    {
        AddressValidationLevel::boundsCheck($validationLevel);
        $this->validationLevel = $validationLevel;
    }

    /**
     * @return int
     */
    public function getMaxRecipientsPerConnection(): int
    {
        return $this->maxRecipientsPerConnection;
    }

    /**
     * @param int $value
     */
    public function setMaxRecipientsPerConnection(int $value): void
    {
        $this->maxRecipientsPerConnection = $value;
    }

    /**
     * @return int
     */
    public function getTimeout(): int
    {
        return $this->timeout;
    }

    /**
     * @param int $timeout
     */
    public function setTimeout(int $timeout): void
    {
        $this->timeout = $timeout;
    }

    /**
     * EmailAddressVerifier constructor.
     */
    public function __construct()
    {
        // The default validation level is SendAttempt (maximum level of verification)
        $this->validationLevel = AddressValidationLevel::SendAttempt;
        $this->maxRecipientsPerConnection = self::MAX_RECIPIENTS_PER_CONNECTION;
        $this->timeout = self::DEFAULT_TIMEOUT;
    }

    /**
     * Gets the domain string to use as an argument of HELO/EHLO command when making test connections to SMTP servers
     *
     * @return string|null
     */
    public function getHelloDomain(): ?string
    {
        return $this->helloDomain;
    }

    /**
     * Sets the domain string to use as an argument of HELO/EHLO command when making test connections to SMTP servers
     *
     * @param string|null $helloDomain
     */
    public function setHelloDomain($helloDomain): void
    {
        if (is_string($helloDomain) && !empty($helloDomain)) {
            $this->helloDomain = $helloDomain;
        }
    }

    /**
     * Gets the string to be used as sender when making test connections to SMTP servers.
     *
     * @return string|null
     */
    public function getMailFrom(): ?string
    {
        return $this->mailFrom;
    }

    /**
     * Sets the string to be used as sender when making test connections to SMTP servers.
     *
     * @param string|null $mailFrom
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
    private function validationLevelComplete(): bool
    {
        $this->currentLevel = $this->validationLevel === $this->currentLevel
            ? AddressValidationLevel::OK
            : AddressValidationLevel::nextLevel($this->currentLevel);
        return ($this->currentLevel === AddressValidationLevel::OK);
    }

    /**
     * Checks if required level of verification has been achieved.
     *
     * @param int $level
     * @return bool TRUE if validation is complete.
     */
    private function checkValidationLevelCompletion(int &$level): bool
    {
        $level = $this->validationLevel === $level
            ? AddressValidationLevel::OK
            : AddressValidationLevel::nextLevel($level);
        return ($level === AddressValidationLevel::OK);
    }

    /**
     * Verifies a single e-mail email for correct syntax and, optionally, checks it for existence.
     *
     * @param string $email The e-mail email to check. Must be somewhat like "user@domain.tld".
     * @return int          AddressValidationLevel::OK if the validation succeeded, or the particular
     *                      validation level at which the verification failed.
     * @throws Exception
     * @see AddressValidationLevel
     */
    public function verify(string $email): int
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
     * @param array $emailsToVerify
     * @return array
     */
    public function verifyBulk(array $emailsToVerify): array
    {
        $collection = new EmailAddressCollection();
        $collection->addMany($emailsToVerify);
        $result = [];

        foreach ($collection->getDomains() as $domain) {
            $domainEmails = $collection->getEmailsInDomain($domain);

            if (empty($domainEmails)) {
                continue;
            }

            $currentLevel = AddressValidationLevel::SyntaxCheck;
            $validEmails = array_filter($domainEmails, static function ($x) {
                return Utils::checkEmail($x, false);
            });

            if ($this->checkValidationLevelCompletion($currentLevel)) {
                self::setBulkResults(AddressValidationLevel::OK, $validEmails, $result);
                break;
            }

            $mxHosts = Utils::getMxHosts($domain);
            if (empty($mxHosts)) {
                self::setBulkResults($currentLevel, $validEmails, $result);
                break;
            }

            if ($this->checkValidationLevelCompletion($currentLevel)) {
                self::setBulkResults(AddressValidationLevel::OK, $validEmails, $result);
                break;
            }

            foreach ($mxHosts as $host) {
                if ($this->verifyMxHostBulk($host, $domain, $currentLevel, $validEmails, $result)) {
                    break;
                }
            }
        }

        return $result;
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
    private function verifyMxHost(string $mx_host, string $domain, string $email): bool
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

    /**
     * @param int $currentLevel
     * @param array $emails
     * @param array $result
     * @return array
     */
    private static function setBulkResults(int $currentLevel, array $emails, array &$result): array
    {
        foreach ($emails as $email) {
            $result[$email] = $currentLevel;
        }
        return $result;
    }

    /**
     * @param string $mx_host
     * @param string $domain
     * @param int $currentLevel
     * @param array $emails
     * @param array $result
     * @return bool
     */
    private function verifyMxHostBulk(string $mx_host, string $domain, int &$currentLevel, array $emails, array &$result): bool
    {
        $domain = $this->helloDomain ?? $domain;
        $mailFrom = $this->mailFrom ?? 'user@' . $domain;

        $smtp = new SmtpConnection();
        $smtp->setDebugLevel(5);
        $smtp->connect($mx_host, 25, $this->timeout);

        if (!$smtp->connected()) {
            self::setBulkResults($currentLevel, $emails, $result);
            return false;
        }

        if ($this->checkValidationLevelCompletion($currentLevel)) {
            // AddressValidationLevel::SmtpConnection completed
            self::setBulkResults($currentLevel, $emails, $result);
            $this->mxTransferLogs[$mx_host] = $smtp->transferLogs;
            $smtp->close();
            return true;
        }

        $success = ($smtp->hello($domain) && $smtp->mail($mailFrom));
        if (!$success) {
            self::setBulkResults($currentLevel, $emails, $result);
            $this->mxTransferLogs[$mx_host] = $smtp->transferLogs;
            $smtp->close();
            return false;
        }

        if (count($emails) > $this->maxRecipientsPerConnection) {
            $partitions = array_chunk($emails, $this->maxRecipientsPerConnection);
        }

        foreach ($emails as $email) {
            $result[$email] = $smtp->recipient($email) ? AddressValidationLevel::OK : $currentLevel;
        }

        $smtp->quit(true);
        $this->mxTransferLogs[$mx_host] = $smtp->transferLogs;
        return true;
    }
}
