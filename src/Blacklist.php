<?php declare(strict_types=1);

namespace VerifyEmail;

use InvalidArgumentException;
use Pdp\Domain;

final class Blacklist
{
    /**
     * @var array
     */
    private $emails = [];

    /**
     * @var array
     */
    private $domains = [];

    /**
     * @param string|Domain $domain
     */
    public function banDomain($domain): void
    {
        if ($domain instanceof Domain) {
            $host = $domain->toAscii()->getContent();
        } else {
            if (!is_string($domain) || empty($domain)) {
                throw new InvalidArgumentException('Domain must be a valid host name');
            }
            $host = $this->canonizeDomain($domain);
        }

        if (!in_array($host, $this->domains, true)) {
            $this->domains[] = $host;
        }
    }

    /**
     * @param string $email
     * @return string
     */
    private function canonizeEmail(string $email): string
    {
        return (new EmailAddress($email))->getEmail();
    }

    /**
     * @param string $domain
     * @return string
     */
    private function canonizeDomain(string $domain): string
    {
        return (new Domain($domain))->toAscii()->getContent();
    }

    /**
     * @param string|EmailAddress $email
     */
    public function banEmail($email): void
    {
        if ($email instanceof EmailAddress) {
            $address = $email->getEmail();
        } else {
            if (!is_string($email) || empty($email)) {
                throw new InvalidArgumentException('Email must be a valid email address');
            }
            $address = $this->canonizeEmail($email);
        }

        if (!in_array($address, $this->emails, true)) {
            $this->emails[] = $address;
        }
    }

    /**
     * Checks whether the supplied email is not blacklisted
     *
     * @param string $email
     * @return bool TRUE if email is not in blacklist
     */
    public function emailAllowed(string $email): bool
    {
        $email = $this->canonizeEmail($email);
        return !in_array($email, $this->emails, true);
    }

    /**
     * Checks whether the supplied domain name is not blacklisted
     *
     * @param string $domain
     * @return bool TRUE if domain is not in blacklist
     */
    public function domainAllowed(string $domain): bool
    {
        $domain = $this->canonizeDomain($domain);
        return !in_array($domain, $this->domains, true);
    }
}
