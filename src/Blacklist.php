<?php declare(strict_types=1);

namespace VerifyEmail;

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
        $host = $this->canonizeDomain($domain);
        if (!$this->hasDomain($host)) {
            $this->domains[] = $host;
        }
    }

    /**
     * @param array $items
     */
    public function setBannedEmails(array $items): void
    {
        if (is_array($items)) {
            $items = array_map(function ($x) {
                return $this->canonizeEmail($x);
            }, $items);
            $this->emails = array_unique($items);
        }
    }

    /**
     * @param array $items
     */
    public function setBannedDomains(array $items): void
    {
        if (is_array($items)) {
            $items = array_map(function ($x) {
                return $this->canonizeDomain($x);
            }, $items);
            $this->domains = array_unique($items);
        }
    }

    /**
     * @param string|EmailAddress $addr
     * @return string
     */
    private function canonizeEmail($addr): string
    {
        $email = ($addr instanceof EmailAddress) ? $addr : new EmailAddress($addr);
        return mb_strtolower($email->getEmail());
    }

    /**
     * @param string|Domain $addr
     * @return string
     */
    private function canonizeDomain($addr): string
    {
        $domain = ($addr instanceof Domain) ? $addr : new Domain($addr);
        return mb_strtolower($domain->toAscii()->getContent());
    }

    /**
     * @param string|EmailAddress $email
     */
    public function banEmail($email): void
    {
        $address = $this->canonizeEmail($email);
        if (!$this->hasEmail($address)) {
            $this->emails[] = $address;
        }
    }

    /**
     * Checks whether the supplied email or the domain is not blacklisted
     *
     * @param string|EmailAddress $email
     * @return bool TRUE if email is not in blacklist
     */
    public function emailAllowed($email): bool
    {
        $addr = ($email instanceof EmailAddress) ? $email : new EmailAddress($email);
        return $this->domainAllowed($addr->getDomain()) && !$this->emailBanned($addr);
    }

    /**
     * Checks whether the supplied domain name is not blacklisted
     *
     * @param string|Domain $domain
     * @return bool TRUE if domain is not in blacklist
     */
    public function domainAllowed($domain): bool
    {
        return !$this->domainBanned($domain);
    }

    /**
     * Checks if domain exists in the ban list
     *
     * @param string|Domain $addr
     * @return bool
     */
    public function domainBanned($addr): bool
    {
        return $this->hasDomain($this->canonizeDomain($addr));
    }

    /**
     * Checks if the email address exists in the ban list
     *
     * @param string|EmailAddress $addr
     * @return bool
     */
    public function emailBanned($addr): bool
    {
        return $this->hasEmail($this->canonizeEmail($addr));
    }

    /**
     * Checks if domain exists in the ban list
     *
     * @param string $addr
     * @return bool
     */
    private function hasDomain(string $addr): bool
    {
        return in_array($addr, $this->domains, false);
    }

    /**
     * Checks if the email address exists in the ban list
     *
     * @param string $addr
     * @return bool
     */
    private function hasEmail(string $addr): bool
    {
        return in_array($addr, $this->emails, false);
    }
}
