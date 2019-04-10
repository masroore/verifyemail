<?php declare(strict_types=1);

namespace VerifyEmail;

use InvalidArgumentException;
use Pdp\Domain;
use Psr\SimpleCache\CacheInterface;

final class Blacklist
{
    private $emails = [];
    private $domains = [];
    private $cache;

    /**
     * Blacklist constructor.
     * @param CacheInterface $cache
     */
    public function __construct(CacheInterface $cache)
    {
        $this->cache = $cache;
    }

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

    private function canonizeEmail(string $email): string
    {
        return (new EmailAddress($email))->getEmail();
    }

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

    /**
     * Check if IPv4 address is blacklisted
     * This should be called only where absolutely necessary
     *
     * Only IPv4 (rbldns does not support AAAA records/IPv6 lookups)
     *
     * @param string $ip the IPv4 address to check
     * @return bool|array   FALSE if ip is not blacklisted, else an array([checked server], [lookup])
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function checkRblDns(string $ip)
    {
        if (!is_string($ip) || empty($ip)) {
            throw new InvalidArgumentException('IP must be a valid IPv4 address');
        }

        $quads = explode('.', $ip);
        $reverse_ip = sprintf('%s.%s.%s.%s', $quads[3], $quads[2], $quads[1], $quads[0]);

        $cacheKey = "rbl:$reverse_ip";
        if ($this->cache->has($cacheKey)) {
            return $this->cache->get($cacheKey);
        }

        // neither spamhaus nor spamcop supports IPv6 addresses
        if (strpos($ip, ':') !== false) {
            $this->cache->set($cacheKey, false);
            return false;
        }

        $rbldns_servers = [
            'sbl.spamhaus.org' => 'http://www.spamhaus.org/query/bl?ip=',
            'bl.spamcop.net' => 'http://spamcop.net/bl.shtml?',
        ];

        // Need to be listed on all servers...
        $listed = true;
        $info = [];

        foreach ($rbldns_servers as $server => $lookup) {
            $host = sprintf('%s.%s.', $reverse_ip, $server);
            if (Utils::checkDnsRecords($host, 'A') === true) {
                $info = [$server, $lookup . $ip];
            } else {
                $listed = false;
            }
        }

        if ($listed) {
            $this->cache->set($cacheKey, $info);
            return $info;
        }

        $this->cache->set($cacheKey, false);
        return false;
    }
}
