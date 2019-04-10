<?php declare(strict_types=1);

namespace VerifyEmail;

use Pdp\Domain;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

class DnsResolver
{
    /**
     * @var CacheInterface
     */
    private $cache;

    /**
     * @var bool
     */
    private static $dnsSupported;

    /**
     * DnsResolver constructor.
     *
     * @param CacheInterface $cache
     */
    public function __construct(CacheInterface $cache)
    {
        $this->cache = $cache;
    }

    /**
     * @param string $domain
     * @return string
     */
    public static function canonizeDomainName(string $domain): string
    {
        $domain = rtrim($domain, '.') . '.';
        return strtolower($domain);
    }

    /**
     * Get MX hosts for the given email address
     *
     * @param string|EmailAddress $email
     * @return array
     * @throws InvalidArgumentException
     */
    public function getMxHostsForEmail($email): array
    {
        if (is_string($email)) {
            $d = new Domain(Utils::extractDomainFromEmail($email));
            $domain = $d->toAscii()->getContent();
        } elseif ($email instanceof EmailAddress) {
            $domain = $email->canonizedDomain();
        }

        return $this->getMxHostsForDomain($domain);
    }

    /**
     * Get MX hosts for the given domain
     *
     * @param string $domain
     * @return array
     * @throws InvalidArgumentException
     */
    public function getMxHostsForDomain(string $domain): array
    {
        if (!is_string($domain) || empty($domain)) {
            throw new \InvalidArgumentException('Domain must be a valid host address');
        }

        if (!self::dnsSupported()) {
            return [];
        }

        $domain = self::canonizeDomainName($domain);
        $cacheKey = "domain:$domain";
        if ($this->cache->has($cacheKey)) {
            return $this->cache->get($cacheKey);
        }

        if (checkdnsrr($domain, 'MX') === false) {
            $this->cache->set($domain, []);
            return [];
        }

        $mx_hosts = $mx_weights = [];
        getmxrr($domain, $mx_hosts, $mx_weights);

        // put the records together in an associative array that we can sort
        $mx_records = array_combine($mx_hosts, $mx_weights);

        // sort them
        asort($mx_records);

        $sorted_hosts = array_keys($mx_records);
        $this->cache->set($cacheKey, $sorted_hosts);

        return $sorted_hosts;
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
     * Check if IPv4 address is blacklisted
     * This should be called only where absolutely necessary
     *
     * Only IPv4 (rbldns does not support AAAA records/IPv6 lookups)
     *
     * @param string $ip the IPv4 address to check
     * @return bool|array FALSE if ip is not blacklisted, else an array([checked server], [lookup])
     * @throws InvalidArgumentException
     */
    public function checkRblDns(string $ip)
    {
        if (!is_string($ip) || empty($ip)) {
            throw new \InvalidArgumentException('IP must be a valid IPv4 address');
        }

        $quads = array_map('intval', explode('.', $ip));
        $reverse_ip = implode('.', array_reverse($quads));

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
