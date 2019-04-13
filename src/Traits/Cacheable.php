<?php declare(strict_types=1);

namespace VerifyEmail\Traits;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

trait Cacheable
{
    /**
     * @var CacheInterface
     */
    private $_cache;

    private function cacheInit(CacheInterface $cache): void
    {
        $this->_cache = $cache;
    }

    /**
     * @param string $key
     * @param null $default
     * @return mixed
     * @throws InvalidArgumentException
     */
    private function cacheGet(string $key, $default = null)
    {
        return $this->_cache->get($key, $default);
    }

    /**
     * @param string $key
     * @param $value
     * @param null $ttl
     * @return bool
     * @throws InvalidArgumentException
     */
    private function cacheSet(string $key, $value, $ttl = null): bool
    {
        return $this->_cache->set($key, $value, $ttl);
    }

    /**
     * @param string $key
     * @return bool
     * @throws InvalidArgumentException
     */
    private function cacheHas(string $key): bool
    {
        return $this->_cache->has($key);
    }
}
