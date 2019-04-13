<?php declare(strict_types=1);

namespace VerifyEmail\Traits;

use Pdp\Domain;

trait CanonizeDomain
{
    /**
     * @param string|Domain $addr
     * @return string
     */
    public static function canonizeDomain($addr): string
    {
        $domain = ($addr instanceof Domain) ? $addr : new Domain($addr);
        return mb_strtolower($domain->toAscii()->getContent());
    }
}
