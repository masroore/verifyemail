<?php declare(strict_types=1);

namespace VerifyEmail\Traits;

use VerifyEmail\EmailAddress;

trait CanonizeEmail
{
    /**
     * @param string|EmailAddress $addr
     * @return string
     */
    public static function canonizeEmail($addr): string
    {
        $email = ($addr instanceof EmailAddress) ? $addr : new EmailAddress($addr);
        return mb_strtolower($email->getEmail());
    }
}
