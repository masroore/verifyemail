<?php declare(strict_types=1);

namespace VerifyEmail;

use InvalidArgumentException;
use Pdp\Domain;
use VerifyEmail\Traits\CanonizeDomain;
use Zend\Validator\EmailAddress as EmailAddressValidator;
use Zend\Validator\Hostname;

final class EmailAddress
{
    use CanonizeDomain;
    /**
     * @var string
     */
    private $email;

    /**
     * @var Domain
     */
    private $domain;

    /**
     * Address constructor.
     * @param string $email
     */
    public function __construct(string $email)
    {
        $email = trim($email);
        if (!is_string($email) || empty($email)) {
            throw new InvalidArgumentException('Email must be a valid email address');
        }

        $validator = new EmailAddressValidator(Hostname::ALLOW_DNS | Hostname::ALLOW_LOCAL | Hostname::ALLOW_IP);
        if (!$validator->isValid($email)) {
            $invalidMessages = $validator->getMessages();
            throw new InvalidArgumentException(array_shift($invalidMessages));
        }

        $this->email = $email;
        $this->setDomainFromEmail($email);
    }

    /**
     * Retrieve email
     *
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * Retrieve domain
     *
     * @return Domain
     */
    public function getDomain(): Domain
    {
        return $this->domain;
    }

    /**
     * Retrieve ASCII domain
     *
     * @return string
     */
    public function canonizedDomain(): string
    {
        return self::canonizeDomain($this->domain);
    }

    private function setDomainFromEmail(string $email): void
    {
        $pos = strrpos($email, '@');
        if (false !== $pos) {
            $domain = substr($email, ++$pos);
            $this->domain = new Domain($domain);
        }
    }
}
