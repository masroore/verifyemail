<?php declare(strict_types=1);

namespace VerifyEmail;

use InvalidArgumentException;
use Pdp\Domain;
use Zend\Validator\EmailAddress;
use Zend\Validator\Hostname;

final class Address
{
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
        $emailAddressValidator = new EmailAddress(Hostname::ALLOW_DNS | Hostname::ALLOW_LOCAL | Hostname::ALLOW_IP);
        if (!is_string($email) || empty($email)) {
            throw new InvalidArgumentException('Email must be a valid email address');
        }

        if (preg_match("/[\r\n]/", $email)) {
            throw new InvalidArgumentException('CRLF injection detected');
        }

        if (!$emailAddressValidator->isValid($email)) {
            $invalidMessages = $emailAddressValidator->getMessages();
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
     * @return string
     */
    public function getDomain(): string
    {
        return $this->domain->toAscii()->getContent();
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
