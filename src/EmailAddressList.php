<?php declare(strict_types=1);

namespace VerifyEmail;

use Countable;
use InvalidArgumentException;
use Iterator;
use RuntimeException;

final class EmailAddressList implements Countable, Iterator
{
    /**
     * List of Address objects we're managing
     *
     * @var array
     */
    private $addresses = [];

    /**
     * Add an address to the list
     *
     * @param string|EmailAddress $emailOrAddress
     * @return EmailAddressList
     * @throws InvalidArgumentException
     */
    public function add($emailOrAddress): EmailAddressList
    {
        if (is_string($emailOrAddress)) {
            $emailOrAddress = $this->createAddress($emailOrAddress);
        }

        if (!$emailOrAddress instanceof EmailAddress) {
            throw new InvalidArgumentException(sprintf(
                '%s expects an email address or %s\Address object as its first argument; received "%s"',
                __METHOD__,
                __NAMESPACE__,
                (is_object($emailOrAddress) ? get_class($emailOrAddress) : gettype($emailOrAddress))
            ));
        }

        $email = strtolower($emailOrAddress->getEmail());
        if ($this->has($email)) {
            return $this;
        }

        $this->addresses[$email] = $emailOrAddress;
        return $this;
    }

    /**
     * Add many addresses at once
     *
     * If an email key is provided, it will be used as the email, and the value
     * as the name. Otherwise, the value is passed as the sole argument to add(),
     * and, as such, can be either email strings or Address\AddressInterface objects.
     *
     * @param array $addresses
     * @return EmailAddressList
     * @throws RuntimeException
     */
    public function addMany(array $addresses): EmailAddressList
    {
        foreach ($addresses as $key => $value) {
            if (is_int($key) || is_numeric($key)) {
                $this->add($value);
                continue;
            }

            if (!is_string($key)) {
                throw new RuntimeException(sprintf(
                    'Invalid key type in provided addresses array ("%s")',
                    (is_object($key) ? get_class($key) : var_export($key, 1))
                ));
            }

            $this->add($key);
        }
        return $this;
    }

    /**
     * Merge another address list into this one
     *
     * @param EmailAddressList $addressList
     * @return EmailAddressList
     */
    public function merge(EmailAddressList $addressList)
    {
        foreach ($addressList as $address) {
            $this->add($address);
        }
        return $this;
    }

    /**
     * Does the email exist in this list?
     *
     * @param string $email
     * @return bool
     */
    public function has(string $email): bool
    {
        $email = strtolower($email);
        return isset($this->addresses[$email]);
    }

    /**
     * Get an address by email
     *
     * @param string $email
     * @return bool|EmailAddress
     */
    public function get(string $email)
    {
        $email = strtolower($email);
        if (!isset($this->addresses[$email])) {
            return false;
        }

        return $this->addresses[$email];
    }

    /**
     * Delete an address from the list
     *
     * @param string $email
     * @return bool
     */
    public function delete(string $email): bool
    {
        $email = strtolower($email);
        if (!isset($this->addresses[$email])) {
            return false;
        }

        unset($this->addresses[$email]);
        return true;
    }

    /**
     * Return count of addresses
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->addresses);
    }

    /**
     * Rewind iterator
     *
     * @return mixed the value of the first addresses element, or false if the addresses is
     * empty.
     * @see addresses
     */
    public function rewind()
    {
        return reset($this->addresses);
    }

    /**
     * Return current item in iteration
     *
     * @return EmailAddress
     */
    public function current(): EmailAddress
    {
        return current($this->addresses);
    }

    /**
     * Return key of current item of iteration
     *
     * @return string
     */
    public function key(): string
    {
        return key($this->addresses);
    }

    /**
     * Move to next item
     *
     * @return mixed the addresses value in the next place that's pointed to by the
     * internal array pointer, or false if there are no more elements.
     * @see addresses
     */
    public function next()
    {
        return next($this->addresses);
    }

    /**
     * Is the current item of iteration valid?
     *
     * @return bool
     */
    public function valid(): bool
    {
        $key = key($this->addresses);
        return ($key !== null && $key !== false);
    }

    /**
     * Create an address object
     *
     * @param string $email
     * @return EmailAddress
     */
    protected function createAddress(string $email): EmailAddress
    {
        return new EmailAddress($email);
    }
}