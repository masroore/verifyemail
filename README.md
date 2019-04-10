##VerifyEmail

Tired of those pesky fake email addresses in your submission forms?

`EmailAddressVerifier` class lets you verify e-mail addresses for correct syntax and, optionally, for existence.

The following validation levels can be set with `EmailAddressVerifier::validationLevel` property (defined by `AddressValidationLevel` class):

- **SyntaxCheck** - syntax check of the e-mail address string.
- **DnsQuery** - DNS MX lookup for domain part of the the e-mail address string, to find out the SMTP MX host responsible for e-mail delivery to the domain.
- **SmtpConnection** - test connection to the SMTP MX host.
- **SendAttempt** - test connection, sending EHLO/HELO and MAIL FROM commands, and submitting the given e-mail address string in RCPT TO command. This mimics normal send attempt, just without sending actual message data. If the server accepts the recipient and says "Yes, I'm ready to receive message data", the component just resets the connection and disconnects, reporting that the address is correct.

## How to install (using composer):
Install using composer...
```
composer require "masroore/verifyemail"
```

### In plain old PHP
```php
require_once("vendor/autoload.php");
```

## Usage basics

```php
$verifier = new EmailAddressVerifier();
$verifier->setMailFrom('sender@domain.tld');
$verifier->setHelloDomain('domain.tld');
$verifier->setValidationLevel(AddressValidationLevel::SendAttempt);
$result = $verifier->verify('check@domain.tld');
if ($result === AddressValidationLevel::OK) {
    echo 'Email verified';
}
```

Using convenience function `EmailAddressVerifier::validate()` to validate email address:

```php
$level = null;
if (EmailAddressVerifier::validate($email, $level)) {
    echo 'Email verified';
}
```