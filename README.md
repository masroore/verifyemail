# VerifyEmail: PHP Email Address Verifier

Tired of those pesky fake email addresses in your submission forms?

`EmailAddressVerifier` class lets you verify e-mail addresses for correct syntax and, optionally, for existence.

The following validation levels can be set with `EmailAddressVerifier::validationLevel` property (defined by `AddressValidationLevel` class):

- **SyntaxCheck** - validate email address by performing syntax check.
- **DnsQuery** - DNS MX lookup for domain part of the the e-mail address string, to find out the SMTP MX host responsible for e-mail delivery to the domain.
- **SmtpConnection** - test connection to the SMTP MX host.
- **SendAttempt** - test connection, sending `EHLO/HELO` and `MAIL FROM` commands, and submitting the given e-mail address string in `RCPT TO` command. This mimics normal send attempt, just without sending actual message data. If the server accepts the recipient and says "Yes, I'm ready to receive message data", the component just resets the connection and disconnects, reporting that the address is correct.

### How to install (using composer):
Install using composer...
```
composer require "masroore/verifyemail"
```

In plain old PHP:

```php
require 'vendor/autoload.php';
```

## Usage basics: Check email address 
To perform PHP email validation, import the `VerifyEmail` namespace in your code:

```php
use VerifyEmail\EmailAddressVerifier;
use VerifyEmail\Utils;
```

To verify an e-mail address in your PHP project, use `EmailAddressVerifier::verify()` method.

By default, EmailAddressVerifier.validationLevel is already SendAttempt (the most advanced e-mail address check available). Therefore we don't need to explicitly set this mode to perform all the checks possible against an e-mail address.

```php
$verifier = new EmailAddressVerifier();
$verifier->setMailFrom('sender@domain.tld');
$verifier->setHelloDomain('domain.tld');
$verifier->setValidationLevel(AddressValidationLevel::SendAttempt);
$result = $verifier->verify('check_email@domain.tld');

if ($result === AddressValidationLevel::OK) {
    echo 'Email verified';
}
```

The previous sample checked valid email address by instantiating the `EmailAddressVerifier` object. For quick form validation in your PHP project you may use the `EmailAddressVerifier::validate()` convenience method instead:  

```php
$level = null;
if (EmailAddressVerifier::validate($email, $level)) {
    echo 'Email verified';
}
```

PHP email checker, email tester, email verifier, email validation, check email address, verify email address, free email verifier, test email address, valid email address
