<?php


namespace VerifyEmail;

use Psr\Log\LoggerInterface;

class SmtpConnection
{
    /**
     * SMTP line break constant.
     *
     * @var string
     */
    const CRLF = "\r\n";

    /**
     * The SMTP port to use if one is not specified.
     *
     * @var int
     */
    const DEFAULT_PORT = 25;

    /**
     * The maximum line length allowed by RFC 2822 section 2.1.1.
     *
     * @var int
     */
    const MAX_LINE_LENGTH = 998;

    /**
     * The socket for the server connection.
     *
     * @var ?resource
     */
    protected $socket;

    /**
     * Debug level for no output.
     */
    const DEBUG_OFF = 0;

    /**
     * Debug level to show client -> server messages.
     */
    const DEBUG_CLIENT = 1;

    /**
     * Debug level to show client -> server and server -> client messages.
     */
    const DEBUG_SERVER = 2;

    /**
     * Debug level to show connection status, client -> server and server -> client messages.
     */
    const DEBUG_CONNECTION = 3;

    /**
     * Debug level to show all messages.
     */
    const DEBUG_LOWLEVEL = 4;

    /**
     * Debug output level.
     * Options:
     * * self::DEBUG_OFF (`0`) No debug output, default
     * * self::DEBUG_CLIENT (`1`) Client commands
     * * self::DEBUG_SERVER (`2`) Client commands and server responses
     * * self::DEBUG_CONNECTION (`3`) As DEBUG_SERVER plus connection status
     * * self::DEBUG_LOWLEVEL (`4`) Low-level data output, all messages.
     *
     * @var int
     */
    private $debugLevel = self::DEBUG_OFF;

    /**
     * How to handle debug output.
     * Options:
     * * `echo` Output plain-text as-is, appropriate for CLI
     * * `html` Output escaped, line breaks converted to `<br>`, appropriate for browser output
     * * `error_log` Output to error log as configured in php.ini
     * Alternatively, you can provide a callable expecting two params: a message string and the debug level:
     *
     * ```php
     * $smtp->debugOutput = function($str, $level) {echo "debug level $level; message: $str";};
     * ```
     *
     * Alternatively, you can pass in an instance of a PSR-3 compatible logger, though only `debug`
     * level output is used:
     *
     * ```php
     * $mail->debugOutput = new myPsr3Logger;
     * ```
     *
     * @var string|callable|LoggerInterface
     */
    public $debugOutput = 'echo';

    public $transferLogs = [];

    /**
     * The timeout value for connection, in seconds.
     * Default of 5 minutes (300sec) is from RFC2821 section 4.5.3.2.
     * This needs to be quite high to function correctly with hosts using greetdelay as an anti-spam measure.
     *
     * @see http://tools.ietf.org/html/rfc2821#section-4.5.3.2
     *
     * @var int
     */
    private $timeout = 300;

    /**
     * How long to wait for commands to complete, in seconds.
     * Default of 5 minutes (300sec) is from RFC2821 section 4.5.3.2.
     *
     * @var int
     */
    private $timeLimit = 300;

    /**
     * The most recent reply received from the server.
     *
     * @var string
     */
    protected $lastReply = '';

    /**
     * @var bool
     */
    private static $hasStreamApi;

    /**
     * Error information, if any, for the last SMTP command.
     *
     * @var array
     */
    private $lastError = [
        'error' => '',
        'detail' => '',
        'smtp_code' => '',
        'smtp_code_ex' => '',
    ];

    /**
     * The set of SMTP extensions sent in reply to EHLO command.
     * Indexes of the array are extension names.
     * Value at index 'HELO' or 'EHLO' (according to command that was sent)
     * represents the server name. In case of HELO it is the only element of the array.
     * Other values can be boolean TRUE or an array containing extension options.
     * If null, no HELO/EHLO string has yet been received.
     *
     * @var array|null
     */
    private $serverCapabilities = null;

    /**
     * Parse SMTP server reply and extract response codes and other details.
     *
     * @param string $response
     * @param string|null $code
     * @param string|null $code_ex
     * @param string|null $detail
     */
    private static function parseResponseCode(string $response, &$code, &$code_ex, &$detail)
    {
        if (preg_match('/^(\d{3})[ -](?:(\d\\.\d\\.\d{1,2}) )?/', $response, $matches)) {
            $code = $matches[1];
            $code_ex = (count($matches) > 2 ? $matches[2] : null);
            // cut off error code from each response line
            $detail = preg_replace(
                "/{$code}[ -]" .
                ($code_ex ? str_replace('.', '\\.', $code_ex) . ' ' : '') . '/m',
                '',
                $response
            );
        } else {
            // fall back to simple parsing if regex fails
            $code = substr($response, 0, 3);
            $code_ex = null;
            $detail = substr($response, 4);
        }
    }

    /**
     * Checks if PHP stream_* function exists
     *
     * @return bool
     */
    private static function hasStreamApi()
    {
        if (null === self::$hasStreamApi) {
            // check this once and cache the result
            self::$hasStreamApi = (bool)function_exists('stream_socket_client');
        }

        return self::$hasStreamApi;
    }

    /**
     * Parse a reply to HELO/EHLO command to discover server extensions.
     * In case of HELO, the only parameter that can be discovered is a server name.
     *
     * @param string $type `HELO` or `EHLO`
     * @param string $heloReply
     */
    protected function parseHelloFields($type, $heloReply)
    {
        $this->serverCapabilities = [];
        $lines = explode("\n", $heloReply);

        foreach ($lines as $n => $s) {
            //First 4 chars contain response code followed by - or space
            $s = trim(substr($s, 4));
            if (empty($s)) {
                continue;
            }
            $fields = explode(' ', $s);
            if (!empty($fields)) {
                if (!$n) {
                    $name = $type;
                    $fields = $fields[0];
                } else {
                    $name = array_shift($fields);
                    switch ($name) {
                        case 'SIZE':
                            $fields = ($fields ? $fields[0] : 0);
                            break;
                        case 'AUTH':
                            if (!is_array($fields)) {
                                $fields = [];
                            }
                            break;
                        default:
                            $fields = true;
                    }
                }
                $this->serverCapabilities[$name] = $fields;
            }
        }
    }


    /**
     * Connect to an SMTP server.
     *
     * @param string $host SMTP server IP or host name
     * @param int $port The port number to connect to
     * @param int $timeout How long to wait for the connection to open
     * @param array $options An array of options for stream_context_create()
     *
     * @return bool
     */
    public function connect($host, $port = null, $timeout = 30, $options = [])
    {
        // make sure we are __not__ connected
        if ($this->connected()) {
            $this->setLastError('Already connected to a server');
            return false;
        }

        $this->setLastError();
        $this->transferLogs = [];

        if ($port === null) {
            $port = self::DEFAULT_PORT;
        }

        $this->log(
            sprintf(
                'Connection: opening to %s:%s, timeout=%s, options=%s',
                $host,
                $port,
                $timeout,
                count($options) > 0 ? var_export($options, true) : '[]'
            ),
            self::DEBUG_CONNECTION
        );

        $errno = 0;
        $errstr = '';

        try {
            set_error_handler([$this, 'errorHandler']);
            if (static::hasStreamApi()) {
                $socket_context = stream_context_create($options);
                $this->socket = stream_socket_client(
                    sprintf('%s:%d', $host, $port),
                    $errno,
                    $errstr,
                    $timeout,
                    STREAM_CLIENT_CONNECT,
                    $socket_context
                );
            } else {
                //Fall back to fsockopen which should work in more places, but is missing some features
                $this->log(
                    'Connection: stream_socket_client not available, falling back to fsockopen',
                    self::DEBUG_CONNECTION
                );
                $this->socket = fsockopen($host, $port, $errno, $errstr, $timeout);
            }
        } finally {
            restore_error_handler();
        }

        // Verify we connected properly
        if (!$this->checkConnection()) {
            $this->setLastError('Failed to connect to server', '', (string)$errno, $errstr);
            $this->log(
                sprintf('SMTP ERROR: %s: %s (%d)', $this->lastError['error'], $errstr, $errno),
                self::DEBUG_CLIENT
            );

            return false;
        }

        $this->log('Connection: opened', self::DEBUG_CONNECTION);

        // SMTP server can take longer to respond, give longer timeout for first read
        // Windows does not have support for this timeout function
        if (stripos(PHP_OS, 'WIN') !== 0) {
            $max = ini_get('max_execution_time');
            // Don't bother if unlimited
            if (0 !== $max && $timeout > $max) {
                @set_time_limit($timeout);
            }
            stream_set_timeout($this->socket, $timeout, 0);
        }

        // get any announcement
        $announce = $this->fetchLinesFromServer();
        $this->log('SERVER -> CLIENT: ' . $announce, self::DEBUG_SERVER);

        $code = $code_ex = $detail = null;
        self::parseResponseCode($announce, $code, $code_ex, $detail);
        $this->transferLogs[] = [
            'command' => '<CONNECT>',
            'response' => $announce,
            'smtp_code' => (int)$code,
            'success' => (int)$code === 220
        ];

        return true;
    }

    /**
     * Check connection state.
     *
     * @return bool True if connected
     */
    public function connected()
    {
        if ($this->checkConnection()) {
            if ((bool)$this->getStreamStatus('eof')) {
                // The socket is valid but we are not connected
                $this->log('SMTP NOTICE: EOF caught while checking if connected', self::DEBUG_CLIENT);
                $this->close();
                return false;
            }

            return true;
        }

        return false;
    }

    /**
     * Checks valid connection.
     *
     * @return bool
     */
    public function checkConnection()
    {
        return is_resource($this->socket);
    }

    /**
     * Close the socket and clean up the state of the class.
     */
    public function close()
    {
        $this->setLastError();
        $this->serverCapabilities = null;
        if ($this->checkConnection()) {
            // close the connection and cleanup
            @fclose($this->socket);
            $this->socket = null; //Makes for cleaner serialization
            $this->log('Connection: closed', self::DEBUG_CONNECTION);
        }
    }

    /**
     * Send data.
     *
     * @param string $message Data.
     * @return  int|bool
     */
    public function send($message)
    {
        set_error_handler([$this, 'errorHandler']);
        $result = fwrite($this->socket, $message);
        restore_error_handler();
        return $result;
    }

    /**
     * Set debug output level.
     *
     * @param int $level
     */
    public function setDebugLevel($level = 0)
    {
        $this->debugLevel = $level;
    }

    /**
     * Get debug output level.
     *
     * @return int
     */
    public function getDebugLevel()
    {
        return $this->debugLevel;
    }

    /**
     * Set debug output method.
     *
     * @param string|callable|LoggerInterface $method The name of the mechanism to use for debugging output,
     *                                                  or a callable/PSR 3 logger to handle it
     */
    public function setDebugOutput($method = null)
    {
        $this->debugOutput = $method;
    }

    /**
     * Get debug output method.
     *
     * @return mixed
     */
    public function getDebugOutput()
    {
        return $this->debugOutput;
    }

    /**
     * Set SMTP timeout.
     *
     * @param int $timeout The timeout duration in seconds
     */
    public function setTimeout($timeout = 0)
    {
        $this->timeout = $timeout;
    }

    /**
     * Get SMTP timeout.
     *
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * Get the last reply from the server.
     *
     * @return string
     */
    public function getLastReply()
    {
        return $this->lastReply;
    }

    /**
     * @param string $key
     * @return mixed
     */
    private function getStreamStatus($key)
    {
        $info = stream_get_meta_data($this->socket);
        return $info[$key];
    }

    /**
     * Read the SMTP server's response.
     * Either before eof or socket timeout occurs on the operation.
     * With SMTP we can tell if we have more lines to read if the
     * 4th character is '-' symbol. If it is a space then we don't
     * need to read anything else.
     *
     * @return string
     */
    protected function fetchLinesFromServer()
    {
        // If the connection is bad, give up straight away
        if (!$this->checkConnection()) {
            return '';
        }

        $data = '';
        $timeout = 0;
        stream_set_timeout($this->socket, $this->timeout);
        if ($this->timeLimit > 0) {
            $timeout = time() + $this->timeLimit;
        }
        $selR = [$this->socket];
        $selW = null;
        while ($this->checkConnection() and !feof($this->socket)) {
            //Must pass vars in here as params are by reference
            if (!stream_select($selR, $selW, $selW, $this->timeLimit)) {
                $this->log(
                    sprintf('SMTP::fetchLinesFromServer(): timed-out (%d sec)', $this->timeout),
                    self::DEBUG_LOWLEVEL
                );
                break;
            }
            //Deliberate noise suppression - errors are handled afterwards
            $str = @fgets($this->socket, 515);
            $this->log(sprintf('SMTP INBOUND: "%s"', trim($str)), self::DEBUG_LOWLEVEL);
            $data .= $str;

            // If response is only 3 chars (not valid, but RFC5321 S4.2 says it must be handled),
            // or 4th character is a space, we are done reading, break the loop,
            // string array access is a micro-optimisation over strlen
            if (!isset($str[3]) || (isset($str[3]) && $str[3] === ' ')) {
                break;
            }

            // Timed-out? Log and break
            if ((bool)$this->getStreamStatus('timed_out')) {
                $this->log(
                    sprintf('SMTP::fetchLinesFromServer(): timed-out (%d sec)', $this->timeout),
                    self::DEBUG_LOWLEVEL
                );
                break;
            }

            // Now check if reads took too long
            if ($timeout && time() > $timeout) {
                $this->log(
                    sprintf('SMTP::fetchLinesFromServer(): timelimit reached (%d sec)', $this->timeLimit),
                    self::DEBUG_LOWLEVEL
                );
                break;
            }
        }

        return $data;
    }

    /**
     * Send a command to an SMTP server and check its return code.
     *
     * @param string $command The command name - not sent to the server
     * @param string $commandRaw The actual command to send
     * @param int|array $expect One or more expected integer success codes
     *
     * @return bool True on success
     */
    protected function sendCommand($command, $commandRaw, $expect)
    {
        if (!$this->connected()) {
            $this->setLastError("Called $command without being connected");
            return false;
        }

        //Reject line breaks in all commands
        if (strpos($commandRaw, "\n") !== false || strpos($commandRaw, "\r") !== false) {
            $this->setLastError("Command '$command' contained line breaks");
            return false;
        }

        $this->sendRaw($commandRaw . static::CRLF, $command);
        $this->lastReply = $this->fetchLinesFromServer();

        // fetch SMTP code and possible error code explanation
        $code = $code_ex = $detail = null;
        self::parseResponseCode($this->lastReply, $code, $code_ex, $detail);
        $success = in_array((int)$code, (array)$expect, true);

        $this->transferLogs[] = [
            'command' => $commandRaw,
            'response' => $this->lastReply,
            'smtp_code' => (int)$code,
            'success' => $success
        ];

        $this->log('SERVER -> CLIENT: ' . $this->lastReply, self::DEBUG_SERVER);

        if (!$success) {
            $this->setLastError("$command command failed", $detail, $code, $code_ex);
            $this->log(
                sprintf('SMTP ERROR: %s: %s', $this->lastError['error'], $this->lastReply),
                self::DEBUG_CLIENT
            );

            return $success;
        }

        $this->setLastError();

        return $success;
    }

    /**
     * Send an SMTP VRFY command.
     *
     * @param string $name The name to verify
     *
     * @return bool
     */
    public function verify($name)
    {
        return $this->sendCommand('VRFY', "VRFY $name", [250, 251]);
    }

    /**
     * Send an SMTP NOOP command.
     * Used to keep keep-alives alive, doesn't actually do anything.
     *
     * @return bool
     */
    public function noop()
    {
        return $this->sendCommand('NOOP', 'NOOP', 250);
    }

    /**
     * Send an SMTP HELO or EHLO command.
     * Used to identify the sending server to the receiving server.
     * This makes sure that client and server are in a known state.
     * Implements RFC 821: HELO <SP> <domain> <CRLF>
     * and RFC 2821 EHLO.
     *
     * @param string $host The host name or IP to connect to
     *
     * @return bool
     */
    public function hello($host = '')
    {
        // try extended hello first (RFC 2821)
        return $this->sendHello('EHLO', $host) or $this->sendHello('HELO', $host);
    }

    /**
     * Send an SMTP HELO or EHLO command.
     * Low-level implementation used by hello().
     *
     * @param string $hello The HELO string
     * @param string $host The hostname to say we are
     *
     * @return bool
     *
     * @see    hello()
     */
    protected function sendHello($hello, $host)
    {
        $result = $this->sendCommand($hello, $hello . ' ' . $host, 250);
        if ($result) {
            $this->parseHelloFields($hello, $this->lastReply);
        } else {
            $this->serverCapabilities = null;
        }

        return $result;
    }

    /**
     * Send an SMTP MAIL command.
     * Starts a mail transaction from the email address specified in
     * $from. Returns true if successful or false otherwise. If True
     * the mail transaction is started and then one or more recipient
     * commands may be called followed by a data command.
     * Implements RFC 821: MAIL <SP> FROM:<reverse-path> <CRLF>.
     *
     * @param string $from Source address of this message
     *
     * @return bool
     */
    public function mail($from)
    {
        return $this->sendCommand('MAIL FROM', sprintf('MAIL FROM:<%s>', $from), 250);
    }

    /**
     * Get the latest error.
     *
     * @return array
     */
    public function getLastError()
    {
        return $this->lastError;
    }

    /**
     * Send an SMTP QUIT command.
     * Closes the socket if there is no error or the $closeConnection argument is true.
     * Implements from RFC 821: QUIT <CRLF>.
     *
     * @param bool $closeConnection Should the connection close?
     *
     * @return bool
     */
    public function quit($closeConnection = true)
    {
        $success = $this->sendCommand('QUIT', 'QUIT', 221);
        $err = $this->lastError; // save any error
        if ($success || $closeConnection) {
            $this->close();
            $this->lastError = $err; // restore any error from the quit command
        }

        return $success;
    }

    /**
     * Send an SMTP RCPT command.
     * Sets the TO argument to $toaddr.
     * Returns true if the recipient was accepted false if it was rejected.
     * Implements from RFC 821: RCPT <SP> TO:<forward-path> <CRLF>.
     *
     * @param string $address The address the message is being sent to
     * @return bool
     */
    public function recipient($address)
    {
        return $this->sendCommand(
            'RCPT TO',
            'RCPT TO:<' . $address . '>',
            [250, 251]
        );
    }

    /**
     * Send an SMTP RSET command.
     * Abort any transaction that is currently in progress.
     * Implements RFC 821: RSET <CRLF>.
     *
     * @return bool True on success
     */
    public function reset()
    {
        return $this->sendCommand('RSET', 'RSET', 250);
    }

    /**
     * Set error messages and codes.
     *
     * @param string $message The error message
     * @param string $detail Further detail on the error
     * @param string $smtp_code An associated SMTP error code
     * @param string $smtp_code_ex Extended SMTP code
     */
    protected function setLastError($message = null, $detail = null, $smtp_code = null, $smtp_code_ex = null)
    {
        $this->lastError = [
            'error' => $message,
            'detail' => $detail,
            'smtp_code' => $smtp_code,
            'smtp_code_ex' => $smtp_code_ex,
        ];
    }

    /**
     * Send raw data to the server.
     *
     * @param string $data The data to send
     * @param string $command Optionally, the command this is part of, used only for controlling debug output
     *
     * @return int|bool The number of bytes sent to the server or false on error
     */
    public function sendRaw($data, $command = '')
    {
        //If SMTP transcripts are left enabled, or debug output is posted online
        //it can leak credentials, so hide credentials in all but lowest level
        if (self::DEBUG_LOWLEVEL > $this->debugLevel &&
            in_array($command, ['User & Password', 'Username', 'Password'], true)) {
            $this->log('CLIENT -> SERVER: <credentials hidden>', self::DEBUG_CLIENT);
        } else {
            $this->log('CLIENT -> SERVER: ' . $data, self::DEBUG_CLIENT);
        }
        return $this->send($data);
    }

    /**
     * Reports an error number and string.
     *
     * @param int $errno The error number returned by PHP
     * @param string $errmsg The error message returned by PHP
     * @param string $errfile The file the error occurred in
     * @param int $errline The line number the error occurred on
     */
    protected function errorHandler($errno, $errmsg, $errfile = '', $errline = 0)
    {
        $notice = 'Connection failed.';
        $this->setLastError($notice, $errmsg, (string)$errno);
        $this->log(
            "$notice Error #$errno: $errmsg [$errfile line $errline]",
            self::DEBUG_CONNECTION
        );
    }

    /**
     * Output debugging info via a user-selected method.
     *
     * @param string $str Debug string to output
     * @param int $level The debug level of this message; see DEBUG_* constants
     *
     * @see SMTP::$Debugoutput
     * @see SMTP::$do_debug
     */
    protected function log($str, $level = 0)
    {
        if ($level > $this->debugLevel) {
            return;
        }

        // is this a PSR-3 logger?
        if ($this->debugOutput instanceof LoggerInterface) {
            $this->debugOutput->debug($str);

            return;
        }

        // avoid clash with built-in function names
        if (!in_array($this->debugOutput, ['error_log', 'html', 'echo']) && is_callable($this->debugOutput)) {
            call_user_func($this->debugOutput, $str, $level);

            return;
        }

        switch ($this->debugOutput) {
            case 'error_log':
                // don't output, just log
                error_log($str);
                break;
            case 'html':
                // cleans up output a bit for a better looking, HTML-safe output
                echo gmdate('Y-m-d H:i:s'), ' ', htmlentities(
                    preg_replace('/[\r\n]+/', '', $str),
                    ENT_QUOTES,
                    'UTF-8'
                ), "<br>\n";
                break;
            case 'echo':
                // normalize line breaks
                $str = preg_replace('/\r\n|\r/ms', "\n", $str);
                echo gmdate('Y-m-d H:i:s'),
                "\t",
                trim(str_replace("\n", "\n                   \t                  ", trim($str))),
                "\n";
                break;
            default:
                // send to /dev/null
                break;
        }
    }

    /**
     * Initiate a TLS (encrypted) session.
     *
     * @return bool
     */
    public function startTLS()
    {
        if (!$this->sendCommand('STARTTLS', 'STARTTLS', 220)) {
            return false;
        }

        //Allow the best TLS version(s) we can
        $crypto_method = STREAM_CRYPTO_METHOD_TLS_CLIENT;

        // PHP 5.6.7 dropped inclusion of TLS 1.1 and 1.2 in STREAM_CRYPTO_METHOD_TLS_CLIENT
        // so add them back in manually if we can
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) {
            $crypto_method |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            $crypto_method |= STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
        }

        // Begin encrypted connection
        set_error_handler([$this, 'errorHandler']);
        $crypto_ok = stream_socket_enable_crypto(
            $this->socket,
            true,
            $crypto_method
        );
        restore_error_handler();

        return (bool)$crypto_ok;
    }

    /**
     * Get SMTP extensions available on the server.
     *
     * @return array|null
     */
    public function getServerCapabilities()
    {
        return $this->serverCapabilities;
    }

    /**
     * Get metadata about the SMTP server from its HELO/EHLO response.
     * The method works in three ways, dependent on argument value and current state:
     *   1. HELO/EHLO has not been sent - returns null and populates $this->error.
     *   2. HELO has been sent -
     *     $name == 'HELO': returns server name
     *     $name == 'EHLO': returns boolean false
     *     $name == any other string: returns null and populates $this->error
     *   3. EHLO has been sent -
     *     $name == 'HELO'|'EHLO': returns the server name
     *     $name == any other string: if extension $name exists, returns True
     *       or its options (e.g. AUTH mechanisms supported). Otherwise returns False.
     *
     * @param string $name Name of SMTP extension or 'HELO'|'EHLO'
     *
     * @return mixed
     */
    public function getServerCapability($name)
    {
        if (!$this->serverCapabilities) {
            $this->setLastError('No HELO/EHLO was sent');
            return null;
        }

        if (!array_key_exists($name, $this->serverCapabilities)) {
            if ('HELO' === $name) {
                return $this->serverCapabilities['EHLO'];
            }

            if ('EHLO' === $name || array_key_exists('EHLO', $this->serverCapabilities)) {
                return false;
            }

            $this->setLastError('HELO handshake was used; No information about server extensions available');
            return null;
        }

        return $this->serverCapabilities[$name];
    }
}
