<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\HttpFoundation;

use LaravelFly\Map\IlluminateBase\SingletonRequestException;
use Symfony\Component\HttpFoundation\Exception\ConflictingHeadersException;
use Symfony\Component\HttpFoundation\Exception\SuspiciousOperationException;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Request represents an HTTP request.
 *
 * The methods dealing with URL accept / return a raw path (% encoded):
 *   * getBasePath
 *   * getBaseUrl
 *   * getPathInfo
 *   * getRequestUri
 *   * getUri
 *   * getUriForPath
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class Request
{
    use \LaravelFly\Map\Util\Dict;

    const HEADER_FORWARDED = 0b00001; // When using RFC 7239
    const HEADER_X_FORWARDED_FOR = 0b00010;
    const HEADER_X_FORWARDED_HOST = 0b00100;
    const HEADER_X_FORWARDED_PROTO = 0b01000;
    const HEADER_X_FORWARDED_PORT = 0b10000;
    const HEADER_X_FORWARDED_ALL = 0b11110; // All "X-Forwarded-*" headers
    const HEADER_X_FORWARDED_AWS_ELB = 0b11010; // AWS ELB doesn't send X-Forwarded-Host

    const METHOD_HEAD = 'HEAD';
    const METHOD_GET = 'GET';
    const METHOD_POST = 'POST';
    const METHOD_PUT = 'PUT';
    const METHOD_PATCH = 'PATCH';
    const METHOD_DELETE = 'DELETE';
    const METHOD_PURGE = 'PURGE';
    const METHOD_OPTIONS = 'OPTIONS';
    const METHOD_TRACE = 'TRACE';
    const METHOD_CONNECT = 'CONNECT';

    /**
     * @var string[]
     */
    protected static $trustedProxies = array();

    /**
     * @var string[]
     */
    protected static $trustedHostPatterns = array();

    /**
     * @var string[]
     */
    protected static $trustedHosts = array();

    protected static $httpMethodParameterOverride = false;

    /**
     * @var string
     */
    protected $locale;

    /**
     * @var string
     */
    protected $defaultLocale = 'en';

    /**
     * @var array
     */
    protected static $formats;

    protected static $requestFactory;

    private static $trustedHeaderSet = -1;

    private static $forwardedParams = array(
        self::HEADER_X_FORWARDED_FOR => 'for',
        self::HEADER_X_FORWARDED_HOST => 'host',
        self::HEADER_X_FORWARDED_PROTO => 'proto',
        self::HEADER_X_FORWARDED_PORT => 'host',
    );

    /**
     * Names for headers that can be trusted when
     * using trusted proxies.
     *
     * The FORWARDED header is the standard as of rfc7239.
     *
     * The other headers are non-standard, but widely used
     * by popular reverse proxies (like Apache mod_proxy or Amazon EC2).
     */
    private static $trustedHeaders = array(
        self::HEADER_FORWARDED => 'FORWARDED',
        self::HEADER_X_FORWARDED_FOR => 'X_FORWARDED_FOR',
        self::HEADER_X_FORWARDED_HOST => 'X_FORWARDED_HOST',
        self::HEADER_X_FORWARDED_PROTO => 'X_FORWARDED_PROTO',
        self::HEADER_X_FORWARDED_PORT => 'X_FORWARDED_PORT',
    );

    // hack
    protected static $instance;

    /**
     * @param array $query The GET parameters
     * @param array $request The POST parameters
     * @param array $attributes The request attributes (parameters parsed from the PATH_INFO, ...)
     * @param array $cookies The COOKIE parameters
     * @param array $files The FILES parameters
     * @param array $server The SERVER parameters
     * @param string|resource|null $content The raw body data
     */
    public function __construct(array $query = array(), array $request = array(), array $attributes = array(), array $cookies = array(), array $files = array(), array $server = array(), $content = null)
    {
        if (static::$instance) throw new SingletonRequestException();

        static::$instance = $this;

        $this->initialize($query, $request, $attributes, $cookies, $files, $server, $content);
    }

    /**
     * Sets the parameters for this request.
     *
     * This method also re-initializes all properties.
     *
     * @param array $query The GET parameters
     * @param array $request The POST parameters
     * @param array $attributes The request attributes (parameters parsed from the PATH_INFO, ...)
     * @param array $cookies The COOKIE parameters
     * @param array $files The FILES parameters
     * @param array $server The SERVER parameters
     * @param string|resource|null $content The raw body data
     */
    public function initialize(array $query = array(), array $request = array(), array $attributes = array(), array $cookies = array(), array $files = array(), array $server = array(), $content = null)
    {
        $cid = \Swoole\Coroutine::getuid();
        $dict = &static::$corDict[$cid];
        $dict['request'] = new ParameterBag($request);
        $dict['query'] = new ParameterBag($query);
        $dict['attributes'] = new ParameterBag($attributes);

        $dict['cookies'] = new ParameterBag($cookies);
        $dict['files'] = new FileBag($files);
        $dict['server'] = new ServerBag($server);
        // todo
        $dict['headers'] = new HeaderBag($dict['server']->getHeaders());

        $dict['content'] = $content;
        $dict['languages'] = null;
        $dict['charsets'] = null;
        $dict['encodings'] = null;
        $dict['acceptableContentTypes'] = null;
        $dict['pathInfo'] = null;
        $dict['requestUri'] = null;
        $dict['baseUrl'] = null;
        $dict['basePath'] = null;
        $dict['method'] = null;
        $dict['format'] = null;
    }

    /**
     * Creates a new request with values from PHP's super globals.
     *
     * @return static
     */
    public static function createFromGlobals()
    {
        throw new SingletonRequestException();
    }

    /**
     * Creates a Request based on a given URI and configuration.
     *
     * The information contained in the URI always take precedence
     * over the other information (server and parameters).
     *
     * @param string $uri The URI
     * @param string $method The HTTP method
     * @param array $parameters The query (GET) or request (POST) parameters
     * @param array $cookies The request cookies ($_COOKIE)
     * @param array $files The request files ($_FILES)
     * @param array $server The server parameters ($_SERVER)
     * @param string|resource|null $content The raw body data
     *
     * @return static
     */
    public static function create($uri, $method = 'GET', $parameters = array(), $cookies = array(), $files = array(), $server = array(), $content = null)
    {
        throw new SingletonRequestException();
        $server = array_replace(array(
            'SERVER_NAME' => 'localhost',
            'SERVER_PORT' => 80,
            'HTTP_HOST' => 'localhost',
            'HTTP_USER_AGENT' => 'Symfony',
            'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'HTTP_ACCEPT_LANGUAGE' => 'en-us,en;q=0.5',
            'HTTP_ACCEPT_CHARSET' => 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
            'REMOTE_ADDR' => '127.0.0.1',
            'SCRIPT_NAME' => '',
            'SCRIPT_FILENAME' => '',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'REQUEST_TIME' => time(),
        ), $server);

        $server['PATH_INFO'] = '';
        $server['REQUEST_METHOD'] = strtoupper($method);

        $components = parse_url($uri);
        if (isset($components['host'])) {
            $server['SERVER_NAME'] = $components['host'];
            $server['HTTP_HOST'] = $components['host'];
        }

        if (isset($components['scheme'])) {
            if ('https' === $components['scheme']) {
                $server['HTTPS'] = 'on';
                $server['SERVER_PORT'] = 443;
            } else {
                unset($server['HTTPS']);
                $server['SERVER_PORT'] = 80;
            }
        }

        if (isset($components['port'])) {
            $server['SERVER_PORT'] = $components['port'];
            $server['HTTP_HOST'] = $server['HTTP_HOST'] . ':' . $components['port'];
        }

        if (isset($components['user'])) {
            $server['PHP_AUTH_USER'] = $components['user'];
        }

        if (isset($components['pass'])) {
            $server['PHP_AUTH_PW'] = $components['pass'];
        }

        if (!isset($components['path'])) {
            $components['path'] = '/';
        }

        switch (strtoupper($method)) {
            case 'POST':
            case 'PUT':
            case 'DELETE':
                if (!isset($server['CONTENT_TYPE'])) {
                    $server['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
                }
            // no break
            case 'PATCH':
                $request = $parameters;
                $query = array();
                break;
            default:
                $request = array();
                $query = $parameters;
                break;
        }

        $queryString = '';
        if (isset($components['query'])) {
            parse_str(html_entity_decode($components['query']), $qs);

            if ($query) {
                $query = array_replace($qs, $query);
                $queryString = http_build_query($query, '', '&');
            } else {
                $query = $qs;
                $queryString = $components['query'];
            }
        } elseif ($query) {
            $queryString = http_build_query($query, '', '&');
        }

        $server['REQUEST_URI'] = $components['path'] . ('' !== $queryString ? '?' . $queryString : '');
        $server['QUERY_STRING'] = $queryString;

        return self::createRequestFromFactory($query, $request, array(), $cookies, $files, $server, $content);
    }

    /**
     * Sets a callable able to create a Request instance.
     *
     * This is mainly useful when you need to override the Request class
     * to keep BC with an existing system. It should not be used for any
     * other purpose.
     *
     * @param callable|null $callable A PHP callable
     */
    public static function setFactory($callable)
    {
        throw new SingletonRequestException();
        self::$requestFactory = $callable;
    }

    /**
     * Clones a request and overrides some of its parameters.
     *
     * @param array $query The GET parameters
     * @param array $request The POST parameters
     * @param array $attributes The request attributes (parameters parsed from the PATH_INFO, ...)
     * @param array $cookies The COOKIE parameters
     * @param array $files The FILES parameters
     * @param array $server The SERVER parameters
     *
     * @return static
     */
    //todo
    public function duplicate(array $query = null, array $request = null, array $attributes = null, array $cookies = null, array $files = null, array $server = null)
    {
        throw new SingletonRequestException();
        $dup = clone $this;
        if (null !== $query) {
            $dup->query = new ParameterBag($query);
        }
        if (null !== $request) {
            $dup->request = new ParameterBag($request);
        }
        if (null !== $attributes) {
            $dup->attributes = new ParameterBag($attributes);
        }
        if (null !== $cookies) {
            $dup->cookies = new ParameterBag($cookies);
        }
        if (null !== $files) {
            $dup->files = new FileBag($files);
        }
        if (null !== $server) {
            $dup->server = new ServerBag($server);
            $dup->headers = new HeaderBag($dup->server->getHeaders());
        }
        $dup->languages = null;
        $dup->charsets = null;
        $dup->encodings = null;
        $dup->acceptableContentTypes = null;
        $dup->pathInfo = null;
        $dup->requestUri = null;
        $dup->baseUrl = null;
        $dup->basePath = null;
        $dup->method = null;
        $dup->format = null;

        if (!$dup->get('_format') && $this->get('_format')) {
            $dup->attributes->set('_format', $this->get('_format'));
        }

        if (!$dup->getRequestFormat(null)) {
            $dup->setRequestFormat($this->getRequestFormat(null));
        }

        return $dup;
    }

    /**
     * Clones the current request.
     *
     * Note that the session is not cloned as duplicated requests
     * are most of the time sub-requests of the main one.
     */
    //todo
    public function __clone()
    {
        throw new SingletonRequestException();
        $this->query = clone $this->query;
        $this->request = clone $this->request;
        $this->attributes = clone $this->attributes;
        $this->cookies = clone $this->cookies;
        $this->files = clone $this->files;
        $this->server = clone $this->server;
        $this->headers = clone $this->headers;
    }

    /**
     * Returns the request as a string.
     *
     * @return string The request
     */
    public function __toString()
    {
        try {
            $content = $this->getContent();
        } catch (\LogicException $e) {
            return trigger_error($e, E_USER_ERROR);
        }

        $cookieHeader = '';
        $cookies = array();

        $dict = static::$corDict[\Swoole\Coroutine::getuid()];

        foreach ($dict['cookies'] as $k => $v) {
            $cookies[] = $k . '=' . $v;
        }

        if (!empty($cookies)) {
            $cookieHeader = 'Cookie: ' . implode('; ', $cookies) . "\r\n";
        }

        return
            sprintf('%s %s %s', $this->getMethod(), $this->getRequestUri(), $dict['server']->get('SERVER_PROTOCOL')) . "\r\n" .
            $dict['headers'] .
            $cookieHeader . "\r\n" .
            $content;
    }

    /**
     * Overrides the PHP global variables according to this request instance.
     *
     * It overrides $_GET, $_POST, $_REQUEST, $_SERVER, $_COOKIE.
     * $_FILES is never overridden, see rfc1867
     */
    public function overrideGlobals()
    {
        throw new SingletonRequestException('global vars are not valid');
    }

    /**
     * Sets a list of trusted proxies.
     *
     * You should only list the reverse proxies that you manage directly.
     *
     * @param array $proxies A list of trusted proxies
     * @param int $trustedHeaderSet A bit field of Request::HEADER_*, to set which headers to trust from your proxies
     *
     * @throws \InvalidArgumentException When $trustedHeaderSet is invalid
     */
    public static function setTrustedProxies(array $proxies, int $trustedHeaderSet)
    {
        self::$trustedProxies = $proxies;
        self::$trustedHeaderSet = $trustedHeaderSet;
    }

    /**
     * Gets the list of trusted proxies.
     *
     * @return array An array of trusted proxies
     */
    public static function getTrustedProxies()
    {
        return self::$trustedProxies;
    }

    /**
     * Gets the set of trusted headers from trusted proxies.
     *
     * @return int A bit field of Request::HEADER_* that defines which headers are trusted from your proxies
     */
    public static function getTrustedHeaderSet()
    {
        return self::$trustedHeaderSet;
    }

    /**
     * Sets a list of trusted host patterns.
     *
     * You should only list the hosts you manage using regexs.
     *
     * @param array $hostPatterns A list of trusted host patterns
     */
    public static function setTrustedHosts(array $hostPatterns)
    {
        self::$trustedHostPatterns = array_map(function ($hostPattern) {
            return sprintf('{%s}i', $hostPattern);
        }, $hostPatterns);
        // we need to reset trusted hosts on trusted host patterns change
        self::$trustedHosts = array();
    }

    /**
     * Gets the list of trusted host patterns.
     *
     * @return array An array of trusted host patterns
     */
    public static function getTrustedHosts()
    {
        return self::$trustedHostPatterns;
    }

    /**
     * Normalizes a query string.
     *
     * It builds a normalized query string, where keys/value pairs are alphabetized,
     * have consistent escaping and unneeded delimiters are removed.
     *
     * @param string $qs Query string
     *
     * @return string A normalized query string for the Request
     */
    public static function normalizeQueryString($qs)
    {
        if ('' == $qs) {
            return '';
        }

        parse_str($qs, $qs);
        ksort($qs);

        return http_build_query($qs, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Enables support for the _method request parameter to determine the intended HTTP method.
     *
     * Be warned that enabling this feature might lead to CSRF issues in your code.
     * Check that you are using CSRF tokens when required.
     * If the HTTP method parameter override is enabled, an html-form with method "POST" can be altered
     * and used to send a "PUT" or "DELETE" request via the _method request parameter.
     * If these methods are not protected against CSRF, this presents a possible vulnerability.
     *
     * The HTTP method can only be overridden when the real HTTP method is POST.
     */
    public static function enableHttpMethodParameterOverride()
    {
        self::$httpMethodParameterOverride = true;
    }

    /**
     * Checks whether support for the _method request parameter is enabled.
     *
     * @return bool True when the _method request parameter is enabled, false otherwise
     */
    public static function getHttpMethodParameterOverride()
    {
        return self::$httpMethodParameterOverride;
    }

    /**
     * Gets a "parameter" value from any bag.
     *
     * This method is mainly useful for libraries that want to provide some flexibility. If you don't need the
     * flexibility in controllers, it is better to explicitly get request parameters from the appropriate
     * public property instead (attributes, query, request).
     *
     * Order of precedence: PATH (routing placeholders or custom attributes), GET, BODY
     *
     * @param string $key The key
     * @param mixed $default The default value if the parameter key does not exist
     *
     * @return mixed
     */
    public function get($key, $default = null)
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if ($this !== $result = $dict['attributes']->get($key, $this)) {
            return $result;
        }

        if ($this !== $result = $dict['query']->get($key, $this)) {
            return $result;
        }

        if ($this !== $result = $dict['request']->get($key, $this)) {
            return $result;
        }

        return $default;
    }

    /**
     * Gets the Session.
     *
     * @return SessionInterface|null The session
     */
    public function getSession()
    {
        $session = static::$corDict[\Swoole\Coroutine::getuid()]['session'];
        if (!$session instanceof SessionInterface && null !== $session) {
            $this->setSession($session = $session());
        }

        if (null === $session) {
            @trigger_error(sprintf('Calling "%s()" when no session has been set is deprecated since Symfony 4.1 and will throw an exception in 5.0. Use "hasSession()" instead.', __METHOD__), E_USER_DEPRECATED);
            // throw new \BadMethodCallException('Session has not been set');
        }

        return $session;
    }

    /**
     * Whether the request contains a Session which was started in one of the
     * previous requests.
     *
     * @return bool
     */
    public function hasPreviousSession()
    {
        // the check for $this->session avoids malicious users trying to fake a session cookie with proper name
        return $this->hasSession() && static::$corDict[\Swoole\Coroutine::getuid()]['cookies']->has($this->getSession()->getName());
    }

    /**
     * Whether the request contains a Session object.
     *
     * This method does not give any information about the state of the session object,
     * like whether the session is started or not. It is just a way to check if this Request
     * is associated with a Session instance.
     *
     * @return bool true when the Request contains a Session object, false otherwise
     */
    public function hasSession()
    {
        return null !== static::$corDict[\Swoole\Coroutine::getuid()]['session'];
    }

    /**
     * Sets the Session.
     *
     * @param SessionInterface $session The Session
     */
    public function setSession(SessionInterface $session)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['session'] = $session;
    }

    /**
     * @internal
     */
    public function setSessionFactory(callable $factory)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['session'] = $factory;
    }

    /**
     * Returns the client IP addresses.
     *
     * In the returned array the most trusted IP address is first, and the
     * least trusted one last. The "real" client IP address is the last one,
     * but this is also the least trusted one. Trusted proxies are stripped.
     *
     * Use this method carefully; you should use getClientIp() instead.
     *
     * @return array The client IP addresses
     *
     * @see getClientIp()
     */
    public function getClientIps()
    {
        $ip = static::$corDict[\Swoole\Coroutine::getuid()]['server']->get('REMOTE_ADDR');

        if (!$this->isFromTrustedProxy()) {
            return array($ip);
        }

        return $this->getTrustedValues(self::HEADER_X_FORWARDED_FOR, $ip) ?: array($ip);
    }

    /**
     * Returns the client IP address.
     *
     * This method can read the client IP address from the "X-Forwarded-For" header
     * when trusted proxies were set via "setTrustedProxies()". The "X-Forwarded-For"
     * header value is a comma+space separated list of IP addresses, the left-most
     * being the original client, and each successive proxy that passed the request
     * adding the IP address where it received the request from.
     *
     * @return string|null The client IP address
     *
     * @see getClientIps()
     * @see http://en.wikipedia.org/wiki/X-Forwarded-For
     */
    public function getClientIp()
    {
        $ipAddresses = $this->getClientIps();

        return $ipAddresses[0];
    }

    /**
     * Returns current script name.
     *
     * @return string
     */
    public function getScriptName()
    {
        $dict = static::$corDict[\Swoole\Coroutine::getuid()];
        return $dict['server']->get('SCRIPT_NAME', $dict['server']->get('ORIG_SCRIPT_NAME', ''));
    }

    /**
     * Returns the path being requested relative to the executed script.
     *
     * The path info always starts with a /.
     *
     * Suppose this request is instantiated from /mysite on localhost:
     *
     *  * http://localhost/mysite              returns an empty string
     *  * http://localhost/mysite/about        returns '/about'
     *  * http://localhost/mysite/enco%20ded   returns '/enco%20ded'
     *  * http://localhost/mysite/about?var=1  returns '/about'
     *
     * @return string The raw path (i.e. not urldecoded)
     */
    public function getPathInfo()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];
        if (null === $dict['pathInfo']) {
            $dict['pathInfo'] = $this->preparePathInfo();
        }

        return $dict['pathInfo'];
    }

    /**
     * Returns the root path from which this request is executed.
     *
     * Suppose that an index.php file instantiates this request object:
     *
     *  * http://localhost/index.php         returns an empty string
     *  * http://localhost/index.php/page    returns an empty string
     *  * http://localhost/web/index.php     returns '/web'
     *  * http://localhost/we%20b/index.php  returns '/we%20b'
     *
     * @return string The raw path (i.e. not urldecoded)
     */
    public function getBasePath()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['basePath']) {
            $dict['basePath'] = $this->prepareBasePath($dict);
        }

        return $dict['basePath'];
    }

    /**
     * Returns the root URL from which this request is executed.
     *
     * The base URL never ends with a /.
     *
     * This is similar to getBasePath(), except that it also includes the
     * script filename (e.g. index.php) if one exists.
     *
     * @return string The raw URL (i.e. not urldecoded)
     */
    public function getBaseUrl()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['baseUrl']) {
            $dict['baseUrl'] = $this->prepareBaseUrl($dict);
        }

        return $dict['baseUrl'];
    }

    /**
     * Gets the request's scheme.
     *
     * @return string
     */
    public function getScheme()
    {
        return $this->isSecure() ? 'https' : 'http';
    }

    /**
     * Returns the port on which the request is made.
     *
     * This method can read the client port from the "X-Forwarded-Port" header
     * when trusted proxies were set via "setTrustedProxies()".
     *
     * The "X-Forwarded-Port" header must contain the client port.
     *
     * @return int|string can be a string if fetched from the server bag
     */
    public function getPort()
    {
        if ($this->isFromTrustedProxy() && $host = $this->getTrustedValues(self::HEADER_X_FORWARDED_PORT)) {
            $host = $host[0];
        } elseif ($this->isFromTrustedProxy() && $host = $this->getTrustedValues(self::HEADER_X_FORWARDED_HOST)) {
            $host = $host[0];
        } elseif (!$host = static::$corDict[\Swoole\Coroutine::getuid()]['headers']->get('HOST')) {
            return static::$corDict[\Swoole\Coroutine::getuid()]['server']->get('SERVER_PORT');
        }

        if ('[' === $host[0]) {
            $pos = strpos($host, ':', strrpos($host, ']'));
        } else {
            $pos = strrpos($host, ':');
        }

        if (false !== $pos) {
            return (int)substr($host, $pos + 1);
        }

        return 'https' === $this->getScheme() ? 443 : 80;
    }

    /**
     * Returns the user.
     *
     * @return string|null
     */
    public function getUser()
    {
        return static::$corDict[\Swoole\Coroutine::getuid()]['headers']->get('PHP_AUTH_USER');
    }

    /**
     * Returns the password.
     *
     * @return string|null
     */
    public function getPassword()
    {
        return static::$corDict[\Swoole\Coroutine::getuid()]['headers']->get('PHP_AUTH_PW');
    }

    /**
     * Gets the user info.
     *
     * @return string A user name and, optionally, scheme-specific information about how to gain authorization to access the server
     */
    public function getUserInfo()
    {
        $userinfo = $this->getUser();

        $pass = $this->getPassword();
        if ('' != $pass) {
            $userinfo .= ":$pass";
        }

        return $userinfo;
    }

    /**
     * Returns the HTTP host being requested.
     *
     * The port name will be appended to the host if it's non-standard.
     *
     * @return string
     */
    public function getHttpHost()
    {
        $scheme = $this->getScheme();
        $port = $this->getPort();

        if (('http' == $scheme && 80 == $port) || ('https' == $scheme && 443 == $port)) {
            return $this->getHost();
        }

        return $this->getHost() . ':' . $port;
    }

    /**
     * Returns the requested URI (path and query string).
     *
     * @return string The raw URI (i.e. not URI decoded)
     */
    public function getRequestUri()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];
        if (null === $dict['requestUri']) {
            $dict['requestUri'] = $this->prepareRequestUri();
        }

        return $dict['requestUri'];
    }

    /**
     * Gets the scheme and HTTP host.
     *
     * If the URL was called with basic authentication, the user
     * and the password are not added to the generated string.
     *
     * @return string The scheme and HTTP host
     */
    public function getSchemeAndHttpHost()
    {
        return $this->getScheme() . '://' . $this->getHttpHost();
    }

    /**
     * Generates a normalized URI (URL) for the Request.
     *
     * @return string A normalized URI (URL) for the Request
     *
     * @see getQueryString()
     */
    public function getUri()
    {
        if (null !== $qs = $this->getQueryString()) {
            $qs = '?' . $qs;
        }

        return $this->getSchemeAndHttpHost() . $this->getBaseUrl() . $this->getPathInfo() . $qs;
    }

    /**
     * Generates a normalized URI for the given path.
     *
     * @param string $path A path to use instead of the current one
     *
     * @return string The normalized URI for the path
     */
    public function getUriForPath($path)
    {
        return $this->getSchemeAndHttpHost() . $this->getBaseUrl() . $path;
    }

    /**
     * Returns the path as relative reference from the current Request path.
     *
     * Only the URIs path component (no schema, host etc.) is relevant and must be given.
     * Both paths must be absolute and not contain relative parts.
     * Relative URLs from one resource to another are useful when generating self-contained downloadable document archives.
     * Furthermore, they can be used to reduce the link size in documents.
     *
     * Example target paths, given a base path of "/a/b/c/d":
     * - "/a/b/c/d"     -> ""
     * - "/a/b/c/"      -> "./"
     * - "/a/b/"        -> "../"
     * - "/a/b/c/other" -> "other"
     * - "/a/x/y"       -> "../../x/y"
     *
     * @param string $path The target path
     *
     * @return string The relative target path
     */
    public function getRelativeUriForPath($path)
    {
        // be sure that we are dealing with an absolute path
        if (!isset($path[0]) || '/' !== $path[0]) {
            return $path;
        }

        if ($path === $basePath = $this->getPathInfo()) {
            return '';
        }

        $sourceDirs = explode('/', isset($basePath[0]) && '/' === $basePath[0] ? substr($basePath, 1) : $basePath);
        $targetDirs = explode('/', isset($path[0]) && '/' === $path[0] ? substr($path, 1) : $path);
        array_pop($sourceDirs);
        $targetFile = array_pop($targetDirs);

        foreach ($sourceDirs as $i => $dir) {
            if (isset($targetDirs[$i]) && $dir === $targetDirs[$i]) {
                unset($sourceDirs[$i], $targetDirs[$i]);
            } else {
                break;
            }
        }

        $targetDirs[] = $targetFile;
        $path = str_repeat('../', \count($sourceDirs)) . implode('/', $targetDirs);

        // A reference to the same base directory or an empty subdirectory must be prefixed with "./".
        // This also applies to a segment with a colon character (e.g., "file:colon") that cannot be used
        // as the first segment of a relative-path reference, as it would be mistaken for a scheme name
        // (see http://tools.ietf.org/html/rfc3986#section-4.2).
        return !isset($path[0]) || '/' === $path[0]
        || false !== ($colonPos = strpos($path, ':')) && ($colonPos < ($slashPos = strpos($path, '/')) || false === $slashPos)
            ? "./$path" : $path;
    }

    /**
     * Generates the normalized query string for the Request.
     *
     * It builds a normalized query string, where keys/value pairs are alphabetized
     * and have consistent escaping.
     *
     * @return string|null A normalized query string for the Request
     */
    public function getQueryString()
    {
        $qs = static::normalizeQueryString(static::$corDict[\Swoole\Coroutine::getuid()]['server']->get('QUERY_STRING'));

        return '' === $qs ? null : $qs;
    }

    /**
     * Checks whether the request is secure or not.
     *
     * This method can read the client protocol from the "X-Forwarded-Proto" header
     * when trusted proxies were set via "setTrustedProxies()".
     *
     * The "X-Forwarded-Proto" header must contain the protocol: "https" or "http".
     *
     * @return bool
     */
    public function isSecure()
    {
        if ($this->isFromTrustedProxy() && $proto = $this->getTrustedValues(self::HEADER_X_FORWARDED_PROTO)) {
            return \in_array(strtolower($proto[0]), array('https', 'on', 'ssl', '1'), true);
        }

        $https = static::$corDict[\Swoole\Coroutine::getuid()]['server']->get('HTTPS');

        return !empty($https) && 'off' !== strtolower($https);
    }

    /**
     * Returns the host name.
     *
     * This method can read the client host name from the "X-Forwarded-Host" header
     * when trusted proxies were set via "setTrustedProxies()".
     *
     * The "X-Forwarded-Host" header must contain the client host name.
     *
     * @return string
     *
     * @throws SuspiciousOperationException when the host name is invalid or not trusted
     */
    public function getHost()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];
        if ($this->isFromTrustedProxy() && $host = $this->getTrustedValues(self::HEADER_X_FORWARDED_HOST)) {
            $host = $host[0];
        } elseif (!$host = $dict['headers']->get('HOST')) {
            if (!$host = $dict['server']->get('SERVER_NAME')) {
                $host = $dict['server']->get('SERVER_ADDR', '');
            }
        }

        // trim and remove port number from host
        // host is lowercase as per RFC 952/2181
        $host = strtolower(preg_replace('/:\d+$/', '', trim($host)));

        // as the host can come from the user (HTTP_HOST and depending on the configuration, SERVER_NAME too can come from the user)
        // check that it does not contain forbidden characters (see RFC 952 and RFC 2181)
        // use preg_replace() instead of preg_match() to prevent DoS attacks with long host names
        if ($host && '' !== preg_replace('/(?:^\[)?[a-zA-Z0-9-:\]_]+\.?/', '', $host)) {
            if (!$dict['isHostValid']) {
                return '';
            }
            $dict['isHostValid'] = false;

            throw new SuspiciousOperationException(sprintf('Invalid Host "%s".', $host));
        }

        if (\count(self::$trustedHostPatterns) > 0) {
            // to avoid host header injection attacks, you should provide a list of trusted host patterns

            if (\in_array($host, self::$trustedHosts)) {
                return $host;
            }

            foreach (self::$trustedHostPatterns as $pattern) {
                if (preg_match($pattern, $host)) {
                    self::$trustedHosts[] = $host;

                    return $host;
                }
            }

            if (!$dict['isHostValid']) {
                return '';
            }
            $dict['isHostValid'] = false;

            throw new SuspiciousOperationException(sprintf('Untrusted Host "%s".', $host));
        }

        return $host;
    }

    /**
     * Sets the request method.
     *
     * @param string $method
     */
    public function setMethod($method)
    {
        $dict = static::$corDict[\Swoole\Coroutine::getuid()];
        $dict['method'] = null;
        $dict['server']->set('REQUEST_METHOD', $method);
    }

    /**
     * Gets the request "intended" method.
     *
     * If the X-HTTP-Method-Override header is set, and if the method is a POST,
     * then it is used to determine the "real" intended HTTP method.
     *
     * The _method request parameter can also be used to determine the HTTP method,
     * but only if enableHttpMethodParameterOverride() has been called.
     *
     * The method is always an uppercased string.
     *
     * @return string The request method
     *
     * @see getRealMethod()
     */
    public function getMethod()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];
        if (null === $dict['method']) {
            // todo
            $dict['method'] = strtoupper($dict['server']->get('REQUEST_METHOD', 'GET'));

            if ('POST' === $dict['method']) {
                if ($method = $dict['headers']->get('X-HTTP-METHOD-OVERRIDE')) {
                    $dict['method'] = strtoupper($method);
                } elseif (self::$httpMethodParameterOverride) {
                    $method = $dict['request']->get('_method', $dict['query']->get('_method', 'POST'));
                    if (\is_string($method)) {
                        $dict['method'] = strtoupper($method);
                    }
                }
            }
        }

        return $dict['method'];
    }

    /**
     * Gets the "real" request method.
     *
     * @return string The request method
     *
     * @see getMethod()
     */
    public function getRealMethod()
    {
        return strtoupper(static::$corDict[\Swoole\Coroutine::getuid()]['server']->get('REQUEST_METHOD', 'GET'));
    }

    /**
     * Gets the mime type associated with the format.
     *
     * @param string $format The format
     *
     * @return string|null The associated mime type (null if not found)
     */
    public function getMimeType($format)
    {
        if (null === static::$formats) {
            static::initializeFormats();
        }

        return isset(static::$formats[$format]) ? static::$formats[$format][0] : null;
    }

    /**
     * Gets the mime types associated with the format.
     *
     * @param string $format The format
     *
     * @return array The associated mime types
     */
    public static function getMimeTypes($format)
    {
        if (null === static::$formats) {
            static::initializeFormats();
        }

        return isset(static::$formats[$format]) ? static::$formats[$format] : array();
    }

    /**
     * Gets the format associated with the mime type.
     *
     * @param string $mimeType The associated mime type
     *
     * @return string|null The format (null if not found)
     */
    public function getFormat($mimeType)
    {
        $canonicalMimeType = null;
        if (false !== $pos = strpos($mimeType, ';')) {
            $canonicalMimeType = substr($mimeType, 0, $pos);
        }

        if (null === static::$formats) {
            static::initializeFormats();
        }

        foreach (static::$formats as $format => $mimeTypes) {
            if (\in_array($mimeType, (array)$mimeTypes)) {
                return $format;
            }
            if (null !== $canonicalMimeType && \in_array($canonicalMimeType, (array)$mimeTypes)) {
                return $format;
            }
        }
    }

    /**
     * Associates a format with mime types.
     *
     * @param string $format The format
     * @param string|array $mimeTypes The associated mime types (the preferred one must be the first as it will be used as the content type)
     */
    //todo
    public function setFormat($format, $mimeTypes)
    {
        if (null === static::$formats) {
            static::initializeFormats();
        }

        static::$formats[$format] = \is_array($mimeTypes) ? $mimeTypes : array($mimeTypes);
    }

    /**
     * Gets the request format.
     *
     * Here is the process to determine the format:
     *
     *  * format defined by the user (with setRequestFormat())
     *  * _format request attribute
     *  * $default
     *
     * @param string|null $default The default format
     *
     * @return string The request format
     */
    public function getRequestFormat($default = 'html')
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['format']) {
            $dict['format'] = $dict['attributes']->get('_format');
        }

        return null === $dict['format'] ? $default : $this->format;
    }

    /**
     * Sets the request format.
     *
     * @param string $format The request format
     */
    public function setRequestFormat($format)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['format'] = $format;
    }

    /**
     * Gets the format associated with the request.
     *
     * @return string|null The format (null if no content type is present)
     */
    public function getContentType()
    {
        return $this->getFormat(static::$corDict[\Swoole\Coroutine::getuid()]['headers']->get('CONTENT_TYPE'));
    }

    /**
     * Sets the default locale.
     *
     * @param string $locale
     */
    public function setDefaultLocale($locale)
    {
        $this->defaultLocale = $locale;

        if (null === $this->locale) {
            $this->setPhpDefaultLocale($locale);
        }
    }

    /**
     * Get the default locale.
     *
     * @return string
     */
    public function getDefaultLocale()
    {
        return $this->defaultLocale;
    }

    /**
     * Sets the locale.
     *
     * @param string $locale
     */
    public function setLocale($locale)
    {
        //todo
        $this->setPhpDefaultLocale($this->locale = $locale);
    }

    /**
     * Get the locale.
     *
     * @return string
     */
    public function getLocale()
    {
        return null === $this->locale ? $this->defaultLocale : $this->locale;
    }

    /**
     * Checks if the request method is of specified type.
     *
     * @param string $method Uppercase request method (GET, POST etc)
     *
     * @return bool
     */
    public function isMethod($method)
    {
        return $this->getMethod() === strtoupper($method);
    }

    /**
     * Checks whether or not the method is safe.
     *
     * @see https://tools.ietf.org/html/rfc7231#section-4.2.1
     *
     * @param bool $andCacheable Adds the additional condition that the method should be cacheable. True by default.
     *
     * @return bool
     */
    public function isMethodSafe(/* $andCacheable = true */)
    {
        if (!\func_num_args() || func_get_arg(0)) {
            // setting $andCacheable to false should be deprecated in 4.1
            throw new \BadMethodCallException('Checking only for cacheable HTTP methods with Symfony\Component\HttpFoundation\Request::isMethodSafe() is not supported.');
        }

        return \in_array($this->getMethod(), array('GET', 'HEAD', 'OPTIONS', 'TRACE'));
    }

    /**
     * Checks whether or not the method is idempotent.
     *
     * @return bool
     */
    public function isMethodIdempotent()
    {
        return \in_array($this->getMethod(), array('HEAD', 'GET', 'PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PURGE'));
    }

    /**
     * Checks whether the method is cacheable or not.
     *
     * @see https://tools.ietf.org/html/rfc7231#section-4.2.3
     *
     * @return bool
     */
    public function isMethodCacheable()
    {
        return \in_array($this->getMethod(), array('GET', 'HEAD'));
    }

    /**
     * Returns the protocol version.
     *
     * If the application is behind a proxy, the protocol version used in the
     * requests between the client and the proxy and between the proxy and the
     * server might be different. This returns the former (from the "Via" header)
     * if the proxy is trusted (see "setTrustedProxies()"), otherwise it returns
     * the latter (from the "SERVER_PROTOCOL" server parameter).
     *
     * @return string
     */
    public function getProtocolVersion()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if ($this->isFromTrustedProxy()) {
            preg_match('~^(HTTP/)?([1-9]\.[0-9]) ~', $dict['headers']->get('Via'), $matches);

            if ($matches) {
                return 'HTTP/' . $matches[2];
            }
        }

        return $dict['server']->get('SERVER_PROTOCOL');
    }

    /**
     * Returns the request body content.
     *
     * @param bool $asResource If true, a resource will be returned
     *
     * @return string|resource The request body content or a resource to read the body stream
     *
     * @throws \LogicException
     */
    public function getContent($asResource = false)
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];
        $currentContentIsResource = \is_resource($dict['content']);

        if (true === $asResource) {
            if ($currentContentIsResource) {
                rewind($dict['content']);

                return $dict['content'];
            }

            // Content passed in parameter (test)
            if (\is_string($dict['content'])) {
                $resource = fopen('php://temp', 'r+');
                fwrite($resource, $dict['content']);
                rewind($resource);

                return $resource;
            }

            $dict['content'] = false;

            return fopen('php://input', 'rb');
        }

        if ($currentContentIsResource) {
            rewind($dict['content']);

            return stream_get_contents($dict['content']);
        }

        if (null === $dict['content'] || false === $dict['content']) {
            $dict['content'] = file_get_contents('php://input');
        }

        return $dict['content'];
    }

    /**
     * Gets the Etags.
     *
     * @return array The entity tags
     */
    public function getETags()
    {
        return preg_split('/\s*,\s*/', static::$corDict[\Swoole\Coroutine::getuid()]['headers']->get('if_none_match'), null, PREG_SPLIT_NO_EMPTY);
    }

    /**
     * @return bool
     */
    public function isNoCache()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];
        return $dict['headers']->hasCacheControlDirective('no-cache') || 'no-cache' == $dict['headers']->get('Pragma');
    }

    /**
     * Returns the preferred language.
     *
     * @param array $locales An array of ordered available locales
     *
     * @return string|null The preferred locale
     */
    public function getPreferredLanguage(array $locales = null)
    {
        $preferredLanguages = $this->getLanguages();

        if (empty($locales)) {
            return isset($preferredLanguages[0]) ? $preferredLanguages[0] : null;
        }

        if (!$preferredLanguages) {
            return $locales[0];
        }

        $extendedPreferredLanguages = array();
        foreach ($preferredLanguages as $language) {
            $extendedPreferredLanguages[] = $language;
            if (false !== $position = strpos($language, '_')) {
                $superLanguage = substr($language, 0, $position);
                if (!\in_array($superLanguage, $preferredLanguages)) {
                    $extendedPreferredLanguages[] = $superLanguage;
                }
            }
        }

        $preferredLanguages = array_values(array_intersect($extendedPreferredLanguages, $locales));

        return isset($preferredLanguages[0]) ? $preferredLanguages[0] : $locales[0];
    }

    /**
     * Gets a list of languages acceptable by the client browser.
     *
     * @return array Languages ordered in the user browser preferences
     */
    public function getLanguages()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null !== $dict['languages']) {
            return $dict['languages'];
        }

        $languages = AcceptHeader::fromString($dict['headers']->get('Accept-Language'))->all();
        $dict['languages'] = array();
        foreach ($languages as $lang => $acceptHeaderItem) {
            if (false !== strpos($lang, '-')) {
                $codes = explode('-', $lang);
                if ('i' === $codes[0]) {
                    // Language not listed in ISO 639 that are not variants
                    // of any listed language, which can be registered with the
                    // i-prefix, such as i-cherokee
                    if (\count($codes) > 1) {
                        $lang = $codes[1];
                    }
                } else {
                    for ($i = 0, $max = \count($codes); $i < $max; ++$i) {
                        if (0 === $i) {
                            $lang = strtolower($codes[0]);
                        } else {
                            $lang .= '_' . strtoupper($codes[$i]);
                        }
                    }
                }
            }

            $dict['languages'][] = $lang;
        }

        return $dict['languages'];
    }

    /**
     * Gets a list of charsets acceptable by the client browser.
     *
     * @return array List of charsets in preferable order
     */
    public function getCharsets()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null !== $dict['charsets']) {
            return $dict['charsets'];
        }

        return $dict['charsets'] = array_keys(AcceptHeader::fromString($dict['headers']->get('Accept-Charset'))->all());
    }

    /**
     * Gets a list of encodings acceptable by the client browser.
     *
     * @return array List of encodings in preferable order
     */
    public function getEncodings()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null !== $dict['encodings']) {
            return $dict['encodings'];
        }

        return $dict['encodings'] = array_keys(AcceptHeader::fromString($dict['headers']->get('Accept-Encoding'))->all());
    }

    /**
     * Gets a list of content types acceptable by the client browser.
     *
     * @return array List of content types in preferable order
     */
    public function getAcceptableContentTypes()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];
        if (null !== $dict['acceptableContentTypes']) {
            return $dict['acceptableContentTypes'];
        }

        return $dict['acceptableContentTypes'] = array_keys(AcceptHeader::fromString($dict['headers']->get('Accept'))->all());
    }

    /**
     * Returns true if the request is a XMLHttpRequest.
     *
     * It works if your JavaScript library sets an X-Requested-With HTTP header.
     * It is known to work with common JavaScript frameworks:
     *
     * @see http://en.wikipedia.org/wiki/List_of_Ajax_frameworks#JavaScript
     *
     * @return bool true if the request is an XMLHttpRequest, false otherwise
     */
    public function isXmlHttpRequest()
    {
        return 'XMLHttpRequest' == static::$corDict[\Swoole\Coroutine::getuid()]['headers']->get('X-Requested-With');
    }

    /*
     * The following methods are derived from code of the Zend Framework (1.10dev - 2010-01-24)
     *
     * Code subject to the new BSD license (http://framework.zend.com/license/new-bsd).
     *
     * Copyright (c) 2005-2010 Zend Technologies USA Inc. (http://www.zend.com)
     */

    protected function prepareRequestUri()
    {
        $requestUri = '';

        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];
        $server = $dict['server'];
        if ('1' == $server->get('IIS_WasUrlRewritten') && '' != $server->get('UNENCODED_URL')) {
            // IIS7 with URL Rewrite: make sure we get the unencoded URL (double slash problem)
            $requestUri = $server->get('UNENCODED_URL');
            $server->remove('UNENCODED_URL');
            $server->remove('IIS_WasUrlRewritten');
        } elseif ($server->has('REQUEST_URI')) {
            $requestUri = $server->get('REQUEST_URI');
            // HTTP proxy reqs setup request URI with scheme and host [and port] + the URL path, only use URL path
            $schemeAndHttpHost = $this->getSchemeAndHttpHost();
            if (0 === strpos($requestUri, $schemeAndHttpHost)) {
                $requestUri = substr($requestUri, \strlen($schemeAndHttpHost));
            }
        } elseif ($server->has('ORIG_PATH_INFO')) {
            // IIS 5.0, PHP as CGI
            $requestUri = $server->get('ORIG_PATH_INFO');
            if ('' != $server->get('QUERY_STRING')) {
                $requestUri .= '?' . $server->get('QUERY_STRING');
            }
            $server->remove('ORIG_PATH_INFO');
        }

        // normalize the request URI to ease creating sub-requests from this request
        $server->set('REQUEST_URI', $requestUri);

        return $requestUri;
    }

    /**
     * Prepares the base URL.
     *
     * @return string
     */
    protected function prepareBaseUrl($dict)
    {
        $server = $dict['server'];
        $filename = basename($server->get('SCRIPT_FILENAME'));

        if (basename($server->get('SCRIPT_NAME')) === $filename) {
            $baseUrl = $server->get('SCRIPT_NAME');
        } elseif (basename($server->get('PHP_SELF')) === $filename) {
            $baseUrl = $server->get('PHP_SELF');
        } elseif (basename($server->get('ORIG_SCRIPT_NAME')) === $filename) {
            $baseUrl = $server->get('ORIG_SCRIPT_NAME'); // 1and1 shared hosting compatibility
        } else {
            // Backtrack up the script_filename to find the portion matching
            // php_self
            $path = $server->get('PHP_SELF', '');
            $file = $server->get('SCRIPT_FILENAME', '');
            $segs = explode('/', trim($file, '/'));
            $segs = array_reverse($segs);
            $index = 0;
            $last = \count($segs);
            $baseUrl = '';
            do {
                $seg = $segs[$index];
                $baseUrl = '/' . $seg . $baseUrl;
                ++$index;
            } while ($last > $index && (false !== $pos = strpos($path, $baseUrl)) && 0 != $pos);
        }

        // Does the baseUrl have anything in common with the request_uri?
        $requestUri = $this->getRequestUri();
        if ('' !== $requestUri && '/' !== $requestUri[0]) {
            $requestUri = '/' . $requestUri;
        }

        if ($baseUrl && false !== $prefix = $this->getUrlencodedPrefix($requestUri, $baseUrl)) {
            // full $baseUrl matches
            return $prefix;
        }

        if ($baseUrl && false !== $prefix = $this->getUrlencodedPrefix($requestUri, rtrim(\dirname($baseUrl), '/' . \DIRECTORY_SEPARATOR) . '/')) {
            // directory portion of $baseUrl matches
            return rtrim($prefix, '/' . \DIRECTORY_SEPARATOR);
        }

        $truncatedRequestUri = $requestUri;
        if (false !== $pos = strpos($requestUri, '?')) {
            $truncatedRequestUri = substr($requestUri, 0, $pos);
        }

        $basename = basename($baseUrl);
        if (empty($basename) || !strpos(rawurldecode($truncatedRequestUri), $basename)) {
            // no match whatsoever; set it blank
            return '';
        }

        // If using mod_rewrite or ISAPI_Rewrite strip the script filename
        // out of baseUrl. $pos !== 0 makes sure it is not matching a value
        // from PATH_INFO or QUERY_STRING
        if (\strlen($requestUri) >= \strlen($baseUrl) && (false !== $pos = strpos($requestUri, $baseUrl)) && 0 !== $pos) {
            $baseUrl = substr($requestUri, 0, $pos + \strlen($baseUrl));
        }

        return rtrim($baseUrl, '/' . \DIRECTORY_SEPARATOR);
    }

    /**
     * Prepares the base path.
     *
     * @return string base path
     */
    protected function prepareBasePath($dict)
    {
        $baseUrl = $this->getBaseUrl();
        if (empty($baseUrl)) {
            return '';
        }

        $filename = basename($dict['server']->get('SCRIPT_FILENAME'));
        if (basename($baseUrl) === $filename) {
            $basePath = \dirname($baseUrl);
        } else {
            $basePath = $baseUrl;
        }

        if ('\\' === \DIRECTORY_SEPARATOR) {
            $basePath = str_replace('\\', '/', $basePath);
        }

        return rtrim($basePath, '/');
    }

    /**
     * Prepares the path info.
     *
     * @return string path info
     */
    protected function preparePathInfo()
    {
        if (null === ($requestUri = $this->getRequestUri())) {
            return '/';
        }

        // Remove the query string from REQUEST_URI
        if (false !== $pos = strpos($requestUri, '?')) {
            $requestUri = substr($requestUri, 0, $pos);
        }
        if ('' !== $requestUri && '/' !== $requestUri[0]) {
            $requestUri = '/' . $requestUri;
        }

        if (null === ($baseUrl = $this->getBaseUrl())) {
            return $requestUri;
        }

        $pathInfo = substr($requestUri, \strlen($baseUrl));
        if (false === $pathInfo || '' === $pathInfo) {
            // If substr() returns false then PATH_INFO is set to an empty string
            return '/';
        }

        return (string)$pathInfo;
    }

    /**
     * Initializes HTTP request formats.
     */
    protected static function initializeFormats()
    {
        static::$formats = array(
            'html' => array('text/html', 'application/xhtml+xml'),
            'txt' => array('text/plain'),
            'js' => array('application/javascript', 'application/x-javascript', 'text/javascript'),
            'css' => array('text/css'),
            'json' => array('application/json', 'application/x-json'),
            'jsonld' => array('application/ld+json'),
            'xml' => array('text/xml', 'application/xml', 'application/x-xml'),
            'rdf' => array('application/rdf+xml'),
            'atom' => array('application/atom+xml'),
            'rss' => array('application/rss+xml'),
            'form' => array('application/x-www-form-urlencoded'),
        );
    }

    private function setPhpDefaultLocale(string $locale)
    {
        // if either the class Locale doesn't exist, or an exception is thrown when
        // setting the default locale, the intl module is not installed, and
        // the call can be ignored:
        try {
            if (class_exists('Locale', false)) {
                \Locale::setDefault($locale);
            }
        } catch (\Exception $e) {
        }
    }

    /*
     * Returns the prefix as encoded in the string when the string starts with
     * the given prefix, false otherwise.
     *
     * @return string|false The prefix as it is encoded in $string, or false
     */
    private function getUrlencodedPrefix(string $string, string $prefix)
    {
        if (0 !== strpos(rawurldecode($string), $prefix)) {
            return false;
        }

        $len = \strlen($prefix);

        if (preg_match(sprintf('#^(%%[[:xdigit:]]{2}|.){%d}#', $len), $string, $match)) {
            return $match[0];
        }

        return false;
    }


    private static function createRequestFromFactory(array $query = array(), array $request = array(), array $attributes = array(), array $cookies = array(), array $files = array(), array $server = array(), $content = null)
    {
        if (self::$requestFactory) {
            $request = \call_user_func(self::$requestFactory, $query, $request, $attributes, $cookies, $files, $server, $content);

            if (!$request instanceof self) {
                throw new \LogicException('The Request factory must return an instance of Symfony\Component\HttpFoundation\Request.');
            }

            return $request;
        }

        return new static($query, $request, $attributes, $cookies, $files, $server, $content);
    }

    /**
     * Indicates whether this request originated from a trusted proxy.
     *
     * This can be useful to determine whether or not to trust the
     * contents of a proxy-specific header.
     *
     * @return bool true if the request came from a trusted proxy, false otherwise
     */
    public function isFromTrustedProxy()
    {
        return self::$trustedProxies && IpUtils::checkIp(static::$corDict[\Swoole\Coroutine::getuid()]['server']->get('REMOTE_ADDR'), self::$trustedProxies);
    }

    private function getTrustedValues($type, $ip = null)
    {
        $clientValues = array();
        $forwardedValues = array();

        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if ((self::$trustedHeaderSet & $type) && $dict['headers']->has(self::$trustedHeaders[$type])) {
            foreach (explode(',', $dict['headers']->get(self::$trustedHeaders[$type])) as $v) {
                $clientValues[] = (self::HEADER_X_FORWARDED_PORT === $type ? '0.0.0.0:' : '') . trim($v);
            }
        }

        if ((self::$trustedHeaderSet & self::HEADER_FORWARDED) && $dict['headers']->has(self::$trustedHeaders[self::HEADER_FORWARDED])) {
            $forwarded = $dict['headers']->get(self::$trustedHeaders[self::HEADER_FORWARDED]);
            $parts = HeaderUtils::split($forwarded, ',;=');
            $forwardedValues = array();
            $param = self::$forwardedParams[$type];
            foreach ($parts as $subParts) {
                if (null === $v = HeaderUtils::combine($subParts)[$param] ?? null) {
                    continue;
                }
                if (self::HEADER_X_FORWARDED_PORT === $type) {
                    if (']' === substr($v, -1) || false === $v = strrchr($v, ':')) {
                        $v = $this->isSecure() ? ':443' : ':80';
                    }
                    $v = '0.0.0.0' . $v;
                }
                $forwardedValues[] = $v;
            }
        }

        if (null !== $ip) {
            $clientValues = $this->normalizeAndFilterClientIps($clientValues, $ip);
            $forwardedValues = $this->normalizeAndFilterClientIps($forwardedValues, $ip);
        }

        if ($forwardedValues === $clientValues || !$clientValues) {
            return $forwardedValues;
        }

        if (!$forwardedValues) {
            return $clientValues;
        }

        if (!$dict['isForwardedValid']) {
            return null !== $ip ? array('0.0.0.0', $ip) : array();
        }
        $dict['isForwardedValid'] = false;

        throw new ConflictingHeadersException(sprintf('The request has both a trusted "%s" header and a trusted "%s" header, conflicting with each other. You should either configure your proxy to remove one of them, or configure your project to distrust the offending one.', self::$trustedHeaders[self::HEADER_FORWARDED], self::$trustedHeaders[$type]));
    }

    private function normalizeAndFilterClientIps(array $clientIps, $ip)
    {
        if (!$clientIps) {
            return array();
        }
        $clientIps[] = $ip; // Complete the IP chain with the IP the request actually came from
        $firstTrustedIp = null;

        foreach ($clientIps as $key => $clientIp) {
            if (strpos($clientIp, '.')) {
                // Strip :port from IPv4 addresses. This is allowed in Forwarded
                // and may occur in X-Forwarded-For.
                $i = strpos($clientIp, ':');
                if ($i) {
                    $clientIps[$key] = $clientIp = substr($clientIp, 0, $i);
                }
            } elseif (0 === strpos($clientIp, '[')) {
                // Strip brackets and :port from IPv6 addresses.
                $i = strpos($clientIp, ']', 1);
                $clientIps[$key] = $clientIp = substr($clientIp, 1, $i - 1);
            }

            if (!filter_var($clientIp, FILTER_VALIDATE_IP)) {
                unset($clientIps[$key]);

                continue;
            }

            if (IpUtils::checkIp($clientIp, self::$trustedProxies)) {
                unset($clientIps[$key]);

                // Fallback to this when the client IP falls into the range of trusted proxies
                if (null === $firstTrustedIp) {
                    $firstTrustedIp = $clientIp;
                }
            }
        }

        // Now the IP chain contains only untrusted proxies and the client IP
        return $clientIps ? array_reverse($clientIps) : array($firstTrustedIp);
    }
}
