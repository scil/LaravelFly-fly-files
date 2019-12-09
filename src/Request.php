<?php
/**
 * 1. dict
 * 2. SingletonRequestException
 * 3. cache vars prefix with 'fly'
 * 4. extra var $corDict['flyChangedForAll'] for updating cache
 * 5. extra caches marked with 'hack'
 */

namespace Illuminate\Http;

use ArrayAccess;
use Closure;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Support\Traits\Macroable;
use RuntimeException;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

use LaravelFly\Map\IlluminateBase\SingletonRequestException;


class Request extends SymfonyRequest implements Arrayable, ArrayAccess
{
    use Concerns\InteractsWithContentTypes,
        Concerns\InteractsWithFlashData,
        Concerns\InteractsWithInput,
        Macroable;

    /**
     * Create a new Illuminate HTTP request from server variables.
     *
     * @return static
     */
    public static function capture()
    {
        throw new SingletonRequestException();
    }

    /**
     * Return the Request instance.
     *
     * @return $this
     */
    public function instance()
    {
        return $this;
    }

    /**
     * Get the request method.
     *
     * @return string
     */
    public function method()
    {
        return $this->getMethod();
    }

    /**
     * Get the root URL for the application.
     *
     * @return string
     */
    public function root()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['flyRoot']) {
            return $dict['flyRoot'] = rtrim($this->getSchemeAndHttpHost() . $this->getBaseUrl(), '/');
        }

        return $dict['flyRoot'];

        return rtrim($this->getSchemeAndHttpHost() . $this->getBaseUrl(), '/');
    }

    /**
     * Get the URL (no query string) for the request.
     *
     * @return string
     */
    public function url()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['flyUrl']) {
            return $dict['flyUrl'] = rtrim(preg_replace('/\?.*/', '', $this->getUri()), '/');
        }

        return $dict['flyUrl'];

        return rtrim(preg_replace('/\?.*/', '', $this->getUri()), '/');
    }

    /**
     * Get the full URL for the request.
     *
     * @return string
     */
    public function fullUrl()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['flyFullUrl']) {
            $query = $this->getQueryString();

            $question = $this->getBaseUrl() . $this->getPathInfo() === '/' ? '/?' : '?';

            return $dict['flyFullUrl'] = $query ? $this->url() . $question . $query : $this->url();;
        }

        return $dict['flyFullUrl'];

        $query = $this->getQueryString();

        $question = $this->getBaseUrl() . $this->getPathInfo() === '/' ? '/?' : '?';

        return $query ? $this->url() . $question . $query : $this->url();
    }

    /**
     * Get the full URL for the request with the added query string parameters.
     *
     * @param  array $query
     * @return string
     */
    public function fullUrlWithQuery(array $query)
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['flyUrlWithQuery']) {
            $question = $this->getBaseUrl() . $this->getPathInfo() === '/' ? '/?' : '?';

            return $dict['flyUrlWithQuery'] = count($this->query()) > 0
            ? $this->url().$question.Arr::query(array_merge($this->query(), $query))
            : $this->fullUrl().$question.Arr::query($query);

        }

        return $dict['flyUrlWithQuery'];

        $question = $this->getBaseUrl() . $this->getPathInfo() == '/' ? '/?' : '?';

        return count($this->query()) > 0
            ? $this->url() . $question . http_build_query(array_merge($this->query(), $query))
            : $this->fullUrl() . $question . http_build_query($query);
    }

    /**
     * Get the current path info for the request.
     *
     * @return string
     */
    public function path()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['flyPath']) {
            $pattern = trim($this->getPathInfo(), '/');
            return $dict['flyPath'] = $pattern == '' ? '/' : $pattern;
        }

        return $dict['flyPath'];

        $pattern = trim($this->getPathInfo(), '/');

        return $pattern == '' ? '/' : $pattern;
    }

    /**
     * Get the current decoded path info for the request.
     *
     * @return string
     */
    public function decodedPath()
    {
        return rawurldecode($this->path());
    }

    /**
     * Get a segment from the URI (1 based index).
     *
     * @param  int $index
     * @param  string|null $default
     * @return string|null
     */
    public function segment($index, $default = null)
    {
        return Arr::get($this->segments(), $index - 1, $default);
    }

    /**
     * Get all of the segments for the request path.
     *
     * @return array
     */
    public function segments()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['flySegments']) {
            $segments = explode('/', $this->decodedPath());
            return $dict['flySegments'] = array_values(array_filter($segments, function ($value) {
                return $value !== '';
            }));
        }

        return $dict['flySegments'];

        $segments = explode('/', $this->decodedPath());

        return array_values(array_filter($segments, function ($value) {
            return $value !== '';
        }));
    }

    /**
     * Determine if the current request URI matches a pattern.
     *
     * @param  mixed  ...$patterns
     * @return bool
     */
    public function is(...$patterns)
    {
        $path = $this->decodedPath();

        foreach ($patterns as $pattern) {
            if (Str::is($pattern, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the route name matches a given pattern.
     *
     * @param  mixed  ...$patterns
     * @return bool
     */
    public function routeIs(...$patterns)
    {
        return $this->route() && $this->route()->named(...$patterns);
    }

    /**
     * Determine if the current request URL and query string matches a pattern.
     *
     * @param  mixed  ...$patterns
     * @return bool
     */
    public function fullUrlIs(...$patterns)
    {
        $url = $this->fullUrl();

        foreach ($patterns as $pattern) {
            if (Str::is($pattern, $url)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the request is the result of an AJAX call.
     *
     * @return bool
     */
    public function ajax()
    {
        return $this->isXmlHttpRequest();
    }

    /**
     * Determine if the request is the result of an PJAX call.
     *
     * @return bool
     */
    public function pjax()
    {
        return static::$corDict[\Swoole\Coroutine::getuid()]['headers']->get('X-PJAX') == true;
    }

    /**
     * Determine if the request is the result of an prefetch call.
     *
     * @return bool
     */
    public function prefetch()
    {
        $dict = static::$corDict[\Swoole\Coroutine::getuid()];

        return strcasecmp($dict['server']->get('HTTP_X_MOZ'), 'prefetch') === 0 ||
               strcasecmp($dict['headers']->get('Purpose'), 'prefetch') === 0;
    }

    /**
     * Determine if the request is over HTTPS.
     *
     * @return bool
     */
    public function secure()
    {
        return $this->isSecure();
    }

    /**
     * Get the client IP address.
     *
     * @return string|null
     */
    public function ip()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        return $dict['flyIp'] ?? ( $dict['flyIp'] = $this->getClientIp() );

    }

    /**
     * Get the client IP addresses.
     *
     * @return array
     */
    public function ips()
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['flyIps']) {
            return $dict['flyIps'] = $this->getClientIps();
        }

        return $dict['flyIps'];

        return $this->getClientIps();
    }

    /**
     * Get the client user agent.
     *
     * @return string
     */
    public function userAgent()
    {
        return static::$corDict[\Swoole\Coroutine::getuid()]['headers']->get('User-Agent');
    }

    /**
     * Merge new input into the current request's input array.
     *
     * @param  array $input
     * @return $this
     */
    public function merge(array $input)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;
        $this->getInputSource()->add($input);

        return $this;
    }

    /**
     * Replace the input for the current request.
     *
     * @param  array $input
     * @return $this
     */
    public function replace(array $input)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;
        $this->getInputSource()->replace($input);

        return $this;
    }

    /**
     * This method belongs to Symfony HttpFoundation and is not usually needed when using Laravel.
     *
     * Instead, you may use the "input" method.
     *
     * @param  string $key
     * @param  mixed $default
     * @return mixed
     */
    public function get($key, $default = null)
    {
        return parent::get($key, $default);
    }

    /**
     * Get the JSON payload for the request.
     *
     * @param  string|null  $key
     * @param  mixed $default
     * @return \Symfony\Component\HttpFoundation\ParameterBag|mixed
     */
    public function json($key = null, $default = null)
    {
        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        // print_r(__FILE__,__LINE__);

        if (!isset($dict['json'])) {
            static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;
            $dict['json'] = new ParameterBag((array)json_decode($this->getContent(), true));
        }

        if (is_null($key)) {
            return $dict['json'];
        }

        return data_get($dict['json']->all(), $key, $default);
    }

    /**
     * Get the input source for the request.
     *
     * @return \Symfony\Component\HttpFoundation\ParameterBag
     */
    protected function getInputSource()
    {
        // no cache for json, because there's a method setJson may change cache
        if ($this->isJson()) {
            return $this->json();
        }

        $dict = &static::$corDict[\Swoole\Coroutine::getuid()];

        if (null === $dict['flyInputSource']) {
            return $dict['flyInputSource'] =
                in_array($this->getRealMethod(), ['GET', 'HEAD']) ? $dict['query'] : $dict['request'];
        }

        return $dict['flyInputSource'];

        if ($this->isJson()) {
            return $this->json();
        }

        $dict = static::$corDict[\Swoole\Coroutine::getuid()];

        return in_array($this->getRealMethod(), ['GET', 'HEAD']) ? $dict['query'] : $dict['request'];
    }

    /**
     * Create a new request instance from the given Laravel request.
     *
     * @param  \Illuminate\Http\Request $from
     * @param  \Illuminate\Http\Request|null $to
     * @return static
     */
    public static function createFrom(self $from, $to = null)
    {
        throw new SingletonRequestException();
        static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;
    }

    /**
     * Create an Illuminate request from a Symfony instance.
     *
     * @param  \Symfony\Component\HttpFoundation\Request $request
     * @return static
     */
    public static function createFromBase(SymfonyRequest $request)
    {
        throw new SingletonRequestException();
        static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;
    }

    /**
     * {@inheritdoc}
     */
    public function duplicate(array $query = null, array $request = null, array $attributes = null, array $cookies = null, array $files = null, array $server = null)
    {
        throw new SingletonRequestException();
        static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;
    }

    /**
     * Filter the given array of files, removing any empty values.
     *
     * @param  mixed $files
     * @return mixed
     */
    protected function filterFiles($files)
    {
        if (!$files) {
            return;
        }

        foreach ($files as $key => $file) {
            if (is_array($file)) {
                $files[$key] = $this->filterFiles($files[$key]);
            }

            if (empty($files[$key])) {
                unset($files[$key]);
            }
        }

        return $files;
    }

    /**
     * Get the session associated with the request.
     *
     * @return \Illuminate\Session\Store
     *
     * @throws \RuntimeException
     */
    public function session()
    {
        if (!$this->hasSession()) {
            throw new RuntimeException('Session store not set on request.');
        }

        return static::$corDict[\Swoole\Coroutine::getuid()]['session'];
    }

    /**
     * Get the session associated with the request.
     *
     * @return \Illuminate\Session\Store|null
     */
    public function getSession()
    {
        return static::$corDict[\Swoole\Coroutine::getuid()]['session'];
    }

    /**
     * Set the session instance on the request.
     *
     * @param  \Illuminate\Contracts\Session\Session $session
     * @return void
     */
    public function setLaravelSession($session)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['session'] = $session;
    }

    /**
     * Get the user making the request.
     *
     * @param  string|null $guard
     * @return mixed
     */
    public function user($guard = null)
    {
        return call_user_func($this->getUserResolver(), $guard);
    }

    /**
     * Get the route handling the request.
     *
     * @param  string|null $param
     * @param  mixed   $default
     *
     * @return \Illuminate\Routing\Route|object|string
     */
    public function route($param = null, $default = null)
    {
        $route = call_user_func($this->getRouteResolver());

        if (is_null($route) || is_null($param)) {
            return $route;
        }

        return $route->parameter($param, $default);
    }

    /**
     * Get a unique fingerprint for the request / route / IP address.
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    public function fingerprint()
    {
        if (!$route = $this->route()) {
            throw new RuntimeException('Unable to generate fingerprint. Route unavailable.');
        }

        return sha1(implode('|', array_merge(
            $route->methods(),
            [$route->getDomain(), $route->uri(), $this->ip()]
        )));
    }

    /**
     * Set the JSON payload for the request.
     *
     * @param  \Symfony\Component\HttpFoundation\ParameterBag $json
     * @return $this
     */
    public function setJson($json)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;

        static::$corDict[\Swoole\Coroutine::getuid()]['json'] = $json;

        return $this;
    }

    /**
     * Get the user resolver callback.
     *
     * @return \Closure
     */
    public function getUserResolver()
    {
        return static::$corDict[\Swoole\Coroutine::getuid()]['userResolver'] ?: function () {
            //
        };
    }

    /**
     * Set the user resolver callback.
     *
     * @param  \Closure $callback
     * @return $this
     */
    public function setUserResolver(Closure $callback)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['userResolver'] = $callback;

        return $this;
    }

    /**
     * Get the route resolver callback.
     *
     * @return \Closure
     */
    public function getRouteResolver()
    {
        return static::$corDict[\Swoole\Coroutine::getuid()]['routeResolver'] ?: function () {
            //
        };
    }

    /**
     * Set the route resolver callback.
     *
     * @param  \Closure $callback
     * @return $this
     */
    public function setRouteResolver(Closure $callback)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['routeResolver'] = $callback;

        return $this;
    }

    /**
     * Get all of the input and files for the request.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->all();
    }

    /**
     * Determine if the given offset exists.
     *
     * @param  string $offset
     * @return bool
     */
    public function offsetExists($offset)
    {
        return Arr::has(
            $this->all() + $this->route()->parameters(),
            $offset
        );
    }

    /**
     * Get the value at the given offset.
     *
     * @param  string $offset
     * @return mixed
     */
    public function offsetGet($offset)
    {
        return $this->__get($offset);
    }

    /**
     * Set the value at the given offset.
     *
     * @param  string $offset
     * @param  mixed $value
     * @return void
     */
    public function offsetSet($offset, $value)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;
        $this->getInputSource()->set($offset, $value);
    }

    /**
     * Remove the value at the given offset.
     *
     * @param  string $offset
     * @return void
     */
    public function offsetUnset($offset)
    {
        static::$corDict[\Swoole\Coroutine::getuid()]['flyChangedForAll'] = true;
        $this->getInputSource()->remove($offset);
    }

    /**
     * Check if an input element is set on the request.
     *
     * @param  string $key
     * @return bool
     */
    public function __isset($key)
    {
        return !is_null($this->__get($key));
    }

    /**
     * Get an input element from the request.
     *
     * @param  string $key
     * @return mixed
     */
    public function __get($key)
    {
        return Arr::get($this->all(), $key, function () use ($key) {
            return $this->route($key);
        });
    }
}
