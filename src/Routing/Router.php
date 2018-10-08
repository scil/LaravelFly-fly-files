<?php
/**
 * add Dict, plus
 *
 * 1.    $middlewareCacheByRoute
 *   note that this cache is totally useless when a route middleware may be registered in a request.
 *   so vars are across multple requests, changed in any request would change this var
 *
 *   update: when LARAVELFLY_SERVICES['kernel'] && LARAVELFLY_SERVICES['routes'], $middlewareStable is useless and cache is used always
 *        $middlewareAlwaysStable
 *
 * 2.   $singletonMiddlewares
 *
 *
 */

namespace Illuminate\Routing;

use Closure;
use ArrayObject;
use JsonSerializable;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Collection;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Traits\Macroable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Contracts\Routing\BindingRegistrar;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Illuminate\Contracts\Routing\Registrar as RegistrarContract;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

class Router implements RegistrarContract, BindingRegistrar
{
    use \LaravelFly\Map\Util\Dict {
        \LaravelFly\Map\Util\Dict::initForRequestCorontine as init;
    }
    use Macroable {
        __call as macroCall;
    }
    protected $events;
    /**
     * The IoC container instance.
     *
     * @var \LaravelFly\Map\Application
     */
    protected $container;

    public static $verbs = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

    protected static $normalAttriForObj = [
        // see below
    ];

    protected static $arrayAttriForObj = ['middleware', 'middlewareGroups', 'middlewarePriority', 'binders', 'patterns',

        // no refactor for coroutine
        // 'groupStack'
    ];

    protected $groupStack = [];

    public function __construct(Dispatcher $events, Container $container = null)
    {
        $this->events = $events;
        $this->container = $container ?: new Container;

        static::$normalAttriForObj = [
            'current' => null,
            'currentRequest' => null,
            'routes' => function () {
                return new RouteCollection;
            }
        ];
        $this->initOnWorker(false);
    }


    public function initForRequestCorontine($cid)
    {
        $this->init($cid);

        if (!LARAVELFLY_SERVICES['routes']) {
            $newRoutes = clone static::$corDict[WORKER_COROUTINE_ID]['routes'];
            static::$corDict[$cid]['routes'] = $newRoutes;
            $this->container->instance('routes', $newRoutes);
        }
    }

    public function get($uri, $action = null)
    {
        return $this->addRoute(['GET', 'HEAD'], $uri, $action);
    }

    /**
     * Register a new POST route with the router.
     *
     * @param  string $uri
     * @param  \Closure|array|string|null $action
     * @return \Illuminate\Routing\Route
     */
    public function post($uri, $action = null)
    {
        return $this->addRoute('POST', $uri, $action);
    }

    /**
     * Register a new PUT route with the router.
     *
     * @param  string $uri
     * @param  \Closure|array|string|null $action
     * @return \Illuminate\Routing\Route
     */
    public function put($uri, $action = null)
    {
        return $this->addRoute('PUT', $uri, $action);
    }

    /**
     * Register a new PATCH route with the router.
     *
     * @param  string $uri
     * @param  \Closure|array|string|null $action
     * @return \Illuminate\Routing\Route
     */
    public function patch($uri, $action = null)
    {
        return $this->addRoute('PATCH', $uri, $action);
    }

    /**
     * Register a new DELETE route with the router.
     *
     * @param  string $uri
     * @param  \Closure|array|string|null $action
     * @return \Illuminate\Routing\Route
     */
    public function delete($uri, $action = null)
    {
        return $this->addRoute('DELETE', $uri, $action);
    }

    /**
     * Register a new OPTIONS route with the router.
     *
     * @param  string $uri
     * @param  \Closure|array|string|null $action
     * @return \Illuminate\Routing\Route
     */
    public function options($uri, $action = null)
    {
        return $this->addRoute('OPTIONS', $uri, $action);
    }

    /**
     * Register a new route responding to all verbs.
     *
     * @param  string $uri
     * @param  \Closure|array|string|null $action
     * @return \Illuminate\Routing\Route
     */
    public function any($uri, $action = null)
    {
        return $this->addRoute(self::$verbs, $uri, $action);
    }

    /**
     * Register a new Fallback route with the router.
     *
     * @param  \Closure|array|string|null $action
     * @return \Illuminate\Routing\Route
     */
    public function fallback($action)
    {
        $placeholder = 'fallbackPlaceholder';

        return $this->addRoute(
            'GET', "{{$placeholder}}", $action
        )->where($placeholder, '.*')->fallback();
    }

    /**
     * Create a redirect from one URI to another.
     *
     * @param  string $uri
     * @param  string $destination
     * @param  int $status
     * @return \Illuminate\Routing\Route
     */
    public function redirect($uri, $destination, $status = 301)
    {
        return $this->any($uri, '\Illuminate\Routing\RedirectController')
            ->defaults('destination', $destination)
            ->defaults('status', $status);
    }

    /**
     * Register a new route that returns a view.
     *
     * @param  string $uri
     * @param  string $view
     * @param  array $data
     * @return \Illuminate\Routing\Route
     */
    public function view($uri, $view, $data = [])
    {
        return $this->match(['GET', 'HEAD'], $uri, '\Illuminate\Routing\ViewController')
            ->defaults('view', $view)
            ->defaults('data', $data);
    }

    /**
     * Register a new route with the given verbs.
     *
     * @param  array|string $methods
     * @param  string $uri
     * @param  \Closure|array|string|null $action
     * @return \Illuminate\Routing\Route
     */
    public function match($methods, $uri, $action = null)
    {
        return $this->addRoute(array_map('strtoupper', (array)$methods), $uri, $action);
    }

    /**
     * Register an array of resource controllers.
     *
     * @param  array $resources
     * @return void
     */
    public function resources(array $resources)
    {
        foreach ($resources as $name => $controller) {
            $this->resource($name, $controller);
        }
    }

    /**
     * Route a resource to a controller.
     *
     * @param  string $name
     * @param  string $controller
     * @param  array $options
     * @return \Illuminate\Routing\PendingResourceRegistration
     */
    public function resource($name, $controller, array $options = [])
    {
        if ($this->container && $this->container->bound(ResourceRegistrar::class)) {
            $registrar = $this->container->make(ResourceRegistrar::class);
        } else {
            $registrar = new ResourceRegistrar($this);
        }

        return new PendingResourceRegistration(
            $registrar, $name, $controller, $options
        );
    }

    /**
     * Register an array of API resource controllers.
     *
     * @param  array $resources
     * @return void
     */
    public function apiResources(array $resources)
    {
        foreach ($resources as $name => $controller) {
            $this->apiResource($name, $controller);
        }
    }

    /**
     * Route an API resource to a controller.
     *
     * @param  string $name
     * @param  string $controller
     * @param  array $options
     * @return \Illuminate\Routing\PendingResourceRegistration
     */
    public function apiResource($name, $controller, array $options = [])
    {
        return $this->resource($name, $controller, array_merge([
            'only' => ['index', 'show', 'store', 'update', 'destroy'],
        ], $options));
    }

    public function group(array $attributes, $routes)
    {
        $this->updateGroupStack($attributes);

        // Once we have updated the group stack, we'll load the provided routes and
        // merge in the group's attributes when the routes are created. After we
        // have created the routes, we will pop the attributes off the stack.
        $this->loadRoutes($routes);

        array_pop($this->groupStack);
    }

    protected function updateGroupStack(array $attributes)
    {
        if (!empty($this->groupStack)) {
            $attributes = RouteGroup::merge($attributes, end($this->groupStack));
        }

        $this->groupStack[] = $attributes;
    }

    /**
     * Merge the given array with the last group stack.
     *
     * @param  array $new
     * @return array
     */
    public function mergeWithLastGroup($new)
    {
        return RouteGroup::merge($new, end($this->groupStack));
    }

    protected function loadRoutes($routes)
    {
        if ($routes instanceof Closure) {
            $routes($this);
        } else {
            $router = $this;

            require $routes;
        }
    }

    public function getLastGroupPrefix()
    {
        if (!empty($this->groupStack)) {
            $last = end($this->groupStack);

            return $last['prefix'] ?? '';
        }

        return '';
    }

    protected function addRoute($methods, $uri, $action)
    {
        return static::$corDict[\Co::getUid()]['routes']->add($this->createRoute($methods, $uri, $action));
    }

    protected function createRoute($methods, $uri, $action)
    {

        // If the route is routing to a controller we will parse the route action into
        // an acceptable array format before registering it and creating this route
        // instance itself. We need to build the Closure that will call this out.
        if ($this->actionReferencesController($action)) {
            $action = $this->convertToControllerAction($action);
        }

        $route = $this->newRoute(
            $methods, $this->prefix($uri), $action
        );

        // If we have groups that need to be merged, we will merge them now after this
        // route has already been created and is ready to go. After we're done with
        // the merge we will be ready to return the route back out to the caller.
        if ($this->hasGroupStack()) {
            $this->mergeGroupAttributesIntoRoute($route);
        }

        $this->addWhereClausesToRoute($route);

        return $route;
    }

    protected function actionReferencesController($action)
    {
        if (!$action instanceof Closure) {
            return is_string($action) || (isset($action['uses']) && is_string($action['uses']));
        }

        return false;
    }

    protected function convertToControllerAction($action)
    {
        if (is_string($action)) {
            $action = ['uses' => $action];
        }

        // Here we'll merge any group "uses" statement if necessary so that the action
        // has the proper clause for this property. Then we can simply set the name
        // of the controller on the action and return the action array for usage.
        if (!empty($this->groupStack)) {
            $action['uses'] = $this->prependGroupNamespace($action['uses']);
        }

        // Here we will set this controller name on the action array just so we always
        // have a copy of it for reference if we need it. This can be used while we
        // search for a controller name or do some other type of fetch operation.
        $action['controller'] = $action['uses'];

        return $action;
    }

    protected function prependGroupNamespace($class)
    {
        $group = end($this->groupStack);

        return isset($group['namespace']) && strpos($class, '\\') !== 0
            ? $group['namespace'] . '\\' . $class : $class;
    }

    protected function newRoute($methods, $uri, $action)
    {
        return (new Route($methods, $uri, $action))
            ->setRouter($this)
            ->setContainer($this->container);
    }

    /**
     * Prefix the given URI with the last prefix.
     *
     * @param  string $uri
     * @return string
     */
    protected function prefix($uri)
    {
        return trim(trim($this->getLastGroupPrefix(), '/') . '/' . trim($uri, '/'), '/') ?: '/';
    }

    protected function addWhereClausesToRoute($route)
    {
        $route->where(array_merge(
            static::$corDict[\Swoole\Coroutine::getuid()]['patterns'], $route->getAction()['where'] ?? []
        ));

        return $route;
    }

    protected function mergeGroupAttributesIntoRoute($route)
    {
        $route->setAction($this->mergeWithLastGroup($route->getAction()));
    }

    public function respondWithRoute($name)
    {
        $cid = \Co::getUid();

        $route = tap(static::$corDict[$cid]['routes']->getByName($name))->bind(static::$corDict[$cid]['currentRequest']);

        return $this->runRoute(static::$corDict[$cid]['currentRequest'], $route);
    }

    /**
     * Dispatch the request to the application.
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    public function dispatch(Request $request)
    {
        static::$corDict[\Co::getUid()]['currentRequest'] = $request;

        return $this->dispatchToRoute($request);
    }

    public function dispatchToRoute(Request $request)
    {
        return $this->runRoute($request, $this->findRoute($request));
    }

    protected function findRoute($request)
    {
        $cid = \Co::getUid();

        static::$corDict[$cid]['current'] = $route = static::$corDict[$cid]['routes']->match($request);

        $this->container->instance(Route::class, $route);

        return $route;
    }

    /**
     * Return the response for the given route.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Illuminate\Routing\Route $route
     * @return mixed
     */
    protected function runRoute(Request $request, Route $route)
    {

        $request->setRouteResolver(function () use ($route) {
            return $route;
        });

        $this->events->dispatch(new Events\RouteMatched($route, $request));

        return $this->prepareResponse($request,
            $this->runRouteWithinStack($route, $request)
        );
    }

    protected function runRouteWithinStack(Route $route, Request $request)
    {
        $shouldSkipMiddleware = $this->container->bound('middleware.disable') &&
            $this->container->make('middleware.disable') === true;

        $middleware = $shouldSkipMiddleware ? [] : $this->gatherRouteMiddleware($route);

        return (new Pipeline($this->container))
            ->send($request)
            ->through($middleware)
            ->then(function ($request) use ($route) {
                return $this->prepareResponse(
                    $request, $route->run()
                );
            });
    }

    static $middlewareStable = false;

    static $middlewareAlwaysStable = false;

    /**
     * @param bool $middlewareAlwaysStable
     */
    public function enableMiddlewareAlwaysStable(): void
    {
        self::$middlewareAlwaysStable = true;
    }

    /**
     * @param Route $route
     * @param bool $terminal hack: Cache for terminateMiddleware objects.
     * @return array|mixed
     */
    public function gatherRouteMiddleware(Route $route, $terminal = false)
    {
        //hack
        static $used = 0,
        $cacheByRoute = [],  // hack: Cache for route middlewares.
        $cacheForterminate = [];// hack: Cache for terminateMiddleware objects. only route middlewares here, no kernel middlewares

        $id = version_compare(PHP_VERSION, '7.2.0', '>=') ? spl_object_id($route) : spl_object_hash($route);

        if ((self::$middlewareAlwaysStable || static::$middlewareStable)
            &&
            isset($cacheByRoute[$id])) {

            ++$used;
            return $terminal ? $cacheForterminate[$id] : $cacheByRoute[$id];
            // return $cacheByRoute[$id];

        }

        self::$middlewareAlwaysStable || (static::$middlewareStable = true);

        $middleware = collect($route->gatherMiddleware())->map(function ($name) {
            $cid = \Co::getUid();
            return (array)MiddlewareNameResolver::resolve($name, static::$corDict[$cid]['middleware'], static::$corDict[$cid]['middlewareGroups']);
        })->flatten();


        // if no cache found for current route's terminal middlewares, return just now. no more making any cache.
        if ($terminal) {
            return $this->sortMiddleware($middleware);
        }

        // by default , cache an empty array
        $cacheForterminate[$id] = [];

        return $cacheByRoute[$id] = array_map(function ($one) use (&$cacheForterminate, $id) {

            // hack: Cache for route middlewares objects.
            static $cacheForObj = [];

            if (isset($cacheForObj[$one])) {
                return $cacheForObj[$one];
            }

            // store object (middleware's instance)
            if ($instance = $this->container->getStableMiddlewareInstance($one, static::$singletonMiddlewares)) {
                /**
                 * hack: Cache for terminateMiddleware objects.
                 * @var array
                 */
                if (method_exists($instance, 'terminate')) {
                    $cacheForterminate[$id][] = $instance;
                }
                return $cacheForObj[$one] = $instance;
            }

            // store string (middleware's name)
            $cacheForterminate[$id][] = $one; // hack: Cache for terminateMiddleware objects.
            return $cacheForObj[$one] = $one;

        }, $this->sortMiddleware($middleware));

    }

    // hack: Cache for route middlewares objects.
    static $singletonMiddlewares = [];

    /**
     * hack: Cache for route middlewares objects.
     * @param array $middlewares
     */
    public function setSingletonMiddlewares(array $middlewares): void
    {
        self::$singletonMiddlewares = $middlewares;
    }


    protected function sortMiddleware(Collection $middlewares)
    {
        return (new SortedMiddleware(static::$corDict[\Co::getUid()]['middlewarePriority'], $middlewares))->all();
    }

    public function prepareResponse($request, $response)
    {
        return static::toResponse($request, $response);
    }

    /**
     * Static version of prepareResponse.
     *
     * @param  \Symfony\Component\HttpFoundation\Request $request
     * @param  mixed $response
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    public static function toResponse($request, $response)
    {
        if ($response instanceof Responsable) {
            $response = $response->toResponse($request);
        }

        if ($response instanceof PsrResponseInterface) {
            $response = (new HttpFoundationFactory)->createResponse($response);
        } elseif (!$response instanceof SymfonyResponse &&
            ($response instanceof Arrayable ||
                $response instanceof Jsonable ||
                $response instanceof ArrayObject ||
                $response instanceof JsonSerializable ||
                is_array($response))) {
            $response = new JsonResponse($response);
        } elseif (!$response instanceof SymfonyResponse) {
            $response = new Response($response);
        }

        if ($response->getStatusCode() === Response::HTTP_NOT_MODIFIED) {
            $response->setNotModified();
        }

        return $response->prepare($request);
    }

    public function substituteBindings($route)
    {
        $cid = \Co::getUid();
        $one = static::$corDict[$cid]['binders'];
        foreach ($route->parameters() as $key => $value) {
            if (isset($one[$key])) {
                $route->setParameter($key, $this->performBinding($key, $value, $route, $cid));
            }
        }

        return $route;
    }

    public function substituteImplicitBindings($route)
    {
        ImplicitRouteBinding::resolveForRoute($this->container, $route);
    }

    protected function performBinding($key, $value, $route, $cid)
    {
        return call_user_func(static::$corDict[$cid]['binders'][$key], $value, $route);
    }

    public function matched($callback)
    {
        $this->events->listen(Events\RouteMatched::class, $callback);
    }

    public function getMiddleware()
    {
        return static::$corDict[\Co::getUid()]['middleware'];
    }

    public function aliasMiddleware($name, $class)
    {
        static::$corDict[\Co::getUid()]['middleware'][$name] = $class;

        // hack
        self::$middlewareAlwaysStable || (static::$middlewareStable = false);

        return $this;
    }

    public function hasMiddlewareGroup($name)
    {
        return array_key_exists($name, static::$corDict[\Co::getUid()]['middlewareGroups']);
    }

    public function getMiddlewareGroups()
    {
        return static::$corDict[\Co::getUid()]['middlewareGroups'];
    }

    /**
     * Register a group of middleware.
     *
     * @param  string $name
     * @param  array $middleware
     * @return $this
     */
    public function middlewareGroup($name, array $middleware)
    {
        static::$corDict[\Co::getUid()]['middlewareGroups'][$name] = $middleware;

        // hack
        self::$middlewareAlwaysStable || (static::$middlewareStable = false);

        return $this;
    }

    /**
     * Add a middleware to the beginning of a middleware group.
     *
     * If the middleware is already in the group, it will not be added again.
     *
     * @param  string $group
     * @param  string $middleware
     * @return $this
     */
    public function prependMiddlewareToGroup($group, $middleware)
    {
        $cid = \Co::getUid();
        if (isset(static::$corDict[$cid]['middlewareGroups'][$group]) && !in_array($middleware, static::$corDict[$cid]['middlewareGroups'][$group])) {

            // hack
            self::$middlewareAlwaysStable || (static::$middlewareStable = false);

            array_unshift(static::$corDict[$cid]['middlewareGroups'][$group], $middleware);
        }

        return $this;
    }

    /**
     * Add a middleware to the end of a middleware group.
     *
     * If the middleware is already in the group, it will not be added again.
     *
     * @param  string $group
     * @param  string $middleware
     * @return $this
     */
    public function pushMiddlewareToGroup($group, $middleware)
    {
        $cid = \Co::getUid();
        if (!array_key_exists($group, static::$corDict[$cid]['middlewareGroups'])) {
            static::$corDict[$cid]['middlewareGroups'][$group] = [];
        }

        if (!in_array($middleware, static::$corDict[$cid]['middlewareGroups'][$group])) {

            // hack
            self::$middlewareAlwaysStable || (static::$middlewareStable = false);

            static::$corDict[$cid]['middlewareGroups'][$group][] = $middleware;
        }

        return $this;
    }

    /**
     * Add a new route parameter binder.
     *
     * @param  string $key
     * @param  string|callable $binder
     * @return void
     */
    public function bind($key, $binder)
    {
        $cid = \Co::getUid();
        static::$corDict[$cid]['binders'][str_replace('-', '_', $key)] = RouteBinding::forCallback(
            $this->container, $binder
        );
    }

    public function model($key, $class, Closure $callback = null)
    {
        $this->bind($key, RouteBinding::forModel($this->container, $class, $callback));
    }

    public function getBindingCallback($key)
    {
        $cid = \Co::getUid();
        if (isset(static::$corDict[$cid]['binders'][$key = str_replace('-', '_', $key)])) {
            return static::$corDict[$cid]['binders'][$key];
        }
    }

    /**
     * Get the global "where" patterns.
     *
     * @return array
     */
    public function getPatterns()
    {
        return static::$corDict[\Co::getUid()]['patterns'];
    }

    /**
     * Set a global where pattern on all routes.
     *
     * @param  string $key
     * @param  string $pattern
     * @return void
     */
    public function pattern($key, $pattern)
    {
        static::$corDict[\Co::getUid()]['patterns'][$key] = $pattern;
    }

    /**
     * Determine if the router currently has a group stack.
     *
     * @return bool
     */
    public function hasGroupStack()
    {
        return ! empty($this->groupStack);
    }

    /**
     * Get the current group stack for the router.
     *
     * @return array
     */
    public function getGroupStack()
    {
        return $this->groupStack;
    }

    public function input($key, $default = null)
    {
        return $this->current()->parameter($key, $default);
    }

    public function getCurrentRequest()
    {
        return static::$corDict[\Co::getUid()]['currentRequest'];
    }

    public function getCurrentRoute()
    {
        return $this->current();
    }

    public function current()
    {
        return static::$corDict[\Co::getUid()]['current'];
    }

    public function has($name)
    {
        $names = is_array($name) ? $name : func_get_args();

        foreach ($names as $value) {
            if (!static::$corDict[\Co::getUid()]['routes']->hasNamedRoute($value)) {
                return false;
            }
        }

        return true;
    }

    public function currentRouteName()
    {
        return $this->current() ? $this->current()->getName() : null;
    }

    /**
     * Alias for the "currentRouteNamed" method.
     *
     * @param  dynamic $patterns
     * @return bool
     */
    public function is(...$patterns)
    {
        return $this->currentRouteNamed(...$patterns);
    }

    /**
     * Determine if the current route matches a pattern.
     *
     * @param  dynamic $patterns
     * @return bool
     */
    public function currentRouteNamed(...$patterns)
    {
        return $this->current() && $this->current()->named(...$patterns);
    }

    /**
     * Get the current route action.
     *
     * @return string|null
     */
    public function currentRouteAction()
    {
        if ($this->current()) {
            return $this->current()->getAction()['controller'] ?? null;
        }
    }

    /**
     * Alias for the "currentRouteUses" method.
     *
     * @param  array ...$patterns
     * @return bool
     */
    public function uses(...$patterns)
    {
        foreach ($patterns as $pattern) {
            if (Str::is($pattern, $this->currentRouteAction())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the current route action matches a given action.
     *
     * @param  string $action
     * @return bool
     */
    public function currentRouteUses($action)
    {
        return $this->currentRouteAction() == $action;
    }

    /**
     * Register the typical authentication routes for an application.
     *
     * @return void
     */
    public function auth()
    {
        // Authentication Routes...
        $this->get('login', 'Auth\LoginController@showLoginForm')->name('login');
        $this->post('login', 'Auth\LoginController@login');
        $this->post('logout', 'Auth\LoginController@logout')->name('logout');

        // Registration Routes...
        $this->get('register', 'Auth\RegisterController@showRegistrationForm')->name('register');
        $this->post('register', 'Auth\RegisterController@register');

        // Password Reset Routes...
        $this->get('password/reset', 'Auth\ForgotPasswordController@showLinkRequestForm')->name('password.request');
        $this->post('password/email', 'Auth\ForgotPasswordController@sendResetLinkEmail')->name('password.email');
        $this->get('password/reset/{token}', 'Auth\ResetPasswordController@showResetForm')->name('password.reset');
        $this->post('password/reset', 'Auth\ResetPasswordController@reset');
    }

//todo test
    public function singularResourceParameters($singular = true)
    {
        ResourceRegistrar::singularParameters($singular);
    }

    /**
     * Set the global resource parameter mapping.
     *
     * @param  array $parameters
     * @return void
     */
    public function resourceParameters(array $parameters = [])
    {
        ResourceRegistrar::setParameters($parameters);
    }

    /**
     * Get or set the verbs used in the resource URIs.
     *
     * @param  array $verbs
     * @return array|null
     */
    public function resourceVerbs(array $verbs = [])
    {
        return ResourceRegistrar::verbs($verbs);
    }

    /**
     * Get the underlying route collection.
     *
     * @return \Illuminate\Routing\RouteCollection
     */
    public function getRoutes()
    {
        return static::$corDict[\Co::getUid()]['routes'];
    }

    /**
     * Set the route collection instance.
     *
     * @param  \Illuminate\Routing\RouteCollection $routes
     * @return void
     */
    public function setRoutes(RouteCollection $routes)
    {
        $cid = \Co::getUid();
        foreach ($routes as $route) {
            $route->setRouter($this)->setContainer($this->container);
        }

        static::$corDict[$cid]['routes'] = $routes;

        $this->container->instance('routes', static::$corDict[$cid]['routes']);
    }

    public function __call($method, $parameters)
    {
        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        if ($method == 'middleware') {
            return (new RouteRegistrar($this))->attribute($method, is_array($parameters[0]) ? $parameters[0] : $parameters);
        }

        return (new RouteRegistrar($this))->attribute($method, $parameters[0]);
    }
}