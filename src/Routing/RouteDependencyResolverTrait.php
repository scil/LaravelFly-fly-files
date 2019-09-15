<?php
/**
 * 1. cache . Now, no support for
 *      Route Model Binding
 *      mixed of type hint arguments and normal arguments
 */

namespace Illuminate\Routing;

use Illuminate\Support\Arr;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use ReflectionParameter;


const CONTROLLER_METHOD_ARGUMENTS_UNKNOWN = -1;
// const CONTROLLER_METHOD_ARGUMENTS_NO = 0; // no args
const CONTROLLER_METHOD_ARGUMENTS_SIMPLE = 1; // no type hint, no default values; or !method_exists; or no args
const CONTROLLER_METHOD_ARGUMENTS_NO_HINT = 2; // no type hint, has default values
const CONTROLLER_METHOD_ARGUMENTS_ALL_HINT = 3; // no type hint, has default values
const CONTROLLER_METHOD_ARGUMENTS_OTHER = 4; // no type hint, has default values

const CONTROLLER_METHOD_ARGUMENT_NOT_HINT = 0;
const CONTROLLER_METHOD_ARGUMENT_HINT____ = 1;
const CONTROLLER_METHOD_ARGUMENT_HINT_DEFAULT = 3;
const CONTROLLER_METHOD_ARGUMENT_HINT_SINGLE = 4;
const CONTROLLER_METHOD_ARGUMENT_HINT_MAKE = 5;

trait RouteDependencyResolverTrait
{


    /**
     * Resolve the object method's type-hinted dependencies.
     *
     * @param  array $parameters
     * @param  object $instance
     * @param  string $method
     * @return array
     */
    protected function resolveClassMethodDependencies(array $parameters, $instance, $method)
    {
        static $cacheMark = [], $cacheInfo = [];

        $cacheKey = get_class($instance) . $method;

//        echo "method cache\n";
//        var_dump($cacheKey, $cacheMark, $cacheInfo);

        if (isset($cacheMark[$cacheKey])) {
            switch ($cacheMark[$cacheKey]) {
                // case CONTROLLER_METHOD_ARGUMENTS_NO:
                case CONTROLLER_METHOD_ARGUMENTS_SIMPLE:
                    return $parameters;
                case CONTROLLER_METHOD_ARGUMENTS_NO_HINT:
                    list($argsNumber, $default) = $cacheInfo[$cacheKey];
                    $real = count($parameters);
                    if ($real == $argsNumber) return $parameters;
                    if ($real + 1 == $argsNumber) {
                        $parameters[] = $default[-1];
                        return $parameters;
                    }
                    return array_merge($parameters, array_slice($default, $real - $argsNumber));
                case CONTROLLER_METHOD_ARGUMENTS_ALL_HINT:

                    // no Route Model Binding
                    if (!$parameters) {
                        list($classes, $types, $values) = $cacheInfo[$cacheKey];
                        $result = [];
                        foreach ($classes as $index => $argClass) {
                            switch ($types[$index]) {
                                case CONTROLLER_METHOD_ARGUMENT_HINT_SINGLE:
                                    $result[] = $values[$index];
                                    break;
                                case CONTROLLER_METHOD_ARGUMENT_HINT_MAKE:
                                    $result[] = $this->container->make($values[$index]);
                                    break;
                            }

                        }
                        return $result;
                    }

                // case CONTROLLER_METHOD_ARGUMENTS_OTHER:
                default:
                    return $this->resolveMethodDependencies(
                        $parameters, $cacheInfo[$cacheKey]
                    );


            }
        }

        if (!method_exists($instance, $method)) {
            $cacheMark[$cacheKey] = CONTROLLER_METHOD_ARGUMENTS_SIMPLE;
            return $parameters;
        }

        list($result, $argumentsMark, $argsInfo) = $this->resolveMethodDependenciesH(
            $parameters, new ReflectionMethod($instance, $method)
        );


        if ($argumentsMark !== CONTROLLER_METHOD_ARGUMENTS_UNKNOWN) {

            $cacheMark[$cacheKey] = $argumentsMark;
            if ($argumentsMark > CONTROLLER_METHOD_ARGUMENTS_SIMPLE) {
                $cacheInfo[$cacheKey] = $argsInfo;
            }
        }


        return $result;

        return $this->resolveMethodDependenciesH(
            $parameters, new ReflectionMethod($instance, $method)
        );
    }

    /**
     * Resolve the given method's type-hinted dependencies.
     *
     * @param  array $parameters
     * @param  \ReflectionFunctionAbstract $reflector
     * @return array
     */
    public function resolveMethodDependenciesH(array $parameters, ReflectionFunctionAbstract $reflector)
    {
        $instanceCount = 0;

        $values = array_values($parameters);

        $argumentsMark = CONTROLLER_METHOD_ARGUMENTS_UNKNOWN;
        $argsInfo = null;

        $defaultValues = [];
        $realInstanceCount = 0;
        $classes = [];
        $types = [];
        $values = [];


        foreach ($reflector->getParameters() as $key => $parameter) {
            list($v, $mark, $className) = $this->transformDependencyH(
                $parameter, $parameters
            );

            $instance = $v;


            if ($mark != CONTROLLER_METHOD_ARGUMENT_NOT_HINT) {
                $realInstanceCount++;
            }

            if ($mark == CONTROLLER_METHOD_ARGUMENT_HINT____) {
                list($v, $mark, $className) = $this->___temp_default;
            }

            $classes[] = $className;
            $types[] = $mark;
            $values[] = $mark == CONTROLLER_METHOD_ARGUMENT_HINT_MAKE ? $className : $v;


            if (!is_null($instance)) {
                $instanceCount++;

                $this->spliceIntoParameters($parameters, $key, $instance);
            } elseif ($parameter->isDefaultValueAvailable()) {
                $defaultValues[] = $parameter->getDefaultValue();
            } elseif (!isset($values[$key - $instanceCount]) &&
                $parameter->isDefaultValueAvailable()) {
                $this->spliceIntoParameters($parameters, $key, $parameter->getDefaultValue());
            }


        }


        $number = $reflector->getNumberOfParameters();
        if ($number == 0) {
            // $argumentsMark = CONTROLLER_METHOD_ARGUMENTS_NO;
            $argumentsMark = CONTROLLER_METHOD_ARGUMENTS_SIMPLE;
        } elseif (!$realInstanceCount) {
            if (!$defaultValues) {
                $argumentsMark = CONTROLLER_METHOD_ARGUMENTS_SIMPLE;
            } else {
                $argumentsMark = CONTROLLER_METHOD_ARGUMENTS_NO_HINT;
                $argsInfo = [$number, $defaultValues];
            }
        } else {
            $argsInfo = [
                $classes, $types, $values
            ];
            if ($number == $realInstanceCount) {
                $argumentsMark = CONTROLLER_METHOD_ARGUMENTS_ALL_HINT;
            } else {
                $argumentsMark = CONTROLLER_METHOD_ARGUMENTS_OTHER;
                $argsInfo = $reflector;
            }
        }

//        echo "method resolve\n";
//        var_dump($parameters, $argumentsMark,$argsInfo);

        return [$parameters, $argumentsMark, $argsInfo];
    }

    /**
     * Attempt to transform the given parameter into a class instance.
     *
     * @param  \ReflectionParameter $parameter
     * @param  array $parameters
     * @return mixed
     */
    protected
    function transformDependencyH(ReflectionParameter $parameter, $parameters)
    {

        $class = $parameter->getClass();


        // 'this controller method arg is not instance';
        if (!$class) {
            return [null, CONTROLLER_METHOD_ARGUMENT_NOT_HINT, null];
        }

        $className = $class->name;

        if ($parameter->isDefaultValueAvailable()) {
            $default = $parameter->getDefaultValue();
        }


        if (isset($default)) {
            $return = [$default, CONTROLLER_METHOD_ARGUMENT_HINT_DEFAULT, $className];
        } elseif ($single = $this->container->getInstanceFromWorker($className)) {
            $return = [$single, CONTROLLER_METHOD_ARGUMENT_HINT_SINGLE, $className];
        } else {
            $v = $this->container->make($className);
            $return = [$v, CONTROLLER_METHOD_ARGUMENT_HINT_MAKE, $className];
        }

        // instance and have in parameters
        if ($this->alreadyInParameters($className, $parameters)) {
            $this->___temp_default = $return;
            return [null, CONTROLLER_METHOD_ARGUMENT_HINT____, $className];
        }

        return $return;

    }

    public function resolveMethodDependencies(array $parameters, ReflectionFunctionAbstract $reflector)
    {
        $instanceCount = 0;

        $values = array_values($parameters);

        foreach ($reflector->getParameters() as $key => $parameter) {
            $instance = $this->transformDependency(
                $parameter, $parameters
            );

            if (!is_null($instance)) {
                $instanceCount++;

                $this->spliceIntoParameters($parameters, $key, $instance);
            } elseif (!isset($values[$key - $instanceCount]) &&
                $parameter->isDefaultValueAvailable()) {
                $this->spliceIntoParameters($parameters, $key, $parameter->getDefaultValue());
            }
        }

        return $parameters;
    }

    /**
     * Attempt to transform the given parameter into a class instance.
     *
     * @param  \ReflectionParameter $parameter
     * @param  array $parameters
     * @return mixed
     */
    protected function transformDependency(ReflectionParameter $parameter, $parameters)
    {
        $class = $parameter->getClass();

        // If the parameter has a type-hinted class, we will check to see if it is already in
        // the list of parameters. If it is we will just skip it as it is probably a model
        // binding and we do not want to mess with those; otherwise, we resolve it here.
        if ($class && !$this->alreadyInParameters($class->name, $parameters)) {
            return $parameter->isDefaultValueAvailable()
                ? $parameter->getDefaultValue()
                : $this->container->make($class->name);
        }
    }

    /**
     * Determine if an object of the given class is in a list of parameters.
     *
     * @param  string $class
     * @param  array $parameters
     * @return bool
     */
    protected
    function alreadyInParameters($class, array $parameters)
    {
        return !is_null(Arr::first($parameters, function ($value) use ($class) {
            return $value instanceof $class;
        }));
    }

    /**
     * Splice the given value into the parameter list.
     *
     * @param  array $parameters
     * @param  string $offset
     * @param  mixed $value
     * @return void
     */
    protected
    function spliceIntoParameters(array &$parameters, $offset, $value)
    {
        array_splice(
            $parameters, $offset, 0, [$value]
        );
    }
}
