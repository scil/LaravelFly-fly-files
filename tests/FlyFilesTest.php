<?php

use BaseTestCase as Base;

class FlyFilesTest extends Base
{
	
    const mapFlyFiles = [
        'Container.php' =>
            '/vendor/laravel/framework/src/Illuminate/Container/Container.php',
        'Application.php' =>
            '/vendor/laravel/framework/src/Illuminate/Foundation/Application.php',
        'ServiceProvider.php' =>
            '/vendor/laravel/framework/src/Illuminate/Support/ServiceProvider.php',
        'Router.php' =>
            '/vendor/laravel/framework/src/Illuminate/Routing/Router.php',
        'ViewConcerns/ManagesComponents.php' =>
            '/vendor/laravel/framework/src/Illuminate/View/Concerns/ManagesComponents.php',
        'ViewConcerns/ManagesLayouts.php' =>
            '/vendor/laravel/framework/src/Illuminate/View/Concerns/ManagesLayouts.php',
        'ViewConcerns/ManagesLoops.php' =>
            '/vendor/laravel/framework/src/Illuminate/View/Concerns/ManagesLoops.php',
        'ViewConcerns/ManagesStacks.php' =>
            '/vendor/laravel/framework/src/Illuminate/View/Concerns/ManagesStacks.php',
        'ViewConcerns/ManagesTranslations.php' =>
            '/vendor/laravel/framework/src/Illuminate/View/Concerns/ManagesTranslations.php',
        'Facade.php' =>
            '/vendor/laravel/framework/src/Illuminate/Support/Facades/Facade.php',

        /**
         * otherwise
         * on each boot of PaginationServiceProvider and NotificationServiceProvider,
         * view paths would be appended to app('view')->finder->hints by  $this->loadViewsFrom again and again
         */
        'FileViewFinder' . (LARAVELFLY_SERVICES['view.finder'] ? 'SameView' : '') . '.php' =>
            '/vendor/laravel/framework/src/Illuminate/View/FileViewFinder.php',

    ];

    /**
     * fly files included conditionally.
     * this array is only for
     * test tests/Map/Feature/FlyFilesTest.php
     *
     * @var array
     */
    protected static $conditionFlyFiles = [
        'log_cache' => [
            'StreamHandler.php' =>
                '/vendor/monolog/monolog/src/Monolog/Handler/StreamHandler.php',
        ],
        'config' => [
            'Config/Repository.php' =>
                '/vendor/laravel/framework/src/Illuminate/Config/Repository.php'

        ],
        'kernel' => [
            // '../Kernel.php' =>
            // match the dir structure of tests/offcial_files
            'Http/Kernel.php' =>
                '/vendor/laravel/framework/src/Illuminate/Foundation/Http/Kernel.php'

        ]
    ];
    
    
    static function getAllFlyMap()
    {
        $r = static::mapFlyFiles;

        foreach (static::$conditionFlyFiles as $map) {
            $r = array_merge($r, $map);
        }
        return $r;
    }



    function testFlyFiles()
    {
        $map = static::getAllFlyMap();

        $flyFilesNumber = 14;

        self::assertEquals($flyFilesNumber, count($map));

        // -4: 5 files in a dir,
        // -1: Kernel.php
        // +3: . an .. and FileViewFinderSameView.php
        self::assertEquals($flyFilesNumber - 4 - 1 + 3, count(scandir(static::$flyDir, SCANDIR_SORT_NONE)));

        // +3: another kernel.php whoses class is App\Http\Kernel.php
        //     Http/
        //     extended/
        // -1: FileViewFinderSameView.php
        self::assertEquals($flyFilesNumber - 4 - 1 + 3 + 3 - 1, count(scandir(static::$backOfficalDir, SCANDIR_SORT_NONE)));

        foreach ($map as $f => $originLocation) {

            self::assertEquals(true, is_file(static::$backOfficalDir . $f));
            if ($f === 'Http/Kernel.php')
                $f = '../Kernel.php';
            self::assertEquals(true, is_file(static::$flyDir . $f), static::$flyDir . $f);
            // var_dump(static::$workingRoot . $originLocation);
            self::assertEquals(true, is_file(static::$workingRoot . $originLocation));
        }
    }

    function testCompareFilesContent()
    {
        $map = static::$map;
        $this->compareFilesContent($map);
    }

}