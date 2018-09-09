<?php

/**
 ** first:
 ** cd laravel_fly_root
 ** git clone -b 5.6 https://github.com/laravel/framework.git /vagrant/www/zc/vendor/scil/laravel-fly-local/vendor/laravel/framework
 ** composer update
 ** //cd laravel_project_root
 *
 ** Mode Map
 * vendor/bin/phpunit  --stop-on-failure -c phpunit.xml.dist --testsuit LaravelFly_Map_Process
 *
 * vendor/bin/phpunit  --stop-on-failure -c phpunit.xml.dist --testsuit LaravelFly_Map_Other
 *
 * vendor/bin/phpunit  --stop-on-failure -c phpunit.xml.dist --testsuit LaravelFly_Map_LaravelTests
 *
 ** Mode Backup
 * vendor/bin/phpunit  --stop-on-failure -c phpunit.xml.dist --testsuit LaravelFly_Backup
 *
 ** example for debugging with gdb:
 * gdb ~/php/7.1.14root/bin/php       // this php is a debug versioin, see D:\vagrant\ansible\files\scripts\php-debug\
 * r  vendor/bin/phpunit  --stop-on-failure -c phpunit.xml.dist --testsuit LaravelFly_Map_LaravelTests
 *
 */

use PHPUnit\Framework\TestCase;

abstract class BaseTestCase extends TestCase
{

    static function setUpBeforeClass()
    {

    }

    function compareFilesContent($map)
    {

        $diffOPtions = '--ignore-all-space --ignore-blank-lines';

        $same = true;

        foreach ($map as $back => $offcial) {
            $back = static::$backOfficalDir . $back;
            $offcial = static::$laravelAppRoot . $offcial;

            $cmdArguments = "$diffOPtions $back $offcial ";

            unset($a);
            exec("diff --brief $cmdArguments > /dev/null", $a, $r);
//            echo "\n\n[CMD] diff $cmdArguments\n\n";
//            print_r($a);
            if ($r !== 0) {
                $same = false;
                echo "\n\n[CMD] diff $cmdArguments\n\n";
                system("diff  $cmdArguments");
            }
        }

        self::assertEquals(true, $same);

    }

}

