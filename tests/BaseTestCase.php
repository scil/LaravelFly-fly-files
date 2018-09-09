<?php

namespace LaravelFlyFiles\Test;
/**
 * composer update
 * vendor/bin/phpunit  --stop-on-failure -c phpunit.xml.dist
 */

use PHPUnit\Framework\TestCase;

abstract class BaseTestCase extends TestCase
{
	static $flyDir;
	static $backOfficalDir;
	static $workingRoot;

    static function setUpBeforeClass()
    {
	static::$flyDir = __DIR__. '/../src/';
		static::$backOfficalDir =  __DIR__. '/../offcial_files/';
		static::$workingRoot = __DIR__. '/../';
    }

    function compareFilesContent($map)
    {

        $diffOPtions = '--ignore-all-space --ignore-blank-lines';

        $same = true;

        foreach ($map as $back => $offcial) {
            $back = static::$backOfficalDir . $back;
            $offcial = static::$workingRoot . $offcial;

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

