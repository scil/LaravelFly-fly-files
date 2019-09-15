<?php declare(strict_types=1);
/**
 * only add
 *  use \LaravelFly\Map\CommonHack\StreamHandlerLogCache;
 */

/*
 * This file is part of the Monolog package.
 *
 * (c) Jordi Boggiano <j.boggiano@seld.be>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Monolog\Handler;

use Monolog\Logger;
use Symfony\Component\EventDispatcher\GenericEvent;

/**
 * Stores to any stream resource
 *
 * Can be used to store into php://stderr, remote and local files, etc.
 *
 * @author Jordi Boggiano <j.boggiano@seld.be>
 */
class StreamHandler extends AbstractProcessingHandler
{
    use \LaravelFly\Map\CommonHack\StreamHandlerLogCache;

    /** @var resource|null */
    protected $stream;
    protected $url;
    /** @var string|null */
    private $errorMessage;    
    protected $filePermission;
    protected $useLocking;
    private $dirCreated;


    /**
     * {@inheritdoc}
     */
    public function close(): void
    {
        if ($this->url && is_resource($this->stream)) {
            $this->cacheWrite();
            fclose($this->stream);
        }
        $this->stream = null;
        $this->dirCreated = null;
    }

    /**
     * Return the currently active stream if it is open
     *
     * @return resource|null
     */
    public function getStream()
    {
        return $this->stream;
    }

    /**
     * Return the stream URL if it was configured with a URL and not an active resource
     *
     * @return string|null
     */
     public function getUrl(): ?string
    {
        return $this->url;
    }


    /**
     * Write to stream
     * @param resource $stream
     * @param array $record
     */
         protected function streamWrite($stream, array $record): void
    {
        fwrite($stream, (string)$record['formatted']);
    }

    private function customErrorHandler($code, $msg): bool
    {
        $this->errorMessage = preg_replace('{^(fopen|mkdir)\(.*?\): }', '', $msg);
        return true;
    }

    private function getDirFromStream(string $stream): ?string
    {
        $pos = strpos($stream, '://');
        if ($pos === false) {
            return dirname($stream);
        }

        if ('file://' === substr($stream, 0, 7)) {
            return dirname(substr($stream, 7));
        }

        return null;
    }

    private function createDir(): void
    {
        // Do not try to create dir if it has already been tried.
        if ($this->dirCreated) {
            return;
        }

        $dir = $this->getDirFromStream($this->url);
        if (null !== $dir && !is_dir($dir)) {
            $this->errorMessage = null;
            set_error_handler([$this, 'customErrorHandler']);            
            $status = mkdir($dir, 0777, true);
            restore_error_handler();
            if (false === $status && !is_dir($dir)) {
                throw new \UnexpectedValueException(sprintf('There is no existing directory at "%s" and its not buildable: ' . $this->errorMessage, $dir));
            }
        }
        $this->dirCreated = true;
    }
}
