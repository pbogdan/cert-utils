#!/usr/bin/env php
<?php

$autoloads = array(
    __DIR__ . '/../../autoload.php',
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/vendor/autoload.php'
);

$autoload = "";

foreach ($autoloads as $file) {
    if (file_exists($file)) {
        $autoload = $file;
        break;
    }
}

if (!$autoload) {
    echo "Unable to find autoload.php!";
    exit(1);
}

require $autoload;
require __DIR__.'/library.php';

use Cert\Commands\FindExpiredCommand;
use Cert\Commands\FindNoChain;
use Cert\Commands\BuildChainCommand;

use Symfony\Component\Console\Application;

$application = new Application();
$application->add(new FindExpiredCommand());
$application->add(new FindNoChain());
$application->add(new BuildChainCommand());
$application->run();

// Local Variables:
// mode: php-mode
// End:
