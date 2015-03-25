#!/usr/bin/env php
<?php

require __DIR__.'/vendor/autoload.php';

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
