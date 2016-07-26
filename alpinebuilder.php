#!/usr/bin/env php
<?php

require __DIR__ . '/vendor/autoload.php';

use JLM\AlpineBuilder\Command as Command;
use Symfony\Component\Console\Application;

$application = new Application();

$application->add(new Command\Download);
//$application->add(new Command\MakeVm);
//$application->add(new Command\MakeAmi);
//$application->add(new Command\MakeBox);

$application->run();
