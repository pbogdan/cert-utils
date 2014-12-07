#!/usr/bin/env php
<?php

if ($argc == 1) {
    echo "Please specify path to the directory\n";
    exit(1);
}


$dir = new RecursiveDirectoryIterator($argv[1]);
$iter = new RecursiveIteratorIterator($dir);

$certs = new RegexIterator(
    $iter,
    '/^.+\.(crt|pem)/i',
    RecursiveRegexIterator::MATCH
);

foreach ($certs as $cert) {
    $regex = "/BEGIN CERTIFICATE/";
    $n = preg_match_all($regex, file_get_contents($cert->getPathname()), $matches);

    if ($n <= 1) {
        echo "likely no chain: $cert\n";
    }
}
