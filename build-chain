#!/usr/bin/env php
<?php

require_once __DIR__ . "/library.php";

if ($argc == 1) {
    echo "Please specify path to the certificate\n";
    exit(1);
}

$certPath = $argv[1];

if (!file_exists($certPath)) {
    echo "File $certPath doesn't exist\n";
    exit(1);
}

try {
    list ($inform, $format) = detectCertFormat($certPath);
    $cert = parseFormattedCert(readCertificate($certPath, $inform, $format));
} catch(Exception $e) {
    echo "Unable to load certificate: {$e->output}\n";
    exit(1);
}

// perform some basic checks
if (isExpired($cert)) {
    echo "Certificate has expired\n";
    exit(1);
}

if (areCertsLinked($cert, $cert)) {
    echo "Self-signed or CA cert\n";
    exit(1);
}

try {
    $out = buildChain($cert, $certPath);
    echo $out;
} catch (Exception $e) {
    echo $e->getMessage();
    exit(1);
}