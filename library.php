<?php

use Desarrolla2\Cache\Cache;
use Desarrolla2\Cache\Adapter\File;

// most of this code is based on Perl code from
// https://github.com/psypete/public-bin
function detectCertFormat($filePath)
{
    $f = file_get_contents($filePath);

    $fmt = "x509";

    if (preg_match("/BEGIN PKCS(7|12)/", $f, $matches)) {
        $inform = "pem";

        if ($matches[1] == "7") {
            $fmt = "pkcs7";
        } elseif ($matches[1] == "12") {
            $fmt = "pkcs12";
        }
    } else if (preg_match("/BEGIN CERTIFICATE/", $f, $matches)) {
        $inform = "pem";
    } else if (preg_match("/\.p7c$/", $filePath)) {
        $fmt    = "pkcs7";
        $inform = "der";
    } else {
        $inform = "der";
    }

    return [$inform, $fmt];
}

function readCertificate($filePath, $inform, $format)
{
    if ($format == "x509") {
        $cmd = sprintf(
            "openssl %s -noout -text -inform %s -in %s",
            $format,
            $inform,
            escapeshellarg($filePath)
        );
    } else {
        $cmd = sprintf(
            "openssl %s -text -print_certs -inform %s -in %s",
            $format,
            $inform,
            escapeshellarg($filePath)
    );
    }

    return execute($cmd);
}

function parseFormattedCert($parsedCert)
{
    $lines = $parsedCert;
    for ($i = 0; $i < sizeof($parsedCert); $i++) {
        $line = $lines[$i];
        $matches = [];

        if (preg_match("/^\s+Issuer: (.+)$/", $line, $matches)) {
            // .p7c might contain multiple cert which we don't handle at the
            // moment so stop processing after the first one
            if (isset($cert["issuer"])) {
                break;
            }
            $cert["issuer"] = trim($matches[1]);
        }

        if (preg_match("/^\s+Subject: (.+)/", $line, $matches)) {
            $cert["subject"] = trim($matches[1]);
        }


        if (preg_match("/CA Issuers - URI:(.+)/", $line, $matches)) {
            $cert["issuers"][] = trim($matches[1]);
        }

        if (preg_match("/X509v3 Subject Key Identifier:/", $line, $matches)) {
            $cert["subj_key_ident"] = trim($lines[++$i]);
        }

        if (preg_match("/X509v3 Authority Key Identifier:/", $line, $matches)) {
            $cert["auth_key_ident"] = str_replace(
                "keyid:",
                "",
                trim($lines[++$i])
            );
        }

        if (preg_match("/^\s+Validity\s*$/", $line)) {
            for ($j = 0; $j < 3; $j++) {
                $sline = $lines[$j + $i];

                if (preg_match("/^\s+Not (Before|After)\s*: (.+)$/", $sline, $smatches)) {
                    list ($when, $time) = [$smatches[1], $smatches[2]];

                    if ( $when == "Before") {
                        $cert['created'] = strtotime(trim($time));
                    } else if ($when == "After") {
                        $cert['expires'] = strtotime(trim($time));
                    }
                }
            }
        }
    }

    return $cert;
}

function isExpired($cert, $expiry = null)
{
    if (is_null($expiry)) {
        $expiry = time();
    }

    if (isset($cert["expires"])) {
        // @todo: better validation of expires
        return $cert["expires"] < $expiry;
    } else {
        throw new Exception("Certificate without expiration time!");
    }
}

// where $cert1 is the "higher" certificate in the chain
function areCertsLinked($cert1, $cert2)
{
    $pair1 = ["subj_key_ident", "auth_key_ident"];
    $pair2 = ["subject", "issuer"];

    foreach ([$pair1, $pair2] as $field) {
        list($f1, $f2) = $field;

        if (isset($cert1[$f1]) && strlen($cert1[$f1]) > 0
            && isset($cert2[$f2]) && strlen($cert2[$f2]) > 0
        ) {
            if ($cert1[$f1] == $cert2[$f2]) {
                return true;
            }
        }
    }

    return false;
}

function findMatchingRoot($cert)
{
    foreach (glob("/etc/ssl/certs/*") as $root) {
        list ($inform, $format) = detectCertFormat($root);
        $rootCert = parseFormattedCert(readCertificate($root, $inform, $format));

        if (areCertsLinked($rootCert, $cert)) {
            if (!areCertsLinked($rootCert, $rootCert)) {
                throw new Exception("Invalid root certificate $root!");
            }
            return $root;
        }
    }

    throw new Exception("Unable to find matching root certificate");
}

function downloadIssuer($uri)
{
    $ext = pathinfo($uri, PATHINFO_EXTENSION);
    $hash = sha1($uri);
    $path = __DIR__ . "/cache/ca-issuer-$hash.$ext";

    if (!file_exists($path)) {
        $cmd = sprintf(
            "wget %s -O %s",
            escapeshellarg($uri),
            escapeshellarg($path)
        );
        execute($cmd);
    }

    return $path;
}

function buildChain($cert, $certPath, $includeRoot = false)
{
    if (isExpired($cert)) {
        throw new Exception("Certificate has expired");
    }

    if (areCertsLinked($cert, $cert)) {
        throw new Exception("Self-signed or CA cert");
    }

    $uris = $cert["issuers"];

    if (!$uris) {
        throw new Exception("Certificate doesn't specify issuers");
    }

    $c = $cert;

    $chain = [];

    while (sizeof($uris) > 0) {
        $old = $c;
        $uri = array_shift($uris);

        $path = downloadIssuer($uri);
        list ($inform, $format) = detectCertFormat($path);
        $c = parseFormattedCert(readCertificate($path, $inform, $format));

        if (isExpired($c)) {
            throw new Exception("Expired intermediate in the chain");
        }
        if (areCertsLinked($c, $c)) {
            break;
        }

        if (!areCertsLinked($c, $old)) {
            $msg = "Intermediate doesn't match previous certificate in the chain";
            throw new Exception($msg);
        }

        $chain[] = $path;

        if (isset($c["issuers"])) {
            foreach ($c["issuers"] as $i) {
                    $uris[] = $i;
                    // we don't currently have a good way of handling multiple
                    // issuers
                    break;
            }
        }
    }

    // we are at the end of the chain, see if there's matching root CA
    $cacheDir = __DIR__ . '/cache';
    $adapter = new File($cacheDir);
    $adapter->setOption('ttl', 600);
    $cache = new Cache($adapter);

    if (!$cache->get(md5($path) . "-root")) {
        $root = findMatchingRoot($c);
        $chain[] = $root;
        $cache->set(md5($path) . "-root", $root);
    } else {
        $chain[] = $cache->get(md5($path) . "-root");
    }


    // build certificate bundle
    foreach ($chain as $i => $path) {
        list ($inform, $format) = detectCertFormat($path);

        $cmd = sprintf(
            "openssl x509 -inform %s -outform pem -in %s -out %s",
            escapeshellarg($inform),
            escapeshellarg($path),
            escapeshellarg(__DIR__ . "/tmp/" . sha1($cert["subject"]) . "-$i.pem")
        );
        exec($cmd);
    }

    unlink(__DIR__ . "/tmp/bundle.crt");

    foreach ($chain as $i => $path) {
        file_put_contents(
            __DIR__ . "/tmp/bundle.crt",
            file_get_contents(__DIR__ . "/tmp/" . sha1($cert["subject"]) . "-$i.pem"),
            FILE_APPEND
        );
    }

    // verify the chain is valid
    $cmd = sprintf(
        "openssl verify -verbose -purpose sslserver -CAfile %s/tmp/bundle.crt %s",
        __DIR__,
        escapeshellarg($certPath)
    );

    try {
        execute($cmd);
    } catch (Exception $e) {
        $err = implode("\n", $e->output);
        throw new Exception("Can't verify the bundle: {$err}");
    }

    // extract the original cert (it might contain some, or all, parts of the
    // chain already)
    $cmd = sprintf(
        "openssl x509 -inform pem -outform pem -in %s",
        $certPath
    );

    $out = implode("\n", execute($cmd));
    $out .= "\n";

    if (!$includeRoot) {
        array_pop($chain);
    }

    foreach ($chain as $i => $path) {
        $out .= file_get_contents(__DIR__ . "/tmp/" . sha1($cert["subject"]) . "-$i.pem");
        unlink(__DIR__ . "/tmp/" . sha1($cert["subject"]) . "-$i.pem");
    }

    return $out;
}

function execute($cmd)
{
    $cmd = $cmd . " 2>&1";
    exec($cmd, $output, $code);

    if ($code != 0) {
        $e = new \Exception("Command '$cmd' failed exit code $code");
        $e->output = $output;
        $e->cmd = $cmd;
        throw $e;
    }

    return $output;
}
