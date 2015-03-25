<?php

namespace Cert\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class FindExpiredCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('find:expired')
            ->setDescription('Recursively scan directory for certificate files and report ones that have expired.')
            ->addArgument(
                'directory',
                InputArgument::REQUIRED,
                'directory to scan'
            )
            ->addOption(
               'expiry',
               null,
               InputOption::VALUE_OPTIONAL,
               'Reference expiration date'
            )
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $error = $output->getErrorOutput();
        $dir = new \RecursiveDirectoryIterator($input->getArgument("directory"));
        $iter = new \RecursiveIteratorIterator($dir);

        if ($input->getOption("expiry")) {
            $expiry = strtotime($input->getOption("expiry"));
            if ($expiry === false) {
                $expiry = time();
                $error->writeln("Invalid expiry arg, defaulting to now");
            }
        } else {
            $expiry = time();
        }

        $certs = new \RegexIterator(
            $iter,
            '/^.+\.(crt|pem)/i',
            \RecursiveRegexIterator::MATCH
        );

        foreach ($certs as $path) {
            try {
                $expirationDate = "";
                $inform = "";
                $format = "";

                list ($inform, $format) = \detectCertFormat($path);
                $cert = \parseFormattedCert(\readCertificate($path, $inform, $format));

                if (isExpired($cert, $expiry)) {
                    $expirationDate = \date('Y-m-d H:i:s e', $cert["expires"]);
                    $output->writeln("Certificate {$path} expires on {$expirationDate}");
                }
            } catch(\Exception $e) {
                //file_put_contents("php://stderr", "^^ Unable to load certificate {$cert}\n");
                $error->writeln("^^ Unable to load certificate {$path}\n");
            }
        }


    }
}