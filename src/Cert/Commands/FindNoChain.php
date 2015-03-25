<?php

namespace Cert\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class FindNoChain extends Command
{
    protected function configure()
    {
        $this
            ->setName('find:no-chain')
            ->setDescription('Recursively scan directory for certificate files and report ones that likely contain no certificate chain. Currently it doesn\'t verify validity of the chain for the certificate files that do contain it.')
            ->addArgument(
                'directory',
                InputArgument::REQUIRED,
                'directory to scan'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $error = $output->getErrorOutput();

        $dir = new \RecursiveDirectoryIterator($input->getArgument("directory"));
        $iter = new \RecursiveIteratorIterator($dir);

        $certs = new \RegexIterator(
            $iter,
            '/^.+\.(crt|pem)/i',
            \RecursiveRegexIterator::MATCH
        );

        foreach ($certs as $cert) {
            $regex = "/BEGIN CERTIFICATE/";
            $n = \preg_match_all($regex, \file_get_contents($cert->getPathname()), $matches);
            if ($n <= 1) {
                $output->writeln("likely no chain: $cert");
            }
        }
    }
}