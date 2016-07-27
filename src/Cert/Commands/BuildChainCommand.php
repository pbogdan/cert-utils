<?php

namespace Cert\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class BuildChainCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('build-chain')
            ->setDescription('Build an intermediate certificate chain for an SSL certificate stored in file and print it on stdout.')
            ->addArgument(
                'path',
                InputArgument::REQUIRED,
                'path to the certificate'
            )
            ->addOption(
                'include-root',
                null,
                InputOption::VALUE_NONE,
                'whether to include root cert in the chain'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $error = $output->getErrorOutput();
        $path = $input->getArgument("path");
        $includeRoot = $input->getOption("include-root");

        if (!\file_exists($path)) {
            throw new \Exception("File {$path} doesn't exist");
        }

        try {
            list ($inform, $format) = \detectCertFormat($path);
            $cert = \parseFormattedCert(\readCertificate($path, $inform, $format));
        } catch(\Exception $e) {
            $err = implode("\n", $e->output);
            throw new \Exception("Unable to load certificate: {$err}");
        }

        // perform some basic checks
        if (\isExpired($cert)) {
            $error->writeln("Certificate has expired");
        }

        if (\areCertsLinked($cert, $cert)) {
            throw new \Exception("Self-signed or CA cert");
        }

        // this can fail with an exception
        $out = \buildChain($cert, $path, $includeRoot);
        $output->write($out);
    }
}