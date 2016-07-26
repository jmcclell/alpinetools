<?php
Namespace JLM\AlpineBuilder\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\ProgressBar;

class Download extends Command
{
    const ALPINE_GPG_PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

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
Mkc=
=FcYC
-----END PGP PUBLIC KEY BLOCK-----";

    const ALPINE_GPG_PUBLIC_KEY_FINGERPRINT = "0482 D840 22F5 2DF1 C4E7  CD43 293A CD09 07D9 495A";


    const DIST_STANDARD = 'standard';
    const DIST_EXTENDED = 'extended';
    const DIST_VANILLA = 'vanilla';
    const DIST_VIRTUAL = 'virtual';
    const DIST_XEN = 'xen';
    const DIST_RASPBERRY_PI = 'rpi';
    const DIST_GENERIC_ARM = 'arm';


    const ARCH_64BIT = 'x86_64';
    const ARCH_32BIT = 'x86';
    const ARCH_ARM = 'armhf';

    const ARCHITECTURE_MAP = [
        self::DIST_STANDARD => ['default' => self::ARCH_64BIT, self::ARCH_32BIT],
        self::DIST_EXTENDED => ['default' => self::ARCH_64BIT, self::ARCH_32BIT],
        self::DIST_VANILLA => ['default' => self::ARCH_64BIT, self::ARCH_32BIT],
        self::DIST_VIRTUAL => ['default' => self::ARCH_64BIT, self::ARCH_32BIT],
        self::DIST_XEN => ['default' => self::ARCH_64BIT],
        self::DIST_RASPBERRY_PI => ['default' => self::ARCH_ARM],
        self::DIST_GENERIC_ARM => ['default' => self::ARCH_ARM],
    ];

    const DEFAULT_DIST = self::DIST_STANDARD;

    protected function configure()
    {
        $this
            ->setName('download')
            ->setDescription('Download the specified Alpine Linux ISO file to the current or specified directory')
            ->addArgument(
                'release',
                InputArgument::REQUIRED,
                'The Alpine Linux release version (e.g. 3.4.2) of the ISO to download.'
            )
            ->addArgument(
                'outputDir',
                InputArgument::OPTIONAL,
                'The path of the directory to download the ISO to. Defauls to current directory.'
            )
            ->addOption(
                'dist',
                null,
                InputOption::VALUE_REQUIRED,
                "The Alpine Linux distribution type (e.g. Standard, Vanilla, etc.) of the ISO to download. Defaults to Standard distribution.\nAvailable distributions:\n\tstandard\n\textended\n\tvanilla\n\tvirtual\n\txen\n\trpi\n\tarm"
            )
            ->addOption(
                'arch',
                null,
                InputOption::VALUE_REQUIRED,
                "The architecture (e.g. x86_64) of the ISO to download. Note: Not all architecture are available for every distribution.\nAvailable architectures:\n\tx86_64\n\tx86\n\tarmhf.rpi\n\tarmhf\n\nArchitectures by distribution:\n\tStandard: x86_64 (default), x86\n\tExtended: x86_64 (default), x86\n\tVanilla: x86_64 (default), x86\n\tVirtual: x86_64 (default), x86\n\tXen: x86_64 (default)\n\tRaspberry Pi (rpi): armhf (default)\n\tGeneric ARM (arm): armhf (default)"
            );
    }

    protected function execute(InputInterface $in, OutputInterface $out)
    {
        $args = $this->getArgs($in);
        if (!$args->isValid()) {
            $errors = $args->validationErrors;
            foreach ($errors as $error) {
                $out->writeln("<error>- $error</error>");
            }
            exit(1);
        }

        $this->downloadISO($args, $out);
        $this->validateISOSha1Checksum($args, $out);
        $this->validateISOSha256Checksum($args, $out);
        $this->validateISOGPGSignature($args, $out);
    }

    protected function verifyOutputPath(DownloadArgs $args, OutputInterface $out)
    {
        if (!is_dir($args->outputDir)) {
            $out->writeln("<error>The path '{$args->outputDir}' is not a directory.");
            exit(1);
        }
    }



    protected function downloadISO(DownloadArgs $args, OutputInterface $out)
    {
        $out->writeln("Downloading ISO: {$args->ISOUrl} to {$args->ISOFilename}");
        $this->verifyOutputPath($args, $out);
        $client = new \GuzzleHttp\Client();
        $progressBar = new ProgressBar($out);
        $client->request('GET', $args->ISOUrl, [
            'sink' => $args->ISOFilename,
            'progress' => function($dlTotalSize, $dlSizeSoFar, $ulTotalSize, $ulSizeSoFar) use ($progressBar) {
                if ($dlTotalSize !== 0) {
                    if ($progressBar->getMaxSteps() === 0) {
                        $progressBar->start($dlTotalSize);
                    }
                   $progressBar->setProgress($dlSizeSoFar);
               }
            }
        ]);
        $progressBar->finish();
        $out->writeln("\t<info>Download complete.</info>");
    }

    protected function validateISOSha256Checksum(DownloadArgs $args, OutputInterface $out)
    {
        $out->write("Verifying Sha256 Checksum: ");
        $client = new \GuzzleHttp\Client();
        $response = $client->request('GET', $args->ISOSha256ChecksumUrl);
        $checksum = (string)trim($response->getBody());
        $actual = (string)trim(hash_file('sha256', $args->ISOFilePath) . '  ' . $args->ISOFilename);
        if ($checksum === $actual) {
            $out->writeln("<info>Passed</info>");
        } else {
            $out->writeln("<fg=red>Failed</>");
            $out->writeln("<error>Sha256 Checksum Verification Failed!");
            $out->writeln("Checksum: $checksum");
            $out->writeln("  Actual: $actual</error>");
        }
    }

    protected function validateISOSha1Checksum(DownloadArgs $args, OutputInterface $out)
    {
        $out->write("Verifying Sha1 Checksum: ");
        $client = new \GuzzleHttp\Client();
        $response = $client->request('GET', $args->ISOSha1ChecksumUrl);
        $checksum = (string)trim($response->getBody());
        $actual = (string)trim(sha1_file($args->ISOFilePath) . '  ' . $args->ISOFilename);
        if ($checksum === $actual) {
            $out->writeln("<info>Passed</info>");
        } else {
            $out->writeln("<fg=red>Failed</>");
            $out->writeln("<error>Sha1 Checksum Verification Failed!");
            $out->writeln("Checksum: $checksum");
            $out->writeln("  Actual: $actual</error>");
        }
    }

    protected function validateISOGPGSignature(DownloadArgs $args, OutputInterface $out)
    {
        $out->write("Verifying GPG Signature: ");
        $temp = tmpfile();
        $meta = stream_get_meta_data($temp);
        $client = new \GuzzleHttp\Client();
        $response = $client->request('GET', $args->ISOGPGSignatureUrl, ['sink' => $temp]);
        $signature = (string)$response->getBody();
        exec("gpg --verify {$meta['uri']} {$args->ISOFilePath} 2>&1", $output, $retval);
        fclose($temp);
        if ($retval !== 0) {
            $output = implode("\n", $output);
            $out->writeln("<fg=red>Failed</>");
            $out->writeln("<error>Error performing GPG Signature verification.\n$output</error>");
        } else {
            $out->writeln("<info>Passed</info>");
        }
    }


    protected function getArgs(InputInterface $in)
    {

        $release = $in->getArgument('release');
        $outputDir = $in->getArgument('outputDir');
        $dist = $in->getOption('dist');
        $arch = $in->getOption('arch');
        return new DownloadArgs($outputDir, $release, $dist, $arch);
    }

    protected function importAlpineGpgKey(OutputInterface $out)
    {
        exec('gpg --list-sigs', $output, $retval);
        if ($retval !== 0) {
            $out->writeln("<error>GPG error." . implode("\n", $output) . "</error>");
            exit(1);
        }
        $found = false;
        foreach ($output as $line) {
            if (strpos($line, self::ALPINE_GPG_PUBLIC_KEY_FINGERPRINT) != false) {
                $out->writeln("<info>Alpine GPG Public Key found in keyring</info>");
                $found = true;
                break;
            }
        }

        unset($output);
        unset($retval);

        if ($found === false) {
            $out->writeln("<info>Alpine GPG Public Key not found in keyring. Adding it.</info>");
            $temp = tmpfile();
            fwrite($temp, self::ALPINE_GPG_PUBLIC_KEY);
            $meta = stream_get_meta_data($temp);
            exec('gpg --import ' . $meta['uri'], $output, $retval);
            fclose($temp);

            if ($retval !== 0) {
                $out->writeln("<error>GPG error." . implode("\n", $output) . "</error>");
                exit(1);
            }
            $out->writeln("<info>Alpine GPG Public Key added to keyring.</info>");
        }
    }
}

class DownloadArgs {
    private $outputDir;
    private $release;
    private $dist;
    private $arch;
    private $validated = false;
    private $validationErrors = [];

    public function __construct($outputDir, $release, $dist, $arch)
    {
        $this->outputDir = $outputDir;
        $this->release = $release;
        $this->dist = $dist;
        $this->arch = $arch;
    }

    public function getOutputDir()
    {
        return $this->outputDir ?? getcwd();
    }

    public function getRelease()
    {
        return $this->release;
    }

    public function getDist()
    {
        return $this->dist ?? Download::DIST_STANDARD;
    }

    public function getArch()
    {
        return $this->arch ?? (Download::ARCHITECTURE_MAP[$this->getDist()]['default'] ?? Download::ARCH_X86_64);
    }

    public function isValid()
    {
        if ($this->validated === true) {
            return count($this->validationErrors) === 0;
        }
        // outputdir can be anything, let file handling yell at them if it's something stupid
        // release can be anything, let 404 if they do something stupid
        // dist should be one of the available dists
        // arch should be one of the available archs for the chosen dist

        if (isset($this->dist)) {
            if (!in_array($this->dist, [
                Download::DIST_STANDARD,
                Download::DIST_EXTENDED,
                Download::DIST_VANILLA,
                Download::DIST_VIRTUAL,
                Download::XEN,
                Download::RASPBERY_PI,
                Download::GENERIC_ARM,
            ])) {
                $this->validationErrors[] = "Unrecognized distribution given: '{$this->dist}'";
            }
        }

        if (isset($this->arch)) {
            $dist = $this->getDist();

            if (isset(Download::ARCHITECTURE_MAP[$dist]) ||
                !in_array($this->arch, Download::ARCHITECTURE_MAP[$dist])) {
                $this->validationErrors[] = "Unsupported architecture ('{$this->arch}') chosen for given distribution ('{$dist}').";
            }
        }

        $this->validated = true;
        return $this->isValid();
    }

    public function getReleaseBranch()
    {
        $r = $this->getRelease();
        $p = strrpos($r, '.');
        if ($p !== false) {
            $rs = substr($r, 0, $p);
        } else {
            $rs = $r;
        }
        return $rs;
    }

    public function getISOUrl()
    {
        $distAbbreviations = [
            Download::DIST_STANDARD => '',
            Download::DIST_EXTENDED => '-extended',
            Download::DIST_VANILLA => '-vanilla',
            Download::DIST_VIRTUAL => '-virt',
            Download::DIST_XEN => '-xen',
            Download::DIST_RASPBERRY_PI => '-rpi',
            Download::DIST_GENERIC_ARM => '-uboot',
        ];

        $architecture = $this->getArch();
        $releaseBranch = $this->getReleaseBranch();
        $distabbrv = $distAbbreviations[$this->getDist()] ?? '';
        $release = $this->getRelease();
        $archabbrv = $this->getArch();

        if ($this->arch === Download::ARCH_ARM && $this->dist === Download::DIST_RASPBERRY_PI) {
            $archabbrv .= '.rpi';
        }

        return 'http://dl-cdn.alpinelinux.org/alpine/v' . $releaseBranch . '/releases/' . $architecture . '/alpine' . $distabbrv .'-' . $release . '-' . $archabbrv . '.iso';
    }

    public function getISOFilename()
    {
        $url = $this->getISOUrl();
        return substr($url, strrpos($url, '/') + 1);
    }

    public function getISOFilePath()
    {
        return $this->getOutputDir() . '/' . $this->getISOFilename();
    }

    public function getISOSha256ChecksumUrl()
    {
        return $this->getISOUrl() . '.sha256';
    }

    public function getISOSha1ChecksumUrl()
    {
        return $this->getISOUrl().'.sha1';
    }

    public function getISOGPGSignatureUrl()
    {
        return $this->getISOUrl().'.asc';
    }

    public function getValidationErrors()
    {
        return $this->validationErrors;
    }

    public function __get($key)
    {
        $getter = 'get' . ucfirst($key);
        if (method_exists($this, $getter)) {
            return $this->{$getter}();
        }
        throw new \RuntimeException("There is no argument named: '$key'. More specifically, there is no getter named '$getter'.");
    }
}
