<?php

namespace Hyrioo\HyrnaticAuthenticator\Commands;

use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Support\Str;

class GenerateSecretCommand extends Command
{
    use ConfirmableTrait;

    public $signature = 'authenticator:secret
                    {--show : Display the key instead of modifying files}
                    {--force : Force the operation to run when in production}';

    public $description = 'Set secret for JWT';

    public function handle(): int
    {
        $key = Str::random(64);

        if ($this->option('show')) {
            $this->comment($key);
            return self::SUCCESS;
        }

        if ($this->confirmToProceed() === false) {
            return self::FAILURE;
        }

        /** @var \Illuminate\Foundation\Application $application */
        $application = $this->laravel;
        $path = $application->environmentFilePath();
        $path = realpath($path) ?: $path;
        $contents = file_exists($path) ? @file_get_contents($path) : '';

        if ($contents === false || is_dir($path)) {
            $this->components->error('The environment file could not be read.');

            return self::FAILURE;
        }

        $updated = preg_replace(
            '/^[\t ]*(?:export[\t ]+)?JWT_SECRET[\t ]*=[^\r\n]*/m',
            'JWT_SECRET='.$key,
            $contents,
            -1,
            $replacements,
        );

        if ($replacements === 0) {
            $lineEnding = str_contains($contents, "\r\n") ? "\r\n" : PHP_EOL;
            $updated .= ($contents !== '' && !str_ends_with($contents, "\n") ? $lineEnding : '')
                .'JWT_SECRET='.$key.$lineEnding;
        }

        if ($updated === null || !$this->writeEnvironmentFile($path, $updated)) {
            $this->components->error('The environment file could not be updated. JWT secret was not changed.');

            return self::FAILURE;
        }

        $this->laravel['config']['hyrnatic-authenticator.secret'] = $key;

        $this->components->info('JWT Secret set successfully.');

        if ($application->configurationIsCached()) {
            $this->components->warn('Rebuild the configuration cache and restart long-running workers to use the new JWT secret.');
        }

        return self::SUCCESS;
    }

    protected function writeEnvironmentFile(string $path, string $contents): bool
    {
        $temporaryPath = @tempnam(dirname($path), '.jwt-secret-');
        if ($temporaryPath === false) {
            return false;
        }

        try {
            $permissions = file_exists($path) ? @fileperms($path) : 0600;
            if ($permissions === false || !@chmod($temporaryPath, $permissions & 0777)) {
                return false;
            }

            if (@file_put_contents($temporaryPath, $contents) !== strlen($contents)
                || @file_get_contents($temporaryPath) !== $contents
            ) {
                return false;
            }

            return @rename($temporaryPath, $path);
        } finally {
            if (is_file($temporaryPath)) {
                @unlink($temporaryPath);
            }
        }
    }
}
