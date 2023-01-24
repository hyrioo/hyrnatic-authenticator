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

        $path = $this->laravel->environmentFilePath();

        if (Str::contains(file_get_contents($path), 'JWT_SECRET') === false) {
            // create new entry
            file_put_contents($path, PHP_EOL."JWT_SECRET=$key".PHP_EOL, FILE_APPEND);
        } else {
            if ($this->confirmToProceed() === false) {
                return self::FAILURE;
            }

            // update existing entry
            file_put_contents($path, str_replace(
                'JWT_SECRET='.$this->laravel['config']['hyrnatic-authenticator.secret'],
                'JWT_SECRET='.$key, file_get_contents($path)
            ));
        }

        $this->laravel['config']['hyrnatic-authenticator.secret'] = $key;

        $this->components->info('JWT Secret set successfully.');

        return self::SUCCESS;
    }
}
