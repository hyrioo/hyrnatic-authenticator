<?php

namespace Hyrioo\HyrnaticAuthenticator\Commands;

use Illuminate\Console\Command;

class GenerateSecretCommand extends Command
{
    public $signature = 'authenticator:secret';

    public $description = 'My command';

    public function handle(): int
    {

        return self::SUCCESS;
    }
}
