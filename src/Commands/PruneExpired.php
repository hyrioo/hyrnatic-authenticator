<?php

namespace Hyrioo\HyrnaticAuthenticator\Commands;

use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Illuminate\Console\Command;

class PruneExpired extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'authenticator:prune-expired';

    /**
     * The console command description.
     *
     * @var string
     */
    public $description = 'Prune tokens families';

    public function handle(): int
    {
        /** @var TokenFamily $model */
        $model = HyrnaticAuthenticator::$tokenFamilyModel;

        $this->components->task(
            'Pruning tokens with prune_at older than now',
            fn () => $model::query()->where('prune_at', '<', now())->delete()
        );

        $this->components->info("Tokens pruned successfully.");

        return self::SUCCESS;
    }
}
