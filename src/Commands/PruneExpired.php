<?php

namespace Hyrioo\HyrnaticAuthenticator\Commands;

use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\TokenFamily;
use Illuminate\Console\Command;

class PruneExpired extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'sanctum:prune-expired {--hours=24 : The number of hours to retain expired Sanctum tokens}';

    /**
     * The console command description.
     *
     * @var string
     */
    public $description = 'Prune tokens expired for more than specified number of hours';

    public function handle(): int
    {
        /** @var TokenFamily $model */
        $model = HyrnaticAuthenticator::$tokenFamilyModel;

        $hours = $this->option('hours');

        $this->components->task(
            'Pruning tokens with expired expires_at timestamps',
            fn () => $model::query()->where('expires_at', '<', now()->subHours($hours))->orWhere('prune_at', '<', now()->subHours($hours))->delete()
        );

        $this->components->info("Tokens expired for more than [$hours hours] pruned successfully.");

        return self::SUCCESS;
    }
}
