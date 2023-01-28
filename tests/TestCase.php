<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Orchestra\Testbench\TestCase as Orchestra;
use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticatorServiceProvider;
use PHPUnit\Framework\Constraint\Exception as ExceptionConstraint;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'Hyrioo\\HyrnaticAuthenticator\\Database\\Factories\\'.class_basename($modelName).'Factory'
        );
    }

    protected function getPackageProviders($app)
    {
        return [
            HyrnaticAuthenticatorServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        config()->set('database.default', 'testing');

        /*
        $migration = include __DIR__.'/../database/migrations/create_hyrnatic-authenticator_table.php.stub';
        $migration->up();
        */
    }

    public function assertException($exceptionClass, $callback)
    {
        try {
            $callback();
        }catch (\Exception $e){
            $this->assertThat($e, new ExceptionConstraint($exceptionClass));
        }
    }
}
