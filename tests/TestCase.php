<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Illuminate\Database\Eloquent\Factories\Factory;
use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticatorServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Throwable;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        HyrnaticAuthenticator::clearRegisteredScopes();

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
        $connection = $this->databaseEnvironment('DB_CONNECTION', 'sqlite');

        $app['config']->set('database.default', 'testbench');
        $app['config']->set('database.connections.testbench', $this->databaseConfig($connection));
    }

    private function databaseConfig(string $connection): array
    {
        return match ($connection) {
            'mysql' => [
                'driver' => 'mysql',
                'host' => $this->databaseEnvironment('DB_HOST', 'mysql'),
                'port' => $this->databaseEnvironment('DB_PORT', '3306'),
                'database' => $this->databaseEnvironment('DB_DATABASE', 'testing'),
                'username' => $this->databaseEnvironment('DB_USERNAME', 'homestead'),
                'password' => $this->databaseEnvironment('DB_PASSWORD', 'secret'),
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'prefix' => '',
                'prefix_indexes' => true,
                'strict' => true,
            ],
            'pgsql' => [
                'driver' => 'pgsql',
                'host' => $this->databaseEnvironment('DB_HOST', 'postgres'),
                'port' => $this->databaseEnvironment('DB_PORT', '5432'),
                'database' => $this->databaseEnvironment('DB_DATABASE', 'testing'),
                'username' => $this->databaseEnvironment('DB_USERNAME', 'postgres'),
                'password' => $this->databaseEnvironment('DB_PASSWORD', 'secret'),
                'charset' => 'utf8',
                'prefix' => '',
                'prefix_indexes' => true,
                'search_path' => 'public',
                'sslmode' => 'prefer',
            ],
            default => [
                'driver' => 'sqlite',
                'database' => $this->databaseEnvironment('DB_DATABASE', ':memory:'),
                'prefix' => '',
                'foreign_key_constraints' => true,
            ],
        };
    }

    private function databaseEnvironment(string $key, string $default): string
    {
        $value = $_SERVER[$key] ?? $_ENV[$key] ?? getenv($key);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    /**
     * @param class-string<Throwable> $exceptionClass
     */
    public function assertException(string $exceptionClass, callable $callback): void
    {
        try {
            $callback();
        } catch (Throwable $exception) {
            $this->assertInstanceOf($exceptionClass, $exception);

            return;
        }

        $this->fail("Expected exception [{$exceptionClass}] was not thrown.");
    }
}
