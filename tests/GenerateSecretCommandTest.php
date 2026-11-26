<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\Commands\GenerateSecretCommand;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

class GenerateSecretCommandTest extends TestCase
{
    private string $environmentDirectory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->environmentDirectory = sys_get_temp_dir().'/authenticator-secret-'.bin2hex(random_bytes(8));
        mkdir($this->environmentDirectory, 0700);
        $this->app->useEnvironmentPath($this->environmentDirectory);
        $this->app->loadEnvironmentFrom('.env.testing-secret');
        config(['hyrnatic-authenticator.secret' => str_repeat('s', 32)]);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->environmentDirectory.'/.*') as $path) {
            if (is_file($path)) {
                unlink($path);
            }
        }
        rmdir($this->environmentDirectory);

        parent::tearDown();
    }

    #[DataProvider('environmentFiles')]
    public function test_secret_is_written_to_the_configured_environment_file(?string $contents, string $expected): void
    {
        $path = $this->app->environmentFilePath();
        if ($contents !== null) {
            file_put_contents($path, $contents);
            chmod($path, 0600);
        }

        $command = new GenerateSecretCommand();
        $command->setLaravel($this->app);
        $output = new BufferedOutput();

        $this->assertSame(0, $command->run(new ArrayInput(['--force' => true]), $output));
        $secret = config('hyrnatic-authenticator.secret');
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9]{64}$/', $secret);
        $this->assertSame(str_replace('{secret}', $secret, $expected), file_get_contents($path));
        $this->assertSame($secret, \Dotenv\Dotenv::parse(file_get_contents($path))['JWT_SECRET']);
        $this->assertSame(0600, fileperms($path) & 0777);
        $this->assertStringContainsString('JWT Secret set successfully.', $output->fetch());
    }

    public static function environmentFiles(): array
    {
        return [
            'missing file' => [null, "JWT_SECRET={secret}\n"],
            'empty file' => ['', "JWT_SECRET={secret}\n"],
            'unquoted stale value' => ["JWT_SECRET=old\n", "JWT_SECRET={secret}\n"],
            'double quoted' => ["JWT_SECRET=\"old\"\n", "JWT_SECRET={secret}\n"],
            'single quoted' => ["JWT_SECRET='old'\n", "JWT_SECRET={secret}\n"],
            'spaces and export' => ["  export JWT_SECRET = old # comment\n", "JWT_SECRET={secret}\n"],
            'commented entry' => ["# JWT_SECRET=old\n", "# JWT_SECRET=old\nJWT_SECRET={secret}\n"],
            'similarly named entry' => ["OTHER_JWT_SECRET=old\n", "OTHER_JWT_SECRET=old\nJWT_SECRET={secret}\n"],
            'no final newline' => ['OTHER=value', "OTHER=value\nJWT_SECRET={secret}\n"],
            'CRLF' => ["OTHER=value\r\nJWT_SECRET=old\r\n", "OTHER=value\r\nJWT_SECRET={secret}\r\n"],
            'duplicate entries' => ["JWT_SECRET=old\nJWT_SECRET=older\n", "JWT_SECRET={secret}\nJWT_SECRET={secret}\n"],
        ];
    }

    public function test_failed_write_preserves_the_existing_secret_and_reports_failure(): void
    {
        $path = $this->app->environmentFilePath();
        $previousSecret = config('hyrnatic-authenticator.secret');
        $contents = 'JWT_SECRET='.$previousSecret.PHP_EOL;
        file_put_contents($path, $contents);
        $command = new class extends GenerateSecretCommand {
            protected function writeEnvironmentFile(string $path, string $contents): bool
            {
                return false;
            }
        };
        $command->setLaravel($this->app);
        $output = new BufferedOutput();

        $this->assertSame(1, $command->run(new ArrayInput(['--force' => true]), $output));
        $this->assertSame($previousSecret, config('hyrnatic-authenticator.secret'));
        $this->assertSame($contents, file_get_contents($path));
        $this->assertStringNotContainsString('JWT Secret set successfully.', $output->fetch());
    }

    public function test_show_does_not_change_the_environment_or_configuration(): void
    {
        $previousSecret = config('hyrnatic-authenticator.secret');
        $command = new GenerateSecretCommand();
        $command->setLaravel($this->app);
        $output = new BufferedOutput();

        $this->assertSame(0, $command->run(new ArrayInput(['--show' => true]), $output));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9]{64}$/', trim($output->fetch()));
        $this->assertSame($previousSecret, config('hyrnatic-authenticator.secret'));
        $this->assertFileDoesNotExist($this->app->environmentFilePath());
    }
}
