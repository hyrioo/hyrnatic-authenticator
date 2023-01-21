<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('auth_tokens', function (Blueprint $table) {
            $table->id();
            $table->morphs('authable');
            $table->string('name')->nullable();
            $table->string('family')->index();
            $table->string('token', 64)->unique();
            $table->text('scopes')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });

        Schema::create('refresh_tokens', function (Blueprint $table) {
            $table->id();
            $table->morphs('authable');
            $table->string('hash');
            $table->string('family')->index();
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('auth_tokens');
        Schema::dropIfExists('refresh_tokens');
    }
};
