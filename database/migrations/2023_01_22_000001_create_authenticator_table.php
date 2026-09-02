<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('token_families', function (Blueprint $table) {
            $table->id();
            $table->string('authable_type', 191);
            $table->string('authable_id', 191);
            $table->string('name')->nullable();
            $table->string('family', 48)->unique();
            $table->json('scopes');
            $table->json('access_claims');
            $table->json('refresh_claims');
            $table->integer('last_refresh_sequence');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamp('prune_at')->nullable()->index();
            $table->timestamps();

            $table->index(['authable_type', 'authable_id'], 'token_families_authable_index');
        });
    }

    public function down()
    {
        Schema::dropIfExists('token_families');
    }
};
