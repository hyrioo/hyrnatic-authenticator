<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('scopes', function (Blueprint $table) {
            $table->id();
            $table->string('key', 191)->unique();
            $table->string('name');
            $table->string('source')->default('custom');
            $table->string('resource_type', 191)->nullable();
            $table->json('sub_scopes')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();
        });

        Schema::create('model_scopes', function (Blueprint $table) {
            $table->id();
            $table->string('authable_type', 191);
            $table->string('authable_id', 191);
            $table->string('scope_key', 191);
            $table->string('resource_type', 191)->nullable();
            $table->string('resource_id', 191)->nullable();
            $table->string('binding_key', 64);
            $table->timestamps();

            $table->unique(
                ['authable_type', 'authable_id', 'scope_key', 'binding_key'],
                'model_scopes_unique_assignment'
            );
            $table->index(['authable_type', 'authable_id'], 'model_scopes_authable_index');
            $table->index(['resource_type', 'resource_id'], 'model_scopes_resource_index');
        });
    }

    public function down()
    {
        Schema::dropIfExists('model_scopes');
        Schema::dropIfExists('scopes');
    }
};
