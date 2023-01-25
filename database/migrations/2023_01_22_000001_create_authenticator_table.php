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
            $table->morphs('authable');
            $table->string('name')->nullable();
            $table->string('family')->index();
            $table->text('scopes');
            $table->timestamp('last_used_at')->nullable();
            $table->integer('last_refresh_sequence');
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('token_family');
    }
};
