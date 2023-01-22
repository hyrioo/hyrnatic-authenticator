<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('permission_groups', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('scope');

            $table->timestamps();
        });

        Schema::create('roles', function (Blueprint $table) {
            $table->id();
            $table->string('name');

            $table->timestamps();
        });
        Schema::create('model_has_role', function (Blueprint $table) {
            $table->foreignId('role_id');
            $table->morphs('model');

            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('model_has_role');
        Schema::dropIfExists('roles');
        Schema::dropIfExists('permission_groups');
    }
};
