<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('model_has_scope', function (Blueprint $table) {
            $table->morphs('authable');
            $table->nullableMorphs('model');
            $table->string('scope');
            $table->timestamps();

            $table->index(['authable_id', 'authable_type', 'model_id', 'model_type']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('model_has_scope');
    }
};
