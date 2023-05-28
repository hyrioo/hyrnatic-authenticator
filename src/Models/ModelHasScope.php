<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property string $scope
 */
class ModelHasScope extends Model
{
    public function authable()
    {
        return $this->morphTo('authable');
    }

    public function model()
    {
        return $this->morphTo('model');
    }
}
