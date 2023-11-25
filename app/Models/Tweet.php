<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use App\Helpers\UniqueSlug;

class Tweet extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id', 'content', 'slug',
    ];

    protected static function boot()
    {
        static::creating(function ($model) {
            $model->slug = UniqueSlug::generate($model, 'slug', substr($model->content, 0, 50));
        });

        parent::boot();
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function followers(): HasMany
    {
        return $this->hasMany(Follower::class);
    }
    public function reactions(): HasMany
    {
        return $this->hasMany(Reaction::class);
    }

}
