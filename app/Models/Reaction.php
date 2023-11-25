<?php

namespace App\Models;

use App\Enums\React;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Reaction extends Model
{
    use HasFactory;

    protected $casts = [
        'react' => React::class,
    ];


    protected $fillable = [
        'user_id', 'tweet_id', 'react'
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function tweet()
    {
        return $this->belongsTo(Tweet::class);
    }
}
