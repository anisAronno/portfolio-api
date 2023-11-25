<?php

namespace App\Observers;

use App\Models\Reaction;
use AnisAronno\LaravelCacheMaster\CacheControl;

class ReactionObserver
{
    /**
     * Handle the Reaction "created" event.
     */
    public function created(Reaction $reaction): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Reaction "updated" event.
     */
    public function updated(Reaction $reaction): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Reaction "deleted" event.
     */
    public function deleted(Reaction $reaction): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Reaction "restored" event.
     */
    public function restored(Reaction $reaction): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Reaction "force deleted" event.
     */
    public function forceDeleted(Reaction $reaction): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }
}
