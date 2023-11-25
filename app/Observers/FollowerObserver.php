<?php

namespace App\Observers;

use App\Models\Follower;
use AnisAronno\LaravelCacheMaster\CacheControl;

class FollowerObserver
{
    /**
     * Handle the Follower "created" event.
     */
    public function created(Follower $follower): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Follower "updated" event.
     */
    public function updated(Follower $follower): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Follower "deleted" event.
     */
    public function deleted(Follower $follower): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Follower "restored" event.
     */
    public function restored(Follower $follower): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Follower "force deleted" event.
     */
    public function forceDeleted(Follower $follower): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }
}
