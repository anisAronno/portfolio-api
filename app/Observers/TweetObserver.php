<?php

namespace App\Observers;

use App\Models\Tweet;
use AnisAronno\LaravelCacheMaster\CacheControl;

class TweetObserver
{
    /**
     * Handle the Tweet "created" event.
     */
    public function created(Tweet $tweet): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Tweet "updated" event.
     */
    public function updated(Tweet $tweet): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Tweet "deleted" event.
     */
    public function deleted(Tweet $tweet): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Tweet "restored" event.
     */
    public function restored(Tweet $tweet): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }

    /**
     * Handle the Tweet "force deleted" event.
     */
    public function forceDeleted(Tweet $tweet): void
    {
        CacheControl::forgetCache(['tweet','followingTweets',  'tweetByUserName']);
    }
}
