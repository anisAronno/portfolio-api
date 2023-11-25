<?php

namespace App\Providers;

use App\Models\Follower;
use App\Models\Reaction;
use App\Models\Tweet;
use App\Models\User;
use App\Observers\FollowerObserver;
use App\Observers\ReactionObserver;
use App\Observers\TweetObserver;
use App\Observers\UserObserver;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;

class EventServiceProvider extends ServiceProvider
{
    /**
     * The event to listener mappings for the application.
     *
     * @var array<class-string, array<int, class-string>>
     */
    protected $listen = [
        Registered::class => [
            SendEmailVerificationNotification::class,
        ],
    ];

    /**
     * Register any events for your application.
     */
    public function boot(): void
    {
        Tweet::observe(TweetObserver::class);
        Follower::observe(FollowerObserver::class);
        Reaction::observe(ReactionObserver::class);
        User::observe(UserObserver::class);
    }

    /**
     * Determine if events and listeners should be automatically discovered.
     */
    public function shouldDiscoverEvents(): bool
    {
        return false;
    }
}
