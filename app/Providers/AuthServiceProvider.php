<?php

namespace App\Providers;

// use Illuminate\Support\Facades\Gate;
use App\Enums\UserRole;
use App\Models\Tweet;
use App\Policies\TweetPolicy;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The model to policy mappings for the application.
     *
     * @var array<class-string, class-string>
     */
    protected $policies = [
        Tweet::class => TweetPolicy::class,
    ];

    /**
     * Register any authentication / authorization services.
     */
    public function boot(): void
    {
        ResetPassword::createUrlUsing(function ($user, string $token) {
            return config('app.frontend_url') . '/password-reset?token=' . $token . '&email=' . $user->getEmailForPasswordReset();
        });

        Gate::define('isAdmin', function ($user) {
            return $user->role == UserRole::ADMIN->value;
        });
        Gate::define('isAuthor', function ($user) {
            return $user->role == UserRole::AUTHOR->value;
        });
        Gate::define('isUser', function ($user) {
            return $user->role == UserRole::USER->value;
        });
    }
}
