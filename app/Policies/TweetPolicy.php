<?php

namespace App\Policies;

use App\Models\Tweet;
use App\Models\User;
use Illuminate\Auth\Access\HandlesAuthorization;
use Illuminate\Auth\Access\Response;

class TweetPolicy
{
    use HandlesAuthorization;

    /**
     * Determine whether the user can view any models.
     *
     * @param User $user
     * @return boolean
     */
    public function viewAny(User $user): bool
    {
        return true;
    }

    /**
     * Determine whether the user can view the model.
     *
     * @param User $user
     * @param Tweet $tweet
     * @return boolean
     */
    public function view(User $user, Tweet $tweet): bool
    {
        return true;
    }

    /**
     * Determine whether the user can create models.
     *
     * @param User $user
     * @return boolean
     */
    public function create(User $user): bool
    {
        return true;
    }

    /**
     * Determine whether the user can update the model.
     * @param User $user
     * @param Tweet $tweet
     * @return Response|boolean
     */
    public function update(User $user, Tweet $tweet): Response|bool
    {
        return optional($user)->id === $tweet->user_id
        ? Response::allow()
        : Response::deny('You do not own this Tweet.');
    }

    /**
     *  * Determine whether the user can delete the model.
     * @param User $user
     * @param Tweet $tweet
     * @return Response|boolean
     */
    public function delete(User $user, Tweet $tweet): Response|bool
    {
        return optional($user)->id === $tweet->user_id
        ? Response::allow()
        : Response::deny('You do not own this Tweet.');
    }

    /**
     * Determine whether the user can restore the model.
     *
     * @param User $user
     * @param Tweet $tweet
     * @return Response|boolean
     */
    public function restore(User $user, Tweet $tweet): Response|bool
    {
        return optional($user)->id === $tweet->user_id
        ? Response::allow()
        : Response::deny('You do not own this Tweet.');
    }

    /**
     * Determine whether the user can permanently delete the model.
     *
     * @param User $user
     * @param Tweet $tweet
     * @return Response|bool
     */
    public function forceDelete(User $user, Tweet $tweet): Response|bool
    {
        return optional($user)->id === $tweet->user_id
        ? Response::allow()
        : Response::deny('You do not own this Tweet.');
    }
}
