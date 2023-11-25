<?php

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\FollowerController;
use App\Http\Controllers\Api\HomeController;
use App\Http\Controllers\Api\ReactionController;
use App\Http\Controllers\Api\TweetController;
use Illuminate\Support\Facades\Route;

Route::controller(AuthController::class)->group(function () {
    Route::post('login', 'login')->middleware('guest');
    Route::post('register', 'register')->middleware('guest');
    Route::post('logout', 'logout')->middleware(['auth:sanctum']);
    Route::post('refresh', 'refresh')->middleware(['auth:sanctum']);
    Route::get('profile', 'profile')->middleware(['auth:sanctum']);
    Route::get('user-profile/{user:username}', 'userProfile')->middleware(['auth:sanctum'])->name('userProfile');
    Route::post('profile-update/{user:username}', 'profileUpdate')->middleware(['auth:sanctum']);
    Route::post('password-update/{user:username}', 'passwordUpdate')->middleware(['auth:sanctum']);
    Route::post('profile-picture-upload', 'userAvatarUpdate')->middleware(['auth:sanctum']);
    Route::post('password-recover', 'passwordRecover')->name('password.recover')->middleware('guest');
    Route::post('password-reset', 'passwordReset')->name('password.reset')->middleware('guest');
});

Route::controller(HomeController::class)->middleware(['auth:sanctum'])->group(function () {
    Route::get('tweets', 'tweets')->name('tweets');
    Route::get('following-tweets', 'followingTweets')->name('followingTweets');
    Route::get('tweets/{user:username}', 'tweetsByUsername')->name('tweetsByUsername');
});

Route::controller(TweetController::class)->middleware(['auth:sanctum'])->group(function () {
    Route::get('tweet', 'index');
    Route::get('tweet/{tweet:slug}', 'show');
    Route::post('tweet', 'store');
    Route::put('tweet/{tweet:slug}', 'update');
    Route::delete('tweet/{tweet:slug}', 'destroy');
});

Route::controller(FollowerController::class)->middleware(['auth:sanctum'])->group(function () {
    Route::post('follow', 'follow');
    Route::post('unfollow', 'unFollow');
});

Route::controller(ReactionController::class)->middleware(['auth:sanctum'])->group(function () {
    Route::post('react/{tweet}', 'reactToTweet');
    Route::post('remove-react/{tweet}', 'removeReactFromTweet');
});
