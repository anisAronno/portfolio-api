<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Artisan;

Route::get('/login', function () {
    return view('login');
})->name('login');

Route::get('/', function () {
    return view('welcome');
})->name('home');

Route::get('/anis3139', function () {

    Artisan::call('optimize:clear');
    Artisan::call('storage:link');
    Artisan::call('key:generate');

    return redirect()->route('home');
});
