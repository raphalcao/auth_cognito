<?php

use Illuminate\Support\Facades\Route;

use TechChallenge\Api\Auth\Auth;

Route::prefix('auth')->controller(Auth::class)->group(function () {
    Route::post('/register', 'register');
    Route::post('/login', 'login');
    Route::post('/logout', 'logout');

});
