<?php

use Illuminate\Support\Facades\Route;
use TechChallenge\Adapter\Driver\Controller\Product;

Route::get('/', function () {
    return view('welcome');
});


/*
Route::group(['prefix' => 'api'], function () {
    Route::controller(Product::class)->withoutMiddleware(['csrf'])->group(function () {
        Route::post('/product/store', [Product::class, "store"]);
        Route::put('/product/edit/{productId}', [Product::class, "edit"]);
    });
});
*/