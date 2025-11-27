<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Cvss4Controller;

Route::get('/', function () {
    return view('cvss4.cvss4');
});

Route::get('/cvss4/calculate', [Cvss4Controller::class, 'calculate']);
Route::get('/cvss4/metrics.json', [Cvss4Controller::class, 'metrics']);
