<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class LoginRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        $loginField = $this->input('email') ? 'email' : 'username';

        return [
            $loginField => [
                'required',
                Rule::exists('users', $loginField),
            ],
            'password' => 'required|string|min:6',
        ];
    }

    public function messages()
    {
        return [
            'email.exists' => 'Account not found',
            'username.exists' => 'Account not found',
            'password.required' => 'The password field is required.',
            'password.string' => 'The password must be a string.',
            'password.min' => 'The password must be at least 6 characters.',
        ];
    }

}
