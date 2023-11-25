<?php

namespace App\Http\Requests;

use App\Rules\MatchPassword;
use Illuminate\Foundation\Http\FormRequest;

class PasswordUpdateRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return auth()->check();
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'old_password'          => ['required', new MatchPassword()],
            'password'              => 'required| min:8| max:32 |confirmed',
            'password_confirmation' => 'required| min:8',
        ];
    }
}
