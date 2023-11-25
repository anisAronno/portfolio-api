<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class ProfileUpdateRequest extends FormRequest
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
           'name' => 'required|string|between:2,100',
           'username' => ['required', 'string', 'min:3', 'max:100', 'alpha_dash',  Rule::unique('users')->ignore($this->user?->id)],
           'email' => ['required', 'string', 'email:rfc,dns', 'max:100',  Rule::unique('users')->ignore($this->user?->id)]
        ];
    }
}
