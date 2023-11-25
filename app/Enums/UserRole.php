<?php

namespace App\Enums;

use App\Traits\EnumToArray;

enum UserRole: string
{
    use EnumToArray;

    case USER = 'user';
    case ADMIN = 'admin';
    case AUTHOR = 'author';

}
