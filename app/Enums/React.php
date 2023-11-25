<?php

namespace App\Enums;

use App\Traits\EnumToArray;
use Illuminate\Support\Str;

enum React: string
{
    use EnumToArray;

    case LIKE = '&#128077;';
    case LOVE = '&#10084;';
    case HAHA = '&#128513;';
    case SAD = '&#128546;';
    case CARE = '&#129392;';
    case ANGRY = '&#128545;';

    public static function getEmojiName(string $emoji): ?string
    {
        foreach (self::array() as $enumKey => $enumValue) {
            if ($enumValue === $emoji) {
                return Str::lower($enumKey);
            }
        }
        return null;
    }

}
