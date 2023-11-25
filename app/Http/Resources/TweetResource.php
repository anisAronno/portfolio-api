<?php

namespace App\Http\Resources;

use App\Enums\React;
use App\Http\Resources\UserResource;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Carbon;

class TweetResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $reactionArr = React::values();

        $reactions = collect($reactionArr)->map(function ($emoji) {
            return [
                'emoji' => $emoji,
                'name' => React::getEmojiName($emoji),
            ];
        })->all();

        return [
            "id" => $this->id,
            "content" => $this->content,
            "slug" => $this->slug,
            'created_at' => Carbon::parse($this->created_at)->diffForHumans(),
            "total_reactions" => $this->whenNotNull($this->total_reactions),
            "user_reactions" => $this->whenNotNull($this->user_reactions),
            "reaction_count" => $this->whenNotNull($this->reaction_count),
            "reaction_arr" => $reactions,
            'user' => new UserResource($this->whenLoaded('user')),
        ];
    }
}
