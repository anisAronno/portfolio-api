<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ReactionResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            "id" => $this->whenNotNull($this->id),
            "react" => $this->react,
            "reaction_count" => $this->whenNotNull($this->reaction_count),
            "tweet_id" => $this->whenNotNull($this->tweet_id),
            "user" => new UserResource($this->whenLoaded("user")),
        ];
    }
}
