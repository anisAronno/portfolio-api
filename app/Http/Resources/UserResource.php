<?php

namespace App\Http\Resources;

use AnisAronno\MediaHelper\Facades\Media;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Carbon;

class UserResource extends JsonResource
{
    public static $wrap = 'user';

    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {

        return [
            "id" => $this->id,
            "name" => $this->name,
            "email" => $this->email,
            "phone" => $this->phone,
            "role" => $this->role,
            'image' => !empty($this->image) ? Media::getURL($this->image) : 'https://www.gravatar.com/avatar/'.md5($this->email),
            "username" => $this->username,
            "tweets_count" => $this->whenNotNull($this->tweets_count),
            "followers_count" => $this->whenNotNull($this->followers_count),
            "following_count" => $this->whenNotNull($this->following_count),
            "isFollowing" => $this->whenNotNull($this->isFollowing),
            'created_at' => Carbon::parse($this->created_at)->diffForHumans(),
            'tweets' => TweetResource::collection($this->whenLoaded('tweets')),
            'followers' => FollowerResource::collection($this->whenLoaded('followers')),
            'following' => FollowingResource::collection($this->whenLoaded('following')),
        ];
    }
}
