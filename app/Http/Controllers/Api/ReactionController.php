<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreReactionRequest;
use App\Models\Tweet;
use Illuminate\Http\JsonResponse;

class ReactionController extends Controller
{
    /**
    * Create a new AuthController instance.
    *
    * @return void
    */
    public function __construct()
    {
        $this->middleware('auth:sanctum');
    }

    /**
     * React to Tweet
     *
     * @param Tweet $tweet
     * @param StoreReactionRequest $request
     * @return JsonResponse
     */
    public function reactToTweet(Tweet $tweet, StoreReactionRequest $request): JsonResponse
    {
        $user = auth()->user();

        $existingReaction = $tweet->reactions()->where('user_id', $user->id)->first();

        if ($existingReaction) {
            $existingReaction->update(['react' => $request->react]);
        } else {
            $tweet->reactions()->create([
                'user_id' => $user->id,
                'react' => $request->react,
            ]);
        }

        return response()->json(['message' => 'Reaction added successfully.', 'success' => true]);
    }

    /**
     * Remove React
     *
     * @param Tweet $tweet
     * @return JsonResponse
     */
    public function removeReactFromTweet(Tweet $tweet): JsonResponse
    {
        $user = auth()->user();

        $existingReaction = $tweet->reactions()->where('user_id', $user->id)->first();

        if ($existingReaction) {
            $existingReaction->delete();

            return response()->json(['message' => 'Reaction removed successfully.', 'success' => true]);
        }

        return response()->json(['message' => 'User has not reacted to this tweet.', 'success' => false], 404);
    }
}
