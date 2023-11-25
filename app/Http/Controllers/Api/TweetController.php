<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreTweetRequest;
use App\Http\Requests\UpdateTweetRequest;
use App\Http\Resources\TweetResource;
use App\Models\Tweet;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\DB;

class TweetController extends Controller
{
    /**
    * Create a new AuthController instance.
    *
    * @return void
    */
    public function __construct()
    {
        $this->middleware('auth:sanctum');
        $this->authorizeResource(Tweet::class, 'tweet');
    }

    /**
     * Display User Tweet
     *
     * @return JsonResource|JsonResponse
     */
    public function index(): JsonResource|JsonResponse
    {
        $user = auth()->user()->load('tweets');

        $tweets = $user->tweets()->orderByDesc('id')->paginate();

        return (TweetResource::collection($tweets->load(['reactions.user'])))->additional([
            'message'  => 'Tweet retrieved successfully.',
            'success'  => true,
         ]);
    }

    /**
     * Store Tweet
     *
     * @param StoreTweetRequest $request
     * @return JsonResource|JsonResponse
     */
    public function store(StoreTweetRequest $request): JsonResource|JsonResponse
    {
        try {
            DB::beginTransaction();
            $user = auth()->user();

            $tweet = $user->tweets()->create([
                'content' => $request->input('content'),
            ]);

            $tweet->refresh();

            $tweet->load([
                'user' => function ($query) use ($user) {
                    $query->without('followers')->with(['followers' => function ($followerQuery) use ($user) {
                        $followerQuery->where('follower_id', $user->id);
                    }]);
                },
                'reactions' => function ($subQuery) {
                    $subQuery->select('tweet_id', 'react')
                        ->selectRaw('COUNT(*) as reaction_count')
                        ->groupBy('tweet_id', 'react');
                }
            ]);

            $totalReactions = $tweet->reactions->sum('reaction_count');
            $tweet->total_reactions = $totalReactions;

            $aggregatedReactions = $tweet->reactions
                ->groupBy('react')
                ->map(function ($reactions) {
                    return $reactions->sum('reaction_count');
                });
            $tweet->reaction_count = $aggregatedReactions;

            $userReactions = $tweet->reactions
                ->where('user_id', $user->id)
                ->pluck('react')
                ->unique()
                ->values();
            $tweet->user_reactions = $userReactions;

            DB::commit();
            return (new TweetResource($tweet))->additional([
                'message' => 'Tweet created successfully.',
                'success' => true,
            ]);
        } catch (\Throwable $th) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => $th->getMessage()
            ], 400);
        }

    }

    /**
     * Display Single Tweets
     *
     * @param Tweet $tweet
     * @return JsonResource
     */
    public function show(Tweet $tweet): JsonResource
    {
        return (new TweetResource($tweet->load(['reactions.user'])))->additional([
            'message' => 'Tweet retrieved successfully.',
            'success' => true,
        ]);
    }

    /**
     * Update Tweet
     *
     * @param UpdateTweetRequest $request
     * @param Tweet $tweet
     * @return JsonResource
     */
    public function update(UpdateTweetRequest $request, Tweet $tweet): JsonResource|JsonResponse
    {
        try {
            DB::beginTransaction();

            $user = auth()->user();

            $tweet->update([
                'content' => $request->input('content'),
            ]);

            $tweet->refresh();

            $tweet->load([
                'user' => function ($query) use ($user) {
                    $query->without('followers')->with(['followers' => function ($followerQuery) use ($user) {
                        $followerQuery->where('follower_id', $user->id);
                    }]);
                },
                'reactions' => function ($subQuery) {
                    $subQuery->select('tweet_id', 'react')
                        ->selectRaw('COUNT(*) as reaction_count')
                        ->groupBy('tweet_id', 'react');
                }
            ]);

            $totalReactions = $tweet->reactions->sum('reaction_count');
            $tweet->total_reactions = $totalReactions;

            $aggregatedReactions = $tweet->reactions
                ->groupBy('react')
                ->map(function ($reactions) {
                    return $reactions->sum('reaction_count');
                });
            $tweet->reaction_count = $aggregatedReactions;

            $userReactions = $tweet->reactions
                ->where('user_id', $user->id)
                ->pluck('react')
                ->unique()
                ->values();
            $tweet->user_reactions = $userReactions;

            DB::commit();
            return (new TweetResource($tweet))->additional([
                'message' => 'Tweet updated successfully.',
                'success' => true,
            ]);
        } catch (\Throwable $th) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => $th->getMessage()
            ], 400);
        }
    }


    /**
     * Delete Tweet
     *
     * @param Tweet $tweet
     * @return JsonResponse
     */
    public function destroy(Tweet $tweet): JsonResponse
    {
        if ($tweet->delete()) {
            return response()->json([
                'success' => true,
                'message' => 'Successfully deleted.'
            ], 200);
        } else {
            return response()->json([
                'success' => false,
                'message' => 'Deleted Failed!'
            ], 400);
        }
    }
}
