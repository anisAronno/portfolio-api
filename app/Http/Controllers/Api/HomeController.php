<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Resources\TweetResource;
use App\Models\Tweet;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use AnisAronno\LaravelCacheMaster\CacheControl;

class HomeController extends Controller
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
     * Following Tweet
     *
     * @return JsonResource
     */
    public function followingTweets(Request $request): JsonResource
    {
        $page = $request->input('page', 1);
        $searchUsername = $request->input('username');
        $user = auth()->user();

        $key = md5('following_tweets_'.$user->email.'_'.$page .'_'. ($searchUsername ? '_' . $searchUsername : ''));
        $tagKey = 'followingTweets';

        $tweets = CacheControl::init([$tagKey])->remember($key, now()->addDay(), function () use ($user, $searchUsername) {
            $tweets = Tweet::whereIn('user_id', $user->following()->pluck('users.id')->toArray())
                ->with([
                    'user' => function ($query) use ($user) {
                        $query->without('followers')->with(['followers' => function ($followerQuery) use ($user) {
                            $followerQuery->where('follower_id', $user->id);
                        }]);
                    },
                    'reactions' => function ($subQuery) {
                        $subQuery->select('tweet_id', 'user_id', 'react')
                        ->selectRaw('COUNT(*) as reaction_count')
                        ->with('user')
                        ->groupBy('tweet_id', 'user_id', 'react');
                    }
                ])
                ->when($searchUsername, function ($query) use ($searchUsername) {
                    $query->whereHas('user', function ($userQuery) use ($searchUsername) {
                        $userQuery->where('username', $searchUsername);
                    });
                })
                ->when(!$searchUsername, function ($query) use ($user) {
                    $query->where('user_id', '!=', $user->id);
                })
                ->orderByDesc('id')
                ->paginate(10)
                ->withQueryString();

            $tweets->getCollection()->transform(function ($tweet) use ($user) {
                $tweet->user->isFollowing = in_array($tweet->user_id, $user->following()->pluck('users.id')->toArray());
                unset($tweet->user->followers);
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

                unset($tweet->reactions);

                return $tweet;
            });

            return $tweets;
        });
        return TweetResource::collection($tweets)
            ->additional([
                'message' => 'Home tweets retrieved successfully.',
                'success' => true,
        ]);
    }

    /**
     * Home Page Tweet
     *
     * @return JsonResource
     */
    public function tweets(Request $request): JsonResource
    {
        $page = $request->input('page', 1);
        $searchUsername = $request->input('username');
        $user = auth()->user();

        $key = md5('tweets_'.$user->email.'_'.$page .'_'. ($searchUsername ? '_' . $searchUsername : ''));
        $tagKey = 'tweet';

        $tweets = CacheControl::init([$tagKey])->remember($key, now()->addDay(), function () use ($user, $searchUsername) {
            $tweets = Tweet::with([
                'user' => function ($query) use ($user) {
                    $query->without('followers')->with(['followers' => function ($followerQuery) use ($user) {
                        $followerQuery->where('follower_id', $user->id);
                    }]);
                },
                'reactions' => function ($subQuery) {
                    $subQuery->select('tweet_id', 'user_id', 'react')
                    ->selectRaw('COUNT(*) as reaction_count')
                    ->with('user')
                    ->groupBy('tweet_id', 'user_id', 'react');
                }
            ])
            ->when($searchUsername, function ($query) use ($searchUsername) {
                $query->whereHas('user', function ($userQuery) use ($searchUsername) {
                    $userQuery->where('username', $searchUsername);
                });
            })
            ->when(!$searchUsername, function ($query) use ($user) {
                $query->where('user_id', '!=', $user->id);
            })
            ->orderByDesc('id')
            ->paginate(10)
            ->withQueryString();

            $tweets->getCollection()->transform(function ($tweet) use ($user) {
                $tweet->user->isFollowing = in_array($tweet->user_id, $user->following()->pluck('users.id')->toArray());
                unset($tweet->user->followers);
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

                unset($tweet->reactions);

                return $tweet;
            });

            return $tweets;

        });

        return TweetResource::collection($tweets)
            ->additional([
                'message' => 'Home tweets retrieved successfully.',
                'success' => true,
        ]);
    }

    /**
     * Get tweets by username.
     *
     * @param  string  $username
     * @return JsonResource
    */
    public function tweetsByUsername(Request $request, $username): JsonResource
    {
        $page = $request->input('page', 1);

        $key = 'tweetsByUserName_' . $page . ($username ? '_' . $username : '');

        $tagKey = 'tweetByUserName';

        $tweets = CacheControl::init([$tagKey])->remember($key, now()->addDay(), function () use ($username) {
            return Tweet::whereHas('user', function ($query) use ($username) {
                $query->where('username', $username);
            })
                ->with([
                'user' => function ($query) {
                    $user = auth()->user();

                    $query->without('followers')->with(['followers' => function ($followerQuery) use ($user) {
                        $followerQuery->where('follower_id', $user->id);
                    }]);
                },
                'reactions' => function ($subQuery) {
                    $subQuery->select('tweet_id', 'user_id', 'react')
                        ->selectRaw('COUNT(*) as reaction_count')
                        ->with('user')
                        ->groupBy('tweet_id', 'user_id', 'react');
                }
            ])
                ->orderByDesc('id')
                ->paginate()
                ->withQueryString();
        });

        $tweets->getCollection()->transform(function ($tweet) {
            $user = auth()->user();

            $tweet->user->isFollowing = in_array($tweet->user_id, $user->following()->pluck('users.id')->toArray());
            unset($tweet->user->followers);

            $totalReactions = $tweet->reactions->sum('reaction_count');
            $tweet->total_reactions = $totalReactions;

            $aggregatedReactions = $tweet->reactions->groupBy('react')
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

            unset($tweet->reactions);

            return $tweet;
        });

        return TweetResource::collection($tweets)
            ->additional([
                'message' => 'Tweets retrieved successfully.',
                'success' => true,
            ]);
    }


}
