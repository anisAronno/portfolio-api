<?php

namespace Database\Seeders;

use App\Models\Follower;
use App\Models\Reaction;
use App\Models\Tweet;
use App\Enums\React;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Schema;
use Faker\Factory as Faker;

class UserSeeder extends Seeder
{
    public function run(): void
    {
        Schema::disableForeignKeyConstraints();
        User::truncate();
        Tweet::truncate();
        Reaction::truncate();
        Follower::truncate();
        Schema::enableForeignKeyConstraints();

        User::factory()->count(5)
            ->has(
                Follower::factory()->count(2),
                'followers',
            )
            ->has(
                Follower::factory()->count(2),
                'following',
            )
            ->create();

        $faker = Faker::create();

        User::all()->each(function ($user) use ($faker) {
            Tweet::factory()->count(5)
                ->create([
                    'user_id' => $user->id,
                    'content' => $faker->paragraph(),
                ]);

            $user->followers->each(function ($follower) use ($faker) {
                Tweet::factory()->count(5)
                    ->create([
                        'user_id' => $follower->id,
                        'content' => $faker->paragraph(),
                    ]);
            });

            $user->following->each(function ($followedUser) use ($faker) {
                Tweet::factory()->count(5)
                    ->create([
                        'user_id' => $followedUser->id,
                        'content' => $faker->paragraph(),
                    ]);
            });
        });

        Tweet::all()->each(function ($tweet) use ($faker) {
            $users = User::inRandomOrder()->take(5)->pluck('id')->toArray();
            foreach ($users as $userId) {
                Reaction::factory()->create([
                    'user_id' => $userId,
                    'tweet_id' => $tweet->id,
                    'react' => $faker->randomElement(React::values()),
                ]);
            }
        });
    }
}
