<?php

function login(MongoDB\Client $client)
{
    $users = $client->app->users;
    // ruleid: php.nosql-injection
    $user = $users->findOne(['name' => $_POST['name'], 'password' => $_POST['password']]);
    $sessions = $client->selectCollection('app', 'sessions');
    // ruleid: php.nosql-injection
    $count = $sessions->countDocuments(['token' => $_COOKIE['token']]);
    // ruleid: php.nosql-injection
    $posts = $client->app->posts->find(['$where' => "this.author == '" . $_GET['author'] . "'"]);
    return [$user, $count, $posts];
}

class OrderRepo
{
    private $ordersCollection;

    public function purge($request)
    {
        // ruleid: php.nosql-injection
        return $this->ordersCollection->deleteMany($request->input('filter'));
    }
}

function safe(MongoDB\Client $client)
{
    $users = $client->app->users;
    // ok: php.nosql-injection
    $user = $users->findOne(['name' => (string) $_POST['name']]);
    // ok: php.nosql-injection
    $post = $client->app->posts->findOne(['_id' => new MongoDB\BSON\ObjectId($_GET['id'])]);
    // ok: php.nosql-injection
    $row = User::query()->find($_GET['id']);
    return [$user, $post, $row];
}

// The program's own values, not request input.
function purge(MongoDB\Collection $events, array $filter)
{
    // ok: php.nosql-injection
    return $events->deleteMany($filter);
}
