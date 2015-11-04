<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2015/5/12 0012
 * Time: 下午 10:01
 */

namespace Jzyuchen\OAuthClient;

class OAuthClient {

    public function __construct(){

    }

    public function get($provider){
        $clientId = config('oauth-client.consumers.'.$provider.'.clientId');
        $clientSecret = config('oauth-client.consumers.'.$provider.'.clientSecret');
        $className = config('oauth-client.consumers.'.$provider.'.className');
        $redirectUri  = config('oauth-client.consumers.'.$provider.'.redirectUri');
        $model = new $className(array(
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $redirectUri
        ));

        return $model;
    }
}
