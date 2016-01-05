<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2015/5/12 0012
 * Time: 下午 10:17
 */

namespace Jzyuchen\OAuthClient\Provider;

use League\OAuth2\Client\Entity\User;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;

class Weixin extends AbstractProvider {

    protected $apiDomain = 'https://api.weixin.qq.com/sns';
    protected $openid = ''; // only stupid tencent offers this..

    /**
     * Get the URL that this provider uses to begin authorization.
     *
     * @return string
     */
    public function urlAuthorize()
    {
        return 'https://open.weixin.qq.com/connect/qrconnect';
    }

    public function getAuthorizationParameters(array $options)
    {
        if (empty($options['state'])) {
            $options['state'] = $this->getRandomState();
        }
        if (empty($options['scope'])) {
            $options['scope'] = $this->getDefaultScopes();
        }
        $options += [
            'response_type'   => 'code',
            'approval_prompt' => 'auto'
        ];
        if (is_array($options['scope'])) {
            $separator = $this->getScopeSeparator();
            $options['scope'] = implode($separator, $options['scope']);
        }
        // Store the state as it may need to be accessed later on.
        $this->state = $options['state'];
        return [
            'appid'       => $this->clientId,
            'redirect_uri'    => $this->redirectUri,
            'state'           => $this->state,
            'scope'           => $options['scope'],
            'response_type'   => $options['response_type'],
            'approval_prompt' => $options['approval_prompt'],
        ];
    }

    /**
     * Get the URL that this provider users to request an access token.
     *
     * @return string
     */
    public function urlAccessToken()
    {
        return 'https://api.weixin.qq.com/sns/oauth2/access_token';
    }

    public function getAccessToken($grant, array $options = [])
    {
        $grant = $this->verifyGrant($grant);
        $params = [
            'appid'     => $this->clientId,
            'secret' => $this->clientSecret,
        ];
        $params   = $grant->prepareRequestParameters($params, $options);
        $request  = $this->getAccessTokenRequest($params);
        $response = $this->getResponse($request);
        $prepared = $this->prepareAccessTokenResponse($response);
        $token    = $this->createAccessToken($prepared, $grant);
        return $token;
    }

    public function createAccessToken(array $response, \League\OAuth2\Client\Grant\AbstractGrant $grant)
    {
        $this->openid = $response['openid'];
        return new AccessToken($response);
    }

    /**
     * Get the URL that this provider uses to request user details.
     *
     * Since this URL is typically an authorized route, most providers will require you to pass the access_token as
     * a parameter to the request. For example, the google url is:
     *
     * 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token='.$token
     *
     * @param AccessToken $token
     * @return string
     */
    public function urlUserDetails(AccessToken $token)
    {
        return 'https://api.weixin.qq.com/sns/userinfo?access_token='.$token.'&openid='.$this->openid;
    }

    /**
     * Given an object response from the server, process the user details into a format expected by the user
     * of the client.
     *
     * @param object $response
     * @param AccessToken $token
     * @return mixed
     */
    public function userDetails($response, AccessToken $token)
    {
        $user = new User();
        $gender = (isset($response->sex)) ? $response->sex : null;
        $province = (isset($response->province)) ? $response->province : null;
        $imageUrl = (isset($response->headimgurl)) ? $response->headimgurl : null;
        $user->exchangeArray([
            'uid' => $response->openid,
            'nickname' => $response->nickname,
            'gender' => $gender,
            'province' => $province,
            'imageUrl' => $imageUrl,
            'urls'  => null,
        ]);
        return $user;
    }
}