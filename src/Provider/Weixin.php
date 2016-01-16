<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2015/5/12 0012
 * Time: 下午 10:17
 */

namespace Jzyuchen\OAuthClient\Provider;

use Guzzle\Http\Exception\BadResponseException;
use League\OAuth2\Client\Entity\User;
use League\OAuth2\Client\Exception\IDPException;
use League\OAuth2\Client\Grant\GrantInterface;
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

    public function getAuthorizationUrl($options = [])
    {
        $this->state = isset($options['state']) ? $options['state'] : md5(uniqid(rand(), true));

        $params = [
            'appid' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $this->state,
            'scope' => is_array($this->scopes) ? implode($this->scopeSeparator, $this->scopes) : $this->scopes,
            'response_type' => isset($options['response_type']) ? $options['response_type'] : 'code',
            'approval_prompt' => isset($options['approval_prompt']) ? $options['approval_prompt'] : 'auto',
        ];

        return $this->urlAuthorize().'?'.$this->httpBuildQuery($params, '', '&');
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

    public function getAccessToken($grant = 'authorization_code', $params = [])
    {
        if (is_string($grant)) {
            // PascalCase the grant. E.g: 'authorization_code' becomes 'AuthorizationCode'
            $className = str_replace(' ', '', ucwords(str_replace(['-', '_'], ' ', $grant)));
            $grant = 'League\\OAuth2\\Client\\Grant\\'.$className;
            if (! class_exists($grant)) {
                throw new \InvalidArgumentException('Unknown grant "'.$grant.'"');
            }
            $grant = new $grant();
        } elseif (! $grant instanceof GrantInterface) {
            $message = get_class($grant).' is not an instance of League\OAuth2\Client\Grant\GrantInterface';
            throw new \InvalidArgumentException($message);
        }

        $defaultParams = [
            'appid'     => $this->clientId,
            'secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
            'grant_type'    => $grant,
        ];

        $requestParams = $grant->prepRequestParams($defaultParams, $params);

        try {
            switch (strtoupper($this->method)) {
                case 'GET':
                    // @codeCoverageIgnoreStart
                    // No providers included with this library use get but 3rd parties may
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken() . '?' . $this->httpBuildQuery($requestParams, '', '&'));
                    $request = $client->get(null, $this->getHeaders(), $requestParams)->send();
                    $response = $request->getBody();
                    break;
                // @codeCoverageIgnoreEnd
                case 'POST':
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken());
                    $request = $client->post(null, $this->getHeaders(), $requestParams)->send();
                    $response = $request->getBody();
                    break;
                // @codeCoverageIgnoreStart
                default:
                    throw new \InvalidArgumentException('Neither GET nor POST is specified for request');
                // @codeCoverageIgnoreEnd
            }
        } catch (BadResponseException $e) {
            // @codeCoverageIgnoreStart
            $response = $e->getResponse()->getBody();
            // @codeCoverageIgnoreEnd
        }

        $result = $this->prepareResponse($response);

        if (isset($result['error']) && ! empty($result['error'])) {
            // @codeCoverageIgnoreStart
            throw new IDPException($result);
            // @codeCoverageIgnoreEnd
        }

        $result = $this->prepareAccessTokenResult($result);

        if (!empty($result['openid'])) {
            $result['uid'] = $result['openid'];
        }

        return $grant->handleResponse($result);
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
        return 'https://api.weixin.qq.com/sns/userinfo?access_token='.$token->accessToken.'&openid='.$token->uid;
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
