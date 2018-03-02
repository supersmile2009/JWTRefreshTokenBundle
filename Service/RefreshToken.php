<?php

/*
 * This file is part of the GesdinetJWTRefreshTokenBundle package.
 *
 * (c) Gesdinet <http://www.gesdinet.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Gesdinet\JWTRefreshTokenBundle\Service;

use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Gesdinet\JWTRefreshTokenBundle\Model\RefreshTokenManagerInterface;
use Gesdinet\JWTRefreshTokenBundle\Security\Authenticator\RefreshTokenAuthenticator;
use Gesdinet\JWTRefreshTokenBundle\Security\Provider\RefreshTokenProvider;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

/**
 * Class RefreshToken.
 */
class RefreshToken
{
    /**
     * @var RefreshTokenAuthenticator
     */
    private $authenticator;

    /**
     * @var RefreshTokenProvider
     */
    private $provider;

    /**
     * @var AuthenticationSuccessHandlerInterface 
     */
    private $successHandler;

    /**
     * @var AuthenticationFailureHandlerInterface 
     */
    private $failureHandler;

    /**
     * @var RefreshTokenManagerInterface 
     */
    private $refreshTokenManager;

    /**
     * @var integer
     */
    private $ttl;

    /**
     * @var string
     */
    private $providerKey;

    /**
     * @var bool
     */
    private $ttlUpdate;

    public function __construct(
        RefreshTokenAuthenticator $authenticator,
        RefreshTokenProvider $provider,
        AuthenticationSuccessHandlerInterface $successHandler,
        AuthenticationFailureHandlerInterface $failureHandler,
        RefreshTokenManagerInterface $refreshTokenManager,
        $ttl,
        $providerKey,
        $ttlUpdate
    ) {
        $this->authenticator = $authenticator;
        $this->provider = $provider;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
        $this->refreshTokenManager = $refreshTokenManager;
        $this->ttl = $ttl;
        $this->providerKey = $providerKey;
        $this->ttlUpdate = $ttlUpdate;
    }

    /**
     * Refresh token.
     *
     * @param Request $request
     *
     * @return mixed
     *
     * @throws InvalidArgumentException
     * @throws AuthenticationException
     */
    public function refresh(Request $request)
    {
        try {
            $preAuthenticatedToken = $this->authenticator->authenticateToken(
                $this->authenticator->createToken($request, $this->providerKey),
                $this->provider,
                $this->providerKey
            );
        } catch (AuthenticationException $e) {
            return $this->failureHandler->onAuthenticationFailure($request, $e);
        }

        $refreshToken = $this->refreshTokenManager->get($preAuthenticatedToken->getCredentials());

        if (null === $refreshToken || !$refreshToken->isValid()) {
            return $this->failureHandler->onAuthenticationFailure($request, new AuthenticationException(
                    sprintf('Refresh token "%s" is invalid.', $refreshToken)
                )
            );
        }

        if ($this->ttlUpdate) {
            $expirationDate = new \DateTime();
            $expirationDate->modify(sprintf('+%d seconds', $this->ttl));
            $refreshToken->setValid($expirationDate);

            $this->refreshTokenManager->save($refreshToken);
        }

        return $this->successHandler->onAuthenticationSuccess($request, $preAuthenticatedToken);
    }
}
