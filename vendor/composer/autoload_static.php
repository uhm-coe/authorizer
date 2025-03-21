<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit3afe4a77f11b1a9be67c8c9e1abad910
{
    public static $files = array (
        '7b11c4dc42b3b3023073cb14e519683c' => __DIR__ . '/..' . '/ralouphie/getallheaders/src/getallheaders.php',
        '6e3fae29631ef280660b3cdad06f25a8' => __DIR__ . '/..' . '/symfony/deprecation-contracts/function.php',
        '37a3dc5111fe8f707ab4c132ef1dbc62' => __DIR__ . '/..' . '/guzzlehttp/guzzle/src/functions_include.php',
        '1f87db08236948d07391152dccb70f04' => __DIR__ . '/..' . '/google/apiclient-services/autoload.php',
        'decc78cc4436b1292c6c0d151b19445c' => __DIR__ . '/..' . '/phpseclib/phpseclib/phpseclib/bootstrap.php',
        '344f11dc3484aaed5cbde58e23513be4' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS.php',
        'a8d3953fd9959404dd22d3dfcd0a79f0' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
    );

    public static $prefixLengthsPsr4 = array (
        'p' => 
        array (
            'phpseclib3\\' => 11,
        ),
        'T' => 
        array (
            'TheNetworg\\OAuth2\\Client\\' => 25,
        ),
        'P' => 
        array (
            'Psr\\Log\\' => 8,
            'Psr\\Http\\Message\\' => 17,
            'Psr\\Http\\Client\\' => 16,
            'Psr\\Cache\\' => 10,
            'ParagonIE\\ConstantTime\\' => 23,
        ),
        'M' => 
        array (
            'Monolog\\' => 8,
        ),
        'L' => 
        array (
            'League\\OAuth2\\Client\\' => 21,
        ),
        'G' => 
        array (
            'GuzzleHttp\\Psr7\\' => 16,
            'GuzzleHttp\\Promise\\' => 19,
            'GuzzleHttp\\' => 11,
            'Google\\Service\\' => 15,
            'Google\\Auth\\' => 12,
            'Google\\' => 7,
        ),
        'F' => 
        array (
            'Firebase\\JWT\\' => 13,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'phpseclib3\\' => 
        array (
            0 => __DIR__ . '/..' . '/phpseclib/phpseclib/phpseclib',
        ),
        'TheNetworg\\OAuth2\\Client\\' => 
        array (
            0 => __DIR__ . '/..' . '/thenetworg/oauth2-azure/src',
        ),
        'Psr\\Log\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/log/Psr/Log',
        ),
        'Psr\\Http\\Message\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/http-factory/src',
            1 => __DIR__ . '/..' . '/psr/http-message/src',
        ),
        'Psr\\Http\\Client\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/http-client/src',
        ),
        'Psr\\Cache\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/cache/src',
        ),
        'ParagonIE\\ConstantTime\\' => 
        array (
            0 => __DIR__ . '/..' . '/paragonie/constant_time_encoding/src',
        ),
        'Monolog\\' => 
        array (
            0 => __DIR__ . '/..' . '/monolog/monolog/src/Monolog',
        ),
        'League\\OAuth2\\Client\\' => 
        array (
            0 => __DIR__ . '/..' . '/league/oauth2-github/src',
            1 => __DIR__ . '/..' . '/league/oauth2-client/src',
        ),
        'GuzzleHttp\\Psr7\\' => 
        array (
            0 => __DIR__ . '/..' . '/guzzlehttp/psr7/src',
        ),
        'GuzzleHttp\\Promise\\' => 
        array (
            0 => __DIR__ . '/..' . '/guzzlehttp/promises/src',
        ),
        'GuzzleHttp\\' => 
        array (
            0 => __DIR__ . '/..' . '/guzzlehttp/guzzle/src',
        ),
        'Google\\Service\\' => 
        array (
            0 => __DIR__ . '/..' . '/google/apiclient-services/src',
        ),
        'Google\\Auth\\' => 
        array (
            0 => __DIR__ . '/..' . '/google/auth/src',
        ),
        'Google\\' => 
        array (
            0 => __DIR__ . '/..' . '/google/apiclient/src',
        ),
        'Firebase\\JWT\\' => 
        array (
            0 => __DIR__ . '/..' . '/firebase/php-jwt/src',
        ),
    );

    public static $classMap = array (
        'CAS_AuthenticationException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/AuthenticationException.php',
        'CAS_Client' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Client.php',
        'CAS_CookieJar' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/CookieJar.php',
        'CAS_Exception' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Exception.php',
        'CAS_GracefullTerminationException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/GracefullTerminationException.php',
        'CAS_InvalidArgumentException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/InvalidArgumentException.php',
        'CAS_Languages_Catalan' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/Catalan.php',
        'CAS_Languages_ChineseSimplified' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/ChineseSimplified.php',
        'CAS_Languages_English' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/English.php',
        'CAS_Languages_French' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/French.php',
        'CAS_Languages_Galego' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/Galego.php',
        'CAS_Languages_German' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/German.php',
        'CAS_Languages_Greek' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/Greek.php',
        'CAS_Languages_Japanese' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/Japanese.php',
        'CAS_Languages_LanguageInterface' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/LanguageInterface.php',
        'CAS_Languages_Portuguese' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/Portuguese.php',
        'CAS_Languages_Spanish' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Languages/Spanish.php',
        'CAS_OutOfSequenceBeforeAuthenticationCallException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/OutOfSequenceBeforeAuthenticationCallException.php',
        'CAS_OutOfSequenceBeforeClientException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/OutOfSequenceBeforeClientException.php',
        'CAS_OutOfSequenceBeforeProxyException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/OutOfSequenceBeforeProxyException.php',
        'CAS_OutOfSequenceException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/OutOfSequenceException.php',
        'CAS_PGTStorage_AbstractStorage' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/PGTStorage/AbstractStorage.php',
        'CAS_PGTStorage_Db' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/PGTStorage/Db.php',
        'CAS_PGTStorage_File' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/PGTStorage/File.php',
        'CAS_ProxiedService' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService.php',
        'CAS_ProxiedService_Abstract' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService/Abstract.php',
        'CAS_ProxiedService_Exception' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService/Exception.php',
        'CAS_ProxiedService_Http' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService/Http.php',
        'CAS_ProxiedService_Http_Abstract' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService/Http/Abstract.php',
        'CAS_ProxiedService_Http_Get' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService/Http/Get.php',
        'CAS_ProxiedService_Http_Post' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService/Http/Post.php',
        'CAS_ProxiedService_Imap' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService/Imap.php',
        'CAS_ProxiedService_Testable' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxiedService/Testable.php',
        'CAS_ProxyChain' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxyChain.php',
        'CAS_ProxyChain_AllowedList' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxyChain/AllowedList.php',
        'CAS_ProxyChain_Any' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxyChain/Any.php',
        'CAS_ProxyChain_Interface' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxyChain/Interface.php',
        'CAS_ProxyChain_Trusted' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxyChain/Trusted.php',
        'CAS_ProxyTicketException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ProxyTicketException.php',
        'CAS_Request_AbstractRequest' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Request/AbstractRequest.php',
        'CAS_Request_CurlMultiRequest' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Request/CurlMultiRequest.php',
        'CAS_Request_CurlRequest' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Request/CurlRequest.php',
        'CAS_Request_Exception' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Request/Exception.php',
        'CAS_Request_MultiRequestInterface' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Request/MultiRequestInterface.php',
        'CAS_Request_RequestInterface' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Request/RequestInterface.php',
        'CAS_ServiceBaseUrl_AllowedListDiscovery' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ServiceBaseUrl/AllowedListDiscovery.php',
        'CAS_ServiceBaseUrl_Base' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ServiceBaseUrl/Base.php',
        'CAS_ServiceBaseUrl_Interface' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ServiceBaseUrl/Interface.php',
        'CAS_ServiceBaseUrl_Static' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/ServiceBaseUrl/Static.php',
        'CAS_Session_PhpSession' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/Session/PhpSession.php',
        'CAS_TypeMismatchException' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS/TypeMismatchException.php',
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
        'Google_AccessToken_Revoke' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_AccessToken_Verify' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_AuthHandler_AuthHandlerFactory' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_AuthHandler_Guzzle5AuthHandler' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_AuthHandler_Guzzle6AuthHandler' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_AuthHandler_Guzzle7AuthHandler' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Client' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Collection' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Exception' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Http_Batch' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Http_MediaFileUpload' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Http_REST' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Model' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Service' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Service_Exception' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Service_Resource' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Task_Composer' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Task_Exception' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Task_Retryable' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Task_Runner' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'Google_Utils_UriTemplate' => __DIR__ . '/..' . '/google/apiclient/src/aliases.php',
        'phpCAS' => __DIR__ . '/..' . '/apereo/phpcas/source/CAS.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit3afe4a77f11b1a9be67c8c9e1abad910::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit3afe4a77f11b1a9be67c8c9e1abad910::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit3afe4a77f11b1a9be67c8c9e1abad910::$classMap;

        }, null, ClassLoader::class);
    }
}
