<?php

namespace PluboJWT;

use Exception;
use RuntimeException;

class InvalidTokenException extends Exception {}
class ExpiredTokenException extends Exception {}
class InvalidSignatureException extends Exception {}
class InvalidArgumentException extends Exception {}

/**
 * @author Albert Tarrés - Sirvelia
 */
class JWT
{
    private static $RSA_KEYS_STORE_PREFIX   = '';
    private static $BLACKLIST_PREFIX        = '';
    private static $DAY_IN_SECONDS          = 3600 * 24;
    private static $SUPPORTED_ALGORITHMS    = [
        'HS256' => [ 'hash' => 'sha256', 'type' => 'hmac' ],
        'HS384' => [ 'hash' => 'sha384', 'type' => 'hmac' ],
        'HS512' => [ 'hash' => 'sha512', 'type' => 'hmac' ],
        'RS256' => [ 'hash' => 'sha256', 'type' => 'rsa' ],
        'RS384' => [ 'hash' => 'sha384', 'type' => 'rsa' ],
        'RS512' => [ 'hash' => 'sha512', 'type' => 'rsa' ]
    ];

    /**
     * Separates into an array the different parts of a given JWT token
     * 
     * @param string $token         The token to explode.
     * 
     * @return array                The separated parts of the given token.
     */
    private static function explodeToken( $token )
    {
        $jwt_parts  = explode( '.', $token );
        if ( count( $jwt_parts ) < 3 ) throw new InvalidTokenException( "Invalid token structure." );

        return $jwt_parts;
    }

    /**
     * Encrypts the given payload using OpenSSL with AES-256-CBC.
     * 
     * @param string    $payload    Data to encrypt.
     * @param string    $secret     Secret used for the encryption.
     * 
     * @return string               The encoded payload.
     */
    private static function encryptPayload( $payload, $secret )
    {
        $initialization_vector  = random_bytes( 16 );
        $encrypted_payload      = openssl_encrypt( $payload, 'aes-256-cbc', $secret, 0, $initialization_vector );

        return base64_encode( $initialization_vector . $encrypted_payload );
    }

    /**
     * Decrypts the given payload
     * 
     * @param string    $payload    The encrypted payload
     * @param string    $key        Secret or key used to decrypt the payload content
     * 
     * @return string               The decoded payload string
     */
    private static function decryptPayload( $payload, $key )
    {
        $payload                = base64_decode( $payload );
        $initialization_vector  = substr( $payload, 0, 16 );
        $encrypted_data         = substr( $payload, 16 );

        if ( openssl_pkey_get_public( $key ) !== false ) {
            $decrypted          = null;
            openssl_public_decrypt( $encrypted_data, $decrypted, $key );
        }
        else {
            $decrypted          = openssl_decrypt( $encrypted_data, 'aes-256-cbc', $key, 0, $initialization_vector );
        }

        if ( $decrypted === false ) {
            throw new InvalidTokenException( "Decryption Failed." );
        }

        return $decrypted;
    }

    /**
     * Generates an **INSECURE** default key based on the algorithm type.
     * 
     * Not recommended.
     * 
     * @param string    $algorithm          The algorithm to generate a key for.
     * @param bool      $get_private_key    Whether to get the private key (`true`) or public key (`false`) for RSA.
     * 
     * @return string                       The generated secret.
     */
    private static function generateDefaultKey( $algorithm, $get_private_key = true )
    {
        if ( !isset( self::$SUPPORTED_ALGORITHMS[ $algorithm ] ) ) {
            throw new InvalidArgumentException( "Unsupported algorithm: $algorithm" );
        }

        $alg_type = self::$SUPPORTED_ALGORITHMS[ $algorithm ]['type'];

        if ( $alg_type === 'hmac' ) {
            return self::generateDefaultSecret();
        }
        
        if ( $alg_type === 'rsa' ) {
            return self::generateDefaultRSAKey( $algorithm, $get_private_key );
        }

        throw new InvalidArgumentException( "Unsupported algorithm type." );
    }

    /**
     * Generates an **INSECURE** default secret for HMAC algorithms.
     * 
     * Not recommended for production use.
     * 
     * @return string The generated secret.
     */
    private static function generateDefaultSecret()
    {
        return hash( 'sha256', self::getSystemSeed() );
    }

    /**
     * Generates an **INSECURE** default RSA key pair.
     * 
     * Not recommended for production use.
     * 
     * @param string    $algorithm          The RSA algorithm to use.
     * @param bool      $get_private_key    Whether to get the private key (`true`) or public key (`false`).
     * 
     * @return resource                     The generated private key resource.
     */
    private static function generateDefaultRSAKey( $algorithm, $get_private_key = true )
    {
        if ( is_callable( 'get_option' ) ) {
            $stored_key_pairs = get_option( self::$RSA_KEYS_STORE_PREFIX . 'jwt_default_rsa_keys', false );
        }
        else {
            $stored_key_pairs = false;
        }

        if ( $stored_key_pairs ) {
            $stored_key_pairs = json_decode( $stored_key_pairs );

            if ( $get_private_key ) {
                return $stored_key_pairs->private_key;
            }

            return $stored_key_pairs->public_key;
        }

        $config = [
            'digest_alg'        => self::$SUPPORTED_ALGORITHMS[ $algorithm ]['hash'],
            'private_key_bits'  => 2048,
            'private_key_type'  => OPENSSL_KEYTYPE_RSA
        ];

        $result = openssl_pkey_new( $config );
        if ( $result === false ) {
            throw new RuntimeException( "Failed to generate RSA key pair." );
        }
        
        $private_key = null;
        openssl_pkey_export( $result, $private_key );
        $public_key = openssl_pkey_get_details( $result )['key'];

        if ( is_callable( 'update_option' ) ) {
            update_option( self::$RSA_KEYS_STORE_PREFIX . 'jwt_default_rsa_keys', json_encode( [
                'private_key'   => $private_key,
                'public_key'    => $public_key
            ] ) );
        }

        if ( $get_private_key ) {
            return $private_key;
        }

        return $public_key;
    }

    /**
     * Generates a seed based on system information.
     * 
     * @return string The generated seed
     */
    private static function getSystemSeed()
    {
        $system_info    = php_uname();
        $server_ip      = filter_var( $_SERVER['SERVER_ADDR'] ?? '127.0.0.1', FILTER_VALIDATE_IP ) ?: '127.0.0.1';
        $file_time      = filemtime( dirname( __FILE__ ) );
        return $system_info . $server_ip . $file_time;
    }

    /**
     * Creates a new JWT token.
     * 
     * @param array                 $payload            Data to encode into the JWT payload.
     * @param string|resource|null  $key                Secret key or private key for signing the token. If not provided, a default will be used.
     * @param string|false|null     $expiration         Custom expiration time in seconds. Defaults to 2 days if not set.
     * @param string                $algorithm          The algorithm used for the signature. Defaults to `HS256`.
     * @param bool                  $encrypt_payload    If `true`, the payload will be encrypted using AES-256-CBC. Defaults to false.
     * 
     * @return string                                   The generated token
     */
    public static function new( $payload, $key = null, $expiration = null, $algorithm = 'HS256', $encrypt_payload = false )
    {
        if ( !isset( self::$SUPPORTED_ALGORITHMS[ $algorithm ] ) ) {
            throw new InvalidArgumentException( "Unsupported algorithm: $algorithm" );
        }

        $header = json_encode( [ 'typ' => 'JWT', 'alg' => $algorithm ] );

        $key = $key ?: self::generateDefaultKey( $algorithm );

        $issued_at  = null;
        $not_before = null;
        $issuer     = null;
        $audience   = null;
        
        if ( isset( $payload['iat'] ) && $payload['iat'] ) {
            $issued_at = $payload['iat'];
        }

        if ( isset( $payload['nbf'] ) && $payload['nbf'] ) {
            $not_before = $payload['nbf'];
        }

        if ( isset( $payload['iss'] ) && $payload['iss'] ) {
            $issuer = $payload['iss'];
            unset( $payload['iss'] );
        }

        if ( isset( $payload['aud'] ) && $payload['aud'] ) {
            $audience = $payload['aud'];
            unset( $payload['aud'] );
        }

        if ( $encrypt_payload ) {
            $encrypted_data = self::encryptPayload( json_encode( $payload ), $key );
            $claims = [
                'exp'               => $expiration ? strtotime( $expiration ) : time() + ( self::$DAY_IN_SECONDS * 2 ),
                'iat'               => $issued_at ?: time(),
                'nbf'               => $not_before ?: time(),
                'encrypted'         => true,
                'encrypted_data'    => $encrypted_data
            ];
        }
        else {
            $claims = array_merge( [
                'exp'   => $expiration ? strtotime( $expiration ) : time() + ( self::$DAY_IN_SECONDS * 2 ),
                'iat'   => $issued_at ?: time(),
                'nbf'   => $not_before ?: time(),
            ], $payload );
        }

        if ( $issuer ) {
            $claims['iss'] = $issuer;
        }

        if ( $audience ) {
            $claims['aud'] = $audience;
        }

        if ( $expiration === false ) {
            unset( $claims['exp'] );
        }

        $base64_url_header      = self::base64UrlEncode( $header );
        $base64_url_payload     = self::base64UrlEncode( json_encode( $claims ) );

        $signature              = self::sign( "$base64_url_header.$base64_url_payload", $key, $algorithm );
        $base64_url_signature   = self::base64UrlEncode( $signature );

        return "$base64_url_header.$base64_url_payload.$base64_url_signature";
    }

    /**
     * Decodes a JWT Token
     * 
     * @param string        $token      The JWT token to decode.
     * @param bool          $complete   Whether to return the full token with header and signature.
     * @param string|null   $key        The secret or key used for signing the token. It is only used if the payload has been encrypted.
     * @param string        $algorithm  The algorithm used to encode the token.
     * 
     * @return array        Decoded payload or array with header, payload and signature if $complete is true.
     */
    public static function decode( $token, $complete = false, $key = null, $algorithm = 'HS256' )
    {
        $jwt_parts  = self::explodeToken( $token );
        
        $header     = json_decode( base64_decode( $jwt_parts[0] ) );
        $payload    = json_decode( base64_decode( $jwt_parts[1] ) );
        $signature  = $jwt_parts[2];

        $is_rsa     = in_array( $algorithm, [ 'RS256', 'RS284', 'RS512' ] );
        $key        = $key ?: self::generateDefaultKey( $algorithm, !$is_rsa );

        if ( isset( $payload->encrypted ) && $payload->encrypted ) {
            $payload = json_decode( self::decryptPayload( $payload->encrypted_data, $key ) );
        }

        return $complete ? [ $header, $payload, $signature ] : $payload;
    }

    /**
     * Verify the validity of a JWT token.
     * 
     * @param string                $token              The JWT token to verify.
     * @param string|resource|null  key                 Secret key or public key for verifying the token. If not provided, a default will be used.
     * @param string|null           $expected_algorithm If set, the JWT header algorithm will be compared with the given expected algorithm. Defaults to null.
     * @param string|null           $issuer             Issuer to verify. Not checked if is `null` (default).
     * @param string|null           $audience           Audience to verify. Not checked if is `null` (default).
     * @param int                   $leeway             Error margin in seconds. Defaults to `0`.
     * 
     * @return object                                   The decoded payload
     */
    public static function verify($token, $key = null, $expected_algorithm = null, $issuer = null, $audience = null, $leeway = 0)
    {
        $jwt_parts  = self::explodeToken( $token );
        $header     = json_decode( base64_decode( $jwt_parts[0] ) );
        $payload    = json_decode( base64_decode( $jwt_parts[1] ) );
        $signature  = self::base64UrlDecode( $jwt_parts[2] );

        if ( !isset( $header->alg ) || ( $expected_algorithm && $header->alg !== $expected_algorithm ) ) {
            throw new InvalidTokenException( "Algorithm mismatch or missing." );
        }

        $key        = $key ?: self::generateDefaultKey( $header->alg, false );

        // Check signature before decrypting
        $base64_url_header  = $jwt_parts[0];
        $base64_url_payload = $jwt_parts[1];

        if ( !self::verifySignature( "$base64_url_header.$base64_url_payload", $signature, $key, $header->alg ) ) {
            throw new InvalidTokenException( "Invalid token signature." );
        }

        // Decrypt payload if it's encrypted
        if ( isset( $payload->encrypted ) && $payload->encrypted ) {
            $decrypted_payload = json_decode( self::decryptPayload( $payload->encrypted_data, $key ) );
            // Merge decrypted data back into payload
            $payload = (object) array_merge( (array) $payload, (array) $decrypted_payload );
            unset( $payload->encrypted_data );
            unset( $payload->encrypted );
        }

        if ( self::isBlacklisted( $token ) ) {
            throw new InvalidTokenException( "Token has been revoked." );
        }

        $current_time = time();

        // Check claims
        if ( isset( $payload->exp ) && $payload->exp && ( $current_time > ( $payload->exp + $leeway ) ) ) {
            throw new ExpiredTokenException( "Token has expired." );
        }

        if ( isset( $payload->iat ) && $payload->iat && ( $payload->iat > ( $current_time + $leeway ) ) ) {
            throw new InvalidTokenException( "Invalid token issue time." );
        }

        if ( isset( $payload->nbf ) && $payload->nbf && ( $payload->nbf > ( $current_time + $leeway ) ) ) {
            throw new InvalidTokenException( "Token can't be used yet." );
        }

        if ( $issuer !== null && ( !isset( $payload->iss ) || !$payload->iss || $payload->iss !== $issuer ) ) {
            throw new InvalidTokenException( "Invalid token issuer." );
        }

        if ( $audience !== null && ( !isset( $payload->aud ) || !$payload->aud || $payload->aud !== $audience ) ) {
            throw new InvalidTokenException( "Invalid token audience." );
        }

        return $payload;
    }

    /**
     * Verifies the provided JWT token through a given introspection endpoint.
     * 
     * @param string $token     The token to verify.
     * @param string $endpoint  The introspection endpoint which will check the token validity.
     * 
     * @return array            An array containing the body of the endpoint's response.
     */
    public static function verify_from_endpoint( string $token, string $endpoint )
    {
        if ( !$token || !$endpoint ) {
            throw new InvalidArgumentException( "Missing required parameters." );
        }

        if ( is_callable( 'wp_remote_post' ) && is_callable( 'wp_remote_retrieve_response_code' ) && is_callable( 'wp_remote_retrieve_body' ) ) {
            $response = wp_remote_post( $endpoint, [
                'headers' => [ 'Authorization' => "Bearer $token" ]
            ] );

            if ( is_wp_error( $response ) ) {
                throw new InvalidTokenException( "Error validating the JWT." );
            }

            $response_code = wp_remote_retrieve_response_code( $response );
            if ( $response_code !== 200 ) {
                throw new InvalidTokenException( "Invalid response code: $response_code" );
            }

            $body = wp_remote_retrieve_body( $response );
            return json_decode( $body );
        }

        $ch = curl_init( $endpoint );
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt( $ch, CURLOPT_POST, true );
        curl_setopt( $ch, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer $token"
        ] );

        $result         = curl_exec( $ch );
        $http_status    = curl_getinfo( $ch, CURLINFO_HTTP_CODE );

        if ( curl_errno( $ch ) ) {
            throw new InvalidTokenException( "Error validating the JWT." );
        }

        curl_close( $ch );

        if ( $http_status !== 200 ) {
            throw new InvalidTokenException( "Invalid response code: $http_status" );
        }

        return json_decode( $result, true );
    }

    /**
     * Signs the given input using the specified algorithm and key.
     * 
     * @param string            $input      The input to sign.
     * @param string|resource   $key        The key to use for signing.
     * @param string            $algorithm  The algorithm to use.
     * 
     * @return string                       The signature.
     */
    private static function sign( $input, $key, $algorithm )
    {
        if ( !isset( self::$SUPPORTED_ALGORITHMS[ $algorithm ] ) ) {
            throw new InvalidArgumentException( "Unsupported algorithm: $algorithm" );
        }

        $alg_details = self::$SUPPORTED_ALGORITHMS[ $algorithm ];

        if ( $alg_details['type'] === 'hmac' ) {
            return hash_hmac( $alg_details['hash'], $input, $key, true );
        }
        if ( $alg_details['type'] === 'rsa' ) {
            $signature = '';
            openssl_sign( $input, $signature, $key, $alg_details['hash'] );
            return $signature;
        }

        throw new InvalidArgumentException( "Unsupported algorithm type." );
    }

    /**
     * Verifies the signature of the given input.
     * 
     * @param string            $input      The input that was signed.
     * @param string            $signature  The signature to verify.
     * @param string|resource   $key        The key to use for verification.
     * @param string            $algorithm  The algorithm used for signing.
     * 
     * @return bool                         `true` if the signature is valid, `false` otherwise.
     */
    private static function verifySignature( $input, $signature, $key, $algorithm )
    {
        if ( !isset( self::$SUPPORTED_ALGORITHMS[ $algorithm ] ) ) {
            throw new InvalidArgumentException( "Unsupported algorithm: $algorithm" );
        }

        $alg_details = self::$SUPPORTED_ALGORITHMS[ $algorithm ];

        if ( $alg_details['type'] === 'hmac' ) {
            $expected_signature = self::sign( $input, $key, $algorithm );
            return hash_equals( $expected_signature, $signature );
        }
        
        if ( $alg_details['type'] === 'rsa' ) {
            return openssl_verify( $input, $signature, $key, $alg_details['hash'] ) === 1;
        }

        throw new InvalidArgumentException( "Unsupported algorithm type" );
    }

    /**
     * Encodes the given input to Base64Url format.
     * 
     * @param string $input The input to encode.
     * 
     * @return string       The Base64Url encoded string.
     */
    private static function base64UrlEncode( $input )
    {
        return str_replace( [ '+', '/', '=' ], [ '-', '_', '' ], base64_encode( $input ) );
    }

    /**
     * Decodes the given Base64Url encoded string.
     * 
     * @param string $input The Base64Url encoded string to decode.
     * 
     * @return string       The decoded string
     */
    private static function base64UrlDecode( $input )
    {
        $remainder      = strlen( $input ) % 4;

        if ( $remainder ) {
            $pad_len    = 4 - $remainder;
            $input      .= str_repeat( '=', $pad_len );
        }

        return base64_decode( strtr( $input, '-_', '+/' ) );
    }

    /**
     * Blacklists a JWT.
     * 
     * Only Available in WordPress environment.
     * 
     * @param string $token             The token to blacklist.
     * @param string $blacklist_prefix  A prefix to store the blacklist into the database
     */
    public static function blacklist( $token )
    {
        if ( !is_callable( 'update_option' ) || !is_callable( 'get_option' ) ) return;

        $signature          = explode( '.', $token )[ 2 ];
        $blacklisted_tokens = json_decode( get_option( self::$BLACKLIST_PREFIX . 'jwt_blacklist', '[]' ) );
        
        if ( in_array( $signature, $blacklisted_tokens ) ) return;

        $blacklisted_tokens[] = $signature;
        update_option( self::$BLACKLIST_PREFIX . 'jwt_blacklist', json_encode( $blacklisted_tokens ) );
    }

    /**
     * Checks wether a token is blacklisted or not.
     * 
     * Only Available in WordPress environment.
     * 
     * @param string $token             The token to check.
     * @param string $blacklist_prefix  A prefix to store the blacklist into the database
     * 
     * @return bool                     `true` if blacklisted, `false` otherwise.
     */
    private static function isBlacklisted( $token )
    {
        if ( !is_callable( 'update_option' ) || !is_callable( 'get_option' ) ) return false;

        $signature          = explode( '.', $token )[ 2 ];
        $blacklisted_tokens = json_decode( get_option( self::$BLACKLIST_PREFIX . 'jwt_blacklist', '[]' ) );

        return in_array( $signature, $blacklisted_tokens );
    }
}