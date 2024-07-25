package com.anuj.auth;

import com.anuj.auth.utils.AuthPrincipal;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private final String jwksUrl;

    public JWTAuthorizationFilter(String jwksUrl) {
        this.jwksUrl = jwksUrl;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String token = request.getHeader("token");
        if(token != null) {
            DecodedJWT jwt = getDecodedJWT(token, request);
            UsernamePasswordAuthenticationToken authentication = getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }

    private DecodedJWT getDecodedJWT(String token, HttpServletRequest request) throws IOException {
        try {
            JsonObject jwks = CognitoJWKSProvider.getJwks(jwksUrl);
            DecodedJWT decodedJWT = JWT.decode(token);
            String kid = decodedJWT.getKeyId();

            JsonArray keys = jwks.getAsJsonArray("keys");
            JsonObject key = null;
            for (int i = 0; i < keys.size(); i++) {
                if (keys.get(i).getAsJsonObject().get("kid").getAsString().equals(kid)) {
                    key = keys.get(i).getAsJsonObject();
                    break;
                }
            }

            if (key == null) {
                throw new JWTVerificationException("Key ID not found in JWKS");
            }

            RSAPublicKey publicKey = getRSAPublicKey(key);
            Algorithm algorithm = Algorithm.RSA256(new RSAKeyProvider() {
                @Override
                public RSAPublicKey getPublicKeyById(String keyId) {
                    return publicKey;
                }

                @Override
                public RSAPrivateKey getPrivateKey() {
                    return null;
                }

                public RSAPublicKey getPublicKey() {
                    return publicKey;
                }

                @Override
                public String getPrivateKeyId() {
                    return null;
                }
            });

            return JWT.require(algorithm).build().verify(token);
        }
        catch (Exception e) {
            request.setAttribute("exception", e);
        }
        return null;
    }

    private RSAPublicKey getRSAPublicKey(JsonObject key) throws IOException {
        try {
            byte[] nBytes = Base64.getUrlDecoder().decode(key.get("n").getAsString());
            byte[] eBytes = Base64.getUrlDecoder().decode(key.get("e").getAsString());
            BigInteger modulus = new BigInteger(1, nBytes);
            BigInteger exponent = new BigInteger(1, eBytes);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (Exception e) {
            throw new IOException("Failed to create RSA public key", e);
        }
    }

    private UsernamePasswordAuthenticationToken getAuthentication(DecodedJWT jwt) {
        Map<String, Claim> user = jwt.getClaims();
        if (user != null) {
            AuthPrincipal authPrincipal = buildCurrentUserAuthPrincipal(user);
            return new UsernamePasswordAuthenticationToken(authPrincipal, jwt, new ArrayList<>());
        }
        return null;
    }

    private AuthPrincipal buildCurrentUserAuthPrincipal(Map<String, Claim> claims) {
        return AuthPrincipal.builder()
                .sub(claims.get("sub").asString())
                .tenantName(claims.get("custom:tenant_name").asString())
                .groups(claims.get("cognito:groups").asString())
                .emailVerified(claims.get("email_verified").asBoolean())
                .issuer(claims.get("iss").asString())
                .username(claims.get("cognito:username").asString())
                .originJti(claims.get("origin_jti").asString())
                .audience(claims.get("aud").asString())
                .eventId(claims.get("event_id").asString())
                .tokenUse(claims.get("token_use").asString())
                .authTime(claims.get("auth_time").asLong())
                .exp(claims.get("exp").asLong())
                .iat(claims.get("iat").asLong())
                .jti(claims.get("jti").asString())
                .email(claims.get("email").asString())
                .build();
    }
}