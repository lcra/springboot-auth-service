package com.luke.auth.service;

import com.luke.auth.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class JwtService {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
    
    @Value("${app.jwt.private-key}")
    private Resource privateKeyResource;
    
    @Value("${app.jwt.public-key}")
    private Resource publicKeyResource;
    
    @Value("${app.jwt.access-token-expiration}")
    private long accessTokenExpiration;
    
    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;
    
    @Value("${app.jwt.issuer}")
    private String issuer;
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    @PostConstruct
    private void initKeys() {
        try {
            this.privateKey = loadPrivateKey();
            this.publicKey = loadPublicKey();
            logger.info("JWT keys loaded successfully");
        } catch (Exception e) {
            logger.error("Failed to load JWT keys", e);
            throw new RuntimeException("Failed to initialize JWT keys", e);
        }
    }
    
    private PrivateKey loadPrivateKey() throws Exception {
        try {
            String privateKeyPem = new String(privateKeyResource.getInputStream().readAllBytes())
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            
            byte[] decoded = Base64.getDecoder().decode(privateKeyPem);
            
            // Try PKCS8 format first
            try {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePrivate(keySpec);
            } catch (Exception e) {
                // If PKCS8 fails, the key might be in PKCS1 format
                // For now, we'll convert it using BouncyCastle or assume PKCS8
                throw new RuntimeException("Private key must be in PKCS8 format. Use: openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in jwt-private.pem -out jwt-private-pkcs8.pem");
            }
        } catch (Exception e) {
            logger.error("Failed to load private key: {}", e.getMessage());
            throw e;
        }
    }
    
    private PublicKey loadPublicKey() throws Exception {
        String publicKeyPem = new String(publicKeyResource.getInputStream().readAllBytes())
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        
        byte[] decoded = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    
    public String generateAccessToken(User user) {
        return generateToken(user, accessTokenExpiration, "access");
    }
    
    public String generateRefreshToken(User user) {
        return generateToken(user, refreshTokenExpiration, "refresh");
    }
    
    private String generateToken(User user, long expiration, String tokenType) {
        Instant now = Instant.now();
        Instant expiryDate = now.plusMillis(expiration);
        
        String roles = user.getRoles().stream()
            .map(role -> role.getName())
            .collect(Collectors.joining(","));
        
        String permissions = user.getRoles().stream()
            .flatMap(role -> role.getPermissions().stream())
            .map(permission -> permission.getName())
            .distinct()
            .collect(Collectors.joining(","));
        
        return Jwts.builder()
            .setSubject(user.getEmail())
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiryDate))
            .setIssuer(issuer)
            .setId(UUID.randomUUID().toString())
            .claim("userId", user.getId())
            .claim("firstName", user.getFirstName())
            .claim("lastName", user.getLastName())
            .claim("roles", roles)
            .claim("permissions", permissions)
            .claim("tokenType", tokenType)
            .claim("active", user.getIsActive())
            .claim("emailVerified", user.getEmailVerified())
            .signWith(privateKey, SignatureAlgorithm.RS256)
            .compact();
    }
    
    public Claims extractClaims(String token) {
        try {
            return Jwts.parser()
                .setSigningKey(publicKey)
                .requireIssuer(issuer)
                .parseClaimsJws(token)
                .getBody();
        } catch (ExpiredJwtException e) {
            logger.debug("JWT token expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            logger.error("Malformed JWT token: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            logger.error("JWT token compact of handler are invalid: {}", e.getMessage());
            throw e;
        }
    }
    
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }
    
    public String extractJti(String token) {
        return extractClaims(token).getId();
    }
    
    public Long extractUserId(String token) {
        Claims claims = extractClaims(token);
        return claims.get("userId", Long.class);
    }
    
    public String extractTokenType(String token) {
        Claims claims = extractClaims(token);
        return claims.get("tokenType", String.class);
    }
    
    public Date extractExpiration(String token) {
        return extractClaims(token).getExpiration();
    }
    
    public LocalDateTime extractExpirationAsLocalDateTime(String token) {
        Date expiration = extractExpiration(token);
        return expiration.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
    }
    
    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }
    
    public boolean isValidToken(String token) {
        try {
            extractClaims(token);
            return !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("Invalid token: {}", e.getMessage());
            return false;
        }
    }
    
    public boolean isAccessToken(String token) {
        try {
            return "access".equals(extractTokenType(token));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    
    public boolean isRefreshToken(String token) {
        try {
            return "refresh".equals(extractTokenType(token));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    
    public Map<String, Object> getTokenInfo(String token) {
        Claims claims = extractClaims(token);
        return Map.of(
            "jti", claims.getId(),
            "subject", claims.getSubject(),
            "userId", claims.get("userId", Long.class),
            "tokenType", claims.get("tokenType", String.class),
            "roles", claims.get("roles", String.class),
            "permissions", claims.get("permissions", String.class),
            "issuedAt", claims.getIssuedAt(),
            "expiresAt", claims.getExpiration(),
            "issuer", claims.getIssuer()
        );
    }
}