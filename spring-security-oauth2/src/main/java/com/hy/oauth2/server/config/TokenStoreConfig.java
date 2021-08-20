package com.hy.oauth2.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.util.Assert;

import javax.sql.DataSource;

/**
 * redis存储token
 *
 * @author wyl
 * @since 2021-08-20 15:45:04
 */
@Configuration
public class TokenStoreConfig {

    @Autowired
    private DataSource dataSource;

    /**
     * 基于内存存储token
     *
     * @return
     */
    @Primary
    @Bean
    @ConditionalOnProperty(prefix = "security.oauth2.token.store", name = "type", havingValue = "inMemory", matchIfMissing = true)
    public TokenStore inMemoryTokenStore() {
        return new InMemoryTokenStore();
    }

    /**
     * 基于数据库存储token
     *
     * @return
     */
    @Bean
    @ConditionalOnProperty(prefix = "security.oauth2.token.store", name = "type", havingValue = "jdbc", matchIfMissing = false)
    public TokenStore jdbcTokenStore() {
//		oauth_access_token oauth_refresh_token 创建两张表
//		return new JdbcTokenStore( dataSource ) ;
        return new JdbcTokenStore(dataSource);
    }

    @Bean
    @ConditionalOnProperty(prefix = "security.oauth2.token.store", name = "type", havingValue = "redis", matchIfMissing = false)
    public TokenStore redisTokenStore(RedisConnectionFactory connectionFactory) {
        Assert.state(connectionFactory != null, "connectionFactory must be provided");
        return new RedisTokenStore(connectionFactory);
    }

    /**
     * {
     * "exp": 1629494755,
     * "user_name": "admin",
     * "authorities": [
     * "SystemContentDelete",
     * "SystemUserView",
     * "SystemUser",
     * "SystemUserInsert",
     * "SystemUserDelete",
     * "SystemUserUpdate",
     * "SystemContentInsert",
     * "SystemContentUpdate",
     * "SystemContentView",
     * "System",
     * "SystemContent"
     * ],
     * "jti": "6291f374-d694-4f9c-87b8-af1eaf195ec3",
     * "client_id": "client",
     * "scope": [
     * "app"
     * ]
     * }
     */
    //使用jwt替换原有的uuid生成token方式
    @Configuration
    @ConditionalOnProperty(prefix = "security.oauth2.token.store", name = "type", havingValue = "jwt", matchIfMissing = false)
    public static class JWTTokenConfig {
        @Bean
        public JwtTokenStore jwtTokenStore() {
            return new JwtTokenStore(jwtAccessTokenConverter());
        }

        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            //new ResJwtAccessTokenConverter();  可以自定义转化器
            JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();

            accessTokenConverter.setSigningKey("hy-oauth2");//对称加密key
            return accessTokenConverter;
        }
    }

}
