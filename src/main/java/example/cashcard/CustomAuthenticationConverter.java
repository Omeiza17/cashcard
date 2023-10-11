package example.cashcard;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Value("${spring.security.oauth2.resourceserver.jwt.auth.converter.principal-attributes}")
    private String principalAttributes;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt source) {
        return new JwtAuthenticationToken(source, null, extractUsername(source));
    }

    private String extractUsername(Jwt source) {
        return source.getClaim(principalAttributes);
    }
}
