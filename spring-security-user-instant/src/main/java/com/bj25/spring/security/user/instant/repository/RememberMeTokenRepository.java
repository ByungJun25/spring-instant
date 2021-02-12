package com.bj25.spring.security.user.instant.repository;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.bj25.spring.security.user.instant.model.RememberMeToken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface RememberMeTokenRepository extends JpaRepository<RememberMeToken, UUID>, PersistentTokenRepository {

    Optional<RememberMeToken> findBySeries(String series);

    List<RememberMeToken> removeByUsername(String username);

    default void createNewToken(PersistentRememberMeToken token) {
        RememberMeToken entity = RememberMeToken.builder()
                .lastUsed(LocalDateTime.ofInstant(token.getDate().toInstant(), ZoneId.systemDefault()))
                .series(token.getSeries()).value(token.getTokenValue()).username(token.getUsername()).build();
        this.save(entity);
    }

    default void updateToken(String series, String tokenValue, Date lastUsed) {
        RememberMeToken token = this.findBySeries(series)
                .map(t -> t.update(tokenValue, LocalDateTime.ofInstant(lastUsed.toInstant(), ZoneId.systemDefault())))
                .orElse(null);

        if (token != null) {
            this.save(token);
        }
    }

    default PersistentRememberMeToken getTokenForSeries(String seriesId) {
        return this.findBySeries(seriesId).map(t -> t.asPersistentRememberMeToken()).orElse(null);
    }

    @Transactional
    default void removeUserTokens(String username) {
        this.removeByUsername(username);
    }
}
