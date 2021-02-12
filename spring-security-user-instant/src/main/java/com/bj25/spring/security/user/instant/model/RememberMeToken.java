package com.bj25.spring.security.user.instant.model;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@Entity
@Table(name = "remember_me")
public class RememberMeToken {

    @Id
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    @Column(columnDefinition = "BINARY(16)")
    private UUID id;

    @Column(name = "username", length = 64, nullable = false)
    private String username;

    @Column(name = "series", length = 64, unique = true, nullable = false)
    private String series;

    @Column(name = "token", length = 64, nullable = false)
    private String value;

    @Column(name = "last_used", columnDefinition = "DATETIME")
    private LocalDateTime lastUsed;

    @Builder
    public RememberMeToken(String username, String series, String value, LocalDateTime lastUsed) {
        this.username = username;
        this.series = series;
        this.value = value;
        this.lastUsed = lastUsed;
    }

    public RememberMeToken update(String value, LocalDateTime lastUsed) {
        this.value = value;
        this.lastUsed = lastUsed;

        return this;
    }

    public PersistentRememberMeToken asPersistentRememberMeToken() {
        final Date date = Date.from(this.lastUsed.atZone(ZoneId.systemDefault()).toInstant());
        return new PersistentRememberMeToken(this.username, this.series, this.value, date);
    }
}
