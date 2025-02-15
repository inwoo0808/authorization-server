package org.oauth.oauth2.repository;

import org.oauth.oauth2.entity.RegisterEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface RegisterRepository extends JpaRepository<RegisterEntity, String> {
    Optional<RegisterEntity> findByClientId(String clientId);
}
