package com.example.access_management.role.entity;

import com.example.access_management.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import java.util.HashSet;
import java.util.Set;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
@Entity @Table(name = "roles")
public class Role extends BaseEntity {
  @Column(unique = true, nullable = false)
  private String name;

  private String description;

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "role_permissions",
      joinColumns = @JoinColumn(name = "role_id"),
      inverseJoinColumns = @JoinColumn(name = "permission_id"))
  @Builder.Default
  private Set<Permission> permissions = new HashSet<>();
}
