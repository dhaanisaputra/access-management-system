package com.example.access_management.role.entity;

import com.example.access_management.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
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

  // Behavior
  public void addPermission(Permission permission) {
    this.permissions.add(permission);
  }

  public void removePermission(Permission permission) {
    this.permissions.remove(permission);
  }

  public boolean hasPermission(String permissionName) {
    return permissions.stream().anyMatch(p -> p.getName().equals(permissionName));
  }
}
