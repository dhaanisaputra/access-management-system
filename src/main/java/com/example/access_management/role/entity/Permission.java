package com.example.access_management.role.entity;

import com.example.access_management.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
@Entity @Table(name = "permissions")
public class Permission extends BaseEntity {
  @Column(unique = true, nullable = false)
  private String name;

  private String description;
}
