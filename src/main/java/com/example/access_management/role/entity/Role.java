package com.example.access_management.role.entity;

import com.example.access_management.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

// ponytail: minimal stub for Task 2 compilation; Task 4 will expand with permissions + builder
@Getter
@Setter
@Entity
@Table(name = "roles")
public class Role extends BaseEntity {
  @Column(unique = true, nullable = false)
  private String name;
  private String description;
}
