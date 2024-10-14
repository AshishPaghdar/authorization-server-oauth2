package com.inexture.sso.entity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;


@Entity
@Table(name = "app_user")
@Getter
@Setter
public class User {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  @Column(name = "id", updatable = false, nullable = false)
  private UUID id;
 

  @ManyToMany(cascade = {CascadeType.PERSIST,CascadeType.MERGE}, fetch = FetchType.EAGER)
  @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
  private List<Role> roles = new ArrayList<>();

  @Column(nullable = false, unique = true,name = "USERNAME")
  private String username;

  @Column(name = "PASSWORD") private String password;
  @Column(name = "FIRSTNAME") private String firstName;
  @Column(name = "MIDDLENAME") private String middleName;
  @Column(name = "LASTNAME") private String lastName;
  @Column(name = "locale") private String locale;
  @Column(name = "avatarUrl") private String avatarUrl;
  @Column(name = "ACTIVE") private boolean active;

  @CreationTimestamp
  protected LocalDateTime createdAt;
}