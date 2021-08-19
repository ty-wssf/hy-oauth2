package com.hy.oauth2.server.entity;

import java.io.Serializable;

/**
 * 角色权限表(TbRolePermission)实体类
 *
 * @author wyl
 * @since 2021-08-19 20:59:15
 */
public class TbRolePermission implements Serializable {
    private static final long serialVersionUID = -98961903891534158L;

    private Long id;
    /**
     * 角色 ID
     */
    private Long roleId;
    /**
     * 权限 ID
     */
    private Long permissionId;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getRoleId() {
        return roleId;
    }

    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }

    public Long getPermissionId() {
        return permissionId;
    }

    public void setPermissionId(Long permissionId) {
        this.permissionId = permissionId;
    }

}
