package com.hy.oauth2.server.entity;

import java.io.Serializable;

/**
 * 用户角色表(TbUserRole)实体类
 *
 * @author wyl
 * @since 2021-08-19 20:59:15
 */
public class TbUserRole implements Serializable {
    private static final long serialVersionUID = 670628142778104201L;

    private Long id;
    /**
     * 用户 ID
     */
    private Long userId;
    /**
     * 角色 ID
     */
    private Long roleId;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Long getRoleId() {
        return roleId;
    }

    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }

}
