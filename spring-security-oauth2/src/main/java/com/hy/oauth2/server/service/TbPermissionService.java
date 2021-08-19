package com.hy.oauth2.server.service;

import com.hy.oauth2.server.entity.TbPermission;

import java.util.List;

public interface TbPermissionService {


    /**
     * 获取用户权限
     *
     * @param userId
     * @return
     */
    List<TbPermission> selectByUserId(Long userId);

}
