package com.hy.oauth2.server.service;

import com.hy.oauth2.server.entity.TbUser;

/**
 * 通过数据库查询用户信息,提供相关用户信息后，认证工作由框架自行完成
 */
public interface TbUserService {

    TbUser getByUsername(String username);

}
