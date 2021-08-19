package com.hy.oauth2.server.service.impl;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.db.Db;
import com.hy.oauth2.server.entity.TbUser;
import com.hy.oauth2.server.service.TbUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.List;

@Service
public class TbUserServiceImpl implements TbUserService {

    @Autowired
    private DataSource dataSource;

    @Override
    public TbUser getByUsername(String username) {
        try {
            List<TbUser> list = Db.use(dataSource).query("select * from tb_user where username = ?", TbUser.class, username);
            if (CollUtil.isNotEmpty(list)) {
                return list.get(0);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

}
