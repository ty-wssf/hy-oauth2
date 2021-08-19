package com.hy.oauth2.server.service.impl;

import cn.hutool.db.Db;
import com.hy.oauth2.server.entity.TbPermission;
import com.hy.oauth2.server.entity.TbUser;
import com.hy.oauth2.server.service.TbPermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

@Service
public class TbPermissionServiceImpl implements TbPermissionService {

    @Autowired
    private DataSource dataSource;

    @Override
    public List<TbPermission> selectByUserId(Long userId) {
        String sql = "SELECT p.*" +
                " FROM" +
                "  tb_user AS u" +
                "  LEFT JOIN tb_user_role AS ur" +
                "    ON u.id = ur.user_id" +
                "  LEFT JOIN tb_role AS r" +
                "    ON r.id = ur.role_id" +
                "  LEFT JOIN tb_role_permission AS rp" +
                "    ON r.id = rp.role_id" +
                "  LEFT JOIN tb_permission AS p" +
                "    ON p.id = rp.permission_id" +
                " WHERE u.id = ?";
        try {
            return Db.use(dataSource).query(sql, TbPermission.class, userId);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

}
