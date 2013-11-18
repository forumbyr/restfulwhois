package com.cnnic.whois.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.cnnic.whois.dao.base.BaseDao;
import com.cnnic.whois.execption.ManagementException;
import com.cnnic.whois.util.JdbcUtils;
import com.cnnic.whois.util.WhoisUtil;

public class AccessControlDAO extends BaseDao {
	private static AccessControlDAO accessControlDAO = new AccessControlDAO();

	/**
	 * Get ExColumnDAO objects
	 * 
	 * @return ExColumnDAO objects
	 */
	public static AccessControlDAO getAccessControlDAO() {
		return accessControlDAO;
	}

	/**
	 * List permission information
	 * 
	 * @param tableName
	 * @return map
	 * @throws ManagementException
	 */
	public Map<String, Object> listPermissionCoulumn(String tableName)
			throws ManagementException {
//		TODO : 取得数据库连接
		Connection connection = JdbcUtils.getConnection();
		PreparedStatement stmt = null;
		Map<String, Object> permissionList = new HashMap<String, Object>();
		try {
			stmt = connection.prepareStatement(WhoisUtil.SELECT_COLUMNINFOERMISSION);
			stmt.setString(1, tableName);
			ResultSet results = stmt.executeQuery();
			while (results.next()) {
				String columnName = results.getString(WhoisUtil.COLUMNNAME);
				Map<String, String> userList = new HashMap<String, String>();
				userList.put(WhoisUtil.ANONYMOUS, results.getString(WhoisUtil.ANONYMOUS));
				userList.put(WhoisUtil.AUTHENTICATED, results.getString(WhoisUtil.AUTHENTICATED));
				userList.put(WhoisUtil.ROOT, results.getString(WhoisUtil.ROOT));
				permissionList.put(columnName, userList);
			}
			return permissionList;
		} catch (SQLException e) {
			e.printStackTrace();
			throw new ManagementException(e);
		} finally {
			JdbcUtils.free(null, null, connection);
		}
	}

	/**
	 * Update permission information
	 * 
	 * @param tableName
	 * @param permissionList
	 * @throws ManagementException
	 */
	public void updatePermission(String tableName,
			Map<String, List<String>> permissionList)
			throws ManagementException {
		Set<String> columnkeySet = permissionList.keySet();
//		TODO : 取得数据库连接
		Connection connection = JdbcUtils.getConnection();
		PreparedStatement stmt = null;

		try {
			stmt = connection.prepareStatement(WhoisUtil.UPDATE_PERMISSION);
			for (String key : columnkeySet) {
				List<String> permissionValueList = (List<String>) permissionList
						.get(key);
				stmt.setString(1, permissionValueList.get(0));
				stmt.setString(2, permissionValueList.get(1));
				stmt.setString(3, permissionValueList.get(2));
				stmt.setString(4, tableName);
				stmt.setString(5, key);
				stmt.execute();
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new ManagementException(e);
		} finally {
			JdbcUtils.free(null, null, connection);
		}
	}
}
