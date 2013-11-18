package com.cnnic.whois.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.cnnic.whois.execption.ManagementException;
import com.cnnic.whois.util.JdbcUtils;
import com.cnnic.whois.util.WhoisUtil;

public class ExColumnDAO {
	private static ExColumnDAO columnDAO = new ExColumnDAO();

	/**
	 * Get ExColumnDAO objects
	 * 
	 * @return ExColumnDAO objects
	 */
	public static ExColumnDAO getColumnDAO() {
		return columnDAO;
	}

	/**
	 * Add the extension field
	 * 
	 * @param tableName
	 * @param columnMap
	 * @throws ManagementException
	 */
	public void addCoulumn(String tableName, Map<String, String> columnMap)
			throws ManagementException {
//		TODO : 取得数据库连接
		Connection connection = JdbcUtils.getConnection();
		PreparedStatement stmt = null;

		try {
			String sql = "";
			Set<String> keys = columnMap.keySet();

			String isNullsql = WhoisUtil.SELECT_PERMISSION_ISNULL;
			stmt = connection.prepareStatement(isNullsql);
			for (String key : keys) {

				stmt.setString(1, tableName);
				stmt.setString(2, key.substring("$x$".length()));
				ResultSet results = stmt.executeQuery();

				stmt = connection.prepareStatement(isNullsql);
				stmt.setString(1, tableName);
				stmt.setString(2, key);
				ResultSet resultextends = stmt.executeQuery();

				if (results.next() || resultextends.next()) {
					throw new ManagementException(
							"Already exists in the field ");
				}

			}

			for (String key : keys) {
				sql = WhoisUtil.ADDCOLUMN1 + tableName + WhoisUtil.ADDCOLUMN2
						+ key + WhoisUtil.ADDCOLUMN3 + columnMap.get(key)
						+ WhoisUtil.ADDCOLUMN4;
				stmt = connection.prepareStatement(sql);
				stmt.execute();

				sql = WhoisUtil.ADDCOLUMNNAMEPERMISSION1 + WhoisUtil.POINT
						+ tableName + WhoisUtil.ADDCOLUMNNAMEPERMISSION2
						+ WhoisUtil.POINT + key + "','" + columnMap.get(key)
						+ WhoisUtil.POINT + WhoisUtil.ADDCOLUMNNAMEPERMISSION3;
				stmt = connection.prepareStatement(sql);
				stmt.execute();
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new ManagementException(e);
		} finally {
			JdbcUtils.free(null, null, connection);
		}
	}

	/**
	 * List extension field
	 * 
	 * @param tableName
	 * @return map collection
	 * @throws ManagementException
	 */
	public Map<String, String> listCoulumn(String tableName)
			throws ManagementException {
//		TODO : 取得数据库连接
		Connection connection = JdbcUtils.getConnection();
		PreparedStatement stmt = null;
		Map<String, String> columnInfoList = new HashMap<String, String>();

		try {
			stmt = connection.prepareStatement(WhoisUtil.LIST_COLUMNINFO);
			stmt.setString(1, tableName);
			ResultSet results = stmt.executeQuery();
			while (results.next()) {
				String columnName = results.getString("columnName").substring(
						WhoisUtil.EXTENDPRX.length());
				columnInfoList.put(columnName,
						results.getString("columnLength"));
			}
			return columnInfoList;
		} catch (SQLException e) {
			e.printStackTrace();
			throw new ManagementException(e);
		} finally {
			JdbcUtils.free(null, null, connection);
		}
	}

	/**
	 * Update extension field
	 * 
	 * @param tableName
	 * @param oldColumnName
	 * @param newCloumnName
	 * @param columnLength
	 * @throws ManagementException
	 */
	public void updateCoulumn(String tableName, String oldColumnName,
			String newCloumnName, String columnLength)
			throws ManagementException {
//		TODO : 取得数据库连接
		Connection connection = JdbcUtils.getConnection();
		PreparedStatement stmt = null;

		try {
			String isNullsql = WhoisUtil.SELECT_PERMISSION_ISNULL;
			stmt = connection.prepareStatement(isNullsql);
			stmt.setString(1, tableName);
			stmt.setString(2, newCloumnName);
			ResultSet results = stmt.executeQuery();
			if (results.next()) {
				throw new ManagementException("Already exists in the field ");
			}

			oldColumnName = WhoisUtil.EXTENDPRX + oldColumnName;
			newCloumnName = WhoisUtil.EXTENDPRX + newCloumnName;

			stmt = connection.prepareStatement(isNullsql);
			stmt.setString(1, tableName);
			stmt.setString(2, newCloumnName);
			ResultSet resultsIsNull = stmt.executeQuery();
			if (resultsIsNull.next()) { //If the update is already in the database will throw this exception
				if (!resultsIsNull.getString("columnName")
						.equals(oldColumnName))
					throw new ManagementException(
							"Already exists in the field ");
			}

			String sql = WhoisUtil.UPDATE_COLUMNINFO1 + tableName
					+ WhoisUtil.UPDATE_COLUMNINFO2 + oldColumnName + " "
					+ newCloumnName + WhoisUtil.ADDCOLUMN3 + columnLength
					+ WhoisUtil.ADDCOLUMN4;
			stmt = connection.prepareStatement(sql);
			stmt.execute();

			stmt = connection
					.prepareStatement(WhoisUtil.UPDATE_COLUMNINFOERMISSION);
			stmt.setString(1, newCloumnName);
			stmt.setString(2, columnLength);
			stmt.setString(3, tableName);
			stmt.setString(4, oldColumnName);
			stmt.execute();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new ManagementException(e);
		} finally {
			JdbcUtils.free(null, null, connection);
		}
	}

	/**
	 * Delete extension field
	 * 
	 * @param tableName
	 * @param columnName
	 * @throws ManagementException
	 */
	public void deleteCoulumn(String tableName, String columnName)
			throws ManagementException {
//		TODO : 取得数据库连接
		Connection connection = JdbcUtils.getConnection();
		PreparedStatement stmt = null;
		columnName = WhoisUtil.EXTENDPRX + columnName;

		try {
			String sql = WhoisUtil.DELETE_COLUMNINFO1 + tableName
					+ WhoisUtil.DELETE_COLUMNINFO2 + columnName;
			stmt = connection.prepareStatement(sql);
			stmt.execute();

			sql = WhoisUtil.DELETE_COLUMNINFOERMISSION1 + columnName
					+ WhoisUtil.DELETE_COLUMNINFOERMISSION2 + tableName + "'";
			stmt = connection.prepareStatement(sql);
			stmt.execute();
		} catch (SQLException e) {
			e.printStackTrace();
			throw new ManagementException(e);
		} finally {
			JdbcUtils.free(null, null, connection);
		}
	}

}
