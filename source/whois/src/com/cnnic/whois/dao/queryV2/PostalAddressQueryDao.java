package com.cnnic.whois.dao.queryV2;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import com.cnnic.whois.bean.PageBean;
import com.cnnic.whois.bean.QueryJoinType;
import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.util.WhoisUtil;

public class PostalAddressQueryDao extends AbstractDbQueryDao {
	public PostalAddressQueryDao(List<AbstractDbQueryDao> dbQueryDaos) {
		super(dbQueryDaos);
	}

	/**
	 * Connect to the database query postalAddress information
	 * 
	 * @param queryInfo
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryPostalAddress(String queryInfo,
			String role, String format) throws QueryException {
		Connection connection = null;
		Map<String, Object> map = null;

		try {
			connection = ds.getConnection();
			String selectSql = WhoisUtil.SELECT_LIST_POSTALADDRESS + "'"
					+ queryInfo + "'";
			map = query(connection, selectSql,
					permissionCache.getPostalAddressKeyFileds(role),
					"$mul$postalAddress", role, format);
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException se) {
				}
			}
		}
		return map;
	}

	@Override
	public QueryType getQueryType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean supportType(QueryType queryType) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Map<String, Object> query(QueryParam param, String role, String format,
			PageBean... page) throws QueryException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected boolean supportJoinType(QueryType queryType,
			QueryJoinType queryJoinType) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Object querySpecificJoinTable(String key, String handle,
			String role, Connection connection, String format)
			throws SQLException {
		return querySpecificJoinTable(key, handle,
				WhoisUtil.SELECT_JOIN_LIST_POSTALADDRESS, role, connection,
				permissionCache.getPostalAddressKeyFileds(role), format);
	}
}