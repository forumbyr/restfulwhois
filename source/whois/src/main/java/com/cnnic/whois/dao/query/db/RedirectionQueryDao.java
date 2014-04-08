package com.cnnic.whois.dao.query.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.cnnic.whois.bean.QueryJoinType;
import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.bean.RedirectionQueryParam;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.execption.RedirectExecption;
import com.cnnic.whois.util.JdbcUtils;
import com.cnnic.whois.util.WhoisUtil;
/**
 * redirection query dao,query from redirect table
 * @author nic
 *
 */
@Repository
public class RedirectionQueryDao extends AbstractDbQueryDao {

	@Autowired
	private JdbcUtils jdbcUtils;
	
	@Override
	public Map<String, Object> query(QueryParam param)
			throws QueryException, RedirectExecption {
		Connection connection = null;
		PreparedStatement stmt = null;
		ResultSet results = null;
		String selectSql = "";
		RedirectionQueryParam redirectionQueryParam = (RedirectionQueryParam)param;
		String tableName = redirectionQueryParam.getTableName();
		String queryInfo = redirectionQueryParam.getQ();
		if (tableName .equals(WhoisUtil.AUTNUM)) {
			long queryPara = Long.valueOf(queryInfo );
			selectSql = WhoisUtil.SELECT_URL_AUTNUM_EDIRECTION1 + queryPara
					+ WhoisUtil.SELECT_URL_AUTNUM_EDIRECTION2 + queryPara;
		} else {
			queryInfo = queryInfo.substring(queryInfo.lastIndexOf(".") + 1);
			selectSql = WhoisUtil.SELECT_URL_DOAMIN_REDIRECTION + "'"
					+ queryInfo + "'";
		}

		try {
			connection = jdbcUtils.getConnection();
			stmt = connection.prepareStatement(selectSql);
			results = stmt.executeQuery();
			if (results.next()) {
				String redirectUrl = results.getString("redirectURL");
				if (!(redirectUrl.endsWith("/"))) {
					redirectUrl += "/";
				}
				throw new RedirectExecption(redirectUrl + param.getQ());
			}
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
		return null;
	}

	@Override
	public QueryType getQueryType() {
		return QueryType.REDIRECTION;
	}

	@Override
	public boolean supportType(QueryType queryType) {
		return getQueryType().equals(queryType);
	}

	@Override
	protected boolean supportJoinType(QueryType queryType,
			QueryJoinType queryJoinType) {
		return false;
	}

	@Override
	public Object querySpecificJoinTable(String key, String handle) throws SQLException {
		throw new UnsupportedOperationException();
	}
}
