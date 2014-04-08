package com.cnnic.whois.dao.query.db;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Repository;

import com.cnnic.whois.bean.QueryJoinType;
import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.util.WhoisUtil;
/**
 * event query dao
 * @author nic
 *
 */
@Repository
public class EventsQueryDao extends AbstractDbQueryDao {
	public static final String GET_ALL_EVENTS = "select * from events ";

	@Override
	public Map<String, Object> query(QueryParam param)
			throws QueryException {
		Map<String, Object> map = null;
		try {
			String selectSql = WhoisUtil.SELECT_LIST_EVENTS + "'"
					+ param.getQ() + "'";
			map = query(selectSql, columnCache
					.getEventsKeyFileds(), "$mul$events");
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	@Override
	public Map<String, Object> getAll() throws QueryException {
		Map<String, Object> map = null;
		try {
			map = query(GET_ALL_EVENTS, columnCache.getEventsKeyFileds(), "$mul$events");
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	@Override
	public QueryType getQueryType() {
		return QueryType.EVENTS;
	}

	@Override
	public boolean supportType(QueryType queryType) {
		return QueryType.EVENTS.equals(queryType);
	}

	@Override
	protected boolean supportJoinType(QueryType queryType,
			QueryJoinType queryJoinType) {
		return QueryJoinType.EVENTS.equals(queryJoinType);
	}

	@Override
	public Object querySpecificJoinTable(String key, String handle) throws SQLException {
		return querySpecificJoinTable(key, handle,
				WhoisUtil.SELECT_JOIN_LIST_EVENTS, columnCache.getEventsKeyFileds());
	}

	@Override
	public List<String> getKeyFields(String role) {
		return permissionCache.getEventsKeyFileds(role);
	}
}
