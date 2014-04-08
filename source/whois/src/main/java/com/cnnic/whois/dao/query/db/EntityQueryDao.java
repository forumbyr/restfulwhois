package com.cnnic.whois.dao.query.db;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.bean.index.Index;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.service.index.SearchResult;
import com.cnnic.whois.util.WhoisUtil;
/**
 * entity query dao
 * @author nic
 *
 */
@Repository
public class EntityQueryDao extends AbstractSearchQueryDao {
	private static final String MAP_KEY = "$mul$entity";
	public static final String GET_ALL_DNRENTITY = "select * from DNREntity ";
	public static final String GET_ALL_RIRENTITY = "select * from RIREntity ";
	
	@Autowired
	private com.cnnic.whois.dao.query.search.EntityQueryDao searchEntityQueryDao;

	@Override
	public Map<String, Object> query(QueryParam param)
			throws QueryException {
		SearchResult<? extends Index> result = 
				searchEntityQueryDao.preciseQueryEntitiesByHandleOrName(param);
		Map<String, Object> map = null;
		try {
			map = fuzzyQuery(result, StringUtils.EMPTY);//mark as not multi search
			if(null != map){
				map = rdapConformance(map);
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	@SuppressWarnings("unused")
	private Map<String, Object> queryDNREntity(String queryInfo, String role,
			String format) throws QueryException {
		Map<String, Object> map = null;
		try {
			String selectSql = WhoisUtil.SELECT_LIST_DNRENTITY + "'"
					+ queryInfo + "'";
			Map<String, Object> entityMap = query(selectSql,
					columnCache.getDNREntityKeyFileds(),
					MAP_KEY);
			if (entityMap != null) {
				map = rdapConformance(map);
				map.putAll(entityMap);
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	/**
	 * query rir entity 
	 * @param queryInfo:query string
	 * @param role :user role
	 * @param format:response format
	 * @return query result map
	 * @throws QueryException
	 */
	@SuppressWarnings("unused")
	private Map<String, Object> queryRIREntity(String queryInfo, String role,
			String format) throws QueryException {
		Map<String, Object> map = null;
		try {
			String selectSql = WhoisUtil.SELECT_LIST_RIRENTITY + "'"
					+ queryInfo + "'";
			Map<String, Object> entityMap = query(selectSql,
					columnCache.getRIREntityKeyFileds(),
					MAP_KEY);
			if (entityMap != null) {
				map = rdapConformance(map);
				map.putAll(entityMap);
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	@Override
	protected Map<String, Object> formatValue(Map<String, Object> map){
		if (map.containsKey(WhoisUtil.QUERY_JOIN_TYPE) && map.containsKey("events")) {
			String entityHandle = (String) map.get(WhoisUtil.HANDLE);
			Map<String, Object> map_Events = new LinkedHashMap<String, Object>();
			Object[] eventsObjs = (Object[]) map.get("events");
			for(Object eventObj : eventsObjs){
				map_Events = (Map<String, Object>) eventObj;
				if (map_Events.containsKey("Event_Actor")) {
					String eventactor = (String) map_Events.get("Event_Actor");
					if (entityHandle.equals(eventactor)) {
						map_Events.remove("Event_Actor");
						List<Map<String, Object>> listEvents = new ArrayList<Map<String, Object>>();
						listEvents.add(map_Events);
						map.put("asEventActor", listEvents.toArray());
						map.remove("events");
					}
				}
			}
		}
		map = WhoisUtil.toVCard(map);
		return map;
	}

	/**
	 * get all entity ,will be implemented by dnr/rir entity dao
	 * @param sql:dnr/rir query sql
	 * @param keyFields:authrozied keys
	 * @return query result map
	 * @throws QueryException
	 */
	protected Map<String, Object> getAllEntity(String sql, List<String> keyFields)
			throws QueryException {
		Map<String, Object> map = null;
		try {
			Map<String, Object> entityMap = query(sql, keyFields,
					MAP_KEY);
			if (entityMap != null) {
				map = rdapConformance(map);
				map.putAll(entityMap);
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	@Override
	public QueryType getQueryType() {
		return QueryType.ENTITY;
	}

	@Override
	public boolean supportType(QueryType queryType) {
		return QueryType.ENTITY.equals(queryType);
	}
}
